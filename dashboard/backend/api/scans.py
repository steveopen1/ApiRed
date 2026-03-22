"""
Scans API
扫描API - 扫描操作
"""

import asyncio
import json
import httpx
from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel

from ..db import db

router = APIRouter(prefix="/api/scans", tags=["scans"])

class ScanCreate(BaseModel):
    target_id: int
    config: Optional[dict] = {}

class ScanResponse(BaseModel):
    id: int
    target_id: int
    status: str
    total_apis: int = 0
    alive_apis: int = 0
    critical_vulns: int = 0
    high_vulns: int = 0
    medium_vulns: int = 0
    low_vulns: int = 0
    started_at: str
    completed_at: Optional[str] = None

class ScanResultDetail(BaseModel):
    apis: List[dict] = []
    vulnerabilities: List[dict] = []
    sensitive_data: List[dict] = []

_active_scans = {}

COMMON_API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/api/users", "/api/user", "/api/login", "/api/auth",
    "/api/products", "/api/product", "/api/items", "/api/item",
    "/api/orders", "/api/order", "/api/transactions",
    "/api/admin", "/api/manage", "/api/dashboard",
    "/api/health", "/api/status", "/api/info",
    "/api/config", "/api/settings", "/api/profile",
    "/api/data", "/api/db", "/api/backup",
]

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"]

async def check_api_alive(url: str, method: str = "GET") -> bool:
    """检查API是否存活"""
    try:
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=True) as client:
            response = await client.request(method, url)
            return response.status_code < 500
    except:
        return False

async def run_scan(scan_id: int, target_id: int, target_url: str):
    """执行扫描任务"""
    discovered_apis = []
    alive_apis = []
    vulnerabilities = []
    
    try:
        db.update_target(target_id, status='scanning')
        _active_scans[scan_id] = {'status': 'running', 'target_id': target_id}
        
        base_url = target_url.rstrip('/')
        if not base_url.startswith(('http://', 'https://')):
            base_url = 'http://' + base_url
        
        for path in COMMON_API_PATHS:
            if _active_scans.get(scan_id, {}).get('status') == 'cancelled':
                db.update_target(target_id, status='cancelled')
                return
            
            url = base_url + path
            for method in HTTP_METHODS:
                try:
                    async with httpx.AsyncClient(timeout=3.0, follow_redirects=True) as client:
                        response = await client.request(method, url, timeout=3.0)
                        status_code = response.status_code
                        
                        discovered_apis.append({
                            'url': url,
                            'method': method,
                            'status': status_code
                        })
                        
                        if 200 <= status_code < 500:
                            alive_apis.append({
                                'url': url,
                                'method': method,
                                'status': status_code
                            })
                        
                        if status_code == 200 and ('admin' in path or 'manage' in path or 'dashboard' in path):
                            vulnerabilities.append({
                                'vuln_type': 'Information Disclosure',
                                'severity': 'medium',
                                'url': url,
                                'description': f'Administrative endpoint exposed: {path}',
                                'payload': None,
                                'remediation': 'Restrict access to administrative endpoints'
                            })
                        
                        if status_code == 401 or status_code == 403:
                            vulnerabilities.append({
                                'vuln_type': 'Missing Authentication',
                                'severity': 'high',
                                'url': url,
                                'description': f'Endpoint does not require authentication: {path}',
                                'payload': None,
                                'remediation': 'Implement proper authentication for this endpoint'
                            })
                        
                        if 'password' in path.lower() or 'secret' in path.lower() or 'token' in path.lower():
                            vulnerabilities.append({
                                'vuln_type': 'Sensitive Data Exposure',
                                'severity': 'high',
                                'url': url,
                                'description': f'Sensitive path detected: {path}',
                                'payload': None,
                                'remediation': 'Ensure sensitive data is properly protected'
                            })
                            
                except Exception:
                    pass
        
        critical_count = sum(1 for v in vulnerabilities if v['severity'] == 'critical')
        high_count = sum(1 for v in vulnerabilities if v['severity'] == 'high')
        medium_count = sum(1 for v in vulnerabilities if v['severity'] == 'medium')
        low_count = sum(1 for v in vulnerabilities if v['severity'] == 'low')
        
        for vuln in vulnerabilities:
            db.create_vulnerability(
                scan_id=scan_id,
                target_id=target_id,
                vuln_type=vuln['vuln_type'],
                severity=vuln['severity'],
                url=vuln['url'],
                description=vuln['description'],
                payload=vuln.get('payload'),
                remediation=vuln.get('remediation')
            )
        
        result = {
            'status': 'completed',
            'total_apis': len(discovered_apis),
            'alive_apis': len(alive_apis),
            'critical_vulns': critical_count,
            'high_vulns': high_count,
            'medium_vulns': medium_count,
            'low_vulns': low_count,
            'discovered_apis': discovered_apis[:50],
            'vulnerabilities': vulnerabilities
        }
        
        db.update_target(target_id, 
                        status='completed',
                        api_count=len(alive_apis),
                        vuln_count=critical_count + high_count + medium_count,
                        last_scan_at=datetime.now().isoformat())
        
        db.create_scan_result(
            target_id=target_id,
            status='completed',
            total_apis=len(discovered_apis),
            alive_apis=len(alive_apis),
            critical_vulns=critical_count,
            high_vulns=high_count,
            medium_vulns=medium_count,
            low_vulns=low_count,
            result_json=json.dumps(result)
        )
        
        _active_scans[scan_id] = {'status': 'completed', 'result': result}
        
    except Exception as e:
        db.update_target(target_id, status='failed')
        _active_scans[scan_id] = {'status': 'failed', 'error': str(e)}

@router.post("/", response_model=ScanResponse)
async def create_scan(scan: ScanCreate, background_tasks: BackgroundTasks):
    """创建扫描任务"""
    all_targets = db.get_targets()
    target = None
    for t in all_targets:
        if t['id'] == scan.target_id:
            target = t
            break
    
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    now = datetime.now().isoformat()
    scan_result_id = db.create_scan_result(
        target_id=scan.target_id,
        status='running'
    )
    
    db.update_target(scan.target_id, status='scanning')
    
    background_tasks.add_task(run_scan, scan_result_id, scan.target_id, target['url'])
    
    return ScanResponse(
        id=scan_result_id,
        target_id=scan.target_id,
        status="running",
        total_apis=0,
        alive_apis=0,
        critical_vulns=0,
        high_vulns=0,
        medium_vulns=0,
        low_vulns=0,
        started_at=now,
        completed_at=None
    )

@router.get("/", response_model=List[ScanResponse])
async def list_scans(
    target_id: Optional[int] = None,
    limit: int = 50
):
    """获取扫描列表"""
    scan_results = db.get_scan_results(target_id=target_id, limit=limit)
    return [
        ScanResponse(
            id=r['id'],
            target_id=r['target_id'],
            status=r['status'],
            total_apis=r.get('total_apis', 0),
            alive_apis=r.get('alive_apis', 0),
            critical_vulns=r.get('critical_vulns', 0),
            high_vulns=r.get('high_vulns', 0),
            medium_vulns=r.get('medium_vulns', 0),
            low_vulns=r.get('low_vulns', 0),
            started_at=r.get('created_at', ''),
            completed_at=r.get('created_at') if r['status'] == 'completed' else None
        ) for r in scan_results
    ]

@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: int):
    """获取扫描状态"""
    scan_results = db.get_scan_results(limit=1000)
    for r in scan_results:
        if r['id'] == scan_id:
            return ScanResponse(
                id=r['id'],
                target_id=r['target_id'],
                status=r['status'],
                total_apis=r.get('total_apis', 0),
                alive_apis=r.get('alive_apis', 0),
                critical_vulns=r.get('critical_vulns', 0),
                high_vulns=r.get('high_vulns', 0),
                medium_vulns=r.get('medium_vulns', 0),
                low_vulns=r.get('low_vulns', 0),
                started_at=r.get('created_at', ''),
                completed_at=r.get('created_at') if r['status'] == 'completed' else None
            )
    raise HTTPException(status_code=404, detail="Scan not found")

@router.get("/{scan_id}/result", response_model=ScanResultDetail)
async def get_scan_result(scan_id: int):
    """获取扫描详情"""
    scan_results = db.get_scan_results(limit=1000)
    for r in scan_results:
        if r['id'] == scan_id:
            result_json = r.get('result_json')
            if result_json:
                data = json.loads(result_json)
                return ScanResultDetail(
                    apis=data.get('discovered_apis', []),
                    vulnerabilities=data.get('vulnerabilities', []),
                    sensitive_data=[]
                )
            return ScanResultDetail()
    raise HTTPException(status_code=404, detail="Scan not found")

@router.post("/{scan_id}/cancel")
async def cancel_scan(scan_id: int):
    """取消扫描"""
    if scan_id in _active_scans:
        _active_scans[scan_id]['status'] = 'cancelled'
        return {"message": "Scan cancelled"}
    return {"message": "Scan not found"}
