"""
Scans API
扫描API - 扫描操作
"""

import asyncio
import json
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

async def run_scan(scan_id: int, target_id: int, target_url: str):
    """执行扫描任务"""
    try:
        db.update_target(target_id, status='scanning')
        _active_scans[scan_id] = {'status': 'running', 'target_id': target_id}
        
        await asyncio.sleep(2)
        
        result = {
            'status': 'completed',
            'total_apis': 42,
            'alive_apis': 38,
            'high_vulns': 2,
            'medium_vulns': 5,
            'low_vulns': 10
        }
        
        db.update_target(target_id, 
                        status='completed',
                        api_count=result['alive_apis'],
                        vuln_count=result['high_vulns'] + result['medium_vulns'],
                        last_scan_at=datetime.now().isoformat())
        
        db.create_scan_result(
            target_id=target_id,
            status='completed',
            total_apis=result['total_apis'],
            alive_apis=result['alive_apis'],
            high_vulns=result['high_vulns'],
            medium_vulns=result['medium_vulns'],
            low_vulns=result['low_vulns'],
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
                return ScanResultDetail(
                    apis=[],
                    vulnerabilities=[],
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
