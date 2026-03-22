"""
Targets API
目标API - 目标CRUD操作
"""

from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from ..db import db

router = APIRouter(prefix="/api/targets", tags=["targets"])

class TargetCreate(BaseModel):
    project_id: int
    url: str
    name: Optional[str] = None
    scan_config: Optional[dict] = {}

class TargetUpdate(BaseModel):
    name: Optional[str] = None
    status: Optional[str] = None

class TargetResponse(BaseModel):
    id: int
    project_id: int
    url: str
    name: Optional[str]
    status: str
    api_count: int = 0
    vuln_count: int = 0
    last_scan_at: Optional[str] = None
    created_at: str

class TargetListResponse(BaseModel):
    targets: List[TargetResponse]
    total: int

def _parse_target(row: dict) -> TargetResponse:
    """解析目标数据"""
    return TargetResponse(**row)

@router.post("/", response_model=TargetResponse)
async def create_target(target: TargetCreate):
    """添加目标"""
    target_id = db.create_target(
        project_id=target.project_id,
        url=target.url,
        name=target.name
    )
    targets = db.get_targets(project_id=target.project_id)
    for t in targets:
        if t['id'] == target_id:
            return _parse_target(t)
    raise HTTPException(status_code=500, detail="Failed to create target")

@router.get("/", response_model=TargetListResponse)
async def list_targets(
    project_id: Optional[int] = None,
    status: Optional[str] = None,
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200)
):
    """获取目标列表"""
    targets = db.get_targets(project_id=project_id, status=status, skip=skip, limit=limit)
    return TargetListResponse(
        targets=[_parse_target(t) for t in targets],
        total=len(targets)
    )

@router.get("/{target_id}", response_model=TargetResponse)
async def get_target(target_id: int):
    """获取目标详情"""
    targets = db.get_targets()
    for t in targets:
        if t['id'] == target_id:
            return _parse_target(t)
    raise HTTPException(status_code=404, detail="Target not found")

@router.put("/{target_id}", response_model=TargetResponse)
async def update_target(target_id: int, target: TargetUpdate):
    """更新目标"""
    kwargs = {}
    if target.name is not None:
        kwargs['name'] = target.name
    if target.status is not None:
        kwargs['status'] = target.status
    
    if not kwargs:
        raise HTTPException(status_code=400, detail="No fields to update")
    
    db.update_target(target_id, **kwargs)
    targets = db.get_targets()
    for t in targets:
        if t['id'] == target_id:
            return _parse_target(t)
    raise HTTPException(status_code=404, detail="Target not found")

@router.delete("/{target_id}")
async def delete_target(target_id: int):
    """删除目标"""
    deleted = db.delete_target(target_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Target not found")
    return {"message": "Target deleted"}

@router.post("/{target_id}/scan")
async def start_scan(target_id: int):
    """启动扫描"""
    targets = db.get_targets()
    for t in targets:
        if t['id'] == target_id:
            db.update_target(target_id, status='scanning')
            return {
                "message": "Scan started",
                "target_id": target_id,
                "scan_id": f"scan_{target_id}_{int(datetime.now().timestamp())}"
            }
    raise HTTPException(status_code=404, detail="Target not found")
