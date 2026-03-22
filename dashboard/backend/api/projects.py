"""
Projects API
项目API - 项目CRUD操作
"""

import json
from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from ..db import db

router = APIRouter(prefix="/api/projects", tags=["projects"])

class ProjectCreate(BaseModel):
    name: str
    description: Optional[str] = None
    tags: List[str] = []

class ProjectUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[List[str]] = None

class ProjectResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    tags: List[str]
    target_count: int = 0
    api_count: int = 0
    vuln_count: int = 0
    created_at: str
    updated_at: str

class TargetBrief(BaseModel):
    id: int
    url: str
    name: Optional[str]
    status: str
    api_count: int = 0
    vuln_count: int = 0

class ProjectDetailResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    tags: List[str]
    targets: List[TargetBrief] = []
    stats: dict
    created_at: str
    updated_at: str

def _parse_project(row: dict) -> ProjectResponse:
    """解析项目数据"""
    row['tags'] = json.loads(row.get('tags', '[]'))
    return ProjectResponse(**row)

@router.post("/", response_model=ProjectResponse)
async def create_project(project: ProjectCreate):
    """创建项目"""
    project_id = db.create_project(
        name=project.name,
        description=project.description,
        tags=project.tags
    )
    new_project = db.get_project(project_id)
    return _parse_project(new_project)

@router.get("/", response_model=List[ProjectResponse])
async def list_projects(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=20, ge=1, le=100),
    tag: Optional[str] = None
):
    """获取项目列表"""
    projects = db.get_projects(skip=skip, limit=limit, tag=tag)
    return [_parse_project(p) for p in projects]

@router.get("/{project_id}", response_model=ProjectDetailResponse)
async def get_project(project_id: int):
    """获取项目详情"""
    project = db.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    targets = db.get_targets(project_id=project_id)
    stats = {
        "total_targets": project.get('target_count', 0),
        "total_apis": project.get('api_count', 0),
        "critical_vulns": project.get('vuln_count', 0),
        "high_vulns": project.get('vuln_count', 0),
        "medium_vulns": 0,
        "low_vulns": 0
    }
    
    target_briefs = [
        TargetBrief(
            id=t['id'],
            url=t['url'],
            name=t.get('name'),
            status=t.get('status', 'pending'),
            api_count=t.get('api_count', 0),
            vuln_count=t.get('vuln_count', 0)
        ) for t in targets
    ]
    
    project['tags'] = json.loads(project.get('tags', '[]'))
    return ProjectDetailResponse(
        **{**project, "targets": target_briefs, "stats": stats}
    )

@router.put("/{project_id}", response_model=ProjectResponse)
async def update_project(project_id: int, project: ProjectUpdate):
    """更新项目"""
    kwargs = {}
    if project.name is not None:
        kwargs['name'] = project.name
    if project.description is not None:
        kwargs['description'] = project.description
    if project.tags is not None:
        kwargs['tags'] = json.dumps(project.tags)
    
    if not kwargs:
        raise HTTPException(status_code=400, detail="No fields to update")
    
    db.update_project(project_id, **kwargs)
    updated = db.get_project(project_id)
    if not updated:
        raise HTTPException(status_code=404, detail="Project not found")
    return _parse_project(updated)

@router.delete("/{project_id}")
async def delete_project(project_id: int):
    """删除项目"""
    deleted = db.delete_project(project_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Project not found")
    return {"message": "Project deleted"}

@router.get("/{project_id}/stats")
async def get_project_stats(project_id: int):
    """获取项目统计"""
    project = db.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return {
        "total_targets": project.get('target_count', 0),
        "total_apis": project.get('api_count', 0),
        "critical_vulns": project.get('vuln_count', 0),
        "high_vulns": project.get('vuln_count', 0),
        "medium_vulns": 0,
        "low_vulns": 0,
        "scan_trend": []
    }
