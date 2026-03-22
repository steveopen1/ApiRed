"""
Dashboard Backend Models
数据库模型定义
"""

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel
from dataclasses import dataclass, field

@dataclass
class Project:
    """项目模型"""
    id: int = 0
    name: str = ""
    description: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    target_count: int = 0
    api_count: int = 0
    vuln_count: int = 0
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class Target:
    """目标模型"""
    id: int = 0
    project_id: int = 0
    url: str = ""
    name: Optional[str] = None
    status: str = "pending"
    api_count: int = 0
    vuln_count: int = 0
    last_scan_at: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class ScanResult:
    """扫描结果模型"""
    id: int = 0
    target_id: int = 0
    status: str = "pending"
    total_apis: int = 0
    alive_apis: int = 0
    high_vulns: int = 0
    medium_vulns: int = 0
    low_vulns: int = 0
    result_json: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class Vulnerability:
    """漏洞模型"""
    id: int = 0
    scan_id: int = 0
    target_id: int = 0
    vuln_type: str = ""
    severity: str = ""
    title: str = ""
    description: str = ""
    payload: Optional[str] = None
    remediation: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class APIEndpoint:
    """API端点模型"""
    id: int = 0
    target_id: int = 0
    url: str = ""
    method: str = "GET"
    path: str = ""
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
