"""
Data Models Module
数据模型定义
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum
import uuid


class APIStatus(Enum):
    """API状态枚举"""
    UNKNOWN = "unknown"
    ALIVE = "alive"
    DEAD = "dead"
    UNAUTHORIZED = "unauthorized"
    SUSPICIOUS = "suspicious"


class Severity(Enum):
    """严重程度枚举"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class APIEndpoint:
    """API端点模型（统一版本）"""
    api_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    endpoint_id: str = ""  # Dashboard 使用
    task_id: str = ""  # Dashboard 使用
    path: str = ""
    method: str = "GET"
    base_url: str = ""
    full_url: str = ""
    status: APIStatus = APIStatus.UNKNOWN
    status_code: int = 0
    response_type: str = ""
    sources: List[Dict[str, Any]] = field(default_factory=list)
    score: int = 0
    parameters: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: str = ""
    response_sample: Optional[str] = None
    is_high_value: bool = False
    service_key: str = ""
    regex_context: Optional[str] = None
    content_hash: str = ""  # KnowledgeBase 使用
    summary: str = ""  # API Spec Parser 使用
    request_body: Optional[Dict] = None  # API Spec Parser 使用
    responses: Dict = field(default_factory=dict)  # API Spec Parser 使用
    security: List[Dict] = field(default_factory=list)  # API Spec Parser 使用
    tags: List[str] = field(default_factory=list)  # KnowledgeBase/API Spec Parser 使用
    created_at: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    updated_at: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'api_id': self.api_id,
            'endpoint_id': self.endpoint_id or self.api_id,
            'task_id': self.task_id,
            'path': self.path,
            'method': self.method,
            'base_url': self.base_url,
            'full_url': self.full_url,
            'status': self.status.value if isinstance(self.status, Enum) else self.status,
            'status_code': self.status_code,
            'response_type': self.response_type,
            'sources': self.sources,
            'score': self.score,
            'parameters': self.parameters,
            'headers': self.headers,
            'cookies': self.cookies,
            'response_sample': self.response_sample,
            'is_high_value': self.is_high_value,
            'service_key': self.service_key,
            'regex_context': self.regex_context,
            'content_hash': self.content_hash,
            'summary': self.summary,
            'request_body': self.request_body,
            'responses': self.responses,
            'security': self.security,
            'tags': self.tags,
            'created_at': self.created_at,
            'updated_at': self.updated_at
        }


@dataclass
class Vulnerability:
    """漏洞模型（统一版本）"""
    vuln_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    api_id: str = ""  # 核心模型使用
    endpoint_id: str = ""  # Dashboard 使用
    task_id: str = ""  # Dashboard 使用
    vuln_type: str = ""
    severity: Severity = Severity.MEDIUM
    title: str = ""
    description: str = ""
    evidence: str = ""
    payload: Optional[str] = None
    remediation: str = ""
    references: List[str] = field(default_factory=list)  # 核心模型有
    cwe_id: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'vuln_id': self.vuln_id,
            'api_id': self.api_id,
            'endpoint_id': self.endpoint_id or self.api_id,
            'task_id': self.task_id,
            'vuln_type': self.vuln_type,
            'severity': self.severity.value if isinstance(self.severity, Enum) else self.severity,
            'title': self.title,
            'description': self.description,
            'evidence': self.evidence,
            'payload': self.payload,
            'remediation': self.remediation,
            'references': self.references,
            'cwe_id': self.cwe_id,
            'created_at': self.created_at
        }


@dataclass
class SensitiveData:
    """敏感数据模型"""
    data_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    api_id: str = ""
    data_type: str = ""
    matches: List[str] = field(default_factory=list)
    severity: Severity = Severity.MEDIUM
    evidence: str = ""
    context: str = ""
    location: str = ""
    created_at: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'data_id': self.data_id,
            'api_id': self.api_id,
            'data_type': self.data_type,
            'matches': self.matches,
            'severity': self.severity.value if isinstance(self.severity, Enum) else self.severity,
            'evidence': self.evidence,
            'context': self.context,
            'location': self.location,
            'created_at': self.created_at
        }


@dataclass
class ScanResult:
    """扫描结果模型（统一版本）"""
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    task_id: str = ""  # Dashboard 使用
    target_url: str = ""
    start_time: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    end_time: Optional[str] = None
    duration: float = 0.0
    status: str = "running"
    total_apis: int = 0
    alive_apis: int = 0
    high_value_apis: int = 0
    total_vulns: int = 0  # Dashboard 使用
    total_sensitive: int = 0  # Dashboard 使用
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    sensitive_data: List[SensitiveData] = field(default_factory=list)
    api_endpoints: List[APIEndpoint] = field(default_factory=list)
    statistics: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'scan_id': self.scan_id,
            'task_id': self.task_id,
            'target_url': self.target_url,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'duration': self.duration,
            'status': self.status,
            'total_apis': self.total_apis,
            'alive_apis': self.alive_apis,
            'high_value_apis': self.high_value_apis,
            'total_vulns': self.total_vulns or len(self.vulnerabilities),
            'total_sensitive': self.total_sensitive or len(self.sensitive_data),
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
            'sensitive_data': [s.to_dict() for s in self.sensitive_data],
            'api_endpoints': [a.to_dict() for a in self.api_endpoints],
            'statistics': self.statistics,
            'errors': self.errors,
            'created_at': self.created_at
        }


@dataclass
class ServiceInfo:
    """服务信息模型"""
    service_key: str = ""
    service_name: str = ""
    base_url: str = ""
    api_count: int = 0
    high_value_count: int = 0
    vulnerability_count: int = 0
    sensitive_count: int = 0
    apis: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'service_key': self.service_key,
            'service_name': self.service_name,
            'base_url': self.base_url,
            'api_count': self.api_count,
            'high_value_count': self.high_value_count,
            'vulnerability_count': self.vulnerability_count,
            'sensitive_count': self.sensitive_count,
            'apis': self.apis
        }


@dataclass
class StageStats:
    """阶段统计模型"""
    stage_name: str = ""
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    duration: float = 0.0
    input_count: int = 0
    output_count: int = 0
    error_count: int = 0
    success_rate: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'stage_name': self.stage_name,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'duration': self.duration,
            'input_count': self.input_count,
            'output_count': self.output_count,
            'error_count': self.error_count,
            'success_rate': self.success_rate
        }


@dataclass
class AttackChain:
    """攻击链"""
    chain_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    entry_point: str = ""
    api_path: List[str] = field(default_factory=list)
    vulnerability: str = ""
    severity: str = ""
    remediation: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'chain_id': self.chain_id,
            'entry_point': self.entry_point,
            'api_path': self.api_path,
            'vulnerability': self.vulnerability,
            'severity': self.severity,
            'remediation': self.remediation
        }
