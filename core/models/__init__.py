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
    UNauthorized = "unauthorized"
    SUSPICIOUS = "suspicious"


class Severity(Enum):
    """严重程度枚举"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class APIEndpoint:
    """API端点模型"""
    api_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    path: str = ""
    method: str = "GET"
    base_url: str = ""
    full_url: str = ""
    status: APIStatus = APIStatus.UNKNOWN
    sources: List[Dict[str, Any]] = field(default_factory=list)
    score: int = 0
    parameters: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: str = ""
    response_sample: Optional[str] = None
    is_high_value: bool = False
    service_key: str = ""
    regex_context: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    updated_at: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'api_id': self.api_id,
            'path': self.path,
            'method': self.method,
            'base_url': self.base_url,
            'full_url': self.full_url,
            'status': self.status.value if isinstance(self.status, Enum) else self.status,
            'sources': self.sources,
            'score': self.score,
            'parameters': self.parameters,
            'headers': self.headers,
            'cookies': self.cookies,
            'response_sample': self.response_sample,
            'is_high_value': self.is_high_value,
            'service_key': self.service_key,
            'regex_context': self.regex_context,
            'created_at': self.created_at,
            'updated_at': self.updated_at
        }


@dataclass
class Vulnerability:
    """漏洞模型"""
    vuln_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    api_id: str = ""
    vuln_type: str = ""
    severity: Severity = Severity.MEDIUM
    title: str = ""
    description: str = ""
    evidence: str = ""
    payload: Optional[str] = None
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    cwe_id: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'vuln_id': self.vuln_id,
            'api_id': self.api_id,
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
    """扫描结果模型"""
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    target_url: str = ""
    start_time: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    end_time: Optional[str] = None
    duration: float = 0.0
    status: str = "running"
    total_apis: int = 0
    alive_apis: int = 0
    high_value_apis: int = 0
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    sensitive_data: List[SensitiveData] = field(default_factory=list)
    api_endpoints: List[APIEndpoint] = field(default_factory=list)
    statistics: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'scan_id': self.scan_id,
            'target_url': self.target_url,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'duration': self.duration,
            'status': self.status,
            'total_apis': self.total_apis,
            'alive_apis': self.alive_apis,
            'high_value_apis': self.high_value_apis,
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
            'sensitive_data': [s.to_dict() for s in self.sensitive_data],
            'api_endpoints': [a.to_dict() for a in self.api_endpoints],
            'statistics': self.statistics,
            'errors': self.errors
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
