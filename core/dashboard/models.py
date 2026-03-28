"""
Dashboard Data Models
数据模型定义 - 用于任务管理、进度跟踪、发现事件等
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum
import secrets
import json


class TaskStatus(Enum):
    """任务状态枚举"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"


class ScanMode(Enum):
    """扫描模式"""
    RULE = "rule"
    AGENT = "agent"


class FindingType(Enum):
    """发现类型"""
    API = "api"
    VULNERABILITY = "vulnerability"
    SENSITIVE = "sensitive"
    JS = "js"
    SUBDOMAIN = "subdomain"


class LogLevel(Enum):
    """日志级别"""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


@dataclass
class EngineConfig:
    """引擎配置"""
    target: str = ""
    collectors: List[str] = field(default_factory=lambda: ["js", "api"])
    analyzers: List[str] = field(default_factory=lambda: ["scorer", "sensitive"])
    testers: List[str] = field(default_factory=lambda: ["fuzz", "vuln"])
    ai_enabled: bool = False
    checkpoint_enabled: bool = True
    cookies: str = ""
    concurrency: int = 50
    concurrency_probe: bool = False
    proxy: Optional[str] = None
    js_depth: int = 3
    output_dir: str = "./results"
    attack_mode: str = "all"
    no_api_scan: bool = False
    chrome: bool = True
    verify_ssl: bool = True
    resume: bool = False
    targets: List[str] = field(default_factory=list)
    concurrent_targets: int = 5
    aggregate: bool = False
    agent_mode: bool = False
    incremental: bool = False
    enable_sql_test: bool = True
    enable_xss_test: bool = True
    enable_ssrf_test: bool = True
    enable_bypass_test: bool = True
    enable_jwt_test: bool = True
    enable_idor_test: bool = True
    enable_unauthorized_test: bool = True
    enable_info_disclosure_test: bool = True
    report_formats: List[str] = field(default_factory=lambda: ["json", "html"])

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EngineConfig':
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered_data = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered_data)


@dataclass
class ScanTask:
    """扫描任务"""
    task_id: str = field(default_factory=lambda: secrets.token_hex(8))
    target: str = ""
    status: TaskStatus = TaskStatus.PENDING
    scan_mode: ScanMode = ScanMode.RULE
    progress: int = 0
    current_stage: str = ""
    current_phase: str = ""
    engine_config: Optional[EngineConfig] = None
    config_dict: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error_message: str = ""

    pid: int = 0
    output_path: str = ""

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['status'] = self.status.value if isinstance(self.status, Enum) else self.status
        result['scan_mode'] = self.scan_mode.value if isinstance(self.scan_mode, Enum) else self.scan_mode
        if self.engine_config:
            result['engine_config'] = self.engine_config.to_dict()
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ScanTask':
        if 'status' in data and isinstance(data['status'], str):
            data['status'] = TaskStatus(data['status'])
        if 'scan_mode' in data and isinstance(data['scan_mode'], str):
            data['scan_mode'] = ScanMode(data['scan_mode'])
        if 'engine_config' in data and data['engine_config']:
            data['engine_config'] = EngineConfig.from_dict(data['engine_config'])
        return cls(**data)


@dataclass
class StageStats:
    """阶段统计"""
    stage_name: str = ""
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    duration: float = 0.0
    input_count: int = 0
    output_count: int = 0
    error_count: int = 0
    success_rate: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'StageStats':
        return cls(**data) if data else cls()


@dataclass
class ScanProgress:
    """扫描进度"""
    task_id: str
    stage: str = ""
    stage_status: str = "running"
    progress_percent: int = 0
    current_phase: str = ""
    stats: Optional[StageStats] = None
    total_apis: int = 0
    alive_apis: int = 0
    high_value_apis: int = 0
    vulnerabilities_found: int = 0
    sensitive_found: int = 0
    errors: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        if self.stats:
            result['stats'] = self.stats.to_dict()
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ScanProgress':
        if 'stats' in data and data['stats']:
            data['stats'] = StageStats.from_dict(data['stats'])
        return cls(**data)


@dataclass
class Finding:
    """发现事件"""
    task_id: str
    finding_type: FindingType
    data: Dict[str, Any]
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['finding_type'] = self.finding_type.value if isinstance(self.finding_type, Enum) else self.finding_type
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Finding':
        if 'finding_type' in data and isinstance(data['finding_type'], str):
            data['finding_type'] = FindingType(data['finding_type'])
        return cls(**data)


@dataclass
class LogEntry:
    """日志条目"""
    task_id: str
    level: LogLevel
    message: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    source: str = ""

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['level'] = self.level.value if isinstance(self.level, Enum) else self.level
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'LogEntry':
        if 'level' in data and isinstance(data['level'], str):
            data['level'] = LogLevel(data['level'])
        return cls(**data)


@dataclass
class APIEndpoint:
    """API端点"""
    endpoint_id: str = field(default_factory=lambda: secrets.token_hex(8))
    task_id: str = ""
    path: str = ""
    method: str = "GET"
    base_url: str = ""
    full_url: str = ""
    status: str = "unknown"
    status_code: int = 0
    score: int = 0
    is_high_value: bool = False
    sources: List[str] = field(default_factory=list)
    parameters: List[str] = field(default_factory=list)
    response_sample: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'APIEndpoint':
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered_data = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered_data)


@dataclass
class Vulnerability:
    """漏洞"""
    vuln_id: str = field(default_factory=lambda: secrets.token_hex(8))
    task_id: str = ""
    endpoint_id: str = ""
    vuln_type: str = ""
    severity: str = "medium"
    title: str = ""
    description: str = ""
    evidence: str = ""
    payload: Optional[str] = None
    remediation: str = ""
    cwe_id: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Vulnerability':
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered_data = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered_data)


@dataclass
class ScanResult:
    """扫描结果摘要"""
    result_id: str = field(default_factory=lambda: secrets.token_hex(8))
    task_id: str = ""
    target_url: str = ""
    total_apis: int = 0
    alive_apis: int = 0
    high_value_apis: int = 0
    total_vulns: int = 0
    total_sensitive: int = 0
    status: str = "pending"
    duration: float = 0.0
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ScanResult':
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered_data = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered_data)


@dataclass
class ServerConfig:
    """服务器配置"""
    host: str = "0.0.0.0"
    port: int = 8080
    static_path: str = "core/dashboard/static"
    enable_cors: bool = True
    cors_origins: List[str] = field(default_factory=list)
    heartbeat_interval: int = 30
    max_log_entries: int = 1000
    task_history_limit: int = 100

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ServerConfig':
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered_data = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered_data)
