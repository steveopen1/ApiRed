"""
Knowledge Base Module
共享知识库 - 为 Agent 系统提供统一的数据共享
"""

import asyncio
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
import threading


@dataclass
class APIEndpoint:
    """API 端点"""
    path: str
    method: str = "GET"
    source: str = ""
    full_url: str = ""
    status: int = 0
    score: float = 0.0
    tags: List[str] = field(default_factory=list)
    parameters: Dict[str, Any] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: str = ""
    discovered_at: str = field(default_factory=lambda: datetime.now().isoformat())
    last_tested: str = ""
    response_sample: str = ""
    content_hash: str = ""


@dataclass
class Finding:
    """发现结果"""
    finding_type: str
    severity: str = "info"
    title: str = ""
    description: str = ""
    url: str = ""
    evidence: str = ""
    payload: str = ""
    remediation: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class KnowledgeBase:
    """
    共享知识库
    为 Agent 系统提供统一的 API 端点、参数、发现结果存储
    """
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self._initialized = True
        self._endpoints: Dict[str, APIEndpoint] = {}
        self._findings: List[Finding] = []
        self._parameters: Dict[str, Set[str]] = defaultdict(set)
        self._domains: Set[str] = set()
        self._sensitive_patterns: List[str] = []
        self._vulnerabilities: List[Dict] = []
        self._sensitive_data: List[Dict] = []
        self._lock = threading.RLock()
        
        self._event_callbacks: Dict[str, List[callable]] = {
            'endpoint_added': [],
            'finding_added': [],
            'parameter_added': [],
            'vulnerability_added': [],
        }
    
    def add_endpoint(self, endpoint: APIEndpoint) -> bool:
        """添加 API 端点"""
        with self._lock:
            key = f"{endpoint.method}:{endpoint.path}"
            if key in self._endpoints:
                existing = self._endpoints[key]
                if endpoint.full_url:
                    existing.full_url = endpoint.full_url
                if endpoint.status:
                    existing.status = endpoint.status
                if endpoint.score > existing.score:
                    existing.score = endpoint.score
                existing.tags = list(set(existing.tags + endpoint.tags))
                existing.last_tested = datetime.now().isoformat()
                return False
            else:
                self._endpoints[key] = endpoint
                self._emit('endpoint_added', endpoint)
                return True
    
    def get_endpoints(self) -> List[APIEndpoint]:
        """获取所有端点"""
        with self._lock:
            return list(self._endpoints.values())
    
    def get_endpoint_by_path(self, path: str) -> Optional[APIEndpoint]:
        """根据路径获取端点"""
        with self._lock:
            for ep in self._endpoints.values():
                if ep.path == path:
                    return ep
            return None
    
    def get_high_value_endpoints(self, min_score: float = 7.0) -> List[APIEndpoint]:
        """获取高价值端点"""
        with self._lock:
            return [ep for ep in self._endpoints.values() if ep.score >= min_score]
    
    def add_finding(self, finding: Finding) -> None:
        """添加发现"""
        with self._lock:
            self._findings.append(finding)
            self._emit('finding_added', finding)
    
    def get_findings(self, finding_type: str = None, min_severity: str = None) -> List[Finding]:
        """获取发现列表"""
        with self._lock:
            results = self._findings
            
            if finding_type:
                results = [f for f in results if f.finding_type == finding_type]
            
            if min_severity:
                severity_order = ['critical', 'high', 'medium', 'low', 'info']
                min_idx = severity_order.index(min_severity) if min_severity in severity_order else 4
                results = [f for f in results if f.severity in severity_order[:min_idx+1]]
            
            return results
    
    def add_parameter(self, path: str, param: str) -> None:
        """添加参数"""
        with self._lock:
            self._parameters[path].add(param)
            self._emit('parameter_added', {'path': path, 'param': param})
    
    def get_parameters(self, path: str) -> Set[str]:
        """获取路径的参数"""
        with self._lock:
            return self._parameters.get(path, set())
    
    def add_domain(self, domain: str) -> None:
        """添加域名"""
        with self._lock:
            self._domains.add(domain)
    
    def get_domains(self) -> Set[str]:
        """获取所有域名"""
        with self._lock:
            return self._domains.copy()
    
    def add_sensitive_pattern(self, pattern: str) -> None:
        """添加敏感信息匹配模式"""
        with self._lock:
            if pattern not in self._sensitive_patterns:
                self._sensitive_patterns.append(pattern)
    
    def get_sensitive_patterns(self) -> List[str]:
        """获取敏感信息模式"""
        with self._lock:
            return self._sensitive_patterns.copy()
    
    def add_vulnerability(self, vuln: Dict) -> None:
        """添加漏洞"""
        with self._lock:
            self._vulnerabilities.append(vuln)
            self._emit('vulnerability_added', vuln)
    
    def get_vulnerabilities(self) -> List[Dict]:
        """获取漏洞列表"""
        with self._lock:
            return self._vulnerabilities.copy()
    
    def add_sensitive_data(self, data: Dict) -> None:
        """添加敏感数据"""
        with self._lock:
            self._sensitive_data.append(data)
    
    def get_sensitive_data(self) -> List[Dict]:
        """获取敏感数据列表"""
        with self._lock:
            return self._sensitive_data.copy()
    
    def on(self, event: str, callback: callable) -> None:
        """注册事件回调"""
        if event in self._event_callbacks:
            self._event_callbacks[event].append(callback)
    
    def _emit(self, event: str, data: Any) -> None:
        """触发事件"""
        for callback in self._event_callbacks.get(event, []):
            try:
                callback(data)
            except Exception:
                pass
    
    def get_summary(self) -> Dict[str, Any]:
        """获取知识库摘要"""
        with self._lock:
            return {
                'total_endpoints': len(self._endpoints),
                'high_value_endpoints': len(self.get_high_value_endpoints()),
                'total_findings': len(self._findings),
                'critical_findings': len([f for f in self._findings if f.severity == 'critical']),
                'high_findings': len([f for f in self._findings if f.severity == 'high']),
                'total_parameters': sum(len(p) for p in self._parameters.values()),
                'total_vulnerabilities': len(self._vulnerabilities),
                'total_sensitive_data': len(self._sensitive_data),
                'domains': list(self._domains),
            }
    
    def clear(self) -> None:
        """清空知识库"""
        with self._lock:
            self._endpoints.clear()
            self._findings.clear()
            self._parameters.clear()
            self._domains.clear()
            self._vulnerabilities.clear()
            self._sensitive_data.clear()
    
    def export(self) -> Dict[str, Any]:
        """导出知识库"""
        with self._lock:
            return {
                'endpoints': [
                    {
                        'path': ep.path,
                        'method': ep.method,
                        'source': ep.source,
                        'full_url': ep.full_url,
                        'status': ep.status,
                        'score': ep.score,
                        'tags': ep.tags,
                        'parameters': ep.parameters,
                        'discovered_at': ep.discovered_at,
                    }
                    for ep in self._endpoints.values()
                ],
                'findings': [f.to_dict() for f in self._findings],
                'vulnerabilities': self._vulnerabilities,
                'sensitive_data': self._sensitive_data,
                'summary': self.get_summary(),
            }
