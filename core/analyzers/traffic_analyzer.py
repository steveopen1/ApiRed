"""
Traffic Analyzer - 流量分析器
分析API流量，学习正常行为模式，建立基线
"""

from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
import re


@dataclass
class ResponsePattern:
    """响应模式"""
    content_type: str
    status_codes: Set[int]
    schema_keys: Set[str] = field(default_factory=set)
    is_paginated: bool = False
    is_error_response: bool = False


@dataclass
class RequestPattern:
    """请求模式"""
    method: str
    path_pattern: str
    required_params: Set[str] = field(default_factory=set)
    optional_params: Set[str] = field(default_factory=set)
    auth_required: bool = False


@dataclass
class APIBehaviorBaseline:
    """API行为基线"""
    base_url: str
    total_requests: int = 0
    unique_endpoints: int = 0
    response_patterns: Dict[str, ResponsePattern] = field(default_factory=dict)
    request_patterns: Dict[str, RequestPattern] = field(default_factory=dict)
    common_params: Set[str] = field(default_factory=set)
    sensitive_endpoints: Set[str] = field(default_factory=set)
    auth_endpoints: Set[str] = field(default_factory=set)
    
    def is_sensitive_endpoint(self, path: str) -> bool:
        return path in self.sensitive_endpoints
    
    def is_auth_endpoint(self, path: str) -> bool:
        return path in self.auth_endpoints
    
    def get_response_pattern(self, path: str) -> Optional[ResponsePattern]:
        return self.response_patterns.get(path)


class TrafficAnalyzer:
    """流量分析器"""
    
    SENSITIVE_PATTERNS = [
        r'/admin', r'/user', r'/profile', r'/account',
        r'/password', r'/secret', r'/key', r'/token',
        r'/credential', r'/auth', r'/login', r'/config',
        r'/setting', r'/private', r'/api_key', r'/apikey'
    ]
    
    AUTH_PATTERNS = [
        r'/login', r'/signin', r'/auth', r'/token',
        r'/session', r'/logout', r'/register', r'/signup'
    ]
    
    PAGINATION_PATTERNS = [
        r'page', r'offset', r'limit', r'size',
        r'per_page', r'perPage', r'cursor'
    ]
    
    def __init__(self):
        self.baseline: Optional[APIBehaviorBaseline] = None
        self._request_history: List[Dict] = []
        self._response_history: List[Dict] = []
    
    def learn_from_response(
        self,
        path: str,
        method: str,
        status_code: int,
        content_type: str,
        content: Optional[str] = None
    ) -> None:
        """
        从响应中学习
        
        Args:
            path: API路径
            method: HTTP方法
            status_code: 状态码
            content_type: Content-Type
            content: 响应内容
        """
        key = f"{method}:{path}"
        
        if not self.baseline:
            from urllib.parse import urlparse
            parsed = urlparse(path)
            self.baseline = APIBehaviorBaseline(
                base_url=f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme else path
            )
        
        self.baseline.total_requests += 1
        
        if key not in self.baseline.response_patterns:
            self.baseline.response_patterns[key] = ResponsePattern(
                content_type=content_type,
                status_codes=set()
            )
        
        pattern = self.baseline.response_patterns[key]
        pattern.status_codes.add(status_code)
        
        if content_type:
            pattern.content_type = content_type
        
        if content:
            self._analyze_content_schema(key, content, pattern)
        
        if content and self._is_error_response(status_code, content):
            pattern.is_error_response = True
        
        self._response_history.append({
            'path': path,
            'method': method,
            'status_code': status_code,
            'content_type': content_type
        })
    
    def learn_from_request(
        self,
        path: str,
        method: str,
        params: Optional[Dict] = None
    ) -> None:
        """
        从请求中学习
        
        Args:
            path: API路径
            method: HTTP方法
            params: 请求参数
        """
        key = f"{method}:{path}"
        
        if not self.baseline:
            self.baseline = APIBehaviorBaseline(base_url="")
        
        self.baseline.unique_endpoints += 1
        
        if key not in self.baseline.request_patterns:
            self.baseline.request_patterns[key] = RequestPattern(
                method=method,
                path_pattern=path,
                required_params=set(),
                optional_params=set()
            )
        
        pattern = self.baseline.request_patterns[key]
        
        if params:
            for param_name in params.keys():
                self.baseline.common_params.add(param_name)
                
                if self._is_common_param(param_name):
                    pattern.optional_params.add(param_name)
                else:
                    pattern.required_params.add(param_name)
        
        path_lower = path.lower()
        if any(re.search(p, path_lower) for p in self.SENSITIVE_PATTERNS):
            self.baseline.sensitive_endpoints.add(key)
        
        if any(re.search(p, path_lower) for p in self.AUTH_PATTERNS):
            self.baseline.auth_endpoints.add(key)
            pattern.auth_required = True
    
    def _analyze_content_schema(
        self,
        key: str,
        content: str,
        pattern: ResponsePattern
    ) -> None:
        """分析响应内容的schema"""
        if not content:
            return
        
        try:
            if '{' in content and ':' in content:
                json_match = re.findall(r'["\']?(\w+)["\']?\s*:', content[:1000])
                pattern.schema_keys.update(json_match)
            
            if any(p in content.lower() for p in ['page', 'offset', 'limit']):
                pattern.is_paginated = True
        except Exception:
            pass
    
    def _is_error_response(self, status_code: int, content: str) -> bool:
        """判断是否为错误响应"""
        if status_code >= 400:
            return True
        
        error_indicators = [
            'error', 'exception', 'failed', 'failure',
            'invalid', 'unauthorized', 'forbidden', 'not found'
        ]
        
        content_lower = content.lower()[:500]
        return any(ind in content_lower for ind in error_indicators)
    
    def _is_common_param(self, param_name: str) -> bool:
        """判断是否为常见参数"""
        common_params = [
            'page', 'limit', 'offset', 'size', 'per_page',
            'sort', 'order', 'filter', 'q', 'query', 'search',
            'id', 'uuid', 'user_id', 'token', 'api_key'
        ]
        return param_name.lower() in common_params
    
    def should_test_endpoint(self, path: str, method: str) -> Tuple[bool, str]:
        """
        判断是否应该测试端点
        
        Returns:
            Tuple[bool, str]: (是否应该测试, 原因)
        """
        if not self.baseline:
            return True, "No baseline available"
        
        key = f"{method}:{path}"
        
        if key in self.baseline.response_patterns:
            pattern = self.baseline.response_patterns[key]
            
            if pattern.is_error_response:
                return False, "Endpoint consistently returns errors"
            
            if 404 in pattern.status_codes and len(pattern.status_codes) == 1:
                return False, "Endpoint consistently returns 404"
        
        return True, "Endpoint appears active"
    
    def get_baseline(self) -> Optional[APIBehaviorBaseline]:
        """获取学习到的基线"""
        return self.baseline
    
    def compare_with_baseline(
        self,
        path: str,
        method: str,
        response_content: str
    ) -> Dict[str, Any]:
        """
        与基线比较，检测异常
        
        Returns:
            Dict with 'is_anomaly', 'reason', 'confidence'
        """
        if not self.baseline:
            return {
                'is_anomaly': False,
                'reason': 'No baseline',
                'confidence': 0.0
            }
        
        key = f"{method}:{path}"
        
        if key not in self.baseline.response_patterns:
            return {
                'is_anomaly': False,
                'reason': 'New endpoint',
                'confidence': 0.5
            }
        
        pattern = self.baseline.response_patterns[key]
        
        if self._is_error_response(0, response_content):
            if not pattern.is_error_response:
                return {
                    'is_anomaly': True,
                    'reason': 'Response contains error indicators but baseline was successful',
                    'confidence': 0.7
                }
        
        schema_keys = set(re.findall(r'["\']?(\w+)["\']?\s*:', response_content[:500]))
        new_keys = schema_keys - pattern.schema_keys
        
        if new_keys and len(new_keys) > 2:
            return {
                'is_anomaly': True,
                'reason': f'Response schema differs: new keys {new_keys}',
                'confidence': 0.6
            }
        
        return {
            'is_anomaly': False,
            'reason': 'Response matches baseline',
            'confidence': 0.9
        }


def create_traffic_analyzer_from_endpoints(endpoints: List) -> TrafficAnalyzer:
    """
    从端点列表创建流量分析器
    
    Args:
        endpoints: APIEndpoint列表
        
    Returns:
        TrafficAnalyzer: 流量分析器
    """
    analyzer = TrafficAnalyzer()
    
    for endpoint in endpoints:
        if hasattr(endpoint, 'path') and hasattr(endpoint, 'method'):
            method = getattr(endpoint, 'method', 'GET')
            
            analyzer.learn_from_request(
                path=endpoint.path,
                method=method,
                params=getattr(endpoint, 'parameters', None)
            )
            
            if hasattr(endpoint, 'response_sample') and endpoint.response_sample:
                content_type = 'application/json'
                if '{' not in endpoint.response_sample:
                    content_type = 'text/html'
                
                analyzer.learn_from_response(
                    path=endpoint.path,
                    method=method,
                    status_code=200,
                    content_type=content_type,
                    content=endpoint.response_sample
                )
    
    return analyzer
