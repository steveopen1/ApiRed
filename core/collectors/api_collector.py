"""
API Collector Module
API采集模块
"""

import re
import json
from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin


@dataclass
class APIFindResult:
    """API发现结果"""
    path: str
    method: str = "GET"
    source_type: str = "regex"
    base_url: str = ""
    context: Optional[str] = None
    url_type: str = "api_path"


class APIRouter:
    """API路由提取器"""
    
    API_PATTERNS = {
        'axios': re.compile(r'''
            (?:axios|request)\s*[.(]?\s*(?:get|post|put|delete|patch)\s*\(?
            ['"`]([^'"`]+)['"`]
        ''', re.VERBOSE | re.IGNORECASE),
        
        'fetch': re.compile(r'''
            fetch\s*\(\s*['"`]([^'"`]+)['"`]
        ''', re.VERBOSE),
        
        'jquery': re.compile(r'''
            \.\s*(?:get|post|ajax)\s*\(?
            ['"`]([^'"`]+)['"`]
        ''', re.VERBOSE | re.IGNORECASE),
        
        'router': re.compile(r'''
            (?:router|route|Route)\s*[.(]?\s*
            (?:get|post|put|delete|patch)\s*\(?
            ['"`]([^'"`]+)['"`]
        ''', re.VERBOSE | re.IGNORECASE),
        
        'path': re.compile(r'''
            ['"`](?:/api|/v\d+/|/rest)[^\s'"`]+['"`]
        ''', re.VERBOSE | re.IGNORECASE),
    }
    
    HTTP_METHODS = ['get', 'post', 'put', 'delete', 'patch', 'options', 'head']
    
    @classmethod
    def extract_apis(cls, js_content: str) -> List[APIFindResult]:
        """从JS内容提取API"""
        results = []
        found_paths: Set[str] = set()
        
        for name, pattern in cls.API_PATTERNS.items():
            matches = pattern.findall(js_content)
            for path in matches:
                if path and path not in found_paths:
                    found_paths.add(path)
                    
                    method = "GET"
                    for m in cls.HTTP_METHODS:
                        if m in path.lower():
                            method = m.upper()
                            break
                    
                    results.append(APIFindResult(
                        path=path,
                        method=method,
                        source_type=f"js_{name}",
                        url_type="api_path"
                    ))
        
        return results
    
    @classmethod
    def extract_from_swagger(cls, swagger_content: str) -> List[APIFindResult]:
        """从Swagger JSON提取API"""
        results = []
        
        try:
            data = json.loads(swagger_content)
            paths = data.get('paths', {})
            
            for path, methods in paths.items():
                for method, details in methods.items():
                    if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                        results.append(APIFindResult(
                            path=path,
                            method=method.upper(),
                            source_type="swagger",
                            url_type="api_path"
                        ))
        except json.JSONDecodeError:
            pass
        
        return results


class BaseURLAnalyzer:
    """Base URL分析器"""
    
    BASE_URL_PATTERNS = [
        re.compile(r'''(?:baseUrl|baseURL|BASE_URL|API_BASE)\s*[:=]\s*['"`]([^'"`]+)['"`]'''),
        re.compile(r'''(?:apiUrl|apiURL|API_URL)\s*[:=]\s*['"`]([^'"`]+)['"`]'''),
        re.compile(r'''host\s*[:=]\s*['"`]([^'"`]+)['"`]''', re.IGNORECASE),
    ]
    
    @classmethod
    def extract_base_urls(cls, js_content: str) -> List[str]:
        """提取Base URL"""
        base_urls = []
        
        for pattern in cls.BASE_URL_PATTERNS:
            matches = pattern.findall(js_content)
            base_urls.extend(matches)
        
        return list(set(base_urls))
    
    @classmethod
    def extract_from_url(cls, url: str) -> str:
        """从完整URL提取Base URL"""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"


class ServiceAnalyzer:
    """服务分析器"""
    
    SERVICE_KEYWORDS = ['api', 'gateway', 'service', 'auth', 'admin', 'user', 
                       'order', 'product', 'payment', 'ums', 'bms', 'cms']
    
    @classmethod
    def extract_service_key(cls, url: str, api_path: str = "") -> str:
        """提取服务标识"""
        parts = []
        
        if url:
            parsed = urlparse(url)
            path_parts = [p for p in parsed.path.split('/') if p]
            parts.extend(path_parts)
        
        if api_path:
            path_parts = [p for p in api_path.split('/') if p]
            parts.extend(path_parts)
        
        service_parts = []
        for part in parts:
            for keyword in cls.SERVICE_KEYWORDS:
                if keyword in part.lower():
                    service_parts.append(part)
                    break
        
        return '-'.join(service_parts[:3]) if service_parts else 'unknown'
    
    @classmethod
    def group_by_service(cls, apis: List[Dict]) -> Dict[str, List[Dict]]:
        """按服务分组"""
        services: Dict[str, List[Dict]] = {}
        
        for api in apis:
            service_key = api.get('service_key', 'unknown')
            if service_key not in services:
                services[service_key] = []
            services[service_key].append(api)
        
        return services


class APIAggregator:
    """API聚合器"""
    
    def __init__(self):
        self.apis: Dict[str, APIFindResult] = {}
        self.sources: Dict[str, List[Dict]] = {}
    
    def add_api(self, api: APIFindResult, source_info: Optional[Dict] = None):
        """添加API"""
        key = f"{api.method}:{api.path}"
        
        if key not in self.apis:
            self.apis[key] = api
            self.sources[key] = []
        
        if source_info:
            self.sources[key].append(source_info)
    
    def get_all(self) -> List[APIFindResult]:
        """获取所有API"""
        return list(self.apis.values())
    
    def get_by_source(self, source_type: str) -> List[APIFindResult]:
        """按来源筛选"""
        results = []
        for key, api in self.apis.items():
            if api.source_type == source_type:
                results.append(api)
        return results
    
    def merge(self, other: 'APIAggregator'):
        """合并另一个聚合器"""
        for api in other.get_all():
            self.add_api(api)


class APIPathCombiner:
    """API路径组合器"""
    
    COMMON_PREFIXES = ['/api', '/v1', '/v2', '/v3', '/rest', '/restapi', '/service']
    
    @classmethod
    def normalize_path(cls, path: str) -> str:
        """规范化路径"""
        path = path.strip()
        
        for prefix in cls.COMMON_PREFIXES:
            if path.startswith(prefix):
                return path
        
        if not path.startswith('/'):
            path = '/' + path
        
        return path
    
    @classmethod
    def combine_base_and_path(cls, base_url: str, api_path: str) -> str:
        """组合Base URL和API路径"""
        if not base_url:
            return api_path
        
        if not api_path:
            return base_url
        
        base = base_url.rstrip('/')
        path = api_path.lstrip('/')
        
        return f"{base}/{path}"
    
    @classmethod
    def extract_api_without_prefix(cls, path: str) -> str:
        """提取去除前缀的API路径"""
        normalized = path
        
        for prefix in cls.COMMON_PREFIXES:
            if normalized.startswith(prefix):
                parts = normalized[len(prefix):].lstrip('/')
                if parts:
                    return parts
                return normalized
        
        return normalized
