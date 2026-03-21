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
        """
        从Swagger/OpenAPI JSON/YAML提取API
        支持 Swagger 2.0, OpenAPI 3.0, 3.1
        """
        results = []

        try:
            data = json.loads(swagger_content)
        except json.JSONDecodeError:
            return results

        if 'swagger' in data:
            results.extend(cls._parse_swagger2(data))
        elif 'openapi' in data:
            results.extend(cls._parse_openapi3(data))

        return results

    @classmethod
    def _parse_swagger2(cls, data: Dict) -> List[APIFindResult]:
        """解析 Swagger 2.0"""
        results = []

        paths = data.get('paths', {})
        base_path = data.get('basePath', '')

        for path, methods in paths.items():
            full_path = base_path + path if base_path else path

            for method, details in methods.items():
                if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']:

                    parameters = details.get('parameters', [])
                    param_names = []
                    for param in parameters:
                        if isinstance(param, dict):
                            param_names.append(param.get('name', ''))

                    results.append(APIFindResult(
                        path=full_path,
                        method=method.upper(),
                        source_type="swagger2",
                        url_type="api_path"
                    ))

        return results

    @classmethod
    def _parse_openapi3(cls, data: Dict) -> List[APIFindResult]:
        """解析 OpenAPI 3.0/3.1"""
        results = []

        paths = data.get('paths', {})
        servers = data.get('servers', [])
        base_url = servers[0].get('url', '') if servers else ''

        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue

            for method, details in methods.items():
                if method.upper() not in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']:
                    continue

                if not isinstance(details, dict):
                    continue

                parameters = details.get('parameters', [])
                request_body = details.get('requestBody', {})

                param_names = []
                for param in parameters:
                    if isinstance(param, dict):
                        param_names.append(param.get('name', ''))

                if isinstance(request_body, dict):
                    content = request_body.get('content', {})
                    if 'application/json' in content:
                        schema = content['application/json'].get('schema', {})
                        param_names.extend(cls._extract_schema_params(schema))

                results.append(APIFindResult(
                    path=path,
                    method=method.upper(),
                    source_type="openapi3",
                    url_type="api_path"
                ))

        return results

    @classmethod
    def _extract_schema_params(cls, schema: Dict, prefix: str = '') -> List[str]:
        """从 OpenAPI schema 提取参数名"""
        params = []

        if not isinstance(schema, dict):
            return params

        if '$ref' in schema:
            return params

        properties = schema.get('properties', {})
        for prop_name in properties.keys():
            full_name = f"{prefix}{prop_name}" if prefix else prop_name
            params.append(full_name)

        additional_props = schema.get('additionalProperties')
        if isinstance(additional_props, dict):
            params.extend(cls._extract_schema_params(additional_props, prefix))

        return params

    @classmethod
    def find_swagger_endpoints(cls, target: str) -> List[str]:
        """
        查找可能的 Swagger 端点
        参考 0x727/ChkApi 的 Swagger 各版本解析
        """
        endpoints = [
            '/swagger-ui.html',
            '/swagger-ui/index.html',
            '/swagger-ui/',
            '/api-docs',
            '/api-docs/',
            '/swagger.json',
            '/swagger.yaml',
            '/v2/api-docs',
            '/v3/api-docs',
            '/doc.html',
            '/swagger/swagger-ui.html',
            '/api/swagger.json',
            '/api-docs.json',
            '/swagger/v2/swagger.json',
            '/swagger/v3/swagger.json',
            '/api/documentation',
            '/docs',
            '/documentation',
            '/openapi.json',
            '/openapi.yaml',
            '/openapi.yml',
        ]

        return [target.rstrip('/') + ep for ep in endpoints]


class BaseURLAnalyzer:
    """
    Base URL 分析器
    参考 0x727/ChkApi 的 Base URL 发现逻辑
    Base URL 可以理解为每个微服务的服务名称
    """

    BASE_URL_PATTERNS = [
        re.compile(r'''(?:baseUrl|baseURL|BASE_URL|API_BASE)\s*[:=]\s*['"`]([^'"`]+)['"`]'''),
        re.compile(r'''(?:apiUrl|apiURL|API_URL)\s*[:=]\s*['"`]([^'"`]+)['"`]'''),
        re.compile(r'''host\s*[:=]\s*['"`]([^'"`]+)['"`]''', re.IGNORECASE),
        re.compile(r'''origin\s*[:=]\s*['"`]([^'"`]+)['"`]''', re.IGNORECASE),
        re.compile(r'''domain\s*[:=]\s*['"`]([^'"`]+)['"`]''', re.IGNORECASE),
    ]

    SERVICE_PATH_PATTERNS = [
        re.compile(r'''/(?:api|v\d+|rest|service|gateway|g)/(?:[\w-]+)/(?:[\w-]+)''', re.IGNORECASE),
        re.compile(r'''/(?:[\w]+/){2,}(?:[\w]+)''', re.IGNORECASE),
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

    @classmethod
    def extract_base_from_auto_loaded(cls, url: str, load_url: str) -> Optional[str]:
        """
        从自动加载的URL提取Base URL
        例如: url=http://example.com, load_url=http://example.com/authControl
        则 authControl 是 Base URL
        """
        if not url or not load_url:
            return None

        parsed_main = urlparse(url)
        parsed_load = urlparse(load_url)

        if parsed_main.netloc != parsed_load.netloc:
            return None

        main_path = parsed_main.path.rstrip('/')
        load_path = parsed_load.path.rstrip('/')

        if load_path.startswith(main_path):
            remaining = load_path[len(main_path):].strip('/')
            if remaining and '/' not in remaining:
                return remaining

        return None

    @classmethod
    def extract_base_from_api_path(cls, api_path: str) -> Optional[str]:
        """
        从API路径提取Base URL
        例如: /ophApi/checkCode/getCheckCode -> ophApi 是 Base URL
        """
        if not api_path:
            return None

        path = api_path.strip('/')
        parts = path.split('/')

        if len(parts) >= 2:
            return parts[0]

        return None

    @classmethod
    def extract_base_from_paths(cls, paths: List[str]) -> List[str]:
        """
        从多个路径批量提取 Base URL
        返回所有发现的 Base URL
        """
        base_urls = set()

        for path in paths:
            base = cls.extract_base_from_api_path(path)
            if base:
                base_urls.add(base)

        return list(base_urls)

    @classmethod
    def build_service_urls(cls, base_urls: List[str], target: str) -> List[str]:
        """
        构建完整的服务URL列表
        用于后续API发现
        """
        parsed = urlparse(target)
        scheme = parsed.scheme
        netloc = parsed.netloc

        service_urls = []
        for base in base_urls:
            service_urls.append(f"{scheme}://{netloc}/{base}")

        return service_urls


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
