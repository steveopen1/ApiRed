"""
API Specification Parser
OpenAPI/Swagger 和 WSDL/WADL 解析器
参考 Hacktricks API Security Testing
"""

import re
import json
import yaml
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)


@dataclass
class APIEndpoint:
    """API 端点"""
    path: str
    method: str
    summary: str
    parameters: List[Dict]
    request_body: Optional[Dict]
    responses: Dict
    security: List[Dict]
    tags: List[str]


@dataclass
class APISpecResult:
    """API 规范解析结果"""
    spec_type: str
    version: str
    base_url: str
    api_base_path: str
    endpoints: List[APIEndpoint]
    security_schemes: Dict
    paths: List[str]
    parameters: List[str]
    vulnerabilities: List[Dict]


class APISpecParser:
    """
    API 规范解析器
    
    支持解析:
    1. OpenAPI/Swagger (JSON/YAML)
    2. WSDL (SOAP Web Services)
    3. WADL (REST Web Services)
    
    参考 Hacktricks:
    - https://book.hacktricks.xyz/web-security/api-submission-index
    """
    
    SWAGGER_PATHS = [
        '/swagger.json',
        '/swagger.yaml',
        '/swagger.yml',
        '/api-docs.json',
        '/api-docs.yaml',
        '/api-docs.yml',
        '/openapi.json',
        '/openapi.yaml',
        '/openapi.yml',
        '/api/swagger.json',
        '/swagger/api-docs',
        '/api/spec',
        '/api-docs',
        '/v1/api-docs',
        '/v2/api-docs',
        '/docs.json',
        '/api/swagger.yaml',
        '/api/openapi.yaml',
    ]
    
    WSDL_PATHS = [
        '?wsdl',
        '/soap/wsdl',
        '/services?wsdl',
        '/api.wsdl',
        '/soap/api.wsdl',
        '/services/soap/wsdl',
    ]
    
    SENSITIVE_ENDPOINTS = [
        'admin', 'user', 'login', 'auth', 'password', 'token',
        'api', 'key', 'secret', 'credential', 'config', 'settings',
        'dashboard', 'upload', 'download', 'delete', 'remove',
        'modify', 'edit', 'update', 'create', 'add', 'new',
    ]
    
    def __init__(self, http_client):
        self.http_client = http_client
    
    async def discover_and_parse(self, target_url: str) -> Optional[APISpecResult]:
        """
        发现并解析 API 规范
        
        流程:
        1. 先访问目标首页，提取 API base path
        2. 从 URL 路径中提取可能的 base_path
        3. 使用发现的 base_path 发现 swagger
        4. 解析规范，获取最终 base_url
        
        Args:
            target_url: 目标 URL (如 https://api.example.com)
        
        Returns:
            APISpecResult 或 None
        """
        parsed = urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        url_base_paths = self._extract_base_paths_from_url(target_url)
        
        for bp in url_base_paths:
            full_base = urljoin(base_url, bp)
            spec = await self._discover_openapi(full_base)
            if spec:
                return spec
        
        api_base_path = await self._discover_api_base_path(target_url)
        
        if api_base_path:
            full_base = urljoin(base_url, api_base_path)
            spec = await self._discover_openapi(full_base)
            if spec:
                return spec
        
        spec = await self._discover_wsdl(base_url)
        if spec:
            return spec
        
        for path in self.SWAGGER_PATHS:
            spec_url = urljoin(base_url, path)
            spec = await self._discover_and_parse_spec(spec_url, base_url)
            if spec:
                return spec
        
        return None
    
    def _extract_base_paths_from_url(self, url: str) -> List[str]:
        """
        从 URL 中提取可能的 base_path 列表
        
        例如: http://xxx.com/admin/jiankon-action/xxx.asp
        返回: ['/admin/jiankon-action/', '/admin/']
        """
        parsed = urlparse(url)
        path = parsed.path
        
        if not path or path == '/':
            return []
        
        base_paths = []
        parts = path.strip('/').split('/')
        
        for i in range(len(parts) - 1, 0, -1):
            bp = '/' + '/'.join(parts[:i]) + '/'
            base_paths.append(bp)
        
        return base_paths
    
    async def _discover_api_base_path(self, target_url: str) -> Optional[str]:
        """
        从目标网站发现 API base path
        
        通过分析 HTML/JavaScript 中的 API 配置来发现正确的 base path
        """
        try:
            response = await self.http_client.request(target_url, 'GET')
            if response.status_code != 200:
                return None
            
            content = response.content
            
            patterns = [
                r'"(api[^"]*)"[^"]*baseURL[^"]*"([^"]*)"',
                r'"(baseURL|base_url|apiUrl)[^"]*"([^"]*)"',
                r'"(api|apiUrl)[^"]*"[^"]*"([^"]*)"',
                r'window\.API_URL\s*=\s*["\']([^"\']+)["\']',
                r'window\.BASE_URL\s*=\s*["\']([^"\']+)["\']',
                r'axios\.defaults\.baseURL\s*=\s*["\']([^"\']+)["\']',
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    if isinstance(match, tuple) and len(match) >= 2:
                        api_path = match[1] if match[1] else match[0]
                    else:
                        api_path = match
                    if api_path and self._looks_like_api_path(api_path):
                        return self._normalize_api_path(api_path)
                    if isinstance(match, tuple):
                        for m in match:
                            if m and self._looks_like_api_path(m):
                                return self._normalize_api_path(m)
            
            if '/api/' in content or '/v1/' in content or '/v2/' in content:
                api_matches = re.findall(r'["\'](/(?:api|v[0-9]+)[^"\']*)["\']', content)
                for api_match in api_matches[:5]:
                    if self._looks_like_api_path(api_match):
                        return self._normalize_api_path(api_match)
            
        except Exception as e:
            logger.debug(f"Failed to discover API base path from {target_url}: {e}")
        
        return None
    
    def _looks_like_api_path(self, path: str) -> bool:
        """判断路径是否像 API 路径"""
        if not path:
            return False
        
        path_lower = path.lower()
        
        if 'swagger' in path_lower or 'api' in path_lower or 'v1' in path_lower or 'v2' in path_lower or 'v3' in path_lower:
            return True
        
        if path.startswith('/') and len(path) < 100:
            return True
        
        return False
    
    def _normalize_api_path(self, path: str) -> str:
        """规范化 API 路径"""
        path = path.strip()
        
        if path.startswith('http://') or path.startswith('https://'):
            parsed = urlparse(path)
            return parsed.path
        
        if not path.startswith('/'):
            path = '/' + path
        
        path = re.sub(r'[/]+', '/', path)
        
        if path.endswith('/'):
            path = path[:-1]
        
        return path
    
    async def _discover_openapi(self, base_url: str) -> Optional[APISpecResult]:
        """发现并解析 OpenAPI/Swagger 规范"""
        for path in self.SWAGGER_PATHS:
            spec_url = urljoin(base_url, path)
            spec = await self._discover_and_parse_spec(spec_url, base_url)
            if spec:
                return spec
        
        return None
    
    async def _discover_and_parse_spec(self, spec_url: str, original_base: str) -> Optional[APISpecResult]:
        """尝试获取并解析规范"""
        try:
            response = await self.http_client.request(spec_url, 'GET')
            if response.status_code != 200:
                return None
            
            content = response.content
            
            if not content or len(content) < 50:
                return None
            
            try:
                if spec_url.endswith('.json') or content.strip().startswith('{'):
                    spec = json.loads(content)
                else:
                    spec = yaml.safe_load(content)
            except:
                return None
            
            if not self._is_openapi_spec(spec):
                return None
            
            return self._parse_openapi(spec, original_base)
            
        except Exception as e:
            logger.debug(f"Failed to fetch/parse spec from {spec_url}: {e}")
            return None
    
    async def _discover_wsdl(self, base_url: str) -> Optional[APISpecResult]:
        """发现并解析 WSDL 规范"""
        for path in self.WSDL_PATHS:
            spec_url = urljoin(base_url, path)
            try:
                response = await self.http_client.request(spec_url, 'GET')
                if response.status_code == 200:
                    content = response.content
                    if '<wsdl' in content.lower() or 'soap' in content.lower():
                        return self._parse_wsdl(content, base_url)
            except Exception as e:
                logger.debug(f"Failed to fetch WSDL from {spec_url}: {e}")
        
        return None
    
    def _is_openapi_spec(self, spec: Any) -> bool:
        """检查是否为 OpenAPI 规范"""
        if not isinstance(spec, dict):
            return False
        return any(key in spec for key in ['openapi', 'swagger', 'paths', 'components'])
    
    def _parse_openapi(self, spec: Dict, base_url: str) -> APISpecResult:
        """解析 OpenAPI/Swagger 规范"""
        spec_type = 'openapi' if 'openapi' in spec else 'swagger'
        version = spec.get('openapi', spec.get('swagger', 'unknown'))
        
        servers = spec.get('servers', [])
        if servers and isinstance(servers, list):
            server_info = servers[0]
            if isinstance(server_info, dict):
                server_url = server_info.get('url', base_url)
            else:
                server_url = str(server_info)
            parsed_server = urlparse(server_url)
            api_base_path = parsed_server.path if parsed_server.path else '/'
            final_base = f"{parsed_server.scheme}://{parsed_server.netloc}" if parsed_server.scheme else base_url
            if not final_base or final_base == '://':
                final_base = base_url
                api_base_path = server_info.get('url', '/') if isinstance(server_info, dict) else '/'
        else:
            final_base = base_url
            api_base_path = '/'
        
        endpoints = []
        paths = []
        parameters = set()
        vulnerabilities = []
        
        security_schemes = spec.get('components', {}).get('securitySchemes', {})
        
        for path, path_item in spec.get('paths', {}).items():
            paths.append(path)
            
            if not path.startswith('/'):
                path = '/' + path
            
            for method, operation in path_item.items():
                if method not in ['get', 'post', 'put', 'delete', 'patch', 'options', 'head']:
                    continue
                
                op_params = operation.get('parameters', [])
                for param in op_params:
                    if isinstance(param, dict) and param.get('name'):
                        parameters.add(param['name'])
                
                endpoint = APIEndpoint(
                    path=path,
                    method=method.upper(),
                    summary=operation.get('summary', ''),
                    parameters=op_params,
                    request_body=operation.get('requestBody'),
                    responses=operation.get('responses', {}),
                    security=operation.get('security', []),
                    tags=operation.get('tags', [])
                )
                endpoints.append(endpoint)
                
                if self._is_sensitive_endpoint(path):
                    vulnerabilities.append({
                        'type': 'Sensitive Endpoint',
                        'path': path,
                        'method': method.upper(),
                        'severity': 'medium',
                        'description': f'Sensitive endpoint exposed in API spec: {path}'
                    })
                
                if not operation.get('security') and security_schemes:
                    vulnerabilities.append({
                        'type': 'Missing Authentication',
                        'path': path,
                        'method': method.upper(),
                        'severity': 'high',
                        'description': f'Endpoint has no security scheme defined: {path}'
                    })
        
        return APISpecResult(
            spec_type=spec_type,
            version=version,
            base_url=final_base,
            api_base_path=api_base_path,
            endpoints=endpoints,
            security_schemes=security_schemes,
            paths=paths,
            parameters=list(parameters),
            vulnerabilities=vulnerabilities
        )
    
    def _parse_wsdl(self, content: str, base_url: str) -> APISpecResult:
        """解析 WSDL 规范"""
        endpoints = []
        vulnerabilities = []
        
        service_names = re.findall(r'<service[^>]*name=["\']([^"\']+)["\']', content, re.IGNORECASE)
        soap_actions = re.findall(r'<soap:operation[^>]*soapAction=["\']([^"\']+)["\']', content, re.IGNORECASE)
        
        endpoints.append(APIEndpoint(
            path=base_url,
            method='SOAP',
            summary=f'SOAP Service: {", ".join(service_names) or "Unknown"}',
            parameters=[],
            request_body=None,
            responses={},
            security=[],
            tags=['SOAP']
        ))
        
        if not soap_actions:
            vulnerabilities.append({
                'type': 'WSDL Information Disclosure',
                'severity': 'low',
                'description': 'WSDL endpoint is publicly accessible'
            })
        
        return APISpecResult(
            spec_type='wsdl',
            version='1.0',
            base_url=base_url,
            api_base_path='/',
            endpoints=endpoints,
            security_schemes={},
            paths=[base_url],
            parameters=[],
            vulnerabilities=vulnerabilities
        )
    
    def _is_sensitive_endpoint(self, path: str) -> bool:
        """检查是否为敏感端点"""
        path_lower = path.lower()
        return any(sensitive in path_lower for sensitive in self.SENSITIVE_ENDPOINTS)
    
    def extract_endpoints_for_testing(self, spec: APISpecResult) -> List[Dict]:
        """从解析的规范中提取可用于测试的端点"""
        testable_endpoints = []
        
        for endpoint in spec.endpoints:
            full_url = urljoin(spec.base_url + spec.api_base_path, endpoint.path)
            
            test_info = {
                'url': full_url,
                'method': endpoint.method,
                'parameters': endpoint.parameters,
                'request_body': endpoint.request_body,
                'security': endpoint.security,
                'summary': endpoint.summary,
                'tags': endpoint.tags,
                'spec_base': spec.base_url,
                'api_path': spec.api_base_path,
            }
            testable_endpoints.append(test_info)
        
        return testable_endpoints
