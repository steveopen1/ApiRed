"""
API Specification Parser
OpenAPI/Swagger 和 WSDL/WADL 解析器
参考 Hacktricks API Security Testing
"""

import re
import json
import yaml
import logging
from typing import Dict, List, Any, Optional, Tuple, Set
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
        self._discovered_bases: Set[str] = set()
        self._scanned_specs: Set[str] = set()
    
    def _mark_base_discovered(self, base_url: str) -> bool:
        """
        标记 base_url 已发现，如果已经发现过则返回 False
        
        Returns:
            True 表示新发现，False 表示已存在
        """
        normalized = self._normalize_base_url(base_url)
        if normalized in self._discovered_bases:
            return False
        self._discovered_bases.add(normalized)
        return True
    
    def _mark_spec_scanned(self, spec_url: str) -> bool:
        """
        标记 spec_url 已扫描，如果已经扫描过则返回 False
        
        Returns:
            True 表示新扫描，False 表示已扫描
        """
        if spec_url in self._scanned_specs:
            return False
        self._scanned_specs.add(spec_url)
        return True
    
    def _normalize_base_url(self, url: str) -> str:
        """规范化 URL 用于去重"""
        parsed = urlparse(url.rstrip('/'))
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    
    def _is_already_discovered(self, base_url: str) -> bool:
        """检查 base_url 是否已发现"""
        normalized = self._normalize_base_url(base_url)
        return normalized in self._discovered_bases
    
    async def discover_and_parse(self, target_url: str) -> Optional[APISpecResult]:
        """
        发现并解析 API 规范
        
        流程:
        1. 检查缓存，已发现则跳过
        2. 从 URL 路径中提取可能的 base_path
        3. 使用发现的 base_path 发现 swagger
        4. 从多个渠道发现 API base path
        5. 解析规范，获取最终 base_url
        
        Args:
            target_url: 目标 URL (如 https://api.example.com)
        
        Returns:
            APISpecResult 或 None
        """
        if self._is_already_discovered(target_url):
            logger.debug(f"Base URL already discovered: {target_url}")
            return None
        
        parsed = urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        url_base_paths = self._extract_base_paths_from_url(target_url)
        
        for bp in url_base_paths:
            full_base = urljoin(base_url, bp)
            if not self._mark_base_discovered(full_base):
                continue
            spec = await self._discover_openapi(full_base)
            if spec:
                return spec
        
        api_base_path = await self._discover_api_base_path(target_url)
        
        if api_base_path:
            full_base = urljoin(base_url, api_base_path)
            if self._mark_base_discovered(full_base):
                spec = await self._discover_openapi(full_base)
                if spec:
                    return spec
        
        spec = await self._discover_wsdl(base_url)
        if spec:
            return spec
        
        for path in self.SWAGGER_PATHS:
            spec_url = urljoin(base_url, path)
            if not self._mark_spec_scanned(spec_url):
                continue
            spec = await self._discover_and_parse_spec(spec_url, base_url)
            if spec:
                return spec
        
        self._mark_base_discovered(base_url)
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
        从多个渠道发现 API base path
        
        渠道优先级:
        1. 响应头 (X-Forwarded-Host, Server, Location)
        2. robots.txt
        3. HTML/JS 中的 API 配置
        4. JavaScript 文件
        """
        parsed = urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        try:
            response = await self.http_client.request(target_url, 'GET')
            if response.status_code != 200:
                return None
            
            content = response.content
            headers = response.headers if hasattr(response, 'headers') else {}
            
            base_path = self._extract_from_headers(headers, base_url)
            if base_path:
                return base_path
            
            base_path = await self._extract_from_robots_txt(base_url)
            if base_path:
                return base_path
            
            base_path = self._extract_from_html_js(content, base_url)
            if base_path:
                return base_path
            
            js_urls = self._extract_js_urls(content, base_url)
            for js_url in js_urls[:5]:
                js_content = await self._fetch_js_content(js_url)
                if js_content:
                    base_path = self._extract_from_html_js(js_content, base_url)
                    if base_path:
                        return base_path
            
        except Exception as e:
            logger.debug(f"Failed to discover API base path from {target_url}: {e}")
        
        return None
    
    def _extract_from_headers(self, headers: Dict, base_url: str) -> Optional[str]:
        """从响应头提取 base path"""
        header_patterns = {
            'X-Forwarded-Host': r'(https?://[^/]+)',
            'X-Forwarded-Server': r'(https?://[^/]+)',
            'Server': r'(https?://[^/]+)',
            'Location': r'(https?://[^/]+[^"\']*)',
            'Content-Location': r'(https?://[^/]+[^"\']*)',
        }
        
        for header_name, pattern in header_patterns.items():
            header_value = headers.get(header_name, '')
            if header_value:
                matches = re.findall(pattern, header_value, re.IGNORECASE)
                for match in matches:
                    if match and match != base_url:
                        parsed = urlparse(match if match.startswith('http') else f'http://{match}')
                        if parsed.path and parsed.path != '/':
                            return parsed.path
        
        return None
    
    async def _extract_from_robots_txt(self, base_url: str) -> Optional[str]:
        """从 robots.txt 提取 API 路径"""
        robots_url = urljoin(base_url, '/robots.txt')
        try:
            response = await self.http_client.request(robots_url, 'GET')
            if response.status_code == 200:
                content = response.content
                api_patterns = [
                    r'Allow:\s*(/api[^"\s]*)',
                    r'Disallow:\s*(/api[^"\s]*)',
                    r'Sitemap:\s*(/api[^"\s]*)',
                ]
                for pattern in api_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches:
                        path = self._normalize_api_path(match)
                        if path and self._looks_like_api_path(path):
                            return path
        except Exception as e:
            logger.debug(f"Failed to fetch robots.txt: {e}")
        return None
    
    def _extract_from_html_js(self, content: str, base_url: str) -> Optional[str]:
        """从 HTML/JS 内容提取 API 配置"""
        patterns = [
            r'"(api[^"]*)"[^"]*baseURL[^"]*"([^"]*)"',
            r'"(baseURL|base_url|apiUrl)[^"]*"([^"]*)"',
            r'"(api|apiUrl)[^"]*"[^"]*"([^"]*)"',
            r'window\.API_URL\s*=\s*["\']([^"\']+)["\']',
            r'window\.BASE_URL\s*=\s*["\']([^"\']+)["\']',
            r'axios\.defaults\.baseURL\s*=\s*["\']([^"\']+)["\']',
            r'fetch\([^)]*baseURL[^)]*["\']([^"\']+)["\']',
            r'jQuery\.ajaxSettings\.baseURL\s*=\s*["\']([^"\']+)["\']',
            r'Vue\.http\.defaults\.baseURL\s*=\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    for m in match:
                        if m and self._looks_like_api_path(m):
                            normalized = self._normalize_api_path(m)
                            if normalized:
                                return normalized
                else:
                    if match and self._looks_like_api_path(match):
                        normalized = self._normalize_api_path(match)
                        if normalized:
                            return normalized
        
        api_matches = re.findall(r'["\'](/(?:api|v[0-9]+)[^"\']*)["\']', content)
        for api_match in api_matches[:10]:
            if self._looks_like_api_path(api_match):
                normalized = self._normalize_api_path(api_match)
                if normalized:
                    return normalized
        
        swagger_embed = re.findall(r'<iframe[^>]*src=["\']([^"\']*swagger[^"\']*)["\']', content, re.IGNORECASE)
        for embed_url in swagger_embed:
            parsed = urlparse(embed_url)
            path_parts = parsed.path.rsplit('/', 1)
            if len(path_parts) > 1:
                api_dir = path_parts[0]
                if self._looks_like_api_path(api_dir):
                    return self._normalize_api_path(api_dir)
        
        return None
    
    def _extract_js_urls(self, html_content: str, base_url: str) -> List[str]:
        """从 HTML 中提取 JavaScript 文件 URL"""
        js_urls = []
        
        script_patterns = [
            r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']',
            r'window\.\w+URL\s*=\s*["\']([^"\']+\.js[^"\']*)["\']',
            r'import\s+["\']([^"\']+\.js[^"\']*)["\']',
        ]
        
        for pattern in script_patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, str):
                    js_url = match if match.startswith('http') else urljoin(base_url, match)
                    if js_url not in js_urls:
                        js_urls.append(js_url)
        
        return js_urls
    
    async def _fetch_js_content(self, js_url: str) -> Optional[str]:
        """获取 JavaScript 文件内容"""
        try:
            response = await self.http_client.request(js_url, 'GET')
            if response.status_code == 200:
                return response.content
        except Exception as e:
            logger.debug(f"Failed to fetch JS {js_url}: {e}")
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
        """解析 WSDL 规范，提取 soap:address 中的真实地址"""
        endpoints = []
        vulnerabilities = []
        
        service_names = re.findall(r'<service[^>]*name=["\']([^"\']+)["\']', content, re.IGNORECASE)
        soap_actions = re.findall(r'<soap:operation[^>]*soapAction=["\']([^"\']+)["\']', content, re.IGNORECASE)
        
        soap_addresses = re.findall(r'<soap:address[^>]*location=["\']([^"\']+)["\']', content, re.IGNORECASE)
        if not soap_addresses:
            soap_addresses = re.findall(r'<address[^>]*location=["\']([^"\']+)["\']', content, re.IGNORECASE)
        
        soap_base_path = None
        for addr in soap_addresses:
            if addr and addr.startswith('http'):
                parsed = urlparse(addr)
                if parsed.path:
                    soap_base_path = parsed.path
                    base_url = f"{parsed.scheme}://{parsed.netloc}"
                    break
        
        if soap_base_path:
            wsdl_base = urljoin(base_url, soap_base_path)
        else:
            wsdl_base = base_url
        
        endpoints.append(APIEndpoint(
            path=wsdl_base,
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
