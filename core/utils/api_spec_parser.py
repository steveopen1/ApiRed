"""
API Specification Parser
OpenAPI/Swagger 和 WSDL/WADL 解析器
参考 Hacktricks API Security Testing
"""

import re
import json
import yaml
import logging
from typing import Dict, List, Any, Optional, Set
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
    spec_type: str  # openapi, swagger, wsdl, wadl
    version: str
    base_url: str
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
    ]
    
    WSDL_PATHS = [
        '?wsdl',
        '/soap/wsdl',
        '/services?wsdl',
        '/api.wsdl',
        '/soap/api.wsdl',
    ]
    
    SENSITIVE_ENDPOINTS = [
        'admin', 'user', 'login', 'auth', 'password', 'token',
        'api', 'key', 'secret', 'credential', 'config', 'settings',
        'dashboard', 'upload', 'download', 'delete', 'remove',
        'modify', 'edit', 'update', 'create', 'add', 'new',
    ]
    
    def __init__(self, http_client):
        self.http_client = http_client
    
    async def discover_and_parse(self, base_url: str) -> Optional[APISpecResult]:
        """
        发现并解析 API 规范
        
        Args:
            base_url: 目标 API 的基础 URL
        
        Returns:
            APISpecResult 或 None
        """
        spec = await self._discover_openapi(base_url)
        if spec:
            return spec
        
        spec = await self._discover_wsdl(base_url)
        if spec:
            return spec
        
        return None
    
    async def _discover_openapi(self, base_url: str) -> Optional[APISpecResult]:
        """发现并解析 OpenAPI/Swagger 规范"""
        for path in self.SWAGGER_PATHS:
            spec_url = urljoin(base_url, path)
            try:
                response = await self.http_client.request(spec_url, 'GET')
                if response.status_code == 200:
                    content = response.content
                    try:
                        if path.endswith('.json') or 'json' in content[:10]:
                            spec = json.loads(content)
                        else:
                            spec = yaml.safe_load(content)
                        
                        if self._is_openapi_spec(spec):
                            return self._parse_openapi(spec, base_url)
                    except Exception as e:
                        logger.debug(f"Failed to parse OpenAPI from {spec_url}: {e}")
            except Exception as e:
                logger.debug(f"Failed to fetch {spec_url}: {e}")
        
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
    
    def _is_openapi_spec(self, spec: Dict) -> bool:
        """检查是否为 OpenAPI 规范"""
        if not isinstance(spec, dict):
            return False
        return any(key in spec for key in ['openapi', 'swagger', 'paths', 'components'])
    
    def _parse_openapi(self, spec: Dict, base_url: str) -> APISpecResult:
        """解析 OpenAPI/Swagger 规范"""
        spec_type = 'openapi' if 'openapi' in spec else 'swagger'
        version = spec.get('openapi', spec.get('swagger', 'unknown'))
        
        endpoints = []
        paths = []
        parameters = set()
        vulnerabilities = []
        
        base_path = spec.get('servers', [{}])[0].get('url', base_url) if spec.get('servers') else base_url
        
        security_schemes = spec.get('components', {}).get('securitySchemes', {})
        
        for path, path_item in spec.get('paths', {}).items():
            paths.append(path)
            
            for method, operation in path_item.items():
                if method not in ['get', 'post', 'put', 'delete', 'patch', 'options', 'head']:
                    continue
                
                op_params = operation.get('parameters', [])
                for param in op_params:
                    if param.get('name'):
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
        
        return APISpecResult(
            spec_type=spec_type,
            version=version,
            base_url=base_path,
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
        
        service_names = re.findall(r'<service[^>]*name=["\']([^"\']+)["\']', content)
        port_names = re.findall(r'<port[^>]*name=["\']([^"\']+)["\']', content)
        binding_names = re.findall(r'<binding[^>]*name=["\']([^"\']+)["\']', content)
        
        soap_actions = re.findall(r'<soap:operation[^>]*soapAction=["\']([^"\']+)["\']', content)
        
        endpoints.append(APIEndpoint(
            path=base_url,
            method='SOAP',
            summary=f'SOAP Service: {", ".join(service_names)}',
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
        """
        从解析的规范中提取可用于测试的端点
        
        Returns:
            可测试的端点列表
        """
        testable_endpoints = []
        
        for endpoint in spec.endpoints:
            test_info = {
                'url': urljoin(spec.base_url, endpoint.path),
                'method': endpoint.method,
                'parameters': endpoint.parameters,
                'request_body': endpoint.request_body,
                'security': endpoint.security,
                'summary': endpoint.summary,
                'tags': endpoint.tags
            }
            testable_endpoints.append(test_info)
        
        return testable_endpoints
