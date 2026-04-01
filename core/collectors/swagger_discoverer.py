"""
Swagger/OpenAPI 自动发现模块

支持发现和解析:
- Swagger 2.0
- OpenAPI 3.0/3.1
- 自动从 HTML 页面中发现 API 文档链接
- 支持 JSON 和 YAML 格式
"""

import re
import json
import yaml  # type: ignore
import logging
from typing import List, Dict, Set, Optional, Any, Tuple
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class SwaggerVersion(Enum):
    """Swagger/OpenAPI 版本"""
    SWAGGER_2 = "swagger_2"
    OPENAPI_3_0 = "openapi_3_0"
    OPENAPI_3_1 = "openapi_3_1"
    UNKNOWN = "unknown"


@dataclass
class SwaggerEndpoint:
    """从 Swagger 文档中提取的端点"""
    path: str
    method: str
    summary: str = ""
    description: str = ""
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    request_body: Optional[Dict[str, Any]] = None
    responses: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    security: List[Dict[str, List[str]]] = field(default_factory=list)
    deprecated: bool = False
    operation_id: str = ""


@dataclass
class SwaggerDoc:
    """Swagger/OpenAPI 文档"""
    url: str
    version: SwaggerVersion
    title: str = ""
    description: str = ""
    base_path: str = ""
    host: str = ""
    schemes: List[str] = field(default_factory=list)
    endpoints: List[SwaggerEndpoint] = field(default_factory=list)
    tags: List[Dict[str, str]] = field(default_factory=list)
    security_definitions: Dict[str, Any] = field(default_factory=dict)
    url_prefix: str = ""


class SwaggerDiscoverer:
    """
    Swagger/OpenAPI 自动发现器
    
    功能:
    1. 从 HTML 页面中发现 Swagger 文档链接
    2. 解析 Swagger/OpenAPI 文档
    3. 提取 API 端点信息
    """

    SWAGGER_INDICATORS = [
        r'swagger-ui',
        r'api-docs',
        r'swagger-resources',
        r'/swagger-ui\.',
        r'#/definitions/',
        r'"swagger"',
        r'"openapi"',
    ]

    SWAGGER_URL_PATTERNS = [
        r'/swagger[^/]*\.json',
        r'/api-docs[^/]*',
        r'/swagger-ui\.html',
        r'/docs',
        r'/api/documentation',
        r'/api/swagger',
        r'/v2/api-docs',
        r'/v3/api-docs',
        r'/swagger/index\.html',
        r'/swagger-ui/',
        r'/api/swagger-ui\.html',
        r'/api-docs',
        r'/openapi\.json',
        r'/openapi\.yaml',
        r'/openapi\.yml',
    ]

    COMMON_SWAGGER_PATHS = [
        '/swagger-ui.html',
        '/swagger-ui/index.html',
        '/swagger-ui/swagger-ui-bundle.js',
        '/api-docs',
        '/api-docs/',
        '/v2/api-docs',
        '/v3/api-docs',
        '/v3/api-docs/',
        '/swagger/doc.json',
        '/swagger/resources',
        '/api/swagger',
        '/api/swagger.json',
        '/openapi/fmn.json',
        '/femn/api-docs',
        '/asset/swagger-ui',
        '/component/clue/clueStatic/swagger',
        '/eiap-openapi/swagger',
        '/eiap-openapi/fmn.json',
    ]

    def __init__(self, http_client=None):
        self.http_client = http_client
        self.discovered_docs: List[SwaggerDoc] = []

    VERSION_PATTERNS = [
        r'^v\d+$',
        r'^api-docs$',
        r'^swagger$',
        r'^swagger\.json$',
        r'^openapi\.json$',
        r'^openapi\.yaml$',
        r'^openapi\.yml$',
        r'^api-docs\.json$',
        r'^swagger\.yaml$',
        r'^swagger\.yml$',
    ]

    def _extract_url_prefix(self, url: str) -> str:
        """
        从 Swagger URL 中提取父路径前缀

        例如:
        - /gateway/v2/api-docs -> /gateway
        - /api/v1/swagger.json -> /api
        - /admin/swagger-ui.html -> /admin
        - /v2/api-docs -> ""

        算法:
        1. 解析 URL 获取路径
        2. 识别版本标识 (v1, v2, v3, api-docs, swagger 等)
        3. 版本标识之前的部分就是父路径前缀

        Returns:
            父路径前缀，如 "/gateway" 或 ""
        """
        if not url:
            return ""

        parsed = urlparse(url)
        path = parsed.path.strip('/')

        if not path:
            return ""

        parts = path.split('/')

        if len(parts) < 2:
            return ""

        for i, part in enumerate(parts):
            for pattern in self.VERSION_PATTERNS:
                if re.match(pattern, part, re.IGNORECASE):
                    if i > 0:
                        return '/' + '/'.join(parts[:i])
                    return ""

        last_part = parts[-1].lower()
        for pattern in self.VERSION_PATTERNS:
            if re.match(pattern, last_part, re.IGNORECASE):
                if len(parts) > 1:
                    return '/' + '/'.join(parts[:-1])
                return ""

        if len(parts) > 1:
            return '/' + '/'.join(parts[:-1])

        return ""

    async def discover_from_html(self, html_content: str, base_url: str) -> List[str]:
        """
        从 HTML 内容中发现 Swagger 文档链接
        
        Args:
            html_content: HTML 内容
            base_url: 基础 URL
            
        Returns:
            发现的 Swagger 文档 URL 列表
        """
        swagger_urls = set()
        
        for pattern in self.SWAGGER_URL_PATTERNS:
            regex = f'<[^>]*href=["\']([^"\']*{pattern}[^"\']*)["\']'
            for match in re.finditer(regex, html_content, re.IGNORECASE):
                url = match.group(1)
                if url:
                    full_url = urljoin(base_url, url)
                    swagger_urls.add(full_url)
            
            regex = f'src=["\']([^"\']*{pattern}[^"\']*)["\']'
            for match in re.finditer(regex, html_content, re.IGNORECASE):
                url = match.group(1)
                if url:
                    full_url = urljoin(base_url, url)
                    swagger_urls.add(full_url)
        
        for pattern in self.SWAGGER_INDICATORS:
            if re.search(pattern, html_content, re.IGNORECASE):
                for common_path in self.COMMON_SWAGGER_PATHS:
                    full_url = urljoin(base_url, common_path)
                    swagger_urls.add(full_url)
                break
        
        return list(swagger_urls)

    async def discover_common_paths(self, base_url: str) -> List[str]:
        """
        尝试访问常见的 Swagger 路径
        
        Args:
            base_url: 基础 URL
            
        Returns:
            可访问的 Swagger 文档 URL 列表
        """
        accessible = []
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        for path in self.COMMON_SWAGGER_PATHS:
            url = base + path
            try:
                if self.http_client:
                    resp = await self.http_client.request(url, timeout=5)
                    if resp and resp.status_code == 200:
                        content_type = resp.headers.get('Content-Type', '')
                        if 'json' in content_type or 'yaml' in content_type or 'html' in content_type:
                            accessible.append(url)
                        text = resp.text if hasattr(resp, 'text') else ''
                        if 'swagger' in text.lower() or 'openapi' in text.lower():
                            if url not in accessible:
                                accessible.append(url)
            except Exception:
                pass
        
        return accessible

    async def fetch_and_parse(self, url: str) -> Optional[SwaggerDoc]:
        """
        获取并解析 Swagger 文档
        
        Args:
            url: Swagger 文档 URL
            
        Returns:
            解析后的 SwaggerDoc 对象
        """
        try:
            if not self.http_client:
                return None
            
            resp = await self.http_client.request(url, timeout=10)
            if not resp or resp.status_code != 200:
                return None
            
            content = resp.text if hasattr(resp, 'text') else ''
            content_type = resp.headers.get('Content-Type', '')
            
            swagger_doc = None
            if 'json' in content_type or url.endswith('.json'):
                swagger_doc = self._parse_json(content, url)
            elif 'yaml' in content_type or 'yml' in content_type or url.endswith(('.yaml', '.yml')):
                swagger_doc = self._parse_yaml(content, url)
            elif 'html' in content_type:
                swagger_urls = await self.discover_from_html(content, url)
                for doc_url in swagger_urls:
                    if doc_url.endswith('.json') or 'json' in doc_url:
                        doc = await self.fetch_and_parse(doc_url)
                        if doc:
                            return doc
                json_urls = re.findall(r'["\']([^"\']*\.json[^"\']*)["\']', content)
                for json_url in json_urls[:10]:
                    if 'swagger' in json_url.lower() or 'api-docs' in json_url.lower():
                        full_url = urljoin(url, json_url)
                        doc = await self.fetch_and_parse(full_url)
                        if doc:
                            return doc
            
            if not swagger_doc:
                try:
                    swagger_doc = self._parse_json(content, url)
                except Exception:
                    try:
                        swagger_doc = self._parse_yaml(content, url)
                    except Exception:
                        pass
            
            if swagger_doc:
                self.discovered_docs.append(swagger_doc)
            
            return swagger_doc
            
        except Exception as e:
            logger.debug(f"Failed to fetch/parse swagger from {url}: {e}")
            return None

    def _parse_json(self, content: str, url: str) -> Optional[SwaggerDoc]:
        """解析 JSON 格式的 Swagger 文档"""
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return None
        
        if not data:
            return None
        
        if 'swagger' in data and data['swagger'].startswith('2'):
            return self._parse_swagger_2(data, url)
        elif 'openapi' in data and data['openapi'].startswith('3'):
            return self._parse_openapi_3(data, url)
        
        return None

    def _parse_yaml(self, content: str, url: str) -> Optional[SwaggerDoc]:
        """解析 YAML 格式的 Swagger 文档"""
        try:
            data = yaml.safe_load(content)
        except Exception:
            return None
        
        if not data:
            return None
        
        if 'swagger' in data and str(data['swagger']).startswith('2'):
            return self._parse_swagger_2(data, url)
        elif 'openapi' in data and str(data['openapi']).startswith('3'):
            return self._parse_openapi_3(data, url)
        
        return None

    def _apply_url_prefix(self, path: str, url_prefix: str, base_path: str) -> str:
        """
        将 URL 前缀应用到路径

        优先级: url_prefix > base_path > path

        例如:
        - path="/actuator/env", url_prefix="/gateway", base_path="/" -> "/gateway/actuator/env"
        - path="/actuator/env", url_prefix="", base_path="/api" -> "/api/actuator/env"
        - path="/actuator/env", url_prefix="", base_path="" -> "/actuator/env"
        """
        if not path:
            return path

        if not path.startswith('/'):
            path = '/' + path

        if url_prefix:
            return url_prefix + path

        if base_path:
            if not base_path.startswith('/'):
                base_path = '/' + base_path
            return base_path + path

        return path

    def _parse_swagger_2(self, data: Dict, url: str) -> SwaggerDoc:
        """解析 Swagger 2.0 文档"""
        version = SwaggerVersion.SWAGGER_2

        url_prefix = self._extract_url_prefix(url)
        base_path = data.get('basePath', '')

        doc = SwaggerDoc(
            url=url,
            version=version,
            title=data.get('info', {}).get('title', ''),
            description=data.get('info', {}).get('description', ''),
            base_path=base_path,
            host=data.get('host', ''),
            schemes=data.get('schemes', []),
            security_definitions=data.get('securityDefinitions', {}),
            tags=data.get('tags', []),
            url_prefix=url_prefix,
        )

        paths = data.get('paths', {})
        definitions = data.get('definitions', {})

        for path, path_item in paths.items():
            full_path = self._apply_url_prefix(path, url_prefix, base_path)
            for method, operation in path_item.items():
                if method not in ('get', 'post', 'put', 'delete', 'patch', 'head', 'options'):
                    continue

                if not isinstance(operation, dict):
                    continue

                endpoint = SwaggerEndpoint(
                    path=full_path,
                    method=method.upper(),
                    summary=operation.get('summary', ''),
                    description=operation.get('description', ''),
                    operation_id=operation.get('operationId', ''),
                    deprecated=operation.get('deprecated', False),
                    parameters=operation.get('parameters', []),
                    responses=operation.get('responses', {}),
                    tags=operation.get('tags', []),
                    security=operation.get('security', data.get('security', [])),
                )

                if 'requestBody' in operation:
                    endpoint.request_body = operation['requestBody']

                doc.endpoints.append(endpoint)

        return doc

    def _parse_openapi_3(self, data: Dict, url: str) -> SwaggerDoc:
        """解析 OpenAPI 3.0/3.1 文档"""
        version_str = str(data.get('openapi', '3.0'))
        if version_str.startswith('3.1'):
            version = SwaggerVersion.OPENAPI_3_1
        else:
            version = SwaggerVersion.OPENAPI_3_0

        servers = data.get('servers', [])
        host = servers[0].get('url', '') if servers else ''

        url_prefix = self._extract_url_prefix(url)

        doc = SwaggerDoc(
            url=url,
            version=version,
            title=data.get('info', {}).get('title', ''),
            description=data.get('info', {}).get('description', ''),
            host=host,
            tags=data.get('tags', []),
            url_prefix=url_prefix,
        )

        if servers and len(servers) > 1:
            doc.schemes = [s.get('url', '') for s in servers]

        components = data.get('components', {})
        doc.security_definitions = components.get('securitySchemes', {})

        paths = data.get('paths', {})

        for path, path_item in paths.items():
            full_path = self._apply_url_prefix(path, url_prefix, "")
            for method, operation in path_item.items():
                if method not in ('get', 'post', 'put', 'delete', 'patch', 'head', 'options'):
                    continue

                if not isinstance(operation, dict):
                    continue

                endpoint = SwaggerEndpoint(
                    path=full_path,
                    method=method.upper(),
                    summary=operation.get('summary', ''),
                    description=operation.get('description', ''),
                    operation_id=operation.get('operationId', ''),
                    deprecated=operation.get('deprecated', False),
                    responses=operation.get('responses', {}),
                    tags=operation.get('tags', []),
                    security=operation.get('security', []),
                )

                parameters = operation.get('parameters', [])
                if not parameters and 'requestBody' not in operation:
                    parameters = path_item.get('parameters', [])
                endpoint.parameters = parameters

                if 'requestBody' in operation:
                    endpoint.request_body = operation['requestBody']

                doc.endpoints.append(endpoint)

        return doc

    def get_all_endpoints(self) -> List[SwaggerEndpoint]:
        """获取所有发现的端点"""
        endpoints = []
        for doc in self.discovered_docs:
            endpoints.extend(doc.endpoints)
        return endpoints

    def get_endpoints_with_params(self) -> List[Tuple[str, str, List[Dict]]]:
        """
        获取所有带参数的端点
        
        Returns:
            [(path, method, parameters), ...]
        """
        result = []
        for doc in self.discovered_docs:
            for ep in doc.endpoints:
                if ep.parameters or ep.request_body:
                    result.append((ep.path, ep.method, ep.parameters or []))
        return result

    def generate_test_urls(self, base_url: str) -> List[str]:
        """
        从 Swagger 文档生成测试 URL
        
        Args:
            base_url: 基础 URL
            
        Returns:
            完整的测试 URL 列表
        """
        urls = []
        parsed = urlparse(base_url)
        host = f"{parsed.scheme}://{parsed.netloc}"
        
        for doc in self.discovered_docs:
            base = host + (doc.base_path or '')
            
            for ep in doc.endpoints:
                url = base + ep.path
                urls.append(url)
        
        return list(set(urls))


async def discover_swagger(url: str, http_client=None) -> Optional[SwaggerDoc]:
    """
    便捷函数: 发现并解析 Swagger 文档
    
    Args:
        url: 目标 URL
        http_client: HTTP 客户端
        
    Returns:
        SwaggerDoc 对象或 None
    """
    discoverer = SwaggerDiscoverer(http_client)
    
    if http_client:
        resp = await http_client.request(url, timeout=10)
        if resp and resp.status_code == 200:
            content = resp.text if hasattr(resp, 'text') else ''
            swagger_urls = await discoverer.discover_from_html(content, url)
            
            for swagger_url in swagger_urls:
                doc = await discoverer.fetch_and_parse(swagger_url)
                if doc:
                    return doc
            
            common_urls = await discoverer.discover_common_paths(url)
            for common_url in common_urls:
                doc = await discoverer.fetch_and_parse(common_url)
                if doc:
                    return doc
    
    doc = await discoverer.fetch_and_parse(url)
    return doc


if __name__ == "__main__":
    print("Swagger/OpenAPI Discoverer")
