"""
Frontend Deep Analyzer - 前端深度分析器
从 JavaScript 源码中深度提取 API 端点、认证信息、API Schema 等
"""

import re
import json
import asyncio
import aiohttp
import logging
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


@dataclass
class DiscoveredEndpoint:
    """发现的端点"""
    path: str
    method: str = "GET"
    source: str = ""
    params: List[str] = field(default_factory=list)
    auth_required: bool = False


@dataclass
class AuthInfo:
    """认证信息"""
    login_path: str = ""
    username_field: str = ""
    password_field: str = ""
    token_header: str = ""
    token_type: str = ""  # Bearer, Basic, JWT
    source: str = ""


@dataclass
class GraphQLEndpoint:
    """GraphQL 端点"""
    path: str
    introspection_enabled: bool = False
    query_type: str = ""
    mutation_type: str = ""
    subscription_type: str = ""


@dataclass
class WebSocketEndpoint:
    """WebSocket 端点"""
    url: str
    protocol: str = ""
    source: str = ""


@dataclass
class ProxyConfig:
    """代理配置"""
    target: str = ""
    bypass: List[str] = field(default_factory=list)


class SourceMapAnalyzer:
    """Source Map 分析器 - 从 .map 文件获取源码映射"""
    
    SOURCE_MAP_PATTERNS = [
        r'//# sourceMappingURL=([^\s]+)\.map',
        r'"sources":\s*\[\s*"([^"]+)"',
        r"//\s*sourceMappingURL\s*=\s*([^\s]+)",
    ]
    
    JS_MAP_EXTENSIONS = ['.js.map', '.min.js.map', '.chunk.map']
    
    async def analyze(self, js_url: str, http_client) -> Dict[str, Any]:
        """
        分析 JS 文件对应的 Source Map
        
        Args:
            js_url: JS 文件 URL
            http_client: HTTP 客户端
            
        Returns:
            包含 sourceURLs 和 API 信息的字典
        """
        result = {
            'source_urls': [],
            'original_sources': [],
            'api_endpoints': [],
            'found': False
        }
        
        for pattern in self.JS_MAP_EXTENSIONS:
            map_url = js_url + pattern
            try:
                async with http_client.request(map_url, timeout=10) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        try:
                            map_data = json.loads(content)
                            result['found'] = True
                            
                            if 'sources' in map_data:
                                result['source_urls'] = map_data['sources']
                                result['original_sources'] = map_data.get('sourcesContent', [])
                            
                            for source in result.get('sources', []):
                                if isinstance(source, str) and ('api' in source.lower() or 'service' in source.lower() or 'request' in source.lower()):
                                    result['api_endpoints'].extend(self._extract_from_source(source))
                        except json.JSONDecodeError:
                            pass
                        break
            except Exception:
                continue
        
        return result
    
    def _extract_from_source(self, source_content: str) -> List[str]:
        """从源码内容中提取 API 路径"""
        endpoints = []
        
        patterns = [
            r'''['"]([/][^'"()]+(?:api|login|user|admin|auth)[^'"()]*?)['"]''',
            r'''url\s*:\s*['"]([/][^'"]+)['"]''',
            r'''path\s*:\s*['"]([/][^'"]+)['"]''',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, source_content, re.IGNORECASE)
            endpoints.extend(matches)
        
        return list(set(endpoints))


class VueSFCAnalyzer:
    """Vue SFC 分析器 - 分析 Vue 单文件组件"""
    
    VUE_SFC_PATTERNS = [
        r'''this\.¥import\s*\(['"]([^'"]+)['"]\)''',
        r'''import\s+.*?from\s+['"]([^'"]+)['"]''',
        r'''require\s*\(['"]([^'"]+)['"]\)''',
        r'''api\(['"]([^'"]+)['"]''',
        r'''fetch\(['"]([^'"]+)['"]''',
        r'''axios\.(?:get|post|put|delete)\(['"]([^'"]+)['"]''',
    ]
    
    VUE_LIFE_CYCLE_HOOKS = [
        'created', 'mounted', 'beforeMount', 'beforeCreate', 
        'methods', 'computed', 'watch', 'fetch', 'asyncData'
    ]
    
    def analyze(self, content: str) -> List[DiscoveredEndpoint]:
        """分析 Vue SFC 内容"""
        endpoints = []
        
        for pattern in self.VUE_LIFE_CYCLE_HOOKS:
            hook_matches = re.finditer(
                rf'''{pattern}\s*\(\s*(?:async\s*)?\([^)]*\)\s*={{\s*([^}}]+)''', 
                content
            )
            for match in hook_matches:
                hook_body = match.group(1) if match.lastindex else ''
                found = self._extract_from_vue_context(hook_body + ' ' + content)
                for path in found:
                    endpoints.append(DiscoveredEndpoint(
                        path=path,
                        method='POST' if 'post' in hook_body.lower() else 'GET',
                        source='vue_sfc'
                    ))
        
        return endpoints
    
    def _extract_from_vue_context(self, context: str) -> List[str]:
        """从 Vue 上下文提取 API 路径"""
        paths = []
        
        patterns = [
            r'''['"]?(/[a-zA-Z0-9_/-]+(?:api|login|user|admin|auth)[a-zA-Z0-9_/-]*)['"`]?''',
            r'''¥http[s]?://[^\s'"`]+''',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, context, re.IGNORECASE)
            paths.extend([m.strip("'\"`") for m in matches if isinstance(m, str)])
        
        return list(set(paths))


class WebSocketDiscovery:
    """WebSocket 发现器"""
    
    WS_PATTERNS = [
        r'''new\s+WebSocket\s*\(\s*['"]([^'"]+)['"]''',
        r'''WebSocket\s*\(\s*['"]([^'"]+)['"]''',
        r'''connect\s*\(\s*['"](ws[s]?://[^'"]+)['"']''',
        r'''socket\s*\(\s*['"]([^'"]+)['"']''',
        r'''io\s*\(\s*['"]([^'"]+)['"']''',
        r'''socket\.connect\s*\(\s*['"]([^'"]+)['"']''',
        r'''new\s+SSE\s*\(\s*['"]([^'"]+)['"']''',
        r'''EventSource\s*\(\s*['"]([^'"]+)['"']''',
    ]
    
    def discover(self, content: str) -> List[WebSocketEndpoint]:
        """从内容中发现 WebSocket 端点"""
        endpoints = []
        
        for pattern in self.WS_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                if match.lastindex:
                    url = match.group(1)
                    protocol = 'wss' if url.startswith('wss') else 'ws' if url.startswith('ws') else 'ws'
                    endpoints.append(WebSocketEndpoint(
                        url=url,
                        protocol=protocol,
                        source='websocket_discovery'
                    ))
        
        return endpoints


class GraphQLDiscovery:
    """GraphQL 发现器"""
    
    GRAPHQL_PATTERNS = [
        r'''['"]([/][^'"]*graphql[^'"]*)['"]''',
        r'''['"]([/][^'"]*graphql)['"']''',
        r'''endpoint\s*:\s*['"]([/][^'"]+)['"']''',
        r'''uri\s*:\s*['"]([/][^'"]+)['"']''',
        r'''server\s*:\s*['"]([/][^'"]+)['"']''',
        r'''apiEndpoint\s*:\s*['"]([/][^'"]+)['"']''',
        r'''gql\s*`[^`]+`''',
        r'''graphql\s*\(`[^`]+`\)''',
        r'''useQuery\s*\(`[^`]+`\)''',
        r'''useMutation\s*\(`[^`]+`\)''',
        r'''apollo\s*\.\s*(?:query|mutate)\s*\([^)]+\)''',
    ]
    
    GRAPHQL_COMMON_PATHS = [
        '/graphql',
        '/api/graphql',
        '/api/v1/graphql',
        '/gql',
        '/query',
        '/api/query',
        '/v1/graphql',
        '/v2/graphql',
    ]
    
    INTROSPECTION_QUERY = '''
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types { name fields(includeDeprecated: true) { name } }
      }
    }
    '''
    
    async def discover_common_paths(self, base_url: str, http_client) -> List[GraphQLEndpoint]:
        """探测常见的 GraphQL 端点"""
        endpoints = []
        
        for path in self.GRAPHQL_COMMON_PATHS:
            url = base_url.rstrip('/') + path
            try:
                async with http_client.request(
                    url, 
                    method='POST',
                    json={'query': '{ __typename }'},
                    headers={'Content-Type': 'application/json'},
                    timeout=10
                ) as resp:
                    if resp.status == 200:
                        try:
                            data = await resp.json()
                            introspection = len(data) > 0
                            endpoints.append(GraphQLEndpoint(
                                path=path,
                                introspection_enabled=introspection,
                                source='common_paths'
                            ))
                        except:
                            endpoints.append(GraphQLEndpoint(
                                path=path,
                                introspection_enabled=False,
                                source='common_paths'
                            ))
            except Exception:
                continue
        
        return endpoints
    
    def discover_from_content(self, content: str) -> List[GraphQLEndpoint]:
        """从内容中发现 GraphQL 端点"""
        endpoints = []
        
        for pattern in self.GRAPHQL_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, str) and match.startswith('/'):
                    endpoints.append(GraphQLEndpoint(
                        path=match,
                        source='content_pattern'
                    ))
        
        return endpoints


class ProxyConfigAnalyzer:
    """代理配置分析器"""
    
    NGINX_PROXY_PATTERNS = [
        r'''proxy_pass\s+([^;]+);''',
        r'''set\s+\$[^;\s]+\s+([^;]+);''',
        r'''server\s+([^;\s]+)''',
    ]
    
    VUE_PROXY_PATTERNS = [
        r'''proxy\s*:\s*{[^}]*target\s*:\s*['"]([^'"]+)['"]''',
        r'''proxy\s*:\s*\[[\s*{[^}]+}[^]]*]''',
        r'''axios\.defaults\.baseURL\s*=\s*['"]([^'"]+)['"']''',
        r'''VUE_APP_API_BASE_URL\s*=\s*['"]([^'"]+)['"']''',
        r'''VUE_APP\s+=\s*['"]([^'"]+)['"']''',
        r'''apiBaseURL\s*:\s*['"]([^'"]+)['"']''',
    ]
    
    def discover_from_content(self, content: str) -> List[ProxyConfig]:
        """从内容中发现代理配置"""
        configs = []
        
        vue_matches = re.findall(
            r'''['"](https?://[^'"]+)['"]''',
            content
        )
        
        for match in vue_matches:
            if any(keyword in match.lower() for keyword in ['api', 'backend', 'server', 'proxy']):
                configs.append(ProxyConfig(
                    target=match,
                    source='vue_config'
                ))
        
        return configs
    
    async def discover_nginx_config(self, base_url: str, http_client) -> Optional[ProxyConfig]:
        """尝试发现 Nginx 配置"""
        paths_to_check = [
            '/nginx.conf',
            '/.nginx/nginx.conf',
            '/server/config',
            '/api/config',
            '/config/proxy',
        ]
        
        for path in paths_to_check:
            url = base_url.rstrip('/') + path
            try:
                async with http_client.request(url, timeout=5) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        for pattern in self.NGINX_PROXY_PATTERNS:
                            matches = re.findall(pattern, content)
                            if matches:
                                return ProxyConfig(
                                    target=matches[0],
                                    source='nginx_config'
                                )
            except:
                continue
        
        return None


class FrontendDeepAnalyzer:
    """
    前端深度分析器
    整合所有前端分析功能
    """
    
    def __init__(self, http_client):
        self.http_client = http_client
        self.source_map_analyzer = SourceMapAnalyzer()
        self.vue_analyzer = VueSFCAnalyzer()
        self.ws_discovery = WebSocketDiscovery()
        self.graphql_discovery = GraphQLDiscovery()
        self.proxy_analyzer = ProxyConfigAnalyzer()
    
    async def analyze(self, base_url: str, js_urls: List[str] = None) -> Dict[str, Any]:
        """
        执行深度分析
        
        Args:
            base_url: 目标基础 URL
            js_urls: 可选的 JS URL 列表
            
        Returns:
            包含所有发现信息的字典
        """
        result = {
            'api_endpoints': [],
            'websocket_endpoints': [],
            'graphql_endpoints': [],
            'proxy_configs': [],
            'auth_info': None,
            'source_map_found': False,
        }
        
        try:
            async with self.http_client.request(base_url, timeout=10) as resp:
                if resp.status == 200:
                    content = await resp.text()
                    result['api_endpoints'].extend(
                        self._extract_all_endpoints(content)
                    )
                    result['websocket_endpoints'].extend(
                        self.ws_discovery.discover(content)
                    )
                    result['graphql_endpoints'].extend(
                        self.graphql_discovery.discover_from_content(content)
                    )
                    result['proxy_configs'].extend(
                        self.proxy_analyzer.discover_from_content(content)
                    )
                    result['auth_info'] = self._extract_auth_info(content)
        except Exception as e:
            logger.debug(f"Frontend analyze error: {e}")
        
        if js_urls:
            for js_url in js_urls[:10]:
                try:
                    async with self.http_client.request(js_url, timeout=10) as resp:
                        if resp.status == 200:
                            content = await resp.text()
                            
                            result['api_endpoints'].extend(
                                self._extract_all_endpoints(content)
                            )
                            result['websocket_endpoints'].extend(
                                self.ws_discovery.discover(content)
                            )
                            
                            sm_result = await self.source_map_analyzer.analyze(js_url, self.http_client)
                            if sm_result['found']:
                                result['source_map_found'] = True
                                for ep in sm_result.get('api_endpoints', []):
                                    result['api_endpoints'].append(ep)
                            
                            result['graphql_endpoints'].extend(
                                self.graphql_discovery.discover_from_content(content)
                            )
                except Exception as e:
                    logger.debug(f"JS analyze error: {e}")
        
        result['api_endpoints'] = self._deduplicate_endpoints(result['api_endpoints'])
        result['websocket_endpoints'] = self._deduplicate_ws(result['websocket_endpoints'])
        result['graphql_endpoints'] = self._deduplicate_graphql(result['graphql_endpoints'])
        
        return result
    
    def _extract_all_endpoints(self, content: str) -> List[DiscoveredEndpoint]:
        """从内容中提取所有端点"""
        endpoints = []
        
        patterns = [
            (r'''['"]([/][a-zA-Z0-9_/-]+(?:login|logout|auth|user|admin|api)[a-zA-Z0-9_/-]*)['"']''', 'GET'),
            (r'''['"]([/][^'"]*(?:get|post|put|delete|patch)[a-zA-Z0-9_/-]*)['"']''', 'AUTO'),
            (r'''axios\.(?:get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]''', 'AUTO'),
            (r'''fetch\s*\(\s*['"]([^'"]+)['"]''', 'GET'),
            (r'''request\s*\(\s*['"']['"]\s*,\s*\{[^}]*url\s*:\s*['"]([^'"]+)['"]''', 'AUTO'),
            (r'''\.post\s*\(\s*['"]([^'"]+)''', 'POST'),
            (r'''\.get\s*\(\s*['"]([^'"]+)''', 'GET'),
            (r'''\.put\s*\(\s*['"]([^'"]+)''', 'PUT'),
            (r'''\.delete\s*\(\s*['"]([^'"]+)''', 'DELETE'),
        ]
        
        for pattern, default_method in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, str) and match.startswith('/'):
                    method = default_method if default_method != 'AUTO' else self._infer_method(content, match)
                    endpoints.append(DiscoveredEndpoint(
                        path=match,
                        method=method,
                        source='deep_analyze'
                    ))
        
        return endpoints
    
    def _infer_method(self, content: str, path: str) -> str:
        """推断 HTTP 方法"""
        path_pos = content.find(path)
        if path_pos > 50:
            context = content[max(0, path_pos-100):path_pos+100].lower()
            if 'post' in context:
                return 'POST'
            if 'put' in context:
                return 'PUT'
            if 'delete' in context:
                return 'DELETE'
        return 'GET'
    
    def _extract_auth_info(self, content: str) -> Optional[AuthInfo]:
        """提取认证信息"""
        auth = AuthInfo()
        
        login_patterns = [
            r'''['"]([/][^'"]*(?:login|signin|auth)[^'"]*)['"']''',
        ]
        
        for pattern in login_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                auth.login_path = matches[0]
                break
        
        username_patterns = [
            r'''['"](?:username|userName|account|mobile|phone|email)['"]''',
        ]
        for pattern in username_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                auth.username_field = match.group(0).strip('"\': ')
                break
        
        password_patterns = [
            r'''['"](?:password|pwd|passwd)['"']''',
        ]
        for pattern in password_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                auth.password_field = match.group(0).strip('"\': ')
                break
        
        token_patterns = [
            r'''['"](?:Authorization|Bearer|token|jwt)['"']''',
        ]
        for pattern in token_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                auth.token_header = match.group(0).strip('"\': ')
                if 'bearer' in auth.token_header.lower():
                    auth.token_type = 'Bearer'
                elif 'jwt' in auth.token_header.lower():
                    auth.token_type = 'JWT'
                break
        
        return auth if any([auth.login_path, auth.username_field, auth.token_header]) else None
    
    def _deduplicate_endpoints(self, endpoints: List[DiscoveredEndpoint]) -> List[DiscoveredEndpoint]:
        """去重端点"""
        seen = set()
        unique = []
        for ep in endpoints:
            key = f"{ep.method}:{ep.path}"
            if key not in seen:
                seen.add(key)
                unique.append(ep)
        return unique
    
    def _deduplicate_ws(self, endpoints: List[WebSocketEndpoint]) -> List[WebSocketEndpoint]:
        """去重 WebSocket 端点"""
        seen = set()
        unique = []
        for ep in endpoints:
            if ep.url not in seen:
                seen.add(ep.url)
                unique.append(ep)
        return unique
    
    def _deduplicate_graphql(self, endpoints: List[GraphQLEndpoint]) -> List[GraphQLEndpoint]:
        """去重 GraphQL 端点"""
        seen = set()
        unique = []
        for ep in endpoints:
            if ep.path not in seen:
                seen.add(ep.path)
                unique.append(ep)
        return unique


async def analyze_frontend(
    http_client,
    base_url: str,
    js_urls: List[str] = None
) -> Dict[str, Any]:
    """
    前端深度分析入口函数
    
    Args:
        http_client: HTTP 客户端
        base_url: 目标 URL
        js_urls: JS 文件 URL 列表
        
    Returns:
        分析结果字典
    """
    analyzer = FrontendDeepAnalyzer(http_client)
    return await analyzer.analyze(base_url, js_urls)
