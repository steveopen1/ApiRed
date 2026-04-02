#!/usr/bin/env python3
"""
JS 智能解析与拼接模块 - 基于 FLUX v5.2.1
智能解析 JS URL，处理各种路径格式和构建产物

增强版本 v5.3.0:
- Axios 多实例提取 (baseURL, interceptors)
- 路径参数化解析 (/user/:id)
- GraphQL 端点发现 (gql, query, mutation)
- 环境变量提取 (VITE_, REACT_APP_)
- WebSocket 发现 (ws://, socket.io)
"""

import re
import json
import logging
from typing import List, Dict, Set, Optional, Tuple
from urllib.parse import urljoin, urlparse, urlunparse, quote
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class JSDiscoveryRecord:
    """JS 发现记录"""
    url: str
    original_ref: str
    source_page: str
    discovery_method: str
    confidence: str
    is_secondary_fuzz: bool = False
    fuzz_attempts: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)


@dataclass
class APIEndpoint:
    """API 端点信息"""
    path: str
    method: str
    base_url: Optional[str] = None
    params: List[str] = field(default_factory=list)
    source: str = ""


@dataclass
class ConfigExtraction:
    """配置提取结果"""
    config_type: str
    key: str
    value: str
    source: str


class JSResolver:
    """JS URL 智能解析器"""

    WEBPACK_PATTERNS = {
        'public_path': [
            r'__webpack_require__\.p\s*=\s*["\']([^"\']+)["\']',
            r'publicPath\s*:\s*["\']([^"\']+)["\']',
            r'__webpack_public_path__\s*=\s*["\']([^"\']+)["\']',
        ],
        'chunk_name': [
            r'webpackChunkName\s*:\s*["\']([^"\']+)["\']',
            r'import\s*\(\s*\/\*\s*webpackChunkName:\s*["\']([^"\']+)["\']',
        ],
        'runtime_chunk': [
            r'runtime~[a-f0-9]+\.js',
            r'runtime\.[a-f0-9]+\.js',
        ],
        'manifest': [
            r'webpack-manifest\.json',
            r'asset-manifest\.json',
            r'manifest\.json',
            r'build-manifest\.json',
        ]
    }

    VITE_PATTERNS = {
        'manifest': [
            r'\.vite\/manifest\.json',
            r'vite-manifest\.json',
        ],
        'dynamic_import': [
            r'import\s*\(\s*["\']([^"\']+\.(js|ts|tsx|jsx))["\']\s*\)',
        ],
        'asset_ref': [
            r'__VITE_ASSET__["\']([^"\']+)["\']',
        ]
    }

    FRAMEWORK_PATTERNS = {
        'next_js': [
            r'/_next/static/[^/]+/pages/[^/]+\.js',
            r'/_next/static/chunks/[^/]+\.js',
            r'/_next/static/[^/]+/_buildManifest\.js',
        ],
        'nuxt_js': [
            r'/_nuxt/[^/]+\.js',
            r'/_nuxt/static/[^/]+\.js',
        ],
    }

    STATIC_DIRS = [
        '/static/', '/assets/', '/js/', '/scripts/', '/dist/',
        '/build/', '/public/', '/resources/', '/cdn/',
        '/_next/', '/_nuxt/', '/.vite/', '/webpack/',
    ]

    BUILD_DIRS = [
        'dist', 'build', 'public', 'static', 'assets',
        'js', 'scripts', 'bundle', 'chunks',
    ]

    GRAPHQL_PATTERNS = {
        'endpoint': [
            r'graphql\s*\(\s*["\']([^"\']+)["\']',
            r'endpoint\s*:\s*["\']([^"\']+)["\']',
            r'apollo\s*\(\s*\{[^}]*uri\s*:\s*["\']([^"\']+)["\']',
            r'ApolloClient\s*\(\s*\{[^}]*link\s*:[^}]*HttpLink\s*\([^)]*uri\s*:\s*["\']([^"\']+)["\']',
        ],
        'query': [
            r'gql\s*`[^`]+`',
            r'query\s+(\w+)\s*\{',
            r'mutation\s+(\w+)\s*\{',
            r'fragment\s+(\w+)\s+on',
        ],
        'operation': [
            r'operationName\s*:\s*["\'](\w+)["\']',
            r'opName\s*:\s*["\'](\w+)["\']',
        ]
    }

    WEBSOCKET_PATTERNS = {
        'ws_url': [
            r'(wss?://[^\s\'"]+)',
            r'new\s+WebSocket\s*\(\s*["\']([^"\']+)["\']',
            r'socket\s*\.\s*(connect|emit)\s*\(\s*["\']([^"\']+)["\']',
            r'\.connect\s*\(\s*["\']([^"\']+)["\']',
            r'socket\.io\s*\(\s*\{[^}]*path\s*:\s*["\']([^"\']+)["\']',
            r'io\s*\(\s*["\']([^"\']+)["\']\s*\)',
        ],
        'socket_event': [
            r'socket\.on\s*\(\s*["\']([^"\']+)["\']',
            r'socket\.emit\s*\(\s*["\']([^"\']+)["\']',
            r'emit\s*\(\s*["\']([^"\']+)["\']',
            r'on\s*\(\s*["\']([^"\']+)["\']\s*,',
        ]
    }

    ENV_VAR_PATTERNS = {
        'env_vars': [
            r'(?:process\.env|VITE_|REACT_APP_|APP_|NEXT_PUBLIC_)([A-Z_][A-Z0-9_]*)',
            r'import\.meta\.env\.([A-Z_][A-Z0-9_]*)',
        ],
        'api_url': [
            r'(?:API_URL|BASE_URL|VITE_API_URL|REACT_APP_API_URL)\s*[=:]\s*["\']([^"\']+)["\']',
            r'(?:api|base|root)URL\s*[=:]\s*["\']([^"\']+)["\']',
        ]
    }

    PARAM_PATH_PATTERNS = [
        (r'/\{(\w+)\}', '/{param}'),
        (r'/:\w+', '/{param}'),
        (r'/\$\{(\w+)\}', '/{param}'),
    ]

    def __init__(self, base_url: str):
        self.base_url = base_url
        self.parsed_base = urlparse(base_url)
        self.origin = f"{self.parsed_base.scheme}://{self.parsed_base.netloc}"
        self.base_path = self.parsed_base.path.rsplit('/', 1)[0] if '/' in self.parsed_base.path else ''
        self.resource_prefixes: Set[str] = set()
        self.webpack_public_path: Optional[str] = None
        self.vite_base: Optional[str] = None
        self.base_urls: List[str] = []
        self.api_configs: List[ConfigExtraction] = []
        self.graphql_endpoints: List[str] = []
        self.websocket_urls: List[str] = []
        self.env_vars: Dict[str, str] = {}
        self.parametric_paths: Set[str] = set()

    def resolve(self, ref: str, source_page: str = "", discovery_method: str = "unknown") -> Optional[JSDiscoveryRecord]:
        if not ref or len(ref) < 2:
            return None

        ref = ref.strip().strip('"\'')

        if ref.startswith(('http://', 'https://')):
            return JSDiscoveryRecord(
                url=ref,
                original_ref=ref,
                source_page=source_page,
                discovery_method=discovery_method,
                confidence='high'
            )

        if ref.startswith('//'):
            url = f"{self.parsed_base.scheme}:{ref}"
            return JSDiscoveryRecord(
                url=url,
                original_ref=ref,
                source_page=source_page,
                discovery_method=discovery_method,
                confidence='high'
            )

        if ref.startswith('/'):
            url = urljoin(self.origin, ref)
            return JSDiscoveryRecord(
                url=url,
                original_ref=ref,
                source_page=source_page,
                discovery_method=discovery_method,
                confidence='high'
            )

        if source_page:
            url = urljoin(source_page, ref)
        else:
            url = urljoin(self.base_url, ref)

        return JSDiscoveryRecord(
            url=url,
            original_ref=ref,
            source_page=source_page or self.base_url,
            discovery_method=discovery_method,
            confidence='medium'
        )

    def extract_from_html(self, html: str, source_page: str) -> List[JSDiscoveryRecord]:
        records = []
        base_href = self._extract_base_href(html)
        if base_href:
            self.resource_prefixes.add(base_href)

        script_pattern = r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']'
        for match in re.finditer(script_pattern, html, re.I):
            ref = match.group(1)
            record = self.resolve(ref, source_page, 'script_src')
            if record:
                records.append(record)

        link_pattern = r'<link[^>]+(?:preload|prefetch)[^>]+href=["\']([^"\']+\.js)["\']'
        for match in re.finditer(link_pattern, html, re.I):
            ref = match.group(1)
            record = self.resolve(ref, source_page, 'link_preload')
            if record:
                records.append(record)

        import_pattern = r'import\s*\(\s*["\']([^"\']+\.js)["\']\s*\)'
        for match in re.finditer(import_pattern, html, re.I):
            ref = match.group(1)
            record = self.resolve(ref, source_page, 'dynamic_import')
            if record:
                records.append(record)

        return records

    def extract_from_js(self, js_content: str, source_url: str) -> List[JSDiscoveryRecord]:
        records = []
        self._detect_webpack_config(js_content)
        self._detect_vite_config(js_content)
        self._detect_framework_config(js_content)

        patterns = [
            (r'["\'`]([^"\']+\.js[^"\']*)["\']', 'string_match'),
            (r'src\s*=\s*["\']([^"\']+\.js[^"\']*)["\']', 'src_attribute'),
            (r'import\s+["\']([^"\']+\.js)["\']', 'import_statement'),
            (r'import\s*\(\s*["\']([^"\']+\.js)["\']\s*\)', 'dynamic_import'),
            (r'require\s*\(\s*["\']([^"\']+\.js)["\']\s*\)', 'require_call'),
            (r'webpackChunkName\s*:\s*["\']([^"\']+)["\']', 'webpack_chunk'),
            (r'url\s*:\s*["\']([^"\']+)["\']', 'url_property'),
            (r'dispatch\s*\(\s*["\']([^"\']+)["\']', 'vuex_dispatch'),
            (r'\.get\s*\(\s*["\']([^"\']+)["\']', 'axios_get'),
            (r'\.post\s*\(\s*["\']([^"\']+)["\']', 'axios_post'),
            (r'\.put\s*\(\s*["\']([^"\']+)["\']', 'axios_put'),
            (r'\.delete\s*\(\s*["\']([^"\']+)["\']', 'axios_delete'),
            (r'fetch\s*\(\s*["\']([^"\']+)["\']', 'fetch_call'),
            (r'router\.[a-z]+\s*\(\s*["\']([^"\']+)["\']', 'router_call'),
            (r'\$http\.[a-z]+\s*\(\s*["\']([^"\']+)["\']', 'vue_resource'),
            (r'ajax\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']', 'jquery_ajax'),
            (r'component\s*\(\s*["\']([^"\']+)["\']', 'vue_component'),
            (r'createElement\s*\(\s*["\']([^"\']+)["\']', 'create_element'),
            (r'return\s+["\']([/a-zA-Z0-9_\-]+)["\']', 'return_path'),
            (r'path\s*:\s*["\']([/a-zA-Z0-9_\-]+)["\']', 'path_property'),
            (r'name\s*:\s*["\']([/a-zA-Z0-9_\-]+)["\']', 'name_property'),
            (r'api["\']\s*:\s*["\']([/a-zA-Z0-9_\-]+)["\']', 'api_property'),
        ]

        for pattern, method in patterns:
            for match in re.finditer(pattern, js_content, re.MULTILINE):
                ref = match.group(1)
                if self._is_valid_endpoint(ref):
                    record = self.resolve(ref, source_url, method)
                    if record:
                        records.append(record)

        return records

    def _detect_webpack_config(self, js_content: str):
        for pattern_name, patterns in self.WEBPACK_PATTERNS.items():
            if pattern_name == 'public_path':
                for pattern in patterns:
                    matches = re.finditer(pattern, js_content)
                    for match in matches:
                        if match.groups():
                            self.webpack_public_path = match.group(1)
                            self.resource_prefixes.add(self.webpack_public_path)
                            logger.debug(f"[*] 检测到Webpack public_path: {self.webpack_public_path}")
                            return

    def _detect_vite_config(self, js_content: str):
        for pattern_name, patterns in self.VITE_PATTERNS.items():
            if pattern_name == 'manifest':
                for pattern in patterns:
                    if re.search(pattern, js_content):
                        logger.debug(f"[*] 检测到Vite manifest模式")
                        break

    def _detect_framework_config(self, js_content: str):
        for framework, patterns in self.FRAMEWORK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, js_content):
                    logger.debug(f"[*] 检测到{framework}框架")
                    break

    def _extract_base_href(self, html: str) -> Optional[str]:
        match = re.search(r'<base[^>]+href=["\']([^"\']+)["\']', html, re.I)
        if match:
            return match.group(1)
        return None

    def _is_js_file(self, path: str) -> bool:
        if not path:
            return False
        path_lower = path.lower()
        js_indicators = ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.css']
        invalid_indicators = ['node_modules', 'data:', 'blob:', 'javascript:']
        return any(path_lower.endswith(ext) for ext in js_indicators) and not any(ind in path_lower for ind in invalid_indicators)

    def _is_valid_endpoint(self, path: str) -> bool:
        if not path or len(path) < 2:
            return False
        path_lower = path.lower()
        invalid_patterns = [
            '.js', '.css', '.html', '.png', '.jpg', '.jpeg', '.svg', '.gif', '.ico',
            '.woff', '.woff2', '.ttf', '.eot', '.map', '.json',
            'node_modules', 'data:', 'blob:', 'javascript:', 'void(0)',
            'webpack', 'chunk', 'hot-update', 'manifest',
        ]
        if any(ind in path_lower for ind in invalid_patterns):
            return False
        if path.startswith('/') or path.startswith('http'):
            return True
        if re.match(r'^[a-zA-Z0-9_\-/\.]+$', path):
            return True
        return False

    def generate_fuzz_candidates(self, js_url: str) -> List[str]:
        candidates = []
        parsed = urlparse(js_url)
        path_parts = parsed.path.rsplit('/', 1)
        if len(path_parts) > 1:
            dir_path = path_parts[0]
            filename = path_parts[1]

            for static_dir in self.STATIC_DIRS:
                candidates.append(f"{self.origin}{static_dir}{filename}")

            base_name = filename.rsplit('.', 1)[0] if '.' in filename else filename
            extensions = ['.js', '.jsx', '.ts', '.tsx', '.min.js', '.bundle.js', '.chunk.js']

            for ext in extensions:
                candidates.append(f"{dir_path}/{base_name}{ext}")

            chunk_patterns = [
                f"{dir_path}/{base_name}.chunk.js",
                f"{dir_path}/{base_name}-chunk.js",
                f"{dir_path}/chunk-{filename}",
                f"{dir_path}/{filename.replace('.js', '.chunk.js')}",
            ]
            candidates.extend(chunk_patterns)

        return list(set(candidates))

    def resolve_from_manifest(self, manifest_url: str, js_content: str) -> List[JSDiscoveryRecord]:
        records = []
        try:
            manifest = json.loads(js_content)
            if isinstance(manifest, dict):
                if 'entrypoints' in manifest or 'main' in manifest:
                    for key, value in manifest.items():
                        if isinstance(value, str) and self._is_js_file(value):
                            record = self.resolve(value, manifest_url, 'manifest')
                            if record:
                                records.append(record)
                if 'files' in manifest:
                    for file_path in manifest.get('files', []):
                        if self._is_js_file(file_path):
                            record = self.resolve(file_path, manifest_url, 'manifest')
                            if record:
                                records.append(record)
                if 'assets' in manifest:
                    for asset_name, asset_path in manifest.get('assets', {}).items():
                        if isinstance(asset_path, str) and self._is_js_file(asset_path):
                            record = self.resolve(asset_path, manifest_url, 'webpack_manifest')
                            if record:
                                records.append(record)
        except json.JSONDecodeError:
            pass
        return records

    def extract_all_endpoints(self, js_content: str, source_url: str) -> List[APIEndpoint]:
        """提取所有 API 端点（包括路径参数化）"""
        endpoints = []
        all_paths = self.extract_endpoints_from_js(js_content, source_url)

        for path in all_paths:
            normalized = self._normalize_path(path)
            method = self._infer_method(path)
            param_path = self._normalize_param_path(normalized)

            endpoint = APIEndpoint(
                path=normalized,
                method=method,
                base_url=self._extract_base_url(path),
                params=self._extract_path_params(param_path),
                source=source_url
            )
            endpoints.append(endpoint)

            if param_path != normalized:
                param_endpoint = APIEndpoint(
                    path=param_path,
                    method=method,
                    base_url=endpoint.base_url,
                    params=self._extract_path_params(param_path),
                    source=source_url
                )
                endpoints.append(param_endpoint)

        return endpoints

    def extract_endpoints_from_js(self, js_content: str, source_url: str) -> List[str]:
        """提取所有端点路径"""
        endpoints = set()

        for pattern_group in [
            self.HTTP_PATTERNS,
            self.AXIOS_PATTERNS,
            self.VUEX_PATTERNS,
            self.VUE_ROUTER_PATTERNS,
            self.REACT_PATTERNS,
            self.GRAPHQL_PATTERNS,
            self.WEBSOCKET_PATTERNS,
            self.ENV_VAR_PATTERNS,
        ]:
            for method_name, patterns in pattern_group.items():
                if isinstance(patterns, list):
                    for pattern in patterns:
                        for match in re.finditer(pattern, js_content, re.MULTILINE | re.IGNORECASE):
                            url = match.group(1) if match.groups() else match.group(0)
                            if self._is_valid_endpoint(url):
                                endpoints.add(url)

        return list(endpoints)

    HTTP_PATTERNS = {
        'fetch': [r'fetch\s*\(\s*["\']([^"\']+)["\']'],
        'request': [
            r'\.request\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']',
            r'request\s*\(\s*["\']([^"\']+)["\']',
        ],
        'http_client': [
            r'new\s+HttpClient\(\)\.([a-z]+)\s*\(\s*["\']([^"\']+)["\']',
            r'http\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
        ],
    }

    AXIOS_PATTERNS = {
        'axios_create': [
            r'axios\.create\s*\(\s*\{[^}]*baseURL\s*:\s*["\']([^"\']+)["\']',
        ],
        'axios_instance': [
            r'const\s+\w+\s*=\s*axios\.create',
            r'service\s*=\s*axios\.create',
        ],
        'api_method': [
            r'api\.([a-z]+)\s*\(\s*["\']([^"\']+)["\']',
            r'\w+\.([a-z]+)\s*\(\s*["\']([^"\']+)["\']',
        ],
    }

    VUEX_PATTERNS = {
        'dispatch': [r'dispatch\s*\(\s*["\']([^"\']+)["\']'],
        'action': [r'action\s*\(\s*["\']([^"\']+)["\']'],
    }

    VUE_ROUTER_PATTERNS = {
        'router_path': [
            r'router\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
            r'path\s*:\s*["\']([/a-zA-Z0-9_\-:{}]+)["\']',
        ],
    }

    REACT_PATTERNS = {
        'fetch': [r'fetch\s*\(\s*["\']([^"\']+)["\']'],
        'axios': [r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']'],
        'fetch_base': [
            r'fetch\s*\(\s*`\s*\$\{(baseUrl|apiUrl)[^}]+\}\s*\+\s*["\']([^"\']+)["\']',
        ],
    }

    def _normalize_path(self, path: str) -> str:
        """标准化路径"""
        path = path.strip().strip('"\'')
        if path.startswith('/'):
            return path
        if path.startswith('http'):
            parsed = urlparse(path)
            return parsed.path
        return '/' + path

    def _normalize_param_path(self, path: str) -> str:
        """将参数化路径标准化为 /user/:id 格式"""
        normalized = path
        for pattern, replacement in self.PARAM_PATH_PATTERNS:
            normalized = re.sub(pattern, replacement, normalized)
        return normalized

    def _infer_method(self, path: str) -> str:
        """从路径或上下文推断 HTTP 方法"""
        path_lower = path.lower()
        if 'login' in path_lower or 'auth' in path_lower:
            return 'POST'
        if 'get' in path_lower:
            return 'GET'
        if 'create' in path_lower or 'add' in path_lower:
            return 'POST'
        if 'update' in path_lower or 'edit' in path_lower:
            return 'PUT'
        if 'delete' in path_lower or 'remove' in path_lower:
            return 'DELETE'
        return 'GET'

    def _extract_base_url(self, path: str) -> Optional[str]:
        """从完整 URL 中提取 baseURL"""
        if path.startswith('http'):
            parsed = urlparse(path)
            return f"{parsed.scheme}://{parsed.netloc}"
        return None

    def _extract_path_params(self, path: str) -> List[str]:
        """从路径中提取参数名"""
        params = []
        for pattern, _ in self.PARAM_PATH_PATTERNS:
            matches = re.findall(pattern.replace('(', '').replace(')', '').replace('\\', ''), path)
            params.extend(matches)
        return list(set(params))

    def extract_graphql(self, js_content: str) -> List[str]:
        """提取 GraphQL 端点"""
        endpoints = []
        for pattern in self.GRAPHQL_PATTERNS.get('endpoint', []):
            for match in re.finditer(pattern, js_content, re.IGNORECASE):
                url = match.group(1) if match.groups() else None
                if url and self._is_valid_endpoint(url):
                    endpoints.append(url)
        return list(set(endpoints))

    def extract_websocket(self, js_content: str) -> List[str]:
        """提取 WebSocket 端点"""
        endpoints = []
        for pattern in self.WEBSOCKET_PATTERNS.get('ws_url', []):
            for match in re.finditer(pattern, js_content, re.IGNORECASE):
                url = match.group(1) if match.groups() else None
                if url:
                    endpoints.append(url)
        return list(set(endpoints))

    def extract_env_vars(self, js_content: str) -> Dict[str, str]:
        """提取环境变量配置"""
        env_vars = {}
        for pattern_list in self.ENV_VAR_PATTERNS.values():
            for pattern in pattern_list:
                for match in re.finditer(pattern, js_content, re.MULTILINE):
                    if match.groups():
                        if len(match.groups()) == 2:
                            key, value = match.groups()
                            env_vars[key] = value
                        else:
                            value = match.group(1)
                            env_vars[pattern.split('(')[1].split(')')[0]] = value
        return env_vars

    def extract_api_configs(self, js_content: str) -> List[ConfigExtraction]:
        """提取 API 配置信息"""
        configs = []

        base_url_patterns = [
            r'baseURL\s*:\s*["\']([^"\']+)["\']',
            r'base_url\s*:\s*["\']([^"\']+)["\']',
            r'API_BASE\s*:\s*["\']([^"\']+)["\']',
        ]

        for pattern in base_url_patterns:
            for match in re.finditer(pattern, js_content, re.IGNORECASE):
                config = ConfigExtraction(
                    config_type='baseURL',
                    key='baseURL',
                    value=match.group(1),
                    source='js_config'
                )
                configs.append(config)
                self.base_urls.append(match.group(1))

        timeout_patterns = [
            r'timeout\s*:\s*(\d+)',
            r'requestTimeout\s*:\s*(\d+)',
        ]

        for pattern in timeout_patterns:
            for match in re.finditer(pattern, js_content):
                config = ConfigExtraction(
                    config_type='timeout',
                    key='timeout',
                    value=match.group(1),
                    source='js_config'
                )
                configs.append(config)

        headers_patterns = [
            r'headers\s*:\s*\{[^}]*["\']Content-Type["\']\s*:\s*["\']([^"\']+)["\']',
        ]

        for pattern in headers_patterns:
            for match in re.finditer(pattern, js_content):
                config = ConfigExtraction(
                    config_type='headers',
                    key='Content-Type',
                    value=match.group(1),
                    source='js_config'
                )
                configs.append(config)

        return configs

    def generate_param_variations(self, path: str) -> List[str]:
        """为参数化路径生成测试变体"""
        variations = []
        if '{param}' in path or ':' in path or '${' in path:
            test_values = ['1', 'test', 'admin', '0', '999', 'null', 'undefined']
            for value in test_values:
                variation = path
                variation = re.sub(r'\{param\}', value, variation)
                variation = re.sub(r':\w+', value, variation)
                variation = re.sub(r'\$\{\w+\}', value, variation)
                variations.append(variation)
        return variations

    def get_all_discovered(self) -> Dict:
        """获取所有发现的资产"""
        return {
            'base_urls': list(set(self.base_urls)),
            'graphql_endpoints': self.graphql_endpoints,
            'websocket_urls': self.websocket_urls,
            'env_vars': self.env_vars,
            'parametric_paths': list(self.parametric_paths),
            'webpack_public_path': self.webpack_public_path,
            'vite_base': self.vite_base,
        }


def extract_js_urls(html: str, base_url: str) -> List[str]:
    resolver = JSResolver(base_url)
    records = resolver.extract_from_html(html, base_url)
    return [record.url for record in records]


def extract_endpoints_from_js(js_content: str, js_url: str) -> List[str]:
    resolver = JSResolver(js_url)
    return resolver.extract_endpoints_from_js(js_content, js_url)


def extract_graphql_endpoints(js_content: str) -> List[str]:
    resolver = JSResolver('')
    return resolver.extract_graphql(js_content)


def extract_websocket_urls(js_content: str) -> List[str]:
    resolver = JSResolver('')
    return resolver.extract_websocket(js_content)


def extract_env_variables(js_content: str) -> Dict[str, str]:
    resolver = JSResolver('')
    return resolver.extract_env_vars(js_content)


__all__ = ['JSResolver', 'JSDiscoveryRecord', 'APIEndpoint', 'ConfigExtraction', 'extract_js_urls', 'extract_endpoints_from_js', 'extract_graphql_endpoints', 'extract_websocket_urls', 'extract_env_variables']
