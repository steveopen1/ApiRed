"""
JS Fingerprint Cache Module
JS指纹缓存模块 - 避免重复AST解析
"""

import asyncio
import hashlib
import json
import re
import logging
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field

from .api_collector import APIRouter
from ..cache import LRUCache, LFUCache, TwoLevelCache, MultiLevelCacheManager

logger = logging.getLogger(__name__)


@dataclass
class ParsedJSResult:
    """JS解析结果"""
    apis: List[str]
    urls: List[str]
    dynamic_imports: List[str]
    base_urls: List[str]
    content_hash: str
    file_size: int
    parent_paths: Dict[str, List[str]] = field(default_factory=dict)
    path_templates: List[str] = field(default_factory=list)
    extracted_suffixes: List[str] = field(default_factory=list)
    resource_fragments: List[str] = field(default_factory=list)


class JSFingerprintCache:
    """
    JS文件指纹缓存 (多级缓存架构)
    
    L1: 进程内LRU缓存 (快速访问)
    L2: Storage持久化 (数据库/文件)
    """
    
    def __init__(self, storage, max_memory_items: int = 1000, use_lfu: bool = False):
        self.storage = storage
        self._max_memory_items = max_memory_items
        
        cache_class = LFUCache if use_lfu else LRUCache
        self._memory_cache: Any = cache_class(max_size=max_memory_items, ttl=3600)
    
    def get_cache_key(self, content: bytes) -> str:
        """计算内容哈希作为缓存键"""
        return hashlib.sha256(content).hexdigest()[:32]
    
    def _deserialize_result(self, cache_key: str, cached: dict, content: bytes) -> ParsedJSResult:
        """反序列化缓存结果"""
        ast_cache = cached.get('ast', {})
        return ParsedJSResult(
            apis=ast_cache.get('apis', []),
            urls=ast_cache.get('urls', []),
            dynamic_imports=ast_cache.get('dynamic_imports', []),
            base_urls=cached.get('regex', {}).get('base_urls', []),
            content_hash=cache_key,
            file_size=len(content),
            parent_paths=ast_cache.get('parent_paths', {}),
            path_templates=ast_cache.get('path_templates', []),
            extracted_suffixes=ast_cache.get('extracted_suffixes', []),
            resource_fragments=ast_cache.get('resource_fragments', [])
        )
    
    def get(self, content: bytes) -> Optional[ParsedJSResult]:
        """从缓存获取解析结果"""
        cache_key = self.get_cache_key(content)
        
        cached_result = self._memory_cache.get(cache_key)
        if cached_result is not None:
            return cached_result
        
        cached = self.storage.get_js_cache(cache_key)
        if cached:
            result = self._deserialize_result(cache_key, cached, content)
            self._memory_cache.set(cache_key, result)
            return result
        
        return None
    
    def set(self, content: bytes, result: ParsedJSResult, js_url: str = ""):
        """缓存解析结果"""
        cache_key = self.get_cache_key(content)
        result.content_hash = cache_key
        result.file_size = len(content)
        
        self._memory_cache.set(cache_key, result)
        
        ast_data = {
            'apis': result.apis,
            'urls': result.urls,
            'dynamic_imports': result.dynamic_imports,
            'parent_paths': result.parent_paths,
            'path_templates': result.path_templates,
            'extracted_suffixes': result.extracted_suffixes,
            'resource_fragments': result.resource_fragments
        }
        regex_data = {
            'base_urls': result.base_urls
        }
        
        self.storage.insert_js_cache(
            cache_key, js_url, ast_data, regex_data, len(content)
        )
    
    def clear_memory(self):
        """清空内存缓存"""
        self._memory_cache.clear()
    
    def get_all(self) -> List[ParsedJSResult]:
        """获取所有缓存的解析结果"""
        return list(self._memory_cache._cache.values())
    
    @property
    def cache_stats(self) -> Dict[str, Any]:
        """获取缓存统计信息"""
        return self._memory_cache.stats


class WebpackAnalyzer:
    """
    Webpack打包分析器
    参考 0x727/ChkApi 的 webpack_js_find 功能
    """

    CHUNK_PATTERN = re.compile(r'''
        ["']?([\w]{1,30})["']?\s*:\s*
        ["']?([\w.-]{10,50})["']?
    ''', re.VERBOSE)

    MODULE_PATTERN = re.compile(r'''
        \.\/([\w/-]+)\.js
    ''', re.VERBOSE)

    @classmethod
    def extract_chunks(cls, js_content: str) -> Dict[str, str]:
        """提取chunk映射"""
        chunks = {}
        matches = cls.CHUNK_PATTERN.findall(js_content)
        for name, hash_val in matches:
            if len(hash_val) >= 8:
                chunks[name] = hash_val
        return chunks

    @classmethod
    def extract_modules(cls, js_content: str) -> List[str]:
        """提取模块引用"""
        return cls.MODULE_PATTERN.findall(js_content)

    @classmethod
    def extract_webpack_chunk_paths(cls, js_content: str) -> List[str]:
        """
        提取 Webpack chunk 路径
        整合 0x727/ChkApi 的完整 webpack 解析逻辑
        """
        paths = set()

        m = re.search(
            r'return\s+[a-zA-Z]\.p\+"([^"]+)".*\{(.*)\}\[[a-zA-Z]\]\+"\.js"\}',
            js_content
        )
        if m:
            base_path = m.group(1)
            json_string = m.group(2)
            pairs = json_string.split(',')
            formatted_pairs = []
            for pair in pairs:
                try:
                    key, value = pair.split(':', 1)
                except Exception as e:
                    logger.warning(f"JSON键值对解析异常: {e}")
                    continue
                if not key.strip().startswith('"'):
                    continue
                if not value.strip().startswith('"'):
                    continue
                formatted_pairs.append(key + ':' + value)
            try:
                chunk_mapping = json.loads('{' + ','.join(formatted_pairs) + '}')
                for key, value in chunk_mapping.items():
                    paths.add('/' + base_path + key + '.' + value + '.js')
            except Exception as e:
                logger.warning(f"JSON解析异常: {e}")
                pass

        for m in re.finditer(
            r'__webpack_require__\.u\s*=\s*function\(\w+\)\s*\{\s*return\s*"([^"]+)"\s*\+\s*\w+\s*\+\s*"([^"]+)"',
            js_content
        ):
            dirprefix, suffix = m.groups()
            for c in re.findall(r'__webpack_require__\.e\(\s*[\'"]([^\'"]+)[\'"]\s*\)', js_content):
                paths.add('/' + dirprefix + c + suffix)

        for m in re.finditer(r'webpackChunkName\s*:\s*[\'"]([^\'"]+)[\'"]', js_content):
            name = m.group(1)
            if name and not name.endswith('.js'):
                paths.add('./' + name + '.js')

        for m in re.finditer(r'import\(\s*[\'"]([^\'"]+)[\'"]\s*\)', js_content):
            p = m.group(1).strip()
            if p:
                paths.add(p)

        return list(paths)

    @classmethod
    def extract_promise_chunks(cls, js_content: str) -> List[str]:
        """提取 Promise-based chunk 加载"""
        paths = set()

        promise_patterns = [
            r'\.\/([\w/-]+)\.js',
            r'"([\w/-]+)"\s*:\s*function',
            r'e\.a\("([^"]+)"\)',
        ]

        for pattern in promise_patterns:
            for m in re.finditer(pattern, js_content):
                path = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
                if path and not path.startswith('.'):
                    paths.add('./' + path + '.js')

        return list(paths)


class WebpackChunkAnalyzer:
    """
    Webpack Chunk 递归提取器 - 完整版

    支持：
    1. Webpack 4/5 chunk 映射解析
    2. Module Federation 远程模块发现
    3. dynamic-import/chunk Promise 加载
    4. __webpack_require__ 异步模块
    5. 递归解析 chunk 内容
    """

    WEBPACK_REQUIRE_PATTERNS = [
        r'__webpack_require__\.e\(\s*["\']([^"\']+)["\']\s*\)',
        r'__webpack_require__\.oe\(\s*["\']([^"\']+)["\']\s*\)',
        r'__webpack_require__\.r\(["\']([^"\']+)["\']\)',
    ]

    CHUNK_MAPPING_PATTERNS = [
        r'\.p\s*\+\s*["\']([^"\']+)["\']\s*\+\s*["\']',
        r'["\']([^"\']+)["\']\s*\+\s*["\']([^"\']+)["\']\s*\+\s*["\']',
        r'root\s*\+\s*["\']([^"\']+)["\']',
    ]

    FEDERATION_PATTERNS = [
        r'Federation\.import\(\s*["\']([^"\']+)["\']\s*\)',
        r'federation\.import\(\s*["\']([^"\']+)["\']\s*\)',
        r'remote\.import\(\s*["\']([^"\']+)["\']\s*\)',
        r'__federation_import\(\s*["\']([^"\']+)["\']\s*\)',
    ]

    ASYNC_IMPORT_PATTERNS = [
        r'import\(\s*["\']([^"\']+\.js)["\']\s*\)',
        r'import\s*\(\s*["\']([^"\']+)["\']\s*\)',
        r'require\.e\(\s*["\']([^"\']+)["\']\s*\)',
        r'require\(["\']([^"\']+\.js)["\']\)',
        r'resolve\(["\']([^"\']+)["\']\)',
    ]

    CHUNK_NAME_PATTERNS = [
        r'\.chunkId\s*=\s*["\']([^"\']+)["\']',
        r'chunkId\s*:\s*["\']([^"\']+)["\']',
        r'"name"\s*:\s*["\']([^"\']+)["\']',
        r'"id"\s*:\s*["\']([^"\']+)["\']',
    ]

    @classmethod
    def extract_chunk_references(cls, js_content: str) -> List[str]:
        """
        从 JS 内容中提取所有 chunk 引用

        Returns:
            chunk 路径列表
        """
        refs = set()

        for pattern in cls.ASYNC_IMPORT_PATTERNS:
            for m in re.finditer(pattern, js_content):
                path = m.group(1) if m.lastindex else m.group(0)
                if path and ('.js' in path or 'chunk' in path.lower()):
                    refs.add(path)

        for pattern in cls.FEDERATION_PATTERNS:
            for m in re.finditer(pattern, js_content):
                path = m.group(1) if m.lastindex else m.group(0)
                if path:
                    refs.add(path)

        for pattern in cls.CHUNK_NAME_PATTERNS:
            for m in re.finditer(pattern, js_content):
                chunk_id = m.group(1) if m.lastindex else m.group(0)
                if chunk_id:
                    refs.add(f"./{chunk_id}.js")

        return list(refs)

    @classmethod
    def extract_webpack_manifest(cls, js_content: str) -> Dict[str, Any]:
        """
        提取 Webpack manifest 信息

        Returns:
            {
                'module_ids': [...],
                'chunk_ids': [...],
                'public_path': 'static/js/',
                'remotes': {...},
                'exposes': {...},
            }
        """
        manifest = {
            'module_ids': [],
            'chunk_ids': [],
            'public_path': '',
            'remotes': {},
            'exposes': {},
        }

        public_path_match = re.search(r'publicPath\s*[=:]\s*["\']([^"\']+)["\']', js_content)
        if public_path_match:
            manifest['public_path'] = public_path_match.group(1)

        for pattern in [
            r'moduleIds\s*:\s*\[([^\]]+)',
            r'chunkIds\s*:\s*\[([^\]]+)',
        ]:
            match = re.search(pattern, js_content)
            if match:
                ids_str = match.group(1)
                ids = re.findall(r'["\']([^"\']+)["\']', ids_str)
                if 'moduleIds' in pattern:
                    manifest['module_ids'].extend(ids)
                elif 'chunkIds' in pattern:
                    manifest['chunk_ids'].extend(ids)

        federation_match = re.search(r'FederationPlugin\s*\(\s*\{([^}]+)\})', js_content, re.DOTALL)
        if federation_match:
            fed_config = federation_match.group(2)
            for rem in re.finditer(r'(?:name|remotes|exposes)\s*:\s*\{([^}]+)\}', fed_config, re.DOTALL):
                if 'name' in fed_config[:fed_config.find(rem.group(0))]:
                    manifest['remotes'].update(re.findall(r'["\']([^"\']+)["\']', rem.group(1)))
                elif 'exposes' in fed_config[:fed_config.find(rem.group(0))]:
                    manifest['exposes'].update(re.findall(r'["\']([^"\']+)["\']', rem.group(1)))

        return manifest

    @classmethod
    def build_chunk_url(cls, chunk_ref: str, public_path: str = '') -> str:
        """
        构建完整的 chunk URL

        Args:
            chunk_ref: chunk 引用
            public_path: public path 前缀

        Returns:
            完整的 chunk URL
        """
        if chunk_ref.startswith('http'):
            return chunk_ref

        if chunk_ref.startswith('//'):
            return 'https:' + chunk_ref

        if chunk_ref.startswith('/'):
            return public_path.rstrip('/') + '/' + chunk_ref.lstrip('/')

        return public_path.rstrip('/') + '/' + chunk_ref

    @classmethod
    def extract_all_chunks_from_manifest(cls, js_content: str) -> List[str]:
        """
        从 Webpack manifest 提取所有 chunk 路径

        Returns:
            chunk 路径列表
        """
        chunks = set()
        manifest = cls.extract_webpack_manifest(js_content)

        public_path = manifest.get('public_path', '')

        for chunk_id in manifest.get('chunk_ids', []):
            chunk_url = cls.build_chunk_url(f"./{chunk_id}.js", public_path)
            chunks.add(chunk_url)

        for chunk_id in manifest.get('module_ids', []):
            if isinstance(chunk_id, str) and ('.' in chunk_id or '/' in chunk_id):
                chunk_url = cls.build_chunk_url(chunk_id, public_path)
                chunks.add(chunk_url)

        for remote in manifest.get('remotes', {}).keys():
            if remote.startswith('./') or '/' in remote:
                chunks.add(remote)

        for exposed in manifest.get('exposes', {}).keys():
            if exposed.startswith('./') or '/' in exposed:
                chunks.add(exposed)

        chunks.update(cls.extract_chunk_references(js_content))

        return list(chunks)


class RecursiveJSExtractor:
    """
    递归 JS 提取器

    从初始 JS 列表递归提取所有依赖的 JS 模块
    支持 Webpack/Vite/Parcel 等打包工具
    """

    def __init__(self, http_client=None, max_depth: int = 5, max_chunks_per_level: int = 100):
        self.http_client = http_client
        self.max_depth = max_depth
        self.max_chunks_per_level = max_chunks_per_level
        self.visited_urls: Set[str] = set()
        self.pending_urls: List[str] = []
        self.all_js_contents: Dict[str, str] = {}
        self.all_chunk_refs: List[str] = []

    async def extract_from_urls(self, initial_urls: List[str]) -> Dict[str, str]:
        """
        从初始 URL 列表递归提取所有 JS

        Args:
            initial_urls: 初始 JS URL 列表

        Returns:
            {js_url: js_content}
        """
        self.pending_urls = list(set(initial_urls))[:self.max_chunks_per_level]

        for depth in range(self.max_depth):
            if not self.pending_urls:
                break

            logger.info(f"Recursive JS extraction depth {depth + 1}, pending: {len(self.pending_urls)}")

            batch = self.pending_urls[:self.max_chunks_per_level]
            self.pending_urls = self.pending_urls[self.max_chunks_per_level:]

            contents = await self._fetch_batch(batch)

            new_chunks = []
            for url, content in contents.items():
                if url not in self.visited_urls:
                    self.visited_urls.add(url)
                    self.all_js_contents[url] = content

                    if content:
                        chunk_refs = WebpackChunkAnalyzer.extract_all_chunks_from_manifest(content)
                        for chunk in chunk_refs:
                            normalized = self._normalize_chunk_url(chunk, url)
                            if normalized and normalized not in self.visited_urls:
                                new_chunks.append(normalized)

            self.pending_urls.extend(new_chunks)
            self.pending_urls = list(set(self.pending_urls))

        return self.all_js_contents

    async def _fetch_batch(self, urls: List[str]) -> Dict[str, str]:
        """批量获取 JS 内容"""
        if not self.http_client:
            return {}

        contents = {}
        tasks = []

        for url in urls:
            if url and url not in self.visited_urls:
                tasks.append(self._fetch_js(url))

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for url, result in zip(urls, results):
                if isinstance(result, str):
                    contents[url] = result

        return contents

    async def _fetch_js(self, url: str) -> str:
        """获取单个 JS 文件内容"""
        try:
            if self.http_client:
                resp = await self.http_client.request(url, timeout=10)
                if resp and resp.status_code == 200:
                    return resp.text
        except Exception as e:
            logger.debug(f"Failed to fetch {url}: {e}")
        return ""

    def _normalize_chunk_url(self, chunk: str, referer: str) -> Optional[str]:
        """规范化 chunk URL"""
        if not chunk:
            return None

        chunk = chunk.strip()

        if chunk.startswith('http'):
            return chunk

        if chunk.startswith('//'):
            return 'https:' + chunk

        if chunk.startswith('/'):
            from urllib.parse import urlparse
            ref_parsed = urlparse(referer)
            base = f"{ref_parsed.scheme}://{ref_parsed.netloc}"
            return base + chunk

        from urllib.parse import urljoin
        return urljoin(referer, chunk)

    @classmethod
    def extract_promise_chunks(cls, js_content: str) -> List[str]:
        """提取 Promise-based chunk 加载"""
        paths = set()

        promise_patterns = [
            r'\.\/([\w/-]+)\.js',
            r'"([\w/-]+)"\s*:\s*function',
            r'e\.a\("([^"]+)"\)',
        ]

        for pattern in promise_patterns:
            for m in re.finditer(pattern, js_content):
                path = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
                if path and not path.startswith('.'):
                    paths.add('./' + path + '.js')

        return list(paths)


class DynamicImportAnalyzer:
    """动态导入分析器"""
    
    IMPORT_PATTERN = re.compile(r'''
        (?:import|dynamicImport)\s*\(?
        ['"`]([^'"`]+)['"`]
    ''', re.VERBOSE | re.IGNORECASE)
    
    REQUIRE_PATTERN = re.compile(r'''
        require\s*\(?
        ['"`]([^'"`]+)['"`]
    ''', re.VERBOSE)
    
    @classmethod
    def extract_imports(cls, js_content: str) -> List[str]:
        """提取动态导入"""
        imports = set()
        
        imports.update(cls.IMPORT_PATTERN.findall(js_content))
        imports.update(cls.REQUIRE_PATTERN.findall(js_content))
        
        return list(imports)


class JSParser:
    """
    JS内容解析器 - 增强版
    
    支持 AST 解析优先，正则作为后备方案。
    智能提取 API 路径、父路径、RESTful 模板、启发式猜测。
    """
    
    HTTP_METHODS = {
        'get', 'post', 'put', 'delete', 'patch', 'head', 'options', 'trace', 'connect',
        'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT'
    }
    
    HTTP_CLIENTS = {
        'axios', 'fetch', 'request', 'http', 'https', 'ajax', 'vue', 'vueResource',
        'superagent', 'got', 'nodeFetch', 'undici', 'urllib', 'reqwest', 'httpx',
        'jQuery', '$', '$.ajax', 'vue.http', 'vue.fetch', 'this.axios', 'this.$http',
        'window.fetch', 'global.fetch', 'api', 'service', 'client', 'httpClient',
        'create', 'instance', 'app', 'router', 'route'
    }
    
    COMMON_PATTERNS = {
        'url', 'uri', 'path', 'endpoint', 'api', 'baseURL', 'baseUrl', 'BASE_URL',
        'href', 'src', 'action', 'route'
    }
    
    DYNAMIC_PARAM_PATTERNS = [
        r'\{[^}]+\}',     
        r':[a-zA-Z_][a-zA-Z0-9_]*',  
        r'<[^>]+>',        
    ]
    
    CRUD_SUFFIXES = ['list', 'get', 'add', 'create', 'update', 'edit', 'delete', 'remove',
                     'detail', 'info', 'page', 'all', 'count', 'export', 'import',
                     'enable', 'disable', 'submit', 'cancel', 'reset', 'search', 'query',
                     'filter', 'sort', 'upload', 'download']
    
    RESOURCE_VERBS = ['list', 'get', 'create', 'update', 'delete', 'add', 'edit', 'remove',
                      'detail', 'info', 'page', 'all', 'count', 'export', 'import',
                      'enable', 'disable', 'submit', 'cancel', 'reset', 'login', 'logout',
                      'token', 'refresh', 'captcha', 'verify', 'register', 'signup', 'signin',
                      'password', 'reset', 'forgot', 'confirm', 'approve', 'reject']
    
    MANAGER_MODULES = ['admin', 'manage', 'config', 'setting', 'system', 'dashboard',
                       'profile', 'account', 'user', 'role', 'permission', 'menu',
                       'log', 'monitor', 'statistics', 'report', 'analytics']
    
    _UUID_PATTERN = re.compile(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', re.IGNORECASE)
    _ALPHANUM_DASH_UNDERSCORE_PATTERN = re.compile(r'^[a-zA-Z0-9_-]+$')
    _LOWERCASE_ALPHANUM_PATTERN = re.compile(r'^[a-z0-9]+$')
    _DYNAMIC_PARAM_PATTERNS = [
        re.compile(r'\{[^}]+\}'),
        re.compile(r':[a-zA-Z_][a-zA-Z0-9_]*'),
        re.compile(r'<[^>]+>'),
    ]
    
    _SUFFIX_PATTERNS = [
        re.compile(r'["\']((?:list|add|create|delete|detail|info|update|edit|remove|get|set|save|submit)[A-Z][a-zA-Z]*)["\']'),
        re.compile(r'["\'](/(?:list|add|create|delete|detail|info|update|edit|remove|get|set|save|submit)(?:/[^"\']*)?)["\']'),
        re.compile(r'["\']((?:List|Add|Create|Delete|Detail|Info|Update|Edit|Remove|Get|Set|Save|Submit)[A-Za-z]*)["\']'),
        re.compile(r'\.(?:list|add|create|delete|detail|info|update|edit|remove|get|set|save|submit)\s*\('),
    ]
    
    _RESOURCE_PATTERNS = [
        re.compile(r'["\'](?:/(?:admin|user|order|product|role|menu|category|config|system|auth|api|v\d+(?:\.\d+)?)/[a-z][a-zA-Z]*(?:/[a-z][a-zA-Z]*)?)["\']', re.IGNORECASE),
        re.compile(r'["\'](#{(?:/[a-z][a-zA-Z]*)+})["\']'),
        re.compile(r'(?:url|path|api|endpoint|route)\s*[:=]\s*["\']([^"\']+)["\']'),
    ]
    
    _COMMON_SUFFIXES_SET = frozenset([
        'list', 'add', 'create', 'delete', 'detail', 'info', 'update', 'edit', 'remove',
        'get', 'set', 'save', 'query', 'search', 'filter', 'sort', 'page',
        'all', 'count', 'total', 'sum', 'export', 'import', 'upload', 'download',
        'enable', 'disable', 'status', 'config', 'settings', 'login', 'logout',
        'register', 'reset', 'init', 'refresh', 'sync', 'menu', 'nav', 'route',
        'tree', 'select', 'option', 'combo', 'autocomplete', 'validate', 'verify',
        'approve', 'reject', 'cancel', 'close', 'open', 'check',
        'bind', 'unbind', 'link', 'unlink', 'join', 'leave', 'accept', 'refuse',
    ])
    
    _COMMON_RESOURCES_SET = frozenset([
        'user', 'users', 'order', 'orders', 'product', 'products', 'goods',
        'role', 'roles', 'menu', 'menus', 'category', 'categories', 'catalog',
        'config', 'configuration', 'settings', 'system', 'admin', 'auth', 'login',
        'department', 'dept', 'organization', 'org', 'employee',
        'customer', 'customers', 'supplier', 'suppliers', 'account', 'accounts',
        'profile', 'permission', 'permissions', 'resource', 'resources',
        'tag', 'tags', 'comment', 'comments',
        'attachment', 'attachments', 'file', 'files', 'image', 'images', 'video', 'videos',
        'payment', 'transaction', 'invoice', 'refund', 'cart', 'shop', 'item', 'items',
        'sku', 'stock', 'inventory', 'warehouse', 'address', 'area', 'region',
    ])

    NON_RESOURCE_SEGMENTS = frozenset({
        'inspect', 'proxy', 'gateway', 'api', 'service', 'web', 'www',
        'v1', 'v2', 'v3', 'v4', 'v5', 'rest', 'graphql', 'rpc',
        'internal', 'external', 'open', 'public', 'private',
        'mobile', 'app', 'client', 'cdn', 'static', 'assets',
    })

    FILE_EXTENSIONS = {
        '.js', '.css', '.html', '.htm', '.json', '.xml',
        '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
        '.woff', '.woff2', '.ttf', '.eot', '.map',
        '.txt', '.md', '.yaml', '.yml', '.env',
    }
    
    COMMON_FILE_PATHS = {
        'assets', 'static', 'public', 'dist', 'build',
        'images', 'img', 'icons', 'fonts', 'css', 'js',
        'lib', 'libs', 'node_modules', 'vendor', 'bower_components',
    }
    
    def __init__(self, cache: Optional[JSFingerprintCache] = None):
        self.cache = cache
        self._ast_parser = None
        self._use_ast = self._check_esprima_available()
        self._extracted_apis = set()
        
        self.prefix_discovery_enabled = True
        self.max_prefix_count = 50
        self.min_prefix_frequency = 2
        self.max_path_depth = 5
    
    def _check_esprima_available(self) -> bool:
        """检查 esprima 是否可用"""
        try:
            import esprima  # type: ignore
            self._ast_parser = esprima
            return True
        except ImportError:
            return False
    
    def _is_likely_id(self, s: str) -> bool:
        """
        判断路径段是否可能是 ID
        """
        if not s or len(s) < 1:
            return False
        
        if s.isdigit():
            return True
        
        if self._UUID_PATTERN.match(s):
            return True
        
        if len(s) > 3 and s[:2].isalpha() and s[2:].isdigit():
            return True
        
        if len(s) > 8 and self._ALPHANUM_DASH_UNDERSCORE_PATTERN.match(s) and ('-' in s or '_' in s):
            return True
        
        if len(s) > 12 and self._LOWERCASE_ALPHANUM_PATTERN.match(s):
            return True
        
        return False
    
    def _is_file_path(self, path: str) -> bool:
        """
        判断路径是否可能是文件路径而非 API 路径
        """
        if not path:
            return False
        
        path_lower = path.lower()
        
        if any(path_lower.endswith(ext) for ext in self.FILE_EXTENSIONS):
            return True
        
        parts = path.strip('/').lower().split('/')
        for part in parts:
            if part in self.COMMON_FILE_PATHS:
                return True
            if '.' in part and not part.startswith('.'):
                return True
        
        return False
    
    def generate_parent_paths(self, path: str, max_depth: int = 3) -> List[str]:
        """
        从完整路径生成可能的父路径前缀（通用版）
        
        例如: /admin/user/list -> [/admin/user, /admin]
        例如: /api/v2/orders/123 -> [/api/v2/orders] (ID级别不作为资源)
        
        Args:
            path: 完整路径
            max_depth: 最大父路径深度
            
        Returns:
            父路径列表（从长到短）
        """
        if not path or not isinstance(path, str):
            return []
        
        original_path = path
        
        if path.startswith('http://') or path.startswith('https://'):
            from urllib.parse import urlparse
            parsed = urlparse(path)
            path = parsed.path
        
        path = path.strip('/')
        if not path:
            return []
        
        parts = path.split('/')
        
        if len(parts) <= 2:
            return []
        
        def is_likely_id(s: str) -> bool:
            return (
            s.isdigit() or 
            bool(self._UUID_PATTERN.match(s)) or
            (len(s) > 3 and s[:2].isalpha() and s[2:].isdigit()) or
            (len(s) > 8 and bool(self._ALPHANUM_DASH_UNDERSCORE_PATTERN.match(s)) and ('-' in s or '_' in s))
        )
        
        valid_parts_count = len(parts)
        for i, part in enumerate(parts):
            if is_likely_id(part) and i > 0:
                valid_parts_count = i
                break
        
        if valid_parts_count < 2:
            return []
        
        parent_paths = []
        for i in range(1, min(valid_parts_count, max_depth + 1)):
            parent_path = '/' + '/'.join(parts[:-i])
            if parent_path and len(parent_path) > 1:
                parent_paths.append(parent_path)
        
        return parent_paths
    
    def discover_api_prefixes(
        self,
        paths: List[str],
        min_frequency: Optional[int] = None,
        max_prefixes: Optional[int] = None
    ) -> List[str]:
        """
        从多个 API 路径中发现公共前缀（智能前缀发现 - 改进版）
        
        改进点：
        - 过滤文件路径（.js, .css, .html 等）
        - 限制最大路径深度
        - 限制返回的前缀数量
        - 去重去子路径
        - 记录发现来源用于调试
        
        Args:
            paths: API 路径列表
            min_frequency: 最小出现频率（默认使用 self.min_prefix_frequency）
            max_prefixes: 最大前缀数量（默认使用 self.max_prefix_count）
            
        Returns:
            发现的 API 前缀列表
        """
        if not paths or len(paths) < 2:
            return []
        
        if not self.prefix_discovery_enabled:
            return []
        
        min_freq = min_frequency if min_frequency is not None else self.min_prefix_frequency
        max_pfx = max_prefixes if max_prefixes is not None else self.max_prefix_count
        
        path_segments: List[Tuple[List[str], str]] = []
        
        for path in paths:
            if not isinstance(path, str):
                continue
            
            original_path = path
            
            if path.startswith('http://') or path.startswith('https://'):
                from urllib.parse import urlparse
                parsed = urlparse(path)
                path = parsed.path
            
            path = path.strip('/')
            if not path:
                continue
            
            if self._is_file_path(path):
                continue
            
            parts = path.split('/')
            
            if len(parts) > self.max_path_depth:
                parts = parts[:self.max_path_depth]
            
            filtered_parts = []
            for i, part in enumerate(parts):
                if i > 0:
                    if self._is_likely_id(part):
                        break
                    part_lower = part.lower()
                    if (part_lower not in self._COMMON_SUFFIXES_SET and
                        part_lower not in self._COMMON_RESOURCES_SET and
                        part_lower not in self.NON_RESOURCE_SEGMENTS):
                        break
                filtered_parts.append(part)
            
            if len(filtered_parts) >= 1:
                path_segments.append((filtered_parts, original_path))
        
        if not path_segments:
            return []
        
        prefix_sources: Dict[str, Set[str]] = {}
        
        for segments, original in path_segments:
            for depth in range(1, len(segments) + 1):
                prefix = '/' + '/'.join(segments[:depth])
                if prefix not in prefix_sources:
                    prefix_sources[prefix] = set()
                prefix_sources[prefix].add(original)
        
        prefix_counts = [(p, len(sources)) for p, sources in prefix_sources.items()]
        
        candidates = [(p, c) for p, c in prefix_counts if c >= min_freq]
        
        candidates.sort(key=lambda x: (-x[1], -len(x[0])))
        
        prefixes: List[str] = []
        for prefix, count in candidates:
            if len(prefixes) >= max_pfx:
                break
            
            is_subpath = False
            for existing in prefixes:
                if existing.startswith(prefix + '/') or existing == prefix:
                    is_subpath = True
                    break
            if not is_subpath:
                prefixes.append(prefix)
        
        return prefixes
    
    def discover_api_prefixes_detailed(
        self,
        paths: List[str],
        min_frequency: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        发现 API 前缀的详细版本（包含来源信息）
        
        Returns:
            {
                'prefixes': [...],
                'details': {
                    '/admin/user': {
                        'count': 5,
                        'sources': ['/admin/user/list', '/admin/user/add', ...]
                    }
                }
            }
        """
        if not paths or len(paths) < 2:
            return {'prefixes': [], 'details': {}}
        
        min_freq = min_frequency if min_frequency is not None else self.min_prefix_frequency
        
        path_segments: List[Tuple[List[str], str]] = []
        
        for path in paths:
            if not isinstance(path, str):
                continue
            
            original_path = path
            
            if path.startswith('http://') or path.startswith('https://'):
                from urllib.parse import urlparse
                parsed = urlparse(path)
                path = parsed.path
            
            path = path.strip('/')
            if not path or self._is_file_path(path):
                continue
            
            parts = path.split('/')
            if len(parts) > self.max_path_depth:
                parts = parts[:self.max_path_depth]
            
            filtered_parts = []
            for i, part in enumerate(parts):
                if i > 0:
                    if self._is_likely_id(part):
                        break
                    part_lower = part.lower()
                    if (part_lower not in self._COMMON_SUFFIXES_SET and
                        part_lower not in self._COMMON_RESOURCES_SET and
                        part_lower not in self.NON_RESOURCE_SEGMENTS):
                        break
                filtered_parts.append(part)
            
            if len(filtered_parts) >= 1:
                path_segments.append((filtered_parts, original_path))
        
        if not path_segments:
            return {'prefixes': [], 'details': {}}
        
        prefix_sources: Dict[str, Set[str]] = {}
        
        for segments, original in path_segments:
            for depth in range(1, len(segments) + 1):
                prefix = '/' + '/'.join(segments[:depth])
                if prefix not in prefix_sources:
                    prefix_sources[prefix] = set()
                prefix_sources[prefix].add(original)
        
        details = {}
        prefixes = []
        
        for prefix, sources in prefix_sources.items():
            count = len(sources)
            if count >= min_freq:
                details[prefix] = {
                    'count': count,
                    'sources': list(sources)
                }
                prefixes.append(prefix)
        
        prefixes.sort(key=lambda p: (-details[p]['count'], -len(p)))
        
        prefixes = prefixes[:self.max_prefix_count]
        
        final_details = {p: details[p] for p in prefixes}
        
        return {
            'prefixes': prefixes,
            'details': final_details,
            'statistics': {
                'total_paths': len(paths),
                'unique_prefixes': len(prefixes),
                'min_frequency': min_freq
            }
        }
    
    def extract_path_template(self, path: str) -> str:
        """
        提取 RESTful 路径模板，将动态参数替换为占位符
        
        例如: /users/123 -> /users/{id}
              /orders/abc-123/items -> /orders/{id}/items
        
        Args:
            path: 完整路径
            
        Returns:
            路径模板
        """
        if not path:
            return path
        
        template = path
        
        for pattern in self._DYNAMIC_PARAM_PATTERNS:
            template = pattern.sub('{param}', template)
        
        return template
    
    def cluster_urls_by_prefix(self, urls: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        将 URL 按域名和路径前缀聚类
        
        用于发现同属于一个 API 模块的多个端点。
        
        Args:
            urls: URL 列表
            
        Returns:
            {
                "http://example.com/admin": {
                    "domain": "http://example.com",
                    "path_prefix": "/admin",
                    "urls": [完整的 URL 列表],
                    "count": 数量
                }
            }
        """
        from urllib.parse import urlparse
        
        clusters: Dict[str, Dict[str, Any]] = {}
        
        for url in urls:
            if not isinstance(url, str):
                continue
            
            try:
                parsed = urlparse(url)
                domain = f"{parsed.scheme}://{parsed.netloc}"
                path = parsed.path
                
                if not path or path == '/':
                    continue
                
                path = path.strip('/')
                
                parts = path.split('/')
                
                for depth in range(1, len(parts) + 1):
                    prefix_path = '/' + '/'.join(parts[:depth])
                    cluster_key = f"{domain}{prefix_path}"
                    
                    if cluster_key not in clusters:
                        clusters[cluster_key] = {
                            'domain': domain,
                            'path_prefix': prefix_path,
                            'full_prefix': cluster_key,
                            'urls': [],
                            'count': 0
                        }
                    
                    clusters[cluster_key]['urls'].append(url)
                    clusters[cluster_key]['count'] += 1
                    
            except Exception:
                continue
        
        for cluster in clusters.values():
            cluster['urls'] = list(set(cluster['urls']))
            cluster['count'] = len(cluster['urls'])
        
        return clusters
    
    def extract_restful_templates(self, paths: List[str]) -> List[str]:
        """
        从路径列表中提取 RESTful 模板
        
        将具体的 ID 路径转换为模板形式：
        - /users/123 -> /users/{id}
        - /orders/abc-123/items -> /orders/{id}/items
        
        Args:
            paths: 路径列表
            
        Returns:
            模板化后的路径列表
        """
        templates: Set[str] = set()
        
        for path in paths:
            if not isinstance(path, str):
                continue
            
            if path.startswith('http://') or path.startswith('https://'):
                from urllib.parse import urlparse
                parsed = urlparse(path)
                path = parsed.path
            
            path = path.strip('/')
            if not path:
                continue
            
            parts = path.split('/')
            template_parts = []
            
            for i, part in enumerate(parts):
                if self._is_likely_id(part):
                    template_parts.append('{id}')
                    break
                else:
                    template_parts.append(part)
            
            template = '/' + '/'.join(template_parts)
            
            if template != '/' + path:
                templates.add(template)
        
        return list(templates)

    def extract_suffixes_from_js(self, js_content: str) -> Tuple[List[str], List[str]]:
        """
        从 JS 代码中智能提取后缀和资源片段
        
        从 JS 代码字符串字面量中识别：
        - 后缀：list, add, create, delete, detail, info 等
        - 资源片段：user, order, product, role, menu 等
        
        Args:
            js_content: JS 代码内容
            
        Returns:
            (extracted_suffixes, resource_fragments) 元组
        """
        suffixes: Set[str] = set()
        resources: Set[str] = set()
        
        for pattern in self._SUFFIX_PATTERNS:
            for match in pattern.finditer(js_content):
                word = match.group(1) if match.lastindex else match.group(0)
                if word:
                    clean_word = word.strip('/').lower()
                    if 2 < len(clean_word) < 30:
                        suffixes.add(clean_word)
        
        for pattern in self._RESOURCE_PATTERNS:
            for match in pattern.finditer(js_content):
                path = match.group(1) if match.lastindex else match.group(0)
                if path:
                    parts = path.strip('/').split('/')
                    for part in parts:
                        if part and 2 < len(part) < 30:
                            if not part.startswith('{') and not part.endswith('}'):
                                part_lower = part.lower()
                                if part_lower not in ('api', 'admin', 'rest', 'http', 'https', 'www') and not part_lower.startswith('v'):
                                    resources.add(part_lower)
        
        js_lower = js_content.lower()
        
        for suffix in self._COMMON_SUFFIXES_SET:
            if suffix in js_lower:
                suffixes.add(suffix)
        
        for resource in self._COMMON_RESOURCES_SET:
            if resource in js_lower:
                resources.add(resource)
        
        suffixes_list = self._filter_invalid_fragments(list(suffixes), is_suffix=True)
        resources_list = self._filter_invalid_fragments(list(resources), is_suffix=False)
        
        return (suffixes_list, resources_list)
    
    def _filter_invalid_fragments(self, fragments: List[str], is_suffix: bool = False) -> List[str]:
        """
        过滤无效的片段
        
        Args:
            fragments: 待过滤的片段列表
            is_suffix: 是否为后缀片段
            
        Returns:
            过滤后的片段列表
        """
        invalid_patterns = [
            '.color', '.style', '.background', '.border', '.margin', '.padding',
            '.width', '.height', '.size', '.font', '.text', '.align', '.display',
            '.opacity', '.transform', '.animation', '.transition', '.position',
            '.zindex', '.overflow', '.visibility', '.cursor', '.gradient',
            '.shadow', '.radius', '.rotate', '.scale', '.translate',
            '.header', '.footer', '.sidebar', '.container', '.wrapper',
            '.content', '.button', '.input', '.form', '.label', '.icon',
            '.image', '.photo', '.picture', '.video', '.audio', '.media',
            '.modal', '.dialog', '.tooltip', '.popover', '.dropdown', '.menu',
            '.nav', '.tab', '.accordion', '.carousel', '.slider', '.scroll',
            '.loading', '.spinner', '.progress', '.badge', '.alert', '.toast',
            '.card', '.panel', '.well', '.jumbotron', '.thumbnail', '.media',
            '.list', '.table', '.row', '.cell', '.column', '.header', '.footer',
            '.item', '.row', '.element', '.node', '.component', '.module',
            '.util', '.helper', '.factory', '.service', '.controller', '.directive',
            '.filter', '.map', '.reduce', '.forEach', '.some', '.every',
            '.length', '.size', '.count', '.index', '.id', '.key', '.value',
            '.prototype', '.constructor', '.call', '.apply', '.bind', '.this',
            '.get', '.set', '.has', '.contains', '.add', '.remove', '.clear',
        ]
        
        css_property_patterns = [
            r'^[a-z]+[A-Z]',  # camelCase like lineStyle, itemStyle
            r'.*\.[a-z]+$',   # ending with dot property like .color, .size
            r'^[a-z]+-[a-z]+$',  # kebab-case
        ]
        
        filtered = []
        for frag in fragments:
            frag_lower = frag.lower()
            frag_stripped = frag_lower.strip()
            
            if not frag_stripped or len(frag_stripped) < 2:
                continue
            
            if frag_stripped in (',', '.', '/', '\\', '-', '_', '=', '+', '*', '&', '%', '$', '#', '@', '!', '~', '`', '^', '(', ')', '[', ']', '{', '}', '|', ';', ':', '"', "'", '<', '>', '?', ' '):
                continue
            
            if frag_stripped.startswith('.') or frag_stripped.startswith(','):
                continue
            
            if '.' in frag_stripped and not frag_stripped.startswith('/'):
                continue
            
            if any(invalid in frag_lower for invalid in invalid_patterns):
                continue
            
            for pattern in css_property_patterns:
                if re.match(pattern, frag_stripped):
                    continue
            
            if is_suffix:
                if any(c in frag_stripped for c in '=?&%$#@!~`^*()[]{}|;:\'"<>'):
                    continue
            
            filtered.append(frag)
        
        return filtered
    
    def generate_crud_guesses(self, resource_path: str) -> List[str]:
        """
        基于资源路径生成可能的 CRUD 操作猜测
        
        Args:
            resource_path: 资源路径，如 /users, /admin/user
            
        Returns:
            猜测的完整路径列表
        """
        if not resource_path:
            return []
        
        path = resource_path.strip('/')
        base = '/' + path
        
        crud_suffixes = [
            'list', 'page', 'all',
            'add', 'create', 'new',
            'update', 'edit', 'modify',
            'delete', 'remove',
            'detail', 'info', 'get', 'show',
            'exists', 'check',
            'count', 'total', 'sum',
            'export', 'import', 'upload', 'download',
            'enable', 'disable',
            'search', 'query', 'filter',
            'sort', 'order',
        ]
        
        guesses = []
        for suffix in crud_suffixes:
            guesses.append(f'{base}/{suffix}')
        
        return guesses
    
    def _to_singular(self, word: str) -> str:
        """复数转单数"""
        if not word:
            return word
        
        if word.endswith('ies'):
            return word[:-3] + 'y'
        elif word.endswith('es') and len(word) > 3:
            if word.endswith('ses') or word.endswith('xes') or word.endswith('zes') or word.endswith('ches') or word.endswith('shes'):
                return word[:-2]
            return word[:-1]
        elif word.endswith('s') and len(word) > 2 and not word.endswith('ss'):
            return word[:-1]
        
        return word
    
    def _to_plural(self, word: str) -> str:
        """单数转复数"""
        if not word:
            return word
        
        if word.endswith('y') and len(word) > 2 and word[-2] not in 'aeiou':
            return word[:-1] + 'ies'
        elif word.endswith(('s', 'x', 'z', 'ch', 'sh')):
            return word + 'es'
        else:
            return word + 's'
    
    def _is_action_path(self, path: str) -> bool:
        """
        判断路径是否已经是动作路径（不应再添加 CRUD 变体）
        """
        if not path:
            return False
        
        path = path.strip('/')
        parts = path.split('/')
        last_part = parts[-1].lower() if parts else ''
        
        if last_part in self.CRUD_SUFFIXES or last_part in self.RESOURCE_VERBS:
            return True
        
        if last_part.isdigit():
            return True
        
        if self._UUID_PATTERN.match(last_part):
            return True
        
        if self._ALPHANUM_DASH_UNDERSCORE_PATTERN.match(last_part):
            if len(last_part) > 5:
                if last_part[:2].isalpha() and last_part[2:].isdigit():
                    return True
                if '-' in last_part or '_' in last_part:
                    return True
        
        if '@' in last_part or '%' in last_part or '#' in last_part:
            return True
        
        if len(last_part) > 10 and self._LOWERCASE_ALPHANUM_PATTERN.match(last_part):
            return True
        
        return False
    
    def generate_crud_variations(self, path: str) -> List[str]:
        """
        生成基于 CRUD 动作的路径变体（只应用于资源路径）
        
        例如: /users -> [/users/list, /users/add, /users/create, ...]
              /admin/user -> [/admin/user/list, /admin/user/add, ...]
        
        注意：不会对已包含动作后缀的路径添加变体
        
        Args:
            path: 基础路径
            
        Returns:
            CRUD 变体路径列表
        """
        if not path or not isinstance(path, str):
            return []
        
        if self._is_action_path(path):
            return []
        
        path = path.strip('/')
        if not path:
            return []
        
        variations = []
        
        for suffix in self.CRUD_SUFFIXES:
            variations.append(f'/{path}/{suffix}')
        
        return variations
    
    def generate_resource_variations(self, path: str) -> List[str]:
        """
        生成资源相关的路径变体（单复数、RESTful 模式）
        
        例如: /user -> [/users, /user/{id}, /users/{id}]
              /admin/user -> [/admin/users, /admin/user, /admin/user/{id}]
        
        Args:
            path: 资源路径
            
        Returns:
            资源变体路径列表
        """
        if not path or not isinstance(path, str):
            return []
        
        path = path.strip('/')
        if not path:
            return []
        
        variations = []
        parts = path.split('/')
        last_part = parts[-1]
        singular = self._to_singular(last_part)
        plural = self._to_plural(last_part)
        
        base_parts = parts[:-1]
        base = '/'.join(base_parts) if base_parts else ''
        
        if base:
            variations.append(f'/{base}/{plural}')
            variations.append(f'/{base}/{singular}')
            variations.append(f'/{base}/{singular}/{{id}}')
            variations.append(f'/{base}/{plural}/{{id}}')
        else:
            variations.append(f'/{plural}')
            variations.append(f'/{singular}')
            variations.append(f'/{singular}/{{id}}')
            variations.append(f'/{plural}/{{id}}')
        
        return [v for v in variations if v != '/' + path]
    
    def extract_full_path_presets(self, js_content: str) -> Dict[str, List[str]]:
        """
        从 JS 内容中提取完整路径，并生成可能的父路径前缀
        
        Returns:
            {完整路径: [父路径1, 父路径2, ...]}
        """
        results = {}
        
        for api in self._extracted_apis:
            if isinstance(api, str) and api.startswith('/') and '/' in api:
                parents = self.generate_parent_paths(api)
                if parents:
                    results[api] = parents
        
        return results
    
    def parse(self, js_content: str, js_url: str = "") -> ParsedJSResult:
        """
        解析JS内容 - 完整优化版
        
        Args:
            js_content: JS 内容
            js_url: JS 文件 URL
            
        Returns:
            解析结果（包含原始路径、父路径、CRUD变体、资源变体、路径模板）
        """
        content_bytes = js_content.encode('utf-8', errors='ignore')
        
        cached_result = None
        if self.cache:
            cached_result = self.cache.get(content_bytes)
            if cached_result:
                return cached_result
        
        if self._use_ast:
            apis = self._extract_with_ast(js_content)
            urls = APIRouter.extract_base_urls(js_content)
            dynamic_imports = DynamicImportAnalyzer.extract_imports(js_content)
            
            regex_apis = APIRouter.extract_routes(js_content)
            all_apis = list(set(apis) | set(regex_apis))
            if all_apis:
                apis = all_apis
        else:
            urls, dynamic_imports, apis = self._fallback_parse(js_content)
        
        self._extracted_apis.update(apis)
        
        original_apis = set()
        for api in apis:
            if not isinstance(api, str) or not api.startswith('/'):
                continue
            if '/' not in api:
                continue
            if self._is_file_path(api):
                continue
            original_apis.add(api)
        
        parent_apis = set()
        path_templates = set()
        parent_paths_map = {}
        
        for api in original_apis:
            parents = self.generate_parent_paths(api, max_depth=3)
            for parent in parents:
                parent_apis.add(parent)
            
            parent_paths_map[api] = parents
            
            template = self.extract_path_template(api)
            if template and template != api:
                path_templates.add(template)
        
        all_apis = list(original_apis | parent_apis)
        
        discovered_prefixes = self.discover_api_prefixes(list(original_apis), min_frequency=2)
        for prefix in discovered_prefixes:
            if prefix not in parent_apis:
                parent_apis.add(prefix)
        
        restful_templates = self.extract_restful_templates(list(original_apis))
        for template in restful_templates:
            path_templates.add(template)
        
        chunks = WebpackAnalyzer.extract_chunks(js_content)
        modules = WebpackAnalyzer.extract_modules(js_content)
        
        all_urls = list(set(urls + modules + list(chunks.keys())))
        
        extracted_suffixes, resource_fragments = self.extract_suffixes_from_js(js_content)
        
        result = ParsedJSResult(
            apis=all_apis,
            urls=all_urls,
            dynamic_imports=dynamic_imports,
            base_urls=APIRouter.extract_base_urls(js_content),
            content_hash="",
            file_size=len(content_bytes),
            parent_paths=parent_paths_map,
            path_templates=list(path_templates),
            extracted_suffixes=extracted_suffixes,
            resource_fragments=resource_fragments
        )
        
        if self.cache:
            self.cache.set(content_bytes, result, js_url)
        
        return result
    
    def _extract_with_ast(self, js_content: str) -> List[str]:
        """
        使用 AST 解析提取 API 路由
        
        Args:
            js_content: JS 内容
            
        Returns:
            提取的 API 路由列表
        """
        try:
            tree = self._ast_parser.parse(js_content, js_content_type='script')  # type: ignore
            return self._traverse_ast(tree.body)
        except Exception as e:
            logger.warning(f"AST解析异常: {e}")
            return []
    
    def _traverse_ast(self, nodes: List, depth: int = 0, max_depth: int = 8) -> List[str]:
        """
        遍历 AST 节点提取调用表达式
        
        Args:
            nodes: AST 节点列表
            depth: 当前深度
            max_depth: 最大递归深度
            
        Returns:
            提取的 URL 列表（去重）
        """
        urls = []
        seen = set()
        
        for node in nodes:
            for url in self._extract_from_node(node, depth, max_depth):
                if url not in seen:
                    seen.add(url)
                    urls.append(url)
        
        return urls
    
    def _extract_from_node(self, node, depth: int = 0, max_depth: int = 8) -> List[str]:
        """
        从单个 AST 节点提取 URL
        
        Args:
            node: AST 节点
            depth: 当前深度
            max_depth: 最大递归深度，避免深层嵌套导致性能问题
        """
        urls = []
        
        if not node or depth > max_depth:
            return urls
        
        if hasattr(node, 'type'):
            node_type = node.type
            
            if node_type in ('CallExpression', 'OptionalCallExpression'):
                urls.extend(self._extract_call_expr(node))
            
            elif node_type == 'ExpressionStatement' and hasattr(node, 'expression'):
                urls.extend(self._extract_from_node(node.expression, depth + 1, max_depth))
            
            elif node_type == 'VariableDeclaration' and hasattr(node, 'declarations'):
                for decl in node.declarations:
                    if hasattr(decl, 'init') and decl.init:
                        urls.extend(self._extract_from_node(decl.init, depth + 1, max_depth))
            
            elif node_type == 'VariableDeclarator' and hasattr(node, 'init') and node.init:
                urls.extend(self._extract_from_node(node.init, depth + 1, max_depth))
            
            elif node_type == 'AssignmentExpression' and hasattr(node, 'right'):
                urls.extend(self._extract_from_node(node.right, depth + 1, max_depth))
            
            elif node_type == 'SequenceExpression' and hasattr(node, 'expressions'):
                for expr in node.expressions:
                    urls.extend(self._extract_from_node(expr, depth + 1, max_depth))
            
            elif node_type == 'LogicalExpression' and hasattr(node, 'right'):
                urls.extend(self._extract_from_node(node.right, depth + 1, max_depth))
            
            elif node_type == 'ConditionalExpression':
                if hasattr(node, 'consequent') and node.consequent:
                    urls.extend(self._extract_from_node(node.consequent, depth + 1, max_depth))
                if hasattr(node, 'alternate') and node.alternate:
                    urls.extend(self._extract_from_node(node.alternate, depth + 1, max_depth))
            
            elif node_type == 'Literal' and hasattr(node, 'value') and isinstance(node.value, str):
                val = node.value
                if self._is_api_path(val) or self._is_likely_api_string(val):
                    urls.append(val)
            
            elif node_type == 'TemplateLiteral':
                if hasattr(node, 'quasis') and node.quasis:
                    for quasi in node.quasis:
                        val = getattr(quasi, 'value', {}).get('raw', '') or ''
                        if val and (self._is_api_path(val) or self._is_likely_api_string(val)):
                            urls.append(val)
            
            elif node_type == 'BinaryExpression' and hasattr(node, 'left') and hasattr(node, 'right'):
                left = self._extract_from_node(node.left, depth + 1, max_depth)
                right = self._extract_from_node(node.right, depth + 1, max_depth)
                if left: urls.extend(left)
                if right: urls.extend(right)
            
            elif node_type == 'MemberExpression' and hasattr(node, 'object'):
                urls.extend(self._extract_from_node(node.object, depth + 1, max_depth))
            
            elif hasattr(node, 'body'):
                if isinstance(node.body, list):
                    urls.extend(self._traverse_ast(node.body))
                elif node.body:
                    urls.extend(self._extract_from_node(node.body, depth + 1, max_depth))
                
                if hasattr(node, 'consequent') and node.consequent:
                    urls.extend(self._extract_from_node(node.consequent, depth + 1, max_depth))
                if hasattr(node, 'alternate') and node.alternate:
                    urls.extend(self._extract_from_node(node.alternate, depth + 1, max_depth))
        
        return urls
    
    def _extract_call_expr(self, node) -> List[str]:
        """从 CallExpression 提取 URL"""
        urls = []
        
        callee = getattr(node, 'callee', None)
        if not callee:
            return urls
        
        method_name = self._get_method_name(callee)
        
        if method_name in self.HTTP_METHODS:
            for arg in getattr(node, 'arguments', []):
                url = self._extract_arg_url(arg)
                if url:
                    urls.append(url)
        
        if callee.type == 'MemberExpression':
            obj_type = self._get_callee_type(callee)
            
            if obj_type in self.HTTP_CLIENTS or method_name in self.HTTP_METHODS:
                for arg in getattr(node, 'arguments', []):
                    url = self._extract_arg_url(arg)
                    if url:
                        urls.append(url)
            
            if hasattr(callee, 'object') and callee.object:
                urls.extend(self._extract_from_node(callee.object))
                
        elif callee.type == 'Identifier':
            if method_name in self.HTTP_CLIENTS:
                for arg in getattr(node, 'arguments', []):
                    url = self._extract_arg_url(arg)
                    if url:
                        urls.append(url)
            
            if method_name in self.HTTP_METHODS:
                for arg in getattr(node, 'arguments', []):
                    url = self._extract_arg_url(arg)
                    if url:
                        urls.append(url)
        
        return urls
    
    def _get_callee_type(self, callee) -> str:
        """获取被调用对象的类型名"""
        if callee.type == 'MemberExpression':
            obj = getattr(callee, 'object', None)
            if obj:
                if obj.type == 'Identifier':
                    return getattr(obj, 'name', '')
                elif obj.type == 'MemberExpression':
                    return self._get_callee_type(obj) + '.' + self._get_method_name(callee)
                elif obj.type == 'ThisExpression':
                    return 'this.' + self._get_method_name(callee)
        return ''
    
    def _extract_arg_url(self, arg) -> str:
        """从函数参数提取 URL"""
        if not arg:
            return ""
        
        arg_type = getattr(arg, 'type', '')
        
        if arg_type == 'Literal':
            val = getattr(arg, 'value', '')
            if isinstance(val, str) and self._is_api_path(val):
                return val
        
        if arg_type == 'TemplateLiteral':
            val = self._extract_string_value(arg)
            if val and self._is_api_path(val):
                return val
        
        if arg_type == 'BinaryExpression':
            val = self._extract_string_value(arg)
            if val and self._is_api_path(val):
                return val
        
        if arg_type == 'ObjectExpression':
            return self._extract_url_from_object(arg)
        
        if arg_type == 'Identifier':
            return ""
        
        val = self._extract_string_value(arg)
        if val and (self._is_api_path(val) or self._is_likely_api_string(val)):
            return val
        
        return ""
    
    def _extract_url_from_object(self, obj_node) -> str:
        """从对象表达式提取 URL（如 axios 配置对象）"""
        for prop in getattr(obj_node, 'properties', []):
            if not hasattr(prop, 'key') or not hasattr(prop, 'value'):
                continue
            
            key_name = ''
            if hasattr(prop.key, 'name'):
                key_name = prop.key.name
            elif hasattr(prop.key, 'value'):
                key_name = prop.key.value
            
            key_name_lower = key_name.lower() if isinstance(key_name, str) else ''
            
            if key_name_lower in ('url', 'uri', 'path', 'endpoint'):
                value = prop.value
                if getattr(value, 'type', '') == 'Literal':
                    url = getattr(value, 'value', '')
                    if isinstance(url, str) and self._is_api_path(url):
                        return url
                elif getattr(value, 'type', '') == 'TemplateLiteral':
                    url = self._extract_string_value(value)
                    if url and self._is_api_path(url):
                        return url
            
            if key_name_lower == 'method':
                continue
            
            if key_name_lower == 'params':
                continue
            
            if key_name_lower in ('headers', 'data', 'body'):
                continue
            
            if key_name_lower in self.COMMON_PATTERNS:
                value = prop.value
                if getattr(value, 'type', '') == 'Literal':
                    url = getattr(value, 'value', '')
                    if isinstance(url, str) and self._is_api_path(url):
                        return url
        
        return ""
    
    def _get_method_name(self, callee) -> str:
        """获取方法名"""
        if hasattr(callee, 'property') and callee.property:
            if hasattr(callee.property, 'name'):
                return callee.property.name
            elif hasattr(callee.property, 'value'):
                return callee.property.value
        
        if hasattr(callee, 'name'):
            return callee.name
        
        return ""
    
    def _extract_string_value(self, node) -> str:
        """从 AST 节点提取字符串值"""
        if not node:
            return ""
        
        if hasattr(node, 'value') and isinstance(node.value, str):
            return node.value
        
        if hasattr(node, 'raw'):
            raw = node.raw
            if raw and len(raw) >= 2:
                return raw[1:-1]
        
        if node.type == 'TemplateLiteral':
            if hasattr(node, 'quasis') and node.quasis:
                return ''.join(getattr(q, 'value', {}).get('raw', '') or '' for q in node.quasis)
        
        if node.type == 'BinaryExpression':
            left = self._extract_string_value(getattr(node, 'left', None))
            right = self._extract_string_value(getattr(node, 'right', None))
            if left and right:
                return left + right
        
        return ""
    
    def _is_api_path(self, value: str) -> bool:
        """
        判断是否为 API 路径（通用版）
        
        只要路径以 / 开头且层级 >= 2，就认为是可能的 API 路径。
        排除文件路径。
        """
        if not value or not isinstance(value, str):
            return False
        value = value.strip()
        if not value or len(value) < 3:
            return False
        
        if value.startswith('http://') or value.startswith('https://'):
            return True
        
        if not value.startswith('/'):
            return False
        
        path = value.strip('/')
        if not path:
            return False
        
        if self._is_file_path(path):
            return False
        
        parts = path.split('/')
        
        if len(parts) >= 2:
            return True
        
            return False
        
        return False
    
    def _is_likely_api_string(self, value: str) -> bool:
        """
        判断字符串是否可能是 API 路径（宽松模式）
        
        用于 AST 解析中，当普通 _is_api_path 失败时的二次判断。
        匹配常见的 API 路径模式：
        - /api/xxx
        - /v1/xxx, /v2/xxx
        - /rest/xxx
        - /service/xxx
        - /sys/xxx (系统接口)
        - 等等
        """
        if not value or not isinstance(value, str):
            return False
        
        value = value.strip()
        if len(value) < 4:
            return False
        
        if value.startswith(('http://', 'https://')):
            return True
        
        if not value.startswith('/'):
            return False
        
        path = value.strip('/')
        if not path:
            return False
        
        if self._is_file_path(path):
            return False
        
        api_indicators = [
            '/api/', '/v1/', '/v2/', '/v3/', '/v4/',
            '/rest/', '/restapi/', '/service/', '/services/',
            '/sys/', '/sysauth/', '/sysconst/', '/sysmenu/', '/sysorg/', '/sysdict/',
            '/sysdicttype/', '/sysuser/', '/sysrole/', '/syspermission/', '/sysconfig/',
            '/admin/', '/manage/', '/system/',
            '/resource/', '/resources/', '/endpoint/', '/endpoints/',
            '/user/', '/users/', '/order/', '/orders/',
            '/product/', '/products/', '/data/', '/info/',
            '/auth/', '/login/', '/logout/', '/token/',
            '/menu/', '/role/', '/permission/', '/dict/',
            '/monitor/', '/logs/', '/log/', '/file/', '/files/',
            '/config/', '/setting/', '/settings/',
        ]
        
        path_lower = value.lower()
        for indicator in api_indicators:
            if path_lower.startswith(indicator) or indicator in path_lower:
                return True
        
        parts = value.strip('/').split('/')
        if len(parts) >= 2:
            first_part = parts[0].lower()
            if first_part in ('api', 'v1', 'v2', 'v3', 'rest', 'service', 'sys', 'sysauth', 'sysconst', 'sysconfig', 'admin', 'manage', 'monitor', 'logs', 'file', 'files', 'config', 'auth'):
                return True
        
        return False
    
    def _fallback_parse(self, js_content: str) -> Tuple[List[str], List[str], List[str]]:
        """使用正则表达式解析作为后备方案"""
        urls = APIRouter.extract_base_urls(js_content)
        dynamic_imports = DynamicImportAnalyzer.extract_imports(js_content)
        apis = APIRouter.extract_routes(js_content)
        return urls, dynamic_imports, apis
    
    def parse_with_fallback(self, js_content: str) -> List[str]:
        """先尝试 AST 解析，失败后使用正则"""
        if self._use_ast:
            result = self._extract_with_ast(js_content)
            if result:
                return result
        return self._parse_with_regex(js_content)
    
    def _parse_with_regex(self, js_content: str) -> List[str]:
        """使用正则表达式解析"""
        patterns = {
            'fetch': r'fetch\s*\(\s*["\']([^"\']+)["\']',
            'axios': r'axios\.(get|post|put|delete)\s*\(\s*["\']([^"\']+)["\']',
            'router': r'router\.(get|post|put|delete)\s*\(\s*["\']([^"\']+)["\']',
            'api_direct': r'''["'](/api/[a-zA-Z0-9/{}?=&_-]+)["']''',
            'path_with_keywords': r'''["'](/(?:user|users|admin|login|logout|register|student|teacher|course|order|product|api|v\d+|rest|oauth)[a-zA-Z0-9/_-]*)["']''',
        }
        
        urls = []
        for pattern in patterns.values():
            matches = re.findall(pattern, js_content)
            if matches:
                if isinstance(matches[0], tuple):
                    urls.extend([m[1] if len(m) > 1 else m[0] for m in matches])
                else:
                    urls.extend(matches)
        
        return list(set(urls))
