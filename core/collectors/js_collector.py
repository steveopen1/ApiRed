"""
JS Fingerprint Cache Module
JS指纹缓存模块 - 避免重复AST解析
"""

import hashlib
import json
import re
import logging
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field

from .api_collector import APIRouter

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


class JSFingerprintCache:
    """JS文件指纹缓存"""
    
    def __init__(self, storage):
        self.storage = storage
        self._memory_cache: Dict[str, ParsedJSResult] = {}
        self._max_memory_items = 1000
    
    def get_cache_key(self, content: bytes) -> str:
        """计算内容哈希作为缓存键"""
        return hashlib.sha256(content).hexdigest()[:32]
    
    def get(self, content: bytes) -> Optional[ParsedJSResult]:
        """从缓存获取解析结果"""
        cache_key = self.get_cache_key(content)
        
        if cache_key in self._memory_cache:
            return self._memory_cache[cache_key]
        
        cached = self.storage.get_js_cache(cache_key)
        if cached:
            ast_cache = cached.get('ast', {})
            result = ParsedJSResult(
                apis=ast_cache.get('apis', []),
                urls=ast_cache.get('urls', []),
                dynamic_imports=ast_cache.get('dynamic_imports', []),
                base_urls=cached.get('regex', {}).get('base_urls', []),
                content_hash=cache_key,
                file_size=len(content),
                parent_paths=cached.get('parent_paths', {}),
                path_templates=cached.get('path_templates', [])
            )
            
            self._add_to_memory(cache_key, result)
            return result
        
        return None
    
    def set(self, content: bytes, result: ParsedJSResult, js_url: str = ""):
        """缓存解析结果"""
        cache_key = self.get_cache_key(content)
        result.content_hash = cache_key
        result.file_size = len(content)
        
        self._add_to_memory(cache_key, result)
        
        ast_data = {
            'apis': result.apis,
            'urls': result.urls,
            'dynamic_imports': result.dynamic_imports,
            'parent_paths': result.parent_paths,
            'path_templates': result.path_templates
        }
        regex_data = {
            'base_urls': result.base_urls
        }
        
        self.storage.insert_js_cache(
            cache_key, js_url, ast_data, regex_data, len(content)
        )
    
    def _add_to_memory(self, key: str, result: ParsedJSResult):
        """添加到内存缓存"""
        if len(self._memory_cache) >= self._max_memory_items:
            first_key = next(iter(self._memory_cache))
            del self._memory_cache[first_key]
        
        self._memory_cache[key] = result
    
    def clear_memory(self):
        """清空内存缓存"""
        self._memory_cache.clear()
    
    def get_all(self) -> List[ParsedJSResult]:
        """获取所有缓存的解析结果"""
        results = []
        seen_hashes = set()
        
        for cache_key, result in self._memory_cache.items():
            if cache_key not in seen_hashes:
                seen_hashes.add(cache_key)
                results.append(result)
        
        return results


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
    
    _UUID_PATTERN = re.compile(r'^[a-f0-9-]{8,}$')
    _ALPHANUM_DASH_UNDERSCORE_PATTERN = re.compile(r'^[a-zA-Z0-9_-]+$')
    _LOWERCASE_ALPHANUM_PATTERN = re.compile(r'^[a-z0-9]+$')
    _DYNAMIC_PARAM_PATTERNS = [
        re.compile(r'\{[^}]+\}'),
        re.compile(r':[a-zA-Z_][a-zA-Z0-9_]*'),
        re.compile(r'<[^>]+>'),
    ]
    
    def __init__(self, cache: Optional[JSFingerprintCache] = None):
        self.cache = cache
        self._ast_parser = None
        self._use_ast = self._check_esprima_available()
        self._extracted_apis = set()
    
    def _check_esprima_available(self) -> bool:
        """检查 esprima 是否可用"""
        try:
            import esprima
            self._ast_parser = esprima
            return True
        except ImportError:
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
        
        original_apis = set(apis)
        parent_apis = set()
        path_templates = set()
        parent_paths_map = {}
        
        for api in apis:
            if not isinstance(api, str) or not api.startswith('/'):
                continue
            
            if '/' not in api:
                continue
            
            parents = self.generate_parent_paths(api, max_depth=3)
            for parent in parents:
                parent_apis.add(parent)
            
            parent_paths_map[api] = parents
            
            template = self.extract_path_template(api)
            if template and template != api:
                path_templates.add(template)
        
        all_apis = list(original_apis | parent_apis)
        
        chunks = WebpackAnalyzer.extract_chunks(js_content)
        modules = WebpackAnalyzer.extract_modules(js_content)
        
        all_urls = list(set(urls + modules + list(chunks.keys())))
        
        result = ParsedJSResult(
            apis=all_apis,
            urls=all_urls,
            dynamic_imports=dynamic_imports,
            base_urls=APIRouter.extract_base_urls(js_content),
            content_hash="",
            file_size=len(content_bytes),
            parent_paths=parent_paths_map,
            path_templates=list(path_templates)
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
            tree = self._ast_parser.parse(js_content, js_content_type='script')
            return self._traverse_ast(tree.body)
        except Exception as e:
            logger.warning(f"AST解析异常: {e}")
            return []
    
    def _traverse_ast(self, nodes: List) -> List[str]:
        """
        遍历 AST 节点提取调用表达式
        
        Args:
            nodes: AST 节点列表
            
        Returns:
            提取的 URL 列表（去重）
        """
        urls = []
        seen = set()
        
        for node in nodes:
            for url in self._extract_from_node(node):
                if url not in seen:
                    seen.add(url)
                    urls.append(url)
        
        return urls
    
    def _extract_from_node(self, node) -> List[str]:
        """从单个 AST 节点提取 URL"""
        urls = []
        
        if not node:
            return urls
        
        if hasattr(node, 'type'):
            if node.type == 'ExpressionStatement' and hasattr(node, 'expression'):
                urls.extend(self._extract_from_node(node.expression))
            
            elif node.type in ('CallExpression', 'OptionalCallExpression'):
                urls.extend(self._extract_call_expr(node))
            
            elif node.type == 'VariableDeclaration' and hasattr(node, 'declarations'):
                for decl in node.declarations:
                    if hasattr(decl, 'init') and decl.init:
                        urls.extend(self._extract_from_node(decl.init))
            
            elif node.type == 'VariableDeclarator' and hasattr(node, 'init') and node.init:
                urls.extend(self._extract_from_node(node.init))
            
            elif node.type == 'AssignmentExpression' and hasattr(node, 'right'):
                urls.extend(self._extract_from_node(node.right))
            
            elif node.type == 'SequenceExpression' and hasattr(node, 'expressions'):
                for expr in node.expressions:
                    urls.extend(self._extract_from_node(expr))
            
            elif node.type == 'LogicalExpression' and hasattr(node, 'right'):
                urls.extend(self._extract_from_node(node.right))
            
            elif node.type == 'ConditionalExpression':
                if hasattr(node, 'consequent') and node.consequent:
                    urls.extend(self._extract_from_node(node.consequent))
                if hasattr(node, 'alternate') and node.alternate:
                    urls.extend(self._extract_from_node(node.alternate))
            
            elif node.type == 'Literal' and hasattr(node, 'value') and isinstance(node.value, str):
                val = node.value
                if self._is_api_path(val) or self._is_likely_api_string(val):
                    urls.append(val)
            
            elif node.type == 'TemplateLiteral':
                if hasattr(node, 'quasis') and node.quasis:
                    for quasi in node.quasis:
                        val = getattr(quasi, 'value', {}).get('raw', '') or ''
                        if val and (self._is_api_path(val) or self._is_likely_api_string(val)):
                            urls.append(val)
            
            elif node.type == 'BinaryExpression' and hasattr(node, 'left') and hasattr(node, 'right'):
                left = self._extract_from_node(node.left)
                right = self._extract_from_node(node.right)
                if left: urls.extend(left)
                if right: urls.extend(right)
            
            elif hasattr(node, 'body'):
                if isinstance(node.body, list):
                    urls.extend(self._traverse_ast(node.body))
                elif node.body:
                    urls.extend(self._extract_from_node(node.body))
                
                if hasattr(node, 'consequent') and node.consequent:
                    urls.extend(self._extract_from_node(node.consequent))
                if hasattr(node, 'alternate') and node.alternate:
                    urls.extend(self._extract_from_node(node.alternate))
        
        return urls
        
        if hasattr(node, 'type'):
            if node.type == 'ExpressionStatement' and hasattr(node, 'expression'):
                urls.extend(self._extract_from_node(node.expression))
            
            elif node.type in ('CallExpression', 'OptionalCallExpression'):
                urls.extend(self._extract_call_expr(node))
            
            elif node.type == 'VariableDeclaration' and hasattr(node, 'declarations'):
                for decl in node.declarations:
                    if hasattr(decl, 'init') and decl.init:
                        urls.extend(self._extract_from_node(decl.init))
            
            elif node.type == 'AssignmentExpression' and hasattr(node, 'right'):
                urls.extend(self._extract_from_node(node.right))
            
            elif node.type == 'SequenceExpression' and hasattr(node, 'expressions'):
                for expr in node.expressions:
                    urls.extend(self._extract_from_node(expr))
            
            elif node.type == 'LogicalExpression' and hasattr(node, 'right'):
                urls.extend(self._extract_from_node(node.right))
            
            elif hasattr(node, 'body'):
                if isinstance(node.body, list):
                    urls.extend(self._traverse_ast(node.body))
                elif node.body:
                    urls.extend(self._extract_from_node(node.body))
                
                if hasattr(node, 'consequent') and node.consequent:
                    urls.extend(self._extract_from_node(node.consequent))
                if hasattr(node, 'alternate') and node.alternate:
                    urls.extend(self._extract_from_node(node.alternate))
        
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
        
        只要路径以 / 开头且层级 >= 2，或者是常见 API 路径模式，就认为是可能的 API 路径。
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
        
        parts = path.split('/')
        
        if len(parts) >= 2:
            return True
        
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
