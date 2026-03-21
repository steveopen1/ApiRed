"""
JS Fingerprint Cache Module
JS指纹缓存模块 - 避免重复AST解析
"""

import hashlib
import json
import re
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass


@dataclass
class ParsedJSResult:
    """JS解析结果"""
    apis: List[str]
    urls: List[str]
    dynamic_imports: List[str]
    base_urls: List[str]
    content_hash: str
    file_size: int


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
            result = ParsedJSResult(
                apis=cached.get('ast', {}).get('apis', []),
                urls=cached.get('ast', {}).get('urls', []),
                dynamic_imports=cached.get('ast', {}).get('dynamic_imports', []),
                base_urls=cached.get('regex', {}).get('base_urls', []),
                content_hash=cache_key,
                file_size=len(content)
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
            'dynamic_imports': result.dynamic_imports
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


class APIRouter:
    """API路由分析器"""
    
    ROUTE_PATTERN = re.compile(r'''
        (?:router|route|path)\s*[.(]?\s*
        (?:get|post|put|delete|patch|options|head)\s*\(?
        ['"`]([^'"`]+)['"`]
    ''', re.VERBOSE | re.IGNORECASE)
    
    FETCH_PATTERN = re.compile(r'''
        fetch\s*\(\s*['"`]([^'"`]+)['"`]
    ''', re.VERBOSE)
    
    AXIOS_PATTERN = re.compile(r'''
        (?:axios|request)\s*[.(]?\s*(?:get|post|put|delete)\s*\(?
        ['"`]([^'"`]+)['"`]
    ''', re.VERBOSE | re.IGNORECASE)
    
    URL_PATTERN = re.compile(r'''
        (?:api|baseUrl|baseURL)\s*[:=]\s*['"`]([^'"`]+)['"`]
    ''', re.VERBOSE | re.IGNORECASE)
    
    @classmethod
    def extract_routes(cls, js_content: str) -> List[str]:
        """提取路由"""
        routes = []
        
        for pattern in [cls.ROUTE_PATTERN, cls.FETCH_PATTERN, cls.AXIOS_PATTERN]:
            matches = pattern.findall(js_content)
            routes.extend(matches)
        
        return list(set(routes))
    
    @classmethod
    def extract_base_urls(cls, js_content: str) -> List[str]:
        """提取Base URLs"""
        matches = cls.URL_PATTERN.findall(js_content)
        return list(set(matches))


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
                except Exception:
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
            except Exception:
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
    """
    
    def __init__(self, cache: Optional[JSFingerprintCache] = None):
        self.cache = cache
        self._ast_parser = None
        self._use_ast = self._check_esprima_available()
    
    def _check_esprima_available(self) -> bool:
        """检查 esprima 是否可用"""
        try:
            import esprima
            self._ast_parser = esprima
            return True
        except ImportError:
            return False
    
    def parse(self, js_content: str, js_url: str = "") -> ParsedJSResult:
        """
        解析JS内容
        
        Args:
            js_content: JS 内容
            js_url: JS 文件 URL
            
        Returns:
            解析结果
        """
        content_bytes = js_content.encode('utf-8', errors='ignore')
        
        if self.cache:
            cached = self.cache.get(content_bytes)
            if cached:
                return cached
        
        if self._use_ast:
            apis = self._extract_with_ast(js_content)
            if apis:
                urls = APIRouter.extract_base_urls(js_content)
                dynamic_imports = DynamicImportAnalyzer.extract_imports(js_content)
            else:
                urls, dynamic_imports, apis = self._fallback_parse(js_content)
        else:
            urls, dynamic_imports, apis = self._fallback_parse(js_content)
        
        chunks = WebpackAnalyzer.extract_chunks(js_content)
        modules = WebpackAnalyzer.extract_modules(js_content)
        
        all_urls = list(set(urls + modules + list(chunks.keys())))
        
        result = ParsedJSResult(
            apis=apis,
            urls=all_urls,
            dynamic_imports=dynamic_imports,
            base_urls=APIRouter.extract_base_urls(js_content),
            content_hash="",
            file_size=len(content_bytes)
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
        except Exception:
            return []
    
    def _traverse_ast(self, nodes: List) -> List[str]:
        """
        遍历 AST 节点提取调用表达式
        
        Args:
            nodes: AST 节点列表
            
        Returns:
            提取的 URL 列表
        """
        urls = []
        
        for node in nodes:
            if hasattr(node, 'expression') and hasattr(node.expression, 'callee'):
                callee = node.expression.callee
                if hasattr(callee, 'property') and hasattr(callee.property, 'name'):
                    method_name = callee.property.name
                    
                    if method_name in ('get', 'post', 'put', 'delete', 'patch'):
                        args = node.expression.arguments
                        if args and hasattr(args[0], 'value'):
                            urls.append(args[0].value)
            
            if hasattr(node, 'body'):
                if isinstance(node.body, list):
                    urls.extend(self._traverse_ast(node.body))
        
        return urls
    
    def _fallback_parse(self, js_content: str) -> Tuple[List[str], List[str], List[str]]:
        """
        使用正则表达式解析作为后备方案
        
        Args:
            js_content: JS 内容
            
        Returns:
            (urls, dynamic_imports, apis) 元组
        """
        urls = APIRouter.extract_base_urls(js_content)
        dynamic_imports = DynamicImportAnalyzer.extract_imports(js_content)
        apis = APIRouter.extract_routes(js_content)
        
        return urls, dynamic_imports, apis
    
    def parse_with_fallback(self, js_content: str) -> List[str]:
        """
        先尝试 AST 解析，失败后使用正则
        
        Args:
            js_content: JS 内容
            
        Returns:
            提取的 API 列表
        """
        if self._use_ast:
            result = self._extract_with_ast(js_content)
            if result:
                return result
        
        return self._parse_with_regex(js_content)
    
    def _parse_with_regex(self, js_content: str) -> List[str]:
        """
        使用正则表达式解析
        
        Args:
            js_content: JS 内容
            
        Returns:
            提取的 API 列表
        """
        patterns = {
            'fetch': r'fetch\s*\(\s*["\']([^"\']+)["\']',
            'axios': r'axios\.(get|post|put|delete)\s*\(\s*["\']([^"\']+)["\']',
            'router': r'router\.(get|post|put|delete)\s*\(\s*["\']([^"\']+)["\']',
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
