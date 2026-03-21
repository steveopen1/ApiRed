"""
JS Fingerprint Cache Module
JS指纹缓存模块 - 避免重复AST解析
"""

import hashlib
import json
import re
from typing import Dict, List, Optional, Any, Set
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
        
        for pattern in [cls.ROUTER_PATTERN, cls.FETCH_PATTERN, cls.AXIOS_PATTERN]:
            matches = pattern.findall(js_content)
            routes.extend(matches)
        
        return list(set(routes))
    
    @classmethod
    def extract_base_urls(cls, js_content: str) -> List[str]:
        """提取Base URLs"""
        matches = cls.URL_PATTERN.findall(js_content)
        return list(set(matches))


class WebpackAnalyzer:
    """Webpack打包分析器"""
    
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
    """JS内容解析器"""
    
    def __init__(self, cache: Optional[JSFingerprintCache] = None):
        self.cache = cache
    
    def parse(self, js_content: str, js_url: str = "") -> ParsedJSResult:
        """解析JS内容"""
        content_bytes = js_content.encode('utf-8', errors='ignore')
        
        if self.cache:
            cached = self.cache.get(content_bytes)
            if cached:
                return cached
        
        apis = APIRouter.extract_routes(js_content)
        urls = APIRouter.extract_base_urls(js_content)
        dynamic_imports = DynamicImportAnalyzer.extract_imports(js_content)
        base_urls = APIRouter.extract_base_urls(js_content)
        
        chunks = WebpackAnalyzer.extract_chunks(js_content)
        modules = WebpackAnalyzer.extract_modules(js_content)
        
        all_urls = list(set(urls + modules + list(chunks.keys())))
        
        result = ParsedJSResult(
            apis=apis,
            urls=all_urls,
            dynamic_imports=dynamic_imports,
            base_urls=base_urls,
            content_hash="",
            file_size=len(content_bytes)
        )
        
        if self.cache:
            self.cache.set(content_bytes, result, js_url)
        
        return result
