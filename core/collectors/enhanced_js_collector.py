"""
Enhanced JS Collector Module
整合原 ChkApi.py 的 JS 解析逻辑，增强版
融合了 WebpackAnalyzer 的 Webpack 解析功能
"""

import re
import json
import hashlib
import os
import logging
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor
import sqlite3

logger = logging.getLogger(__name__)

try:
    from .js_collector import WebpackAnalyzer
    WEBPACK_ANALYZER_AVAILABLE = True
except ImportError:
    WEBPACK_ANALYZER_AVAILABLE = False
    logger.warning("WebpackAnalyzer not available")


@dataclass
class JSCollectResult:
    """JS采集结果"""
    js_urls: List[str] = field(default_factory=list)
    static_urls: List[str] = field(default_factory=list)
    webpack_chunks: List[str] = field(default_factory=list)
    dynamic_imports: List[str] = field(default_factory=list)
    base_urls: List[str] = field(default_factory=list)
    tree_urls: List[str] = field(default_factory=list)
    api_paths: List[str] = field(default_factory=list)


class JSExtractor:
    """JS内容提取器 - 整合原 jsAndStaticUrlFind.py 逻辑"""
    
    DOMAIN_BLACKLIST = [
        "www.w3.org", "example.com", "github.com", "example.org",
        "www.google", "googleapis.com", "cdn.jsdelivr.net"
    ]
    
    STATIC_EXT_BLACKLIST = [
        '.css', '.jpg', '.jpeg', '.png', '.gif', '.ico', '.svg',
        '.woff', '.woff2', '.ttf', '.eot', '.map'
    ]
    
    @classmethod
    def js_filter(cls, paths: List[str]) -> List[str]:
        """JS路径过滤 - 整合 jsAndStaticUrlFind.jsFilter"""
        result = []
        for path in paths:
            path = path.replace("\\/", "/")
            path = path.replace(" ", "")
            path = path.replace('"', "")
            path = path.replace("'", "")
            path = path.replace("./", "/")
            path = path.replace("%3A", ":")
            path = path.replace("%2F", "/")
            path = path.replace("\\\\", "")
            
            if path.endswith("\\"):
                path = path.rstrip("\\")
            if path.startswith("="):
                path = path.lstrip("=")
            
            for domain in cls.DOMAIN_BLACKLIST:
                if domain in path:
                    path = ""
                    break
            
            if path:
                result.append(path)
        return result
    
    @classmethod
    def static_url_filter(cls, domain: str, paths: List[str]) -> List[str]:
        """静态URL过滤"""
        result = []
        for path in paths:
            path = path.replace("\\/", "/")
            path = path.replace("\\\\", "")
            
            if path.endswith("\\"):
                path = path.rstrip("\\")
            
            if len(path) < 3:
                continue
            if path.endswith('.js'):
                continue
            if any(ext in path.lower() for ext in cls.STATIC_EXT_BLACKLIST):
                continue
            
            if 'http' in path:
                if domain not in path:
                    continue
                result.append(path)
            else:
                result.append(path)
        return list(set(result))
    
    @classmethod
    def extract_webpack_chunks(cls, js_content: str) -> List[str]:
        """
        提取 Webpack chunk 路径
        融合了 WebpackAnalyzer 的高级解析能力
        """
        paths = set()
        
        if WEBPACK_ANALYZER_AVAILABLE:
            try:
                chunks = WebpackAnalyzer.extract_chunks(js_content)
                modules = WebpackAnalyzer.extract_modules(js_content)
                webpack_paths = WebpackAnalyzer.extract_webpack_chunk_paths(js_content)
                paths.update(chunks.keys())
                paths.update(modules)
                paths.update(webpack_paths)
            except Exception as e:
                logger.debug(f"WebpackAnalyzer failed, falling back to regex: {e}")
        
        for m in re.finditer(r'import\(\s*[\'"]([^\'"]+)[\'"]\s*\)', js_content):
            p = m.group(1).strip()
            if p and ('.js' in p or '/api/' in p or '/v' in p):
                paths.add(p)
        
        return list(paths)
    
    @classmethod
    def extract_urls_from_content(
        cls,
        content: str,
        ref_url: str
    ) -> Tuple[List[str], List[str]]:
        """从内容中提取 JS 和静态 URL"""
        parsed = urlparse(ref_url)
        scheme = parsed.scheme
        path = parsed.path
        host = parsed.hostname
        port = parsed.port
        base = f"{scheme}://{host}" + (f":{port}" if port else "")
        root_path = "/"
        
        pattern = re.compile(r'/.*/{1}|/')
        root_result = pattern.findall(path)
        if root_result:
            root_path = root_result[0]
        
        js_patterns = [
            r'http[^\s\'\"\<\>\:\(\)\[\,]+?\.js\b',
            r'["\']/[^\s\'\"\<\>\:\(\)\[\,]+?\.js\b',
            r'=[^\s\'\"\<\>\:\(\)\[\,]+?\.js\b',
            r'=["\'][^\s\'\"\<\>\:\(\)\[\,]+?\.js\b',
        ]
        
        static_url_patterns = [
            r'["\']http[^\s\'\"\<\>\)\(]+?["\']',
            r'=http[^\s\'\"\<\>\)\(]+',
            r'["\']/[^\s\'\"\<\>\:\)\(\u4e00-\u9fa5]+?["\']',
        ]
        
        js_urls = []
        static_urls = []
        
        for js_pattern in js_patterns:
            found = re.findall(js_pattern, content or "")
            found = ["".join(x.strip('"\'')) for x in found]
            found = cls.js_filter(list(set(found)))
            for js_path in found:
                new_url = cls._get_new_url(scheme, base, root_path, js_path)
                new_url = cls._rewrite_internal_host(new_url, base)
                if new_url and new_url not in js_urls:
                    js_urls.append(new_url)
        
        for static_pattern in static_url_patterns:
            found = re.findall(static_pattern, content or "")
            found = ["".join(x.strip('"\'')) for x in found]
            for static_path in found:
                if static_path not in js_urls:
                    static_urls.append(static_path)
        
        return js_urls, static_urls
    
    @staticmethod
    def _get_new_url(scheme: str, base: str, root_path: str, path: str) -> str:
        """构建完整 URL"""
        if path == "" or path == '//' or path == '/':
            return ''
        
        if path.startswith("https:") or path.startswith("http:"):
            return path
        elif path.startswith("//"):
            return scheme + ":" + path
        elif path.startswith("/"):
            return base + path
        elif path.startswith("js/"):
            return base + '/' + path
        else:
            rp = root_path or '/'
            rp_clean = rp.rstrip('/')
            p_clean = path.lstrip('/')
            if rp_clean and (p_clean.startswith(rp_clean.lstrip('/'))):
                return base + '/' + p_clean
            else:
                return base + rp + path
    
    @staticmethod
    def _rewrite_internal_host(url: str, base: str) -> str:
        """重写内部主机"""
        try:
            pu = urlparse(url)
            if pu.hostname in ('127.0.0.1', 'localhost'):
                b = urlparse(base)
                host = b.hostname or ''
                port = pu.port or b.port
                scheme = b.scheme or (pu.scheme or 'http')
                netloc = host if not port else f"{host}:{port}"
                path = pu.path or '/'
                query = ('?' + pu.query) if pu.query else ''
                return f"{scheme}://{netloc}{path}{query}"
        except Exception as e:
            logger.warning(f"URL构建异常: {e}")
            pass
        return url


class APIExtractor:
    """API 路径提取器 - 整合原 apiPathFind.py 逻辑"""
    
    API_PATTERNS = [
        r'(?P<full_url_quoted>["\']http[^\s\'\"\<\>\)\(]{2,250}?["\'])',
        r'(?P<full_url_assign>=https?://[^\s\'\"\<\>\)\(]{2,250})',
        r'(?P<relative_root>["\']/[^\s\'\"\<\>\:\)\(\u4e00-\u9fa5]{1,250}?["\'])',
        r'(?P<relative_path>["\']/[^\s\'\"\<\>\:\)\(\u4e00-\u9fa5]{1,250}?/[^\s\'\"\<\>\:\)\(\u4e00-\u9fa5]{1,250}?["\'])',
    ]
    
    URL_BLACKLIST = [
        'google-analytics.com', 'googleadservices.com', 'facebook.net',
        'twitter.com', 'linkedin.com', 'youtube.com', 'googletagmanager.com'
    ]
    
    URL_EXT_BLACKLIST = [
        '.css', '.jpg', '.jpeg', '.png', '.gif', '.ico', '.svg', '.woff',
        '.map', '.ico', '.xml', '.txt', '.md', '.json', '.html'
    ]
    
    API_ROOT_BLACKLIST = ['\\', '$', '@', '*', '+', '-', '|', '!', '%', '^', '~', '[', ']']
    
    @classmethod
    def url_filter(cls, paths: List[str]) -> List[str]:
        """URL 过滤 - 整合 apiPathFind.urlFilter"""
        result = []
        invalid_keywords = {
            'httpagent', 'httpsagent', 'httpversionnotsupported',
            'xmlhttprequest', 'activexobject', 'mssxml2', 'microsoft',
            'window', 'document', 'location', 'navigator', 'console'
        }
        
        for line in paths:
            line = line.strip()
            
            if any(line.strip('"\'').strip('/').startswith(x) for x in cls.API_ROOT_BLACKLIST):
                continue
            
            line = line.replace(" ", "")
            line = line.replace("\\/", "/")
            line = line.replace('"', "")
            line = line.replace("'", "")
            line = line.replace("%3A", ":")
            line = line.replace("%2F", "/")
            line = line.replace("\\\\", "")
            
            if line.endswith("\\"):
                line = line.rstrip("\\")
            if line.startswith("="):
                line = line.lstrip("=")
            if line.startswith("href="):
                line = line.lstrip("href=")
            if line == 'href':
                line = ""
            
            if not line:
                continue
            
            line_lower = line.lower()
            if line_lower in invalid_keywords:
                continue
            
            if '/' not in line and not line_lower.startswith('http'):
                if line_lower not in ['api', 'v1', 'v2', 'v3']:
                    continue
            
            for black_ext in cls.URL_EXT_BLACKLIST:
                if line.split("?")[0].endswith(black_ext):
                    line = ""
                    break
            
            for blacklist in cls.URL_BLACKLIST:
                if blacklist in line:
                    line = ""
                    break
            
            if line:
                result.append(line)
        
        return result
    
    @classmethod
    def extract_api_paths(cls, js_content: str) -> List[str]:
        """从 JS 内容提取 API 路径"""
        paths = set()
        
        combined_pattern = '|'.join(cls.API_PATTERNS)
        
        for match in re.finditer(combined_pattern, js_content, re.IGNORECASE):
            path = match.group(0).strip('"\'')
            if path and len(path) > 1:
                paths.add(path)
        
        api_specific_patterns = [
            r'(?:api|gateway|service)[/][^\s\'\"]{1,100}',
            r'/v\d+/[^\s\'\"]{1,100}',
            r'/rest/[^\s\'\"]{1,100}',
            r'/api/[^\s\'\"]{1,100}',
        ]
        
        for pattern in api_specific_patterns:
            for match in re.finditer(pattern, js_content, re.IGNORECASE):
                path = match.group(0)
                if path:
                    paths.add(path)
        
        return cls.url_filter(list(paths))


class EnhancedJSCollector:
    """增强版 JS 采集器 - 支持异步并发"""
    
    def __init__(
        self,
        http_client,
        storage=None,
        max_workers: int = 10,
        max_depth: int = 3
    ):
        self.http_client = http_client
        self.storage = storage
        self.max_workers = max_workers
        self.max_depth = max_depth
        
        self.js_cache: Dict[str, str] = {}
        self.url_seen: Set[str] = set()
        self.result = JSCollectResult()
    
    async def collect(
        self,
        target_url: str,
        cookies: str = "",
        progress_callback=None
    ) -> JSCollectResult:
        """执行 JS 采集"""
        self.url_seen.clear()
        self.result = JSCollectResult()
        
        initial_urls = [(target_url, 0)]
        self.url_seen.add(target_url)
        
        current_depth = 0
        while current_depth < self.max_depth:
            urls_to_fetch = [url for url, depth in initial_urls if depth == current_depth]
            
            if not urls_to_fetch:
                break
            
            tasks = []
            for url in urls_to_fetch:
                tasks.append(self._fetch_and_extract(url, cookies))
            
            await self._process_batch(tasks, progress_callback)
            
            current_depth += 1
        
        return self.result
    
    async def _fetch_and_extract(self, url: str, cookies: str) -> Tuple[str, int, List[str], List[str]]:
        """获取 URL 并提取内容"""
        headers = {'Cookie': cookies} if cookies else {}
        
        try:
            response = await self.http_client.request(url, 'GET', headers)
            
            if response.status_code != 200:
                return url, 0, [], []
            
            content = response.content
            
            js_urls, static_urls = JSExtractor.extract_urls_from_content(
                content, url
            )
            
            webpack_chunks = JSExtractor.extract_webpack_chunks(content)
            
            api_paths = APIExtractor.extract_api_paths(content)
            
            return url, 1, js_urls + webpack_chunks + static_urls, api_paths
        
        except Exception as e:
            return url, 0, [], []
    
    async def _process_batch(self, tasks, progress_callback):
        """批量处理"""
        import asyncio
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, Exception):
                continue
            
            url, success, found_urls, api_paths = result
            
            if success:
                for found_url in found_urls:
                    if found_url not in self.url_seen:
                        self.url_seen.add(found_url)
                
                self.result.js_urls.extend([
                    u for u in found_urls if u.endswith('.js') and u not in self.result.js_urls
                ])
                self.result.static_urls.extend([
                    u for u in found_urls if not u.endswith('.js') and u not in self.result.static_urls
                ])
                self.result.api_paths.extend([
                    p for p in api_paths if p not in self.result.api_paths
                ])
    
    def get_statistics(self) -> Dict[str, int]:
        """获取采集统计"""
        return {
            'js_urls': len(self.result.js_urls),
            'static_urls': len(self.result.static_urls),
            'webpack_chunks': len(self.result.webpack_chunks),
            'dynamic_imports': len(self.result.dynamic_imports),
            'base_urls': len(self.result.base_urls),
            'tree_urls': len(self.result.tree_urls),
            'api_paths': len(self.result.api_paths),
            'total_urls': len(self.url_seen)
        }
