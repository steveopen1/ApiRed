"""
API Collector Module
API采集模块
参考 0x727/ChkApi 实现的完整功能
"""

import re
import json
import logging
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin

logger = logging.getLogger(__name__)


class APIMethodInferrer:
    """
    API HTTP 方法智能推断器
    
    渗透测试思维：根据路径名称推断应该使用的 HTTP 方法
    - GET: 查询、获取列表、获取详情
    - POST: 登录、注册、提交、创建、上传
    - PUT: 更新、编辑
    - (DELETE: 不探测，按用户要求)
    """
    
    GET_KEYWORDS = {
        'list', 'get', 'query', 'fetch', 'find', 'search', 'select',
        'all', 'page', 'tree', 'treeList', 'info', 'detail', 'details',
        'count', 'sum', 'total', 'statistics', 'stats', 'summary',
        'config', 'settings', 'menu', 'options', 'menu', 'permissions',
        'index', 'home', 'dashboard', 'profile', 'userinfo', 'info',
        'acl', 'roles', 'rules', 'verify', 'check', 'validate',
        'status', 'state', 'export', 'download', 'file', 'pdf', 'excel',
        'login', 'logout', 'auth', 'sso', 'captcha', 'verify',
    }
    
    POST_KEYWORDS = {
        'add', 'create', 'new', 'insert', 'register', 'signup',
        'login', 'auth', 'verify', 'submit', 'send', 'push',
        'upload', 'import', 'submit', 'apply', 'enroll',
        'save', 'store', 'confirm', 'accept', 'agree',
        'publish', 'release', 'activate', 'enable',
    }
    
    PUT_KEYWORDS = {
        'update', 'edit', 'modify', 'set', 'change', 'replace',
        'reset', 'restore', 'config', 'setting',
        'move', 'copy', 'rename', 'archive',
    }
    
    SENSITIVE_METHODS = {'POST', 'PUT', 'DELETE', 'PATCH'}
    
    @classmethod
    def infer_methods(cls, path: str) -> List[str]:
        """
        根据路径推断应该使用的 HTTP 方法
        
        Args:
            path: API 路径，如 /user/login, /admin/list
            
        Returns:
            应该探测的 HTTP 方法列表
        """
        path_lower = path.lower()
        segments = path_lower.strip('/').split('/')
        
        methods = set()
        
        for segment in segments:
            for keyword in cls.POST_KEYWORDS:
                if keyword in segment:
                    methods.add('POST')
                    break
            
            for keyword in cls.PUT_KEYWORDS:
                if keyword in segment:
                    methods.add('PUT')
                    break
            
            for keyword in cls.GET_KEYWORDS:
                if keyword in segment:
                    methods.add('GET')
                    break
        
        if not methods:
            methods.add('GET')
            methods.add('POST')
        
        return sorted(list(methods), key=lambda x: {'GET': 0, 'POST': 1, 'PUT': 2, 'PATCH': 3}.get(x, 9))
    
    @classmethod
    def is_json_response(cls, content: str, content_type: str = "") -> bool:
        """
        判断响应是否为 JSON
        
        Args:
            content: 响应内容
            content_type: Content-Type 头
            
        Returns:
            True if response is JSON
        """
        if 'application/json' in content_type.lower():
            return True
        
        content = content.strip()
        if content.startswith('{') or content.startswith('['):
            return True
        
        try:
            json.loads(content)
            return True
        except (json.JSONDecodeError, ValueError):
            return False
    
    @classmethod
    def is_html_response(cls, content: str, content_type: str = "") -> bool:
        """
        判断响应是否为 HTML
        
        Args:
            content: 响应内容
            content_type: Content-Type 头
            
        Returns:
            True if response is HTML
        """
        if 'text/html' in content_type.lower():
            return True
        
        content_lower = content.lower().strip()
        if content_lower.startswith('<!doctype html') or content_lower.startswith('<html'):
            return True
        if '<body' in content_lower or '<head' in content_lower:
            return True
        if '<script' in content_lower and '<style' in content_lower:
            return True
        
        return False
    
    @classmethod
    def is_auth_required_response(cls, status_code: int, content: str, content_type: str = "") -> bool:
        """
        判断响应是否表示需要认证
        
        Args:
            status_code: HTTP 状态码
            content: 响应内容
            content_type: Content-Type 头
            
        Returns:
            True if response indicates authentication required
        """
        if status_code in [401, 403]:
            return True
        
        if status_code == 200:
            content_lower = content.lower()
            auth_keywords = [
                'not logged in', 'not login', 'not authorized',
                'please login', 'please auth', 'token expired',
                'unauthorized', 'forbidden', 'access denied',
                'permission denied', '登录', '授权', '认证',
            ]
            for keyword in auth_keywords:
                if keyword in content_lower:
                    return True
        
        return False


@dataclass
class APIFindResult:
    """API发现结果"""
    path: str
    method: str = "GET"
    source_type: str = "regex"
    base_url: str = ""
    context: Optional[str] = None
    url_type: str = "api_path"


class TFIDFUrlClassifier:
    """
    基于TF-IDF的URL分类器
    
    使用TF-IDF风格的评分机制替代硬阈值判断API前缀：
    - TF: 词频（该段在所有URL中出现的频率）
    - IDF: 逆文档频率（log(总URL数 / 包含该段的URL数)）
    - 位置权重：越靠前的段越可能是API前缀
    """
    
    def __init__(self, known_prefixes: Optional[Set[str]] = None, known_resources: Optional[Set[str]] = None):
        self.known_prefixes = known_prefixes or set()
        self.known_resources = known_resources or set()
        self.segment_freq: Dict[str, int] = {}
        self.doc_freq: Dict[str, int] = {}
        self.total_docs = 0
        self.segment_at_position: Dict[int, List[str]] = {}
        self.segment_positions: Dict[str, Set[int]] = {}
    
    def fit(self, urls: List[str]) -> 'TFIDFUrlClassifier':
        """
        从URL列表学习统计信息
        
        Args:
            urls: URL列表
            
        Returns:
            self
        """
        from collections import Counter, defaultdict
        
        segment_urls = {}
        segment_at_position = defaultdict(list)
        segment_positions = defaultdict(set)
        segment_count = Counter()
        doc_freq = Counter()
        
        for url in urls:
            if not url:
                continue
            
            if url.startswith('http://') or url.startswith('https://'):
                parsed = urlparse(url)
                path = parsed.path
            elif url.startswith('/'):
                path = url
            else:
                continue
            
            if not path or path == '/':
                continue
            
            segments = [s for s in path.split('/') if s]
            if not segments:
                continue
            
            full_path = '/' + '/'.join(segments)
            segment_urls[full_path] = segments
            
            for seg in set(segments):
                doc_freq[seg] += 1
            
            for i, seg in enumerate(segments):
                segment_at_position[i].append(seg)
                segment_count[seg] += 1
                segment_positions[seg].add(i)
        
        self.total_docs = len(segment_urls)
        self.segment_freq = dict(segment_count)
        self.doc_freq = dict(doc_freq)
        self.segment_at_position = dict(segment_at_position)
        self.segment_positions = dict(segment_positions)
        
        return self
    
    def score_segment(self, segment: str, positions: Set[int]) -> float:
        """
        计算段是否是API前缀的TF-IDF评分
        
        Args:
            segment: 要评分的段
            positions: 该段出现的位置集合
            
        Returns:
            TF-IDF评分（越高越可能是API前缀）
        """
        import math
        
        if self.total_docs == 0 or segment not in self.segment_freq:
            return 0.0
        
        tf = self.segment_freq[segment] / self.total_docs
        
        docs_with_segment = self.doc_freq.get(segment, 1)
        if docs_with_segment == 0:
            idf = 0.0
        else:
            idf = math.log(self.total_docs / docs_with_segment)
        
        avg_pos = sum(positions) / len(positions) if positions else 0
        pos_weight = 1.0 / (avg_pos + 1)
        
        return tf * idf * pos_weight
    
    def classify_prefixes(self, urls: List[str], dynamic_threshold: bool = True, 
                          static_threshold: float = 0.1) -> Tuple[Set[str], Set[str]]:
        """
        从URL列表中分类API前缀和资源路径
        
        Args:
            urls: URL列表
            dynamic_threshold: 是否使用动态阈值（基于TF-IDF分布）
            static_threshold: 如果不使用动态阈值，则使用此固定阈值
            
        Returns:
            (identified_api_keywords, resource_candidates)
        """
        if self.total_docs == 0:
            self.fit(urls)
        
        identified_api_keywords = set()
        resource_candidates = set()
        
        for seg, positions in self.segment_positions.items():
            if seg.lower() in self.known_prefixes:
                identified_api_keywords.add(seg)
                continue
            
            if seg.lower() in self.known_resources:
                resource_candidates.add(seg)
                continue
            
            score = self.score_segment(seg, positions)
            
            if dynamic_threshold:
                threshold = self._calculate_dynamic_threshold()
            else:
                threshold = static_threshold
            
            if score > threshold:
                identified_api_keywords.add(seg)
        
        return identified_api_keywords, resource_candidates
    
    def _calculate_dynamic_threshold(self) -> float:
        """
        基于TF-IDF分布计算动态阈值
        
        使用所有段评分的25%分位数作为阈值，
        这样可以自适应地根据数据分布来确定阈值。
        """
        import math
        
        if not self.segment_freq:
            return 0.1
        
        scores = []
        for seg, positions in self.segment_positions.items():
            if seg.lower() not in self.known_prefixes and seg.lower() not in self.known_resources:
                score = self.score_segment(seg, positions)
                if score > 0:
                    scores.append(score)
        
        if not scores:
            return 0.1
        
        scores.sort()
        q1_index = len(scores) // 4
        return max(0.05, scores[q1_index] if q1_index < len(scores) else 0.1)


class LLMUrlClassifier:
    """
    LLM辅助URL分类器
    
    特性：
    - 使用LLM进行语义分析
    - 结果缓存避免重复调用
    - 自动降级到TF-IDF方法
    - 支持批量URL分类
    """
    
    _instance_cache: Dict[str, 'LLMUrlClassifier'] = {}
    _result_cache: Dict[str, Any] = {}
    _cache_max_size = 1000
    _cache_ttl = 3600
    
    def __init__(
        self,
        llm_client=None,
        use_cache: bool = True,
        batch_size: int = 50,
        fallback_threshold: float = 0.8
    ):
        self.llm_client = llm_client
        self.use_cache = use_cache
        self.batch_size = batch_size
        self.fallback_threshold = fallback_threshold
        self._call_count = 0
        self._cache_hit_count = 0
    
    @classmethod
    def get_instance(cls, cache_key: str = "default") -> 'LLMUrlClassifier':
        """获取单例实例"""
        if cache_key not in cls._instance_cache:
            cls._instance_cache[cache_key] = LLMUrlClassifier()
        return cls._instance_cache[cache_key]
    
    def _generate_cache_key(self, urls: List[str]) -> str:
        """生成URL列表的缓存键"""
        import hashlib
        url_str = '|'.join(sorted(urls[:100]))
        return hashlib.md5(url_str.encode()).hexdigest()[:16]
    
    def _parse_llm_response(self, response: Any) -> Optional[Dict[str, Any]]:
        """解析LLM响应"""
        import json
        
        try:
            result_text = response
            if hasattr(response, 'result'):
                result_text = response.result
            elif not isinstance(response, str):
                result_text = str(response)
            
            result_text = result_text.strip()
            if result_text.startswith('```json'):
                result_text = result_text[7:]
            if result_text.startswith('```'):
                result_text = result_text[3:]
            if result_text.endswith('```'):
                result_text = result_text[:-3]
            
            result_text = result_text.strip()
            return json.loads(result_text)
        except (json.JSONDecodeError, AttributeError) as e:
            logger.debug(f"LLM response parse failed: {e}")
            return None
    
    async def classify(self, urls: List[str]) -> Tuple[Set[str], Set[str], str]:
        """
        使用LLM对URL进行分类
        
        Args:
            urls: URL列表
            
        Returns:
            (api_prefixes, resource_paths, method)
        """
        if not urls:
            return set(), set(), "empty"
        
        if not self.llm_client:
            return self._classify_with_tfidf(urls)
        
        cache_key = self._generate_cache_key(urls) if self.use_cache else None
        
        if cache_key and cache_key in self._result_cache:
            self._cache_hit_count += 1
            cached = self._result_cache[cache_key]
            if time.time() - cached.get('_timestamp', 0) < self._cache_ttl:
                return (
                    set(cached.get('api_prefixes', [])),
                    set(cached.get('resource_paths', [])),
                    'ai_cached'
                )
        
        try:
            url_samples = urls[:self.batch_size] if len(urls) > self.batch_size else urls
            
            prompt = self._build_prompt(url_samples)
            
            response = await self.llm_client.chat(
                messages=[{"role": "user", "content": prompt}],
                system="你是一个专业的 API 安全分析助手，擅长分析 URL 结构语义。"
            )
            
            if not response:
                return self._classify_with_tfidf(urls)
            
            ai_result = self._parse_llm_response(response)
            
            if not ai_result:
                return self._classify_with_tfidf(urls)
            
            self._call_count += 1
            
            api_prefixes = set(ai_result.get('api_prefixes', []))
            resource_paths = set(ai_result.get('resource_paths', []))
            
            if cache_key:
                self._result_cache[cache_key] = {
                    'api_prefixes': list(api_prefixes),
                    'resource_paths': list(resource_paths),
                    '_timestamp': time.time()
                }
                
                if len(self._result_cache) > self._cache_max_size:
                    oldest_key = min(
                        self._result_cache.keys(),
                        key=lambda k: self._result_cache[k].get('_timestamp', 0)
                    )
                    del self._result_cache[oldest_key]
            
            return api_prefixes, resource_paths, 'ai'
            
        except Exception as e:
            logger.warning(f"LLM classification failed: {e}")
            return self._classify_with_tfidf(urls)
    
    def _classify_with_tfidf(self, urls: List[str]) -> Tuple[Set[str], Set[str], str]:
        """降级到TF-IDF方法"""
        classifier = TFIDFUrlClassifier()
        
        try:
            api_prefixes, resource_paths = classifier.classify_prefixes(urls)
            return api_prefixes, resource_paths, 'tfidf_fallback'
        except Exception:
            return set(), set(), 'failed'
    
    def _build_prompt(self, url_samples: List[str]) -> str:
        """构建LLM提示词"""
        return f"""分析以下 URL 列表，识别哪些路径段是 API 前缀（如 gateway、api、v1、service、prod-api），哪些是资源路径（如 users、orders、auth、login）。

URL 列表：
{chr(10).join(url_samples)}

请以 JSON 格式返回分析结果：
{{
    "api_prefixes": ["api前缀段1", "api前缀段2"],
    "resource_paths": ["资源路径1", "资源路径2"],
    "reasoning": "分析理由"
}}

注意：
- API 前缀通常是服务名、网关、版本标识等
- 资源路径通常是具体业务操作如 users、orders、auth 等"""
    
    @property
    def stats(self) -> Dict[str, Any]:
        """获取分类器统计信息"""
        return {
            'total_calls': self._call_count,
            'cache_hits': self._cache_hit_count,
            'cache_hit_rate': self._cache_hit_count / max(1, self._call_count + self._cache_hit_count),
            'cache_size': len(self._result_cache)
        }
    
    @classmethod
    def clear_cache(cls):
        """清空全局缓存"""
        cls._result_cache.clear()
        cls._instance_cache.clear()


import time


class ContentTypeDetector:
    """
    Content-Type 检测器
    参考 0x727/ChkApi 的 contentTypeList
    """
    
    CONTENT_TYPE_MAP = {
        'text/html': 'html',
        'application/json': 'json',
        'text/plain': 'txt',
        'text/xml': 'xml',
        'text/javascript': 'js',
        'image/gif': 'gif',
        'image/jpeg': 'jpg',
        'image/png': 'png',
        'image/x-icon': 'ico',
        'application/xhtml+xml': 'xhtml',
        'application/xml': 'xml',
        'application/atom+xml': 'atom',
        'application/octet-stream': 'bin',
        'application/pdf': 'pdf',
        'application/msword': 'doc',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'docx',
        'application/vnd.ms-excel': 'xls',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'xlsx',
        'application/zip': 'zip',
        'application/x-zip-compressed': 'zip',
        'application/x-tar': 'tar',
        'multipart/form-data': 'form',
        'application/ld+json': 'json-ld',
        'application/javascript': 'js',
        'text/css': 'css',
        'application/xml-dtd': 'xml',
    }
    
    @classmethod
    def get_tag(cls, content_type: str) -> str:
        """从 content-type 获取标签"""
        for key, tag in cls.CONTENT_TYPE_MAP.items():
            if key in content_type.lower():
                return tag
        return 'unknown'


COMMON_API_PATHS = [
    'add', 'ls', 'focus', 'calc', 'download', 'bind', 'execute',
    'logininfo', 'create', 'decrypt', 'new', 'update', 'click',
    'shell', 'export', 'menu', 'retrieve', 'on', 'message', 'admin',
    'calculate', 'append', 'check', 'crypt', 'rename', 'exec', 'detail',
    'clone', 'query', 'verify', 'is', 'authenticate', 'move', 'toggle',
    'make', 'modify', 'upload', 'help', 'demo', 'with', 'alert', 'mode',
    'gen', 'msg', 'edit', 'vrfy', 'enable', 'run', 'open', 'post',
    'proxy', 'subtract', 'initiate', 'read', 'encrypt', 'auth', 'snd',
    'view', 'save', 'config', 'get', 'alter', 'forceLogout', 'build',
    'list', 'show', 'online', 'test', 'pull', 'notice', 'change',
    'put', 'to', 'status', 'search', 'mod', '0', 'send', 'load',
    'login', 'logout', 'register', 'info', 'detail', 'delete', 'remove',
    'insert', 'select', 'update', 'user', 'users', 'order', 'orders',
    'product', 'products', 'goods', 'item', 'items', 'category', 'cart',
    'shop', 'payment', 'account', 'profile', 'setting', 'settings',
    'dashboard', 'home', 'index', 'about', 'contact', 'service',
    'news', 'article', 'blog', 'comment', 'file', 'files', 'upload',
    'download', 'image', 'images', 'video', 'videos', 'audio',
]


class URLBlacklist:
    """
    URL 黑名单过滤器
    参考 0x727/ChkApi 的黑名单逻辑
    """
    
    STATIC_FILE_EXT_BLACKLIST = [
        '.js', '.css', '.scss', '.sass', '.less',
        '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.webp', '.bmp', '.icon',
        '.woff', '.woff2', '.ttf', '.eot', '.otf',
        '.mp4', '.mp3', '.avi', '.mov', '.webm', '.flv', '.wmv',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.zip', '.tar', '.gz', '.rar', '.7z',
        '.exe', '.dll', '.so', '.dmg', '.app',
        '.swf', '.fla', '.psd', '.ai', '.eps',
        '.mpp', '.vsd', '.vsdx', '.pub',
    ]
    
    URL_BLACKLIST = [
        'data:', 'blob:', 'javascript:', 'mailto:', 'tel:',
        '#', '//', 'about:', 'chrome:', 'view-source:',
    ]
    
    URL_EXT_BLACKLIST = [
        '.html', '.htm', '.jsp', '.jspx', '.asp', '.aspx', '.php', '.php3', '.php4', '.php5',
        '.vue', '.jsx', '.tsx', '.svelte',
        '.xml', '.json', '.yaml', '.yml',
        '.txt', '.md', '.markdown',
    ]
    
    API_ROOT_BLACKLIST = [
        '\\', '$', '@', '*', '+', '-', '|', '!', '%', '^', '~',
        '[', ']', '(', ')', '{', '}', '<', '>',
    ]

    @classmethod
    def is_static_file(cls, url: str) -> bool:
        """判断是否为静态文件"""
        url_lower = url.lower()
        for ext in cls.STATIC_FILE_EXT_BLACKLIST:
            if url_lower.endswith(ext):
                return True
        return False
    
    @classmethod
    def is_blacklisted_url(cls, url: str) -> bool:
        """判断URL是否在黑名单中"""
        url_stripped = url.strip("\"'").strip("/")
        for prefix in cls.URL_BLACKLIST:
            if url_stripped.startswith(prefix):
                return True
        return False
    
    @classmethod
    def is_api_root_blacklisted(cls, path: str) -> bool:
        """判断API根路径是否在黑名单中"""
        path_stripped = path.strip("\"'").strip("/")
        for char in cls.API_ROOT_BLACKLIST:
            if path_stripped.startswith(char):
                return True
        return False
    
    @classmethod
    def is_ext_blacklisted(cls, url: str) -> bool:
        """判断URL扩展名是否在黑名单中"""
        path_part = url.split("?")[0].lower()
        for ext in cls.URL_EXT_BLACKLIST:
            if path_part.endswith(ext):
                return True
        return False


class APIRouter:
    """
    API路由提取器
    参考 0x727/ChkApi 的 apiPathFind.py
    """
    
    from functools import lru_cache
    
    API_PATTERNS = {
        'axios': re.compile(r'''
            (?:axios|request)\s*[.(]?\s*(?:get|post|put|delete|patch)\s*\(?
            ['"`]([^'"`]+)['"`]
        ''', re.VERBOSE | re.IGNORECASE),
        
        'fetch': re.compile(r'''
            fetch\s*\(\s*['"`]([^'"`]+)['"`]
        ''', re.VERBOSE),
        
        'jquery': re.compile(r'''
            \.\s*(?:get|post|ajax)\s*\(?
            ['"`]([^'"`]+)['"`]
        ''', re.VERBOSE | re.IGNORECASE),
        
        'router': re.compile(r'''
            (?:router|route|Route)\s*[.(]?\s*
            (?:get|post|put|delete|patch)\s*\(?
            ['"`]([^'"`]+)['"`]
        ''', re.VERBOSE | re.IGNORECASE),
        
        'path': re.compile(r'''
            ['"`](?:/api|/v\d+/|/rest)[^\s'"`]+['"`]
        ''', re.VERBOSE | re.IGNORECASE),
        
        'full_url_quoted': re.compile(r'''["\']http[^\s\'\'"\>\<\)\(]{2,250}?["\']''', re.IGNORECASE),
        'full_url_assign': re.compile(r'''=https?://[^\s\'\'"\>\<\)\(]{2,250}''', re.IGNORECASE),
        'relative_root': re.compile(r'''["\']/[^\s\'\'"\>\<\:\)\(\u4e00-\u9fa5]{1,250}?["\']''', re.IGNORECASE),
        'relative_path': re.compile(r'''["\'][^\s\'\'"\>\<\:\)\(\u4e00-\u9fa5]{1,250}?/[^\s\'\'"\>\<\:\)\(\u4e00-\u9fa5]{1,250}?["\']''', re.IGNORECASE),
        'path_colon': re.compile(r'''(?<=path:)\s?["\'][^\s\'\'"\>\<\:\)\(\u4e00-\u9fa5]{1,250}?["\']''', re.IGNORECASE),
        'path_colon_space': re.compile(r'''(?<=path\s:)\s?["\'][^\s\'\'"\>\<\:\)\(\u4e00-\u9fa5]{1,250}?["\']''', re.IGNORECASE),
        'path_eq': re.compile(r'''(?<=path=)\s?["\'][^\s\'\'"\>\<\:\)\(\u4e00-\u9fa5]{1,250}?["\']''', re.IGNORECASE),
        'path_eq_space': re.compile(r'''(?<=path\s=)\s?["\'][^\s\'\'"\>\<\:\)\(\u4e00-\u9fa5]{1,250}?["\']''', re.IGNORECASE),
        'url_colon': re.compile(r'''(?<=url:)\s?["\'][^\s\'\'"\>\<\:\)\(\u4e00-\u9fa5]{1,250}?["\']''', re.IGNORECASE),
        'url_colon_space': re.compile(r'''(?<=url\s:)\s?["\'][^\s\'\'"\>\<\:\)\(\u4e00-\u9fa5]{1,250}?["\']''', re.IGNORECASE),
        'url_eq': re.compile(r'''(?<=url=)\s?["\'][^\s\'\'"\>\<\:\)\(\u4e00-\u9fa5]{1,250}?["\']''', re.IGNORECASE),
        'url_eq_space': re.compile(r'''(?<=url\s=)\s?["\'][^\s\'\'"\>\<\:\)\(\u4e00-\u9fa5]{1,250}?["\']''', re.IGNORECASE),
        'index_colon': re.compile(r'''(?<=index:)\s?["\'][^\s\'\'"\>\<\:\)\(\u4e00-\u9fa5]{1,250}?["\']''', re.IGNORECASE),
        'index_colon_space': re.compile(r'''(?<=index\s:)\s?["\'][^\s\'\'"\>\<\:\)\(\u4e00-\u9fa5]{1,250}?["\']''', re.IGNORECASE),
        'index_eq': re.compile(r'''(?<=index=)\s?["\'][^\s\'\'"\>\<\:\)\(\u4e00-\u9fa5]{1,250}?["\']''', re.IGNORECASE),
        'index_eq_space': re.compile(r'''(?<=index\s=)\s?["\'][^\s\'\'"\>\<\:\)\(\u4e00-\u9fa5]{1,250}?["\']''', re.IGNORECASE),
        'href_action_quoted': re.compile(r'''(?:href|action).{0,3}=.{0,3}["\'][^\s\'\'"\>\<\)\(]{2,250}''', re.IGNORECASE),
        'href_action_unquoted': re.compile(r'''(?:href|action).{0,3}=.{0,3}[^\s\'\'"\>\<\)\(]{2,250}''', re.IGNORECASE),
        'path_slash': re.compile(r'''(?:"|\'|`)(/[^"\'`<>]+)(?:"|\'|`)''', re.IGNORECASE),
        'api_root_relative': re.compile(r'''["\'](?:api/|v\d+/)[^\s\'\'"\>\<\)\(]{0,250}["\']''', re.IGNORECASE),
        'plugin_rel_or_dot': re.compile(r'''(?:"|\'|`)(?:\/|\.{1,2}\/)[^"\'`<>\s]{1,250}(?:"|\'|`)''', re.IGNORECASE),
        'plugin_hash_router': re.compile(r'''(?:"|\'|`)(?:\/#\/)[^"\'`<>\s]{1,250}(?:"|\'|`)''', re.IGNORECASE),
        'plugin_var_prefix': re.compile(r'''(?:"|\'|`)[A-Za-z0-9_]+\/[^"\'`<>\s]{1,250}(?:"|\'|`)''', re.IGNORECASE),
    }
    
    KNOWN_API_PREFIXES: frozenset = frozenset({
        'api', 'v1', 'v2', 'v3', 'v4', 'v5',
        'rest', 'restapi', 'graphql', 'grpc',
        'gateway', 'proxy', 'middleware',
        'admin', 'manage', 'management', 'console',
        'web', 'www', 'static', 'cdn', 'assets',
        'service', 'services', 'microservice', 'micro',
        'prod', 'production', 'dev', 'development', 'test', 'stage', 'staging',
        'internal', 'external', 'open', 'public',
        'mobile', 'app', 'client', 'android', 'ios', 'wechat', 'mini',
        'doc', 'docs', 'documentation', 'swagger', 'api-docs',
        'file', 'files', 'upload', 'download', 'storage',
        'data', 'dataset', 'analytics', 'statistics', 'report', 'reports',
        'config', 'configuration', 'settings', 'options',
        'monitor', 'monitoring', 'health', 'healthz', 'status', 'metrics',
        'log', 'logs', 'logging', 'audit',
        'notification', 'notify', 'notice', 'message', 'messages', 'msg',
        'search', 'query', 'find', 'filter',
        'backup', 'restore', 'export', 'import',
        'workflow', 'process', 'task', 'tasks', 'job', 'jobs',
        'build', 'ci', 'cd', 'deploy', 'pipeline',
        'kubernetes', 'k8s', 'docker', 'container',
        'socket', 'websocket', 'ws', 'wss', 'realtime', 'event',
        'hook', 'hooks', 'webhook', 'callback',
        'tenant', 'site', 'org', 'organization', 'company',
        'image', 'images', 'photo', 'video', 'media', 'avatar',
        'cart', 'wishlist', 'favorite', 'favorites',
        'address', 'location', 'geo', 'map',
        'stock', 'inventory', 'warehouse',
        '物流', '订单', '商品', '用户', '管理', '服务', '系统',
    })
    
    KNOWN_RESOURCE_PATHS: frozenset = frozenset({
        'list', 'get', 'add', 'create', 'update', 'edit', 'delete', 'remove',
        'detail', 'info', 'view', 'show', 'display', 'read',
        'save', 'submit', 'submit', 'confirm', 'cancel',
        'search', 'query', 'find', 'filter', 'batch',
        'export', 'import', 'sync', 'push', 'pull',
        'login', 'logout', 'signin', 'signout', 'signup', 'register', 'reset',
        'verify', 'validate', 'check', 'status',
        'enable', 'disable', 'activate', 'deactivate', 'lock', 'unlock',
        'start', 'stop', 'pause', 'resume', 'run', 'execute',
        'count', 'sum', 'total', 'summary', 'statistics', 'analytics',
        'history', 'log', 'logs', 'timeline', 'feed',
        'new', 'latest', 'hot', 'top', 'recommend', 'popular',
        'all', 'any', 'other', 'others', 'common',
        'index', 'home', 'main', 'root', 'dashboard',
        'setting', 'settings', 'config', 'configuration', 'preference',
        'profile', 'account', 'info', 'information', 'personal',
        'avatar', 'photo', 'image', 'images', 'gallery',
        'category', 'categories', 'tag', 'tags', 'label', 'taxonomy',
        'comment', 'comments', 'reply', 'replies', 'review', 'reviews',
        'like', 'unlike', 'share', 'follow', 'unfollow', 'subscribe', 'unsubscribe',
        'notification', 'notifications', 'notice', 'notices',
        'message', 'messages', 'chat', 'conversation', 'conversations',
        'friend', 'friends', 'group', 'groups', 'member', 'members',
        'order', 'orders', 'cart', 'carts', 'payment', 'payments', 'transaction', 'transactions',
        'product', 'products', 'goods', 'item', 'items', 'sku', 'skus',
        'stock', 'inventory', 'price', 'prices', 'discount', 'coupon', 'campaign',
        'address', 'addresses', 'location', 'locations', 'shipping',
        '物流', '订单', '商品', '用户', '评论', '消息', '订单', '产品',
    })
    
    API_FUZZ_PATTERNS = [
        r'["\']http[^\s\'"\<\>\:\(\)\[\,]+?\.js\b',
        r'["\']/[^\s\'"\<\>\:\(\)\[\,]+?\.js\b',
        r'=["\'][^\s\'"\<\>\:\(\)\[\,]+?\.js\b',
        r'["\']http[^\s\'"\<\>\)\(]+?["\']',
        r'=http[^\s\'"\<\>\)\(]+',
        r'["\']/[^\s\'"\<\>\:\)\(\u4e00-\u9fa5]+?["\']',
        r'["\']http[^\s\'\'"\>\<\)\(]{2,250}?["\']',
        r'=https?://[^\s\'\'"\>\<\)\(]{2,250}',
        r'["\']/[^\s\'\'"\>\<\:\)\(\u4e00-\u9fa5]{1,250}?["\']',
        r'(?:href|action).{0,3}=.{0,3}["\'][^\s\'\'"\>\<\)\(]{2,250}',
    ]

    API_PATH_PATTERNS = [
        r'(?:"|\'|`)(\/[^"\'`<>\{\}\[\]\\]+)(?:"|\'|`)',
        r'(?:path|url|route|pathname)\s*[:=]\s*[\'"]([^\'"]+)[\'"]',
        r'(?:href|action|src)\s*=\s*["\']([^"\']+)["\']',
        r'\.get\(\s*["\']([^"\']+)["\']',
        r'\.post\(\s*["\']([^"\']+)["\']',
        r'\.put\(\s*["\']([^"\']+)["\']',
        r'\.delete\(\s*["\']([^"\']+)["\']',
        r'import\s*\(["\']([^"\']+)["\']',
        r'require\(["\']([^"\']+)["\']',
        r'dynamicImport\(["\']([^"\']+)["\']',
    ]
    
    HTTP_METHODS = ['get', 'post', 'put', 'delete', 'patch', 'options', 'head']
    
    @classmethod
    def extract_apis(cls, js_content: str) -> List[APIFindResult]:
        """从JS内容提取API"""
        results = []
        found_paths: Set[str] = set()
        
        for name, pattern in cls.API_PATTERNS.items():
            matches = pattern.findall(js_content)
            for match in matches:
                if isinstance(match, tuple):
                    path = match[0] if match else ""
                else:
                    path = match
                
                if not path:
                    continue
                
                cleaned = cls._clean_path(path)
                if not cleaned:
                    continue
                
                if cleaned in found_paths:
                    continue
                found_paths.add(cleaned)
                
                method = "GET"
                for m in cls.HTTP_METHODS:
                    if m in cleaned.lower():
                        method = m.upper()
                        break
                
                results.append(APIFindResult(
                    path=cleaned,
                    method=method,
                    source_type=f"js_{name}",
                    url_type="api_path"
                ))
        
        return results

    @classmethod
    def extract_routes(cls, js_content: str) -> List[str]:
        """从JS内容提取路由（返回字符串列表，兼容js_collector）"""
        routes = []
        found = set()

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

        API_DIRECT_PATTERN = re.compile(r'''['"](/api/[a-zA-Z0-9/{}?=&_-]+)['"']''')

        for pattern in [ROUTE_PATTERN, FETCH_PATTERN, AXIOS_PATTERN, API_DIRECT_PATTERN]:
            matches = pattern.findall(js_content)
            for route in matches:
                if route and route not in found:
                    found.add(route)
                    routes.append(route)

        return routes

    @classmethod
    def extract_base_urls(cls, js_content: str) -> List[str]:
        """从JS内容提取Base URLs（返回字符串列表，兼容js_collector）"""
        URL_PATTERN = re.compile(r'''
            (?:api|baseUrl|baseURL)\s*[:=]\s*['"`]([^'"`]+)['"`]
        ''', re.IGNORECASE)

        matches = URL_PATTERN.findall(js_content)
        return list(set(matches))
    
    @classmethod
    def extract_apis_with_fuzz(cls, js_content: str) -> List[APIFindResult]:
        """
        使用模糊匹配从JS内容提取API
        参考 0x727/ChkApi 的完整 API 提取逻辑
        """
        results = []
        found_paths: Set[str] = set()
        
        all_patterns = list(cls.API_PATTERNS.values()) + [
            re.compile(p) for p in cls.API_PATH_PATTERNS
        ]
        
        for pattern in all_patterns:
            try:
                matches = pattern.findall(js_content)
                for match in matches:
                    if isinstance(match, tuple):
                        path = match[0] if match else ""
                    else:
                        path = match
                    
                    if not path or not isinstance(path, str):
                        continue
                    
                    path = cls._clean_path(path)
                    if not path:
                        continue
                    
                    if path in found_paths:
                        continue
                    
                    if URLBlacklist.is_static_file(path):
                        continue
                    if URLBlacklist.is_api_root_blacklisted(path):
                        continue
                    
                    found_paths.add(path)
                    method = cls._guess_method_from_path(path)
                    
                    results.append(APIFindResult(
                        path=path,
                        method=method,
                        source_type="js_fuzz",
                        url_type="api_path"
                    ))
            except Exception as e:
                logger.warning(f"API路径处理异常: {e}")
                continue
        
        return results
    
    @classmethod
    def _clean_path(cls, path: str) -> str:
        """
        清理路径
        参考 0x727/ChkApi apiPathFind.py 的 urlFilter 清理逻辑
        """
        if not path:
            return ""
        
        path = path.strip()
        path = path.replace(" ", "")
        path = path.replace("\\/", "/")
        path = path.replace("\"", "")
        path = path.replace("'", "")
        path = path.replace("href=\"", "", 1)
        path = path.replace("href='", "", 1)
        path = path.replace("%3A", ":")
        path = path.replace("%2F", "/")
        path = path.replace("\\\\", "")
        if path.endswith("\\"):
            path = path.rstrip("\\")
        if path.startswith("="):
            path = path.lstrip("=")
        if path.startswith("href="):
            path = path.lstrip("href=")
        if path == 'href':
            return ""
        
        if path.startswith("http://") or path.startswith("https://"):
            return ""
        
        path = path.strip("\"'").strip("/")
        
        if not path:
            return ""
        
        if '/' not in path and not path.lower().startswith('http'):
            if path.lower() not in ['api', 'v1', 'v2', 'v3']:
                if len(path) < 2:
                    return ""
        
        for prefix in ['path:', 'url:', 'index:']:
            if path.lower().startswith(prefix):
                path = path[len(prefix):].strip()
                break
        
        if URLBlacklist.is_blacklisted_url(path):
            return ""
        
        if URLBlacklist.is_static_file(path):
            return ""
        
        if URLBlacklist.is_api_root_blacklisted(path):
            return ""
        
        if URLBlacklist.is_ext_blacklisted(path):
            return ""
        
        return "/" + path if not path.startswith("/") else path
    
    @classmethod
    def _guess_method_from_path(cls, path: str) -> str:
        """从路径猜测HTTP方法"""
        path_lower = path.lower()
        for method in cls.HTTP_METHODS:
            if method in path_lower:
                return method.upper()
        return "GET"
    
    @classmethod
    def url_filter(cls, paths: List[str]) -> List[str]:
        """
        URL过滤
        参考 0x727/ChkApi 的 urlFilter 函数
        """
        filtered = []
        for path in paths:
            if URLBlacklist.is_blacklisted_url(path):
                continue
            if URLBlacklist.is_static_file(path):
                continue
            if URLBlacklist.is_ext_blacklisted(path):
                continue
            
            cleaned = cls._clean_path(path)
            if cleaned and cleaned not in filtered:
                filtered.append(cleaned)
        
        return filtered
    
    @classmethod
    def auto_classify_urls(cls, urls: List[str]) -> Dict[str, List[str]]:
        """
        自动从 URL 列表中分类提取组件
        完全基于统计结构的动态检测，无硬编码关键词
        
        算法原理：
        1. 收集所有路径段及其位置
        2. 对每个位置，找出出现频率最高的段
        3. 如果某段在固定位置出现 >= 2 次，则识别为 API 前缀
        4. 用识别出的前缀分类路径
        
        注意：纯统计方法有局限性，如 auth 可能被误识别为 API 前缀
        AI Agent 模式可以使用语义理解进一步优化此功能
        """
        from collections import Counter, defaultdict
        
        tree_urls = set()
        all_api_paths = set()
        path_with_api_paths = set()
        path_with_no_api_paths = set()
        
        segment_at_position = defaultdict(list)
        segment_count = Counter()
        segment_urls = {}
        
        for url in urls:
            if not url:
                continue
            
            parsed = None
            if url.startswith('http://') or url.startswith('https://'):
                parsed = urlparse(url)
                tree_url = f"{parsed.scheme}://{parsed.netloc}"
                tree_urls.add(tree_url)
                path = parsed.path
            elif url.startswith('/'):
                path = url
            else:
                continue
            
            if not path or path == '/':
                continue
            
            segments = [s for s in path.split('/') if s]
            if not segments:
                continue
            
            full_path = '/' + '/'.join(segments)
            all_api_paths.add(full_path)
            segment_urls[full_path] = segments
            
            for i, seg in enumerate(segments):
                segment_at_position[i].append(seg)
                segment_count[seg] += 1
        
        if not segment_at_position:
            return {
                'tree_urls': [],
                'base_urls': [],
                'path_with_api_paths': [],
                'path_with_no_api_paths': list(all_api_paths),
            }
        
        total_urls = len(segment_urls)
        identified_api_keywords = set()
        
        for pos, segs in segment_at_position.items():
            if len(segs) < 2:
                continue
            
            unique_segments = set(segs)
            most_common_count = 0
            most_common_seg = None
            
            for seg in unique_segments:
                cnt = segs.count(seg)
                if cnt >= most_common_count and cnt >= 2:
                    most_common_count = cnt
                    most_common_seg = seg
            
            if most_common_seg:
                identified_api_keywords.add(most_common_seg)
        
        base_urls = set()
        tree_domains = set()
        for tree_url in tree_urls:
            if tree_url.startswith('http'):
                try:
                    parsed = urlparse(tree_url)
                    domain = f"{parsed.scheme}://{parsed.netloc}"
                    tree_domains.add(domain)
                except Exception:
                    tree_domains.add(tree_url)
            else:
                tree_domains.add(tree_url)
        
        for full_path, segments in segment_urls.items():
            for i, seg in enumerate(segments):
                if seg in identified_api_keywords:
                    api_prefix = '/' + '/'.join(segments[:i+1])
                    path_with_api_paths.add(api_prefix)
                    if tree_domains:
                        base_url = list(tree_domains)[0]
                        base_urls.add(base_url)
                    break
        
        for full_path, segments in segment_urls.items():
            is_api_path = False
            for seg in segments:
                if seg in identified_api_keywords:
                    is_api_path = True
                    break
            
            if not is_api_path:
                path_with_no_api_paths.add(full_path)
            else:
                no_api_suffix = '/' + '/'.join([
                    seg for seg in segments 
                    if seg not in identified_api_keywords
                ])
                if no_api_suffix != '/':
                    path_with_no_api_paths.add(no_api_suffix)
        
        return {
            'tree_urls': list(tree_urls),
            'base_urls': sorted(list(base_urls)),
            'path_with_api_paths': sorted(list(path_with_api_paths)),
            'path_with_no_api_paths': sorted(list(path_with_no_api_paths)),
            '_identified_keywords': sorted(list(identified_api_keywords)),
        }
    
    VERSION_PREFIX_PATTERN = re.compile(r'^v\d+$', re.IGNORECASE)
    
    @classmethod
    def auto_classify_urls_enhanced(cls, urls: List[str], custom_prefixes: Optional[set] = None, custom_resources: Optional[set] = None) -> Dict[str, List[str]]:
        """
        混合算法 URL 分类（知识库 + 统计增强）
        
        算法原理：
        1. 知识库优先：使用已知 API 前缀和资源路径知识库进行初步分类
        2. 版本前缀识别：自动识别 v1, v2, v3 等版本前缀
        3. 统计增强：对知识库无法确定的段，使用统计方法辅助判断
        4. 位置权重：考虑段在路径中的位置，段越靠前越可能是前缀
        
        Args:
            urls: URL 列表
            custom_prefixes: 自定义 API 前缀集合（可选，用于扩展知识库）
            custom_resources: 自定义资源路径集合（可选，用于扩展知识库）
        
        Returns:
            分类后的 URL 组件字典
        """
        from collections import Counter, defaultdict
        
        tree_urls = set()
        all_api_paths = set()
        path_with_api_paths = set()
        path_with_no_api_paths = set()
        
        known_prefixes = set(cls.KNOWN_API_PREFIXES)
        known_resources = set(cls.KNOWN_RESOURCE_PATHS)
        if custom_prefixes:
            known_prefixes.update(custom_prefixes)
        if custom_resources:
            known_resources.update(custom_resources)
        
        segment_at_position = defaultdict(list)
        segment_count = Counter()
        segment_urls = {}
        segment_positions = defaultdict(set)
        
        for url in urls:
            if not url:
                continue
            
            parsed = None
            if url.startswith('http://') or url.startswith('https://'):
                parsed = urlparse(url)
                tree_url = f"{parsed.scheme}://{parsed.netloc}"
                tree_urls.add(tree_url)
                path = parsed.path
            elif url.startswith('/'):
                path = url
            else:
                continue
            
            if not path or path == '/':
                continue
            
            segments = [s for s in path.split('/') if s]
            if not segments:
                continue
            
            full_path = '/' + '/'.join(segments)
            all_api_paths.add(full_path)
            segment_urls[full_path] = segments
            
            for i, seg in enumerate(segments):
                segment_at_position[i].append(seg)
                segment_count[seg] += 1
                segment_positions[seg].add(i)
        
        if not segment_at_position:
            return {
                'tree_urls': [],
                'base_urls': [],
                'path_with_api_paths': [],
                'path_with_no_api_paths': list(all_api_paths),
                '_identified_keywords': [],
                '_method': ['enhanced'],
            }
        
        total_urls = len(segment_urls)
        identified_api_keywords = set()
        resource_candidates = set()
        
        for seg, positions in segment_positions.items():
            if len(positions) == 1:
                pos = list(positions)[0]
                if pos >= 1 and seg.lower() in known_resources:
                    resource_candidates.add(seg)
        
        for pos, segs in segment_at_position.items():
            for seg in set(segs):
                seg_lower = seg.lower()
                
                if seg_lower in known_prefixes:
                    freq = segs.count(seg)
                    if freq >= 1:
                        identified_api_keywords.add(seg)
                        continue
                
                if cls.VERSION_PREFIX_PATTERN.match(seg):
                    freq = segs.count(seg)
                    if freq >= 1:
                        identified_api_keywords.add(seg)
                        continue
                
                if pos <= 2 and len(segs) >= 2:
                    unique_segments = set(segs)
                    most_common_count = 0
                    most_common_seg = None
                    
                    for s in unique_segments:
                        cnt = segs.count(s)
                        if cnt >= most_common_count and cnt >= 2:
                            most_common_count = cnt
                            most_common_seg = s
                    
                    if most_common_seg:
                        seg_lower = most_common_seg.lower()
                        if seg_lower not in known_resources:
                            identified_api_keywords.add(most_common_seg)
        
        tfidf_classifier = TFIDFUrlClassifier(
            known_prefixes=known_prefixes,
            known_resources=known_resources
        )
        tfidf_classifier.fit(urls)
        
        for pos, segs in segment_at_position.items():
            if len(segs) < 2:
                continue
            
            unique_segments = set(segs)
            
            for seg in unique_segments:
                seg_lower = seg.lower()
                if seg_lower in known_resources:
                    continue
                
                score = tfidf_classifier.score_segment(seg, tfidf_classifier.segment_positions.get(seg, {pos}))
                threshold = tfidf_classifier._calculate_dynamic_threshold()
                
                if score > threshold:
                    identified_api_keywords.add(seg)
        
        base_urls = set()
        def get_api_prefix(segments, identified_keywords, known_prefixes):
            """获取 URL 的 API 前缀（只取第一层）"""
            for i, seg in enumerate(segments):
                if seg in identified_keywords:
                    seg_lower = seg.lower()
                    if i == 0 and len(segments) >= 2:
                        next_seg = segments[1]
                        next_lower = next_seg.lower()
                        if next_lower in known_prefixes:
                            return '/' + '/'.join(segments[:2])
                    return '/' + seg
            return None
        
        for full_path, segments in segment_urls.items():
            api_prefix = get_api_prefix(segments, identified_api_keywords, known_prefixes)
            if api_prefix and api_prefix != '/':
                path_with_api_paths.add(api_prefix)
                if tree_urls:
                    base_url = list(tree_urls)[0]
                    base_urls.add(base_url)
            elif segments:
                first_seg = segments[0]
                if first_seg.lower() in known_prefixes or cls.VERSION_PREFIX_PATTERN.match(first_seg):
                    api_prefix = '/' + first_seg
                    path_with_api_paths.add(api_prefix)
                    if tree_urls:
                        base_url = list(tree_urls)[0]
                        base_urls.add(base_url)
        
        for full_path, segments in segment_urls.items():
            is_api_path = False
            for seg in segments:
                if seg in identified_api_keywords:
                    is_api_path = True
                    break
            
            if not is_api_path:
                path_with_no_api_paths.add(full_path)
            else:
                no_api_suffix = '/' + '/'.join([
                    seg for seg in segments 
                    if seg not in identified_api_keywords
                ])
                if no_api_suffix != '/':
                    path_with_no_api_paths.add(no_api_suffix)
        
        return {
            'tree_urls': list(tree_urls),
            'base_urls': sorted(list(base_urls)),
            'path_with_api_paths': sorted(list(path_with_api_paths)),
            'path_with_no_api_paths': sorted(list(path_with_no_api_paths)),
            '_identified_keywords': sorted(list(identified_api_keywords)),
            '_method': ['enhanced'],
        }
    
    @classmethod
    async def auto_classify_urls_with_ai(cls, urls: List[str], llm_client=None) -> Dict[str, List[str]]:
        """
        使用 AI 语义理解进行 URL 分类
        AI Agent 模式增强版：使用 LLM 分析 URL 结构语义
        
        特性：
        - LLMUrlClassifier缓存避免重复调用
        - 自动降级到TF-IDF方法
        - 支持批量URL分类
        
        Args:
            urls: URL 列表
            llm_client: LLM 客户端，如果为 None 则回退到纯统计方法
        
        Returns:
            分类后的 URL 组件字典
        """
        if not urls:
            return cls.auto_classify_urls_enhanced(urls)
        
        if not llm_client:
            return cls.auto_classify_urls_enhanced(urls)
        
        classifier = LLMUrlClassifier.get_instance("api_classifier")
        classifier.llm_client = llm_client
        classifier.use_cache = True
        classifier.batch_size = 50
        
        try:
            api_prefixes, resource_paths, method = await classifier.classify(urls)
            
            if method == 'failed':
                return cls.auto_classify_urls_enhanced(urls)
            
            identified_api_keywords = api_prefixes
            tree_urls = set()
            segment_urls = {}
            
            for url in urls:
                if url.startswith('http://') or url.startswith('https://'):
                    parsed = urlparse(url)
                    tree_url = f"{parsed.scheme}://{parsed.netloc}"
                    tree_urls.add(tree_url)
                    segments = [s for s in parsed.path.split('/') if s]
                elif url.startswith('/'):
                    segments = [s for s in url.split('/') if s]
                else:
                    continue
                
                if segments:
                    segment_urls['/' + '/'.join(segments)] = segments
            
            path_with_api_paths = set()
            path_with_no_api_paths = set()
            base_urls = set()
            
            for full_path, segments in segment_urls.items():
                has_api_prefix = False
                for i, seg in enumerate(segments):
                    if seg in identified_api_keywords:
                        has_api_prefix = True
                        api_prefix = '/' + '/'.join(segments[:i+1])
                        path_with_api_paths.add(api_prefix)
                        if tree_urls:
                            base_urls.add(list(tree_urls)[0] + api_prefix)
                        break
                
                if not has_api_prefix:
                    path_with_no_api_paths.add(full_path)
                else:
                    suffix = '/' + '/'.join([s for s in segments if s not in identified_api_keywords])
                    if suffix != '/':
                        path_with_no_api_paths.add(suffix)
            
            return {
                'tree_urls': list(tree_urls),
                'base_urls': sorted(list(base_urls)),
                'path_with_api_paths': sorted(list(path_with_api_paths)),
                'path_with_no_api_paths': sorted(list(path_with_no_api_paths)),
                '_identified_keywords': sorted(list(identified_api_keywords)),
                '_method': [method]
            }
            
        except Exception as e:
            logger.warning(f"AI classification failed: {e}, falling back to enhanced method")
            return cls.auto_classify_urls_enhanced(urls)
        
        try:
            url_samples = urls[:50] if len(urls) > 50 else urls
            
            prompt = f"""分析以下 URL 列表，识别哪些路径段是 API 前缀（如 gateway、api、v1、service、prod-api），哪些是资源路径（如 users、orders、auth、login）。

URL 列表：
{chr(10).join(url_samples)}

请以 JSON 格式返回分析结果：
{{
    "api_prefixes": ["api前缀段1", "api前缀段2"],
    "resource_paths": ["资源路径1", "资源路径2"],
    "reasoning": "分析理由"
}}

注意：
- API 前缀通常是服务名、网关、版本标识等
- 资源路径通常是具体业务操作如 users、orders、auth 等
"""
            
            response = await llm_client.chat(
                messages=[{"role": "user", "content": prompt}],
                system="你是一个专业的 API 安全分析助手，擅长分析 URL 结构。"
            )
            
            if not response:
                return cls.auto_classify_urls_enhanced(urls)
            
            import json
            try:
                result_text = response
                if hasattr(response, 'result'):
                    result_text = response.result
                elif not isinstance(response, str):
                    result_text = str(response)
                
                result_text = result_text.strip()
                if result_text.startswith('```json'):
                    result_text = result_text[7:]
                if result_text.endswith('```'):
                    result_text = result_text[:-3]
                
                ai_result = json.loads(result_text)
                
                identified_api_keywords = set(ai_result.get('api_prefixes', []))
                
                tree_urls = set()
                segment_urls = {}
                
                for url in urls:
                    if url.startswith('http://') or url.startswith('https://'):
                        parsed = urlparse(url)
                        tree_url = f"{parsed.scheme}://{parsed.netloc}"
                        tree_urls.add(tree_url)
                        segments = [s for s in parsed.path.split('/') if s]
                    elif url.startswith('/'):
                        segments = [s for s in url.split('/') if s]
                    else:
                        continue
                    
                    if segments:
                        segment_urls['/' + '/'.join(segments)] = segments
                
                path_with_api_paths = set()
                path_with_no_api_paths = set()
                base_urls = set()
                
                for full_path, segments in segment_urls.items():
                    has_api_prefix = False
                    for i, seg in enumerate(segments):
                        if seg in identified_api_keywords:
                            has_api_prefix = True
                            api_prefix = '/' + '/'.join(segments[:i+1])
                            path_with_api_paths.add(api_prefix)
                            if tree_urls:
                                base_urls.add(list(tree_urls)[0] + api_prefix)
                            break
                    
                    if not has_api_prefix:
                        path_with_no_api_paths.add(full_path)
                    else:
                        suffix = '/' + '/'.join([s for s in segments if s not in identified_api_keywords])
                        if suffix != '/':
                            path_with_no_api_paths.add(suffix)
                
                return {
                    'tree_urls': list(tree_urls),
                    'base_urls': sorted(list(base_urls)),
                    'path_with_api_paths': sorted(list(path_with_api_paths)),
                    'path_with_no_api_paths': sorted(list(path_with_no_api_paths)),
                    '_identified_keywords': sorted(list(identified_api_keywords)),
                    '_method': ['ai']
                }
                
            except (json.JSONDecodeError, KeyError, TypeError) as e:
                logger.warning(f"AI classification parse failed: {e}, falling back to enhanced method")
                return cls.auto_classify_urls_enhanced(urls)
                
        except Exception as e:
            logger.warning(f"AI classification failed: {e}, falling back to enhanced method")
            return cls.auto_classify_urls_enhanced(urls)
    
    @classmethod
    def build_api_urls(cls, base_urls: List[str], path_with_api_paths: List[str],
                       path_with_no_api_paths: List[str], tree_urls: Optional[List[str]] = None) -> List[str]:
        """
        构建完整的 API URL 列表
        参考 0x727/ChkApi 的 filter_data 函数逻辑
        
        组合方式：
        1. tree_urls + base_urls 作为根路径（前缀）
        2. path_with_api_paths 作为 API 路径段（中间）
        3. path_with_no_api_paths 作为完整路径（后缀）
        
        ChkApi 组合逻辑：
        - tree_urls: 根路径 (http://x.x.x.x:8082/prod-api)
        - base_urls: Base URL (http://x.x.x.x:8082/prod-api)  
        - path_with_api_paths: API路径段 (/gateway/api, /marketing_api)
        - path_with_no_api_paths: 完整路径 (/auth/tenant/list)
        
        示例：
        - tree_url: http://x.x.x.x:8082
        - base_url: http://x.x.x.x:8082/prod-api
        - path_with_api_path: /api
        - path_with_no_api_path: /users/list
        
        组合结果：
        - http://x.x.x.x:8082/prod-api/api/users/list
        - http://x.x.x.x:8082/api/users/list
        """
        api_urls = set()
        
        tree_urls = tree_urls or []
        
        if not path_with_api_paths:
            path_with_api_paths = ['/api']
        
        all_prefix_urls = list(set(tree_urls + base_urls))
        
        all_api_base_urls = set()
        for prefix in all_prefix_urls:
            prefix_clean = prefix.rstrip('/')
            for api_path in path_with_api_paths:
                api_path_clean = api_path.lstrip('/')
                if api_path_clean:
                    full_base = f"{prefix_clean}/{api_path_clean}"
                else:
                    full_base = prefix_clean
                all_api_base_urls.add(full_base)
        
        if not all_api_base_urls:
            all_api_base_urls = {''}
        
        for api_base in all_api_base_urls:
            api_base_clean = api_base.rstrip('/')
            
            for no_api_path in path_with_no_api_paths:
                no_api_clean = no_api_path.lstrip('/') if no_api_path.startswith('/') else no_api_path
                
                if no_api_clean:
                    url = f"{api_base_clean}/{no_api_clean}"
                else:
                    url = api_base_clean
                
                if url:
                    api_urls.add(url)
            
            for common_path in COMMON_API_PATHS:
                common_clean = common_path.lstrip('/') if common_path.startswith('/') else common_path
                url = f"{api_base_clean}/{common_clean}"
                api_urls.add(url)
        
        return list(api_urls)
    
    @classmethod
    def extract_from_swagger(cls, swagger_content: str) -> List[APIFindResult]:
        """
        从Swagger/OpenAPI JSON/YAML提取API
        支持 Swagger 2.0, OpenAPI 3.0, 3.1
        """
        results = []

        try:
            data = json.loads(swagger_content)
        except json.JSONDecodeError:
            return results

        if 'swagger' in data:
            results.extend(cls._parse_swagger2(data))
        elif 'openapi' in data:
            results.extend(cls._parse_openapi3(data))

        return results

    @classmethod
    def _parse_swagger2(cls, data: Dict) -> List[APIFindResult]:
        """解析 Swagger 2.0"""
        results = []

        paths = data.get('paths', {})
        base_path = data.get('basePath', '')

        for path, methods in paths.items():
            full_path = base_path + path if base_path else path

            for method, details in methods.items():
                if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']:

                    parameters = details.get('parameters', [])
                    param_names = []
                    for param in parameters:
                        if isinstance(param, dict):
                            param_names.append(param.get('name', ''))

                    results.append(APIFindResult(
                        path=full_path,
                        method=method.upper(),
                        source_type="swagger2",
                        url_type="api_path"
                    ))

        return results

    @classmethod
    def _parse_openapi3(cls, data: Dict) -> List[APIFindResult]:
        """解析 OpenAPI 3.0/3.1"""
        results = []

        paths = data.get('paths', {})
        servers = data.get('servers', [])
        base_url = servers[0].get('url', '') if servers else ''

        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue

            for method, details in methods.items():
                if method.upper() not in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']:
                    continue

                if not isinstance(details, dict):
                    continue

                parameters = details.get('parameters', [])
                request_body = details.get('requestBody', {})

                param_names = []
                for param in parameters:
                    if isinstance(param, dict):
                        param_names.append(param.get('name', ''))

                if isinstance(request_body, dict):
                    content = request_body.get('content', {})
                    if 'application/json' in content:
                        schema = content['application/json'].get('schema', {})
                        param_names.extend(cls._extract_schema_params(schema))

                results.append(APIFindResult(
                    path=path,
                    method=method.upper(),
                    source_type="openapi3",
                    url_type="api_path"
                ))

        return results

    @classmethod
    def _extract_schema_params(cls, schema: Dict, prefix: str = '') -> List[str]:
        """从 OpenAPI schema 提取参数名"""
        params = []

        if not isinstance(schema, dict):
            return params

        if '$ref' in schema:
            return params

        properties = schema.get('properties', {})
        for prop_name in properties.keys():
            full_name = f"{prefix}{prop_name}" if prefix else prop_name
            params.append(full_name)

        additional_props = schema.get('additionalProperties')
        if isinstance(additional_props, dict):
            params.extend(cls._extract_schema_params(additional_props, prefix))

        return params

    @classmethod
    def find_swagger_endpoints(cls, target: str) -> List[str]:
        """
        查找可能的 Swagger 端点
        参考 0x727/ChkApi 的 Swagger 各版本解析
        """
        endpoints = [
            '/swagger-ui.html',
            '/swagger-ui/index.html',
            '/swagger-ui/',
            '/api-docs',
            '/api-docs/',
            '/swagger.json',
            '/swagger.yaml',
            '/v2/api-docs',
            '/v3/api-docs',
            '/doc.html',
            '/swagger/swagger-ui.html',
            '/api/swagger.json',
            '/api-docs.json',
            '/swagger/v2/swagger.json',
            '/swagger/v3/swagger.json',
            '/api/documentation',
            '/docs',
            '/documentation',
            '/openapi.json',
            '/openapi.yaml',
            '/openapi.yml',
        ]

        return [target.rstrip('/') + ep for ep in endpoints]


class BaseURLAnalyzer:
    """
    Base URL 分析器
    参考 0x727/ChkApi 的 Base URL 发现逻辑
    Base URL 可以理解为每个微服务的服务名称
    """

    BASE_URL_PATTERNS = [
        re.compile(r'''(?:baseUrl|baseURL|BASE_URL|API_BASE)\s*[:=]\s*['"`]([^'"`]+)['"`]'''),
        re.compile(r'''(?:apiUrl|apiURL|API_URL)\s*[:=]\s*['"`]([^'"`]+)['"`]'''),
        re.compile(r'''host\s*[:=]\s*['"`]([^'"`]+)['"`]''', re.IGNORECASE),
        re.compile(r'''origin\s*[:=]\s*['"`]([^'"`]+)['"`]''', re.IGNORECASE),
        re.compile(r'''domain\s*[:=]\s*['"`]([^'"`]+)['"`]''', re.IGNORECASE),
    ]

    SERVICE_PATH_PATTERNS = [
        re.compile(r'''/(?:api|v\d+|rest|service|gateway|g)/(?:[\w-]+)/(?:[\w-]+)''', re.IGNORECASE),
        re.compile(r'''/(?:[\w]+/){2,}(?:[\w]+)''', re.IGNORECASE),
    ]

    @classmethod
    def extract_base_urls(cls, js_content: str) -> List[str]:
        """提取Base URL"""
        base_urls = []

        for pattern in cls.BASE_URL_PATTERNS:
            matches = pattern.findall(js_content)
            base_urls.extend(matches)

        return list(set(base_urls))

    @classmethod
    def extract_from_url(cls, url: str) -> str:
        """从完整URL提取Base URL"""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    @classmethod
    def extract_base_from_auto_loaded(cls, url: str, load_url: str) -> Optional[str]:
        """
        从自动加载的URL提取Base URL
        例如: url=http://example.com, load_url=http://example.com/authControl
        则 authControl 是 Base URL
        """
        if not url or not load_url:
            return None

        parsed_main = urlparse(url)
        parsed_load = urlparse(load_url)

        if parsed_main.netloc != parsed_load.netloc:
            return None

        main_path = parsed_main.path.rstrip('/')
        load_path = parsed_load.path.rstrip('/')

        if load_path.startswith(main_path):
            remaining = load_path[len(main_path):].strip('/')
            if remaining and '/' not in remaining:
                return remaining

        return None

    @classmethod
    def extract_base_from_api_path(cls, api_path: str) -> Optional[str]:
        """
        从API路径提取Base URL（使用混合算法）

        例如: /ophApi/checkCode/getCheckCode -> ophApi 是 Base URL
        例如: /inspect/login/checkCode/getCheckCode -> inspect 是 Base URL

        使用知识库+ID检测混合算法：
        - NON_RESOURCE_SEGMENTS: 代理/网关前缀
        - COMMON_SUFFIXES: 常见后缀
        - COMMON_RESOURCES: 常见资源
        - ID检测: 数字、UUID等
        """
        if not api_path:
            return None

        path = api_path.strip('/')
        parts = path.split('/')

        if len(parts) < 2:
            return None

        NON_RESOURCE = frozenset({
            'inspect', 'proxy', 'gateway', 'api', 'service', 'web', 'www',
            'v1', 'v2', 'v3', 'v4', 'v5', 'rest', 'graphql', 'rpc',
            'internal', 'external', 'open', 'public', 'private',
            'mobile', 'app', 'client', 'cdn', 'static', 'assets',
        })

        COMMON_SUFFIXES = frozenset([
            'list', 'add', 'create', 'delete', 'detail', 'info', 'update', 'edit', 'remove',
            'get', 'set', 'save', 'query', 'search', 'filter', 'sort', 'page',
            'all', 'count', 'total', 'sum', 'export', 'import', 'upload', 'download',
            'enable', 'disable', 'status', 'config', 'settings', 'login', 'logout',
            'register', 'reset', 'init', 'refresh', 'sync', 'menu', 'nav', 'route',
        ])

        COMMON_RESOURCES = frozenset([
            'user', 'users', 'order', 'orders', 'product', 'products', 'goods',
            'role', 'roles', 'menu', 'menus', 'category', 'categories', 'catalog',
            'config', 'configuration', 'settings', 'system', 'admin', 'auth',
            'department', 'dept', 'organization', 'org', 'employee',
            'customer', 'customers', 'supplier', 'suppliers', 'account', 'accounts',
        ])

        def is_id(s: str) -> bool:
            return (
                s.isdigit() or
                bool(re.match(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', s, re.IGNORECASE)) or
                (len(s) > 3 and s[:2].isalpha() and s[2:].isdigit()) or
                (len(s) > 8 and bool(re.match(r'^[a-zA-Z0-9_-]+$', s)) and ('-' in s or '_' in s))
            )

        def is_meaningful(s: str) -> bool:
            s_lower = s.lower()
            if s_lower in NON_RESOURCE:
                return False
            if s_lower in COMMON_SUFFIXES:
                return True
            if s_lower in COMMON_RESOURCES:
                return True
            if is_id(s):
                return False
            return len(s) >= 2

        for i, part in enumerate(parts):
            if part.lower() in NON_RESOURCE:
                if i == 0:
                    return None
                return parts[i]

        for i in range(len(parts) - 1, -1, -1):
            if is_meaningful(parts[i]):
                if i > 0:
                    return parts[i - 1] if i > 0 else None
                return None

        return parts[0] if parts else None

    @classmethod
    def extract_base_from_paths(cls, paths: List[str]) -> List[str]:
        """
        从多个路径批量提取 Base URL
        返回所有发现的 Base URL
        """
        base_urls = set()

        for path in paths:
            base = cls.extract_base_from_api_path(path)
            if base:
                base_urls.add(base)

        return list(base_urls)

    @classmethod
    def build_service_urls(cls, base_urls: List[str], target: str) -> List[str]:
        """
        构建完整的服务URL列表
        用于后续API发现
        """
        parsed = urlparse(target)
        scheme = parsed.scheme
        netloc = parsed.netloc

        service_urls = []
        for base in base_urls:
            service_urls.append(f"{scheme}://{netloc}/{base}")

        return service_urls


class ServiceAnalyzer:
    """服务分析器"""
    
    SERVICE_KEYWORDS = ['api', 'gateway', 'service', 'auth', 'admin', 'user', 
                       'order', 'product', 'payment', 'ums', 'bms', 'cms']
    
    @classmethod
    def extract_service_key(cls, url: str, api_path: str = "") -> str:
        """提取服务标识"""
        parts = []
        
        if url:
            parsed = urlparse(url)
            path_parts = [p for p in parsed.path.split('/') if p]
            parts.extend(path_parts)
        
        if api_path:
            path_parts = [p for p in api_path.split('/') if p]
            parts.extend(path_parts)
        
        service_parts = []
        for part in parts:
            for keyword in cls.SERVICE_KEYWORDS:
                if keyword in part.lower():
                    service_parts.append(part)
                    break
        
        return '-'.join(service_parts[:3]) if service_parts else 'unknown'
    
    @classmethod
    def group_by_service(cls, apis: List[Dict]) -> Dict[str, List[Dict]]:
        """按服务分组"""
        services: Dict[str, List[Dict]] = {}
        
        for api in apis:
            service_key = api.get('service_key', 'unknown')
            if service_key not in services:
                services[service_key] = []
            services[service_key].append(api)
        
        return services


class APIAggregator:
    """
    API聚合器 - 融合了 EnhancedEndpointAggregator 的智能融合能力
    
    增强功能:
    - 置信度评分
    - 证据链管理
    - 自动端点分类
    - 多维度去重
    """
    
    def __init__(self, use_fusion: bool = True):
        self.apis: Dict[str, APIFindResult] = {}
        self.sources: Dict[str, List[Dict]] = {}
        self._use_fusion = use_fusion
        
        if use_fusion:
            try:
                from ..unified_fusion import UnifiedFusionEngine, FusedEndpoint, SourceType, EndpointType
                self._fusion_engine = UnifiedFusionEngine()
                self._enhanced_endpoint_class = FusedEndpoint
                self._source_type_enum = SourceType
                self._endpoint_type_enum = EndpointType
            except ImportError:
                self._fusion_engine = None
                logger.warning("UnifiedFusionEngine not available, fusion disabled")
        else:
            self._fusion_engine = None
    
    def add_api(self, api: APIFindResult, source_info: Optional[Dict] = None):
        """添加API - 嵌入融合引擎"""
        key = f"{api.method}:{api.path}"
        
        if key not in self.apis:
            self.apis[key] = api
            self.sources[key] = []
        
        if source_info:
            self.sources[key].append(source_info)
        
        if self._fusion_engine and hasattr(api, 'base_url') and api.base_url:
            try:
                full_url = f"{api.base_url.rstrip('/')}/{api.path.lstrip('/')}" if api.path else api.base_url
                source_type_val = source_info.get('source_type', 'regex') if source_info else 'regex'
                try:
                    source_type = self._source_type_enum(source_type_val)
                except (ValueError, AttributeError):
                    source_type = self._source_type_enum.UNKNOWN
                
                self._fusion_engine.add_endpoint(
                    url=full_url,
                    method=api.method,
                    source_type=source_type,
                    source_url=api.base_url,
                    confidence=0.5
                )
            except Exception as e:
                logger.debug(f"Fusion engine add failed: {e}")
    
    def get_all(self) -> List[APIFindResult]:
        """获取所有API"""
        return list(self.apis.values())
    
    def get_by_source(self, source_type: str) -> List[APIFindResult]:
        """按来源筛选"""
        results = []
        for key, api in self.apis.items():
            if api.source_type == source_type:
                results.append(api)
        return results
    
    def merge(self, other: 'APIAggregator'):
        """合并另一个聚合器"""
        for api in other.get_all():
            self.add_api(api)
    
    def get_fusion_stats(self) -> Dict:
        """获取融合统计信息"""
        if not self._fusion_engine:
            return {
                'fusion_enabled': False,
                'total_apis': len(self.apis),
            }
        
        fusion_stats = self._fusion_engine.get_stats()  # type: ignore
        return {
            'fusion_enabled': True,
            'total_apis': len(self.apis),
            'after_fusion': fusion_stats.get('after_fusion', len(self.apis)),
            'high_confidence': fusion_stats.get('high_confidence', 0),
            'runtime_confirmed': fusion_stats.get('runtime_confirmed', 0),
            'by_type': fusion_stats.get('by_type', {}),
        }
    
    def get_high_confidence_apis(self) -> List[APIFindResult]:
        """获取高置信度API"""
        if not self._fusion_engine:
            return self.get_all()
        
        high_conf = self._fusion_engine.get_high_confidence()  # type: ignore
        high_conf_urls = {ep.full_url for ep in high_conf}
        
        return [api for api in self.apis.values() 
                if f"{api.base_url.rstrip('/')}/{api.path.lstrip('/')}" in high_conf_urls]
    
    def get_runtime_confirmed_apis(self) -> List[APIFindResult]:
        """获取运行时确认的API"""
        if not self._fusion_engine:
            return []
        
        confirmed = self._fusion_engine.get_runtime_confirmed()  # type: ignore
        confirmed_urls = {ep.full_url for ep in confirmed}
        
        return [api for api in self.apis.values()
                if f"{api.base_url.rstrip('/')}/{api.path.lstrip('/')}" in confirmed_urls]


class APIPathCombiner:
    """API路径组合器"""
    
    COMMON_PREFIXES = ['/api', '/v1', '/v2', '/v3', '/rest', '/restapi', '/service']
    
    INVALID_PATTERNS = [
        'application/x-www-form-urlencoded',
        'multipart/form-data',
        'base64',
        'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/',
        'example.com',
        'www.example.com',
        'https:',
        'http:',
        '://',
        'lib/index',
        '/dist/',
        '/build/',
        '/node_modules/',
        '.js',
        '.css',
        '.html',
        '.json',
        '.png',
        '.jpg',
        '.svg',
        'data:',
        'javascript:',
        'void(',
        'undefined',
        'null',
    ]
    
    INVALID_PATH_PATTERNS = [
        r'^https:$',
        r'^http:$', 
        r'^//$',
        r'^[a-z]:[/\\]?$',
        r'^lib/',
        r'^dist/',
        r'^build/',
        r'^src/',
        r'^assets/',
        r'^static/',
        r'^public/',
        r'\.min\.(js|css)$',
        r'^M/D/YY$',
        r'^YYYY-MM-DD$',
        r'^\d{1,2}:\d{2}$',
        r'^#[0-9a-fA-F]{3,6}$',
        r'^[0-9a-fA-F]{3,6}$',
        r'^\d+$',
        r'^[A-Z]{1,2}\d{1,4}[A-Z]?$',
    ]
    
    INVALID_PATH_PATTERNS_COMPILED = None
    
    @classmethod
    def is_valid_api_path(cls, path: str) -> bool:
        """验证API路径是否有效"""
        if not path:
            return False
        
        import re
        if cls.INVALID_PATH_PATTERNS_COMPILED is None:
            cls.INVALID_PATH_PATTERNS_COMPILED = [re.compile(p, re.IGNORECASE) for p in cls.INVALID_PATH_PATTERNS]
        
        for pattern in cls.INVALID_PATH_PATTERNS_COMPILED:
            if pattern.match(path):
                return False
        
        path_lower = path.lower()
        for pattern in cls.INVALID_PATTERNS:
            if pattern.lower() in path_lower:
                return False
        
        if len(path) < 2:
            return False
        
        if path.startswith('data:') or path.startswith('javascript:'):
            return False
        
        return True
    
    @classmethod
    def normalize_path(cls, path: str) -> str:
        """规范化路径"""
        path = path.strip()
        
        for prefix in cls.COMMON_PREFIXES:
            if path.startswith(prefix):
                return path
        
        if not path.startswith('/'):
            path = '/' + path
        
        return path
    
    @classmethod
    def combine_base_and_path(cls, base_url: str, api_path: str, default_base: str = "") -> str:
        """组合Base URL和API路径"""
        if not base_url:
            if default_base:
                base_url = default_base
            elif api_path.startswith('http'):
                return api_path
            else:
                return api_path
        
        if not api_path:
            return base_url
        
        base = base_url.rstrip('/')
        path = api_path.lstrip('/')
        
        return f"{base}/{path}"
    
    @classmethod
    def extract_api_without_prefix(cls, path: str) -> str:
        """提取去除前缀的API路径"""
        normalized = path
        
        for prefix in cls.COMMON_PREFIXES:
            if normalized.startswith(prefix):
                parts = normalized[len(prefix):].lstrip('/')
                if parts:
                    return parts
        return normalized


class APIDictionaryLoader:
    """互联网开源 API 字典加载器"""
    
    SECLISTS_API_URLS = [
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/objects.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/actions.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/objects-lowercase.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/objects-uppercase.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/actions-lowercase.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/actions-uppercase.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common-api-endpoints-mazen160.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/graphql.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/mcp-server.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/oauth-oidc-scopes.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/hashicorp-consul-api.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/hashicorp-vault.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/SOAP-functions.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt",
    ]
    
    API_WORDLIST_URLS = [
        "https://raw.githubusercontent.com/chrislockard/api_wordlist/master/api_seen_in_wild.txt",
        "raw.githubusercontent.com/chrislockard/api_wordlist/master/objects.txt",
        "https://raw.githubusercontent.com/chrislockard/api_wordlist/master/actions.txt",
        "https://raw.githubusercontent.com/chrislockard/api_wordlist/master/common_paths.txt",
        "https://raw.githubusercontent.com/chrislockard/api_wordlist/master/api_seen_in_wild_paths.txt",
        "https://raw.githubusercontent.com/chrislockard/api_wordlist/master/objects-lowercase.txt",
        "https://raw.githubusercontent.com/chrislockard/api_wordlist/master/objects-uppercase.txt",
        "https://raw.githubusercontent.com/chrislockard/api_wordlist/master/actions-lowercase.txt",
        "https://raw.githubusercontent.com/chrislockard/api_wordlist/master/actions-uppercase.txt",
    ]
    
    ALL_DICTIONARY_URLS = SECLISTS_API_URLS + API_WORDLIST_URLS
    
    _cached_prefixes: Optional[set] = None
    _cached_resources: Optional[set] = None
    _cache_loaded: bool = False
    _cache_loaded_urls: Optional[set] = None
    
    @classmethod
    def _is_valid_api_segment(cls, segment: str) -> bool:
        """检查是否是有效的 API 段"""
        import re
        
        if not segment or len(segment) < 2 or len(segment) > 40:
            return False
        
        if re.match(r'^[\d\.\-\_]+$', segment):
            return False
        
        if segment.startswith('.') or segment.endswith('.'):
            return False
        
        if re.match(r'^v\d+(\.\d+)*$', segment, re.IGNORECASE):
            return True
        
        if re.match(r'.*\.(json|xml|yaml|yml|js|html|css|png|jpg|gif|svg|ico|woff|woff2|ttf|eot)$', segment, re.IGNORECASE):
            return False
        
        invalid_chars = ['<', '>', '{', '}', '(', ')', '[', ']', '&', '$', '!', '@', '%', '^', '*', '+', '=', '|', '\\', ':', ';', '"', "'"]
        for char in invalid_chars:
            if char in segment:
                return False
        
        if re.match(r'.*_onclick$', segment, re.IGNORECASE):
            return False
        
        return True
    
    @classmethod
    async def download_all_api_dicts(cls) -> tuple:
        """
        下载并解析所有互联网开源 API 字典
        
        Returns:
            (api_prefixes, resource_paths) 元组
        """
        import aiohttp  # type: ignore
        
        api_prefixes = set()
        resource_paths = set()
        
        known_prefix_keywords = {
            'api', 'v1', 'v2', 'v3', 'v4', 'v5', 'v6',
            'rest', 'restapi', 'graphql', 'grpc', 'soap',
            'gateway', 'proxy', 'middleware',
            'admin', 'manage', 'management', 'console',
            'web', 'www', 'static', 'cdn', 'assets',
            'service', 'services', 'microservice', 'micro',
            'prod', 'production', 'dev', 'development', 'test', 'stage', 'staging',
            'internal', 'external', 'open', 'public', 'private',
            'mobile', 'app', 'client', 'android', 'ios', 'wechat', 'mini',
            'doc', 'docs', 'documentation', 'swagger', 'api-docs', 'openapi', 'apidocs',
            'file', 'files', 'upload', 'download', 'storage',
            'data', 'dataset', 'analytics', 'statistics', 'report', 'reports',
            'config', 'configuration', 'settings', 'options',
            'monitor', 'monitoring', 'health', 'healthz', 'status', 'metrics', 'ping',
            'log', 'logs', 'logging', 'audit',
            'notification', 'notify', 'notice', 'message', 'messages', 'msg',
            'search', 'query', 'find', 'filter',
            'backup', 'restore', 'export', 'import',
            'workflow', 'process', 'task', 'tasks', 'job', 'jobs',
            'build', 'ci', 'cd', 'deploy', 'pipeline',
            'kubernetes', 'k8s', 'docker', 'container',
            'socket', 'websocket', 'ws', 'wss', 'realtime', 'event',
            'hook', 'hooks', 'webhook', 'callback',
            'tenant', 'site', 'org', 'organization', 'company',
            'image', 'images', 'photo', 'video', 'media', 'avatar',
            'cart', 'wishlist', 'favorite', 'favorites',
            'address', 'location', 'geo', 'map',
            'stock', 'inventory', 'warehouse',
        }
        
        for url in cls.ALL_DICTIONARY_URLS:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as response:
                        if response.status == 200:
                            text = await response.text()
                            for line in text.splitlines():
                                line = line.strip()
                                if not line or line.startswith('#'):
                                    continue
                                
                                line_lower = line.lower()
                                
                                parts = line.split('/')
                                if len(parts) >= 2:
                                    first_part = parts[0].lower()
                                    if first_part in known_prefix_keywords:
                                        api_prefixes.add(first_part)
                                    for part in parts[1:]:
                                        part = part.strip()
                                        if cls._is_valid_api_segment(part):
                                            resource_paths.add(part.lower())
                                elif cls._is_valid_api_segment(line):
                                    resource_paths.add(line_lower)
            except Exception as e:
                logger.debug(f"Failed to download {url}: {e}")
        
        return api_prefixes, resource_paths
    
    @classmethod
    def get_enhanced_prefixes_resources(cls) -> tuple:
        """
        获取增强版的 API 前缀和资源路径集合
        
        优先使用缓存，如果缓存不存在则返回内置知识库
        """
        if cls._cache_loaded and cls._cached_prefixes is not None:
            return cls._cached_prefixes, cls._cached_resources
        
        return APIRouter.KNOWN_API_PREFIXES, APIRouter.KNOWN_RESOURCE_PATHS
    
    @classmethod
    async def load_external_dicts(cls, force_reload: bool = False) -> bool:
        """
        异步加载外部字典
        
        Args:
            force_reload: 是否强制重新加载
            
        Returns:
            是否成功加载
        """
        if cls._cache_loaded and not force_reload:
            return True
        
        try:
            prefixes, resources = await cls.download_all_api_dicts()
            
            cls._cached_prefixes = APIRouter.KNOWN_API_PREFIXES | prefixes
            cls._cached_resources = APIRouter.KNOWN_RESOURCE_PATHS | resources
            cls._cache_loaded = True
            
            logger.info(f"Loaded external API dict: {len(prefixes)} prefixes, {len(resources)} resources")
            return True
        except Exception as e:
            logger.warning(f"Failed to load external dicts: {e}")
            return False
    
    @classmethod
    def get_custom_dicts(cls) -> tuple:
        """
        同步获取自定义字典（用于混合算法）
        
        如果外部字典已加载则返回扩展后的集合，否则返回内置知识库
        """
        if cls._cache_loaded:
            return cls._cached_prefixes or APIRouter.KNOWN_API_PREFIXES, \
                   cls._cached_resources or APIRouter.KNOWN_RESOURCE_PATHS
        
        return APIRouter.KNOWN_API_PREFIXES, APIRouter.KNOWN_RESOURCE_PATHS

        
        return normalized
