"""
Result Noise Reducer Module
结果降噪模块
参考 FLUX v1.1 结果降噪功能
过滤第三方请求、埋点分析、CDN静态资源等
"""

from typing import List, Dict, Any, Set, Tuple
from dataclasses import dataclass
import re
import logging

logger = logging.getLogger(__name__)


@dataclass
class RequestInfo:
    """请求信息"""
    url: str
    method: str
    status_code: int
    content_type: str
    domain: str
    path: str
    is_api: bool
    is_third_party: bool
    is_analytics: bool
    is_cdn: bool
    is_static: bool


class NoiseReducer:
    """
    结果降噪器
    
    过滤：
    1. 第三方域名请求
    2. 埋点/分析请求
    3. CDN 静态资源
    4. 无关资源
    """
    
    THIRD_PARTY_PATTERNS = [
        r'google-analytics\.com',
        r'googletagmanager\.com',
        r'gtag\/js',
        r'analytics',
        r'tracking',
        r'facebook\.net',
        r'facebook\.com\/tr',
        r'fbevents',
        r'connect\.facebook\.net',
        r'doubleclick\.net',
        r'googlesyndication\.com',
        r'googleadservices\.com',
        r'amazon-adsystem\.com',
        r'adnxs\.com',
        r'criteo\.com',
        r'taboola\.com',
        r'outbrain\.com',
        r'mixpanel\.com',
        r'hotjar\.com',
        r'segment\.io',
        r'segment\.com',
        r'intercom\.io',
        r'intercomcdn\.com',
        r'zendesk\.com',
        r'zendesk\.eu',
        r'drift\.com',
        r'marketo\.com',
        r'marketo\.net',
        r'pardot\.com',
        r'eloqua\.com',
        r'hubspot\.com',
        r'hubspotutk\.com',
        r'mouseflow\.com',
        r'crazyegg\.com',
        r'quantserve\.com',
        r'scorecardresearch\.com',
        r'newrelic\.com',
        r'nr-data\.net',
        r'appdynamics\.com',
        r'dynatrace\.com',
        r'pingdom\.net',
        r'sentry\.io',
        r'bugsnag\.com',
        r'rollbar\.com',
        r'logrocket\.com',
        r'insight\.tencent\.com',
        r'mta\.tencentmusic\.com',
    ]
    
    ANALYTICS_PATTERNS = [
        r'\/analytics',
        r'\/tracking',
        r'\/pixel',
        r'\/beacon',
        r'\/collect',
        r'\/event',
        r'\/metrics',
        r'\/telemetry',
        r'\/logs',
        r'\/monitor',
        r'\/stats',
        r'\/counter',
        r'\/hit',
        r'\/pageview',
        r'\/activity',
    ]
    
    CDN_PATTERNS = [
        r'cdn',
        r'cloudfront\.net',
        r'akamai\.net',
        r'fastly\.net',
        r'cloudflare\.com',
        r'jsdelivr\.net',
        r'unpkg\.com',
        r'cdnjs\.cloudflare\.com',
        r'ajax\.googleapis\.com',
        r'fonts\.googleapis\.com',
        r'fonts\.gstatic\.com',
        r'bootstrapcdn\.com',
        r'stackpathcdn\.com',
        r'jquery',
        r'react',
        r'vue',
        r'angular',
    ]
    
    STATIC_EXTENSIONS = [
        '.js', '.css', '.png', '.jpg', '.jpeg',
        '.gif', '.svg', '.ico', '.woff', '.woff2',
        '.ttf', '.eot', '.map', '.webp', '.webm',
        '.mp4', '.mp3', '.wav', '.swf', '.flv',
        '.pdf', '.zip', '.tar', '.gz', '.rar',
    ]
    
    STATIC_PATHS = [
        '/static/',
        '/assets/',
        '/public/',
        '/media/',
        '/images/',
        '/styles/',
        '/scripts/',
        '/fonts/',
        '/vendor/',
        '/node_modules/',
        '/dist/',
        '/build/',
    ]
    
    API_INDICATORS = [
        '/api/',
        '/rest/',
        '/graphql',
        '/v1/',
        '/v2/',
        '/v3/',
        '/v4/',
        '/data/',
        '/json/',
        '/xml/',
    ]
    
    WHITELIST_DOMAINS: Set[str] = set()
    WHITELIST_PATHS: Set[str] = set()
    
    def __init__(
        self,
        target_domain: str = "",
        whitelist_domains: Set[str] = None,
        whitelist_paths: Set[str] = None
    ):
        """
        初始化降噪器
        
        Args:
            target_domain: 目标域名（用于判断第三方）
            whitelist_domains: 域名白名单
            whitelist_paths: 路径白名单
        """
        self.target_domain = target_domain
        self.requests: List[RequestInfo] = []
        
        if whitelist_domains:
            self.WHITELIST_DOMAINS = whitelist_domains
        if whitelist_paths:
            self.WHITELIST_PATHS = whitelist_paths
    
    def add_request(
        self,
        url: str,
        method: str = 'GET',
        status_code: int = 200,
        content_type: str = ''
    ) -> RequestInfo:
        """
        添加请求记录
        
        Args:
            url: 请求 URL
            method: HTTP 方法
            status_code: 状态码
            content_type: Content-Type
            
        Returns:
            RequestInfo: 请求信息
        """
        info = self._analyze_request(url, method, status_code, content_type)
        self.requests.append(info)
        return info
    
    def _analyze_request(
        self,
        url: str,
        method: str,
        status_code: int,
        content_type: str
    ) -> RequestInfo:
        """分析请求特征"""
        from urllib.parse import urlparse
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            path = parsed.path
        except Exception:
            domain = ''
            path = url
        
        info = RequestInfo(
            url=url,
            method=method,
            status_code=status_code,
            content_type=content_type,
            domain=domain,
            path=path,
            is_api=False,
            is_third_party=False,
            is_analytics=False,
            is_cdn=False,
            is_static=False
        )
        
        info.is_third_party = self._is_third_party(domain)
        info.is_analytics = self._is_analytics(url)
        info.is_cdn = self._is_cdn(url)
        info.is_static = self._is_static(path)
        info.is_api = self._is_api(path)
        
        return info
    
    def _is_third_party(self, domain: str) -> bool:
        """判断是否为第三方域名"""
        if not domain:
            return False
        
        if self.target_domain and domain == self.target_domain:
            return False
        
        if domain in self.WHITELIST_DOMAINS:
            return False
        
        return True
    
    def _is_analytics(self, url: str) -> bool:
        """判断是否为埋点/分析请求"""
        url_lower = url.lower()
        
        for pattern in self.ANALYTICS_PATTERNS:
            if re.search(pattern, url_lower):
                return True
        
        for pattern in self.THIRD_PARTY_PATTERNS:
            if re.search(pattern, url_lower):
                return True
        
        return False
    
    def _is_cdn(self, url: str) -> bool:
        """判断是否为 CDN 请求"""
        url_lower = url.lower()
        
        for pattern in self.CDN_PATTERNS:
            if re.search(pattern, url_lower):
                return True
        
        return False
    
    def _is_static(self, path: str) -> bool:
        """判断是否为静态资源"""
        path_lower = path.lower()
        
        for static_path in self.STATIC_PATHS:
            if static_path in path_lower:
                return True
        
        for ext in self.STATIC_EXTENSIONS:
            if path_lower.endswith(ext):
                return True
        
        return False
    
    def _is_api(self, path: str) -> bool:
        """判断是否为 API 请求"""
        path_lower = path.lower()
        
        for indicator in self.API_INDICATORS:
            if indicator in path_lower:
                return True
        
        return False
    
    def is_noise(self, url: str, method: str = 'GET', status_code: int = 200) -> Tuple[bool, str]:
        """
        判断请求是否为噪音
        
        Args:
            url: 请求 URL
            method: HTTP 方法
            status_code: 状态码
            
        Returns:
            Tuple[bool, str]: (是否为噪音, 原因)
        """
        info = self._analyze_request(url, method, status_code, '')
        
        if info.path in self.WHITELIST_PATHS:
            return False, ""
        
        if info.is_analytics:
            return True, "analytics_tracking"
        
        if info.is_cdn and not info.is_api:
            return True, "cdn_static_resource"
        
        if info.is_static and not info.is_api:
            return True, "static_resource"
        
        if info.is_third_party and not info.is_api:
            return True, "third_party_request"
        
        if status_code >= 500:
            return True, "server_error_response"
        
        return False, ""
    
    def filter_requests(
        self,
        requests: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        过滤请求列表
        
        Args:
            requests: 请求列表
            
        Returns:
            List[Dict[str, Any]]: 过滤后的请求列表
        """
        filtered = []
        removed_count = 0
        
        for req in requests:
            url = req.get('url', '')
            method = req.get('method', 'GET')
            status_code = req.get('status_code', 200)
            
            is_noise, reason = self.is_noise(url, method, status_code)
            
            if is_noise:
                removed_count += 1
                logger.debug(f"Filtered noise request: {url} ({reason})")
            else:
                filtered.append(req)
        
        logger.info(f"Filtered {removed_count} noise requests out of {len(requests)}")
        
        return filtered
    
    def get_summary(self) -> Dict[str, int]:
        """获取降噪统计"""
        total = len(self.requests)
        if total == 0:
            return {
                'total': 0,
                'third_party': 0,
                'analytics': 0,
                'cdn': 0,
                'static': 0,
                'api': 0,
                'kept': 0
            }
        
        stats = {
            'total': total,
            'third_party': sum(1 for r in self.requests if r.is_third_party),
            'analytics': sum(1 for r in self.requests if r.is_analytics),
            'cdn': sum(1 for r in self.requests if r.is_cdn),
            'static': sum(1 for r in self.requests if r.is_static),
            'api': sum(1 for r in self.requests if r.is_api),
            'kept': sum(1 for r in self.requests if not self.is_noise(r.url, r.method, r.status_code)[0])
        }
        
        return stats


def filter_noise_requests(
    requests: List[Dict[str, Any]],
    target_domain: str = ""
) -> List[Dict[str, Any]]:
    """
    便捷函数：过滤噪音请求
    
    Args:
        requests: 请求列表
        target_domain: 目标域名
        
    Returns:
        List[Dict[str, Any]]: 过滤后的请求
    """
    reducer = NoiseReducer(target_domain=target_domain)
    return reducer.filter_requests(requests)
