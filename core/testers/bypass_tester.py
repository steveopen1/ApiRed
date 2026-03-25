"""
API Bypass Techniques Module
API 绕过技术模块 - 当 API 返回 401/404/403/500 时尝试多种绕过技术

参考 ChkApi 项目的 Bypass 技术实现
"""

import re
import logging
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class BypassCategory(Enum):
    """绕过技术分类"""
    AUTH_HEADER = "auth_header"
    REQUEST_METHOD = "request_method"
    CONTENT_TYPE = "content_type"
    USER_AGENT = "user_agent"
    IP_SPOOFING = "ip_spoofing"
    HEADER_MANIPULATION = "header_manipulation"
    URL_MANIPULATION = "url_manipulation"
    PARAMETER_MANIPULATION = "parameter_manipulation"


@dataclass
class BypassResult:
    """绕过测试结果"""
    original_status: int
    bypassed_status: Optional[int]
    technique: str
    category: str
    bypassed: bool
    response_time: float
    details: str


class BypassTechniques:
    """
    Bypass 技术集合
    
    当 API 返回以下状态码时尝试绕过:
    - 401 Unauthorized: 尝试添加认证信息
    - 403 Forbidden: 尝试修改请求头
    - 404 Not Found: 尝试 URL 变换
    - 500 Internal Server Error: 尝试修改参数
    - 超时: 尝试简化请求
    """
    
    AUTH_BYPASS_TECHNIQUES = [
        ("Empty Authorization", {"Authorization": ""}),
        ("Bearer Token", {"Authorization": "Bearer "}),
        ("Basic Auth", {"Authorization": "Basic dXNlcjpwYXNz"}),
        ("API Key Header", {"X-API-Key": "test"}),
        ("Custom Auth", {"Authorization": "CustomAuth test"}),
    ]
    
    IP_SPOOFING_TECHNIQUES = [
        ("X-Forwarded-For", {"X-Forwarded-For": "127.0.0.1"}),
        ("X-Forwarded-For Local", {"X-Forwarded-For": "10.0.0.1"}),
        ("X-Real-IP", {"X-Real-IP": "127.0.0.1"}),
        ("X-Client-IP", {"X-Client-IP": "127.0.0.1"}),
        ("CF-Connecting-IP", {"CF-Connecting-IP": "127.0.0.1"}),
        ("X-Originating-IP", {"X-Originating-IP": "127.0.0.1"}),
    ]
    
    USER_AGENT_TECHNIQUES = [
        ("Google Bot", {"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"}),
        ("Mobile", {"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)"}),
        ("curl", {"User-Agent": "curl/7.64.1"}),
    ]
    
    CONTENT_TYPE_TECHNIQUES = [
        ("JSON", {"Content-Type": "application/json"}),
        ("Form URLEncoded", {"Content-Type": "application/x-www-form-urlencoded"}),
        ("Multipart", {"Content-Type": "multipart/form-data"}),
        ("XML", {"Content-Type": "application/xml"}),
    ]
    
    HEADER_MANIPULATION_TECHNIQUES = [
        ("Accept All", {"Accept": "*/*"}),
        ("Accept JSON", {"Accept": "application/json"}),
        ("Cache bypass", {"Cache-Control": "no-cache"}),
        ("Connection close", {"Connection": "close"}),
        ("Keep-Alive", {"Connection": "keep-alive"}),
    ]
    
    URL_MANIPULATION_TECHNIQUES = [
        ("Add trailing slash", lambda url: url.rstrip('/') + '/'),
        ("Remove trailing slash", lambda url: url.rstrip('/')),
        ("Add /v1/", lambda url: url.replace("/api/", "/api/v1/")),
        ("Add /api/v1/", lambda url: url.replace("/api/", "/api/v1/")),
        ("Double slash", lambda url: url.replace("/api", "/api/api")),
        ("Path traversal", lambda url: url.rstrip('/') + "/../test"),
    ]
    
    METHOD_TECHNIQUES = [
        ("GET to POST", "POST"),
        ("POST to GET", "GET"),
        ("PUT to DELETE", "DELETE"),
        ("GET to HEAD", "HEAD"),
        ("GET to OPTIONS", "OPTIONS"),
        ("POST to PATCH", "PATCH"),
    ]


class APIBypassTester:
    """
    API Bypass 测试器
    
    使用多种绕过技术尝试访问被阻止的 API
    """
    
    def __init__(self, http_client=None):
        self.http_client = http_client
        self.techniques = BypassTechniques()
        self.bypass_cache: Set[str] = set()
    
    def _generate_bypass_key(self, url: str, method: str, technique: str) -> str:
        """生成 bypass 缓存 key"""
        return f"{method}:{url}:{technique}"
    
    async def test_bypass(
        self,
        url: str,
        method: str = "GET",
        original_status: int = None,
        headers: Dict[str, str] = None,
        **kwargs
    ) -> List[BypassResult]:
        """
        测试 URL 的各种绕过技术
        
        Args:
            url: 目标 URL
            method: HTTP 方法
            original_status: 原始状态码
            headers: 原始请求头
            **kwargs: 其他参数
        
        Returns:
            BypassResult 列表
        """
        results = []
        headers = headers or {}
        
        if original_status == 401 or original_status is None:
            results.extend(await self._test_auth_bypass(url, method, headers, **kwargs))
        
        if original_status == 403 or original_status == 405:
            results.extend(await self._test_ip_spoofing(url, method, headers, **kwargs))
            results.extend(await self._test_header_manipulation(url, method, headers, **kwargs))
        
        if original_status == 404:
            results.extend(await self._test_url_manipulation(url, method, headers, **kwargs))
        
        if original_status == 500:
            results.extend(await self._test_content_type(url, method, headers, **kwargs))
        
        if original_status and original_status >= 500:
            results.extend(await self._test_method_change(url, "GET", headers, **kwargs))
        
        return [r for r in results if r.bypassed]
    
    async def _test_auth_bypass(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        **kwargs
    ) -> List[BypassResult]:
        """测试认证绕过技术"""
        results = []
        
        for name, auth_headers in self.techniques.AUTH_BYPASS_TECHNIQUES:
            bypass_key = self._generate_bypass_key(url, method, name)
            if bypass_key in self.bypass_cache:
                continue
            
            test_headers = headers.copy()
            test_headers.update(auth_headers)
            
            try:
                response = await self._make_request(url, method, test_headers, **kwargs)
                if response and self._is_bypassed(response.status_code):
                    results.append(BypassResult(
                        original_status=401,
                        bypassed_status=response.status_code,
                        technique=name,
                        category="auth_header",
                        bypassed=True,
                        response_time=getattr(response, 'response_time', 0),
                        details=f"Status changed to {response.status_code}"
                    ))
                    self.bypass_cache.add(bypass_key)
            except Exception as e:
                logger.debug(f"Auth bypass failed for {name}: {e}")
        
        return results
    
    async def _test_ip_spoofing(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        **kwargs
    ) -> List[BypassResult]:
        """测试 IP 欺骗绕过技术"""
        results = []
        
        for name, ip_headers in self.techniques.IP_SPOOFING_TECHNIQUES:
            bypass_key = self._generate_bypass_key(url, method, name)
            if bypass_key in self.bypass_cache:
                continue
            
            test_headers = headers.copy()
            test_headers.update(ip_headers)
            
            try:
                response = await self._make_request(url, method, test_headers, **kwargs)
                if response and self._is_bypassed(response.status_code):
                    results.append(BypassResult(
                        original_status=403,
                        bypassed_status=response.status_code,
                        technique=name,
                        category="ip_spoofing",
                        bypassed=True,
                        response_time=getattr(response, 'response_time', 0),
                        details=f"Status changed to {response.status_code}"
                    ))
                    self.bypass_cache.add(bypass_key)
            except Exception as e:
                logger.debug(f"IP spoofing bypass failed for {name}: {e}")
        
        return results
    
    async def _test_header_manipulation(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        **kwargs
    ) -> List[BypassResult]:
        """测试请求头操纵绕过技术"""
        results = []
        
        for name, extra_headers in self.techniques.USER_AGENT_TECHNIQUES + self.techniques.HEADER_MANIPULATION_TECHNIQUES:
            bypass_key = self._generate_bypass_key(url, method, name)
            if bypass_key in self.bypass_cache:
                continue
            
            test_headers = headers.copy()
            test_headers.update(extra_headers)
            
            try:
                response = await self._make_request(url, method, test_headers, **kwargs)
                if response and self._is_bypassed(response.status_code):
                    results.append(BypassResult(
                        original_status=403,
                        bypassed_status=response.status_code,
                        technique=name,
                        category="header_manipulation",
                        bypassed=True,
                        response_time=getattr(response, 'response_time', 0),
                        details=f"Status changed to {response.status_code}"
                    ))
                    self.bypass_cache.add(bypass_key)
            except Exception as e:
                logger.debug(f"Header manipulation bypass failed for {name}: {e}")
        
        return results
    
    async def _test_content_type(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        **kwargs
    ) -> List[BypassResult]:
        """测试 Content-Type 绕过技术"""
        results = []
        
        for name, ct_headers in self.techniques.CONTENT_TYPE_TECHNIQUES:
            bypass_key = self._generate_bypass_key(url, method, name)
            if bypass_key in self.bypass_cache:
                continue
            
            test_headers = headers.copy()
            test_headers.update(ct_headers)
            
            try:
                response = await self._make_request(url, method, test_headers, **kwargs)
                if response and self._is_bypassed(response.status_code):
                    results.append(BypassResult(
                        original_status=500,
                        bypassed_status=response.status_code,
                        technique=name,
                        category="content_type",
                        bypassed=True,
                        response_time=getattr(response, 'response_time', 0),
                        details=f"Status changed to {response.status_code}"
                    ))
                    self.bypass_cache.add(bypass_key)
            except Exception as e:
                logger.debug(f"Content-Type bypass failed for {name}: {e}")
        
        return results
    
    async def _test_url_manipulation(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        **kwargs
    ) -> List[BypassResult]:
        """测试 URL 操纵绕过技术"""
        results = []
        
        for name, url_transform in self.techniques.URL_MANIPULATION_TECHNIQUES:
            bypass_key = self._generate_bypass_key(url, method, name)
            if bypass_key in self.bypass_cache:
                continue
            
            try:
                new_url = url_transform(url)
                if new_url == url:
                    continue
                
                response = await self._make_request(new_url, method, headers, **kwargs)
                if response and self._is_bypassed(response.status_code):
                    results.append(BypassResult(
                        original_status=404,
                        bypassed_status=response.status_code,
                        technique=name,
                        category="url_manipulation",
                        bypassed=True,
                        response_time=getattr(response, 'response_time', 0),
                        details=f"URL: {url} -> {new_url}, Status: {response.status_code}"
                    ))
                    self.bypass_cache.add(bypass_key)
            except Exception as e:
                logger.debug(f"URL manipulation bypass failed for {name}: {e}")
        
        return results
    
    async def _test_method_change(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        **kwargs
    ) -> List[BypassResult]:
        """测试 HTTP 方法变换绕过技术"""
        results = []
        
        for name, new_method in self.techniques.METHOD_TECHNIQUES:
            bypass_key = self._generate_bypass_key(url, new_method, name)
            if bypass_key in self.bypass_cache:
                continue
            
            try:
                response = await self._make_request(url, new_method, headers, **kwargs)
                if response and self._is_bypassed(response.status_code):
                    results.append(BypassResult(
                        original_status=405,
                        bypassed_status=response.status_code,
                        technique=f"{method} -> {new_method}",
                        category="request_method",
                        bypassed=True,
                        response_time=getattr(response, 'response_time', 0),
                        details=f"Method changed to {new_method}, Status: {response.status_code}"
                    ))
                    self.bypass_cache.add(bypass_key)
            except Exception as e:
                logger.debug(f"Method change bypass failed for {name}: {e}")
        
        return results
    
    async def _make_request(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        **kwargs
    ):
        """发送测试请求"""
        if self.http_client:
            return await self.http_client.request(url, method=method, headers=headers, **kwargs)
        return None
    
    def _is_bypassed(self, status_code: int) -> bool:
        """判断是否绕过成功"""
        if not status_code:
            return False
        return 200 <= status_code < 400


class SmartBypassTester(APIBypassTester):
    """
    智能 Bypass 测试器
    
    在返回 401/403/404/500 等状态码时，
    智能选择合适的绕过技术进行测试
    """
    
    BYPASS_PRIORITY = {
        401: ["auth_header", "header_manipulation"],
        403: ["ip_spoofing", "header_manipulation", "url_manipulation"],
        404: ["url_manipulation"],
        405: ["request_method"],
        500: ["content_type", "parameter_manipulation"],
    }
    
    async def smart_bypass(
        self,
        url: str,
        method: str = "GET",
        status_code: int = None,
        headers: Dict[str, str] = None,
        **kwargs
    ) -> Optional[BypassResult]:
        """
        智能选择绕过技术
        
        Args:
            url: 目标 URL
            method: HTTP 方法
            status_code: 当前状态码
            headers: 请求头
            **kwargs: 其他参数
        
        Returns:
            第一个成功的 BypassResult，或 None
        """
        if status_code not in self.BYPASS_PRIORITY:
            return None
        
        priority_categories = self.BYPASS_PRIORITY[status_code]
        
        for category in priority_categories:
            results = []
            
            if category == "auth_header":
                results = await self._test_auth_bypass(url, method, headers or {}, **kwargs)
            elif category == "ip_spoofing":
                results = await self._test_ip_spoofing(url, method, headers or {}, **kwargs)
            elif category == "header_manipulation":
                results = await self._test_header_manipulation(url, method, headers or {}, **kwargs)
            elif category == "url_manipulation":
                results = await self._test_url_manipulation(url, method, headers or {}, **kwargs)
            elif category == "content_type":
                results = await self._test_content_type(url, method, headers or {}, **kwargs)
            elif category == "request_method":
                results = await self._test_method_change(url, method, headers or {}, **kwargs)
            
            if results:
                return results[0]
        
        return None
