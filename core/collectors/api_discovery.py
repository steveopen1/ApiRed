"""
API Discovery Module - API 拦截与前缀发现模块
增强 BrowserCollector 的 API 发现能力
支持：fetch/XHR 拦截、baseURL 提取、路径映射、认证处理
"""

import re
import json
import asyncio
import logging
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin

logger = logging.getLogger(__name__)


@dataclass
class DiscoveredAPI:
    """发现的 API 端点"""
    url: str
    method: str = "GET"
    source: str = ""  # fetch, xhr, js, manual
    js_path: str = ""  # JS 中的原始路径
    real_path: str = ""  # 实际请求路径
    needs_auth: bool = False
    headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class AuthCredential:
    """认证凭据"""
    token: str = ""
    token_type: str = "Bearer"
    refresh_token: str = ""
    expires_at: float = 0


class ResponseTypeDetector:
    """响应类型检测器"""
    
    JSON_PATTERNS = [
        r'^\s*\{',  # starts with {
        r'^\s*\[',  # starts with [
    ]
    
    HTML_PATTERNS = [
        r'<!DOCTYPE\s+html',
        r'<html',
        r'<head>.*<title>',
        r'window\.location\.href',
    ]
    
    @classmethod
    def detect(cls, content: str, content_type: str = "") -> str:
        """检测响应类型: json, html, redirect, unknown"""
        if not content:
            return "empty"
        
        if "application/json" in content_type or "text/json" in content_type:
            return "json"
        
        if any(re.search(p, content, re.IGNORECASE) for p in cls.JSON_PATTERNS):
            try:
                json.loads(content)
                return "json"
            except:
                pass
        
        if any(re.search(p, content, re.IGNORECASE) for p in cls.HTML_PATTERNS):
            return "html"
        
        if content.startswith("<!") or content.startswith("<html"):
            return "html"
        
        if "title" in content.lower() and "<" in content:
            return "html"
        
        if "window.location" in content.lower():
            return "redirect"
        
        return "unknown"


class BaseURLExtractor:
    """从 JS 代码中提取 baseURL 配置"""
    
    PATTERNS = [
        re.compile(r'baseURL\s*:\s*["\']([^"\']+)["\']', re.I),
        re.compile(r'baseUrl\s*:\s*["\']([^"\']+)["\']', re.I),
        re.compile(r'apiBase\s*:\s*["\']([^"\']+)["\']', re.I),
        re.compile(r'api_url\s*:\s*["\']([^"\']+)["\']', re.I),
        re.compile(r'axios\.create\(\s*\{\s*baseURL\s*:\s*["\']([^"\']+)["\']', re.I),
        re.compile(r'["\']baseURL["\']\s*:\s*["\']([^"\']+)["\']', re.I),
        re.compile(r'root\s*:\s*["\']([^"\']+)["\']', re.I),
    ]
    
    @classmethod
    def extract(cls, js_content: str) -> List[str]:
        """从 JS 内容中提取 baseURL"""
        base_urls = set()
        
        for pattern in cls.PATTERNS:
            matches = pattern.findall(js_content)
            for match in matches:
                if match and not match.startswith("http"):
                    base_urls.add(match)
        
        return list(base_urls)


class PathMapper:
    """JS 路径 → 实际 API 路径 映射器"""
    
    def __init__(self):
        self.base_prefixes: Set[str] = set()
        self.path_mappings: Dict[str, str] = {}
        self.reverse_mappings: Dict[str, str] = {}
    
    def add_base_prefix(self, prefix: str):
        """添加基础前缀"""
        if prefix and not prefix.startswith("http"):
            self.base_prefixes.add(prefix)
    
    def add_mapping(self, js_path: str, real_path: str):
        """添加路径映射"""
        if not js_path.startswith("/"):
            js_path = "/" + js_path
        self.path_mappings[js_path] = real_path
        self.reverse_mappings[real_path] = js_path
    
    def transform_path(self, path: str) -> List[str]:
        """转换路径，返回所有可能的实际路径"""
        if not path.startswith("/"):
            path = "/" + path
        
        results = set()
        
        results.add(path)
        
        for base in self.base_prefixes:
            if not base.endswith("/") and not path.startswith("/"):
                results.add(f"{base}/{path}")
            elif base.endswith("/"):
                results.add(f"{base}{path.lstrip('/')}")
            else:
                results.add(f"{base}{path}")
        
        return list(results)
    
    def get_real_path(self, js_path: str) -> Optional[str]:
        """获取实际路径"""
        if not js_path.startswith("/"):
            js_path = "/" + js_path
        return self.path_mappings.get(js_path)


class APIInterceptor:
    """API 拦截器 - 拦截 fetch 和 XHR 调用"""
    
    INTERCEPT_SCRIPT = '''
    (() => {
        if (window.__apiInterceptorInitialized) return;
        window.__apiInterceptorInitialized = true;
        
        window.__discoveredAPIs = [];
        window.__baseURLs = [];
        
        const originalFetch = window.fetch;
        window.fetch = async (...args) => {
            const url = typeof args[0] === 'string' ? args[0] : args[0].url;
            const method = args[0]?.method || 'GET';
            
            if (url && (url.includes('/api') || url.includes('/prod-api') || 
                        url.includes('/v1') || url.includes('/v2') || 
                        url.includes('/auth') || url.includes('/admin') ||
                        url.match(/\\/api\\/)|url.includes('.do')||url.includes('.json'))) {
                window.__discoveredAPIs.push({url: url, method: method, type: 'fetch'});
                console.log('[API-FETCH]', method, url);
            }
            
            return originalFetch.apply(window, args);
        };
        
        const originalXHROpen = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function(method, url, ...rest) {
            if (url && (url.includes('/api') || url.includes('/prod-api') || 
                        url.includes('/v1') || url.includes('/v2') || 
                        url.includes('/auth') || url.includes('/admin') ||
                        url.match(/\\/api\\/)|url.includes('.do')||url.includes('.json'))) {
                window.__discoveredAPIs.push({url: url, method: method, type: 'xhr'});
                console.log('[API-XHR]', method, url);
            }
            return originalXHROpen.call(this, method, url, ...rest);
        };
        
        if (window.axios) {
            const originalCreate = window.axios.create;
            if (originalCreate) {
                window.axios.create = (...args) => {
                    const instance = originalCreate.apply(window.axios, args);
                    if (args[0]?.baseURL) {
                        window.__baseURLs.push(args[0].baseURL);
                        console.log('[BASE-URL]', args[0].baseURL);
                    }
                    return instance;
                };
            }
        }
        
        window.getDiscoveredAPIs = () => window.__discoveredAPIs;
        window.getBaseURLs = () => window.__baseURLs;
    })();
    '''
    
    @classmethod
    def get_script(cls) -> str:
        return cls.INTERCEPT_SCRIPT


class AuthHandler:
    """认证处理器 - 处理登录、验证码、Token"""
    
    def __init__(self, http_client=None):
        self.http_client = http_client
        self.credentials: Optional[AuthCredential] = None
        self.captcha_image: Optional[bytes] = None
        self.captcha_text: str = ""
        self.session_cookies: Dict[str, str] = {}
    
    async def get_captcha(self, url: str) -> Optional[bytes]:
        """获取验证码图片"""
        if not self.http_client:
            return None
        
        try:
            resp = await self.http_client.request(url, "GET", timeout=10)
            if resp and resp.status_code == 200:
                return resp.content
        except Exception as e:
            logger.debug(f"Captcha request failed: {e}")
        
        return None
    
    async def login(self, url: str, username: str, password: str, 
                   captcha: str = "", **kwargs) -> Tuple[bool, str]:
        """执行登录"""
        if not self.http_client:
            return False, "No HTTP client"
        
        try:
            data = {
                "username": username,
                "password": password,
            }
            if captcha:
                data["code"] = captcha
            
            data.update(kwargs)
            
            resp = await self.http_client.request(
                url, "POST",
                json_data=data,
                timeout=15
            )
            
            if resp and resp.status_code == 200:
                content = resp.content
                if isinstance(content, bytes):
                    content = content.decode('utf-8')
                
                try:
                    json_data = json.loads(content)
                    if json_data.get("code") == 200:
                        token = self._extract_token(resp.headers)
                        if token:
                            self.credentials = AuthCredential(token=token)
                            return True, "Login success"
                        return True, "Login success, no token found"
                    else:
                        return False, json_data.get("msg", "Login failed")
                except:
                    return False, "Invalid response"
            
            return False, f"HTTP {resp.status_code if resp else 'None'}"
        
        except Exception as e:
            return False, str(e)
    
    def _extract_token(self, headers: Dict) -> Optional[str]:
        """从响应头提取 Token"""
        auth_header = headers.get("Authorization", "")
        if auth_header:
            return auth_header
        
        auth_header = headers.get("authorization", "")
        if auth_header:
            return auth_header
        
        return None
    
    def set_token(self, token: str, token_type: str = "Bearer"):
        """手动设置 Token"""
        self.credentials = AuthCredential(token=token, token_type=token_type)
    
    def get_auth_headers(self) -> Dict[str, str]:
        """获取认证头"""
        if self.credentials and self.credentials.token:
            return {
                "Authorization": f"{self.credentials.token_type} {self.credentials.token}"
            }
        return {}
    
    def get_session_cookies(self) -> Dict[str, str]:
        """获取会话 Cookie"""
        return self.session_cookies.copy()


class APIPathDiscoverer:
    """API 路径发现器 - 从 JS 和网络请求中发现 API"""
    
    def __init__(self):
        self.discovered_apis: List[DiscoveredAPI] = []
        self.base_prefixes: Set[str] = set()
        self.path_mapper = PathMapper()
        self.intercepted_calls: List[Dict] = []
    
    def add_intercepted_call(self, url: str, method: str = "GET", source: str = "xhr"):
        """添加拦截到的 API 调用"""
        api = DiscoveredAPI(
            url=url,
            method=method,
            source=source
        )
        
        parsed = urlparse(url)
        if parsed.path:
            api.real_path = parsed.path
            self.path_mapper.add_mapping(parsed.path, parsed.path)
        
        self.discovered_apis.append(api)
        self.intercepted_calls.append({"url": url, "method": method, "source": source})
    
    def add_base_url(self, base_url: str):
        """添加 baseURL"""
        if base_url and not base_url.startswith("http"):
            self.base_prefixes.add(base_url)
            self.path_mapper.add_base_prefix(base_url)
    
    def extract_from_js(self, js_content: str) -> List[str]:
        """从 JS 内容中提取 API 路径"""
        found_paths = []
        
        base_urls = BaseURLExtractor.extract(js_content)
        for base in base_urls:
            self.add_base_url(base)
        
        patterns = [
            r'["\'](/[a-zA-Z0-9_/-]+/[a-zA-Z0-9_/-]+)["\']',
            r'["\']([a-zA-Z0-9_]+/[a-zA-Z0-9_]+)["\']\s*:\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, js_content)
            for match in matches:
                if isinstance(match, tuple) and len(match) >= 2:
                    path = match[0] if match[0].startswith("/") else "/" + match[0]
                    found_paths.append(path)
                elif isinstance(match, str) and match.startswith("/"):
                    found_paths.append(match)
        
        return found_paths
    
    def get_all_paths(self) -> List[str]:
        """获取所有发现的路径"""
        paths = set()
        
        for api in self.discovered_apis:
            if api.real_path:
                paths.add(api.real_path)
        
        for base in self.base_prefixes:
            if not base.endswith("/"):
                base = base + "/"
        
        return list(paths)
    
    def get_api_endpoints(self) -> List[DiscoveredAPI]:
        """获取所有 API 端点"""
        return self.discovered_apis.copy()
    
    def get_base_prefixes(self) -> Set[str]:
        """获取所有 baseURL 前缀"""
        return self.base_prefixes.copy()


class APIResponseAnalyzer:
    """API 响应分析器"""
    
    def __init__(self):
        self.response_cache: Dict[str, Any] = {}
    
    async def analyze_response(self, url: str, response: Any) -> Dict[str, Any]:
        """分析 API 响应"""
        result = {
            "url": url,
            "status": response.status_code if response else None,
            "content_type": "",
            "response_type": "unknown",
            "is_json": False,
            "is_html": False,
            "needs_auth": False,
            "error": None,
        }
        
        if not response:
            result["error"] = "No response"
            return result
        
        result["content_type"] = response.headers.get("Content-Type", "")
        
        try:
            content = response.content
            if isinstance(content, bytes):
                content = content.decode('utf-8', errors='ignore')
            
            result["response_type"] = ResponseTypeDetector.detect(content, result["content_type"])
            
            if result["response_type"] == "json":
                result["is_json"] = True
                try:
                    json_data = json.loads(content)
                    result["json_data"] = json_data
                    
                    if "code" in json_data:
                        if json_data["code"] == 401 or "令牌" in str(json_data.get("msg", "")):
                            result["needs_auth"] = True
                        if "data" in json_data:
                            result["has_data"] = True
                except:
                    pass
            
            elif result["response_type"] == "html":
                result["is_html"] = True
                
        except Exception as e:
            result["error"] = str(e)
        
        return result


def create_api_discoverer() -> APIPathDiscoverer:
    """创建 API 发现器"""
    return APIPathDiscoverer()


def get_intercept_script() -> str:
    """获取拦截脚本"""
    return APIInterceptor.get_script()
