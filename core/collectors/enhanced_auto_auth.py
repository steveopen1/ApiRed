"""
Enhanced Auto Authentication Module
增强自动认证模块 - 认证后自动发现隐藏API

增强功能：
1. 认证后自动触发页面交互
2. 管理后台/API后台自动发现
3. 登录后访问更多页面触发隐藏API
4. 会话保持和后续请求自动携带认证信息
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class PostAuthDiscoveryResult:
    """认证后发现结果"""
    authenticated: bool
    credential: Any
    discovered_endpoints: List[str]
    discovered_routes: List[str]
    csrf_token: Optional[str] = None
    session_cookie: Optional[str] = None


class EnhancedAutoAuthenticator:
    """
    增强版自动认证器
    
    在认证后自动进行：
    1. 访问管理后台常见路径
    2. 触发页面交互（点击、滚动、输入）
    3. 监控网络请求发现隐藏API
    """

    ADMIN_PATHS = [
        '/admin',
        '/manage',
        '/manager',
        '/console',
        '/dashboard',
        '/control',
        '/panel',
        '/backend',
        '/api/admin',
        '/api/manage',
        '/api/v1/admin',
        '/api/v2/admin',
        '/management',
        '/sysadmin',
        '/superadmin',
    ]

    SENSITIVE_ROUTES = [
        '/user/list',
        '/user/add',
        '/user/edit',
        '/order/list',
        '/order/export',
        '/admin/settings',
        '/config',
        '/api/config',
        '/api/settings',
    ]

    def __init__(self, http_client):
        self.http_client = http_client
        self.discovered_endpoints: Set[str] = set()
        self.discovered_routes: Set[str] = set()

    async def authenticate_and_discover(
        self,
        base_url: str,
        credentials: Any,
        login_endpoints: List[Any],
        browser_page=None
    ) -> PostAuthDiscoveryResult:
        """
        认证并自动发现后续API
        
        Args:
            base_url: 目标URL
            credentials: 认证凭据
            login_endpoints: 登录端点列表
            browser_page: 可选的Playwright页面对象
            
        Returns:
            PostAuthDiscoveryResult
        """
        result = PostAuthDiscoveryResult(
            authenticated=False,
            credential=None,
            discovered_endpoints=[],
            discovered_routes=[]
        )

        from .auto_auth import AutoAuthenticator
        authenticator = AutoAuthenticator(self.http_client)

        auth_result = await authenticator.try_authenticate(
            base_url,
            credentials,
            login_endpoints,
            None
        )

        if not auth_result:
            logger.info("[EnhancedAutoAuth] 认证失败，跳过后续发现")
            return result

        result.authenticated = True
        result.credential = auth_result

        if auth_result.headers:
            for key, value in auth_result.headers.items():
                if 'csrf' in key.lower():
                    result.csrf_token = value
                if 'cookie' in key.lower():
                    result.session_cookie = value

        if browser_page:
            await self._discover_with_browser(browser_page, auth_result)
        else:
            await self._discover_with_http(base_url, auth_result)

        result.discovered_endpoints = list(self.discovered_endpoints)
        result.discovered_routes = list(self.discovered_routes)

        logger.info(f"[EnhancedAutoAuth] 发现 {len(result.discovered_endpoints)} 个端点, {len(result.discovered_routes)} 个路由")

        return result

    async def _discover_with_browser(self, page, credential):
        """使用浏览器进行认证后API发现"""
        try:
            headers = {}
            if credential.headers:
                headers.update(credential.headers)
            if credential.cookie:
                headers['Cookie'] = credential.cookie

            for path in self.ADMIN_PATHS:
                try:
                    url = f"{self._get_base_url(page.url())}{path}"
                    resp = await self.http_client.request(url, 'GET', headers=headers)
                    if resp.status_code == 200:
                        self.discovered_routes.add(path)
                        logger.info(f"[EnhancedAutoAuth] 发现管理后台: {path}")
                except Exception as e:
                    logger.debug(f"Admin path {path} failed: {e}")

            await self._trigger_browser_interactions(page, headers)

        except Exception as e:
            logger.debug(f"Browser discovery failed: {e}")

    async def _discover_with_http(self, base_url: str, credential):
        """使用HTTP请求进行认证后API发现"""
        try:
            headers = {}
            if credential.headers:
                headers.update(credential.headers)
            if credential.cookie:
                headers['Cookie'] = credential.cookie

            parsed_url = self._parse_url(base_url)
            base = f"{parsed_url.scheme}://{parsed_url.netloc}"

            for path in self.ADMIN_PATHS:
                try:
                    url = f"{base}{path}"
                    resp = await self.http_client.request(url, 'GET', headers=headers)
                    if resp.status_code == 200:
                        self.discovered_routes.add(path)
                        logger.info(f"[EnhancedAutoAuth] 发现管理后台: {path}")
                except Exception as e:
                    logger.debug(f"Admin path {path} failed: {e}")

            for path in self.SENSITIVE_ROUTES:
                try:
                    url = f"{base}{path}"
                    resp = await self.http_client.request(url, 'GET', headers=headers)
                    if resp.status_code != 404:
                        self.discovered_endpoints.add(path)
                        logger.info(f"[EnhancedAutoAuth] 发现敏感端点: {path}")
                except Exception:
                    pass

        except Exception as e:
            logger.debug(f"HTTP discovery failed: {e}")

    async def _trigger_browser_interactions(self, page, headers: Dict):
        """触发浏览器交互以发现更多API"""
        try:
            await page.evaluate("""
                async () => {
                    // Scroll through the page
                    for (let i = 0; i < 5; i++) {
                        window.scrollBy(0, 500);
                        await new Promise(r => setTimeout(r, 200));
                    }
                    
                    // Try clicking common interactive elements
                    const clickables = document.querySelectorAll('a, button');
                    clickables.forEach(el => {
                        if (el.offsetParent !== null) {
                            el.click();
                        }
                    });
                }
            """)

            await asyncio.sleep(2)

            for header_name, header_value in headers.items():
                if 'cookie' in header_name.lower():
                    await page.set_extra_http_headers({header_name: header_value})

        except Exception as e:
            logger.debug(f"Browser interaction failed: {e}")

    def _parse_url(self, url: str):
        """解析URL"""
        from urllib.parse import urlparse
        return urlparse(url)

    def _get_base_url(self, url: str) -> str:
        """获取基础URL"""
        parsed = self._parse_url(url)
        return f"{parsed.scheme}://{parsed.netloc}"


async def enhanced_auto_authenticate(
    http_client,
    base_url: str,
    js_contents: List[str] = None,
    discovered_paths: List[str] = None,
    browser_page=None
) -> Optional[PostAuthDiscoveryResult]:
    """
    增强版自动化认证入口函数
    
    相比原版auto_authenticate:
    1. 认证后自动访问管理后台
    2. 触发更多页面交互
    3. 发现隐藏的敏感API
    
    Args:
        http_client: HTTP 客户端
        base_url: 目标 URL
        js_contents: 可选的 JS 内容列表
        discovered_paths: 已发现的 API 路径列表
        browser_page: Playwright页面对象（可选）
        
    Returns:
        PostAuthDiscoveryResult，失败返回None
    """
    extractor = AuthInfoExtractor()
    discoverer = LoginInterfaceDiscoverer()

    credentials = []
    login_endpoints = []

    if js_contents:
        for js in js_contents:
            creds, endpoints = extractor.extract_from_js(js)
            credentials.extend(creds)
            login_endpoints.extend(endpoints)

    if login_endpoints:
        logger.info(f"[EnhancedAutoAuth] 发现 {len(login_endpoints)} 个登录接口")

    enhanced_auth = EnhancedAutoAuthenticator(http_client)

    result = await enhanced_auth.authenticate_and_discover(
        base_url,
        credentials,
        login_endpoints,
        browser_page
    )

    if result.authenticated:
        logger.info(f"[EnhancedAutoAuth] 认证成功，发现 {len(result.discovered_endpoints)} 个端点")
    else:
        logger.info(f"[EnhancedAutoAuth] 认证失败")

    return result if result.authenticated else None
