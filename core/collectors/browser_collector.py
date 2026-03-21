"""
Headless Browser Collector
基于 Playwright 的无头浏览器采集器
支持 JS 执行、SPA 路由发现、动态内容采集
"""

import asyncio
import re
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse


@dataclass
class BrowserResource:
    """浏览器采集的资源"""
    url: str
    resource_type: str  # js, api, page, screenshot
    content: str
    method: str = "GET"
    api_patterns: List[str] = None
    vulnerabilities: List[str] = None
    screenshots: List[str] = None
    
    def __post_init__(self):
        if self.api_patterns is None:
            self.api_patterns = []
        if self.vulnerabilities is None:
            self.vulnerabilities = []
        if self.screenshots is None:
            self.screenshots = []


class HeadlessBrowserCollector:
    """
    无头浏览器采集器
    
    功能：
    1. 执行 JavaScript 获取动态内容
    2. 发现 SPA 路由
    3. 拦截 API 请求
    4. 采集隐藏的 API 端点
    5. 页面截图
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.browser = None
        self.context = None
        self.page = None
        self.collected_resources: List[BrowserResource] = []
        self.api_endpoints: Set[str] = set()
        self.js_files: Set[str] = set()
        self.screenshots: List[str] = []
        self._api_url_patterns = [
            r'/(?:api|rest|v\d+)/[a-zA-Z0-9_/-]+',
            r'/callComponent/[a-zA-Z0-9_]+/[a-zA-Z0-9_]+',
            r'/rpc/[a-zA-Z0-9_]+/[a-zA-Z0-9_]+',
            r'/[a-zA-Z0-9_]+/(?:get|post|put|delete|list|query|export|import)',
        ]
    
    async def initialize(self, headless: bool = True):
        """初始化浏览器"""
        try:
            from playwright.async_api import async_playwright
            
            self.playwright = await async_playwright().start()
            self.browser = await self.playwright.chromium.launch(
                headless=headless,
                args=['--no-sandbox', '--disable-dev-shm-usage']
            )
            self.context = await self.browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            )
            self.page = await self.context.new_page()
            
            await self._setup_interceptors()
            return True
        except Exception as e:
            print(f"Failed to initialize browser: {e}")
            return False
    
    async def _setup_interceptors(self):
        """设置请求拦截器"""
        async def handle_request(request):
            url = request.url
            resource_type = request.resource_type
            
            if resource_type == 'script' or url.endswith('.js'):
                self.js_files.add(url)
            
            for pattern in self._api_url_patterns:
                if re.search(pattern, url):
                    self.api_endpoints.add(url)
            
            self.collected_resources.append(BrowserResource(
                url=url,
                resource_type=resource_type,
                content=""
            ))
        
        if self.page:
            self.page.on("request", handle_request)
    
    async def navigate(self, url: str, wait_until: str = "networkidle") -> bool:
        """导航到指定 URL"""
        if not self.page:
            return False
        
        try:
            await self.page.goto(url, wait_until=wait_until, timeout=30000)
            await self.page.wait_for_timeout(2000)
            return True
        except Exception as e:
            print(f"Navigation failed: {e}")
            return False
    
    async def execute_js(self, js_code: str) -> Any:
        """执行 JavaScript 代码"""
        if not self.page:
            return None
        
        try:
            result = await self.page.evaluate(js_code)
            return result
        except Exception as e:
            print(f"JS execution failed: {e}")
            return None
    
    async def discover_spa_routes(self) -> List[str]:
        """发现 SPA 路由"""
        routes = []
        
        if not self.page:
            return routes
        
        js_code = """
        () => {
            const routes = new Set();
            
            // 1. 从 vue-router 获取
            if (window.Vue && window.VueRouter) {
                try {
                    const router = window.VueRouter;
                    router.getRoutes().forEach(r => routes.add(r.path));
                } catch(e) {}
            }
            
            // 2. 从 react-router 获取
            if (window.React && window.ReactRouter) {
                try {
                    const routes = window.ReactRouter.routes || [];
                    routes.forEach(r => routes.add(r.path));
                } catch(e) {}
            }
            
            // 3. 从 angular router 获取
            if (window.ng && window.ng.probe) {
                try {
                    const el = window.ng.probe(document.querySelector('app-root'));
                    const router = el.injector.get(window.ng.router.Router);
                    router.config.forEach(r => routes.add(r.path));
                } catch(e) {}
            }
            
            // 4. 从 History API 获取
            if (window.history && window.history.pushState) {
                const links = document.querySelectorAll('a[href]');
                links.forEach(a => {
                    const href = a.getAttribute('href');
                    if (href && !href.startsWith('http') && !href.startsWith('//') && href !== '#') {
                        routes.add(href);
                    }
                });
            }
            
            return Array.from(routes);
        }
        """
        
        try:
            result = await self.execute_js(js_code)
            if result:
                routes.extend(result)
        except Exception as e:
            print(f"SPA route discovery failed: {e}")
        
        return list(set(routes))
    
    async def discover_api_endpoints(self) -> List[str]:
        """从页面和 JS 中发现 API 端点"""
        endpoints = list(self.api_endpoints)
        
        js_code = """
        () => {
            const endpoints = new Set();
            const patterns = [
                /api\\/[a-zA-Z0-9_\\/-]+/,
                /callComponent\\/[a-zA-Z0-9_]+\\/[a-zA-Z0-9_]+/,
                /rpc\\/[a-zA-Z0-9_]+\\/[a-zA-Z0-9_]+/,
                /v\\d+\\/[a-zA-Z0-9_]+/
            ];
            
            // 1. 从 fetch/axios 调用中发现
            const originalFetch = window.fetch;
            window.fetch = function(...args) {
                const url = args[0];
                if (typeof url === 'string') {
                    patterns.forEach(p => {
                        const match = url.match(p);
                        if (match) endpoints.add(match[0]);
                    });
                }
                return originalFetch.apply(this, args);
            };
            
            // 2. 从 script 标签中发现 API 配置
            const scripts = document.querySelectorAll('script:not([src])');
            scripts.forEach(s => {
                const content = s.textContent;
                patterns.forEach(p => {
                    const match = content.match(p);
                    if (match) endpoints.add(match[0]);
                });
            });
            
            // 3. 从 DOM 中发现
            const allText = document.body ? document.body.innerText : '';
            patterns.forEach(p => {
                const match = allText.match(p);
                if (match) endpoints.add(match[0]);
            });
            
            return Array.from(endpoints);
        }
        """
        
        try:
            result = await self.execute_js(js_code)
            if result:
                endpoints.extend(result)
        except Exception as e:
            print(f"API endpoint discovery failed: {e}")
        
        return list(set(endpoints))
    
    async def take_screenshot(self, path: str) -> Optional[str]:
        """页面截图"""
        if not self.page:
            return None
        
        try:
            await self.page.screenshot(path=path, full_page=True)
            self.screenshots.append(path)
            return path
        except Exception as e:
            print(f"Screenshot failed: {e}")
            return None
    
    async def click_and_interact(self, selector: str) -> bool:
        """点击元素并等待网络空闲"""
        if not self.page:
            return False
        
        try:
            await self.page.click(selector, timeout=5000)
            await self.page.wait_for_load_state("networkidle", timeout=10000)
            return True
        except Exception:
            return False
    
    async def scroll_page(self) -> bool:
        """滚动页面触发懒加载"""
        if not self.page:
            return False
        
        try:
            await self.page.evaluate("""
                async () => {
                    return new Promise((resolve) => {
                        let totalHeight = 0;
                        let distance = 100;
                        let scrollCount = 0;
                        const maxScrolls = 20;
                        
                        const timer = setInterval(() => {
                            window.scrollBy(0, distance);
                            totalHeight += distance;
                            scrollCount++;
                            
                            if (scrollCount >= maxScrolls) {
                                clearInterval(timer);
                                resolve();
                            }
                        }, 100);
                    });
                }
            """)
            return True
        except Exception:
            return False
    
    async def collect_page_content(self) -> Dict[str, Any]:
        """收集页面内容"""
        if not self.page:
            return {}
        
        content = await self.page.content()
        title = await self.page.title()
        
        return {
            'url': self.page.url,
            'title': title,
            'content': content,
            'js_files': list(self.js_files),
            'api_endpoints': list(self.api_endpoints),
            'routes': await self.discover_spa_routes(),
            'screenshots': self.screenshots
        }
    
    async def close(self):
        """关闭浏览器"""
        try:
            if self.page:
                await self.page.close()
            if self.context:
                await self.context.close()
            if self.browser:
                await self.browser.close()
            if self.playwright:
                await self.playwright.stop()
        except Exception:
            pass


async def create_browser_collector(config: Optional[Dict] = None) -> HeadlessBrowserCollector:
    """创建无头浏览器采集器"""
    collector = HeadlessBrowserCollector(config)
    success = await collector.initialize(headless=True)
    if success:
        return collector
    return None
