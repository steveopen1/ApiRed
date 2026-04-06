"""
Headless Browser Collector
基于 Playwright 的无头浏览器采集器
支持 JS 执行、SPA 路由发现、动态内容采集
"""

import asyncio
import os
import re
import logging
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)


def check_browser_dependencies() -> dict:
    """
    检查浏览器依赖状态
    
    Returns:
        状态报告字典
    """
    try:
        from ..utils.browser_deps import BrowserDependencyInstaller, check_and_install_browser_deps
        return check_and_install_browser_deps()
    except ImportError:
        return {
            'error': 'browser_deps module not found',
            'can_run_browser': False
        }


@dataclass
class BrowserResource:
    """浏览器采集的资源"""
    url: str
    resource_type: str  # js, api, page, screenshot
    content: str
    method: str = "GET"
    api_patterns: Optional[List[str]] = None
    vulnerabilities: Optional[List[str]] = None
    screenshots: Optional[List[str]] = None
    
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
    6. 捕获 JS 文件响应正文用于解析
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.browser = None
        self.context = None
        self.page = None
        self.collected_resources: List[BrowserResource] = []
        self.api_endpoints: Set[str] = set()
        self.js_files: Set[str] = set()
        self.js_contents: List[Dict[str, Any]] = []
        self.screenshots: List[str] = []
        self._js_content_set: Set[str] = set()
        self._api_url_patterns = [
            r'/(?:api|rest|v\d+|gateway|proxy|backend|service|app|web|www)[-/][a-zA-Z0-9_/-]+',
            r'/callComponent/[a-zA-Z0-9_]+/[a-zA-Z0-9_]+',
            r'/rpc/[a-zA-Z0-9_]+/[a-zA-Z0-9_]+',
            r'/graphql',
            r'/socket\.io',
            r'/ws(?:s)?://',
            r'/[a-zA-Z0-9_]+/(?:get|post|put|delete|list|query|export|import|save|update|remove|add|create|detail|info)',
            r'/sse(?:/|$)',
            r'/events(?:/|$)',
            r'/realtime(?:/|$)',
        ]
        self._dep_check_done = False
    
    async def initialize(self, headless: bool = True, ignore_ssl_errors: bool = True):
        """初始化浏览器"""
        deps_status = check_browser_dependencies()
        
        if not deps_status.get('can_run_browser', False):
            error_msg = "Browser dependencies not available"
            
            if 'missing_dependencies' in deps_status and deps_status['missing_dependencies']:
                missing = deps_status['missing_dependencies']
                logger.warning(f"Missing browser dependencies: {len(missing)} libraries")
                logger.warning(f"Installation command:\n  {deps_status.get('install_command', 'N/A')}")
            
            if not deps_status.get('playwright_installed', False):
                logger.warning("Playwright is not installed. Run: pip install playwright && python -m playwright install chromium")
            elif not deps_status.get('chromium_installed', False):
                logger.warning("Chromium is not installed. Run: python -m playwright install chromium")
            
            return False
        
        try:
            from playwright.async_api import async_playwright  # type: ignore
            
            self.playwright = await async_playwright().start()
            
            headless_shell_path = '/root/.cache/ms-playwright/chromium_headless_shell-1208/chrome-headless-shell-linux64/chrome-headless-shell'
            if os.path.exists(headless_shell_path):
                self.browser = await self.playwright.chromium.launch(
                    executable_path=headless_shell_path,
                    headless=headless,
                    args=['--no-sandbox', '--disable-dev-shm-usage']
                )
            else:
                self.browser = await self.playwright.chromium.launch(
                    headless=headless,
                    args=['--no-sandbox', '--disable-dev-shm-usage']
                )
            self.context = await self.browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                ignore_https_errors=True
            )
            self.page = await self.context.new_page()
            
            await self._setup_interceptors()
            self._dep_check_done = True
            return True
        except Exception as e:
            error_str = str(e)
            
            if 'libglib' in error_str or 'libnss' in error_str or 'libnspr' in error_str:
                deps_status = check_browser_dependencies()
                if deps_status.get('missing_dependencies'):
                    logger.warning(f"Browser initialization failed due to missing system dependencies")
                    logger.warning(f"Run the following command to install dependencies:")
                    logger.warning(f"  {deps_status.get('install_command', '')}")
            else:
                logger.warning(f"Failed to initialize browser: {e}")
            
            return False
    
    async def _setup_interceptors(self):
        """设置请求和响应拦截器"""
        self._js_content_set = set()
        self._intercepted_apis = []
        self._base_urls = set()

        async def handle_request(request):
            url = request.url
            resource_type = request.resource_type

            if resource_type == 'script' or url.endswith('.js') or '.js?' in url or '.chunk.js' in url:
                self.js_files.add(url)
                logger.debug(f"JS file requested: {url}")

            for pattern in self._api_url_patterns:
                if re.search(pattern, url):
                    self.api_endpoints.add(url)

            self.collected_resources.append(BrowserResource(
                url=url,
                resource_type=resource_type,
                content=""
            ))
        
        async def handle_response(response):
            """拦截 JS 响应并捕获正文"""
            url = response.url

            is_js_url = (
                url.endswith('.js') or
                '.js?' in url or
                '.chunk.js' in url or
                url.endswith('.jsx')
            )

            if not is_js_url:
                return

            content_hash = str(hash(url))

            if content_hash in self._js_content_set:
                return

            self._js_content_set.add(content_hash)

            try:
                body = await response.body()
                if body and len(body) > 0:
                    js_content = body.decode('utf-8', errors='ignore')

                    self.js_contents.append({
                        'url': url,
                        'content': js_content,
                        'size': len(body),
                        'content_hash': content_hash
                    })

                    logger.debug(f"JS content captured: {url} ({len(body)} bytes)")
            except Exception as e:
                logger.warning(f"Failed to capture JS content {url}: {e}")

        if self.page:
            self.page.on("request", handle_request)
            self.page.on("response", handle_response)
    
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
            
            // 1. Vue Router
            if (window.Vue && window.VueRouter) {
                try {
                    const router = window.VueRouter;
                    router.getRoutes().forEach(r => routes.add(r.path));
                } catch(e) {}
            }
            
            // 2. React Router
            if (window.React && window.ReactRouter) {
                try {
                    const routes = window.ReactRouter.routes || [];
                    routes.forEach(r => routes.add(r.path));
                } catch(e) {}
            }
            
            // 3. Angular Router
            if (window.ng && window.ng.probe) {
                try {
                    const el = window.ng.probe(document.querySelector('app-root'));
                    const router = el.injector.get(window.ng.router.Router);
                    router.config.forEach(r => routes.add(r.path));
                } catch(e) {}
            }
            
            // 4. SvelteKit
            if (window.__sveltekit__) {
                try {
                    const manifest = window.__sveltekit__.manifest;
                    if (manifest && manifest.routes) {
                        manifest.routes.forEach(r => routes.add(r.path));
                    }
                } catch(e) {}
            }
            if (window.$app && window.$app.stores) {
                try {
                    const stores = window.$app.stores;
                    if (stores.page) {
                        stores.page.subscribe(p => routes.add(p.url.pathname));
                    }
                } catch(e) {}
            }
            
            // 5. Next.js
            if (window.__NEXT_DATA__) {
                try {
                    const nextData = window.__NEXT_DATA__;
                    if (nextData.routes) {
                        Object.keys(nextData.routes).forEach(r => routes.add(r));
                    }
                    if (nextData.buildId) {
                        routes.add('/_next/' + nextData.buildId);
                    }
                } catch(e) {}
            }
            if (window.next && window.next.router) {
                try {
                    const router = window.next.router;
                    if (router.routes) {
                        router.routes.forEach(r => routes.add(r));
                    }
                } catch(e) {}
            }
            
            // 6. Nuxt.js
            if (window.__NUXT__) {
                try {
                    const nuxtData = window.__NUXT__;
                    if (nuxtData.router && nuxtData.router.routes) {
                        nuxtData.router.routes.forEach(r => routes.add(r.path));
                    }
                } catch(e) {}
            }
            if (window.$nuxt) {
                try {
                    const nuxt = window.$nuxt;
                    if (nuxt.$router) {
                        const router = nuxt.$router;
                        if (router.options && router.options.routes) {
                            router.options.routes.forEach(r => routes.add(r.path));
                        }
                    }
                } catch(e) {}
            }
            
            // 7. Remix
            if (window.__remixContext) {
                try {
                    const context = window.__remixContext;
                    if (context.routeModules) {
                        Object.keys(context.routeModules).forEach(key => {
                            if (key !== 'routes' && key !== 'url') {
                                routes.add('/' + key.replace(/^\//, ''));
                            }
                        });
                    }
                } catch(e) {}
            }
            
            // 8. SolidStart
            if (window.__solidstart) {
                try {
                    const solidRoutes = window.__solidstart.routes;
                    if (solidRoutes) {
                        solidRoutes.forEach(r => routes.add(r.path));
                    }
                } catch(e) {}
            }
            if (window.$solid) {
                try {
                    const router = window.$solid.router;
                    if (router && router.routes) {
                        router.routes.forEach(r => routes.add(r.path));
                    }
                } catch(e) {}
            }
            
            // 9. History API and links
            if (window.history && window.history.pushState) {
                const links = document.querySelectorAll('a[href]');
                links.forEach(a => {
                    const href = a.getAttribute('href');
                    if (href && !href.startsWith('http') && !href.startsWith('//') && href !== '#') {
                        routes.add(href);
                    }
                });
            }
            
            // 10. Svelte (standalone)
            if (window.svelte) {
                try {
                    const svelteRoutes = window.svelte.routes;
                    if (svelteRoutes) {
                        svelteRoutes.forEach(r => routes.add(r));
                    }
                } catch(e) {}
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
        except Exception as e:
            logger.warning(f"点击元素异常: {e}")
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
        except Exception as e:
            logger.warning(f"页面滚动异常: {e}")
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
            'js_contents': list(self.js_contents),
            'api_endpoints': list(self.api_endpoints),
            'routes': await self.discover_spa_routes(),
            'screenshots': self.screenshots
        }
    
    async def sync_storage_to_headers(self) -> Dict[str, str]:
        """
        同步 localStorage/sessionStorage 到请求头
        
        Returns:
            Dict[str, str]: 可用于请求头的键值对
        """
        headers = {}
        
        if not self.page:
            return headers
        
        js_code = """
        () => {
            const storage = {};
            
            // localStorage
            for (let i = 0; i < localStorage.length; i++) {
                const key = localStorage.key(i);
                storage['ls_' + key] = localStorage.getItem(key);
            }
            
            // sessionStorage
            for (let i = 0; i < sessionStorage.length; i++) {
                const key = sessionStorage.key(i);
                storage['ss_' + key] = sessionStorage.getItem(key);
            }
            
            // Cookies
            const cookies = document.cookie;
            if (cookies) {
                storage['cookies'] = cookies;
            }
            
            return storage;
        }
        """
        
        try:
            result = await self.execute_js(js_code)
            if result:
                headers.update(result)
        except Exception as e:
            logger.warning(f"Storage sync failed: {e}")
        
        return headers
    
    async def get_auth_headers(self) -> Dict[str, str]:
        """
        获取认证相关的请求头
        
        Returns:
            Dict[str, str]: 认证头
        """
        auth_headers = {}
        
        storage = await self.sync_storage_to_headers()
        
        for key, value in storage.items():
            key_lower = key.lower()
            if any(x in key_lower for x in ['token', 'auth', 'bearer', 'jwt', 'session', 'cookie', 'apikey', 'api_key']):
                if key.startswith('ls_'):
                    auth_headers[f'X-Storage-{key[3:]}'] = value
                elif key.startswith('ss_'):
                    auth_headers[f'X-Session-{key[3:]}'] = value
                elif key == 'cookies':
                    auth_headers['Cookie'] = value
        
        return auth_headers
    
    async def close(self):
        """关闭浏览器"""
        try:
            if self.page:
                await self.page.close()
            if self.context:
                await self.context.close()
            if self.browser:
                await self.browser.close()
        except Exception as e:
            logger.warning(f"关闭浏览器异常: {e}")
            pass
    
    def get_js_urls(self) -> List[str]:
        """获取收集到的 JS 文件 URLs"""
        return list(self.js_files)

    def get_js_contents(self) -> List[Dict[str, Any]]:
        """获取捕获的 JS 文件内容"""
        return list(self.js_contents)

    def get_js_count(self) -> int:
        """获取捕获的 JS 文件数量"""
        return len(self.js_contents)
    
    async def cleanup(self) -> None:
        """清理资源"""
        await self.close()
    
    async def add_api_interceptor(self):
        """添加 API 拦截器 - 拦截 fetch/XHR 调用并提取 baseURL"""
        if not self.page:
            return
        
        interceptor_script = '''
        (() => {
            if (window.__apiInterceptorActive) return;
            window.__apiInterceptorActive = true;
            window.__interceptedAPIs = [];
            window.__discoveredBaseURLs = [];
            
            const originalFetch = window.fetch;
            window.fetch = async function(...args) {
                const url = typeof args[0] === 'string' ? args[0] : (args[0]?.url || '');
                const method = args[0]?.method || 'GET';
                
                if (url && (url.includes('/prod-api') || url.includes('/api/') || 
                            url.includes('/v1/') || url.includes('/v2/') || 
                            url.includes('/auth') || url.includes('/admin') ||
                            url.match(/\\/[a-z]+\\/[a-z]+/))) {
                    window.__interceptedAPIs.push({url: url, method: method, type: 'fetch', timestamp: Date.now()});
                    console.log('[API-FETCH]', method, url);
                }
                
                return originalFetch.apply(window, args);
            };
            
            const originalXHROpen = XMLHttpRequest.prototype.open;
            XMLHttpRequest.prototype.open = function(method, url, ...rest) {
                if (url && (url.includes('/prod-api') || url.includes('/api/') || 
                            url.includes('/v1/') || url.includes('/v2/') || 
                            url.includes('/auth') || url.includes('/admin') ||
                            url.match(/\\/[a-z]+\\/[a-z]+/))) {
                    window.__interceptedAPIs.push({url: url, method: method, type: 'xhr', timestamp: Date.now()});
                    console.log('[API-XHR]', method, url);
                }
                return originalXHROpen.call(this, method, url, ...rest);
            };
            
            if (window.axios) {
                const originalCreate = window.axios.create;
                if (typeof originalCreate === 'function') {
                    window.axios.create = function(...args) {
                        const instance = originalCreate.apply(window.axios, args);
                        if (args[0]?.baseURL) {
                            window.__discoveredBaseURLs.push(args[0].baseURL);
                            console.log('[BASE-URL]', args[0].baseURL);
                        }
                        return instance;
                    };
                }
            }
            
            if (window.Vue?.axios?.defaults) {
                const baseURL = window.Vue.axios.defaults.baseURL;
                if (baseURL) {
                    window.__discoveredBaseURLs.push(baseURL);
                    console.log('[BASE-URL-VUE]', baseURL);
                }
            }
            
            console.log('[API-INTERCEPTOR] Initialized');
        })();
        '''
        
        try:
            await self.page.add_init_script(interceptor_script)
            logger.info("API interceptor added")
        except Exception as e:
            logger.warning(f"Failed to add API interceptor: {e}")
    
    async def get_intercepted_apis(self) -> List[Dict]:
        """获取拦截到的 API 调用"""
        if not self.page:
            return []
        
        script = '''
        () => {
            return {
                apis: window.__interceptedAPIs || [],
                baseURLs: window.__discoveredBaseURLs || []
            };
        }
        '''
        
        try:
            result = await self.page.evaluate(script)
            if result:
                self._intercepted_apis.extend(result.get('apis', []))
                self._base_urls.update(result.get('baseURLs', []))
            return result.get('apis', [])
        except Exception as e:
            logger.warning(f"Failed to get intercepted APIs: {e}")
            return []
    
    def get_discovered_base_urls(self) -> Set[str]:
        """获取发现的 baseURL 前缀"""
        return self._base_urls.copy()
    
    def get_all_intercepted_apis(self) -> List[Dict]:
        """获取所有拦截到的 API 调用"""
        return self._intercepted_apis.copy()


async def create_browser_collector(config: Optional[Dict] = None) -> Optional[HeadlessBrowserCollector]:
    """创建无头浏览器采集器"""
    collector = HeadlessBrowserCollector(config)
    success = await collector.initialize(headless=True)
    if success:
        return collector
    return None
