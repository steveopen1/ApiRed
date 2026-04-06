"""
JS运行时拦截与动态接口发现模块
解决JS混淆情况下的API发现问题

核心思路：
1. 不试图"解混淆"，而是让混淆代码在浏览器中执行
2. Hook所有XMLHttpRequest和Fetch，捕获运行时API调用
3. 模拟用户交互触发隐藏的API
4. 通过MutationObserver检测动态添加的API引用
"""

import asyncio
import logging
from typing import Dict, List, Set, Optional, Any, Callable
from dataclasses import dataclass, field
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


@dataclass
class InterceptedAPI:
    """拦截到的API调用"""
    url: str
    method: str
    call_type: str  # 'fetch', 'xhr', 'dynamic'
    source_element: Optional[str] = None
    page_url: str = ""
    timestamp: float = 0
    headers: Dict[str, str] = field(default_factory=dict)
    post_data: Optional[str] = None


@dataclass
class InteractionTarget:
    """交互目标元素"""
    selector: str
    element_type: str
    trigger_type: str = "click"  # 'click', 'input', 'scroll', 'hover'
    attributes: Dict[str, str] = field(default_factory=dict)


class JSRuntimeInterceptor:
    """
    JS运行时API拦截器
    
    Hook所有网络请求，不管JS如何混淆，只要执行就会调用
    """

    INTERCEPTOR_SCRIPT = '''
    (() => {
        if (window.__jsRuntimeInterceptor) return;
        window.__jsRuntimeInterceptor = true;
        window.__runtimeAPIs = [];
        window.__baseURLs = new Set();
        window.__apiConstructionLog = [];
        
        // 通用API模式检测（宽松匹配）
        const API_PATTERNS = [
            /\\/api\\//i, /\\/v\\d+/i, /\\/rest\\//i, 
            /\\/graphql/i, /\\/rpc\\//i, /gateway/i,
            /\\/admin\\//i, /\\/user\\//i, /\\/order\\//i,
            /prod-api/i, /test-api/i, /auth/i,
            /\\/[a-z][a-z0-9]{2,20}\\/[a-z][a-z0-9]{2,20}/i
        ];
        
        function isAPIRelated(url) {
            if (!url || typeof url !== 'string') return false;
            // 宽松检测：包含常见API关键词
            const lower = url.toLowerCase();
            return API_PATTERNS.some(p => p.test(lower)) ||
                   lower.includes('.json') ||
                   lower.includes('/data') ||
                   lower.includes('/config');
        }
        
        // 1. Hook Fetch
        const OriginalFetch = window.fetch;
        window.fetch = async function(input, init) {
            const url = typeof input === 'string' ? input : (input?.url || '');
            const method = (init?.method || (input?.method)) || 'GET';
            
            try {
                const response = await OriginalFetch.apply(this, arguments);
                
                if (isAPIRelated(url)) {
                    window.__runtimeAPIs.push({
                        url: url,
                        method: method.toUpperCase(),
                        type: 'fetch',
                        status: response.status,
                        timestamp: Date.now()
                    });
                    console.log('[RUNTIME-FETCH]', method, url);
                }
                
                return response;
            } catch (e) {
                throw e;
            }
        };
        
        // 2. Hook XMLHttpRequest
        const OriginalXHR = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function(method, url, ...rest) {
            if (isAPIRelated(url)) {
                this.__interceptedURL = url;
                this.__interceptedMethod = method;
                window.__runtimeAPIs.push({
                    url: url,
                    method: method.toUpperCase(),
                    type: 'xhr',
                    timestamp: Date.now()
                });
                console.log('[RUNTIME-XHR]', method, url);
            }
            return OriginalXHR.call(this, method, url, ...rest);
        };
        
        const OriginalXRHSend = XMLHttpRequest.prototype.send;
        XMLHttpRequest.prototype.send = function(data) {
            if (this.__interceptedURL) {
                window.__runtimeAPIs.push({
                    url: this.__interceptedURL,
                    method: this.__interceptedMethod || 'GET',
                    type: 'xhr-send',
                    postData: data,
                    timestamp: Date.now()
                });
            }
            return OriginalXRHSend.apply(this, arguments);
        };
        
        // 3. Hook axios
        if (window.axios) {
            const originalAxios = window.axios.request.bind(window.axios);
            window.axios.request = function(config) {
                const url = config?.url || '';
                const method = config?.method || 'GET';
                
                if (isAPIRelated(url)) {
                    window.__runtimeAPIs.push({
                        url: url,
                        method: method.toUpperCase(),
                        type: 'axios',
                        timestamp: Date.now()
                    });
                    console.log('[RUNTIME-AXIOS]', method, url);
                }
                
                return originalAxios(config);
            };
        }
        
        // 4. Hook jQuery.ajax
        if (window.jQuery) {
            const originalAjax = window.jQuery.ajax.bind(window.jQuery);
            window.jQuery.ajax = function(url, settings) {
                const actualURL = typeof url === 'object' ? (url.url || '') : url;
                const method = (typeof url === 'object' ? url.method : (settings?.method)) || 'GET';
                
                if (isAPIRelated(actualURL)) {
                    window.__runtimeAPIs.push({
                        url: actualURL,
                        method: method.toUpperCase(),
                        type: 'jquery',
                        timestamp: Date.now()
                    });
                    console.log('[RUNTIME-JQUERY]', method, actualURL);
                }
                
                return originalAjax(url, settings);
            };
        }
        
        // 5. 提取baseURL配置
        function extractBaseURLs() {
            // axios
            if (window.axios?.defaults?.baseURL) {
                window.__baseURLs.add(window.axios.defaults.baseURL);
            }
            // vue-resource
            if (window.Vue?.http?.defaults?.baseURL) {
                window.__baseURLs.add(window.Vue.http.defaults.baseURL);
            }
            // fetch defaults
            if (window.fetch?.defaults?.baseURL) {
                window.__baseURLs.add(window.fetch.defaults.baseURL);
            }
        }
        extractBaseURLs();
        
        // 6. 监控动态代码执行
        const originalEval = window.eval;
        window.eval = function(code) {
            if (code && typeof code === 'string') {
                window.__apiConstructionLog.push({
                    type: 'eval',
                    codeLength: code.length,
                    timestamp: Date.now()
                });
            }
            return originalEval.apply(this, arguments);
        };
        
        // 7. Function构造函数
        const originalFunction = window.Function;
        window.Function = function(...args) {
            const lastArg = args[args.length - 1];
            if (lastArg && typeof lastArg === 'string') {
                window.__apiConstructionLog.push({
                    type: 'Function',
                    codeLength: lastArg.length,
                    timestamp: Date.now()
                });
            }
            return originalFunction.apply(this, arguments);
        };
        
        console.log('[JS-RUNTIME-INTERCEPTOR] Initialized');
    })();
    '''

    def __init__(self):
        self.intercepted_apis: List[InterceptedAPI] = []
        self.base_urls: Set[str] = set()
        self.construction_log: List[Dict] = []
        self._page = None

    async def attach_to_page(self, page):
        """附加到Playwright页面"""
        self._page = page
        try:
            await page.add_init_script(self.INTERCEPTOR_SCRIPT)
            logger.info("JS运行时拦截器已附加")
            return True
        except Exception as e:
            logger.warning(f"附加JS运行时拦截器失败: {e}")
            return False

    async def get_intercepted_apis(self) -> List[InterceptedAPI]:
        """获取拦截到的API"""
        if not self._page:
            return []

        script = '''
        () => {
            return {
                apis: window.__runtimeAPIs || [],
                baseURLs: Array.from(window.__baseURLs || []),
                constructionLog: window.__apiConstructionLog || []
            };
        }
        '''

        try:
            result = await self._page.evaluate(script)
            if result:
                apis = result.get('apis', [])
                self.base_urls.update(result.get('baseURLs', []))
                self.construction_log.extend(result.get('constructionLog', []))

                for api in apis:
                    intercepted = InterceptedAPI(
                        url=api.get('url', ''),
                        method=api.get('method', 'GET'),
                        call_type=api.get('type', 'unknown'),
                        timestamp=api.get('timestamp', 0),
                        post_data=api.get('postData')
                    )
                    self.intercepted_apis.append(intercepted)

                return self.intercepted_apis
        except Exception as e:
            logger.warning(f"获取拦截API失败: {e}")

        return []

    def get_base_urls(self) -> Set[str]:
        """获取发现的baseURL"""
        return self.base_urls.copy()

    def get_api_urls(self) -> List[str]:
        """获取所有拦截到的API URL"""
        return list(set(api.url for api in self.intercepted_apis if api.url))


class PageInteractionTrigger:
    """
    页面交互触发器 - 自动化触发隐藏API
    
    自动执行：
    1. 点击所有可点击元素
    2. 滚动页面触发懒加载
    3. 输入框输入触发搜索API
    4. 悬停触发hover事件
    """

    def __init__(self):
        self._page = None
        self._clicked_selectors: Set[str] = set()
        self._input_values_tried: Dict[str, List[str]] = {}

    async def attach_to_page(self, page):
        """附加到页面"""
        self._page = page

    async def trigger_all_interactions(self, interceptor: JSRuntimeInterceptor) -> List[str]:
        """
        执行所有交互并返回新发现的API
        
        Returns:
            新发现的API URL列表
        """
        if not self._page:
            return []

        initial_apis = set(interceptor.get_api_urls())

        await self._trigger_clicks(interceptor)
        await self._trigger_scrolls(interceptor)
        await self._trigger_inputs(interceptor)
        await self._trigger_hover(interceptor)

        final_apis = set(interceptor.get_api_urls())
        return list(final_apis - initial_apis)

    async def _trigger_clicks(self, interceptor: JSRuntimeInterceptor):
        """触发所有点击"""
        if not self._page:
            return

        click_script = '''
        () => {
            const clickables = [];
            const selectors = [
                'a[href]', 'button', 'input[type="submit"]', 
                'input[type="button"]', '[onclick]',
                '[role="button"]', '.btn', '.button',
                '[class*="btn"]', '[class*="button"]',
                'li', '[tabindex="0"]', 'summary'
            ];
            
            selectors.forEach(sel => {
                document.querySelectorAll(sel).forEach(el => {
                    if (el.offsetParent !== null && el.style.display !== 'none') {
                        const rect = el.getBoundingClientRect();
                        if (rect.width > 0 && rect.height > 0) {
                            clickables.push({
                                selector: sel,
                                text: el.innerText?.substring(0, 50) || '',
                                attributes: {
                                    id: el.id || '',
                                    class: el.className || '',
                                    href: el.href || ''
                                }
                            });
                        }
                    }
                });
            });
            
            return clickables;
        }
        '''

        try:
            clickables = await self._page.evaluate(click_script)
            logger.info(f"发现 {len(clickables)} 个可点击元素")

            for item in clickables[:30]:
                selector = item['selector']
                if selector in self._clicked_selectors:
                    continue

                try:
                    self._clicked_selectors.add(selector)
                    await self._page.click(selector, timeout=1000)
                    await self._page.wait_for_timeout(300)

                    await interceptor.get_intercepted_apis()

                    if selector == 'a[href]':
                        break

                except Exception as e:
                    logger.debug(f"点击 {selector} 失败: {e}")

        except Exception as e:
            logger.warning(f"点击触发失败: {e}")

    async def _trigger_scrolls(self, interceptor: JSRuntimeInterceptor):
        """触发滚动"""
        if not self._page:
            return

        scroll_script = '''
        () => {
            return new Promise((resolve) => {
                let scrollCount = 0;
                const maxScrolls = 15;
                const distance = 300;
                
                const timer = setInterval(() => {
                    window.scrollBy(0, distance);
                    scrollCount++;
                    
                    if (scrollCount >= maxScrolls) {
                        window.scrollTo(0, 0);
                        clearInterval(timer);
                        resolve();
                    }
                }, 200);
            });
        }
        '''

        try:
            await self._page.evaluate(scroll_script)
            await self._page.wait_for_timeout(500)
            await interceptor.get_intercepted_apis()
        except Exception as e:
            logger.warning(f"滚动触发失败: {e}")

    async def _trigger_inputs(self, interceptor: JSRuntimeInterceptor):
        """触发输入框"""
        if not self._page:
            return

        input_script = '''
        () => {
            const inputs = [];
            document.querySelectorAll('input[type="text"], input[type="search"], input:not([type])').forEach(el => {
                if (el.offsetParent !== null && el.style.display !== 'none' && !el.disabled) {
                    const rect = el.getBoundingClientRect();
                    if (rect.width > 20) {
                        inputs.push({
                            selector: 'input[id="' + el.id + '"]' || 'input[placeholder="' + el.placeholder + '"]',
                            id: el.id || '',
                            name: el.name || '',
                            placeholder: el.placeholder || ''
                        });
                    }
                }
            });
            return inputs;
        }
        '''

        try:
            inputs = await self._page.evaluate(input_script)
            logger.info(f"发现 {len(inputs)} 个输入框")

            test_values = ['test', 'admin', '123', 'a']

            for inp in inputs[:10]:
                selector = inp.get('selector') or f"input[name='{inp.get('name')}']"
                if selector in self._input_values_tried:
                    continue

                try:
                    await self._page.click(selector, timeout=1000)
                    await self._page.type(selector, 'test', delay=50)
                    await self._page.wait_for_timeout(300)

                    self._input_values_tried[selector] = test_values
                    await interceptor.get_intercepted_apis()

                except Exception as e:
                    logger.debug(f"输入触发失败 {selector}: {e}")

        except Exception as e:
            logger.warning(f"输入触发失败: {e}")

    async def _trigger_hover(self, interceptor: JSRuntimeInterceptor):
        """触发悬停"""
        if not self._page:
            return

        hover_script = '''
        () => {
            const hoverables = document.querySelectorAll('a, button, [role="button"], .dropdown-toggle, [class*="menu"]');
            return Array.from(hoverables).slice(0, 20).map(el => {
                const rect = el.getBoundingClientRect();
                return {
                    x: rect.x + rect.width / 2,
                    y: rect.y + rect.height / 2
                };
            });
        }
        '''

        try:
            points = await self._page.evaluate(hover_script)

            for point in points[:10]:
                try:
                    await self._page.mouse.move(point['x'], point['y'])
                    await self._page.wait_for_timeout(200)
                    await interceptor.get_intercepted_apis()
                except Exception:
                    pass

        except Exception as e:
            logger.warning(f"悬停触发失败: {e}")


class MutationObserverWatcher:
    """
    MutationObserver监控器
    
    监控DOM变化，检测动态添加的API相关代码
    """

    WATCHER_SCRIPT = '''
    (() => {
        if (window.__mutationWatcher) return;
        window.__mutationWatcher = true;
        window.__domChanges = [];
        
        const observer = new MutationObserver((mutations) => {
            mutations.forEach(mutation => {
                if (mutation.type === 'childList') {
                    mutation.addedNodes.forEach(node => {
                        if (node.nodeType === 1) {
                            // 检测script标签
                            if (node.tagName === 'SCRIPT') {
                                window.__domChanges.push({
                                    type: 'script_added',
                                    src: node.src || '',
                                    contentLength: node.textContent?.length || 0
                                });
                            }
                            
                            // 检测包含API关键词的元素
                            const html = node.outerHTML || '';
                            if (/api|endpoint|url|fetch|ajax|axios/i.test(html)) {
                                window.__domChanges.push({
                                    type: 'api_element',
                                    html: html.substring(0, 500)
                                });
                            }
                        }
                    });
                }
            });
        });
        
        observer.observe(document.body || document.documentElement, {
            childList: true,
            subtree: true
        });
        
        console.log('[MUTATION-WATCHER] Started');
    })();
    '''

    def __init__(self):
        self._page = None
        self.dom_changes: List[Dict] = []

    async def attach_to_page(self, page):
        """附加到页面"""
        self._page = page
        try:
            await page.add_init_script(self.WATCHER_SCRIPT)
            logger.info("MutationObserver已附加")
            return True
        except Exception as e:
            logger.warning(f"附加MutationObserver失败: {e}")
            return False

    async def get_changes(self) -> List[Dict]:
        """获取DOM变化"""
        if not self._page:
            return []

        script = '''
        () => {
            return window.__domChanges || [];
        }
        '''

        try:
            changes = await self._page.evaluate(script)
            if changes:
                self.dom_changes.extend(changes)
                await self._page.evaluate('window.__domChanges = []')
        except Exception as e:
            logger.warning(f"获取DOM变化失败: {e}")

        return self.dom_changes


class EnhancedRuntimeCollector:
    """
    增强型运行时采集器
    
    整合所有运行时采集能力：
    1. JSRuntimeInterceptor - 拦截所有网络请求
    2. PageInteractionTrigger - 自动化交互触发
    3. MutationObserverWatcher - DOM变化监控
    """

    def __init__(self):
        self.interceptor = JSRuntimeInterceptor()
        self.trigger = PageInteractionTrigger()
        self.watcher = MutationObserverWatcher()
        self._page = None
        self._all_apis: List[str] = []

    async def attach(self, page):
        """附加到页面"""
        self._page = page
        await self.interceptor.attach_to_page(page)
        await self.trigger.attach_to_page(page)
        await self.watcher.attach_to_page(page)

    async def collect(self) -> Dict[str, Any]:
        """
        执行完整采集流程
        
        Returns:
            采集结果
        """
        if not self._page:
            return {'apis': [], 'base_urls': set()}

        initial_count = len(self.interceptor.get_api_urls())

        await self._page.wait_for_load_state('networkidle', timeout=10000)
        await self.interceptor.get_intercepted_apis()

        new_apis = await self.trigger.trigger_all_interactions(self.interceptor)

        await self.watcher.get_changes()

        all_apis = self.interceptor.get_api_urls()
        self._all_apis = all_apis

        return {
            'apis': all_apis,
            'new_apis': new_apis,
            'base_urls': self.interceptor.get_base_urls(),
            'total_count': len(all_apis),
            'initial_count': initial_count
        }

    def get_all_apis(self) -> List[str]:
        """获取所有发现的API"""
        return self._all_apis


async def create_runtime_collector(page) -> Optional[EnhancedRuntimeCollector]:
    """创建运行时采集器"""
    collector = EnhancedRuntimeCollector()
    await collector.attach(page)
    return collector
