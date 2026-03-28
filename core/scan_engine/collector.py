"""
ScanCollector Module
采集阶段实现 - 封装 JS 采集和 API 提取逻辑
"""

import asyncio
import re
import logging
from typing import Dict, List, Any, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)


class ScanCollector:
    """
    采集器封装类
    
    职责：
    1. JS 资源采集
    2. API 端点发现
    3. 路径探测
    4. 框架检测
    
    使用方式：
    ```python
    collector = ScanCollector(http_client, config)
    js_results = await collector.collect_js()
    api_results = await collector.extract_apis()
    ```
    """
    
    def __init__(self, http_client, config):
        self.http_client = http_client
        self.config = config
        self._collector_results = {}
        
    async def run_collectors(self) -> Dict[str, Any]:
        """运行采集阶段"""
        active_collectors = self.config.collectors or ['js', 'api']
        
        collector_results = {}
        
        if 'js' in active_collectors:
            collector_results['js'] = await self.collect_js()
        
        if 'api' in active_collectors:
            collector_results['api'] = await self.extract_apis()
        
        self._collector_results = collector_results
        return collector_results
    
    async def collect_js(self) -> Dict[str, Any]:
        """采集 JS 资源 + 框架检测 + 浏览器动态采集 + 内联 JS 解析"""
        from .utils.http_client import AsyncHttpClient
        from .collectors.inline_js_parser import InlineJSParser, ResponseBasedAPIDiscovery
        from .collectors.api_path_finder import ApiPathFinder, ApiPathCombiner
        
        js_urls = []
        alive_js = []
        js_content_all = ""
        browser_routes = []
        browser_api_endpoints = []
        
        target = self.config.target
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        try:
            response = await self.http_client.request(target, 'GET')
            content = response.content if hasattr(response, 'content') else ''
            
            if content:
                js_urls = self._extract_js_urls_from_html(content, base_url)
                js_content_all += content
                
                framework = self._detect_framework(content)
                logger.info(f"Framework detected: {framework}")
        
        except Exception as e:
            logger.debug(f"Initial fetch failed: {e}")
        
        for js_url in js_urls[:20]:
            try:
                js_content = await self._fetch_js_content(js_url)
                if js_content:
                    alive_js.append({
                        'url': js_url,
                        'content': js_content
                    })
                    js_content_all += js_content
            except Exception:
                pass
        
        inline_apis = []
        if js_content_all:
            inline_apis = self._extract_apis_from_content(js_content_all)
        
        if self.config.chrome:
            browser_results = await self._collect_with_browser(target)
            browser_routes = browser_results.get('routes', [])
            browser_api_endpoints = browser_results.get('apis', [])
        
        return {
            'js_urls': js_urls,
            'alive_js': alive_js,
            'browser_routes': browser_routes,
            'browser_api_endpoints': browser_api_endpoints,
            'inline_apis': inline_apis,
            'js_content_all': js_content_all
        }
    
    async def extract_apis(self) -> Dict[str, Any]:
        """提取 API 端点"""
        from .collectors.api_collector import APIAggregator
        
        aggregator = APIAggregator(self.http_client)
        
        target = self.config.target
        await aggregator.add_target(target)
        
        if hasattr(self, '_collector_results') and 'js' in self._collector_results:
            js_result = self._collector_results['js']
            if 'alive_js' in js_result:
                for js_info in js_result['alive_js']:
                    await aggregator.add_js_content(js_info.get('content', ''), js_info.get('url', ''))
        
        endpoints = await aggregator.discover_apis()
        
        return {
            'endpoints': endpoints,
            'total': len(endpoints)
        }
    
    def _extract_js_urls_from_html(self, content: str, base_url: str) -> List[str]:
        """从 HTML 中提取 JS URL"""
        js_patterns = [
            r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']',
            r'["\']/([a-zA-Z0-9_-]+\.js[^"\']*)["\']',
            r'import\s+["\']([^"\']+\.js[^"\']*)["\']',
            r'require\s*\(["\']"([^"\']+\.js[^"\']*)["\']"\)',
        ]
        
        js_urls = []
        seen = set()
        
        for pattern in js_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                url = match if match.startswith('http') else urljoin(base_url, match)
                if url not in seen:
                    seen.add(url)
                    js_urls.append(url)
        
        return js_urls
    
    def _detect_framework(self, content: str) -> Optional[str]:
        """检测前端框架"""
        frameworks = {
            'Vue': ['vue', 'vue-router', 'vuex', '@vue'],
            'React': ['react', 'react-dom', 'redux', 'react-router'],
            'Angular': ['angular', '@angular'],
            'jQuery': ['jquery'],
            'Bootstrap': ['bootstrap'],
            'Element UI': ['element-ui', 'element-ui/'],
            'Ant Design': ['antd', 'ant-design'],
            'Layui': ['layui'],
        }
        
        content_lower = content.lower()
        for framework, keywords in frameworks.items():
            for keyword in keywords:
                if keyword in content_lower:
                    return framework
        
        return None
    
    async def _fetch_js_content(self, url: str) -> Optional[str]:
        """获取 JS 内容"""
        try:
            response = await self.http_client.request(url, 'GET')
            if hasattr(response, 'content'):
                return response.content
        except Exception:
            pass
        return None
    
    async def _collect_with_browser(self, target: str) -> Dict[str, Any]:
        """使用浏览器采集"""
        from .collectors.headless_browser import HeadlessBrowserCollector
        
        collector = HeadlessBrowserCollector()
        try:
            await collector.initialize(headless=True)
            routes, apis = await collector.crawl(target)
            return {'routes': routes, 'apis': apis}
        except Exception as e:
            logger.debug(f"Browser collection failed: {e}")
            return {'routes': [], 'apis': []}
        finally:
            await collector.close()
    
    def _extract_apis_from_content(self, content: str) -> List[Dict[str, Any]]:
        """从内容中提取 API 调用"""
        api_patterns = [
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](?:https?://)?[a-zA-Z0-9.-]+(/api/[a-zA-Z0-9_/-]+)["\']',
            r'axios\.(?:get|post|put|delete)\(["\']([^"\']+)["\']',
            r'fetch\(["\']([^"\']+)["\']',
        ]
        
        apis = []
        seen = set()
        
        for pattern in api_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                if match and match not in seen:
                    seen.add(match)
                    apis.append({
                        'path': match,
                        'method': 'GET',
                        'source': 'content'
                    })
        
        return apis
