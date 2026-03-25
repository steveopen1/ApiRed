"""
Discover Agent Module
发现代理 - 负责 API 端点发现
"""

import asyncio
from typing import Dict, List, Any, Optional, Set
from urllib.parse import urlparse
import logging

from .orchestrator import AgentInterface, ScanContext
from ..knowledge_base import KnowledgeBase, APIEndpoint
from ..collectors.api_collector import APIRouter, BaseURLAnalyzer, COMMON_API_PATHS
from ..collectors.js_collector import JSParser, WebpackAnalyzer
from ..collectors.browser_collector import HeadlessBrowserCollector
from ..framework import FrameworkDetector
from ..analyzers.response_cluster import ResponseCluster
from ..utils.api_spec_parser import APISpecParser

logger = logging.getLogger(__name__)


class DiscoverAgent(AgentInterface):
    """
    发现代理
    负责从多个来源发现 API 端点
    """
    
    def __init__(self):
        super().__init__("discover")
        self.discovered_endpoints: List[APIEndpoint] = []
        self.js_urls: Set[str] = set()
        self.base_urls: Set[str] = set()
        self._browser = None
        self._framework_detector = None
        self._response_cluster = None
        self._api_spec_parser = None
        self._http_client = None
    
    async def initialize(self, context: ScanContext) -> None:
        """初始化发现代理"""
        await super().initialize(context)
        self._browser = HeadlessBrowserCollector(context.target)
        self._framework_detector = FrameworkDetector()
        self._response_cluster = ResponseCluster()
    
    async def execute(self, context: ScanContext) -> List[APIEndpoint]:
        """
        执行发现任务
        
        发现流程:
        1. Headless Browser 采集 JS URL
        2. JS 静态分析提取 API 路径
        3. FrameworkDetector 框架识别
        4. Swagger/OpenAPI 解析
        5. Webpack 打包分析
        6. Base URL 发现和组合
        7. ResponseCluster 响应聚类
        """
        target = context.target
        cookies = context.cookies
        
        logger.info(f"DiscoverAgent: Starting discovery for {target}")
        
        try:
            all_endpoints = []
            
            js_endpoints = await self._discover_from_js(target, cookies)
            all_endpoints.extend(js_endpoints)
            logger.info(f"DiscoverAgent: Found {len(js_endpoints)} endpoints from JS")
            
            if self._framework_detector:
                framework_info = await self._detect_framework(target, js_endpoints)
                if framework_info:
                    logger.info(f"DiscoverAgent: Detected framework: {framework_info}")
            
            swagger_endpoints = await self._discover_from_swagger(target)
            all_endpoints.extend(swagger_endpoints)
            logger.info(f"DiscoverAgent: Found {len(swagger_endpoints)} endpoints from Swagger")
            
            base_endpoints = await self._discover_with_base_urls(target, js_endpoints)
            all_endpoints.extend(base_endpoints)
            logger.info(f"DiscoverAgent: Found {len(base_endpoints)} endpoints from Base URLs")
            
            fuzzed_endpoints = await self._discover_with_fuzz(target, js_endpoints)
            all_endpoints.extend(fuzzed_endpoints)
            logger.info(f"DiscoverAgent: Found {len(fuzzed_endpoints)} endpoints from Fuzz")
            
            unique_endpoints = self._deduplicate_endpoints(all_endpoints)
            
            for endpoint in unique_endpoints:
                self.knowledge_base.add_endpoint(endpoint)
            
            self.discovered_endpoints = unique_endpoints
            return unique_endpoints
            
        except Exception as e:
            logger.error(f"DiscoverAgent error: {e}")
            return []
    
    async def _discover_from_js(self, target: str, cookies: str) -> List[APIEndpoint]:
        """从 JS 发现 API"""
        endpoints = []
        
        try:
            if self._browser:
                js_urls = self._browser.get_js_urls()
                self.js_urls.update(js_urls)
            
            parser = JSParser()
            
            for js_url in list(self.js_urls)[:50]:
                try:
                    js_content = await self._fetch_js(js_url, cookies)
                    if js_content:
                        api_results = parser.parse(js_content)
                        
                        for result in api_results:
                            endpoint = APIEndpoint(
                                path=result.path,
                                method=result.method,
                                source=f"js:{js_url[:50]}",
                                tags=['js-discovered']
                            )
                            endpoints.append(endpoint)
                            
                            webpack_paths = WebpackAnalyzer.extract_webpack_chunk_paths(js_content)
                            for wpath in webpack_paths:
                                ep = APIEndpoint(
                                    path=wpath,
                                    method='GET',
                                    source=f"webpack:{js_url[:50]}",
                                    tags=['webpack']
                                )
                                endpoints.append(ep)
                                
                except Exception as e:
                    logger.debug(f"JS parse error for {js_url}: {e}")
                    continue
                    
        except Exception as e:
            logger.error(f"JS discovery error: {e}")
        
        return endpoints
    
    async def _discover_from_swagger(self, target: str) -> List[APIEndpoint]:
        """从 Swagger/OpenAPI 发现 (使用 APISpecParser)"""
        endpoints = []
        
        try:
            from ..utils.http_client import AsyncHttpClient
            http_client = AsyncHttpClient()
            parser = APISpecParser(http_client)
            
            spec_result = await parser.discover_and_parse(target)
            
            if spec_result:
                for api_endpoint in spec_result.endpoints:
                    endpoint = APIEndpoint(
                        path=api_endpoint.path,
                        method=api_endpoint.method,
                        source=f"{spec_result.spec_type}:{spec_result.base_url}",
                        tags=[spec_result.spec_type, 'api-spec']
                    )
                    endpoints.append(endpoint)
                
                logger.info(f"DiscoverAgent: Found {len(endpoints)} endpoints from API spec ({spec_result.spec_type})")
                
                for vuln in spec_result.vulnerabilities:
                    logger.info(f"DiscoverAgent: Spec vulnerability: {vuln.get('type')} - {vuln.get('description', '')[:100]}")
            
        except Exception as e:
            logger.debug(f"APISpecParser failed, falling back to old method: {e}")
            
            swagger_urls = APIRouter.find_swagger_endpoints(target)
            
            for swagger_url in swagger_urls:
                try:
                    import aiohttp
                    async with aiohttp.ClientSession() as session:
                        async with session.get(swagger_url, timeout=5) as resp:
                            if resp.status == 200:
                                content = await resp.text()
                                results = APIRouter.extract_from_swagger(content)
                                
                                for result in results:
                                    endpoint = APIEndpoint(
                                        path=result.path,
                                        method=result.method,
                                        source=f"swagger:{swagger_url}",
                                        tags=['swagger', 'openapi']
                                    )
                                    endpoints.append(endpoint)
                                
                except Exception:
                    continue
        
        return endpoints
    
    async def _discover_with_base_urls(
        self, 
        target: str, 
        existing_endpoints: List[APIEndpoint]
    ) -> List[APIEndpoint]:
        """基于 Base URL 组合发现更多端点"""
        endpoints = []
        
        path_with_api = set()
        path_with_no_api = set()
        
        for ep in existing_endpoints:
            path = ep.path.lower()
            if '/api' in path or '/v1' in path or '/v2' in path:
                path_parts = path.split('/')
                for i, part in enumerate(path_parts):
                    if part in ['api', 'v1', 'v2', 'v3']:
                        base_path = '/'.join(path_parts[:i])
                        if base_path:
                            self.base_urls.add(base_path)
                        path_with_api.add(path)
            else:
                path_with_no_api.add(path)
        
        if not path_with_api:
            path_with_api.add('/api')
        
        parsed = urlparse(target)
        base_domain = f"{parsed.scheme}://{parsed.netloc}"
        
        for base in self.base_urls:
            for api_path in path_with_api:
                for no_api_path in path_with_no_api:
                    full_url = f"{base_domain}{base}{api_path}{no_api_path}"
                    endpoint = APIEndpoint(
                        path=f"{base}{api_path}{no_api_path}",
                        method='GET',
                        source='base-combine',
                        full_url=full_url,
                        tags=['base-combined']
                    )
                    endpoints.append(endpoint)
        
        return endpoints
    
    async def _discover_with_fuzz(
        self, 
        target: str, 
        existing_endpoints: List[APIEndpoint]
    ) -> List[APIEndpoint]:
        """使用 Fuzz 发现更多端点"""
        endpoints = []
        
        path_with_api = set()
        
        for ep in existing_endpoints:
            if '/api' in ep.path.lower():
                path_with_api.add(ep.path)
        
        if not path_with_api:
            path_with_api.add('/api')
        
        parsed = urlparse(target)
        base_domain = f"{parsed.scheme}://{parsed.netloc}"
        
        for api_path in path_with_api:
            for common_path in COMMON_API_PATHS[:50]:
                full_url = f"{base_domain}{api_path}/{common_path}"
                endpoint = APIEndpoint(
                    path=f"{api_path}/{common_path}",
                    method='GET',
                    source='fuzz-common',
                    full_url=full_url,
                    tags=['fuzz']
                )
                endpoints.append(endpoint)
        
        return endpoints
    
    async def _detect_framework(
        self,
        target: str,
        endpoints: List[APIEndpoint]
    ) -> Optional[str]:
        """使用 FrameworkDetector 检测框架"""
        if not self._framework_detector:
            return None
        
        try:
            js_contents = []
            for ep in endpoints[:10]:
                if ep.source and 'js' in ep.source.lower():
                    js_url = ep.source.split(':')[1] if ':' in ep.source else None
                    if js_url:
                        content = await self._fetch_js(js_url, "")
                        if content:
                            js_contents.append(content)
            
            target_info = {
                'js_files': ','.join([e.source for e in endpoints[:5] if e.source]),
                'api_paths': ','.join([e.path for e in endpoints[:10]]),
                'response_content': '',
                'headers': ''
            }
            
            matches = self._framework_detector.detect(target_info)
            if matches:
                best_match = matches[0]
                logger.info(f"Framework detected: {best_match.name} (confidence: {best_match.confidence})")
                return best_match.name
                
        except Exception as e:
            logger.debug(f"Framework detection error: {e}")
        
        return None
    
    async def _fetch_js(self, js_url: str, cookies: str) -> Optional[str]:
        """获取 JS 内容"""
        try:
            import aiohttp
            headers = {}
            if cookies:
                headers['Cookie'] = cookies
            
            async with aiohttp.ClientSession() as session:
                async with session.get(js_url, headers=headers, timeout=10) as resp:
                    if resp.status == 200:
                        return await resp.text()
        except Exception as e:
            logger.debug(f"JS fetch error for {js_url}: {e}")
        return None
    
    def _deduplicate_endpoints(
        self, 
        endpoints: List[APIEndpoint]
    ) -> List[APIEndpoint]:
        """去重端点"""
        seen = {}
        result = []
        
        for ep in endpoints:
            key = f"{ep.method}:{ep.path}"
            if key not in seen:
                seen[key] = ep
                result.append(ep)
            else:
                existing = seen[key]
                existing.tags = list(set(existing.tags + ep.tags))
                if ep.source and 'swagger' in ep.source:
                    existing.source = ep.source
        
        return result
    
    async def cleanup(self) -> None:
        """清理资源"""
        if self._browser:
            await self._browser.cleanup()
