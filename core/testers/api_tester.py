"""
API Request Tester
三种请求方式测试 + 有参请求
参考 0x727/ChkApi apiUrlReqNoParameter.py, apiUrlReqWithParameter.py
"""

import json
import time
import asyncio
import logging
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from urllib.parse import urlencode, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

from .parameter_extractor import APIParameterExtractor
from .bypass_techniques import BypassTechniques


@dataclass
class APIRequestResult:
    """API 请求结果"""
    url: str
    method: str
    status_code: int
    headers: Dict[str, str]
    content: str
    content_length: int
    response_time: float
    is_different: bool = False
    bypass_performed: bool = False
    bypass_technique: str = ""
    parameters_used: Dict = field(default_factory=dict)


class APIRequestTester:
    """
    API 请求测试器
    
    支持：
    1. 三种请求方式：GET / POST DATA / POST JSON
    2. 有参请求测试
    3. Bypass 技术
    4. 响应差异检测
    """
    
    def __init__(self, http_client=None):
        self.http_client = http_client
        self.results: List[APIRequestResult] = []
        self.parameter_extractor = APIParameterExtractor()
        self.bypass_techniques = BypassTechniques.get_all_techniques()
    
    async def test_endpoint(self, url: str, params: Dict = None, headers: Dict = None) -> List[APIRequestResult]:
        """
        测试端点的三种请求方式
        
        Args:
            url: API URL
            params: 参数字典
            headers: 请求头
        
        Returns:
            所有请求结果
        """
        results = []
        
        methods = ['GET', 'POST_DATA', 'POST_JSON']
        
        for method in methods:
            result = await self._test_method(url, method, params, headers)
            if result:
                results.append(result)
        
        return results
    
    async def _test_method(self, url: str, method: str, params: Dict = None, headers: Dict = None) -> Optional[APIRequestResult]:
        """测试单个请求方式"""
        if not self.http_client:
            return None
        
        try:
            start_time = time.time()
            
            if method == 'GET':
                response = await self.http_client.request(url, params=params, headers=headers)
            elif method == 'POST_DATA':
                data = urlencode(params or {})
                response = await self.http_client.request(
                    url,
                    method='POST',
                    data=data,
                    headers={**(headers or {}), 'Content-Type': 'application/x-www-form-urlencoded'}
                )
            elif method == 'POST_JSON':
                json_data = json.dumps(params or {})
                response = await self.http_client.request(
                    url,
                    method='POST',
                    data=json_data,
                    headers={**(headers or {}), 'Content-Type': 'application/json'}
                )
            else:
                return None
            
            response_time = time.time() - start_time
            
            content = getattr(response, 'content', b'').decode('utf-8', errors='ignore')
            
            return APIRequestResult(
                url=url,
                method=method,
                status_code=getattr(response, 'status_code', 0),
                headers=dict(getattr(response, 'headers', {})),
                content=content,
                content_length=len(content),
                response_time=response_time
            )
        except Exception as e:
            logger.debug(f"Request failed: {e}")
            return None
    
    async def test_with_bypass(self, url: str, params: Dict = None, headers: Dict = None) -> List[APIRequestResult]:
        """使用 Bypass 技术测试"""
        results = []
        
        original_result = await self.test_endpoint(url, params, headers)
        if original_result:
            results.extend(original_result)
        
        if original_result and original_result[0].status_code in [301, 302, 401, 404, 400]:
            for technique in self.bypass_techniques[:10]:
                bypass_result = await self._test_with_bypass(url, params, headers, technique)
                if bypass_result:
                    results.append(bypass_result)
        
        return results
    
    async def _test_with_bypass(self, url: str, params: Dict, headers: Dict, technique) -> Optional[APIRequestResult]:
        """使用单个 Bypass 技术测试"""
        if not self.http_client:
            return None
        
        try:
            original = {'url': url, 'params': params or {}}
            bypass_config = technique.apply_func(original)
            
            bypass_url = bypass_config.get('url', url)
            bypass_params = bypass_config.get('params', params)
            bypass_method = bypass_config.get('method', 'GET')
            bypass_headers = bypass_config.get('headers', headers or {})
            bypass_data = bypass_config.get('data')
            
            if bypass_method == 'GET':
                response = await self.http_client.request(
                    bypass_url,
                    params=bypass_params,
                    headers=bypass_headers
                )
            else:
                response = await self.http_client.request(
                    bypass_url,
                    method=bypass_method,
                    data=bypass_data,
                    headers=bypass_headers
                )
            
            content = getattr(response, 'content', b'').decode('utf-8', errors='ignore')
            
            return APIRequestResult(
                url=bypass_url,
                method=bypass_method,
                status_code=getattr(response, 'status_code', 0),
                headers=dict(getattr(response, 'headers', {})),
                content=content,
                content_length=len(content),
                response_time=time.time() - time.time(),
                bypass_performed=True,
                bypass_technique=technique.name
            )
        except Exception as e:
            logger.debug(f"Bypass technique {technique.name} failed: {e}")
            return None
    
    def test_responses_different(self, responses: List[APIRequestResult]) -> bool:
        """检测响应是否有差异"""
        if len(responses) < 2:
            return False
        
        contents = [r.content for r in responses]
        return len(set(contents)) > 1
    
    async def test_parameterized(self, url: str, params: Dict, headers: Dict = None) -> List[APIRequestResult]:
        """
        有参请求测试
        从响应中提取参数，然后使用参数请求
        """
        results = []
        
        results.extend(await self.test_endpoint(url, params, headers))
        
        no_param_result = await self.test_endpoint(url, None, headers)
        
        if no_param_result and no_param_result[0].status_code in [200]:
            extracted_params = self.parameter_extractor.extract_from_response(no_param_result[0].content)
            
            if extracted_params:
                param_dict = {p.name: p.example_value for p in extracted_params[:10]}
                
                if param_dict:
                    results.extend(await self.test_endpoint(url, param_dict, headers))
        
        return results


class PreProbeTester:
    """
    PreProbe 预探测器
    
    在大量扫描前先用 HEAD 请求快速探测哪些URL是活跃的
    参考 0x727/ChkApi apiUrlReqWithParameter.py 的 _preprobe_responsive_urls
    """
    
    DEFAULT_OK_CODES = set(list(range(200, 400)) + [401, 403, 405, 500])
    
    def __init__(self, http_client=None, timeout: int = 2):
        self.http_client = http_client
        self.timeout = timeout
        self.responsive_urls: Set[str] = set()
    
    async def _probe_single(self, url: str, headers: Dict = None) -> bool:
        """探测单个 URL 是否响应"""
        try:
            response = await self.http_client.request(
                url,
                method='HEAD',
                headers=headers,
                timeout=self.timeout
            )
            return response.status_code in self.DEFAULT_OK_CODES
        except Exception:
            return False
    
    async def probe_urls(self, urls: List[str], headers: Dict = None, budget: int = 128) -> Set[str]:
        """
        预探测 URLs
        
        Args:
            urls: URL 列表
            headers: 请求头
            budget: 最多探测数量
            
        Returns:
            会响应的 URL 集合
        """
        if not urls or budget <= 0:
            return set()
        
        urls_to_probe = urls[:min(budget, len(urls))]
        responsive = set()
        
        tasks = [self._probe_single(url, headers) for url in urls_to_probe]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for url, result in zip(urls_to_probe, results):
            if isinstance(result, bool) and result:
                responsive.add(url)
        
        self.responsive_urls = responsive
        return responsive
    
    def prioritize_urls(self, urls: List[str]) -> List[str]:
        """
        根据预探测结果优先处理会响应的 URL
        
        Args:
            urls: 原始 URL 列表
            
        Returns:
            排序后的 URL 列表（活跃的在前）
        """
        if not self.responsive_urls:
            return list(urls)
        
        prioritized = []
        for url in urls:
            if url in self.responsive_urls:
                prioritized.append(url)
        
        for url in urls:
            if url not in self.responsive_urls:
                prioritized.append(url)
        
        return prioritized


class MultiThreadedTester:
    """
    多线程 API 测试器
    模仿 0x727/ChkApi 的 300 线程设计
    支持 PreProbe 优化
    """
    
    def __init__(self, http_client=None, max_workers: int = 300, preprobe_budget: int = 128):
        self.http_client = http_client
        self.max_workers = max_workers
        self.preprobe_budget = preprobe_budget
        self.preprobe_tester = PreProbeTester(http_client)
        self.tester = APIRequestTester(http_client)
        self.results: List[APIRequestResult] = []
        self.failed_urls: List[str] = []
        self.preprobe_enabled = True
        self.preprobe_threshold = 100
    
    def test_urls(self, urls: List[str], params: Dict = None, headers: Dict = None) -> List[APIRequestResult]:
        """
        多线程测试 URL 列表
        
        支持 PreProbe 优化：
        1. 如果 URL 数量超过阈值，先预探测活跃 URL
        2. 优先处理会响应的 URL
        
        Args:
            urls: URL 列表
            params: 全局参数
            headers: 全局请求头
        
        Returns:
            所有结果
        """
        urls_to_test = list(urls)
        
        if (self.preprobe_enabled and 
            len(urls_to_test) >= self.preprobe_threshold and 
            self.preprobe_budget > 0):
            
            logger.info(f"PreProbe enabled: testing {len(urls_to_test)} URLs, probing {self.preprobe_budget} first...")
            
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                responsive = loop.run_until_complete(
                    self.preprobe_tester.probe_urls(urls_to_test, headers, self.preprobe_budget)
                )
                logger.info(f"PreProbe found {len(responsive)} responsive URLs")
                
                urls_to_test = self.preprobe_tester.prioritize_urls(urls_to_test)
            finally:
                loop.close()
        
        all_results = []
        failed = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._test_single, url, params, headers): url
                for url in urls_to_test
            }
            
            for future in as_completed(futures):
                url = futures[future]
                try:
                    result = future.result()
                    if result:
                        all_results.extend(result)
                    else:
                        failed.append(url)
                except Exception as e:
                    failed.append(url)
        
        self.results = all_results
        self.failed_urls = failed
        
        return all_results
    
    def _test_single(self, url: str, params: Dict = None, headers: Dict = None):
        """测试单个 URL（同步方法，供线程池调用）"""
        import asyncio
        
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(self.tester.test_endpoint(url, params, headers))
            finally:
                loop.close()
        except Exception:
            return None
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取测试统计"""
        if not self.results:
            return {
                'total': 0,
                'successful': 0,
                'failed': len(self.failed_urls),
                'different_responses': 0
            }
        
        successful = [r for r in self.results if r.status_code == 200]
        different = self.tester.test_responses_different(successful)
        
        return {
            'total': len(self.results),
            'successful': len(successful),
            'failed': len(self.failed_urls),
            'different_responses': different,
            'bypass_performed': sum(1 for r in self.results if r.bypass_performed)
        }


def create_request_tester(http_client=None) -> APIRequestTester:
    """创建请求测试器"""
    return APIRequestTester(http_client)


def create_multi_tester(http_client=None, workers: int = 300) -> MultiThreadedTester:
    """创建多线程测试器"""
    return MultiThreadedTester(http_client, max_workers=workers)
