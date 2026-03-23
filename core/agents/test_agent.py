"""
Test Agent Module
测试代理 - 负责 API 漏洞测试
"""

import asyncio
from typing import Dict, List, Any, Optional, Set
from urllib.parse import urlparse
import logging
import hashlib

from .orchestrator import AgentInterface, ScanContext
from ..knowledge_base import KnowledgeBase, APIEndpoint, Finding
from ..testers.api_tester import APIRequestTester
from ..testers.parameter_extractor import DangerousAPIFilter
from ..testers.bypass_techniques import BypassTechniques
from ..testers.vulnerability_tester import VulnerabilityTester
from ..testers.fuzzer import SmartFuzzer
from ..rules.sensitive_detector import SensitiveRuleEngine
from ..analyzers.response_baseline import ResponseDifferentiator
from ..analyzers.response_cluster import ResponseCluster
from ..analyzers.api_scorer import APIScorer

logger = logging.getLogger(__name__)


class TestAgent(AgentInterface):
    """
    测试代理
    负责对发现的 API 端点进行漏洞测试
    """
    
    def __init__(self):
        super().__init__("test")
        self._tester = None
        self._vulnerability_tester = None
        self._bypass_techniques = None
        self._sensitive_detector = None
        self._differentiator = None
        self._response_cluster = None
        self._api_scorer = None
        self._tested_urls = set()
        self._http_client = None
    
    def _get_tester(self) -> APIRequestTester:
        """延迟初始化 tester"""
        if self._tester is None:
            self._tester = APIRequestTester()
        return self._tester
    
    def _get_vulnerability_tester(self):
        """获取漏洞测试器"""
        if self._vulnerability_tester is None:
            self._vulnerability_tester = VulnerabilityTester(self._http_client)
        return self._vulnerability_tester
    
    def _get_bypass_techniques(self):
        """获取 bypass techniques 列表"""
        if self._bypass_techniques is None:
            self._bypass_techniques = BypassTechniques.get_all_techniques()
        return self._bypass_techniques
    
    def _get_sensitive_detector(self) -> SensitiveRuleEngine:
        """获取敏感信息检测器"""
        if self._sensitive_detector is None:
            self._sensitive_detector = SensitiveRuleEngine()
        return self._sensitive_detector
    
    def _get_differentiator(self) -> ResponseDifferentiator:
        """获取响应差异化器"""
        if self._differentiator is None:
            self._differentiator = ResponseDifferentiator()
        return self._differentiator
    
    def _get_response_cluster(self) -> ResponseCluster:
        """获取响应聚类器"""
        if self._response_cluster is None:
            self._response_cluster = ResponseCluster()
        return self._response_cluster
    
    def _get_api_scorer(self) -> APIScorer:
        """获取 API 评分器"""
        if self._api_scorer is None:
            self._api_scorer = APIScorer()
        return self._api_scorer
    
    def _get_smart_fuzzer(self) -> SmartFuzzer:
        """获取智能模糊测试器"""
        if not hasattr(self, '_smart_fuzzer') or self._smart_fuzzer is None:
            self._smart_fuzzer = SmartFuzzer(safe_mode=True)
        return self._smart_fuzzer

    async def execute(self, context: ScanContext) -> Dict[str, Any]:
        """
        执行测试任务
        
        测试流程:
        1. 获取待测试端点
        2. ResponseCluster 响应聚类
        3. APIScorer API 评分
        4. 三种方式请求 (GET/POST/JSON)
        5. 敏感信息检测
        6. Bypass 测试
        7. VulnerabilityTester 漏洞测试
        8. ResponseDifferentiator 响应差异化
        """
        endpoints = self.knowledge_base.get_endpoints() if self.knowledge_base else []
        
        if not endpoints:
            logger.warning("TestAgent: No endpoints to test")
            return {
                'tested': 0,
                'vulnerabilities': [],
                'sensitive_data': []
            }
        
        logger.info(f"TestAgent: Starting tests for {len(endpoints)} endpoints")
        
        vulnerabilities = []
        sensitive_data = []
        alive_apis = []
        
        dangerous_paths = set()
        for endpoint in endpoints:
            if DangerousAPIFilter.is_dangerous(endpoint.path):
                dangerous_paths.add(endpoint.path)
        
        safe_endpoints = [ep for ep in endpoints if ep.path not in dangerous_paths]
        
        response_cluster = self._get_response_cluster()
        api_scorer = self._get_api_scorer()
        
        for endpoint in safe_endpoints[:100]:
            full_url = endpoint.full_url or f"{context.target.rstrip('/')}{endpoint.path}"
            
            if full_url in self._tested_urls:
                continue
            
            self._tested_urls.add(full_url)
            
            try:
                result = await self._test_endpoint(endpoint, context)
                
                if result.get('alive'):
                    alive_apis.append(result)
                    
                    vulns = result.get('vulnerabilities', [])
                    vulnerabilities.extend(vulns)
                    
                    sensitive = result.get('sensitive_data', [])
                    sensitive_data.extend(sensitive)

                    if self.knowledge_base:
                        for vuln in vulns:
                            self.knowledge_base.add_vulnerability(vuln)

                        for data in sensitive:
                            self.knowledge_base.add_sensitive_data(data)

            except Exception as e:
                logger.debug(f"Test error for {full_url}: {e}")
                continue

        return {
            'tested': len(self._tested_urls),
            'alive_apis': len(alive_apis),
            'vulnerabilities': vulnerabilities,
            'sensitive_data': sensitive_data,
            'dangerous_filtered': len(endpoints) - len(safe_endpoints),
        }

    async def _test_endpoint(
        self,
        endpoint: APIEndpoint,
        context: ScanContext
    ) -> Dict[str, Any]:
        """测试单个端点"""
        full_url = endpoint.full_url or f"{context.target.rstrip('/')}{endpoint.path}"

        result = {
            'url': full_url,
            'path': endpoint.path,
            'method': endpoint.method,
            'alive': False,
            'status_code': 0,
            'vulnerabilities': [],
            'sensitive_data': [],
        }

        tester = self._get_tester()

        try:
            responses = tester.test_endpoint(full_url, params=None, headers=context.headers)

            if responses:
                first_response = responses[0]
                result['status_code'] = first_response.status_code
                result['alive'] = first_response.status_code in [200, 201, 204, 401, 403]

                if result['alive']:
                    content = first_response.content
                    content_hash = hashlib.md5(content[:1000].encode()).hexdigest()

                    differentiator = self._get_differentiator()
                    differentiator.add_response(
                        full_url,
                        endpoint.method,
                        first_response.status_code,
                        content,
                        len(content)
                    )

                    if differentiator.is_duplicate_response(content_hash, threshold=10):
                        logger.debug(f"Skipping duplicate response: {full_url}")

                    sensitive_detector = self._get_sensitive_detector()
                    try:
                        sensitive_results = sensitive_detector.scan(content)
                        for sr in sensitive_results:
                            result['sensitive_data'].append({
                                'type': sr.get('rule_name', 'unknown'),
                                'severity': 'medium',
                                'url': full_url,
                                'context': str(sr.get('match', ''))[:100],
                            })
                    except Exception as e:
                        logger.debug(f"URL scan error: {e}")

                    bypass_results = tester.test_with_bypass(full_url, params=None, headers=context.headers)
                    for bypass_resp in bypass_results:
                        if bypass_resp.bypass_performed:
                            result['vulnerabilities'].append({
                                'type': 'Bypass',
                                'severity': 'high',
                                'url': full_url,
                                'evidence': f"Status: {bypass_resp.status_code}",
                                'payload': bypass_resp.bypass_technique,
                            })
                    
                    smart_fuzzer = self._get_smart_fuzzer()
                    
                    if endpoint.method in ('POST', 'PUT', 'PATCH'):
                        endpoint_params = {}
                        if hasattr(endpoint, 'parameters') and endpoint.parameters:
                            for param in endpoint.parameters:
                                param_name = param if isinstance(param, str) else getattr(param, 'name', None)
                                if param_name:
                                    endpoint_params[param_name] = smart_fuzzer.generate_param_value(param_name)
                        
                        multi_format_requests = smart_fuzzer.generate_multi_format_requests(
                            endpoint.method, full_url, endpoint_params
                        )
                        
                        for mfr in multi_format_requests:
                            try:
                                fuzzer_response = await self._http_client.request(
                                    mfr['url'],
                                    mfr['method'],
                                    data=mfr.get('body'),
                                    headers={**(context.headers or {}), **mfr.get('headers', {})}
                                )
                                if fuzzer_response and fuzzer_response.status_code in [200, 201, 204]:
                                    fuzz_result = smart_fuzzer.guess_param_type('test')
                                    result['vulnerabilities'].append({
                                        'type': 'MultiFormatTest',
                                        'severity': 'info',
                                        'url': f"{full_url} ({mfr['format']})",
                                        'evidence': f"Format: {mfr['format']}, Status: {fuzzer_response.status_code if fuzzer_response else 0}",
                                    })
                            except Exception as e:
                                logger.debug(f"SmartFuzzer multi-format test failed: {e}")
                    
                    if smart_fuzzer.is_upload_endpoint(full_url, endpoint_params):
                        upload_tests = smart_fuzzer.generate_upload_test(full_url)
                        for upload_test in upload_tests:
                            try:
                                upload_response = await self._http_client.request(
                                    upload_test['url'],
                                    upload_test['method'],
                                    data=upload_test.get('files'),
                                    headers={**(context.headers or {}), **upload_test.get('headers', {})}
                                )
                                if upload_response and upload_response.status_code in [200, 201, 204, 400]:
                                    result['vulnerabilities'].append({
                                        'type': 'UploadTest',
                                        'severity': 'medium',
                                        'url': full_url,
                                        'evidence': f"Format: {upload_test['format']}, Status: {upload_response.status_code}",
                                    })
                            except Exception as e:
                                logger.debug(f"SmartFuzzer upload test failed: {e}")

        except Exception as e:
            logger.debug(f"Analysis error: {e}")

        return result

    async def extract_parameters(self, context: ScanContext) -> Dict[str, Set[str]]:
        """提取参数"""
        endpoints = self.knowledge_base.get_endpoints() if self.knowledge_base else []
        all_params = {}

        tester = self._get_tester()

        for endpoint in endpoints[:50]:
            try:
                responses = tester.test_endpoint(
                    f"{context.target.rstrip('/')}{endpoint.path}",
                    params=None,
                    headers=context.headers
                )

                if responses:
                    content = responses[0].content
                    params = tester.parameter_extractor.extract_from_response(content)

                    if params:
                        all_params[endpoint.path] = set(params)

                        if self.knowledge_base:
                            for param in params:
                                self.knowledge_base.add_parameter(endpoint.path, param)

            except Exception:
                continue

        return all_params

    async def cleanup(self) -> None:
        """清理资源"""
        self._tested_urls.clear()
        self._tester = None
        self._sensitive_detector = None
        self._differentiator = None
