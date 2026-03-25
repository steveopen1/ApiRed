"""
Test Agent Module
测试代理 - 负责 API 漏洞测试
"""

import asyncio
from typing import Dict, List, Any, Optional, Set
from urllib.parse import urlparse
import logging
import hashlib
import os

from .orchestrator import AgentInterface, ScanContext
from ..knowledge_base import KnowledgeBase, APIEndpoint, Finding
from ..testers.api_tester import APIRequestTester
from ..testers.parameter_extractor import DangerousAPIFilter
from ..testers.bypass_techniques import BypassTechniques
from ..testers.vulnerability_tester import VulnerabilityTester
from ..testers.fuzzer import SmartFuzzer
from ..rules.sensitive_detector import SensitiveRuleEngine
from ..analyzers.response_baseline import ResponseDifferentiator, ResponseBaselineLearner
from ..analyzers.response_cluster import ResponseCluster
from ..analyzers.api_scorer import APIScorer
from ..analyzers.test_selector import TestSelector, TestCategory
from ..analyzers.endpoint_analyzer import EndpointAnalyzer
from ..utils.gf import GFLibrary
from ..utils.http_client import AsyncHttpClient

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
        self._response_baseline = None
        self._api_scorer = None
        self._test_selector = None
        self._endpoint_analyzer = None
        self._gf_library = None
        self._tested_urls = set()
        self._http_client = None
    
    async def initialize(self, context: ScanContext) -> None:
        """初始化 Agent - 同步主链路模块"""
        await super().initialize(context)
        
        self._http_client = AsyncHttpClient(
            max_concurrent=context.concurrency,
            max_retries=3,
            timeout=30,
            verify_ssl=True
        )
        
        patterns_dir = os.path.join(os.path.dirname(__file__), '..', 'utils', 'patterns')
        if os.path.exists(patterns_dir):
            self._gf_library = GFLibrary(patterns_dir)
            logger.info(f"TestAgent: GF Library initialized from {patterns_dir}")
        else:
            self._gf_library = GFLibrary()
            logger.info("TestAgent: GF Library initialized with default patterns")
        
        self._response_cluster = ResponseCluster()
        self._response_baseline = ResponseBaselineLearner()
        self._api_scorer = APIScorer()
        self._test_selector = TestSelector()
        self._endpoint_analyzer = EndpointAnalyzer()
    
    def _get_tester(self) -> APIRequestTester:
        """延迟初始化 tester"""
        if self._tester is None:
            self._tester = APIRequestTester(self._http_client)
        return self._tester
    
    def _get_vulnerability_tester(self):
        """获取漏洞测试器"""
        if self._vulnerability_tester is None:
            self._vulnerability_tester = VulnerabilityTester(self._http_client, self._gf_library)
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
    
    def _get_response_baseline(self) -> ResponseBaselineLearner:
        """获取响应基线学习器"""
        if self._response_baseline is None:
            self._response_baseline = ResponseBaselineLearner()
        return self._response_baseline
    
    def _get_api_scorer(self) -> APIScorer:
        """获取 API 评分器"""
        if self._api_scorer is None:
            self._api_scorer = APIScorer()
        return self._api_scorer
    
    def _get_test_selector(self) -> TestSelector:
        """获取测试选择器"""
        if self._test_selector is None:
            self._test_selector = TestSelector()
        return self._test_selector
    
    def _get_endpoint_analyzer(self) -> EndpointAnalyzer:
        """获取端点分析器"""
        if self._endpoint_analyzer is None:
            self._endpoint_analyzer = EndpointAnalyzer()
        return self._endpoint_analyzer
    
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
            responses = await tester.test_endpoint(full_url, params=None, headers=context.headers)

            if responses:
                first_response = responses[0]
                result['status_code'] = first_response.status_code
                result['alive'] = first_response.status_code in [200, 201, 202, 204, 301, 302, 307, 401, 403]

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
                        sensitive_results = sensitive_detector.detect(content)
                        for sr in sensitive_results:
                            result['sensitive_data'].append({
                                'type': sr.get('rule_name', 'unknown'),
                                'severity': 'medium',
                                'url': full_url,
                                'context': str(sr.get('match', ''))[:100],
                            })
                    except Exception as e:
                        logger.debug(f"URL scan error: {e}")

                    vuln_tester = self._get_vulnerability_tester()
                    endpoint_params = {}
                    if hasattr(endpoint, 'parameters') and endpoint.parameters:
                        for param in endpoint.parameters:
                            param_name = param if isinstance(param, str) else getattr(param, 'name', None)
                            if param_name:
                                endpoint_params[param_name] = 'test'

                    for param_name in endpoint_params.keys():
                        try:
                            sql_result = await vuln_tester.test_sql_injection(full_url, method=endpoint.method, param_name=param_name)
                            if sql_result and sql_result.is_vulnerable:
                                result['vulnerabilities'].append({
                                    'type': 'SQL_INJECTION',
                                    'severity': sql_result.severity,
                                    'url': full_url,
                                    'evidence': sql_result.evidence,
                                    'payload': sql_result.payload,
                                })
                        except Exception as e:
                            logger.debug(f"SQL injection test error: {e}")

                        try:
                            xss_result = await vuln_tester.test_xss(full_url, method=endpoint.method, param_name=param_name)
                            if xss_result and xss_result.is_vulnerable:
                                result['vulnerabilities'].append({
                                    'type': 'XSS',
                                    'severity': xss_result.severity,
                                    'url': full_url,
                                    'evidence': xss_result.evidence,
                                    'payload': xss_result.payload,
                                })
                        except Exception as e:
                            logger.debug(f"XSS test error: {e}")

                        try:
                            ssrf_result = await vuln_tester.test_ssrf(full_url, method=endpoint.method, param_name=param_name)
                            if ssrf_result and ssrf_result.is_vulnerable:
                                result['vulnerabilities'].append({
                                    'type': 'SSRF',
                                    'severity': ssrf_result.severity,
                                    'url': full_url,
                                    'evidence': ssrf_result.evidence,
                                    'payload': ssrf_result.payload,
                                })
                        except Exception as e:
                            logger.debug(f"SSRF test error: {e}")

                        try:
                            crlf_result = await vuln_tester.test_crlf_injection(full_url, param_name=param_name)
                            if crlf_result and crlf_result.is_vulnerable:
                                result['vulnerabilities'].append({
                                    'type': 'CRLF_INJECTION',
                                    'severity': crlf_result.severity,
                                    'url': full_url,
                                    'evidence': crlf_result.evidence,
                                    'payload': crlf_result.payload,
                                })
                        except Exception as e:
                            logger.debug(f"CRLF injection test error: {e}")

                        try:
                            lfi_result = await vuln_tester.test_lfi(full_url, param_name=param_name)
                            if lfi_result and lfi_result.is_vulnerable:
                                result['vulnerabilities'].append({
                                    'type': 'LFI',
                                    'severity': lfi_result.severity,
                                    'url': full_url,
                                    'evidence': lfi_result.evidence,
                                    'payload': lfi_result.payload,
                                })
                        except Exception as e:
                            logger.debug(f"LFI test error: {e}")

                        try:
                            cmd_result = await vuln_tester.test_command_injection(full_url, param_name=param_name)
                            if cmd_result and cmd_result.is_vulnerable:
                                result['vulnerabilities'].append({
                                    'type': 'COMMAND_INJECTION',
                                    'severity': cmd_result.severity,
                                    'url': full_url,
                                    'evidence': cmd_result.evidence,
                                    'payload': cmd_result.payload,
                                })
                        except Exception as e:
                            logger.debug(f"Command injection test error: {e}")

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
                responses = await tester.test_endpoint(
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
