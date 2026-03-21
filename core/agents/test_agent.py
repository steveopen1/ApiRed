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
from ..testers.fuzz_tester import FuzzTester
from ..rules.rule_engine import SensitiveRuleEngine

logger = logging.getLogger(__name__)


class TestAgent(AgentInterface):
    """
    测试代理
    负责对发现的 API 端点进行漏洞测试
    """
    
    def __init__(self):
        super().__init__("test")
        self.tester = APIRequestTester()
        self.parameter_extractor = ParameterExtractor()
        self.bypass_techniques = BypassTechniques()
        self.fuzz_tester = FuzzTester()
        self.sensitive_detector = SensitiveRuleEngine()
        self.differentiator = ResponseDifferentiator()
        self._tested_urls = set()
    
    async def execute(self, context: ScanContext) -> Dict[str, Any]:
        """
        执行测试任务
        
        测试流程:
        1. 获取待测试端点
        2. 三种方式请求 (GET/POST/JSON)
        3. 敏感信息检测
        4. Bypass 测试
        5. Fuzz 测试
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
        
        methods_to_test = ['GET', 'POST', 'JSON']
        alive = False
        
        for method in methods_to_test:
            try:
                response = await self.tester.test_endpoint(
                    full_url,
                    method=method,
                    cookies=context.cookies,
                    headers=context.headers
                )
                
                if response and response.get('status_code') in [200, 201, 204, 401, 403]:
                    alive = True
                    result['status_code'] = response.get('status_code')
                    result['method'] = method
                    break
                    
            except Exception:
                continue
        
        if not alive:
            return result
        
        result['alive'] = True
        
        try:
            response_content = response.get('content', '')
            content_hash = hashlib.md5(response_content[:1000].encode()).hexdigest()
            self.differentiator.add_response(
                full_url,
                endpoint.method,
                result['status_code'],
                response_content,
                len(response_content)
            )
            
            if self.differentiator.is_duplicate_response(content_hash, threshold=10):
                logger.debug(f"Skipping duplicate response: {full_url}")
            
            sensitive_results = self.sensitive_detector.scan(response_content)
            for sr in sensitive_results:
                result['sensitive_data'].append({
                    'type': sr.get('rule_name', 'unknown'),
                    'severity': 'medium',
                    'url': full_url,
                    'context': sr.get('match', '')[:100],
                })
            
            bypass_result = await self._test_bypass(full_url, endpoint.method, context)
            if bypass_result.get('bypassed'):
                result['vulnerabilities'].append({
                    'type': 'Bypass',
                    'severity': 'high',
                    'url': full_url,
                    'evidence': bypass_result.get('evidence', ''),
                    'payload': bypass_result.get('payload', ''),
                })
            
            fuzz_result = await self._test_fuzz(full_url, endpoint.method, context)
            if fuzz_result.get('vulnerable'):
                result['vulnerabilities'].append({
                    'type': 'Fuzz',
                    'severity': 'medium',
                    'url': full_url,
                    'evidence': fuzz_result.get('evidence', ''),
                    'payload': fuzz_result.get('payload', ''),
                })
            
        except Exception as e:
            logger.debug(f"Analysis error: {e}")
        
        return result
    
    async def _test_bypass(
        self,
        url: str,
        method: str,
        context: ScanContext
    ) -> Dict[str, Any]:
        """测试 Bypass 技术"""
        result = {
            'bypassed': False,
            'technique': '',
            'evidence': '',
            'payload': '',
        }
        
        techniques = self.bypass_techniques.get_by_type('header')[:3]
        
        for technique in techniques:
            try:
                headers = context.headers.copy()
                technique.apply(headers)
                
                response = await self.tester.test_endpoint(
                    url,
                    method=method,
                    headers=headers,
                    cookies=context.cookies
                )
                
                if response and response.get('status_code') == 200:
                    result['bypassed'] = True
                    result['technique'] = technique.name
                    result['evidence'] = f"Status: {response.get('status_code')}"
                    result['payload'] = str(headers)
                    break
                    
            except Exception:
                continue
        
        return result
    
    async def _test_fuzz(
        self,
        url: str,
        method: str,
        context: ScanContext
    ) -> Dict[str, Any]:
        """测试 Fuzz"""
        result = {
            'vulnerable': False,
            'evidence': '',
            'payload': '',
        }
        
        try:
            fuzz_result = await self.fuzz_tester.test_url(
                url,
                method=method,
                cookies=context.cookies
            )
            
            if fuzz_result and fuzz_result.get('vulnerable'):
                result['vulnerable'] = True
                result['evidence'] = fuzz_result.get('evidence', '')
                result['payload'] = fuzz_result.get('payload', '')
                
        except Exception:
            pass
        
        return result
    
    async def extract_parameters(self, context: ScanContext) -> Dict[str, Set[str]]:
        """提取参数"""
        endpoints = self.knowledge_base.get_endpoints() if self.knowledge_base else []
        all_params = {}
        
        for endpoint in endpoints[:50]:
            try:
                params = await self.parameter_extractor.extract_from_endpoint(
                    endpoint.path,
                    context.target
                )
                
                if params:
                    all_params[endpoint.path] = set(params)
                    
                    for param in params:
                        self.knowledge_base.add_parameter(endpoint.path, param)
                        
            except Exception:
                continue
        
        return all_params
    
    async def cleanup(self) -> None:
        """清理资源"""
        self._tested_urls.clear()
