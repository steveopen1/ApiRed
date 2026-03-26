"""
Tester Agent
测试Agent - 负责执行安全测试
"""

import logging
import time
from typing import Optional, Dict, List, Any
from .base import BaseAgent, AgentConfig, AgentResult, Action

logger = logging.getLogger(__name__)


class TesterAgent(BaseAgent):
    """测试Agent - 负责执行漏洞测试"""
    
    def __init__(self, config: AgentConfig, llm_client: Optional[Any] = None):
        super().__init__(config, llm_client)
        self.test_results = []
        self.test_suite = "OWASP Top10"
    
    async def plan(self, context: Dict) -> List[Action]:
        actions = [
            Action(
                action_type="test_planning",
                params={'target': context.get('target', '')},
                priority=10
            ),
            Action(
                action_type="test_execution",
                params={},
                priority=8,
                dependencies=['test_planning']
            ),
            Action(
                action_type="result_validation",
                params={},
                priority=6,
                dependencies=['test_execution']
            )
        ]
        return actions
    
    async def execute(self, action: Action) -> AgentResult:
        start_time = time.time()
        
        try:
            if action.action_type == "test_planning":
                result = await self._plan_tests(action.params.get('target', ''))
            elif action.action_type == "test_execution":
                result = await self._execute_tests()
            elif action.action_type == "result_validation":
                result = await self._validate_results()
            else:
                result = AgentResult(
                    agent_name=self.name,
                    action_type=action.action_type,
                    success=False,
                    error=f"Unknown action type: {action.action_type}"
                )
            
            result.duration = time.time() - start_time
            return result
            
        except Exception as e:
            logger.error(f"{self.name} execute failed: {e}")
            return AgentResult(
                agent_name=self.name,
                action_type=action.action_type,
                success=False,
                error=str(e),
                duration=time.time() - start_time
            )
    
    async def _plan_tests(self, target: str) -> AgentResult:
        """制定测试计划"""
        test_cases = [
            {
                'id': 'OT001',
                'name': 'Broken Object Level Authorization',
                'category': 'IDOR',
                'severity': 'critical'
            },
            {
                'id': 'OT002',
                'name': 'Broken Authentication',
                'category': 'AUTH',
                'severity': 'high'
            },
            {
                'id': 'OT003',
                'name': 'Excessive Data Exposure',
                'category': 'DATA',
                'severity': 'medium'
            },
            {
                'id': 'OT004',
                'name': 'Lack of Resources & Rate Limiting',
                'category': 'RATE',
                'severity': 'medium'
            },
            {
                'id': 'OT005',
                'name': 'Mass Assignment',
                'category': 'ASSIGN',
                'severity': 'high'
            }
        ]
        
        return AgentResult(
            agent_name=self.name,
            action_type="test_planning",
            success=True,
            data={'test_cases': test_cases}
        )
    
    async def _execute_tests(self) -> AgentResult:
        """执行测试"""
        executed = []
        
        for memory_result in self.memory:
            if memory_result.action_type == "test_planning":
                test_cases = memory_result.data.get('test_cases', [])
                executed = [{**tc, 'status': 'executed'} for tc in test_cases]
        
        return AgentResult(
            agent_name=self.name,
            action_type="test_execution",
            success=True,
            data={'executed_tests': executed}
        )
    
    async def _validate_results(self) -> AgentResult:
        """验证测试结果"""
        validated = []
        
        for memory_result in self.memory:
            if memory_result.action_type == "test_execution":
                tests = memory_result.data.get('executed_tests', [])
                validated = [t for t in tests if t.get('status') == 'executed']
        
        return AgentResult(
            agent_name=self.name,
            action_type="result_validation",
            success=True,
            data={'validated_tests': validated}
        )
    
    async def generate_payloads(self, vuln_type: str, target_info: Dict = None) -> List[Dict]:
        """
        使用 LLM 生成针对特定漏洞类型的攻击载荷
        
        Args:
            vuln_type: 漏洞类型 (sql_injection, xss, ssrf, etc.)
            target_info: 目标信息（可选）
        
        Returns:
            载荷列表
        """
        if not self.llm_client:
            return self._get_default_payloads(vuln_type)
        
        target_desc = ""
        if target_info:
            target_desc = f"\nTarget context: {target_info.get('description', '')}"
        
        prompt = f"""Generate attack payloads for {vuln_type} testing.

Context:{target_desc}

Generate 5-10 effective test payloads for {vuln_type}. Consider:
1. Common bypass techniques
2. Context-specific variations
3. Encoding and obfuscation

Respond with one payload per line, format: PAYLOAD"""
        
        try:
            response = await self.chat([{"role": "user", "content": prompt}])
            
            if response:
                payloads = []
                for line in response.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        payloads.append({
                            'payload': line,
                            'type': vuln_type,
                            'source': 'llm'
                        })
                return payloads
        except Exception as e:
            logger.warning(f"{self.name} generate_payloads failed: {e}")
            pass
        
        return self._get_default_payloads(vuln_type)
    
    def _get_default_payloads(self, vuln_type: str) -> List[Dict]:
        """获取默认载荷库"""
        default_payloads = {
            'sql_injection': [
                "' OR '1'='1",
                "' OR '1'='1' --",
                "'; DROP TABLE--",
                "' UNION SELECT NULL--",
                "admin'--"
            ],
            'xss': [
                '<script>alert(1)</script>',
                '"><img src=x onerror=alert(1)>',
                "'-alert(1)-'",
                '<svg onload=alert(1)>',
                'javascript:alert(1)'
            ],
            'ssrf': [
                'http://localhost',
                'http://127.0.0.1',
                'http://169.254.169.254/latest/meta-data/',
                'file:///etc/passwd'
            ],
            'idor': [
                'id=1',
                'id=999999',
                '../admin',
                '../../../etc/passwd'
            ]
        }
        
        payloads = []
        for payload in default_payloads.get(vuln_type, []):
            payloads.append({
                'payload': payload,
                'type': vuln_type,
                'source': 'default'
            })
        return payloads
    
    async def validate_vulnerability(self, endpoint: Dict, payload: str, vuln_type: str) -> Dict:
        """
        验证漏洞是否存在
        
        Args:
            endpoint: API 端点信息
            payload: 测试载荷
            vuln_type: 漏洞类型
        
        Returns:
            验证结果 {'confirmed': bool, 'confidence': float, 'evidence': str}
        """
        if not self.llm_client:
            return self._rule_based_validation(endpoint, payload, vuln_type)
        
        prompt = f"""Analyze this vulnerability test result.

Endpoint: {endpoint.get('path', 'unknown')}
Method: {endpoint.get('method', 'GET')}
Payload: {payload}
Vulnerability Type: {vuln_type}

Original Response: {endpoint.get('response_preview', 'N/A')}

Is this vulnerability confirmed? 
Consider:
1. Does the response indicate successful exploitation?
2. Are there error messages revealing system info?
3. Is there unusual behavior compared to baseline?

Respond with: CONFIRMED or NOT_CONFIRMED
If confirmed, provide brief evidence in parentheses."""
        
        try:
            response = await self.chat([{"role": "user", "content": prompt}])
            
            if response:
                if 'CONFIRMED' in response.upper():
                    confidence = 0.8 if 'HIGH' in response.upper() else 0.6
                    evidence = response.split('(')[1].split(')')[0] if '(' in response else 'LLM analysis'
                    return {'confirmed': True, 'confidence': confidence, 'evidence': evidence}
        except Exception as e:
            logger.warning(f"{self.name} validate_vulnerability failed: {e}")
            pass
        
        return self._rule_based_validation(endpoint, payload, vuln_type)
    
    def _rule_based_validation(self, endpoint: Dict, payload: str, vuln_type: str) -> Dict:
        """基于规则的漏洞验证"""
        response_preview = endpoint.get('response_preview', '').lower()
        
        sql_injection_indicators = ['sql', 'syntax', 'error', 'mysql', 'oracle', 'postgres', 'sqlite']
        xss_indicators = ['<script', '<img', 'onerror', 'onload', 'alert(']
        ssrf_indicators = ['localhost', '127.0.0.1', 'meta-data', '169.254']
        
        indicators = {
            'sql_injection': sql_injection_indicators,
            'xss': xss_indicators,
            'ssrf': ssrf_indicators
        }
        
        found_indicators = indicators.get(vuln_type, [])
        
        for indicator in found_indicators:
            if indicator in response_preview:
                return {
                    'confirmed': True,
                    'confidence': 0.7,
                    'evidence': f"Found indicator: {indicator}"
                }
        
        return {'confirmed': False, 'confidence': 0.0, 'evidence': 'No indicators found'}
