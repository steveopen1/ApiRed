"""
Analyzer Agent
分析Agent - 负责漏洞分析和推理
"""

import logging
import time
from typing import Dict, List, Any
from .base import BaseAgent, AgentConfig, AgentResult, Action

logger = logging.getLogger(__name__)


class AnalyzerAgent(BaseAgent):
    """分析Agent - 负责漏洞分析和推理"""
    
    def __init__(self, config: AgentConfig, llm_client: Optional[Any] = None):
        super().__init__(config, llm_client)
        self.vulnerabilities = []
        self.risk_level = "low"
    
    async def plan(self, context: Dict) -> List[Action]:
        actions = [
            Action(
                action_type="context_gathering",
                params={'target': context.get('target', '')},
                priority=10
            ),
            Action(
                action_type="hypothesis_forming",
                params={},
                priority=8,
                dependencies=['context_gathering']
            ),
            Action(
                action_type="evidence_evaluation",
                params={},
                priority=6,
                dependencies=['hypothesis_forming']
            ),
            Action(
                action_type="conclusion_deduction",
                params={},
                priority=4,
                dependencies=['evidence_evaluation']
            )
        ]
        return actions
    
    async def execute(self, action: Action) -> AgentResult:
        start_time = time.time()
        
        try:
            if action.action_type == "context_gathering":
                result = await self._gather_context(action.params.get('target', ''))
            elif action.action_type == "hypothesis_forming":
                result = await self._form_hypothesis()
            elif action.action_type == "evidence_evaluation":
                result = await self._evaluate_evidence()
            elif action.action_type == "conclusion_deduction":
                result = await self._deduce_conclusion()
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
    
    async def _gather_context(self, target: str) -> AgentResult:
        """收集上下文"""
        return AgentResult(
            agent_name=self.name,
            action_type="context_gathering",
            success=True,
            data={'context_collected': True}
        )
    
    async def _form_hypothesis(self) -> AgentResult:
        """形成假设"""
        hypotheses = []
        
        for memory_result in self.memory:
            if memory_result.action_type == "context_gathering":
                hypotheses.append({
                    'type': 'potential_vuln',
                    'description': 'Need further testing'
                })
        
        return AgentResult(
            agent_name=self.name,
            action_type="hypothesis_forming",
            success=True,
            data={'hypotheses': hypotheses}
        )
    
    async def _evaluate_evidence(self) -> AgentResult:
        """评估证据"""
        return AgentResult(
            agent_name=self.name,
            action_type="evidence_evaluation",
            success=True,
            data={'evidence_ranked': []}
        )
    
    async def _deduce_conclusion(self) -> AgentResult:
        """推断结论"""
        vulnerabilities = []
        
        for memory_result in self.memory:
            if memory_result.action_type == "evidence_evaluation":
                vulnerabilities.extend(memory_result.data.get('vulnerabilities', []))
        
        self.vulnerabilities = vulnerabilities
        
        return AgentResult(
            agent_name=self.name,
            action_type="conclusion_deduction",
            success=True,
            data={'vulnerabilities': vulnerabilities}
        )
    
    async def assess_risk(self, api_endpoint: Dict, response_data: Dict) -> str:
        """
        使用 LLM 评估 API 风险等级
        
        Args:
            api_endpoint: API 端点信息
            response_data: 响应数据
        
        Returns:
            风险等级: low, medium, high, critical
        """
        if not self.llm_client:
            return self._rule_based_risk_assessment(api_endpoint, response_data)
        
        prompt = f"""Analyze this API endpoint and its response to assess security risk.

API Endpoint:
- Path: {api_endpoint.get('path', 'unknown')}
- Method: {api_endpoint.get('method', 'GET')}
- Status Code: {response_data.get('status_code', 'unknown')}

Response Analysis:
- Content Length: {len(response_data.get('content', ''))}
- Content Type: {response_data.get('content_type', 'unknown')}

Assess the risk level considering:
1. Does it expose sensitive data (PII, credentials, tokens)?
2. Does it reveal internal system information?
3. Is it a high-value target (admin, user data, payment)?
4. Are there authentication/authorization issues?

Respond with only one word: low, medium, high, or critical"""
        
        try:
            response = await self.chat([{"role": "user", "content": prompt}])
            
            if response:
                response_lower = response.lower().strip()
                if response_lower in ['low', 'medium', 'high', 'critical']:
                    return response_lower
        except Exception as e:
            logger.warning(f"{self.name} assess_risk failed: {e}")
            pass
        
        return self._rule_based_risk_assessment(api_endpoint, response_data)
    
    def _rule_based_risk_assessment(self, api_endpoint: Dict, response_data: Dict) -> str:
        """基于规则的风险评估"""
        path = api_endpoint.get('path', '').lower()
        content = response_data.get('content', '').lower()
        status_code = response_data.get('status_code', 0)
        
        high_risk_patterns = ['admin', 'user', 'password', 'token', 'key', 'secret', 'auth', 'login', 'account']
        critical_risk_patterns = ['ssn', 'credit', 'card', 'bank', 'social']
        
        if any(p in path for p in critical_risk_patterns):
            return 'critical'
        elif any(p in path for p in high_risk_patterns):
            if status_code == 200 and content:
                return 'high'
            return 'medium'
        elif status_code == 200 and len(content) > 1000:
            return 'medium'
        
        return 'low'
    
    async def suggest_tests(self, api_endpoint: Dict) -> List[Dict]:
        """
        建议针对该 API 的测试用例
        
        Args:
            api_endpoint: API 端点信息
        
        Returns:
            建议的测试用例列表
        """
        if not self.llm_client:
            return self._rule_based_test_suggestions(api_endpoint)
        
        prompt = f"""Based on this API endpoint, suggest security tests to perform.

API Endpoint:
- Path: {api_endpoint.get('path', 'unknown')}
- Method: {api_endpoint.get('method', 'GET')}

Suggest 3-5 security tests from this list:
- SQL Injection (parameter manipulation)
- XSS (reflected/stored)
- SSRF (file://, http://169.254.169.254)
- IDOR (horizontal/vertical privilege escalation)
- JWT Security (weak secret, none algorithm)
- Authentication Bypass (missing auth, weak passwords)
- Rate Limiting (bypass techniques)
- API Key Exposure

Respond with one test per line, format: TEST_NAME - brief description"""
        
        try:
            response = await self.chat([{"role": "user", "content": prompt}])
            
            if response:
                tests = []
                for line in response.split('\n'):
                    line = line.strip()
                    if line and '-' in line:
                        tests.append({'name': line.split('-')[0].strip(), 'description': line.split('-')[1].strip()})
                return tests[:5]
        except Exception as e:
            logger.warning(f"{self.name} suggest_tests failed: {e}")
            pass
        
        return self._rule_based_test_suggestions(api_endpoint)
    
    def _rule_based_test_suggestions(self, api_endpoint: Dict) -> List[Dict]:
        """基于规则的测试建议"""
        method = api_endpoint.get('method', 'GET').upper()
        path = api_endpoint.get('path', '').lower()
        
        tests = [
            {'name': 'SQL_INJECTION', 'description': 'Test for SQL injection vulnerabilities'},
            {'name': 'XSS', 'description': 'Test for cross-site scripting'}
        ]
        
        if 'user' in path or 'admin' in path:
            tests.append({'name': 'IDOR', 'description': 'Test for insecure direct object references'})
        
        if 'auth' in path or 'login' in path:
            tests.append({'name': 'AUTH_BYPASS', 'description': 'Test for authentication bypass'})
        
        if method in ['POST', 'PUT', 'PATCH']:
            tests.append({'name': 'MASS_ASSIGNMENT', 'description': 'Test for mass assignment vulnerabilities'})
        
        return tests
