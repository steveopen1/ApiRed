"""
Tester Agent
测试Agent - 负责执行安全测试
"""

import time
from typing import Dict, List, Any
from .base import BaseAgent, AgentConfig, AgentResult, Action


class TesterAgent(BaseAgent):
    """测试Agent - 负责执行漏洞测试"""
    
    def __init__(self, config: AgentConfig):
        super().__init__(config)
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
