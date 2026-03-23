"""
GraphQL Tester Agent Module
GraphQL 测试代理 - 负责 GraphQL 安全测试
"""

import logging
from typing import Dict, List, Any, Optional

from .orchestrator import AgentInterface, ScanContext
from ..knowledge_base import KnowledgeBase, APIEndpoint, Finding
from ..testers.graphql import GraphQLSecurityTester

logger = logging.getLogger(__name__)


class GraphQLTesterAgent(AgentInterface):
    """
    GraphQL 测试代理
    
    负责 GraphQL 端点的安全测试:
    1. Introspection 查询检测
    2. 批量查询绕过速率限制
    3. 别名滥用 DoS 测试
    4. 字段重复 DoS 测试
    5. 指令重载 DoS 测试
    6. 凭证暴力破解检测
    7. IDOR 测试
    """
    
    COMMON_GRAPHQL_PATHS = [
        '/graphql',
        '/graphiql',
        '/graphql.php',
        '/graphql/console',
        '/api',
        '/api/graphql',
        '/graphql/api',
        '/graphql/graphql',
    ]
    
    def __init__(self):
        super().__init__("graphql_tester")
        self._graphql_tester = None
        self._http_client = None
    
    async def initialize(self, context: ScanContext) -> None:
        """初始化 GraphQL 测试代理"""
        await super().initialize(context)
        from ..http_client import HTTPClient
        self._http_client = HTTPClient()
        self._graphql_tester = GraphQLSecurityTester(self._http_client)
    
    async def execute(self, context: ScanContext) -> Dict[str, Any]:
        """
        执行 GraphQL 测试任务
        
        流程:
        1. 发现 GraphQL 端点
        2. 执行 GraphQL 安全测试
        3. 收集测试结果
        """
        graphql_endpoints = await self._discover_graphql_endpoints(context.target)
        
        if not graphql_endpoints:
            logger.info("GraphQLTesterAgent: No GraphQL endpoints found")
            return {
                'tested': 0,
                'vulnerabilities': [],
                'introspection_enabled': False,
            }
        
        logger.info(f"GraphQLTesterAgent: Testing {len(graphql_endpoints)} GraphQL endpoints")
        
        all_vulnerabilities = []
        introspection_found = False
        
        for endpoint in graphql_endpoints:
            try:
                result = await self._graphql_tester.test_graphql_endpoint(endpoint)
                
                if result.get('is_graphql'):
                    if result.get('introspection_enabled'):
                        introspection_found = True
                    
                    findings = result.get('vulnerabilities', [])
                    all_vulnerabilities.extend(findings)
                    
                    if self.knowledge_base:
                        for vuln in findings:
                            if self.knowledge_base:
                                self.knowledge_base.add_vulnerability(Finding(
                                    endpoint=endpoint,
                                    vulnerability_type=vuln.get('vulnerability_type', 'GraphQL'),
                                    severity=vuln.get('severity', 'medium'),
                                    evidence=vuln.get('evidence', ''),
                                ))
                    
                    idor_results = await self._graphql_tester.test_idor_with_graphql(
                        endpoint,
                        auth_token=context.headers.get('Authorization', '').replace('Bearer ', '') if context.headers else None
                    )
                    all_vulnerabilities.extend(idor_results)
                    
            except Exception as e:
                logger.debug(f"GraphQL test error for {endpoint}: {e}")
        
        return {
            'tested': len(graphql_endpoints),
            'vulnerabilities': all_vulnerabilities,
            'introspection_enabled': introspection_found,
            'endpoints_found': graphql_endpoints,
        }
    
    async def _discover_graphql_endpoints(self, target: str) -> List[str]:
        """发现 GraphQL 端点"""
        endpoints = []
        parsed = target.split('://')
        if len(parsed) < 2:
            return endpoints
        
        base = f"{parsed[0]}://{parsed[1].split('/')[0]}"
        
        for path in self.COMMON_GRAPHQL_PATHS:
            endpoint = f"{base}{path}"
            endpoints.append(endpoint)
        
        return endpoints
    
    async def cleanup(self) -> None:
        """清理资源"""
        self._graphql_tester = None
        self._http_client = None
