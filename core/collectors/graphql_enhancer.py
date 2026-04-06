"""
GraphQL 增强发现与探测模块

增强功能：
1. 全面的 GraphQL 端点发现
2. Schema introspection 支持
3. Introspection 禁用时的回退探测
4. 从 JS/HTML 中提取 GraphQL 操作
5. 支持 persisted queries (APQ)
"""

import re
import json
import logging
from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass, field
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


@dataclass
class GraphQLSchema:
    """GraphQL Schema信息"""
    endpoint: str
    query_type: Optional[str] = None
    mutation_type: Optional[str] = None
    subscription_type: Optional[str] = None
    types: List[Dict] = field(default_factory=list)
    queries: List[Dict] = field(default_factory=list)
    mutations: List[Dict] = field(default_factory=list)
    subscriptions: List[Dict] = field(default_factory=list)
    introspection_enabled: bool = False
    raw_schema: Optional[str] = None


@dataclass
class DiscoveredOperation:
    """发现的 GraphQL 操作"""
    name: Optional[str]
    type: str  # 'query', 'mutation', 'subscription'
    fields: List[str]
    variables: List[str]
    source: str  # 'introspection', 'js_code', 'error_hint'
    endpoint: str


class EnhancedGraphQLDiscovery:
    """
    增强型 GraphQL 发现器
    
    相比原有 GraphQLDiscovery 的增强：
    1. 更全面的端点探测
    2. 支持多种 GraphQL 变体 (GraphQL, GraphQL Mesh, Hasura 等)
    3. Introspection 禁用时的回退探测
    4. 从 JS 代码中提取 operation
    5. Persisted queries 支持
    """

    GRAPHQL_PATTERNS = [
        r'''['"]([/][^'"]*graphql[^'"]*)['"]''',
        r'''['"]([/][^'"]*graphql)['"']''',
        r'''endpoint\s*:\s*['"]([/][^'"]+)['"']''',
        r'''uri\s*:\s*['"]([/][^'"]+)['"']''',
        r'''server\s*:\s*['"]([/][^'"]+)['"']''',
        r'''apiEndpoint\s*:\s*['"]([/][^'"]+)['"']''',
        r'''gql\s*`[^`]+`''',
        r'''graphql\s*\(`[^`]+`\)''',
        r'''useQuery\s*\([^)]*`[^`]+`''',
        r'''useMutation\s*\([^)]*`[^`]+`''',
        r'''apollo\s*\.\s*(?:query|mutate)\s*\([^)]+\)''',
        r'''new\s+ApolloClient\s*\(\s*\{[^}]*uri\s*:\s*['"]([^'"]+)['"]''',
        r'''ApolloClient\s*\(\s*\{[^}]*link\s*:[^}]*HttpLink\s*\([^)]*uri\s*:\s*['"]([^'"]+)['"]''',
    ]

    GRAPHQL_COMMON_PATHS = [
        '/graphql',
        '/api/graphql',
        '/api/v1/graphql',
        '/gql',
        '/query',
        '/api/query',
        '/v1/graphql',
        '/v2/graphql',
        '/graphql/v1',
        '/graphiql',
        '/playground',
        '/graphql/console',
        '/api/graph',
        '/graph',
        '/hasura',
        '/v1/hasura',
        '/v2/hasura',
    ]

    HASURA_PATTERNS = [
        '/v1/graphql',
        '/v2/graphql',
        '/console',
        '/api/rest',
    ]

    APOLLO_PATTERNS = [
        '/graphql',
        '/api/graphql',
        '/graphql/v1',
    ]

    INTROSPECTION_QUERY = '''
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          name
          kind
          description
          fields(includeDeprecated: true) {
            name
            description
            args {
              name
              description
              type {
                name
                kind
              }
              defaultValue
            }
            type {
              name
              kind
            }
            isDeprecated
            deprecationReason
          }
          inputFields {
            name
            description
            type {
              name
              kind
            }
            defaultValue
          }
          enumValues(includeDeprecated: true) {
            name
            description
            isDeprecated
            deprecationReason
          }
        }
        directives {
          name
          description
          locations
          args {
            name
            description
            type {
              name
              kind
            }
            defaultValue
          }
        }
      }
    }
    '''

    TYPENAME_QUERY = '{"query":"{ __typename }"}'

    FALLBACK_QUERIES = [
        '{"query":"{ __schema { queryType { name } } }"}',
        '{"query":"{ __type(name: \"Query\") { name fields { name } } }"}',
        '{"query":"mutation { __typename }"}',
        '{"query":"subscription { __typename }"}',
    ]

    OPERATION_PATTERNS = [
        r'''(?:query|mutation|subscription)\s+(?:(\w+)\s*)?\{''',
        r'''gql\s*`([^`]+)`''',
        r'''useQuery\s*\(\s*`([^`]+)`\s*\)''',
        r'''useMutation\s*\(\s*`([^`]+)`\s*\)''',
        r'''apollo\s*\.\s*(?:query|mutate)\s*\(\s*\{[^}]*query\s*:\s*`([^`]+)`''',
    ]

    def __init__(self):
        self.discovered_schemas: List[GraphQLSchema] = []
        self.discovered_operations: List[DiscoveredOperation] = []
        self._http_client = None

    def set_http_client(self, http_client):
        """设置HTTP客户端"""
        self._http_client = http_client

    async def discover_endpoints(self, base_url: str) -> List[str]:
        """
        发现 GraphQL 端点
        
        Args:
            base_url: 目标基础URL
            
        Returns:
            发现的端点列表
        """
        if not self._http_client:
            return []

        endpoints = []
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in self.GRAPHQL_COMMON_PATHS:
            url = base + path
            if await self._is_graphql_endpoint(url):
                endpoints.append(url)
                logger.info(f"GraphQL endpoint found: {url}")

        if not endpoints:
            for path in self.HASURA_PATTERNS:
                url = base + path
                if await self._is_graphql_endpoint(url):
                    endpoints.append(url)
                    logger.info(f"Hasura endpoint found: {url}")

        return endpoints

    async def _is_graphql_endpoint(self, url: str) -> bool:
        """检查URL是否为GraphQL端点"""
        try:
            for query in [self.TYPENAME_QUERY, self.FALLBACK_QUERIES[0]]:
                response = await self._http_client.request(
                    url,
                    'POST',
                    data=query,
                    headers={'Content-Type': 'application/json'},
                    timeout=10
                )
                if response.status_code == 200:
                    content = response.content
                    if '__typename' in content or '__schema' in content:
                        return True
        except Exception:
            pass
        return False

    async def introspect_schema(self, endpoint: str) -> Optional[GraphQLSchema]:
        """
        获取并解析 GraphQL Schema
        
        Args:
            endpoint: GraphQL 端点 URL
            
        Returns:
            GraphQLSchema 对象，失败返回 None
        """
        schema = GraphQLSchema(endpoint=endpoint)

        introspection_result = await self._send_introspection(endpoint)

        if introspection_result:
            schema.introspection_enabled = True
            schema.raw_schema = introspection_result
            self._parse_schema(schema, introspection_result)
            return schema

        fallback_result = await self._fallback_discovery(endpoint)
        if fallback_result:
            schema.introspection_enabled = False
            schema.queries = fallback_result
            return schema

        return None

    async def _send_introspection(self, endpoint: str) -> Optional[str]:
        """发送 introspection 查询"""
        try:
            response = await self._http_client.request(
                endpoint,
                'POST',
                data=json.dumps({'query': self.INTROSPECTION_QUERY}),
                headers={'Content-Type': 'application/json'},
                timeout=30
            )
            if response.status_code == 200:
                content = response.content
                if '__schema' in content:
                    return content
        except Exception as e:
            logger.debug(f"Introspection failed for {endpoint}: {e}")
        return None

    async def _fallback_discovery(self, endpoint: str) -> Optional[List[Dict]]:
        """
        当 introspection 被禁用时的回退探测
        
        通过发送各种探测查询，从错误响应中推断 schema
        """
        discovered_queries = []

        root_fields_query = '{"query":"{ __schema { queryType { name fields { name type { name kind } } } } }"}'

        try:
            response = await self._http_client.request(
                endpoint,
                'POST',
                data=root_fields_query,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            if response.status_code == 200:
                content = response.content
                if '__schema' in content or 'data' in content:
                    try:
                        data = json.loads(content)
                        if 'data' in data and '__schema' in data['data']:
                            query_type = data['data']['__schema'].get('queryType', {})
                            if 'fields' in query_type:
                                for field in query_type['fields']:
                                    discovered_queries.append({
                                        'name': field.get('name'),
                                        'type': 'query',
                                        'type_name': field.get('type', {}).get('name', 'Unknown')
                                    })
                            return discovered_queries
                    except json.JSONDecodeError:
                        pass

                if 'errors' in content:
                    logger.info(f"Introspection disabled for {endpoint}, using fallback")

        except Exception as e:
            logger.debug(f"Fallback discovery failed: {e}")

        return None

    def _parse_schema(self, schema: GraphQLSchema, introspection_data: str):
        """解析 introspection 结果"""
        try:
            data = json.loads(introspection_data)
            if 'data' not in data or '__schema' not in data['data']:
                return

            s = data['data']['__schema']

            schema.query_type = s.get('queryType', {}).get('name')
            schema.mutation_type = s.get('mutationType', {}).get('name')
            schema.subscription_type = s.get('subscriptionType', {}).get('name')
            schema.types = s.get('types', [])

            query_type_name = schema.query_type
            mutation_type_name = schema.mutation_type

            for t in schema.types:
                if t.get('name') == query_type_name and t.get('kind') == 'OBJECT':
                    for field in t.get('fields', []):
                        schema.queries.append({
                            'name': field.get('name'),
                            'description': field.get('description', ''),
                            'args': [a.get('name') for a in field.get('args', [])],
                            'type': field.get('type', {}).get('name', 'Unknown')
                        })

                if t.get('name') == mutation_type_name and t.get('kind') == 'OBJECT':
                    for field in t.get('fields', []):
                        schema.mutations.append({
                            'name': field.get('name'),
                            'description': field.get('description', ''),
                            'args': [a.get('name') for a in field.get('args', [])],
                            'type': field.get('type', {}).get('name', 'Unknown')
                        })

        except Exception as e:
            logger.warning(f"Schema parsing error: {e}")

    def extract_operations_from_code(self, content: str, endpoint: str = "") -> List[DiscoveredOperation]:
        """
        从 JS/HTML 代码中提取 GraphQL 操作
        
        Args:
            content: JS/HTML 内容
            endpoint: 关联的端点
            
        Returns:
            发现的 operation 列表
        """
        operations = []

        gql_matches = re.findall(r'''gql\s*`([^`]+)`''', content, re.DOTALL)
        for gql_content in gql_matches:
            op = self._parse_gql_operation(gql_content, endpoint, 'js_code')
            if op:
                operations.append(op)

        query_matches = re.findall(
            r'''(?:query|mutation|subscription)\s+(\w+)?\s*\{([^{}]+(?:\{[^{}]+\}[^{}]*)*)\}''',
            content,
            re.DOTALL
        )
        for name, body in query_matches:
            op = self._parse_query_body(name, body, endpoint, 'js_code')
            if op:
                operations.append(op)

        return operations

    def _parse_gql_operation(self, gql_content: str, endpoint: str, source: str) -> Optional[DiscoveredOperation]:
        """解析 gql`...` 模板字符串"""
        lines = gql_content.strip().split('\n')
        op_type = 'query'
        op_name = None
        fields = []
        variables = []

        for line in lines:
            line = line.strip()
            if line.startswith('query '):
                parts = line.split('{')[0].split('(')
                op_name = parts[0].replace('query ', '').strip()
                if '(' in line:
                    vars_match = re.findall(r'(\w+):', parts[1] if len(parts) > 1 else '')
                    variables.extend(vars_match)
                op_type = 'query'
            elif line.startswith('mutation '):
                parts = line.split('{')[0].split('(')
                op_name = parts[0].replace('mutation ', '').strip()
                op_type = 'mutation'
            elif line.startswith('subscription '):
                parts = line.split('{')[0].split('(')
                op_name = parts[0].replace('subscription ', '').strip()
                op_type = 'subscription'

            field_match = re.findall(r'(\w+)', line)
            for f in field_match:
                if f not in ['query', 'mutation', 'subscription', 'fragment', 'on'] and len(f) > 2:
                    if f not in fields:
                        fields.append(f)

        if not fields and not op_name:
            return None

        return DiscoveredOperation(
            name=op_name,
            type=op_type,
            fields=fields,
            variables=variables,
            source=source,
            endpoint=endpoint
        )

    def _parse_query_body(self, name: str, body: str, endpoint: str, source: str) -> Optional[DiscoveredOperation]:
        """解析 query/mutation/subscription 主体"""
        if not name and not body:
            return None

        op_type = 'query'
        if name:
            if name.lower().startswith('mutation'):
                op_type = 'mutation'
            elif name.lower().startswith('subscription'):
                op_type = 'subscription'
                name = None

        fields = re.findall(r'(\w+)', body)
        fields = [f for f in fields if f not in ['query', 'mutation', 'subscription', 'fragment', 'on'] and len(f) > 2]

        return DiscoveredOperation(
            name=name,
            type=op_type,
            fields=list(set(fields)),
            variables=[],
            source=source,
            endpoint=endpoint
        )

    async def test_persisted_queries(self, endpoint: str) -> bool:
        """
        测试是否支持 Persisted Queries (Apollo)
        
        Returns:
            是否支持 APQ
        """
        apq_queries = [
            json.dumps({
                'extensions': {'persistedQuery': {'version': 1, 'sha256Hash': 'abc123'}},
                'query': None
            }),
            json.dumps({
                'id': 'abc123',
                'query': None
            }),
        ]

        for query in apq_queries:
            try:
                response = await self._http_client.request(
                    endpoint,
                    'POST',
                    data=query,
                    headers={'Content-Type': 'application/json'},
                    timeout=10
                )
                if response.status_code == 200:
                    content = response.content
                    if 'PersistedQueryNotFound' in content or 'id' in content.lower():
                        logger.info(f"APQ supported by {endpoint}")
                        return True
            except Exception:
                pass

        return False


class GraphQLOperationExtractor:
    """
    GraphQL 操作提取器
    
    从各种来源提取 GraphQL operations:
    1. JS 文件中的 gql`` 模板
    2. 内联 GraphQL
    3. Apollo Client 配置
    4. Relay Modern 配置
    """

    APOLLO_CLIENT_PATTERNS = [
        r'''ApolloClient\s*\(\s*\{[^}]*?uri\s*:\s*['"]([^'"]+)['"]''',
        r'''ApolloClient\s*\(\s*\{[^}]*?link\s*:[^}]*HttpLink\s*\([^)]*uri\s*:\s*['"]([^'"]+)['"]''',
        r'''createHttpLink\s*\(\s*\{[^}]*?uri\s*:\s*['"]([^'"]+)['"]''',
    ]

    RELAY_PATTERNS = [
        r'''fetchGraphQL\s*\([^)]*query\s*:\s*`([^`]+)`''',
        r'''commitMutation\s*\([^)]*mutation\s*:\s*`([^`]+)`''',
    ]

    HASURA_PATTERNS = [
        r'''hasura\s*\.\s*(?:query|mutation|subscription)''',
        r'''create_hasura_chain''',
    ]

    def __init__(self):
        self.operations: List[DiscoveredOperation] = []

    def extract_from_content(self, content: str, base_url: str = "") -> List[DiscoveredOperation]:
        """从内容中提取所有 GraphQL 操作"""
        operations = []

        gql_pattern = r'''gql\s*`([^`]+)`'''
        for match in re.finditer(gql_pattern, content, re.DOTALL):
            gql_content = match.group(1)
            op = self._parse_gql_template(gql_content, base_url)
            if op:
                operations.append(op)

        apollo_match = re.search(r'''new\s+ApolloClient\s*\(\s*\{''', content)
        if apollo_match:
            endpoint = self._extract_apollo_endpoint(content)
            if endpoint:
                base_url = endpoint

        relay_pattern = r'''(query|mutation|subscription)\s+\w*\s*\{([^{}]+(?:\{[^{}]+\}[^{}]*)*)\}'''
        for match in re.finditer(relay_pattern, content, re.DOTALL):
            op_type = match.group(1).lower()
            body = match.group(2)
            fields = re.findall(r'(\w+)', body)
            operations.append(DiscoveredOperation(
                name=None,
                type=op_type,
                fields=[f for f in fields if len(f) > 2],
                variables=[],
                source='relay',
                endpoint=base_url
            ))

        return operations

    def _parse_gql_template(self, template: str, endpoint: str) -> Optional[DiscoveredOperation]:
        """解析 gql 模板字符串"""
        content = template.strip()

        op_type = 'query'
        op_name = None

        if content.startswith('query'):
            match = re.match(r'query\s+(\w+)?', content)
            if match:
                op_name = match.group(1)
            op_type = 'query'
        elif content.startswith('mutation'):
            match = re.match(r'mutation\s+(\w+)?', content)
            if match:
                op_name = match.group(1)
            op_type = 'mutation'
        elif content.startswith('subscription'):
            match = re.match(r'subscription\s+(\w+)?', content)
            if match:
                op_name = match.group(1)
            op_type = 'subscription'

        field_pattern = r'(\w+)\s*[{(]'
        fields = re.findall(field_pattern, content)
        fields = [f for f in fields if f not in ['query', 'mutation', 'subscription', 'fragment', 'on', 'schema', 'type']]

        if not fields:
            return None

        return DiscoveredOperation(
            name=op_name,
            type=op_type,
            fields=list(set(fields)),
            variables=[],
            source='gql_template',
            endpoint=endpoint
        )

    def _extract_apollo_endpoint(self, content: str) -> Optional[str]:
        """提取 Apollo Client 端点"""
        for pattern in self.APOLLO_CLIENT_PATTERNS:
            match = re.search(pattern, content)
            if match:
                return match.group(1)
        return None


async def enhanced_graphql_discovery(base_url: str, http_client) -> Dict[str, Any]:
    """
    执行增强的 GraphQL 发现
    
    Returns:
        包含发现结果的字典
    """
    discovery = EnhancedGraphQLDiscovery()
    discovery.set_http_client(http_client)

    endpoints = await discovery.discover_endpoints(base_url)

    schemas = []
    for endpoint in endpoints:
        schema = await discovery.introspect_schema(endpoint)
        if schema:
            schemas.append(schema)

    apq_support = False
    if endpoints:
        apq_support = await discovery.test_persisted_queries(endpoints[0])

    return {
        'endpoints': endpoints,
        'schemas': schemas,
        'apq_supported': apq_support,
        'total_found': len(endpoints)
    }
