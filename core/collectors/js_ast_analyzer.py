"""
JavaScript AST-style Analyzer
基于AST风格的JavaScript解析器
不使用外部JS引擎，通过节点遍历提取API和参数
"""

import re
import logging
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class JSNodeType(Enum):
    """JavaScript节点类型"""
    IMPORT = "import"
    REQUIRE = "require"
    CALL = "call"
    OBJECT = "object"
    STRING = "string"
    TEMPLATE = "template"
    ASSIGNMENT = "assignment"
    EXPORT = "export"


@dataclass
class APIEndpoint:
    """提取到的API端点"""
    path: str
    method: str = "GET"
    params: List[str] = field(default_factory=list)
    param_types: Dict[str, str] = field(default_factory=dict)
    source_type: str = "ast"
    context: str = ""


@dataclass
class ParsedCall:
    """解析到的函数调用"""
    callee: str
    arguments: List[str]
    full_string: str
    position: int


@dataclass
class GraphQLInfo:
    """GraphQL操作信息"""
    operation_type: str  # query, mutation, subscription
    operation_name: str
    fields: List[str]
    variables: Dict[str, str]


@dataclass
class ExtractedConfig:
    """提取到的配置信息"""
    key: str
    value: str
    source: str  # env, cookie, localStorage, config object
    context: str


class JavaScriptASTAnalyzer:
    """
    JavaScript AST风格解析器
    
    通过模拟AST遍历的方式解析JS代码，提取：
    1. API路径 (/api/users, /v1/products等)
    2. 函数调用 (fetch, axios, request, $.ajax等)
    3. 导入语句 (import, require)
    4. 配置对象 ({ baseURL, apiUrl等})
    5. 路由定义 (Vue Router, React Router等)
    6. 参数提取 (路径参数, 查询参数)
    7. GraphQL操作 (query, mutation)
    8. WebSocket端点
    9. 环境变量配置
    10. Cookie/LocalStorage配置
    11. 注释中的API文档
    12. 参数类型推断
    """
    
    API_CALLEE_NAMES = {
        'fetch', 'axios', 'request', '$.ajax', '$.get', '$.post',
        'jQuery.ajax', 'jQuery.get', 'jQuery.post',
        'http.request', 'http.get', 'http.post',
        'vue.$http', 'vue.http',
        'api', 'endpoint', 'resource',
    }
    
    ROUTER_CALLEE_NAMES = {
        'router.push', 'router.replace', 'router.go',
        'this.$router.push', 'this.$router.replace',
        'useNavigate', 'useHistory', 'useLocation',
        'navigate', 'history.push', 'history.replace',
        'Link', 'NavLink', 'Route', 'Routes',
        'createRouter', 'createWebHistory',
    }
    
    VUE_ROUTER_PATTERNS = [
        r'''path\s*:\s*['"`]([^'"`]+)['"']''',
        r'''name\s*:\s*['"`]([^'"`]+)['"']''',
        r'''component\s*:\s*['"`]([^'"`]+)['"']''',
        r'''routes\s*:\s*\[[^\]]+\]''',
        r'''\{[^}]*?path\s*:\s*['"`]([^'"`]+)['"'][^}]*?\}''',
    ]
    
    HISTORY_MODE_PATTERNS = [
        r'''createWebHistory\s*\(\s*['"`]([^'"`]+)['"']''',
        r'''createWebHashHistory\s*\(\s*['"`]([^'"`]+)['"']''',
        r'''history\s*:\s*\(?(?:\s*createWebHistory|createWebHashHistory)''',
        r'''mode\s*:\s*['"`]history['"']''',
        r'''historyType\s*:\s*['"`]history['"']''',
    ]
    
    SSE_PATTERNS = [
        r'''new\s+EventSource\s*\(\s*['"`]([^'"`]+)['"`]''',
        r'''EventSource\s*\(\s*['"`]([^'"`]+)['"`]''',
        r'''source\s*=\s*new\s+EventSource\s*\(\s*['"`]([^'"`]+)['"`]''',
        r'''(?:stream|eventsource|event_source)\s*\(?\s*['"`]([^'"`]+)['"`]''',
    ]
    
    CONFIG_PROPERTY_NAMES = {
        'baseURL', 'baseUrl', 'BASE_URL', 'API_URL', 'apiUrl', 'api_url',
        'apiBase', 'apiBase', 'API_BASE',
        'host', 'domain', 'origin',
        'endpoint', 'ENDPOINT',
    }
    
    def __init__(self):
        self.endpoints: List[APIEndpoint] = []
        self.configs: Dict[str, str] = {}
        self.routes: List[str] = []
        self.imports: List[str] = []
        self.calls: List[ParsedCall] = []
        self.strings: List[str] = []
        self.graphql_operations: List[GraphQLInfo] = []
        self.websocket_endpoints: List[str] = []
        self.env_configs: Dict[str, str] = {}
        self.storage_configs: Dict[str, str] = {}
        self.comments: List[str] = []
        self.swagger_docs: List[Dict] = []
        self.parameter_names: Set[str] = set()
        self.headers: Dict[str, str] = {}
    
    def parse(self, js_content: str) -> 'JavaScriptASTAnalyzer':
        """
        解析JS内容
        
        Args:
            js_content: JavaScript代码内容
            
        Returns:
            self, 支持链式调用
        """
        if not js_content:
            return self
        
        self._extract_all_strings(js_content)
        self._extract_import_statements(js_content)
        self._extract_require_calls(js_content)
        self._extract_api_calls(js_content)
        self._extract_router_calls(js_content)
        self._extract_config_objects(js_content)
        self._extract_template_literals(js_content)
        self._extract_graphql_operations(js_content)
        self._extract_websocket_endpoints(js_content)
        self._extract_env_configs(js_content)
        self._extract_storage_configs(js_content)
        self._extract_comments(js_content)
        self._extract_swagger_docs(js_content)
        self._extract_parameter_names(js_content)
        self._extract_header_configs(js_content)
        
        return self
    
    def _extract_all_strings(self, content: str):
        """提取所有字符串字面量"""
        string_pattern = r'''(?:
            "([^"\\]*(?:\\.[^"\\]*)*)" |
            '([^'\\]*(?:\\.[^'\\]*)*)' |
            `([^`\\]*(?:\\.[^`\\]*)*)`
        )'''
        
        for match in re.finditer(string_pattern, content, re.VERBOSE):
            s = match.group(1) or match.group(2) or match.group(3)
            if s and len(s) > 1:
                self.strings.append(s)
    
    def _extract_import_statements(self, content: str):
        """提取import语句"""
        import_patterns = [
            r'''import\s+(?:\{[^}]+\}|[\w]+)\s+from\s+['"`]([^'"`]+)['"`]''',
            r'''import\s+['"`]([^'"`]+)['"`]''',
            r'''export\s+from\s+['"`]([^'"`]+)['"`]''',
            r'''export\s+\{[^}]+\}\s+from\s+['"`]([^'"`]+)['"`]''',
        ]
        
        for pattern in import_patterns:
            for match in re.finditer(pattern, content):
                module = match.group(1) if match.lastindex and match.group(1) else match.group(0)
                if module and '.js' in module:
                    self.imports.append(module)
    
    def _extract_require_calls(self, content: str):
        """提取require()调用"""
        require_patterns = [
            r'''require\s*\(\s*['"`]([^'"`]+)['"`]\s*\)''',
            r'''require\s*\(\s*\[\s*['"`]([^'"`]+)['"`]\s*\]\s*,\s*[^)]+\)''',
        ]
        
        for pattern in require_patterns:
            for match in re.finditer(pattern, content):
                if match.lastindex:
                    module = match.group(1)
                    if module and '.js' in module:
                        self.imports.append(module)
    
    def _extract_api_calls(self, content: str):
        """提取API调用 (fetch, axios, request等)"""
        api_patterns = [
            (r'''(?:fetch|axios|request)\s*\(\s*['"`]([^'"`]+)['"`]''', 'direct'),
            (r'''(?:axios|api|client)\s*\.\s*(?:get|post|put|delete|patch|head|options)\s*\(\s*['"`]([^'"`]+)['"`]''', 'method'),
            (r'''\$(?:\.ajax|\.get|\.post)\s*\(\s*\{[^}]*?(?:url|data)\s*:\s*['"`]([^'"`]+)['"']''', 'jquery'),
            (r'''(?:url|data|endpoint|path)\s*:\s*['"`]([^'"`]+)['"`]''', 'object_property'),
        ]
        
        for pattern, ptype in api_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                if match.lastindex:
                    url = match.group(1)
                    if self._is_likely_api_path(url):
                        method = self._infer_method_from_pattern(content, match.start())
                        endpoint = APIEndpoint(
                            path=url,
                            method=method,
                            source_type='ast_api_call',
                            context=ptype
                        )
                        self.endpoints.append(endpoint)
    
    def _extract_router_calls(self, content: str):
        """提取路由调用"""
        router_patterns = [
            r'''router\s*\.\s*(?:push|replace|go)\s*\(\s*['"`]([^'"`]+)['"`]''',
            r'''this\s*\.\s*\$router\s*\.\s*(?:push|replace|go)\s*\(\s*['"`]([^'"`]+)['"`]''',
            r'''navigate\s*\(\s*['"`]([^'"`]+)['"`]''',
            r'''history\s*\.\s*(?:push|replace)\s*\(\s*['"`]([^'"`]+)['"`]''',
            r'''<Link[^>]*to\s*=\s*['"`]([^'"`]+)['"`]''',
            r'''<Route[^>]*path\s*=\s*['"`]([^'"`]+)['"`]''',
            r'''<NavLink[^>]*to\s*=\s*['"`]([^'"`]+)['"`]''',
        ]
        
        for pattern in router_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                if match.lastindex:
                    path = match.group(1)
                    if path and not path.startswith('javascript:'):
                        self.routes.append(path)
        
        self._extract_vue_router_config(content)
        self._extract_history_mode_base(content)
        self._extract_sse_endpoints(content)
    
    def _extract_vue_router_config(self, content: str):
        """提取 Vue Router 配置中的路由"""
        for pattern in self.VUE_ROUTER_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                if match.lastindex:
                    path = match.group(1)
                    if path and not path.startswith('javascript:') and len(path) > 1:
                        if path.startswith('/') or path.startswith('./'):
                            self.routes.append(path)
    
    def _extract_history_mode_base(self, content: str):
        """提取 History Mode 路由基础路径"""
        for pattern in self.HISTORY_MODE_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                if match.lastindex:
                    base_path = match.group(1)
                    if base_path:
                        self.configs['historyModeBase'] = base_path
    
    def _extract_sse_endpoints(self, content: str):
        """提取 Server-Sent Events 端点"""
        for pattern in self.SSE_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                if match.lastindex:
                    endpoint = match.group(1)
                    if endpoint and len(endpoint) > 3:
                        self.websocket_endpoints.append(f"SSE:{endpoint}")
    
    def _extract_config_objects(self, content: str):
        """提取配置对象"""
        config_patterns = [
            r'''(?:baseURL|baseUrl|BASE_URL|API_URL|apiUrl)\s*[:=]\s*['"`]([^'"`]+)['"`]''',
            r'''(?:host|domain|origin)\s*[:=]\s*['"`]([^'"`]+)['"`]''',
            r'''(?:endpoint|ENDPOINT)\s*[:=]\s*['"`]([^'"`]+)['"`]''',
        ]
        
        for pattern in config_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                if match.lastindex:
                    value = match.group(1)
                    if value:
                        prop_name = self._extract_property_name(content, match.start())
                        if prop_name:
                            self.configs[prop_name] = value
    
    def _extract_template_literals(self, content: str):
        """提取模板字符串中的路径"""
        template_pattern = r'''`[^`]*\$\{[^}]+\}[^`]*`'''
        
        for match in re.finditer(template_pattern, content):
            template = match.group(0)
            if 'api' in template.lower() or 'url' in template.lower():
                self._parse_template_path(template)
    
    def _parse_template_path(self, template: str):
        """解析模板字符串提取路径"""
        path_pattern = r'''\$\{[^}]+\}|\?[^\$]+|\&[^\$]+'''
        cleaned = re.sub(path_pattern, '', template)
        cleaned = cleaned.strip('`')
        
        if self._is_likely_api_path(cleaned):
            endpoint = APIEndpoint(
                path=cleaned,
                method='GET',
                source_type='ast_template',
                context='template_literal'
            )
            self.endpoints.append(endpoint)
    
    def _extract_graphql_operations(self, content: str):
        """提取GraphQL操作"""
        query_patterns = [
            r'''gql\s*`([^`]+)`''',
            r'''(?:query|mutation|subscription)\s*\{[^}]*?(?:query|mutation|subscription)\s*\{''',
            r'''operation(?:Type|Name)\s*[:=]\s*['"`]([^'"`]+)['"']''',
        ]
        
        for pattern in query_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                gql_content = match.group(0) if match.lastindex == 0 else match.group(1)
                if gql_content:
                    self._parse_graphql_operation(gql_content)
    
    def _parse_graphql_operation(self, gql_content: str):
        """解析GraphQL操作"""
        op_type = 'query'
        if gql_content.strip().startswith('mutation'):
            op_type = 'mutation'
        elif gql_content.strip().startswith('subscription'):
            op_type = 'subscription'
        
        name_match = re.search(r'(?:operation\s+)?(\w+)\s*\(', gql_content)
        op_name = name_match.group(1) if name_match else 'anonymous'
        
        fields = []
        field_pattern = r'(\w+)(?:\s*\{|\s*\()'
        for fm in re.finditer(field_pattern, gql_content):
            fields.append(fm.group(1))
        
        graphql_info = GraphQLInfo(
            operation_type=op_type,
            operation_name=op_name,
            fields=fields,
            variables={}
        )
        self.graphql_operations.append(graphql_info)
    
    def _extract_websocket_endpoints(self, content: str):
        """提取WebSocket端点"""
        ws_patterns = [
            r'''new\s+WebSocket\s*\(\s*['"`]([^'"`]+)['"`]''',
            r'''socket\s*\.\s*(?:connect|emit)\s*\(\s*['"`]([^'"`]+)['"`]''',
            r'''io\s*\(\s*['"`]([^'"`]+)['"`]''',
            r'''ws\s*:\s*['"`]([^'"`]+)['"`]''',
            r'''websocket\s*:\s*['"`]([^'"`]+)['"`]''',
            r'''endpoint\s*:\s*['"`](ws[s]?://[^'"`]+)['"`]''',
        ]
        
        for pattern in ws_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                if match.lastindex:
                    endpoint = match.group(1)
                    if endpoint and len(endpoint) > 3:
                        self.websocket_endpoints.append(endpoint)
    
    def _extract_env_configs(self, content: str):
        """提取环境变量配置"""
        env_patterns = [
            r'''process\.env\.([A-Z_][A-Z0-9_]*)\s*=\s*['"`]([^'"`]+)['"`]''',
            r'''VUE_APP_([A-Z_][A-Z0-9_]*)\s*=\s*['"`]([^'"`]+)['"`]''',
            r'''REACT_APP_([A-Z_][A-Z0-9_]*)\s*=\s*['"`]([^'"`]+)['"`]''',
            r'''NEXT_PUBLIC_([A-Z_][A-Z0-9_]*)\s*=\s*['"`]([^'"`]+)['"`]''',
            r'''([A-Z_][A-Z0-9_]*)\s*=\s*['"`](?:https?://[^'"`]+)['"`]''',
        ]
        
        for pattern in env_patterns:
            for match in re.finditer(pattern, content):
                if match.lastindex is not None and match.lastindex >= 2:
                    key = match.group(1)
                    value = match.group(2)
                    self.env_configs[key] = value
                elif match.lastindex == 1:
                    self.env_configs[match.group(1)] = match.group(1)
    
    def _extract_storage_configs(self, content: str):
        """提取LocalStorage/SessionStorage配置"""
        storage_patterns = [
            r'''(?:localStorage|sessionStorage)\s*\.\s*(?:setItem|getItem)\s*\(\s*['"`]([^'"`]+)['"`]''',
            r'''(?:cookie)\s*\.\s*(?:get|set)\s*\(\s*['"`]([^'"`]+)['"`]''',
            r'''(?:set|get)Cookie\s*\(\s*['"`]([^'"`]+)['"`]''',
        ]
        
        for pattern in storage_patterns:
            for match in re.finditer(pattern, content):
                if match.lastindex:
                    key = match.group(1) if match.lastindex >= 1 else match.group(0)
                    if key:
                        self.storage_configs[key] = key
    
    def _extract_comments(self, content: str):
        """提取JS注释中的API文档"""
        single_line_pattern = r'''//\s*(.*api[^\n]*)'''
        multi_line_pattern = r'''/\*\s*([^*]*api[^*]*)\*/'''
        html_comment_pattern = r'''<!--([^-]*(?:api[^-]*){1,3})-->'''
        
        for pattern in [single_line_pattern, multi_line_pattern, html_comment_pattern]:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                comment_text = match.group(1) if match.lastindex else match.group(0)
                if comment_text:
                    self.comments.append(comment_text.strip())
    
    def _extract_swagger_docs(self, content: str):
        """提取Swagger/OpenAPI注解"""
        swagger_patterns = [
            r'''@Operation\([^)]+\)\s*\{[^}]*?(?:summary|description)\s*[:=]\s*['"`]([^'"`]+)['"']''',
            r'''@ApiModel\([^)]*\)\s*@ApiModelProperty\([^)]+\)''',
            r'''/\*\*\s*@api\s+([^/*]+?)(?:\*/|$)''',
            r'''\*\s+@api\s+([^\n]+)''',
        ]
        
        for pattern in swagger_patterns:
            for match in re.finditer(pattern, content):
                if match.lastindex:
                    doc_text = match.group(match.lastindex)
                    self.swagger_docs.append({
                        'text': doc_text.strip() if doc_text else '',
                        'context': match.group(0)[:100]
                    })
    
    def _extract_parameter_names(self, content: str):
        """提取参数名"""
        param_patterns = [
            r'''(?:params|data|payload|body|query|headers)\s*:\s*\{[^}]*?(\w+)[\?:]''',
            r'''function\s*\([^)]*?(\w+)''',
            r'''=>\s*\([^)]*?(\w+)''',
            r'''\.param\s*\(\s*['"`]([^'"`]+)['"`]''',
            r'''\.query\s*\(\s*\{[^}]*?(\w+)''',
            r'''url\s*:\s*['"`]([^'"`]+\{[^}]+\})[^'"`]*['"']''',
        ]
        
        for pattern in param_patterns:
            for match in re.finditer(pattern, content):
                if match.lastindex:
                    param_name = match.group(match.lastindex)
                    if param_name and len(param_name) > 1:
                        self.parameter_names.add(param_name)
        
        path_param_pattern = r'''\{([^}]+)\}'''
        for match in re.finditer(path_param_pattern, content):
            param = match.group(1)
            if param and len(param) > 0:
                self.parameter_names.add(param)
    
    def _extract_header_configs(self, content: str):
        """提取HTTP头配置"""
        header_patterns = [
            r'''(['"])([\w-]+)\1\s*:\s*['"`]([^'"`]+)['"']''',
            r'''Content-Type\s*:\s*['"`]([^'"`]+)['"']''',
            r'''Authorization\s*:\s*['"`]([^'"`]+)['"']''',
            r'''([\w-]+)\s*:\s*['"`]([^'"`]+)['"']''',
        ]
        
        for pattern in header_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                if match.lastindex is not None and match.lastindex >= 2:
                    header_name = match.group(2)
                    header_value = match.group(3) if match.lastindex >= 3 else match.group(0)
                    self.headers[header_name] = header_value
                elif match.lastindex == 1:
                    header_text = match.group(1)
                    if ':' in header_text:
                        parts = header_text.split(':', 1)
                        if len(parts) == 2:
                            self.headers[parts[0].strip()] = parts[1].strip()
    
    def _is_likely_api_path(self, s: str) -> bool:
        """判断是否可能是API路径"""
        if not s or len(s) < 2:
            return False
        
        if s.startswith('http://') or s.startswith('https://'):
            return True
        
        if not s.startswith('/') and not s.startswith('./'):
            return False
        
        invalid_ext = ('.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', 
                       '.ico', '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3')
        if any(s.lower().endswith(ext) for ext in invalid_ext):
            return False
        
        if any(c in s for c in ['(', ')', '<', '>', '{', '}', '[', ']']):
            return False
        
        api_indicators = ['api', 'v1', 'v2', 'v3', 'rest', 'graphql', 'rpc',
                          'user', 'admin', 'login', 'logout', 'auth',
                          'product', 'order', 'item', 'category', 'config',
                          'menu', 'role', 'permission', 'dict', 'system']
        
        s_lower = s.lower()
        return any(ind in s_lower for ind in api_indicators)
    
    def _infer_method_from_pattern(self, content: str, position: int) -> str:
        """根据上下文推断HTTP方法"""
        before = content[max(0, position-50):position].lower()
        
        if '.get' in before or 'get(' in before:
            return 'GET'
        elif '.post' in before or 'post(' in before:
            return 'POST'
        elif '.put' in before or 'put(' in before:
            return 'PUT'
        elif '.delete' in before or 'delete(' in before:
            return 'DELETE'
        elif '.patch' in before or 'patch(' in before:
            return 'PATCH'
        elif '.head' in before or 'head(' in before:
            return 'HEAD'
        
        return 'GET'
    
    def _extract_property_name(self, content: str, position: int) -> Optional[str]:
        """提取属性名"""
        before = content[max(0, position-30):position]
        match = re.search(r'''([\w]+)\s*[:=]''', before)
        return match.group(1) if match else None
    
    def get_endpoints(self) -> List[APIEndpoint]:
        """获取所有提取的API端点"""
        return self.endpoints
    
    def get_api_paths(self) -> List[str]:
        """获取所有API路径"""
        return list(set(ep.path for ep in self.endpoints))
    
    def get_routes(self) -> List[str]:
        """获取所有路由"""
        return list(set(self.routes))
    
    def get_configs(self) -> Dict[str, str]:
        """获取所有配置"""
        return self.configs.copy()
    
    def get_imports(self) -> List[str]:
        """获取所有导入模块"""
        return list(set(self.imports))


class JSASTDifferentialAnalyzer:
    """
    JavaScript AST差分分析器
    
    通过对比两份JS内容，提取新增的API和路由
    用于增量扫描和变更检测
    """
    
    def __init__(self):
        self.baseline_analyzer = JavaScriptASTAnalyzer()
        self.current_analyzer = JavaScriptASTAnalyzer()
    
    def set_baseline(self, js_content: str):
        """设置基线版本"""
        self.baseline_analyzer = JavaScriptASTAnalyzer()
        self.baseline_analyzer.parse(js_content)
    
    def analyze_diff(self, js_content: str) -> Dict[str, Any]:
        """
        分析与基线的差异
        
        Returns:
            {
                'new_paths': [...],
                'removed_paths': [...],
                'new_routes': [...],
                'new_configs': {...}
            }
        """
        self.current_analyzer = JavaScriptASTAnalyzer()
        self.current_analyzer.parse(js_content)
        
        baseline_paths = set(self.baseline_analyzer.get_api_paths())
        current_paths = set(self.current_analyzer.get_api_paths())
        
        baseline_routes = set(self.baseline_analyzer.get_routes())
        current_routes = set(self.current_analyzer.get_routes())
        
        baseline_configs = self.baseline_analyzer.get_configs()
        current_configs = self.current_analyzer.get_configs()
        
        return {
            'new_paths': list(current_paths - baseline_paths),
            'removed_paths': list(baseline_paths - current_paths),
            'new_routes': list(current_routes - baseline_routes),
            'new_configs': {k: v for k, v in current_configs.items() 
                          if k not in baseline_configs or baseline_configs[k] != v},
            'all_current_paths': list(current_paths),
            'all_current_routes': list(current_routes),
        }


def extract_api_paths_from_js(js_content: str) -> List[str]:
    """
    便捷函数：从JS内容中提取API路径
    
    Args:
        js_content: JavaScript代码
        
    Returns:
        API路径列表
    """
    analyzer = JavaScriptAnalyzer()
    analyzer.parse(js_content)
    return analyzer.get_api_paths()


def JavaScriptAnalyzer(content: Optional[str] = None):
    """
    JavaScript综合分析器
    
    整合所有提取能力，返回完整分析结果
    """
    analyzer = JavaScriptASTAnalyzer()
    if content:
        analyzer.parse(content)
    return analyzer


def extract_all_from_js(js_content: str) -> Dict[str, Any]:
    """
    从JS中提取所有信息
    
    Returns:
        包含所有提取信息的字典
    """
    analyzer = JavaScriptASTAnalyzer()
    analyzer.parse(js_content)
    
    return {
        'endpoints': analyzer.get_endpoints(),
        'api_paths': analyzer.get_api_paths(),
        'routes': analyzer.get_routes(),
        'imports': analyzer.get_imports(),
        'configs': analyzer.get_configs(),
        'graphql': analyzer.graphql_operations,
        'websocket': analyzer.websocket_endpoints,
        'env_configs': analyzer.env_configs,
        'storage_configs': analyzer.storage_configs,
        'comments': analyzer.comments,
        'swagger_docs': analyzer.swagger_docs,
        'parameters': list(analyzer.parameter_names),
        'headers': analyzer.headers,
    }


def extract_parameter_names(js_content: str) -> Set[str]:
    """提取参数名"""
    analyzer = JavaScriptASTAnalyzer()
    analyzer._extract_parameter_names(js_content)
    return analyzer.parameter_names


def extract_env_configs(js_content: str) -> Dict[str, str]:
    """提取环境变量配置"""
    analyzer = JavaScriptASTAnalyzer()
    analyzer._extract_env_configs(js_content)
    return analyzer.env_configs


def extract_websocket_endpoints(js_content: str) -> List[str]:
    """提取WebSocket端点"""
    analyzer = JavaScriptASTAnalyzer()
    analyzer._extract_websocket_endpoints(js_content)
    return analyzer.websocket_endpoints
