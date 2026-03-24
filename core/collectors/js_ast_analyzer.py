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
    source_type: str = "ast"
    context: str = ""


@dataclass
class ParsedCall:
    """解析到的函数调用"""
    callee: str
    arguments: List[str]
    full_string: str
    position: int


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
    analyzer = JavaScriptASTAnalyzer()
    analyzer.parse(js_content)
    return analyzer.get_api_paths()
