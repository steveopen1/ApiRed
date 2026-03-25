"""
Inline JavaScript Parser
内联JavaScript解析器 - 从HTML页面中提取内联JS中的API路径
"""

import re
import json
import logging
from typing import Dict, List, Set, Any, Optional, Tuple
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)


class PathValidationConstants:
    """路径验证共享常量"""
    
    SENSITIVE_FILE_PATTERNS = [
        '.pdf', '.xlsx', '.xls', '.docx', '.doc', '.pptx', '.ppt',
        '.exe', '.7z', '.zip', '.rar', '.tar', '.gz',
        '.csv', '.txt', '.log',
        '.bak', '.backup', '.old',
    ]
    
    STATIC_FILE_EXTENSIONS = [
        '.js', '.css', '.html', '.json', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', 
        '.woff', '.woff2', '.ttf', '.eot', '.otf', '.webp', '.bmp', '.tiff', '.webm', '.mp4',
        '.avi', '.mp3', '.wav', '.ogg', '.flac', '.webm',
    ]
    
    INVALID_KEYWORDS = {
        'httpagent', 'httpsagent', 'httpversionnotsupported', 
        'xmlhttprequest', 'activexobject', 'msxml2', 'microsoft',
        'window', 'document', 'location', 'navigator', 'console',
        'function', 'return', 'var', 'let', 'const', 'import', 'export',
        'prototype', 'constructor', 'typeof', 'undefined', 'null',
    }
    
    CONTENT_TYPE_INDICATORS = [
        'text/html', 'application/json', 'text/plain', 'text/xml',
        'text/javascript', 'application/javascript', 'application/x-javascript',
        'image/', 'audio/', 'video/', 'font/',
    ]


class InlineJSParser:
    """
    内联JavaScript解析器
    
    从HTML页面的 <script> 标签内容和内联事件处理器中提取:
    1. API路径 (/api/xxx)
    2. 路由定义 (/user, /admin, etc.)
    3. URL模板 (/user/:id, /order/:id, etc.)
    4. AJAX请求模式
    5. 敏感资源链接 (PDF, Excel, Word, EXE等)
    """
    
    API_PATH_PATTERNS = [
        re.compile(r'''['"`](?:/api)[/a-zA-Z0-9_?&=\-\.%]+['"`]'''),
        re.compile(r'''['"`](?:/v\d+)[/a-zA-Z0-9_?&=\-\.%]+['"`]'''),
        re.compile(r'''['"`](?:/rest)[/a-zA-Z0-9_?&=\-\.%]+['"`]'''),
    ]
    
    ROUTE_PATTERNS = [
        re.compile(r'''router\.push\(['"`]([^\s'"`]+)['"`]'''),
        re.compile(r'''router\.navigateTo\(['"`]([^\s'"`]+)['"`]'''),
        re.compile(r'''location\.href\s*=\s*['"`]([^\s'"`]+)['"`]'''),
        re.compile(r'''window\.open\(['"`]([^\s'"`]+)['"`]'''),
        re.compile(r'''fetch\(['"`]([^\s'"`]+)['"']'''),
        re.compile(r'''axios\.(?:get|post|put|delete)\(['"`]([^\s'"`]+)['"']'''),
        re.compile(r'''\$http\.(?:get|post|put|delete)\(['"`]([^\s'"`]+)['"']'''),
        re.compile(r'''\.(?:get|post|put|delete)\(['"`]([^\s'"`]+)['"']'''),
    ]
    
    URL_TEMPLATE_PATTERN = re.compile(r'''['"](/[a-zA-Z0-9_/:\-{}]+)['"`]''')
    
    CONFIG_PATTERNS = [
        re.compile(r'''baseURL\s*:\s*['"`]([^'"`]+)['"`]'''),
        re.compile(r'''apiBase\s*:\s*['"`]([^'"`]+)['"`]'''),
        re.compile(r'''API_URL\s*=\s*['"`]([^'"`]+)['"`]'''),
        re.compile(r'''VUE_APP_API_URL\s*=\s*['"`]([^'"`]+)['"`]'''),
    ]
    
    SENSITIVE_FILE_PATTERNS = PathValidationConstants.SENSITIVE_FILE_PATTERNS
    STATIC_FILE_EXTENSIONS = PathValidationConstants.STATIC_FILE_EXTENSIONS
    INVALID_KEYWORDS = PathValidationConstants.INVALID_KEYWORDS
    CONTENT_TYPE_INDICATORS = PathValidationConstants.CONTENT_TYPE_INDICATORS
    
    def __init__(self):
        self.extracted_paths: Set[str] = set()
        self.extracted_routes: Set[str] = set()
        self.extracted_templates: Set[str] = set()
        self.extracted_configs: Dict[str, str] = {}
        self.extracted_sensitive_resources: Set[str] = set()
    
    def parse_html(self, html_content: str) -> Dict[str, Set[str]]:
        """
        解析HTML内容，提取内联JavaScript中的路径和路由
        
        Args:
            html_content: HTML页面内容
            
        Returns:
            包含提取结果的字典
        """
        results = {
            'api_paths': set(),
            'routes': set(),
            'url_templates': set(),
            'configs': {},
            'sensitive_resources': set()
        }
        
        script_blocks = self._extract_script_blocks(html_content)
        
        for script_content in script_blocks:
            if not script_content or len(script_content) < 50:
                continue
            
            api_paths, sensitive_resources = self._extract_api_paths(script_content)
            results['api_paths'].update(api_paths)
            results['sensitive_resources'].update(sensitive_resources)
            
            routes = self._extract_routes(script_content)
            results['routes'].update(routes)
            
            templates = self._extract_url_templates(script_content)
            results['url_templates'].update(templates)
            
            configs = self._extract_configs(script_content)
            results['configs'].update(configs)
        
        self.extracted_paths.update(results['api_paths'])
        self.extracted_routes.update(results['routes'])
        self.extracted_templates.update(results['url_templates'])
        self.extracted_configs.update(results['configs'])
        self.extracted_sensitive_resources.update(results['sensitive_resources'])
        
        return results
    
    def _extract_script_blocks(self, html_content: str) -> List[str]:
        """提取所有<script>标签中的内容"""
        scripts = []
        
        script_with_src = re.findall(
            r'<script[^>]*src=["\']([^"\']+)["\'][^>]*>',
            html_content,
            re.IGNORECASE
        )
        
        inline_scripts = re.findall(
            r'<script[^>]*>(.*?)</script>',
            html_content,
            re.DOTALL | re.IGNORECASE
        )
        
        return inline_scripts
    
    def _extract_api_paths(self, script_content: str) -> Tuple[Set[str], Set[str]]:
        """从脚本内容中提取API路径和敏感资源"""
        api_paths = set()
        sensitive_resources = set()
        
        for pattern in self.API_PATH_PATTERNS:
            matches = pattern.findall(script_content)
            for match in matches:
                cleaned = self._clean_path(match)
                if not cleaned:
                    continue
                
                if self._is_sensitive_resource(cleaned):
                    sensitive_resources.add(cleaned)
                elif self._is_valid_api_path(cleaned):
                    api_paths.add(cleaned)
        
        return api_paths, sensitive_resources
    
    def _is_sensitive_resource(self, path: str) -> bool:
        """判断是否为敏感资源文件"""
        if not path:
            return False
        
        path_lower = path.lower()
        for pattern in self.SENSITIVE_FILE_PATTERNS:
            if path_lower.endswith(pattern):
                return True
        
        return False
    
    def _extract_routes(self, script_content: str) -> Set[str]:
        """从脚本内容中提取路由"""
        routes = set()
        
        for pattern in self.ROUTE_PATTERNS:
            matches = pattern.findall(script_content)
            for match in matches:
                cleaned = self._clean_path(match)
                if cleaned and self._is_valid_route(cleaned):
                    routes.add(cleaned)
        
        return routes
    
    def _extract_url_templates(self, script_content: str) -> Set[str]:
        """提取URL模板 (/user/:id 等)"""
        templates = set()
        
        matches = self.URL_TEMPLATE_PATTERN.findall(script_content)
        for match in matches:
            cleaned = self._clean_path(match)
            if cleaned and ':' in cleaned:
                templates.add(cleaned)
        
        return templates
    
    def _extract_configs(self, script_content: str) -> Dict[str, str]:
        """提取API配置"""
        configs = {}
        
        for pattern in self.CONFIG_PATTERNS:
            matches = pattern.findall(script_content)
            for match in matches:
                if match.startswith('http') or match.startswith('/'):
                    configs['api_base'] = match
        
        return configs
    
    def _clean_path(self, path: str) -> str:
        """清理路径字符串"""
        if not path:
            return ""
        
        path = path.strip()
        path = path.lstrip("'\"")
        path = path.rstrip("'\"")
        path = path.split('?')[0]
        path = path.split('#')[0]
        
        if path.startswith('http://'):
            path = path[7:]
        elif path.startswith('https://'):
            path = path[8:]
        
        if '/' in path:
            path = '/' + path.split('/', 1)[1]
        
        return path.strip()
    
    def _is_valid_api_path(self, path: str) -> bool:
        """判断是否为有效的API路径"""
        if not path:
            return False
        
        if len(path) < 2:
            return False
        
        static_file_patterns = ['.js', '.css', '.html', '.json', '.png', '.jpg', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf']
        for pattern in static_file_patterns:
            if path.endswith(pattern):
                return False
        
        return True
    
    def _is_valid_route(self, path: str) -> bool:
        """判断是否为有效的路由"""
        if not path:
            return False
        
        if len(path) < 2:
            return False
        
        if path.startswith('javascript:'):
            return False
        
        if path.startswith('mailto:'):
            return False
        
        if path.startswith('tel:'):
            return False
        
        if path.startswith('data:'):
            return False
        
        return True
    
    def get_all_extracted(self) -> Dict[str, Any]:
        """获取所有提取结果"""
        return {
            'api_paths': list(self.extracted_paths),
            'routes': list(self.extracted_routes),
            'url_templates': list(self.extracted_templates),
            'configs': self.extracted_configs,
            'sensitive_resources': list(self.extracted_sensitive_resources)
        }
    
    def generate_probe_paths(self) -> List[str]:
        """
        生成用于探测的路径列表
        
        从提取的URL模板和路由生成可探测的路径
        例如: /user/:id -> /user/1, /user/admin 等
        """
        probe_paths = []
        
        for template in self.extracted_templates:
            path = template.replace(':id', '1')
            path = path.replace(':name', 'admin')
            path = path.replace(':uuid', '550e8400-e29b-41d4-a716-446655440000')
            probe_paths.append(path)
        
        for route in self.extracted_routes:
            if route not in probe_paths:
                probe_paths.append(route)
        
        for path in self.extracted_paths:
            if path not in probe_paths:
                probe_paths.append(path)
        
        return probe_paths


class ResponseBasedAPIDiscovery:
    """
    基于响应的API发现器
    
    通过分析HTTP响应内容发现新的API端点:
    1. 从HTML响应中提取链接和表单action
    2. 从JSON响应中提取关联的API路径
    3. 从JavaScript响应中提取API调用
    4. 从响应中发现敏感资源链接
    """
    
    HTML_LINK_PATTERN = re.compile(r'''(?:href|src|action)=['"](/[a-zA-Z0-9_/\-.?=&]+)['"']''')
    
    JSON_API_PATTERN = re.compile(r'''['"](/api/[^\s'"`]+)['"`]''')
    
    JS_VAR_PATTERN = re.compile(r'''(?:window|global)\.([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*['"`]([^'"`]+)['"`]''')
    
    SENSITIVE_FILE_PATTERNS = PathValidationConstants.SENSITIVE_FILE_PATTERNS
    STATIC_FILE_EXTENSIONS = PathValidationConstants.STATIC_FILE_EXTENSIONS
    INVALID_KEYWORDS = PathValidationConstants.INVALID_KEYWORDS
    CONTENT_TYPE_INDICATORS = PathValidationConstants.CONTENT_TYPE_INDICATORS
    
    def __init__(self):
        self.discovered_paths: Set[str] = set()
        self.discovered_sensitive_resources: Set[str] = set()
    
    def discover_from_response(self, url: str, content: str, content_type: str) -> Dict[str, Set[str]]:
        """
        从HTTP响应中发现新的API路径和敏感资源
        
        Args:
            url: 响应来源URL
            content: 响应内容
            content_type: Content-Type头
            
        Returns:
            包含api_paths和sensitive_resources的字典
        """
        result = {
            'api_paths': set(),
            'sensitive_resources': set()
        }
        
        if 'html' in content_type.lower():
            paths, sensitive = self._discover_from_html(content)
            result['api_paths'].update(paths)
            result['sensitive_resources'].update(sensitive)
        elif 'json' in content_type.lower():
            paths, sensitive = self._discover_from_json(content)
            result['api_paths'].update(paths)
            result['sensitive_resources'].update(sensitive)
        elif 'javascript' in content_type.lower() or 'script' in content_type.lower():
            paths, sensitive = self._discover_from_js(content)
            result['api_paths'].update(paths)
            result['sensitive_resources'].update(sensitive)
        
        self.discovered_paths.update(result['api_paths'])
        self.discovered_sensitive_resources.update(result['sensitive_resources'])
        return result
    
    def _discover_from_html(self, content: str) -> Tuple[Set[str], Set[str]]:
        """从HTML内容中发现API路径和敏感资源"""
        paths = set()
        sensitive_resources = set()
        
        links = self.HTML_LINK_PATTERN.findall(content)
        for link in links:
            if self._is_sensitive_resource(link):
                sensitive_resources.add(link)
            elif self._is_api_related(link):
                paths.add(link)
        
        forms = re.findall(r'''<form[^>]*action=['"](/[^"']+)['"']''', content, re.IGNORECASE)
        for form_action in forms:
            if self._is_sensitive_resource(form_action):
                sensitive_resources.add(form_action)
            elif self._is_api_related(form_action):
                paths.add(form_action)
        
        ajax_urls = re.findall(r'''(?:url|endpoint|uri)\s*:\s*['"](/[^"']+)['"']''', content, re.IGNORECASE)
        for ajax_url in ajax_urls:
            if self._is_sensitive_resource(ajax_url):
                sensitive_resources.add(ajax_url)
            else:
                paths.add(ajax_url)
        
        return paths, sensitive_resources
    
    def _discover_from_json(self, content: str) -> Tuple[Set[str], Set[str]]:
        """从JSON内容中发现API路径和敏感资源"""
        paths = set()
        sensitive_resources = set()
        
        try:
            data = json.loads(content)
            extracted_paths, extracted_sensitive = self._extract_paths_from_dict(data)
            paths.update(extracted_paths)
            sensitive_resources.update(extracted_sensitive)
        except (json.JSONDecodeError, TypeError):
            api_refs = self.JSON_API_PATTERN.findall(content)
            for ref in api_refs:
                if self._is_sensitive_resource(ref):
                    sensitive_resources.add(ref)
                else:
                    paths.add(ref)
        
        return paths, sensitive_resources
    
    def _extract_paths_from_dict(self, obj: Any, prefix: str = "") -> Tuple[Set[str], Set[str]]:
        """递归从字典中提取路径和敏感资源"""
        paths = set()
        sensitive_resources = set()
        
        if isinstance(obj, dict):
            for key, value in obj.items():
                key_lower = key.lower()
                
                if key_lower in ('url', 'uri', 'endpoint', 'path', 'href', 'src', 'link'):
                    if isinstance(value, str) and value.startswith('/'):
                        if self._is_sensitive_resource(value):
                            sensitive_resources.add(value)
                        else:
                            paths.add(value)
                
                if isinstance(value, (dict, list)):
                    extracted_paths, extracted_sensitive = self._extract_paths_from_dict(value, prefix)
                    paths.update(extracted_paths)
                    sensitive_resources.update(extracted_sensitive)
        
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, (dict, list)):
                    extracted_paths, extracted_sensitive = self._extract_paths_from_dict(item, prefix)
                    paths.update(extracted_paths)
                    sensitive_resources.update(extracted_sensitive)
                elif isinstance(item, str) and item.startswith('/'):
                    if self._is_sensitive_resource(item):
                        sensitive_resources.add(item)
                    elif self._is_api_related(item):
                        paths.add(item)
        
        return paths, sensitive_resources
    
    def _discover_from_js(self, content: str) -> Tuple[Set[str], Set[str]]:
        """从JavaScript内容中发现API路径和敏感资源"""
        paths = set()
        sensitive_resources = set()
        
        api_refs = self.JSON_API_PATTERN.findall(content)
        for ref in api_refs:
            if self._is_sensitive_resource(ref):
                sensitive_resources.add(ref)
            else:
                paths.add(ref)
        
        ajax_patterns = [
            re.compile(r'''\.(?:get|post|put|delete|patch)\(['"](/[^"']+)['"']'''),
            re.compile(r'''fetch\(['"](/[^"']+)['"']'''),
            re.compile(r'''axios\(['"](/[^"']+)['"']'''),
            re.compile(r'''\$http\(['"](/[^"']+)['"']'''),
        ]
        
        for pattern in ajax_patterns:
            matches = pattern.findall(content)
            for match in matches:
                if self._is_sensitive_resource(match):
                    sensitive_resources.add(match)
                else:
                    paths.add(match)
        
        return paths, sensitive_resources
    
    def _is_api_related(self, path: str) -> bool:
        """判断路径是否为有效的Web路径"""
        if not path or len(path) < 2:
            return False
        
        path = path.strip()
        path_lower = path.lower()
        
        if path_lower in self.INVALID_KEYWORDS:
            return False
        
        if '/' not in path and not path_lower.startswith('http'):
            if path_lower not in ['api', 'v1', 'v2', 'v3']:
                return False
        
        for indicator in self.CONTENT_TYPE_INDICATORS:
            if indicator in path_lower:
                return False
        
        for ext in self.STATIC_FILE_EXTENSIONS:
            if path_lower.endswith(ext):
                return False
        
        return True
    
    def _is_sensitive_resource(self, path: str) -> bool:
        """判断是否为敏感资源文件"""
        if not path:
            return False
        
        path_lower = path.lower()
        for pattern in self.SENSITIVE_FILE_PATTERNS:
            if path_lower.endswith(pattern):
                return True
        
        return False
    
    def get_all_discovered(self) -> Dict[str, List[str]]:
        """获取所有发现的新路径和敏感资源"""
        return {
            'api_paths': list(self.discovered_paths),
            'sensitive_resources': list(self.discovered_sensitive_resources)
        }
