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


class InlineJSParser:
    """
    内联JavaScript解析器
    
    从HTML页面的 <script> 标签内容和内联事件处理器中提取:
    1. API路径 (/api/xxx)
    2. 路由定义 (/user, /admin, etc.)
    3. URL模板 (/user/:id, /order/:id, etc.)
    4. AJAX请求模式
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
    
    def __init__(self):
        self.extracted_paths: Set[str] = set()
        self.extracted_routes: Set[str] = set()
        self.extracted_templates: Set[str] = set()
        self.extracted_configs: Dict[str, str] = {}
    
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
            'configs': {}
        }
        
        script_blocks = self._extract_script_blocks(html_content)
        
        for script_content in script_blocks:
            if not script_content or len(script_content) < 50:
                continue
            
            api_paths = self._extract_api_paths(script_content)
            results['api_paths'].update(api_paths)
            
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
    
    def _extract_api_paths(self, script_content: str) -> Set[str]:
        """从脚本内容中提取API路径"""
        paths = set()
        
        for pattern in self.API_PATH_PATTERNS:
            matches = pattern.findall(script_content)
            for match in matches:
                cleaned = self._clean_path(match)
                if cleaned and self._is_valid_api_path(cleaned):
                    paths.add(cleaned)
        
        return paths
    
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
        
        return path.strip()
    
    def _is_valid_api_path(self, path: str) -> bool:
        """判断是否为有效的API路径"""
        if not path:
            return False
        
        if len(path) < 2:
            return False
        
        invalid_patterns = ['.js', '.css', '.html', '.json', '.png', '.jpg', '.gif', '.svg']
        for pattern in invalid_patterns:
            if path.endswith(pattern):
                return False
        
        return True
    
    def _is_valid_route(self, path: str) -> bool:
        """判断是否为有效的路由"""
        if not path:
            return False
        
        if len(path) < 2:
            return False
        
        if path.startswith('http'):
            return False
        
        if path.startswith('javascript:'):
            return False
        
        return True
    
    def get_all_extracted(self) -> Dict[str, Any]:
        """获取所有提取结果"""
        return {
            'api_paths': list(self.extracted_paths),
            'routes': list(self.extracted_routes),
            'url_templates': list(self.extracted_templates),
            'configs': self.extracted_configs
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
    """
    
    HTML_LINK_PATTERN = re.compile(r'''(?:href|src|action)=['"](/[a-zA-Z0-9_/\-.?=&]+)['"']''')
    
    JSON_API_PATTERN = re.compile(r'''['"](/api/[^\s'"`]+)['"`]''')
    
    JS_VAR_PATTERN = re.compile(r'''(?:window|global)\.([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*['"`]([^'"`]+)['"`]''')
    
    def __init__(self):
        self.discovered_paths: Set[str] = set()
    
    def discover_from_response(self, url: str, content: str, content_type: str) -> Set[str]:
        """
        从HTTP响应中发现新的API路径
        
        Args:
            url: 响应来源URL
            content: 响应内容
            content_type: Content-Type头
            
        Returns:
            发现的新路径集合
        """
        new_paths = set()
        
        if 'html' in content_type.lower():
            new_paths.update(self._discover_from_html(content))
        elif 'json' in content_type.lower():
            new_paths.update(self._discover_from_json(content))
        elif 'javascript' in content_type.lower() or 'script' in content_type.lower():
            new_paths.update(self._discover_from_js(content))
        
        self.discovered_paths.update(new_paths)
        return new_paths
    
    def _discover_from_html(self, content: str) -> Set[str]:
        """从HTML内容中发现API路径"""
        paths = set()
        
        links = self.HTML_LINK_PATTERN.findall(content)
        for link in links:
            if self._is_api_related(link):
                paths.add(link)
        
        forms = re.findall(r'''<form[^>]*action=['"](/[^"']+)['"']''', content, re.IGNORECASE)
        for form_action in forms:
            if self._is_api_related(form_action):
                paths.add(form_action)
        
        ajax_urls = re.findall(r'''(?:url|endpoint|uri)\s*:\s*['"](/[^"']+)['"']''', content, re.IGNORECASE)
        for ajax_url in ajax_urls:
            paths.add(ajax_url)
        
        return paths
    
    def _discover_from_json(self, content: str) -> Set[str]:
        """从JSON内容中发现API路径"""
        paths = set()
        
        try:
            data = json.loads(content)
            paths.update(self._extract_paths_from_dict(data))
        except (json.JSONDecodeError, TypeError):
            api_refs = self.JSON_API_PATTERN.findall(content)
            for ref in api_refs:
                paths.add(ref)
        
        return paths
    
    def _extract_paths_from_dict(self, obj: Any, prefix: str = "") -> Set[str]:
        """递归从字典中提取路径"""
        paths = set()
        
        if isinstance(obj, dict):
            for key, value in obj.items():
                key_lower = key.lower()
                
                if key_lower in ('url', 'uri', 'endpoint', 'path', 'href', 'src', 'link'):
                    if isinstance(value, str) and value.startswith('/'):
                        paths.add(value)
                
                if isinstance(value, (dict, list)):
                    paths.update(self._extract_paths_from_dict(value, prefix))
        
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, (dict, list)):
                    paths.update(self._extract_paths_from_dict(item, prefix))
                elif isinstance(item, str) and item.startswith('/') and self._is_api_related(item):
                    paths.add(item)
        
        return paths
    
    def _discover_from_js(self, content: str) -> Set[str]:
        """从JavaScript内容中发现API路径"""
        paths = set()
        
        api_refs = self.JSON_API_PATTERN.findall(content)
        paths.update(api_refs)
        
        ajax_patterns = [
            re.compile(r'''\.(?:get|post|put|delete|patch)\(['"](/[^"']+)['"']'''),
            re.compile(r'''fetch\(['"](/[^"']+)['"']'''),
            re.compile(r'''axios\(['"](/[^"']+)['"']'''),
            re.compile(r'''\$http\(['"](/[^"']+)['"']'''),
        ]
        
        for pattern in ajax_patterns:
            matches = pattern.findall(content)
            paths.update(matches)
        
        return paths
    
    def _is_api_related(self, path: str) -> bool:
        """判断路径是否与API相关"""
        if not path or len(path) < 2:
            return False
        
        path_lower = path.lower()
        
        api_indicators = ['/api', '/v1', '/v2', '/v3', '/rest', '/graphql', '/rpc']
        for indicator in api_indicators:
            if indicator in path_lower:
                return True
        
        if path_lower.startswith('/admin') or path_lower.startswith('/user'):
            return True
        
        return False
    
    def get_all_discovered(self) -> List[str]:
        """获取所有发现的新路径"""
        return list(self.discovered_paths)
