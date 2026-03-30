"""
Inline JavaScript Parser
内联JavaScript解析器 - 从HTML页面中提取内联JS中的API路径
参考 0x727/ChkApi apiPathFind.py 的高性能正则匹配模式
"""

import re
import json
import logging
from typing import Dict, List, Set, Any, Optional, Tuple
from urllib.parse import urljoin, urlparse
from functools import lru_cache

try:
    import regex  # type: ignore
    HAS_REGEX = True
except ImportError:
    HAS_REGEX = False
    regex = re

try:
    import tldextract
    HAS_TLDEXTRACT = True
except ImportError:
    HAS_TLDEXTRACT = False
    tldextract = None

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
    
    API_ROOT_BLACKLIST = [
        '\\', '$', '@', '*', '+', '-', '|', '!', '%', '^', '~',
        '[', ']', '(', ')', '{', '}', '<', '>',
    ]


@lru_cache(maxsize=1)
def _get_compiled_api_pattern():
    """
    预编译所有 API 匹配模式为单一复合正则表达式
    参考 0x727/ChkApi apiPathFind.py 的 get_compiled_api_pattern
    使用 regex 库的命名组来区分不同模式的匹配结果
    """
    if HAS_REGEX:
        api_patterns = [
            r'(?P<full_url_quoted>["\']http[^\s\'\'"\>\<\)\(]{2,250}?["\'])',
            r'(?P<full_url_assign>=https?://[^\s\'\'"\>\<\)\(]{2,250})',
            r'(?P<relative_root>["\']/[^\s\'\'"\>\<\:\)\(\u4e00-\u9fa5]{1,250}?["\'])',
            r'(?P<relative_path>["\'][^\s\'\'"\>\<\:\)\(\u4e00-\u9fa5]{1,250}?/[^\s\'\'"\>\<\:\)\(\u4e00-\u9fa5]{1,250}?/[^\s\'\'"\>\<\:\)\(\u4e00-\u9fa5]{1,250}?["\'])',
            r'(?P<path_colon>(?<=path:)\s?["\'][^\s\'\'"\>\<\:\)\(\u4e00-\u9fa5]{1,250}?["\'])',
            r'(?P<path_colon_space>(?<=path\s:)\s?["\'][^\s\'\'"\>\<\:\)\(\u4e00-\u9fa5]{1,250}?["\'])',
            r'(?P<path_eq>(?<=path=)\s?["\'][^\s\'\'"\>\<\:\)\(\u4e00-\u9fa5]{1,250}?["\'])',
            r'(?P<path_eq_space>(?<=path\s=)\s?["\'][^\s\'\'"\>\<\:\)\(\u4e00-\u9fa5]{1,250}?["\'])',
            r'(?P<url_colon>(?<=url:)\s?["\'][^\s\'\'"\>\<\:\)\(\u4e00-\u9fa5]{1,250}?["\'])',
            r'(?P<url_colon_space>(?<=url\s:)\s?["\'][^\s\'\'"\>\<\:\)\(\u4e00-\u9fa5]{1,250}?["\'])',
            r'(?P<url_eq>(?<=url=)\s?["\'][^\s\'\'"\>\<\:\)\(\u4e00-\u9fa5]{1,250}?["\'])',
            r'(?P<url_eq_space>(?<=url\s=)\s?["\'][^\s\'\'"\>\<\:\)\(\u4e00-\u9fa5]{1,250}?["\'])',
            r'(?P<index_colon>(?<=index:)\s?["\'][^\s\'\'"\>\<\:\)\(\u4e00-\u9fa5]{1,250}?["\'])',
            r'(?P<index_colon_space>(?<=index\s:)\s?["\'][^\s\'\'"\>\<\:\)\(\u4e00-\u9fa5]{1,250}?["\'])',
            r'(?P<index_eq>(?<=index=)\s?["\'][^\s\'\'"\>\<\:\)\(\u4e00-\u9fa5]{1,250}?["\'])',
            r'(?P<index_eq_space>(?<=index\s=)\s?["\'][^\s\'\'"\>\<\:\)\(\u4e00-\u9fa5]{1,250}?["\'])',
            r'(?P<href_action_quoted>(?:href|action).{0,3}=.{0,3}["\'][^\s\'\'"\>\<\)\(]{2,250})',
            r'(?P<href_action_unquoted>(?:href|action).{0,3}=.{0,3}[^\s\'\'"\>\<\)\(]{2,250})',
            r'(?P<path_slash>(?:"|\'|`)(/[^"\'`<>]+)(?:"|\'|`))',
            r'(?P<api_root_relative>["\'](?:api/|v\d+/)[^\s\'\'"\>\<\)\(]{0,250}["\'])',
            r'(?P<plugin_rel_or_dot>(?:"|\'|`)(?:\/|\.{1,2}\/)[^"\'`<>\s]{1,250}(?:"|\'|`))',
            r'(?P<plugin_hash_router>(?:"|\'|`)(?:\/#\/)[^"\'`<>\s]{1,250}(?:"|\'|`))',
            r'(?P<plugin_var_prefix>(?:"|\'|`)[A-Za-z0-9_]+\/[^"\'`<>\s]{1,250}(?:"|\'|`))',
        ]
        combined_pattern = r'|'.join(f'(?:{p})' for p in api_patterns)
        return regex.compile(combined_pattern, regex.IGNORECASE)
    else:
        api_patterns = [
            r'(["\'])(http[^\s\'\'"\>\<\)\(]{2,250}?)\1',
            r'(=)(https?://[^\s\'\'"\>\<\)\(]{2,250})',
            r'(["\'])(/[^\s\'\'"\>\<\:\)\(]{1,250}?)\1',
            r'(path:)\s?(["\'])([^\s\'\'"\>\<\:\)]{1,250}?)\2',
            r'(path\s:)\s?(["\'])([^\s\'\'"\>\<\:\)]{1,250}?)\2',
            r'(path=)\s?(["\'])([^\s\'\'"\>\<\:\)]{1,250}?)\2',
            r'(path\s=)\s?(["\'])([^\s\'\'"\>\<\:\)]{1,250}?)\2',
            r'(url:)\s?(["\'])([^\s\'\'"\>\<\:\)]{1,250}?)\2',
            r'(url\s:)\s?(["\'])([^\s\'\'"\>\<\:\)]{1,250}?)\2',
            r'(url=)\s?(["\'])([^\s\'\'"\>\<\:\)]{1,250}?)\2',
            r'(url\s=)\s?(["\'])([^\s\'\'"\>\<\:\)]{1,250}?)\2',
            r'(index:)\s?(["\'])([^\s\'\'"\>\<\:\)]{1,250}?)\2',
            r'(index\s:)\s?(["\'])([^\s\'\'"\>\<\:\)]{1,250}?)\2',
            r'(index=)\s?(["\'])([^\s\'\'"\>\<\:\)]{1,250}?)\2',
            r'(index\s=)\s?(["\'])([^\s\'\'"\>\<\:\)]{1,250}?)\2',
            r'(?:href|action).{0,3}=.{0,3}(["\'])([^\s\'\'"\>\<\)]{2,250})\1',
            r'(?:"|\'|`)((?:/|\.{1,2}\/)[^"\'`<>\s]{1,250})(?:"|\'|`)',
            r'(?:"|\'|`)((?:api/|v\d+/)[^"\'`<>\s]{0,250})(?:"|\'|`)',
        ]
        combined_pattern = r'|'.join(f'(?:{p})' for p in api_patterns)
        return re.compile(combined_pattern, re.IGNORECASE)


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
        re.compile(r'''['"`](/(?:api|prod-api|test-api|pre-api|rest|api-test|v\d+|graphql|rpc|gateway|swagger|openapi)(?:[/a-zA-Z0-9_?&=\-\.%]+|/?))['"`]'''),
        re.compile(r'''['"`](/(?:admin|management|api-admin|console|dashboard)(?:[/a-zA-Z0-9_?&=\-\.%]+|/?))['"`]'''),
        re.compile(r'''['"`](/(?:sys-[a-z]+-api|sys/[a-z]+|ums|oauth|auth|login|passport)(?:[/a-zA-Z0-9_?&=\-\.%]+|/?))['"`]'''),
        re.compile(r'''['"`](/(?:service|services|app|application|web|open)(?:[/a-zA-Z0-9_?&=\-\.%]+|/?))['"`]'''),
        re.compile(r'''['"`](/(?:data|datas|file|files|content|contents|resource|resources)(?:[/a-zA-Z0-9_?&=\-\.%]+|/?))['"`]'''),
        re.compile(r'''['"`](/(?:user|users|customer|customers|account|member|members|client|clients)(?:[/a-zA-Z0-9_?&=\-\.%]+|/?))['"`]'''),
        re.compile(r'''['"`](/(?:order|orders|product|products|item|items|cart|shop)(?:[/a-zA-Z0-9_?&=\-\.%]+|/?))['"`]'''),
        re.compile(r'''['"`](/(?:upload|download|export|import|backup|config|cfg|setting|settings)(?:[/a-zA-Z0-9_?&=\-\.%]+|/?))['"`]'''),
        re.compile(r'''['"`](/(?:news|article|post|posts|blog|cms|content|media|file)(?:[/a-zA-Z0-9_?&=\-\.%]+|/?))['"`]'''),
        re.compile(r'''['"`](/(?:monitor|monitoring|stats|statistics|analytics|report|reports)(?:[/a-zA-Z0-9_?&=\-\.%]+|/?))['"`]'''),
        re.compile(r'''['"`](/(?:message|messages|notification|notifications|notice|notices)(?:[/a-zA-Z0-9_?&=\-\.%]+|/?))['"`]'''),
        re.compile(r'''['"`](/(?:job|jobs|task|tasks|schedule|scheduler|worker|workers)(?:[/a-zA-Z0-9_?&=\-\.%]+|/?))['"`]'''),
        re.compile(r'''['"`](/(?:search|query|find|filter|list|page|pages)(?:[/a-zA-Z0-9_?&=\-\.%]+|/?))['"`]'''),
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
    API_ROOT_BLACKLIST = [
        '\\', '$', '@', '*', '+', '-', '|', '!', '%', '^', '~',
        '[', ']', '(', ')', '{', '}', '<', '>',
    ]
    
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
    
    def _extract_api_paths_advanced(self, script_content: str) -> Tuple[Set[str], Set[str]]:
        """
        使用预编译的复合正则表达式从脚本内容中提取API路径（高级版）
        参考 0x727/ChkApi apiPathFind.py 的 get_compiled_api_pattern
        """
        api_paths = set()
        sensitive_resources = set()
        
        compiled_pattern = _get_compiled_api_pattern()
        
        try:
            matches = compiled_pattern.findall(script_content)
            for match in matches:
                if isinstance(match, tuple):
                    matched_text = None
                    for group in match:
                        if group:
                            matched_text = group
                            break
                    if not matched_text:
                        continue
                else:
                    matched_text = match
                
                cleaned = self._url_filter_clean(matched_text)
                if not cleaned:
                    continue
                
                if self._is_api_root_blacklisted(cleaned):
                    continue
                
                if self._is_sensitive_resource(cleaned):
                    sensitive_resources.add(cleaned)
                elif self._is_valid_api_path(cleaned) or self._is_valid_route(cleaned):
                    api_paths.add(cleaned)
        except Exception as e:
            logger.debug(f"Advanced API extraction failed: {e}")
        
        return api_paths, sensitive_resources
    
    def _url_filter_clean(self, path: str) -> str:
        """
        URL 清理函数
        参考 0x727/ChkApi apiPathFind.py 的 urlFilter 逻辑
        """
        if not path:
            return ""
        
        path = path.strip()
        path = path.replace(" ", "")
        path = path.replace("\\/", "/")
        path = path.replace("\"", "")
        path = path.replace("'", "")
        path = path.replace("href=\"", "", 1)
        path = path.replace("href='", "", 1)
        path = path.replace("%3A", ":")
        path = path.replace("%2F", "/")
        path = path.replace("\\\\", "")
        if path.endswith("\\"):
            path = path.rstrip("\\")
        if path.startswith("="):
            path = path.lstrip("=")
        if path.startswith("href="):
            path = path.lstrip("href=")
        if path == 'href':
            return ""
        
        if not path:
            return ""
        
        path_lower = path.lower()
        if path_lower in self.INVALID_KEYWORDS:
            return ""
        
        for indicator in self.CONTENT_TYPE_INDICATORS:
            if indicator in path_lower:
                return ""
        
        if '/' not in path and not path_lower.startswith('http'):
            if path_lower not in ['api', 'v1', 'v2', 'v3']:
                return ""
        
        return path
    
    def _is_api_root_blacklisted(self, path: str) -> bool:
        """判断 API 根路径是否在黑名单中"""
        path_stripped = path.strip("'\"").strip("/")
        for char in self.API_ROOT_BLACKLIST:
            if path_stripped.startswith(char):
                return True
        return False
    
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
        
        path_lower = path.lower()
        for ext in self.STATIC_FILE_EXTENSIONS:
            if path_lower.endswith(ext):
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
        
        path_lower = path.lower()
        for ext in self.STATIC_FILE_EXTENSIONS:
            if path_lower.endswith(ext):
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
    5. 从响应中发现IP:port和域名信息
    """
    
    HTML_LINK_PATTERN = re.compile(r'''(?:href|src|action)=['"](/[a-zA-Z0-9_/\-.?=&]+)['"']''')
    
    JSON_API_PATTERN = re.compile(r'''['"](/api/[^\s'"`]+)['"`]''')
    
    JS_VAR_PATTERN = re.compile(r'''(?:window|global)\.([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*['"`]([^'"`]+)['"`]''')
    
    IP_PORT_PATTERN = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})\b')
    
    FULL_URL_PATTERN = re.compile(r'https?://[^\s\'"<>]+')
    
    SENSITIVE_FILE_PATTERNS = PathValidationConstants.SENSITIVE_FILE_PATTERNS
    STATIC_FILE_EXTENSIONS = PathValidationConstants.STATIC_FILE_EXTENSIONS
    INVALID_KEYWORDS = PathValidationConstants.INVALID_KEYWORDS
    CONTENT_TYPE_INDICATORS = PathValidationConstants.CONTENT_TYPE_INDICATORS
    
    def __init__(self, target_domain: str = "", realtime_output=None):
        self.discovered_paths: Set[str] = set()
        self.discovered_sensitive_resources: Set[str] = set()
        self.discovered_ips: Set[str] = set()
        self.discovered_domains: Set[str] = set()
        self.target_domain = target_domain
        self._realtime = realtime_output
        self._seen_ips: Set[str] = set()
        self._seen_domains: Set[str] = set()
        self._seen_apis: Set[str] = set()
        self._seen_urls: Set[str] = set()
    
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
            'sensitive_resources': set(),
            'ips': set(),
            'domains': set()
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
        
        ips, domains = self._extract_ips_and_domains(content, url)
        result['ips'].update(ips)
        result['domains'].update(domains)
        
        self._output_discoveries(result, url)
        
        self.discovered_paths.update(result['api_paths'])
        self.discovered_sensitive_resources.update(result['sensitive_resources'])
        self.discovered_ips.update(result['ips'])
        self.discovered_domains.update(result['domains'])
        return result
    
    def _output_discoveries(self, result: Dict[str, Set[str]], source_url: str):
        """输出发现的内容到终端和文件"""
        if not self._realtime:
            return
        
        for ip_port in result['ips']:
            if ip_port not in self._seen_ips:
                self._seen_ips.add(ip_port)
                ip, port = ip_port.rsplit(':', 1) if ':' in ip_port else (ip_port, "")
                self._realtime.output_ip(ip, port, source=source_url)
        
        for domain in result['domains']:
            if domain not in self._seen_domains:
                self._seen_domains.add(domain)
                
                if HAS_TLDEXTRACT and self.target_domain:
                    try:
                        extracted_domain = tldextract.extract(domain)  # type: ignore
                        extracted_target = tldextract.extract(self.target_domain)  # type: ignore
                        if extracted_domain and extracted_target:
                            if extracted_domain.subdomain:
                                self._realtime.output_subdomain(domain, source=source_url)
                            if extracted_domain.domain == extracted_target.domain and extracted_domain.suffix == extracted_target.suffix:
                                if not extracted_domain.subdomain:
                                    self._realtime.output_rootdomain(domain, source=source_url)
                        continue
                    except Exception:
                        pass
                
                if domain.endswith(self.target_domain) and '.' in domain.replace(self.target_domain, ''):
                    self._realtime.output_subdomain(domain, source=source_url)
                elif self.target_domain in domain:
                    pass
                else:
                    self._realtime.output_subdomain(domain, source=source_url)
        
        for api_path in result['api_paths']:
            if api_path not in self._seen_apis:
                self._seen_apis.add(api_path)
                self._realtime.output_api(api_path, source=source_url)
        
        for sensitive in result['sensitive_resources']:
            self._realtime.output_sensitive("resource", sensitive, source=source_url)
    
    def _extract_ips_and_domains(self, content: str, source_url: str) -> Tuple[Set[str], Set[str]]:
        """
        从内容中提取IP:port和域名信息
        
        Args:
            content: 响应内容
            source_url: 来源URL
            
        Returns:
            (ips, domains) 元组
        """
        ips = set()
        domains = set()
        
        if not content:
            return ips, domains
        
        ip_ports = self.IP_PORT_PATTERN.findall(content)
        for ip, port in ip_ports:
            full_ip_port = f"{ip}:{port}"
            if self._is_likely_valid_ip_port(ip, port):
                ips.add(full_ip_port)
        
        url_matches = self.FULL_URL_PATTERN.findall(content)
        parsed_source = urlparse(source_url)
        source_domain = parsed_source.netloc
        
        for url in url_matches:
            try:
                parsed = urlparse(url)
                if parsed.netloc:
                    domain = parsed.netloc
                    
                    if self.target_domain and self._is_related_domain(domain, self.target_domain):
                        domains.add(domain)
                    elif not self.target_domain and self._is_valid_domain(domain):
                        domains.add(domain)
            except Exception:
                continue
        
        return ips, domains
    
    def _is_likely_valid_ip_port(self, ip: str, port: str) -> bool:
        """验证IP:port是否可能有效"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            
            for part in parts:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            
            port_num = int(port)
            if port_num < 1 or port_num > 65535:
                return False
            
            private_ips = ['10.', '172.16.', '172.17.', '172.18.', '172.19.',
                          '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
                          '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
                          '172.30.', '172.31.', '192.168.', '127.', '0.']
            for prefix in private_ips:
                if ip.startswith(prefix):
                    return True
            
            return True
        except (ValueError, AttributeError):
            return False
    
    def _is_related_domain(self, domain: str, target: str) -> bool:
        """判断域名是否与目标相关"""
        if not domain or not target:
            return False
        
        domain_lower = domain.lower()
        target_lower = target.lower()
        
        if target_lower in domain_lower or domain_lower in target_lower:
            return True
        
        if HAS_TLDEXTRACT:
            try:
                extracted_domain = tldextract.extract(domain)  # type: ignore
                extracted_target = tldextract.extract(target)  # type: ignore
                if extracted_domain and extracted_target:
                    if extracted_domain.domain == extracted_target.domain:
                        return True
            except Exception:
                pass
        
        return False
    
    def _is_valid_domain(self, domain: str) -> bool:
        """验证域名是否有效"""
        if not domain:
            return False
        
        domain_lower = domain.lower()
        
        invalid_prefixes = ['data:', 'javascript:', 'mailto:', 'tel:', 'ftp:']
        for prefix in invalid_prefixes:
            if domain_lower.startswith(prefix):
                return False
        
        if domain_lower.startswith('127.') or domain_lower.startswith('0.'):
            return False
        
        localhost_variants = ['localhost', 'localhost.localdomain']
        if domain_lower in localhost_variants:
            return False
        
        return True
    
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
        """获取所有发现的新路径、敏感资源、IP和域名"""
        return {
            'api_paths': list(self.discovered_paths),
            'sensitive_resources': list(self.discovered_sensitive_resources),
            'ips': list(self.discovered_ips),
            'domains': list(self.discovered_domains)
        }
    
    def get_ips(self) -> List[str]:
        """获取所有发现的IP:port"""
        return list(self.discovered_ips)
    
    def get_domains(self) -> List[str]:
        """获取所有发现的域名"""
        return list(self.discovered_domains)
    
    def clear(self):
        """清空所有发现的数据"""
        self.discovered_paths.clear()
        self.discovered_sensitive_resources.clear()
        self.discovered_ips.clear()
        self.discovered_domains.clear()
