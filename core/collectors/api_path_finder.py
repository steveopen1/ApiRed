"""
ApiPathFinder Module
基于原项目 ChkApi_0x727 的核心API发现逻辑
提供强大的API路径发现能力
"""

import re
import logging
from typing import List, Dict, Set, Tuple, Optional, Any
from urllib.parse import urlparse, urljoin
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


API_ROOT_BLACK_LIST = [
    "\\", "#", "$", "@", "*", "+", "-", "|", "!", "%", "^", "~", "[", "]"
]

API_ROOT_BLACK_LIST_DURING_SPIDER = [
    x for x in API_ROOT_BLACK_LIST if x != "#"
]

URL_BLACK_LIST = [
    ".js?", ".css?", ".jpeg?", ".jpg?", ".png?", ".gif?",
    "github.com", "www.w3.org", "example.com", "example.org",
    "<", ">", "{", "}", "[", "]", "|", "^", ";",
    "/js/", "location.href", "javascript:void",
    "webpack://", "chrome-extension://",
]

PATH_BLACK_PREFIX = [
    "/2000/", "/1999/", "/1998/", "/1997/", "/1996/",
    "/node_modules/", "/npm/", "/bower_components/",
    "/webpack/", "/target/", "/dist/", 
]

PATH_BLACK_KEYWORDS = [
    'blots/', 'modules/syntax', 'element-ui@',
    'alicdn.com', 'cdnjs.cloudflare.com', 'unpkg.com', 'jsdelivr.net',
    'github.com', 'github.io', 'googleapis.com',
    'zloirock/core-js', 'ElemeFE/element',
    'ruoyi-vue', 'y_project/',
]

PATH_BLACK_PATTERNS = [
    r'^//',  # //开头
    r'^/\.$',  # /.
    r'^/#',  # /#
    r'^/,$',  # /, 单独的逗号
    r'^/[a-z],$',  # /g, 单字母逗号
    r'^,[a-z]$',  # ,g 逗号开头
    r'^[a-z],$',  # g, 单字母逗号
    r'^[a-z]=[a-z]$',  # 单字母等于 g=u
    r'^/[a-z]/[a-z]$',  # /a/b, /a/i
    r'\.color$',  # CSS属性 .color
    r'\.style$',  # CSS属性 .style
    r'^/[^/]*[A-Z][^/]*\.color',  # /xxxColor.color 驼峰命名的CSS属性
    r'^/[^/]*[A-Z][^/]*\.style',  # /xxxStyle.style 驼峰命名的CSS属性
    r't\.ttl$',  # TTL类文件
    r'/blob/',  # GitHub blob
    r'/tree/',  # GitHub tree
    r'^YYYY-MM-DD$',  # 日期格式
    r'^M/D/YY$',  # 日期格式 M/D/YY
    r'^MM?/DD?/YY(?:YY)?$',  # 日期格式 MM/DD/YYYY
    r'^\d{1,2}:\d{2}$',  # 时间格式
    r'^[A-Z]{1,2}\d{1,4}[A-Z]?$',  # 股票代码格式
    r'^[a-z]+-[a-z]+(-[a-z]+)+$',  # CSS类名格式 sub-menu-more
    r'^#[0-9a-fA-F]{3,6}$',  # 颜色代码
    r'^[0-9a-fA-F]{3,6}$',  # 纯颜色代码
    r'^(?:http|https)?:$',  # 协议字符串
    r'^http$',  # 协议字符串无冒号 http
    r'^[\w.-]+@[\w.-]+\.\w+$',  # 邮箱格式
    r'^[a-z]+&&',  # JavaScript表达式 t&&
    r'^application/',  # MIME类型 application/sdp
    r'^http协议',  # 中文错误消息 http协议不支持对讲
    r'^/trackID=$',  # URL参数而非路径
]

API_PATH_MIN_LENGTH = 2
API_PATH_MAX_LENGTH = 200

VUE_ROUTER_DIRS = [
    'components', 'views', 'pages', 'layouts', 'modules',
    'dashboard', 'error', 'mixins', 'utils', 'directives',
    'filters', 'assets', 'store', 'router', 'plugins',
    'locales', 'styles', 'icons', 'svg', 'images', 'fonts',
    'gameMoney', 'hotel', 'ticket', 'yearCard', 'monitor',
    'tool', 'system', 'scenicSpots', 'museumExplain', 'opinion',
]

VUE_ROUTE_PATTERN = r'return\s+(?:{[^}]*)?\[["\u0027]([^\["\u0027]+)["\]]'
REACT_ROUTE_PATTERN = r'Route\s+path=["\u0027]([^["\']+)["\u0027]'
ROUTER_PATH_PATTERN = r'(?:router|Route)[.\s]*path[:\s]*["\u0027]([^["\']+)["\u0027]'

COMMON_API_PATHS = [
    'add', 'ls', 'focus', 'calc', 'download', 'bind', 'execute',
    'logininfo', 'create', 'decrypt', 'new', 'update', 'click',
    'shell', 'export', 'menu', 'retrieve', 'on', 'message', 'admin',
    'calculate', 'append', 'check', 'crypt', 'rename', 'exec', 'detail',
    'clone', 'query', 'verify', 'is', 'authenticate', 'move', 'toggle',
    'make', 'modify', 'upload', 'help', 'demo', 'with', 'alert', 'mode',
    'gen', 'msg', 'edit', 'vrfy', 'enable', 'run', 'open', 'post',
    'proxy', 'subtract', 'initiate', 'read', 'encrypt', 'auth', 'snd',
    'view', 'save', 'config', 'get', 'alter', 'forceLogout', 'build',
    'list', 'show', 'online', 'test', 'pull', 'notice', 'change',
    'put', 'to', 'status', 'search', 'mod', '0', 'send', 'load',
    'login', 'logout', 'register', 'info', 'delete', 'remove',
    'insert', 'select', 'user', 'users', 'order', 'orders',
    'product', 'products', 'goods', 'item', 'items', 'category', 'cart',
    'shop', 'payment', 'account', 'profile', 'setting', 'settings',
    'dashboard', 'home', 'index', 'about', 'contact', 'service',
    'news', 'article', 'blog', 'comment', 'file', 'files',
    'image', 'images', 'video', 'videos', 'audio', 'media', 'uploads',
    'resource', 'resources', 'dict', 'dicts', 'dictionary', 'enum', 'enums',
    'area', 'region', 'province', 'city', 'district', 'street', 'address',
    'org', 'organization', 'dept', 'department', 'company',
    'tag', 'tags', 'label', 'labels', 'classify', 'group', 'groups',
    'attachment', 'attachments', 'document', 'documents', 'doc',
    'pictures', 'picture', 'photo', 'photos', 'avatar',
    'video', 'videos', 'audio', 'media',
    'comment', 'comments', 'reply', 'replies',
    'notice', 'notices', 'notification', 'notifications', 'notify',
    'news', 'article', 'articles', 'post', 'posts', 'topic', 'topics',
    'workflow', 'process', 'task', 'tasks', 'approve', 'approval', 'reject',
    'schedule', 'calendar', 'booking', 'appointment', 'reservation',
]

DANGER_API_LIST = [
    'del', 'delete', 'insert', 'logout', 'remove', 'drop', 'shutdown',
    'stop', 'poweroff', 'restart', 'rewrite', 'terminate', 'deactivate',
    'halt', 'disable'
]

RESPONSE_BLACK_TEXT = [
    '<RecommendDoc>https://api.aliyun.com',
    '<Code>MethodNotAllowed</Code>',
    '<Code>AccessDenied</Code>',
    'FAIL_SYS_API_NOT_FOUNDED::请求API不存在',
    '"未找到API注册信息"',
    '"status":400,', '"status":403',
    '"msg":"参数错误"',
    '"miss header param x-ca-key"',
    '"message":"No message available"',
    '"code":1003,"message":"The specified token is expired or invalid."',
    '{"csrf":"',
    '"status":401,"error":"Unauthorized"',
    '"Request method \'POST\' not supported"',
    '"error":"Internal Server Error"',
    '"code":"HttpRequestMethodNotSupported"',
    '"accessErrorId"',
    '<status>403</status>',
    '"code":"AUTHX_01002"'
]

CONTENT_TYPE_LIST = [
    {'key': 'text/html', 'tag': 'html'},
    {'key': 'application/json', 'tag': 'json'},
    {'key': 'text/plain', 'tag': 'txt'},
    {'key': 'text/xml', 'tag': 'xml'},
    {'key': 'text/javascript', 'tag': 'js'},
    {'key': 'image/gif', 'tag': 'gif'},
    {'key': 'image/jpeg', 'tag': 'jpg'},
    {'key': 'image/jpg', 'tag': 'jpg'},
    {'key': 'image/png', 'tag': 'png'},
    {'key': 'image/*', 'tag': 'img'},
    {'key': 'image/x-icon', 'tag': 'ico'},
    {'key': 'application/xhtml+xml', 'tag': 'xhtml'},
    {'key': 'application/xml', 'tag': 'xml'},
    {'key': 'application/atom+xml', 'tag': 'atom+xml'},
    {'key': 'application/octet-stream', 'tag': 'bin'},
    {'key': 'binary/octet-stream', 'tag': 'bin'},
    {'key': 'audio/x-wav', 'tag': 'wav'},
    {'key': 'audio/mp3', 'tag': 'mp3'},
    {'key': 'video/x-ms-wmv', 'tag': 'wmv'},
    {'key': 'video/mpeg4', 'tag': 'mp4'},
    {'key': 'video/avi', 'tag': 'avi'},
    {'key': 'application/pdf', 'tag': 'pdf'},
    {'key': 'application/msword', 'tag': 'msword'},
    {'key': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'tag': 'docx'},
    {'key': 'application/vnd.ms-excel', 'tag': 'excel'},
    {'key': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'tag': 'xlsx'},
    {'key': 'application/vnd.ms-powerpoint', 'tag': 'ppt'},
    {'key': 'application/vnd.openxmlformats-officedocument.presentationml.presentation', 'tag': 'pptx'},
    {'key': 'application/zip', 'tag': 'zip'},
    {'key': 'application/x-zip-compressed', 'tag': 'zip'},
    {'key': 'application/x-tar', 'tag': 'tar'},
    {'key': 'multipart/form-data', 'tag': 'file'},
    {'key': 'application/ld+json', 'tag': 'ld+json'},
    {'key': 'text/x-yaml', 'tag': 'yaml'},
    {'key': 'text/css', 'tag': 'css'},
    {'key': 'text/x-python', 'tag': 'python'},
    {'key': 'text/x-java', 'tag': 'java'},
    {'key': 'text/x-csharp', 'tag': 'csharp'},
    {'key': 'text/x-go', 'tag': 'go'},
    {'key': 'text/x-rust', 'tag': 'rust'},
    {'key': 'text/x-sql', 'tag': 'sql'},
    {'key': 'text/x-php', 'tag': 'php'},
    {'key': 'text/typescript', 'tag': 'typescript'},
    {'key': 'text/javascript', 'tag': 'javascript'},
    {'key': 'text/x-lua', 'tag': 'lua'},
]

CONTENT_TYPE_PURE = [x['key'] for x in CONTENT_TYPE_LIST]

STATIC_FILE_EXT_BLACK_LIST = [
    "pdf", "docx", "doc", "exe", "apk", "mp4", "mkv", "mp3", "flv",
    "css", "less", "woff", "woff2", "vue", "svg", "png", "jpg",
    "jpeg", "tif", "bmp", "gif", "psd", "exif", "fpx", "avif",
    "apng", "webp", "swf", "ico", "svga", "ts", "eot", "lrc",
    "tpl", "cur", "success", "error", "complete", "zip", "rar",
    "7z", "tar", "gz", "xz"
]

STATIC_FILE_EXT_BLACK_LIST_FULL = [f".{ext}" for ext in STATIC_FILE_EXT_BLACK_LIST]

URL_EXT_BLACK_LIST = ["." + x if not x.startswith(",") else x for x in STATIC_FILE_EXT_BLACK_LIST]


@dataclass
class DiscoveredAPI:
    """发现的API端点"""
    path: str
    referer: str = ""
    url_type: str = "api_path"
    method: str = "GET"
    query_params: str = ""
    is_static: bool = False


class ApiPathFinder:
    """
    API路径发现器
    
    基于原项目 ChkApi_0x727 的核心逻辑实现
    """
    
    API_PATTERNS = [
        r'["\']http[^\s\'""<>\)\(]{2,250}?["\']',
        r'=http[^\s\'""<>\)\(]{2,250}',
        r'["\']/[^\s\'""<>\:\)\(\u4e00-\u9fa5]{1,250}?["\']',
        r'["\'][^\s\'""<>\:\)\(\u4e00-\u9fa5]{1,250}?/[^\s\'""<>\:\)\(\u4e00-\u9fa5]{1,250}?["\']',
        r'(?i)(?<=path:)\s?["\'][^\s\'""<>\:\)\(]{1,250}?["\']',
        r'(?i)(?<=path\s:)\s?["\'][^\s\'""<>\:\)\(]{1,250}?["\']',
        r'(?i)(?<=path=)\s?["\'][^\s\'""<>\:\)\(]{1,250}?["\']',
        r'(?i)(?<=path\s=)\s?["\'][^\s\'""<>\:\)\(]{1,250}?["\']',
        r'(?i)(?<=url:)\s?["\'][^\s\'""<>\:\)\(]{1,250}?["\']',
        r'(?i)(?<=url\s:)\s?["\'][^\s\'""<>\:\)\(]{1,250}?["\']',
        r'(?i)(?<=url=)\s?["\'][^\s\'""<>\:\)\(]{1,250}?["\']',
        r'(?i)(?<=url\s=)\s?["\'][^\s\'""<>\:\)\(]{1,250}?["\']',
        r'(?i)(?<=index:)\s?["\'][^\s\'""<>\:\)\(]{1,250}?["\']',
        r'(?i)(?<=index\s:)\s?["\'][^\s\'""<>\:\)\(]{1,250}?["\']',
        r'(?i)(?<=index=)\s?["\'][^\s\'""<>\:\)\(]{1,250}?["\']',
        r'(?i)(?<=index\s=)\s?["\'][^\s\'""<>\:\)\(]{1,250}?["\']',
        r'(?i)(?<=src:)\s?["\'][^\s\'""<>\:\)\(]{1,250}?["\']',
        r'(?i)(?<=src\s:)\s?["\'][^\s\'""<>\:\)\(]{1,250}?["\']',
        r'(?i)(?<=src=)\s?["\'][^\s\'""<>\:\)\(]{1,250}?["\']',
        r'(?i)(?<=href:)\s?["\'][^\s\'""<>\:\)\(]{1,250}?["\']',
        r'(?i)(?<=href\s:)\s?["\'][^\s\'""<>\:\)\(]{1,250}?["\']',
        r'(?i)(?<=href=)\s?["\'][^\s\'""<>\:\)\(]{1,250}?["\']',
        r'(?i)(?<=action:)\s?["\'][^\s\'""<>\:\)\(]{1,250}?["\']',
        r'(?i)(?<=action\s:)\s?["\'][^\s\'""<>\:\)\(]{1,250}?["\']',
        r'(?i)(?<=action=)\s?["\'][^\s\'""<>\:\)\(]{1,250}?["\']',
        r'(?i)(?<=api:)\s?["\'][^\s\'""<>\:\)\(]{1,250}?["\']',
        r'(?i)(?<=api\s:)\s?["\'][^\s\'""<>\:\)\(]{1,250}?["\']',
        r'(?i)(?<=api=)\s?["\'][^\s\'""<>\:\)\(]{1,250}?["\']',
        r'(?i)(?<=endpoint:)\s?["\'][^\s\'""<>\:\)\(]{1,250}?["\']',
        r'(?i)(?<=endpoint\s:)\s?["\'][^\s\'""<>\:\)\(]{1,250}?["\']',
        r'(?i)(?<=endpoint=)\s?["\'][^\s\'""<>\:\)\(]{1,250}?["\']',
        r'(?i)(?<=baseUrl:)\s?["\'][^\s\'""<>\:\)\(]{1,250}?["\']',
        r'(?i)(?<=baseUrl\s:)\s?["\'][^\s\'""<>\:\)\(]{1,250}?["\']',
        r'(?i)(?<=baseUrl=)\s?["\'][^\s\'""<>\:\)\(]{1,250}?["\']',
        r'(?i)(?<=base_url:)\s?["\'][^\s\'""<>\:\)\(]{1,250}?["\']',
        r'(?i)(?<=base_url\s:)\s?["\'][^\s\'""<>\:\)\(]{1,250}?["\']',
        r'(?i)(?<=base_url=)\s?["\'][^\s\'""<>\:\)\(]{1,250}?["\']',
        r'(?:"|\'|`)(/[^""`<>\s]+)(?:"|\'|`)',
        r"(?i)router\.push\(['\"]([^'\"]+)['\"]\)",
        r"(?i)router\.replace\(['\"]([^'\"]+)['\"]\)",
        r"(?i)\$router\.push\(['\"]([^'\"]+)['\"]\)",
        r"(?i)<Route\s+path=['\"]([^'\"]+)['\"]",
        r"(?i)<Link\s+to=['\"]([^'\"]+)['\"]",
        r"(?i)Navigate\s+to=['\"]([^'\"]+)['\"]",
    ]
    
    def __init__(self):
        self.discovered_apis: List[DiscoveredAPI] = []
        self.all_api_paths: Set[str] = set()
        self._compiled_patterns = [re.compile(p) for p in self.API_PATTERNS]
    
    def url_filter(self, lst: List[str]) -> List[str]:
        """
        URL过滤函数 - 原项目核心逻辑
        
        过滤掉:
        1. 包含contentTypeListPure中内容的URL
        2. 以黑名单开头的URL
        3. 包含黑名单关键词的URL
        4. 以特定扩展名结尾的URL
        5. 数字开头/包含版本号的路径
        """
        tmp = []
        for line in lst:
            if not line or len(line.strip()) < 2:
                continue
            
            clean_line = line.strip().strip("'\" ").rstrip('/')
            
            if not clean_line:
                continue
            
            if any(x in CONTENT_TYPE_PURE for x in [clean_line]):
                continue
            
            first_segment = clean_line.lstrip("/").split("/")[0] if clean_line.startswith("/") else clean_line.split("/")[0]
            if any(first_segment.startswith(x) for x in API_ROOT_BLACK_LIST_DURING_SPIDER):
                continue
            
            clean_line = clean_line.replace(" ", "")
            clean_line = clean_line.replace("\\/", "/")
            clean_line = clean_line.replace("\"", "")
            clean_line = clean_line.replace("'", "")
            clean_line = clean_line.replace("href=\"", "", 1)
            clean_line = clean_line.replace("href='", "", 1)
            clean_line = clean_line.replace("%3A", ":")
            clean_line = clean_line.replace("%2F", "/")
            clean_line = clean_line.replace("\\\\", "")
            if clean_line.endswith("\\"):
                clean_line = clean_line.rstrip("\\")
            if clean_line.startswith("="):
                clean_line = clean_line.lstrip("=")
            if clean_line.startswith("href="):
                clean_line = clean_line.lstrip("href=")
            if clean_line == 'href' or not clean_line:
                continue
            
            if any(x in clean_line for x in URL_BLACK_LIST):
                continue
            
            is_blacklisted = False
            for x in URL_EXT_BLACK_LIST:
                if clean_line.lower().endswith(x):
                    is_blacklisted = True
                    break
            if is_blacklisted:
                continue
            
            path_lower = clean_line.lower()
            
            if clean_line.startswith('./'):
                clean_line = '/' + clean_line[2:]
                path_lower = clean_line.lower()
            
            if path_lower.startswith('/node_modules/') or '/node_modules/' in path_lower:
                continue
            if path_lower.startswith('/bower_components/') or '/bower_components/' in path_lower:
                continue
            
            if re.match(r'^/\d{3,}/', clean_line):
                continue
            if re.search(r'/v\d+\.\d+', clean_line):
                pass
            if '/webpack/' in path_lower or '/target/' in path_lower:
                continue
            
            for keyword in PATH_BLACK_KEYWORDS:
                if keyword in path_lower:
                    is_blacklisted = True
                    break
            if is_blacklisted:
                continue
            
            for pattern in PATH_BLACK_PATTERNS:
                if re.search(pattern, clean_line):
                    is_blacklisted = True
                    break
            if is_blacklisted:
                continue
            
            if len(clean_line) < API_PATH_MIN_LENGTH or len(clean_line) > API_PATH_MAX_LENGTH:
                continue
            
            tmp.append(clean_line)
        
        return tmp
    
    def find_api_paths_in_text(self, text: str, referer: str = "") -> List[DiscoveredAPI]:
        """
        在文本中查找API路径
        
        Args:
            text: JavaScript/HTML文本内容
            referer: 来源URL
            
        Returns:
            发现的API路径列表
        """
        found_apis = []
        found_paths_set = set()
        
        for pattern in self._compiled_patterns:
            try:
                matches = pattern.findall(text)
                if not matches:
                    continue
                
                for match in matches:
                    cleaned = self._clean_match(match)
                    if not cleaned:
                        continue
                    
                    paths = self.url_filter([cleaned])
                    for path in paths:
                        if path not in found_paths_set and len(path) > 1:
                            found_paths_set.add(path)
                            
                            api = self._create_api_object(path, referer)
                            if api:
                                found_apis.append(api)
                                self.all_api_paths.add(path)
            except Exception as e:
                logger.debug(f"Pattern matching error: {e}")
                continue
        
        return found_apis
    
    def _clean_match(self, match: str) -> str:
        """清理匹配到的字符串"""
        if not match:
            return ""
        
        path = match.strip().strip("'\"` ").rstrip('/')
        
        path = path.replace("\\/", "/")
        path = path.replace("%3A", ":")
        path = path.replace("%2F", "/")
        
        if path.startswith("="):
            path = path.lstrip("=")
        
        if path.startswith("http://") or path.startswith("https://"):
            parsed = urlparse(path)
            path = parsed.path
            if parsed.query:
                path = f"{path}?{parsed.query}"
        
        return path
    
    def _create_api_object(self, path: str, referer: str) -> Optional[DiscoveredAPI]:
        """创建API对象"""
        if not path or len(path) < 2:
            return None
        
        path_lower = path.lower()
        
        if any(ext in path_lower for ext in STATIC_FILE_EXT_BLACK_LIST_FULL):
            return None
        
        if any(path_lower.startswith(x) for x in ["javascript:", "mailto:", "data:", "blob:"]):
            return None
        
        if path.startswith("/static/") or path.startswith("/assets/"):
            return None
        
        is_static = any(path_lower.endswith("." + ext) for ext in STATIC_FILE_EXT_BLACK_LIST)
        
        return DiscoveredAPI(
            path=path,
            referer=referer,
            url_type="api_path",
            method="GET",
            is_static=is_static
        )
    
    def get_all_paths(self) -> List[str]:
        """获取所有发现的路径"""
        return list(self.all_api_paths)
    
    def get_api_paths_only(self) -> List[str]:
        """仅获取API路径（排除静态资源）"""
        return [p for p in self.all_api_paths if not self._is_static_path(p)]
    
    def _is_static_path(self, path: str) -> bool:
        """判断是否为静态资源路径"""
        path_lower = path.lower()
        return any(path_lower.endswith("." + ext) for ext in STATIC_FILE_EXT_BLACK_LIST)


class ApiPathCombiner:
    """
    API路径组合器 - 原项目 filter_data() 核心逻辑

    智能组合:
    1. base_urls + path_with_api_paths
    2. base_urls + path_with_no_api_paths + self_api_path
    3. 路径变体生成（解决 /inspect/login 前缀问题）
    """

    NON_RESOURCE_SEGMENTS = frozenset({
        'inspect', 'proxy', 'gateway', 'api', 'service', 'web', 'www',
        'v1', 'v2', 'v3', 'v4', 'v5', 'rest', 'graphql', 'rpc',
        'internal', 'external', 'open', 'public', 'private',
        'mobile', 'app', 'client', 'cdn', 'static', 'assets',
    })

    _UUID_PATTERN = re.compile(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', re.IGNORECASE)
    _ALPHANUM_DASH_UNDERSCORE_PATTERN = re.compile(r'^[a-zA-Z0-9_-]+$')

    _COMMON_SUFFIXES_SET = frozenset([
        'list', 'add', 'create', 'delete', 'detail', 'info', 'update', 'edit', 'remove',
        'get', 'set', 'save', 'query', 'search', 'filter', 'sort', 'page',
        'all', 'count', 'total', 'sum', 'export', 'import', 'upload', 'download',
        'enable', 'disable', 'status', 'config', 'settings', 'login', 'logout',
        'register', 'reset', 'init', 'refresh', 'sync', 'menu', 'nav', 'route',
        'tree', 'select', 'option', 'combo', 'autocomplete', 'validate', 'verify',
        'approve', 'reject', 'cancel', 'close', 'open', 'check',
        'bind', 'unbind', 'link', 'unlink', 'join', 'leave', 'accept', 'refuse',
    ])

    _COMMON_RESOURCES_SET = frozenset([
        'user', 'users', 'order', 'orders', 'product', 'products', 'goods',
        'role', 'roles', 'menu', 'menus', 'category', 'categories', 'catalog',
        'config', 'configuration', 'settings', 'system', 'admin', 'auth', 'login',
        'department', 'dept', 'organization', 'org', 'employee',
        'customer', 'customers', 'supplier', 'suppliers', 'account', 'accounts',
        'profile', 'permission', 'permissions', 'resource', 'resources',
        'tag', 'tags', 'comment', 'comments',
        'attachment', 'attachments', 'file', 'files', 'image', 'images', 'video', 'videos',
        'payment', 'transaction', 'invoice', 'refund', 'cart', 'shop', 'item', 'items',
        'sku', 'stock', 'inventory', 'warehouse', 'address', 'area', 'region',
    ])

    def __init__(self):
        self.self_api_paths = COMMON_API_PATHS

    @staticmethod
    def _is_likely_id(s: str) -> bool:
        """判断是否为ID"""
        return (
            s.isdigit() or
            bool(re.match(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', s, re.IGNORECASE)) or
            (len(s) > 3 and s[:2].isalpha() and s[2:].isdigit()) or
            (len(s) > 8 and bool(re.match(r'^[a-zA-Z0-9_-]+$', s)) and ('-' in s or '_' in s))
        )

    @staticmethod
    def _is_common_suffix(s: str) -> bool:
        """判断是否为常见后缀"""
        return s.lower() in ApiPathCombiner._COMMON_SUFFIXES_SET

    @staticmethod
    def _is_common_resource(s: str) -> bool:
        """判断是否为常见资源"""
        return s.lower() in ApiPathCombiner._COMMON_RESOURCES_SET

    @staticmethod
    def _is_likely_id(s: str) -> bool:
        """判断是否为ID"""
        return (
            s.isdigit() or
            bool(re.match(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', s, re.IGNORECASE)) or
            (len(s) > 3 and s[:2].isalpha() and s[2:].isdigit()) or
            (len(s) > 8 and bool(re.match(r'^[a-zA-Z0-9_-]+$', s)) and ('-' in s or '_' in s))
        )

    @staticmethod
    def _is_meaningful_segment(s: str) -> bool:
        """
        判断路径段是否有实际意义（知识库辅助判断）

        综合考虑：
        - 是否是常见后缀
        - 是否是常见资源
        - 是否是ID
        - 是否是代理前缀
        """
        s_lower = s.lower()

        if s_lower in ApiPathCombiner.NON_RESOURCE_SEGMENTS:
            return False

        if ApiPathCombiner._is_common_suffix(s_lower):
            return True

        if ApiPathCombiner._is_common_resource(s_lower):
            return True

        if ApiPathCombiner._is_likely_id(s):
            return False

        if len(s) < 2:
            return False

        return True

    @staticmethod
    def extract_base_path(api_path: str) -> Optional[str]:
        """
        提取代理/网关前缀（统计学+知识库+ID检测混合）

        对于 /inspect/login/checkCode/getCheckCode：
        - 'login' 是常见资源 → 有意义
        - 'checkCode' 是驼峰资源 → 有意义
        - 'getCheckCode' 是常见后缀 → 有意义
        - 所以第一段没有实际意义的 segment 就是代理前缀: /inspect
        """
        if not api_path:
            return None

        path = api_path.strip('/')
        parts = path.split('/')

        for i, part in enumerate(parts):
            if part.lower() in ApiPathCombiner.NON_RESOURCE_SEGMENTS:
                if i == 0:
                    return None
                return '/' + '/'.join(parts[:i])

        first_meaningful_idx = 0
        for i in range(len(parts) - 1, -1, -1):
            if ApiPathCombiner._is_meaningful_segment(parts[i]):
                first_meaningful_idx = i
                break

        if first_meaningful_idx > 0:
            return '/' + '/'.join(parts[:first_meaningful_idx])

        return None

        path = api_path.strip('/')
        parts = path.split('/')

        for i, part in enumerate(parts):
            if part.lower() in ApiPathCombiner.NON_RESOURCE_SEGMENTS:
                if i == 0:
                    return None
                return '/' + '/'.join(parts[:i])

        for i in range(len(parts) - 1, 0, -1):
            part = parts[i].lower()
            if not ApiPathCombiner._is_common_suffix(part) and \
               not ApiPathCombiner._is_common_resource(part) and \
               not ApiPathCombiner._is_likely_id(part):
                if i > 0:
                    return '/' + '/'.join(parts[:i])
                return None

        return None

    @staticmethod
    def extract_resource_path(api_path: str) -> Optional[str]:
        """
        提取资源路径（去掉代理前缀后的路径）

        对于 /inspect/login/checkCode/getCheckCode：
        - 去掉 /inspect 前缀后: /login/checkCode/getCheckCode
        """
        if not api_path:
            return None

        base_path = ApiPathCombiner.extract_base_path(api_path)
        if base_path:
            if api_path.startswith(base_path):
                resource = api_path[len(base_path):]
                return resource if resource else api_path
            return '/' + api_path[len(base_path):].lstrip('/')
        return api_path

    @staticmethod
    def generate_path_variants(api_path: str) -> Dict[str, str]:
        """
        生成路径变体 - 基于知识库识别的 base_path + resource_path

        输入: /inspect/login/checkCode/getCheckCode

        返回:
        {
            'original': /inspect/login/checkCode/getCheckCode,
            'parent_paths': ['/inspect/login/checkCode', '/inspect/login', '/inspect'],
            'base_path': /inspect,
            'resource_path': /login/checkCode/getCheckCode,
            'v1': /login/checkCode/getCheckCode,
            'v2': /inspect/login/checkCode/getCheckCode,
        }
        """
        if not api_path:
            return {}

        parent_paths = ApiPathCombiner.generate_parent_paths(api_path, max_depth=3)
        base_path = ApiPathCombiner.extract_base_path(api_path)
        resource_path = ApiPathCombiner.extract_resource_path(api_path)

        if resource_path is None:
            resource_path = api_path

        variants: Dict[str, Any] = {
            'original': api_path,
            'parent_paths': parent_paths,
            'base_path': base_path,
            'resource_path': resource_path,
        }

        variants['v1'] = resource_path

        if base_path:
            variants['v2'] = base_path + resource_path
        else:
            variants['v2'] = resource_path

        return variants
    
    def filter_data(
        self,
        all_load_url: List[Dict[str, str]],
        all_api_paths: List[DiscoveredAPI]
    ) -> Dict[str, Any]:
        """
        智能组合API路径
        
        Args:
            all_load_url: 所有加载的URL列表
            all_api_paths: 所有发现的API路径
            
        Returns:
            包含各种组合结果的字典
        """
        base_urls = []
        tree_urls = []
        path_with_api_urls = []
        path_with_api_paths = []
        path_with_no_api_paths = []
        
        base_domain = ""
        
        for item in all_load_url:
            item_url = item.get('url', '')
            url_type = item.get('url_type', '')
            parsed = urlparse(item_url)
            
            if not parsed.netloc:
                continue
            
            if url_type == 'no_js':
                if parsed.path in ['/', '']:
                    tree_urls.append(item_url)
                    continue
                
                tree_url = f"{parsed.scheme}://{parsed.netloc}"
                tree_urls.append(tree_url)
                
                path = parsed.path
                api_path_index = path.find('api/')
                if api_path_index != -1:
                    path_with_api_url = f"{parsed.scheme}://{parsed.netloc}{path[:api_path_index]}api"
                    path_with_api_urls.append(path_with_api_url)
                    
                    base_url = path_with_api_url.rsplit('/', 1)[0]
                    if base_url and base_url != path_with_api_url:
                        base_urls.append(base_url.rstrip('/'))
        
        tree_urls = list(set(tree_urls))
        path_with_api_urls = list(set(path_with_api_urls))
        base_urls = list(set(base_urls))
        
        for api in all_api_paths:
            api_path = api.path
            if not api_path or api_path == '/' or api_path.startswith('http'):
                continue
            if len(api_path) < 2:
                continue
            
            api_path_index = api_path.find('api/')
            if api_path_index != -1:
                path_with_api_path = f"/{api_path[:api_path_index].lstrip('/')}api"
                if path_with_api_path not in path_with_api_paths:
                    path_with_api_paths.append(path_with_api_path)
                
                path_no_api = f"/{api_path[api_path_index+4:]}"
                if path_no_api and path_no_api != '/' and len(path_no_api) > 1:
                    path_with_no_api_paths.append(path_no_api)
            else:
                if api_path.startswith('/'):
                    path_with_no_api_paths.append(api_path)
                else:
                    path_with_no_api_paths.append('/' + api_path)
        
        for path_with_api_url in path_with_api_urls:
            parsed = urlparse(path_with_api_url)
            path_str = parsed.path
            if path_str:
                path_with_api_paths.append(path_str)
        
        path_with_api_paths = list(set(path_with_api_paths))
        path_with_no_api_paths = list(set(path_with_no_api_paths))

        all_parent_paths = set()
        all_resource_paths = set()
        all_variants = []

        for path in path_with_no_api_paths:
            variants = self.generate_path_variants(path)
            all_parent_paths.update(variants.get('parent_paths', []))
            resource = variants.get('resource_path', path) or path
            all_resource_paths.add(resource)

            if variants.get('v1'):
                all_variants.append(variants['v1'])
            if variants.get('v2'):
                all_variants.append(variants['v2'])

        for path in path_with_api_paths:
            variants = self.generate_path_variants(path)
            all_parent_paths.update(variants.get('parent_paths', []))

        parent_paths_list = list(all_parent_paths)
        resource_paths_list = list(all_resource_paths)

        if not path_with_api_paths:
            path_with_api_paths.append('/api')

        all_combined_urls = []
        for base in base_urls + tree_urls:
            for api_path in path_with_api_paths:
                if api_path == '/api' and base_urls:
                    all_combined_urls.append(base)
                elif api_path:
                    combined = f"{base}{api_path}"
                    all_combined_urls.append(combined)

        api_urls = []
        variant_urls = []

        for combined_url in all_combined_urls:
            for no_api_path in path_with_no_api_paths:
                full_url = f"{combined_url}{no_api_path}"
                if full_url not in api_urls:
                    api_urls.append(full_url)

            for resource_path in resource_paths_list:
                for parent_path in parent_paths_list:
                    variant_url = f"{parent_path}{resource_path}"
                    if variant_url not in variant_urls:
                        variant_urls.append(variant_url)

                variant_url = resource_path
                if variant_url not in variant_urls:
                    variant_urls.append(variant_url)

            for self_api in self.self_api_paths:
                full_url = f"{combined_url}/{self_api}"
                if full_url not in api_urls:
                    api_urls.append(full_url)

        return {
            'tree_urls': tree_urls,
            'base_urls': base_urls,
            'parent_paths': parent_paths_list,
            'resource_paths': resource_paths_list,
            'path_with_api_paths': path_with_api_paths,
            'path_with_no_api_paths': path_with_no_api_paths,
            'path_variants': all_variants,
            'all_combined_urls': list(set(all_combined_urls)),
            'api_urls': list(set(api_urls)),
            'variant_urls': list(set(variant_urls))
        }
    
    def generate_probe_urls(
        self,
        base_url: str,
        paths_to_probe: List[str],
        suffixes: List[str] = None
    ) -> List[str]:
        """
        生成探测URL列表
        
        Args:
            base_url: 基础URL
            paths_to_probe: 需要探测的路径列表
            suffixes: 探测后缀列表
            
        Returns:
            完整的探测URL列表
        """
        if suffixes is None:
            suffixes = self.self_api_paths
        
        probe_urls = []
        
        for path in paths_to_probe:
            clean_path = path.strip().rstrip('/')
            
            if clean_path.startswith('http'):
                full_base = clean_path
            else:
                full_base = f"{base_url.rstrip('/')}/{clean_path.lstrip('/')}"
            
            probe_urls.append(full_base)
            
            for suffix in suffixes[:20]:
                probe_urls.append(f"{full_base}/{suffix}")
        
        return list(set(probe_urls))
