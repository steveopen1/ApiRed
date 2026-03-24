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
]

PATH_BLACK_PATTERN = [
    r'^\/\d+\/',
    r'\.min\.(js|css)$',
    r'^/@[a-zA-Z0-9]',
]

FILE_EXT_BLACK_LIST = [
    "exe", "apk", "mp4", "mkv", "mp3", "flv", "js", "css", "less",
    "woff", "woff2", "vue", "svg", "png", "jpg", "jpeg", "tif",
    "bmp", "gif", "psd", "exif", "fpx", "avif", "apng", "webp",
    "swf", "ico", "svga", "html", "htm", "shtml", "ts", "eot",
    "lrc", "tpl", "cur", "success", "error", "complete", "zip",
    "rar", "7z", "tar", "gz", "xz"
]

URL_EXT_BLACK_LIST = ["." + x if not x.startswith(",") else x for x in FILE_EXT_BLACK_LIST]

STATIC_FILE_EXT_BLACK_LIST = [
    "pdf", "docx", "doc", "exe", "apk", "mp4", "mkv", "mp3", "flv",
    "css", "less", "woff", "woff2", "vue", "svg", "png", "jpg",
    "jpeg", "tif", "bmp", "gif", "psd", "exif", "fpx", "avif",
    "apng", "webp", "swf", "ico", "svga", "ts", "eot", "lrc",
    "tpl", "cur", "success", "error", "complete", "zip", "rar",
    "7z", "tar", "gz", "xz"
]

STATIC_FILE_EXT_BLACK_LIST_FULL = [f".{ext}" for ext in STATIC_FILE_EXT_BLACK_LIST]

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
            
            for x in URL_EXT_BLACK_LIST:
                if clean_line.lower().endswith(x):
                    continue
            
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
            
            if not clean_line or len(clean_line) < 2:
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
    """
    
    def __init__(self):
        self.self_api_paths = COMMON_API_PATHS
    
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
        for combined_url in all_combined_urls:
            for no_api_path in path_with_no_api_paths:
                full_url = f"{combined_url}{no_api_path}"
                if full_url not in api_urls:
                    api_urls.append(full_url)
            
            for self_api in self.self_api_paths:
                full_url = f"{combined_url}/{self_api}"
                if full_url not in api_urls:
                    api_urls.append(full_url)
        
        return {
            'tree_urls': tree_urls,
            'base_urls': base_urls,
            'path_with_api_paths': path_with_api_paths,
            'path_with_no_api_paths': path_with_no_api_paths,
            'all_combined_urls': list(set(all_combined_urls)),
            'api_urls': list(set(api_urls))
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
