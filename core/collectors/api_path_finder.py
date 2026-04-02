"""
ApiPathFinder Module
基于原项目 ChkApi_0x727 的核心API发现逻辑
提供强大的API路径发现能力
"""

import re
import hashlib
import logging
from collections import defaultdict
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
    {'key': 'application/x-www-form-urlencoded', 'tag': 'post'},
    {'key': 'application/vnd.tcpdump.pcap', 'tag': 'pcap'},
    {'key': 'application/mbox', 'tag': 'mbox'},
    {'key': 'text/x-gpsql', 'tag': 'x-gpsql'},
    {'key': 'text/x-chdr', 'tag': 'x-chdr'},
    {'key': 'text/x-modelica', 'tag': 'x-modelica'},
    {'key': 'text/babel$', 'tag': 'babel$'},
    {'key': 'text/x-sparksql', 'tag': 'x-sparksql'},
    {'key': 'text/x-octave', 'tag': 'x-octave'},
    {'key': 'x-shader/x-fragment', 'tag': 'x-fragment'},
    {'key': 'text/x-haml', 'tag': 'x-haml'},
    {'key': 'text/x-c++hdr', 'tag': 'x-c++hdr'},
    {'key': 'text/x-gfm', 'tag': 'x-gfm'},
    {'key': 'text/x-esper', 'tag': 'x-esper'},
    {'key': 'text/sass/i', 'tag': 'i'},
    {'key': 'text/vbscript', 'tag': 'vbscript'},
    {'key': 'text/jsx', 'tag': 'jsx'},
    {'key': 'text/x-rpm-spec', 'tag': 'x-rpm-spec'},
    {'key': 'application/x-powershell', 'tag': 'x-powershell'},
    {'key': 'text/x-elm', 'tag': 'x-elm'},
    {'key': 'text/x-cmake', 'tag': 'x-cmake'},
    {'key': 'text/x-erlang', 'tag': 'x-erlang'},
    {'key': 'text/x-fsharp', 'tag': 'x-fsharp'},
    {'key': 'text/x-livescript', 'tag': 'x-livescript'},
    {'key': 'text/x-pig', 'tag': 'x-pig'},
    {'key': 'text/x-json', 'tag': 'x-json'},
    {'key': 'text/x-objectivec', 'tag': 'x-objectivec'},
    {'key': 'video/ogg', 'tag': 'ogg'},
    {'key': 'text/x-webidl', 'tag': 'x-webidl'},
    {'key': 'application/x-cypher-query', 'tag': 'x-cypher-query'},
    {'key': 'text/x-sas', 'tag': 'x-sas'},
    {'key': 'text/x-rst', 'tag': 'x-rst'},
    {'key': 'text/x-properties', 'tag': 'x-properties'},
    {'key': 'text/x-fortran', 'tag': 'x-fortran'},
    {'key': 'text/x-verilog', 'tag': 'x-verilog'},
    {'key': 'text/x-ttcn-cfg', 'tag': 'x-ttcn-cfg'},
    {'key': 'text/x-oz', 'tag': 'x-oz'},
    {'key': 'text/x-diff', 'tag': 'x-diff'},
    {'key': 'application/javascript', 'tag': 'javascript'},
    {'key': 'text/x-fcl', 'tag': 'x-fcl'},
    {'key': 'text/x-sqlite', 'tag': 'x-sqlite'},
    {'key': 'text/x-ecl', 'tag': 'x-ecl'},
    {'key': 'text/x-scss', 'tag': 'x-scss'},
    {'key': 'text/jinja2', 'tag': 'jinja2'},
    {'key': 'application/sparql-query', 'tag': 'sparql-query'},
    {'key': 'text/x-julia', 'tag': 'x-julia'},
    {'key': 'text/x-dockerfile', 'tag': 'x-dockerfile'},
    {'key': 'text/x-mariadb', 'tag': 'x-mariadb'},
    {'key': 'text/yaml', 'tag': 'yaml'},
    {'key': 'application/x-jsp', 'tag': 'x-jsp'},
    {'key': 'application/x-httpd-php', 'tag': 'x-httpd-php'},
    {'key': 'text/x-perl', 'tag': 'x-perl'},
    {'key': 'application/x-json', 'tag': 'x-json'},
    {'key': 'text/x-csharp', 'tag': 'x-csharp'},
    {'key': 'text/x-cobol', 'tag': 'x-cobol'},
    {'key': 'text/x-groovy', 'tag': 'x-groovy'},
    {'key': 'text/x-squirrel', 'tag': 'x-squirrel'},
    {'key': 'text/markdown', 'tag': 'markdown'},
    {'key': 'application/pgp-encrypted', 'tag': 'pgp-encrypted'},
    {'key': 'text/x-latex', 'tag': 'x-latex'},
    {'key': 'application/dart', 'tag': 'dart'},
    {'key': 'application/x-aspx', 'tag': 'x-aspx'},
    {'key': 'text/x-gas', 'tag': 'x-gas'},
    {'key': 'text/x-protobuf', 'tag': 'x-protobuf'},
    {'key': 'text/x-literate-haskell', 'tag': 'x-literate-haskell'},
    {'key': 'text/x-django', 'tag': 'x-django'},
    {'key': 'text/x-smarty', 'tag': 'x-smarty'},
    {'key': 'application/edn', 'tag': 'edn'},
    {'key': 'application/n-triples', 'tag': 'n-triples'},
    {'key': 'auth/forge-password', 'tag': 'forge-password'},
    {'key': 'text/x-sml', 'tag': 'x-sml'},
    {'key': 'text/x-brainfuck', 'tag': 'x-brainfuck'},
    {'key': 'application/pgp', 'tag': 'pgp'},
    {'key': 'text/x-d', 'tag': 'x-d'},
    {'key': 'text/x-gss', 'tag': 'x-gss'},
    {'key': 'application/x-javascript', 'tag': 'x-javascript'},
    {'key': 'text/troff', 'tag': 'troff'},
    {'key': 'application/x-httpd', 'tag': 'x-httpd'},
    {'key': 'text/x-idl', 'tag': 'x-idl'},
    {'key': 'text/x-clojure', 'tag': 'x-clojure'},
    {'key': 'text/x-xu', 'tag': 'x-xu'},
    {'key': 'text/x-hive', 'tag': 'x-hive'},
    {'key': 'text/x-gql', 'tag': 'x-gql'},
    {'key': 'text/x-pug', 'tag': 'x-pug'},
    {'key': 'text/apl', 'tag': 'apl'},
    {'key': 'application/xquery', 'tag': 'xquery'},
    {'key': 'audio/wav', 'tag': 'wav'},
    {'key': 'application/x-php', 'tag': 'x-php'},
    {'key': 'video/mp4', 'tag': 'mp4'},
    {'key': 'application/spring-json', 'tag': 'spring-json'},
]

CONTENT_TYPE_PURE = frozenset(item['key'] for item in CONTENT_TYPE_LIST)

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
        self._method_patterns = self._compile_method_patterns()
    
    def _compile_method_patterns(self) -> List[Tuple[re.Pattern, str]]:
        """编译HTTP方法识别模式"""
        patterns = [
            (re.compile(r'\.get\s*\(\s*["\']([^"\']+)["\']'), 'GET'),
            (re.compile(r'\.post\s*\(\s*["\']([^"\']+)["\']'), 'POST'),
            (re.compile(r'\.put\s*\(\s*["\']([^"\']+)["\']'), 'PUT'),
            (re.compile(r'\.delete\s*\(\s*["\']([^"\']+)["\']'), 'DELETE'),
            (re.compile(r'\.patch\s*\(\s*["\']([^"\']+)["\']'), 'PATCH'),
            (re.compile(r'\.head\s*\(\s*["\']([^"\']+)["\']'), 'HEAD'),
            (re.compile(r'\.options\s*\(\s*["\']([^"\']+)["\']'), 'OPTIONS'),
            (re.compile(r'\.get\s*\(\s*`([^`]+)`'), 'GET'),
            (re.compile(r'\.post\s*\(\s*`([^`]+)`'), 'POST'),
            (re.compile(r'\.put\s*\(\s*`([^`]+)`'), 'PUT'),
            (re.compile(r'\.delete\s*\(\s*`([^`]+)`'), 'DELETE'),
            (re.compile(r'axios\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE), 'AUTO'),
            (re.compile(r'fetch\s*\(\s*["\']([^"\']+)["\']'), 'GET'),
            (re.compile(r'\$(?:\.ajax|\.get|\.post)\s*\(\s*\{[^}]*?url\s*:\s*["\']([^"\']+)["\']'), 'AUTO'),
            (re.compile(r'method\s*:\s*["\']?(POST|PUT|DELETE|PATCH)["\']?', re.IGNORECASE), 'AUTO'),
            (re.compile(r'_method\s*=\s*["\']?(POST|PUT|DELETE|PATCH)["\']?', re.IGNORECASE), 'AUTO'),
            (re.compile(r'\.request\s*\(\s*\{[^}]*?method\s*:\s*["\']?(POST|PUT|DELETE|PATCH)["\']?', re.IGNORECASE), 'AUTO'),
        ]
        return [(re.compile(p, re.IGNORECASE), m) for p, m in patterns]
    
    def infer_method_from_context(self, text: str, path: str) -> str:
        """
        从上下文推断HTTP方法
        
        Args:
            text: 包含路径的文本内容
            path: API路径
            
        Returns:
            HTTP方法 (GET, POST, PUT, DELETE, PATCH, AUTO)
        """
        path_lower = path.lower()
        path_pos = text.lower().find(path_lower)
        
        if path_pos == -1:
            return 'GET'
        
        context_start = max(0, path_pos - 200)
        context_end = min(len(text), path_pos + len(path) + 200)
        context = text[context_start:context_end]
        
        method_counts = {'GET': 0, 'POST': 0, 'PUT': 0, 'DELETE': 0, 'PATCH': 0}
        
        for pattern, method in self._method_patterns:
            matches = pattern.findall(context)
            if method == 'AUTO':
                for match in matches:
                    match_upper = match.upper() if isinstance(match, str) else ''
                    if match_upper in method_counts:
                        method_counts[match_upper] += 1
                    else:
                        method_counts['GET'] += 1
            else:
                method_counts[method] += len(matches)
        
        max_method = max(method_counts.items(), key=lambda x: x[1])
        return max_method[0] if max_method[1] > 0 else 'GET'
    
    def find_api_paths_with_method(self, text: str, referer: str = "") -> List[DiscoveredAPI]:
        """
        在文本中查找API路径并识别HTTP方法
        
        Args:
            text: JavaScript/HTML文本内容
            referer: 来源URL
            
        Returns:
            发现的API路径列表（带HTTP方法）
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
                            
                            method = self.infer_method_from_context(text, path)
                            api = self._create_api_object(path, referer, method)
                            if api:
                                found_apis.append(api)
                                self.all_api_paths.add(path)
            except Exception as e:
                logger.debug(f"Pattern matching error: {e}")
                continue
        
        return found_apis
    
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
    
    def _create_api_object(self, path: str, referer: str, method: str = "GET") -> Optional[DiscoveredAPI]:
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
        
        if method == "AUTO":
            method = "GET"
        
        return DiscoveredAPI(
            path=path,
            referer=referer,
            url_type="api_path",
            method=method,
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

    COMMON_RESOURCES = [
        'user', 'users', 'order', 'orders', 'product', 'products', 'goods',
        'role', 'roles', 'menu', 'menus', 'category', 'categories',
        'config', 'configuration', 'settings', 'system', 'admin', 'auth',
        'department', 'dept', 'employee', 'customer', 'customers',
        'account', 'accounts', 'permission', 'permissions',
        'file', 'files', 'image', 'images', 'video', 'videos',
        'payment', 'transaction', 'invoice', 'receipt',
        'address', 'notification', 'message', 'msg',
        'device', 'devices', 'gateway', 'sensor', 'alarm',
        'tag', 'tags', 'comment', 'comments', 'article', 'articles',
        'log', 'logs', 'monitor', 'tool', 'tools',
        'checkCode', 'captcha', 'captchas',
    ]

    COMMON_METHODS = [
        'list', 'add', 'create', 'delete', 'remove', 'detail', 'info', 'update', 'edit',
        'get', 'set', 'save', 'query', 'search', 'filter', 'export', 'import',
        'login', 'logout', 'register', 'reset', 'verify', 'refresh',
        'enable', 'disable', 'status', 'config', 'upload', 'download',
        'getCheckCode', 'getCheckcode', 'check', 'validate',
    ]

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
        return s.lower() in [
            'list', 'add', 'create', 'delete', 'detail', 'info', 'update', 'edit',
            'get', 'set', 'save', 'query', 'search', 'filter', 'export', 'import',
            'login', 'logout', 'register', 'reset', 'verify', 'refresh',
            'enable', 'disable', 'status', 'config', 'upload', 'download',
        ]

    @staticmethod
    def _is_common_resource(s: str) -> bool:
        """判断是否为常见资源"""
        return s.lower() in [
            'user', 'users', 'order', 'orders', 'product', 'products', 'goods',
            'role', 'roles', 'menu', 'menus', 'category', 'categories',
            'config', 'configuration', 'settings', 'system', 'admin', 'auth',
            'department', 'dept', 'employee', 'customer', 'customers',
            'account', 'accounts', 'permission', 'permissions',
            'file', 'files', 'image', 'images', 'video', 'videos',
            'payment', 'transaction', 'invoice', 'receipt',
            'address', 'notification', 'message', 'msg',
            'device', 'devices', 'gateway', 'sensor', 'alarm',
            'tag', 'tags', 'comment', 'comments', 'article', 'articles',
            'checkCode', 'captcha',
        ]

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
        提取代理/网关前缀（使用混合算法）

        对于 /inspect/login/checkCode/getCheckCode：
        - 'login' 是常见资源
        - 'checkCode' 是驼峰资源
        - 'getCheckCode' 是常见后缀
        - 所以第一段非资源 segment 就是代理前缀: /inspect
        """
        if not api_path:
            return None

        api_prefix_index = ApiPathCombiner.find_api_prefix_index(api_path)
        if api_prefix_index is not None and api_prefix_index > 0:
            return '/' + '/'.join(api_path.strip('/').split('/')[:api_prefix_index])

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

    @staticmethod
    def extract_resource_path(api_path: str) -> Optional[str]:
        """
        提取资源路径（去掉第一段后的所有部分）

        例如: /inspect/login/checkCode/getCheckCode
        返回: /login/checkCode/getCheckCode
        """
        if not api_path:
            return None

        path = api_path.strip('/')
        parts = path.split('/')

        if len(parts) >= 2:
            return '/' + '/'.join(parts[1:])

        return api_path

    @staticmethod
    def extract_api_prefix_from_base(base_url: str) -> Optional[str]:
        """
        从 base_url 中提取 API 前缀路径

        例如: http://x.x.x.x:8082/prod-api -> /prod-api
        """
        if not base_url:
            return None

        parsed = urlparse(base_url)
        path = parsed.path.strip('/')
        if path:
            return '/' + path
        return None

    @staticmethod
    def generate_path_variants(api_path: str, base_url_path: str = "") -> Dict[str, Any]:
        """
        生成路径变体 - 基于正确的语义组合

        对于 /inspect/prod-api/checkCode/getCheckCode，base_url_path = /inspect/：
        - base_url 路径 = /inspect/
        - 相对路径 = /prod-api/checkCode/getCheckCode
        - 微服务前缀 (api_prefix) = prod-api
        - 资源路径 = /checkCode/getCheckCode

        生成以下变体用于 fuzzing：
        1. 原始相对路径: /prod-api/checkCode/getCheckCode
        2. 微服务前缀 + 常见资源 + 常见方法: /prod-api/user/add, /prod-api/order/list
        3. 尝试 /api 前缀: /api/checkCode/getCheckCode
        4. 去掉微服务前缀: /checkCode/getCheckCode
        """
        if not api_path:
            return {}

        path = api_path.strip('/')
        parts = path.split('/')

        api_prefix_index = ApiPathCombiner.find_api_prefix_index(api_path)

        first_parent: Optional[str] = None
        api_prefix: Optional[str] = None
        resource_path: Optional[str] = None

        if api_prefix_index is not None:
            if api_prefix_index == 0:
                first_parent = None
                api_prefix = parts[0]
                resource_path = '/' + '/'.join(parts[1:]) if len(parts) > 1 else api_path
            elif api_prefix_index > 0:
                first_parent = '/' + '/'.join(parts[:api_prefix_index])
                api_prefix = parts[api_prefix_index]
                resource_path = '/' + '/'.join(parts[api_prefix_index + 1:])
        else:
            first_parent = '/' + parts[0] if parts else None
            api_prefix = None
            resource_path = '/' + '/'.join(parts[1:]) if len(parts) > 1 else api_path

        base_path_parts = base_url_path.strip('/').split('/') if base_url_path else []
        relative_parts = []
        i = 0
        for bp in base_path_parts:
            if i < len(parts) and parts[i] == bp:
                i += 1
            else:
                break
        relative_parts = parts[i:]
        relative_path = '/' + '/'.join(relative_parts) if relative_parts else api_path

        api_prefixes = ApiPathCombiner.API_PREFIXES
        common_resources = ApiPathCombiner.COMMON_RESOURCES
        common_methods = ApiPathCombiner.COMMON_METHODS

        fuzzing_variants = []
        if api_prefix:
            for resource in common_resources[:15]:
                for method in common_methods[:10]:
                    fuzzing_variants.append(f'/{api_prefix}/{resource}/{method}')
                    fuzzing_variants.append(f'/{api_prefix}/{resource}/{method}s')

        variants: Dict[str, Any] = {
            'original': api_path,
            'relative_path': relative_path,
            'first_parent': first_parent,
            'api_prefix': api_prefix,
            'api_prefix_index': api_prefix_index,
            'resource_path': resource_path,
            'v1': f'/{api_prefix}{resource_path}' if api_prefix else relative_path,
            'v2': f'/{api_prefix}' if api_prefix else None,
            'v3': f'/api{resource_path}' if api_prefix else f'/api{relative_path}',
            'v4': resource_path,
            'fuzzing_variants': fuzzing_variants,
        }

        return variants

    API_PREFIXES = [
        'api', 'prod-api', 'test-api', 'dev-api',
        'v1', 'v2', 'v3', 'v4', 'v5',
        'rest', 'graphql', 'rpc', 'soap', 'grpc',
        'gateway', 'proxy', 'service',
        'admin', 'manage', 'system',
    ]

    PREFIX_PATTERNS = [
        r'/([a-zA-Z][a-zA-Z0-9_-]+)/',           # /xxx/ 或 /xxx-xxx/ 模式
        r'/([a-zA-Z]+_[a-zA-Z0-9_]+)/',        # /xxx_xxx/ 模式
        r'["\']/([a-zA-Z][a-zA-Z0-9_-]+)/',    # "/xxx/" 模式
        r'baseUrl\s*[=:+]\s*["\']/([^"\']+)',     # baseUrl = "/api"
        r'API_PREFIX\s*[=:+]\s*["\']/([^"\']+)',  # API_PREFIX = "/prod-api"
        r'BASE_URL\s*[=:+]\s*["\']/([^"\']+)',   # BASE_URL = "/api"
        r'prefix\s*[=:+]\s*["\']/([^"\']+)',      # prefix: "/v1"
        r'"([a-zA-Z]+-[a-zA-Z]+)"\s*:\s*["\']/([^"\']+)',  # "gas-engine": "/api"
    ]

    @staticmethod
    def discover_prefixes_from_js(js_content: str) -> List[str]:
        """
        从 JS 内容中发现所有可能的前缀模式

        使用多种正则模式匹配：
        1. /xxx/ 或 /xxx-xxx/ 模式
        2. /xxx_xxx/ 模式
        3. baseUrl = "/api" 模式
        4. API_PREFIX = "/prod-api" 模式
        5. 前缀拼接如 baseUrl + '/api'
        """
        prefixes = set()

        prefix_patterns = [
            r'/([a-zA-Z][a-zA-Z0-9_-]+)/',           # /xxx/ 或 /xxx-xxx/
            r'/([a-zA-Z]+_[a-zA-Z0-9_]+)/',        # /xxx_xxx/
            r'baseUrl\s*[=:+]\s*["\']/([^"\']+)',     # baseUrl = "/api"
            r'API_PREFIX\s*[=:+]\s*["\']/([^"\']+)',  # API_PREFIX = "/prod-api"
            r'BASE_URL\s*[=:+]\s*["\']/([^"\']+)',   # BASE_URL = "/api"
            r'prefix\s*[=:+]\s*["\']/([^"\']+)',      # prefix: "/v1"
            r'"([a-zA-Z]+-[a-zA-Z]+)"\s*:\s*["\']/([^"\']+)',  # "gas-engine": "/api"
        ]

        for pattern in prefix_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    prefix = match[0] if len(match) > 0 else match
                else:
                    prefix = match
                if prefix and len(prefix) > 1:
                    prefixes.add(f'/{prefix}')

        prefix_patterns2 = [
            r'\+\s*["\']/([a-zA-Z][a-zA-Z0-9_-]+)["\']',  # prefix + '/api'
            r'["\']/([a-zA-Z][a-zA-Z0-9_-]+)["\']\s*\+',  # '/api' + suffix
        ]

        for pattern in prefix_patterns2:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                if match and len(match) > 1:
                    prefixes.add(f'/{match}')

        return list(prefixes)

    VERSION_PREFIXES = ['v1', 'v2', 'v3', 'v4', 'v5']

    @staticmethod
    def validate_api_prefix(prefix: str, js_content: str = "") -> bool:
        """
        验证是否为真正的 API 前缀

        使用混合算法：知识库 + 模式匹配 + 频率统计

        注意：v1, v2, v3 等版本号不能单独作为前缀，需要和其他前缀结合
        """
        if not prefix:
            return False

        prefix_clean = prefix.strip('/').lower()

        if prefix_clean in [p.lower() for p in ApiPathCombiner.VERSION_PREFIXES]:
            return False

        if prefix_clean in [p.lower() for p in ApiPathCombiner.API_PREFIXES]:
            return True

        if re.match(r'^[a-zA-Z]+(-[a-zA-Z]+)+$', prefix_clean):
            return True

        if re.match(r'^[a-zA-Z]+(_[a-zA-Z0-9]+)+$', prefix_clean):
            return True

        if js_content:
            count = js_content.count(prefix) + js_content.count(prefix.lower()) + js_content.count(prefix.upper())
            if count >= 2:
                return True

        return False

    @staticmethod
    def is_version_prefix(prefix: str) -> bool:
        """判断是否为版本号前缀"""
        return prefix.strip('/').lower() in [p.lower() for p in ApiPathCombiner.VERSION_PREFIXES]

    @staticmethod
    def find_api_prefix_index(path: str) -> Optional[int]:
        """
        查找路径中 API 前缀的位置

        例如: /inspect/prod-api/checkCode/getCheckCode
        返回: 1 (prod-api 在 parts[1])

        例如: /login/api/wx_login
        返回: 1 (api 在 parts[1])
        """
        if not path:
            return None

        parts = path.strip('/').split('/')

        for i, part in enumerate(parts):
            if part.lower() in ApiPathCombiner.API_PREFIXES:
                return i

        return None

    def filter_data(
        self,
        all_load_url: List[Dict[str, str]],
        all_api_paths: List[DiscoveredAPI],
        js_contents: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        智能组合API路径 - 完整拼接矩阵

        支持：
        1. tree_urls × base_urls × discovered_prefixes × resource_paths
        2. 从 JS 内容中发现更多前缀
        3. 混合拼接最大化发现隐藏接口

        Args:
            all_load_url: 所有加载的URL列表
            all_api_paths: 所有发现的API路径
            js_contents: JS 内容字典 {url: content}

        Returns:
            包含各种组合结果的字典
        """
        if js_contents is None:
            js_contents = {}

        base_urls = []
        tree_urls = []
        path_with_api_urls = []
        path_with_api_paths = []
        path_with_no_api_paths = []
        discovered_prefixes = set()

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

        for js_url, js_content in js_contents.items():
            prefixes = self.discover_prefixes_from_js(js_content)
            for prefix in prefixes:
                if self.validate_api_prefix(prefix, js_content):
                    discovered_prefixes.add(prefix)

        path_with_api_paths = list(set(path_with_api_paths))
        path_with_no_api_paths = list(set(path_with_no_api_paths))
        discovered_prefixes = list(discovered_prefixes)

        if not path_with_api_paths:
            path_with_api_paths.append('/api')

        all_first_parents = set()
        all_parent_resource_map = {}
        all_variants = []
        all_resource_paths = set()

        for path in path_with_no_api_paths:
            variants = self.generate_path_variants(path)

            first_parent = variants.get('first_parent')
            if first_parent:
                all_first_parents.add(first_parent)

            parents = variants.get('parents', {})
            for parent, resource in parents.items():
                all_parent_resource_map[parent] = resource
                all_resource_paths.add(resource)

            if variants.get('v1'):
                all_variants.append(variants['v1'])
            if variants.get('v2'):
                all_variants.append(variants['v2'])

        for path in path_with_api_paths:
            variants = self.generate_path_variants(path)
            first_parent = variants.get('first_parent')
            if first_parent:
                all_first_parents.add(first_parent)

        first_parents_list = list(all_first_parents)
        parent_resource_list = list(all_parent_resource_map.items())

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

            for self_api in self.self_api_paths:
                full_url = f"{combined_url}/{self_api}"
                if full_url not in api_urls:
                    api_urls.append(full_url)

        all_api_prefixes = ['/api', '/rest', '/graphql', '/rpc']
        all_prefixes = list(discovered_prefixes) + all_api_prefixes + first_parents_list

        version_prefixes = ['/v1', '/v2', '/v3', '/v4', '/v5']

        for base in base_urls + tree_urls:
            base_clean = base.rstrip('/')
            parsed_base = urlparse(base)

            for variant in all_variants:
                full_url = f"{base_clean}{variant}"
                if full_url not in variant_urls:
                    variant_urls.append(full_url)

            for first_parent in first_parents_list:
                first_parent_clean = first_parent.rstrip('/')

                if parsed_base.path and parsed_base.path != '/':
                    combined = f"{first_parent_clean}{parsed_base.path}"
                else:
                    combined = first_parent_clean

                for resource in all_resource_paths:
                    full_url = f"{parsed_base.scheme}://{parsed_base.netloc}{combined}{resource}"
                    if full_url not in variant_urls:
                        variant_urls.append(full_url)

                for api_prefix in all_prefixes:
                    for variant in all_variants:
                        variant_path = '/' + '/'.join(variant.split('/')[2:]) if '/' in variant else variant
                        full_url = f"{parsed_base.scheme}://{parsed_base.netloc}{first_parent_clean}{api_prefix}{variant_path}"
                        if full_url not in variant_urls:
                            variant_urls.append(full_url)

                for version in version_prefixes:
                    for resource in all_resource_paths:
                        full_url = f"{parsed_base.scheme}://{parsed_base.netloc}{first_parent_clean}{api_prefix}{version}{resource}"  # type: ignore
                        if full_url not in variant_urls:
                            variant_urls.append(full_url)

        for base in base_urls + tree_urls:
            parsed_base = urlparse(base)

            for prefix in all_prefixes:
                for variant in all_variants:
                    full_url = f"{parsed_base.scheme}://{parsed_base.netloc}{prefix}{variant}"
                    if full_url not in variant_urls:
                        variant_urls.append(full_url)

                for no_api_path in path_with_no_api_paths:
                    full_url = f"{parsed_base.scheme}://{parsed_base.netloc}{prefix}{no_api_path}"
                    if full_url not in variant_urls:
                        variant_urls.append(full_url)

            for prefix in all_prefixes:
                for version in version_prefixes:
                    for no_api_path in path_with_no_api_paths:
                        full_url = f"{parsed_base.scheme}://{parsed_base.netloc}{prefix}{version}{no_api_path}"
                        if full_url not in variant_urls:
                            variant_urls.append(full_url)

        return {
            'tree_urls': tree_urls,
            'base_urls': base_urls,
            'discovered_prefixes': discovered_prefixes,
            'first_parents': first_parents_list,
            'parent_resource_map': parent_resource_list,
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
        suffixes: Optional[List[str]] = None
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


class ResponseDiffer:
    """
    响应差异化分析器
    使用 SHA256 对响应内容去重，发现差异化响应
    """

    @staticmethod
    def compute_content_hash(content: bytes) -> str:
        """计算响应内容的 SHA256 哈希值"""
        return hashlib.sha256(content).hexdigest()

    @staticmethod
    def diff_responses(responses: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        对响应列表进行差异化分析

        Args:
            responses: 响应列表，每个元素包含 url, content, status_code, content_type 等

        Returns:
            按 content_hash 分组的响应字典
            {
                'hash1': [{url, content, status_code, ...}, ...],
                'hash2': [...],
            }
        """
        hash_map = defaultdict(list)

        for resp in responses:
            content = resp.get('content', b'')
            if isinstance(content, str):
                content = content.encode('utf-8')

            content_hash = ResponseDiffer.compute_content_hash(content)
            resp['content_hash'] = content_hash
            hash_map[content_hash].append(resp)

        return dict(hash_map)

    @staticmethod
    def filter_unique_responses(
        responses: List[Dict[str, Any]],
        min_group_size: int = 1
    ) -> List[Dict[str, Any]]:
        """
        过滤出唯一的响应（按内容hash去重）

        Args:
            responses: 响应列表
            min_group_size: 最小分组大小，用于过滤常见响应

        Returns:
            唯一响应列表
        """
        hash_map = ResponseDiffer.diff_responses(responses)

        unique = []
        for content_hash, group in hash_map.items():
            if len(group) >= min_group_size:
                group[0]['response_count'] = len(group)
                unique.append(group[0])

        return unique

    @staticmethod
    def find_different_responses(
        baseline: Dict[str, Any],
        responses: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        找出与基线不同的响应

        Args:
            baseline: 基线响应
            responses: 待比较的响应列表

        Returns:
            与基线不同的响应列表
        """
        baseline_hash = baseline.get('content_hash')
        if not baseline_hash:
            baseline_content = baseline.get('content', b'')
            if isinstance(baseline_content, str):
                baseline_content = baseline_content.encode('utf-8')
            baseline_hash = ResponseDiffer.compute_content_hash(baseline_content)

        different = []
        for resp in responses:
            resp_hash = resp.get('content_hash')
            if not resp_hash:
                content = resp.get('content', b'')
                if isinstance(content, str):
                    content = content.encode('utf-8')
                resp_hash = ResponseDiffer.compute_content_hash(content)
                resp['content_hash'] = resp_hash

            if resp_hash != baseline_hash:
                different.append(resp)

        return different

    @staticmethod
    def get_rare_responses(
        responses: List[Dict[str, Any]],
        threshold: int = 10
    ) -> List[Dict[str, Any]]:
        """
        找出稀有响应（出现次数少于阈值的响应）

        Args:
            responses: 响应列表
            threshold: 阈值，默认10

        Returns:
            稀有响应列表
        """
        hash_map = ResponseDiffer.diff_responses(responses)

        rare = []
        for content_hash, group in hash_map.items():
            if len(group) < threshold:
                rare.extend(group)

        return rare
