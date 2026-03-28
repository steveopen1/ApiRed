"""
Scanner Patterns Configuration
扫描器相关配置模式
"""

API_SPEC_PATTERNS = [
    'swagger', 'swagger-ui', 'api-docs', 'openapi', 
    '/v1/api-docs', '/v2/api-docs', '/api/spec',
    '/api-docs', '/documentation', '/apidoc', '/api/doc',
]

API_ROOT_BLACK_LIST = [
    'favicon.ico', 'robots.txt', 'humans.txt', 'crossdomain.xml',
    'sitemap.xml', 'sitemap_index.xml', '.well-known', 'apple-app-site-association',
    '.env', '.git', '.svn', '.DS_Store', 'Thumbs.db',
    'META-INF', 'WEB-INF', 'WEB-INF/web.xml',
]

API_ROOT_BLACK_LIST_DURING_SPIDER = [
    'login', 'logout', 'register', 'signup', 'signin', 'auth',
    'captcha', 'verify', 'validation', 'reset-password', 'forgot-password',
    'confirm-email', 'verify-email', 'activate', 'unlock',
]

URL_BLACK_LIST = [
    'static', 'css', 'js', 'images', 'img', 'assets', 'fonts', 'media',
    'favicon', 'robots', 'sitemap', '404', '500', 'error', 'exception',
    'health', 'ping', 'metrics', 'monitor', 'info', 'version',
]

PATH_BLACK_PREFIX = [
    '/static/', '/assets/', '/public/', '/images/', '/css/', '/js/',
    '/vendor/', '/node_modules/', '/bower_components/',
    '/favicon', '/robots', '/sitemap', '/.well-known/',
]

PATH_BLACK_KEYWORDS = [
    'static', 'assets', 'public', 'images', 'css', 'js', 'fonts',
    'media', 'favicon', 'robots', 'sitemap',
]

PATH_BLACK_PATTERNS = [
    r'\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map)$',
    r'/static/', r'/assets/', r'/public/', r'/images/',
]

VUE_ROUTER_DIRS = [
    'router', 'routers', 'routes', 'vue-router', 'router/index',
    'router/routes', 'views', 'pages', 'components',
]

DANGER_API_LIST = [
    '/admin', '/manage', '/console', '/backend', '/system',
    '/internal', '/private', '/secret', '/config', '/setup',
    '/debug', '/test', '/staging', '/production',
]

RESPONSE_BLACK_TEXT = [
    '<!DOCTYPE html>', '<html', '<head>', '<title>Error</title>',
    '<body>', '<div class="error"', 'Page not found', '404 Not Found',
    '403 Forbidden', '500 Internal Server Error',
]

CONTENT_TYPE_LIST = [
    'text/html', 'application/json', 'application/xml', 'text/xml',
    'text/plain', 'application/javascript', 'text/css', 'image/',
    'font/', 'video/', 'audio/',
]

STATIC_FILE_EXT_BLACK_LIST = [
    'js', 'css', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'ico',
    'woff', 'woff2', 'ttf', 'eot', 'map', 'xml', 'html', 'txt',
]

URL_EXT_BLACK_LIST = [
    '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
    '.woff', '.woff2', '.ttf', '.eot', '.map', '.xml', '.html', '.txt',
]
