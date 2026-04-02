"""
API Bypass 技术库

实现多种 Bypass 技术，用于绕过 API 访问限制:
1. 路径规范化 Bypass
2. HTTP 方法 Bypass
3. 参数 Bypass
4. 版本号 Bypass
5. 路径遍历 Bypass
6. 协议/Content-Type Bypass
7. 认证 Bypass

参考 ChkApi_0x727 的 Bypass 技术实现
"""

import re
import logging
from typing import List, Dict, Set, Optional, Any, Tuple, Callable
from urllib.parse import urlparse, urljoin, quote, unquote
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class BypassTechnique(Enum):
    """Bypass 技术类型"""
    PATH_SUFFIX = "path_suffix"
    PATH_PREFIX = "path_prefix"
    HTTP_METHOD = "http_method"
    PARAMETER = "parameter"
    VERSION = "version"
    PATH_TRAVERSAL = "path_traversal"
    CONTENT_TYPE = "content_type"
    PROTOCOL = "protocol"
    AUTH_BYPASS = "auth_bypass"
    CASE_NORMALIZATION = "case_normalization"
    URL_ENCODING = "url_encoding"
    DOUBLE_SLASH = "double_slash"


@dataclass
class BypassResult:
    """Bypass 结果"""
    original_url: str
    bypassed_url: str
    technique: BypassTechnique
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    data: Optional[str] = None
    content_type: Optional[str] = None
    expected_status: int = 200
    description: str = ""


@dataclass 
class BypassResponse:
    """Bypass 响应结果"""
    bypassed_url: str
    status_code: int
    content: bytes
    headers: Dict[str, str]
    bypass_technique: BypassTechnique
    is_different: bool = False


class APIBypasser:
    """
    API Bypass 技术集合
    
    提供多种 Bypass 技术，用于发现隐藏 API 端点
    """

    PATH_SUFFIXES = [
        '', '/', '.json', '.jsonp', '.xml', '.yaml', '.yml',
        '.html', '.htm', '.do', '.action', '.asp', '.aspx',
        '.php', '.jsp', '/json', '/xml', '/yaml',
        '?json=1', '?output=json', '?format=json',
        '?api_key=', '?token=', '?key=',
    ]

    HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']

    METHOD_ALTERNATIVES = {
        'GET': ['POST', 'PUT', 'DELETE', 'PATCH'],
        'POST': ['GET', 'PUT', 'DELETE'],
        'PUT': ['POST', 'GET'],
        'DELETE': ['POST', 'GET'],
    }

    VERSION_PREFIXES = [
        '/v1', '/v2', '/v3', '/v4', '/v5',
        '/v1.0', '/v2.0', '/v3.0',
        '/api/v1', '/api/v2', '/api/v3',
        '/rest/v1', '/rest/v2',
        '/api', '/rest', '/graphql',
    ]

    COMMON_PARAMS = [
        'page=1', 'pageSize=10', 'limit=10', 'offset=0',
        'sort=asc', 'order=id', 'filter=', 'q=',
        'format=json', 'output=json', 'callback=',
        'api_key=test', 'token=test', 'key=test',
        'debug=true', 'test=1', '_=',
        'id=1', 'userId=1', 'uid=1', 'uuid=1',
        'name=', 'username=', 'phone=', 'mobile=',
        'status=1', 'type=1', 'category=',
        'startDate=', 'endDate=', 'startTime=', 'endTime=',
        'keyword=', 'query=', 'search=',
    ]
    
    RESTFUL_SUFFIXES = [
        'list', 'page', 'all', 'tree', 'export', 'import',
        'detail', 'info', 'view', 'show', 'get', 'fetch',
        'add', 'create', 'new', 'insert', 'save',
        'edit', 'update', 'modify', 'put', 'patch',
        'delete', 'remove', 'del', 'cancel',
        'login', 'logout', 'register', 'reset', 'forgetPassword',
        'enable', 'disable', 'status', 'switch', 'toggle',
        'bind', 'unbind', 'link', 'unlink',
        'upload', 'download', 'preview', 'thumbnail',
        'count', 'total', 'sum', 'statistics', 'stat',
        'approve', 'reject', 'submit', 'confirm', 'complete',
        'refresh', 'sync', 'init', 'config', 'setting',
        'menu', 'nav', 'options', 'select', 'combo',
        'template', 'sample', 'demo', 'test',
    ]

    PATH_TRAVERSAL_PATTERNS = [
        ('/../', '/'), ('/./', '/'), ('//', '/'),
        ('/%2e/', '/'), ('/%252e/', '.'),
        (';/', '/'), ('/;/', '/'),
    ]

    CONTENT_TYPES = [
        'application/json',
        'application/xml',
        'application/x-www-form-urlencoded',
        'multipart/form-data',
        'text/plain',
        'text/xml',
    ]

    AUTH_HEADERS = [
        {'Authorization': 'Bearer test'},
        {'Authorization': 'Basic dGVzdDp0ZXN0'},
        {'X-API-Key': 'test'},
        {'X-Auth-Token': 'test'},
        {'Cookie': 'token=test'},
    ]

    CASE_VARIANTS = [
        str.lower,
        str.upper,
        lambda s: s.title(),
        lambda s: ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(s)),
    ]

    def __init__(self):
        self.bypass_results: List[BypassResult] = []
        self._custom_bypasses: List[Callable] = []

    def add_custom_bypass(self, bypass_func: Callable):
        """添加自定义 Bypass 函数"""
        self._custom_bypasses.append(bypass_func)

    def bypass_all(self, url: str, method: str = "GET") -> List[BypassResult]:
        """
        对 URL 应用所有 Bypass 技术
        
        Args:
            url: 目标 URL
            method: HTTP 方法
            
        Returns:
            Bypass 结果列表
        """
        results = []
        
        results.extend(self.bypass_path_suffix(url, method))
        results.extend(self.bypass_path_prefix(url, method))
        results.extend(self.bypass_http_method(url, method))
        results.extend(self.bypass_version(url, method))
        results.extend(self.bypass_parameters(url, method))
        results.extend(self.bypass_path_traversal(url, method))
        results.extend(self.bypass_content_type(url, method))
        results.extend(self.bypass_case_normalization(url, method))
        results.extend(self.bypass_url_encoding(url, method))
        results.extend(self.bypass_double_slash(url, method))
        
        for custom_bypass in self._custom_bypasses:
            try:
                custom_results = custom_bypass(url, method)
                if custom_results:
                    results.extend(custom_results)
            except Exception as e:
                logger.debug(f"Custom bypass failed: {e}")
        
        self.bypass_results.extend(results)
        return results

    def bypass_path_suffix(self, url: str, method: str = "GET") -> List[BypassResult]:
        """路径后缀 Bypass"""
        results = []
        parsed = urlparse(url)
        path = parsed.path.rstrip('/')
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        for suffix in self.PATH_SUFFIXES:
            if not suffix:
                continue
            
            new_path = path + suffix
            bypassed_url = base + new_path
            if parsed.query:
                bypassed_url += '?' + parsed.query
            
            results.append(BypassResult(
                original_url=url,
                bypassed_url=bypassed_url,
                technique=BypassTechnique.PATH_SUFFIX,
                method=method,
                description=f"Add suffix: {suffix}"
            ))
        
        if not path.endswith('.json'):
            results.append(BypassResult(
                original_url=url,
                bypassed_url=f"{base}{path}.json",
                technique=BypassTechnique.PATH_SUFFIX,
                method=method,
                description="Add .json suffix"
            ))
        
        return results

    def bypass_path_prefix(self, url: str, method: str = "GET") -> List[BypassResult]:
        """路径前缀 Bypass"""
        results = []
        parsed = urlparse(url)
        path = parsed.path.lstrip('/')
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        prefixes = ['api/', 'api', 'v1/', 'v2/', 'rest/', 'rest', 'graphql/', 'graphql']
        
        for prefix in prefixes:
            if not path.startswith(prefix):
                new_path = '/' + prefix + path
                bypassed_url = base + new_path
                if parsed.query:
                    bypassed_url += '?' + parsed.query
                
                results.append(BypassResult(
                    original_url=url,
                    bypassed_url=bypassed_url,
                    technique=BypassTechnique.PATH_PREFIX,
                    method=method,
                    description=f"Add prefix: {prefix}"
                ))
        
        return results

    def bypass_http_method(self, url: str, method: str = "GET") -> List[BypassResult]:
        """HTTP 方法 Bypass"""
        results = []
        alternatives = self.METHOD_ALTERNATIVES.get(method.upper(), [])
        
        for alt_method in alternatives:
            results.append(BypassResult(
                original_url=url,
                bypassed_url=url,
                technique=BypassTechnique.HTTP_METHOD,
                method=alt_method,
                description=f"Change method from {method} to {alt_method}"
            ))
        
        return results

    def bypass_version(self, url: str, method: str = "GET") -> List[BypassResult]:
        """版本号 Bypass"""
        results = []
        parsed = urlparse(url)
        path = parsed.path
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        path_without_version = re.sub(r'/v\d+(\.\d+)?', '', path)
        
        for version in self.VERSION_PREFIXES:
            if version not in path:
                new_path = version + path_without_version
                bypassed_url = base + new_path
                if parsed.query:
                    bypassed_url += '?' + parsed.query
                
                results.append(BypassResult(
                    original_url=url,
                    bypassed_url=bypassed_url,
                    technique=BypassTechnique.VERSION,
                    method=method,
                    description=f"Add version prefix: {version}"
                ))
        
        return results

    def bypass_parameters(self, url: str, method: str = "GET") -> List[BypassResult]:
        """参数 Bypass"""
        results = []
        parsed = urlparse(url)
        
        for param in self.COMMON_PARAMS:
            if param not in parsed.query:
                separator = '&' if parsed.query else '?'
                new_query = parsed.query + separator + param if parsed.query else param
                bypassed_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                
                results.append(BypassResult(
                    original_url=url,
                    bypassed_url=bypassed_url,
                    technique=BypassTechnique.PARAMETER,
                    method=method,
                    description=f"Add parameter: {param}"
                ))
        
        return results

    def bypass_path_traversal(self, url: str, method: str = "GET") -> List[BypassResult]:
        """路径遍历 Bypass"""
        results = []
        parsed = urlparse(url)
        path = parsed.path
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        for pattern, replacement in self.PATH_TRAVERSAL_PATTERNS:
            if pattern in path:
                new_path = path.replace(pattern, replacement)
                bypassed_url = base + new_path
                if parsed.query:
                    bypassed_url += '?' + parsed.query
                
                results.append(BypassResult(
                    original_url=url,
                    bypassed_url=bypassed_url,
                    technique=BypassTechnique.PATH_TRAVERSAL,
                    method=method,
                    description=f"Path traversal: {pattern} -> {replacement}"
                ))
        
        return results

    def bypass_content_type(self, url: str, method: str = "GET") -> List[BypassResult]:
        """Content-Type Bypass"""
        results = []
        
        for content_type in self.CONTENT_TYPES:
            results.append(BypassResult(
                original_url=url,
                bypassed_url=url,
                technique=BypassTechnique.CONTENT_TYPE,
                method=method,
                content_type=content_type,
                description=f"Change Content-Type to: {content_type}"
            ))
        
        return results

    def bypass_case_normalization(self, url: str, method: str = "GET") -> List[BypassResult]:
        """大小写规范化 Bypass"""
        results = []
        parsed = urlparse(url)
        path = parsed.path
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        segments = path.split('/')
        for i, segment in enumerate(segments):
            if segment and not segment.startswith('{'):
                for variant_fn in self.CASE_VARIANTS:
                    new_segment = variant_fn(segment)
                    if new_segment != segment:
                        new_segments = segments[:i] + [new_segment] + segments[i+1:]
                        new_path = '/'.join(new_segments)
                        bypassed_url = base + new_path
                        if parsed.query:
                            bypassed_url += '?' + parsed.query
                        
                        results.append(BypassResult(
                            original_url=url,
                            bypassed_url=bypassed_url,
                            technique=BypassTechnique.CASE_NORMALIZATION,
                            method=method,
                            description=f"Case normalization: {segment} -> {new_segment}"
                        ))
                        break
        
        return results

    def bypass_url_encoding(self, url: str, method: str = "GET") -> List[BypassResult]:
        """URL 编码 Bypass"""
        results = []
        parsed = urlparse(url)
        path = parsed.path
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        segments = path.split('/')
        for i, segment in enumerate(segments):
            if segment and not segment.startswith('{') and '%' not in segment:
                encoded = quote(segment)
                if encoded != segment:
                    new_segments = segments[:i] + [encoded] + segments[i+1:]
                    new_path = '/'.join(new_segments)
                    bypassed_url = base + new_path
                    if parsed.query:
                        bypassed_url += '?' + parsed.query
                    
                    results.append(BypassResult(
                        original_url=url,
                        bypassed_url=bypassed_url,
                        technique=BypassTechnique.URL_ENCODING,
                        method=method,
                        description=f"URL encoding: {segment} -> {encoded}"
                    ))
        
        return results

    def bypass_double_slash(self, url: str, method: str = "GET") -> List[BypassResult]:
        """双斜线 Bypass"""
        results = []
        
        if '://' in url and ':///' not in url:
            bypassed_url = url.replace('://', ':///', 1)
            if '///' in bypassed_url:
                results.append(BypassResult(
                    original_url=url,
                    bypassed_url=bypassed_url,
                    technique=BypassTechnique.DOUBLE_SLASH,
                    method=method,
                    description="Add extra slash after protocol"
                ))
        
        return results
    
    def fuzz_parent_child_paths(self, url: str, method: str = "GET") -> List[BypassResult]:
        """
        父子路径 Fuzzing - 发现同级的隐藏端点
        
        Args:
            url: 目标 URL (例如 /api/v1/clean/workOrder/list)
            method: HTTP 方法
            
        Returns:
            Fuzzing 结果列表
        """
        results = []
        parsed = urlparse(url)
        path = parsed.path.rstrip('/')
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        segments = [s for s in path.split('/') if s]
        if len(segments) < 2:
            return results
        
        parent_paths = []
        for i in range(1, len(segments)):
            parent = '/' + '/'.join(segments[:i])
            parent_paths.append(parent)
        
        resource = segments[-1] if segments else ""
        
        for parent in parent_paths:
            for suffix in self.RESTFUL_SUFFIXES[:20]:
                new_path = f"{parent}/{suffix}"
                if new_path != path:
                    bypassed_url = base + new_path
                    results.append(BypassResult(
                        original_url=url,
                        bypassed_url=bypassed_url,
                        technique=BypassTechnique.PATH_PREFIX,
                        method=method,
                        description=f"Parent path fuzzing: {parent} + /{suffix}"
                    ))
        
        if len(segments) >= 2:
            parent_without_last = '/' + '/'.join(segments[:-1])
            for suffix in self.RESTFUL_SUFFIXES[:15]:
                new_path = f"{parent_without_last}/{suffix}"
                if new_path != path:
                    bypassed_url = base + new_path
                    results.append(BypassResult(
                        original_url=url,
                        bypassed_url=bypassed_url,
                        technique=BypassTechnique.PATH_PREFIX,
                        method=method,
                        description=f"Sibling fuzzing: {parent_without_last} + /{suffix}"
                    ))
        
        return results
    
    def fuzz_path_parameters(self, url: str, method: str = "GET") -> List[BypassResult]:
        """
        路径参数 Fuzzing - 将查询参数转为路径参数
        
        Args:
            url: 目标 URL
            method: HTTP 方法
            
        Returns:
            Fuzzing 结果列表
        """
        results = []
        parsed = urlparse(url)
        path = parsed.path.rstrip('/')
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        if not parsed.query:
            return results
        
        params = dict(p.split('=') if '=' in p else (p, '') for p in parsed.query.split('&'))
        
        for param_name, param_value in params.items():
            if param_value:
                path_with_param = f"{path}/{param_value}"
                query_without_param = '&'.join(f"{k}={v}" if v else k for k, v in params.items() if k != param_name)
                bypassed_url = base + path_with_param
                if query_without_param:
                    bypassed_url += '?' + query_without_param
                
                results.append(BypassResult(
                    original_url=url,
                    bypassed_url=bypassed_url,
                    technique=BypassTechnique.PATH_TRAVERSAL,
                    method=method,
                    description=f"Path param fuzzing: {param_name}={param_value} -> /{param_value}"
                ))
        
        return results
    
    def generate_bypass_matrix(self, urls: List[str], methods: Optional[List[str]] = None) -> List[BypassResult]:
        """
        生成 Bypass 矩阵
        
        Args:
            urls: URL 列表
            methods: HTTP 方法列表
            
        Returns:
            所有 Bypass 结果
        """
        if methods is None:
            methods = ['GET']
        
        results = []
        for url in urls:
            for method in methods:
                results.extend(self.bypass_all(url, method))
        
        return results

    def get_bypasses_by_technique(self, technique: BypassTechnique) -> List[BypassResult]:
        """按技术类型获取 Bypass 结果"""
        return [r for r in self.bypass_results if r.technique == technique]

    def get_stats(self) -> Dict[str, int]:
        """获取 Bypass 统计信息"""
        stats = {}
        for technique in BypassTechnique:
            count = len(self.get_bypasses_by_technique(technique))
            if count > 0:
                stats[technique.value] = count
        return stats


class SmartBypasser:
    """
    智能 Bypass 选择器
    
    根据响应状态码智能选择 Bypass 技术:
    - 301/302 (重定向) -> 尝试跟踪重定向或路径变化
    - 401/403 (认证) -> 尝试认证 Bypass
    - 404 (未找到) -> 尝试多种路径 Bypass
    - 405 (方法不允许) -> 尝试 HTTP 方法 Bypass
    - 500 (服务器错误) -> 记录但不继续 Bypass
    """

    STATUS_BYPASS_MAP = {
        301: [BypassTechnique.PATH_SUFFIX, BypassTechnique.PATH_PREFIX, BypassTechnique.PATH_TRAVERSAL],
        302: [BypassTechnique.PATH_SUFFIX, BypassTechnique.PATH_PREFIX],
        401: [BypassTechnique.AUTH_BYPASS, BypassTechnique.PARAMETER],
        403: [BypassTechnique.AUTH_BYPASS, BypassTechnique.PATH_SUFFIX, BypassTechnique.CASE_NORMALIZATION],
        404: [
            BypassTechnique.PATH_SUFFIX, BypassTechnique.PATH_PREFIX, 
            BypassTechnique.VERSION, BypassTechnique.PATH_TRAVERSAL,
            BypassTechnique.URL_ENCODING, BypassTechnique.DOUBLE_SLASH
        ],
        405: [BypassTechnique.HTTP_METHOD, BypassTechnique.CONTENT_TYPE],
    }

    def __init__(self):
        self.bypasser = APIBypasser()
        self.failed_bypasses: Dict[str, List[BypassResult]] = {}

    def select_bypasses(self, url: str, method: str, status_code: int) -> List[BypassResult]:
        """
        根据状态码智能选择 Bypass 技术
        
        Args:
            url: 目标 URL
            method: HTTP 方法
            status_code: 响应状态码
            
        Returns:
            选中的 Bypass 结果
        """
        techniques = self.STATUS_BYPASS_MAP.get(status_code, [])
        
        if not techniques:
            techniques = list(BypassTechnique)
        
        results = []
        for technique in techniques:
            if technique == BypassTechnique.PATH_SUFFIX:
                results.extend(self.bypasser.bypass_path_suffix(url, method))
            elif technique == BypassTechnique.PATH_PREFIX:
                results.extend(self.bypasser.bypass_path_prefix(url, method))
            elif technique == BypassTechnique.HTTP_METHOD:
                results.extend(self.bypasser.bypass_http_method(url, method))
            elif technique == BypassTechnique.VERSION:
                results.extend(self.bypasser.bypass_version(url, method))
            elif technique == BypassTechnique.PARAMETER:
                results.extend(self.bypasser.bypass_parameters(url, method))
            elif technique == BypassTechnique.PATH_TRAVERSAL:
                results.extend(self.bypasser.bypass_path_traversal(url, method))
            elif technique == BypassTechnique.CONTENT_TYPE:
                results.extend(self.bypasser.bypass_content_type(url, method))
            elif technique == BypassTechnique.AUTH_BYPASS:
                results.extend(self._auth_bypass(url, method))
        
        return results

    def _auth_bypass(self, url: str, method: str) -> List[BypassResult]:
        """认证 Bypass"""
        results = []
        
        auth_headers_list = APIBypasser.AUTH_HEADERS
        for headers in auth_headers_list:
            results.append(BypassResult(
                original_url=url,
                bypassed_url=url,
                technique=BypassTechnique.AUTH_BYPASS,
                method=method,
                headers=headers,
                description=f"Auth bypass with headers: {list(headers.keys())}"
            ))
        
        return results

    def record_failure(self, bypass_result: BypassResult, reason: str):
        """记录失败的 Bypass"""
        key = f"{bypass_result.bypassed_url}:{bypass_result.method}"
        if key not in self.failed_bypasses:
            self.failed_bypasses[key] = []
        self.failed_bypasses[key].append(bypass_result)

    def should_skip(self, url: str, method: str) -> bool:
        """判断是否应该跳过某个 URL"""
        key = f"{url}:{method}"
        if key in self.failed_bypasses:
            failures = self.failed_bypasses[key]
            if len(failures) >= 10:
                return True
        return False


def quick_bypass(url: str, http_client=None) -> List[str]:
    """
    便捷函数: 快速生成 Bypass URL
    
    Args:
        url: 目标 URL
        http_client: HTTP 客户端
        
    Returns:
        Bypass URL 列表
    """
    bypasser = APIBypasser()
    results = bypasser.bypass_all(url)
    return [r.bypassed_url for r in results]


if __name__ == "__main__":
    print("API Bypass Library")
    bypasser = APIBypasser()
    test_urls = [
        "http://example.com/api/user",
        "http://example.com/api/v1/order/list",
    ]
    for url in test_urls:
        results = bypasser.bypass_all(url)
        print(f"\n{url}:")
        print(f"  Total bypasses: {len(results)}")
        for technique, count in bypasser.get_stats().items():
            print(f"  {technique}: {count}")
