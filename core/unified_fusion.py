"""
Unified Fusion Engine - 统一融合引擎
真正的混合模式（Ensemble）而非串联回退

混合模式原理：
1. 并行执行多种发现方法（AI语义、知识库匹配、统计推断）
2. 每种方法产生候选端点，带置信度分数
3. 合并所有候选，用加权置信度评分排序
4. 高置信度方法的结果排在前面

置信度权重：
- AI语义分析: 0.9 (最高，但可能误判)
- 知识库匹配: 0.8 (确定性强)
- 运行时确认: 0.7 (已验证)
- 正则匹配: 0.5 (基础方法)
- 统计推断: 0.3 (作为补充)
"""

import re
import logging
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)


class SourceType(Enum):
    """端点来源类型"""
    JS_STRING = "js_string"
    JS_CONCAT = "js_concat"
    JS_AST = "js_ast"
    JS_FUZZ = "js_fuzz"
    WEBPACK = "webpack"
    RENDER_DOM = "render_dom"
    RUNTIME_XHR = "runtime_xhr"
    RUNTIME_FETCH = "runtime_fetch"
    ROUTE_HOOK = "route_hook"
    API_DOC = "api_doc"
    AI_INFERRED = "ai_inferred"
    KNOWLEDGE_BASE = "knowledge_base"
    STATISTICAL = "statistical"
    FINGERPRINT = "fingerprint"
    STATIC = "static"
    REGEX = "regex"
    UNKNOWN = "unknown"


class EndpointType(Enum):
    """端点类型分类"""
    API_ENDPOINT = "api_endpoint"
    PAGE_ROUTE = "page_route"
    STATIC_RESOURCE = "static_resource"
    ADMIN_PANEL = "admin_panel"
    AI_INTERFACE = "ai_interface"
    DOC_PAGE = "doc_page"
    UNKNOWN = "unknown"


class ConfidenceLevel(Enum):
    """置信度等级"""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class EndpointEvidence:
    """端点证据"""
    source_type: SourceType
    source_url: str = ""
    discovery_method: str = ""
    confidence: float = 0.0
    raw_evidence: str = ""
    context: Dict = field(default_factory=dict)


@dataclass
class FusedEndpoint:
    """融合端点"""
    url: str
    method: str = "GET"
    endpoint_type: EndpointType = EndpointType.UNKNOWN
    evidence_chain: List[EndpointEvidence] = field(default_factory=list)
    primary_source: Optional[SourceType] = None
    confidence_score: float = 0.0
    runtime_observed: bool = False
    runtime_status: int = 0
    runtime_content_type: str = ""
    description: str = ""
    params: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    sources: Set[SourceType] = field(default_factory=set)
    
    @property
    def fusion_key(self) -> str:
        return f"{self.method}:{self.url}".lower()
    
    def add_evidence(self, evidence: EndpointEvidence):
        self.evidence_chain.append(evidence)
        self.sources.add(evidence.source_type)
        self._recalculate_confidence()
    
    def _recalculate_confidence(self):
        if not self.evidence_chain:
            return
        
        total_score = 0.0
        weights = 0.0
        
        for evidence in self.evidence_chain:
            weight = self._get_source_weight(evidence.source_type)
            total_score += evidence.confidence * weight
            weights += weight
        
        if weights > 0:
            self.confidence_score = total_score / weights
        
        if self.confidence_score >= 0.7:
            self.confidence_level = ConfidenceLevel.HIGH
        elif self.confidence_score >= 0.4:
            self.confidence_level = ConfidenceLevel.MEDIUM
        else:
            self.confidence_level = ConfidenceLevel.LOW
        
        if len(self.sources) > 1:
            self.confidence_score *= 1.1
            self.confidence_score = min(1.0, self.confidence_score)
    
    def _get_source_weight(self, source: SourceType) -> float:
        weights = {
            SourceType.AI_INFERRED: 0.9,
            SourceType.KNOWLEDGE_BASE: 0.8,
            SourceType.RUNTIME_FETCH: 0.75,
            SourceType.RUNTIME_XHR: 0.75,
            SourceType.API_DOC: 0.7,
            SourceType.JS_AST: 0.6,
            SourceType.JS_FUZZ: 0.5,
            SourceType.WEBPACK: 0.5,
            SourceType.ROUTE_HOOK: 0.5,
            SourceType.STATISTICAL: 0.3,
            SourceType.REGEX: 0.3,
            SourceType.STATIC: 0.1,
            SourceType.UNKNOWN: 0.1,
        }
        return weights.get(source, 0.1)


class UnifiedFusionEngine:
    """
    统一融合引擎 - 真正的混合模式
    
    同时运行多种发现方法，结果合并后统一评分排序
    """

    API_PATTERNS = [
        r'/api/', r'/v\d+/', r'/graphql', r'/rest/',
        r'/swagger', r'/openapi', r'/rpc/',
    ]

    ADMIN_PATTERNS = [
        r'/admin', r'/manage', r'/dashboard', r'/console',
        r'/backend', r'/system',
    ]

    AI_PATTERNS = [
        r'/ai/', r'/llm/', r'/chat/', r'/embed',
        r'/vector', r'/model', r'/predict', r'/inference',
    ]

    STATIC_PATTERNS = [
        r'\.(js|css|png|jpg|jpeg|gif|svg|woff|woff2|ttf|eot|ico|map)$',
        r'/static/', r'/assets/', r'/images/', r'/fonts/',
    ]

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
        self.endpoints: Dict[str, FusedEndpoint] = {}
        self._ai_results: Dict[str, List[str]] = {}
        self._kb_results: Dict[str, List[str]] = {}
        self._stat_results: Dict[str, List[str]] = {}
        self.fusion_stats = {
            'total_discovered': 0,
            'after_fusion': 0,
            'ai_contributed': 0,
            'kb_contributed': 0,
            'stat_contributed': 0,
        }

    @staticmethod
    def generate_parent_paths(path: str, max_depth: int = 3) -> List[str]:
        """
        从完整路径生成可能的父路径前缀（直接复用 js_collector 的逻辑）

        例如: /inspect/login/checkCode/getCheckCode
        返回: ['/inspect/login/checkCode', '/inspect/login', '/inspect']
        """
        if not path or not isinstance(path, str):
            return []

        if path.startswith('http://') or path.startswith('https://'):
            from urllib.parse import urlparse
            parsed = urlparse(path)
            path = parsed.path

        path = path.strip('/')
        if not path:
            return []

        parts = path.split('/')

        if len(parts) <= 2:
            return []

        def is_likely_id(s: str) -> bool:
            return (
                s.isdigit() or
                bool(re.match(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', s, re.IGNORECASE)) or
                (len(s) > 3 and s[:2].isalpha() and s[2:].isdigit()) or
                (len(s) > 8 and bool(re.match(r'^[a-zA-Z0-9_-]+$', s)) and ('-' in s or '_' in s))
            )

        valid_parts_count = len(parts)
        for i, part in enumerate(parts):
            if is_likely_id(part) and i > 0:
                valid_parts_count = i
                break

        if valid_parts_count < 2:
            return []

        parent_paths = []
        for i in range(1, min(valid_parts_count, max_depth + 1)):
            parent_path = '/' + '/'.join(parts[:-i])
            if parent_path and len(parent_path) > 1:
                parent_paths.append(parent_path)

        return parent_paths

    @staticmethod
    def _is_common_suffix(s: str) -> bool:
        """判断是否为常见后缀"""
        return s.lower() in UnifiedFusionEngine._COMMON_SUFFIXES_SET

    @staticmethod
    def _is_common_resource(s: str) -> bool:
        """判断是否为常见资源"""
        return s.lower() in UnifiedFusionEngine._COMMON_RESOURCES_SET

    @staticmethod
    def _is_likely_id(s: str) -> bool:
        """判断是否为ID"""
        return (
            s.isdigit() or
            bool(UnifiedFusionEngine._UUID_PATTERN.match(s)) or
            (len(s) > 3 and s[:2].isalpha() and s[2:].isdigit()) or
            (len(s) > 8 and bool(UnifiedFusionEngine._ALPHANUM_DASH_UNDERSCORE_PATTERN.match(s)) and ('-' in s or '_' in s))
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

        if s_lower in UnifiedFusionEngine.NON_RESOURCE_SEGMENTS:
            return False

        if UnifiedFusionEngine._is_common_suffix(s_lower):
            return True

        if UnifiedFusionEngine._is_common_resource(s_lower):
            return True

        if UnifiedFusionEngine._is_likely_id(s):
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
            if part.lower() in UnifiedFusionEngine.NON_RESOURCE_SEGMENTS:
                if i == 0:
                    return None
                return '/' + '/'.join(parts[:i])

        first_meaningful_idx = 0
        for i in range(len(parts) - 1, -1, -1):
            if UnifiedFusionEngine._is_meaningful_segment(parts[i]):
                first_meaningful_idx = i
                break

        if first_meaningful_idx > 0:
            return '/' + '/'.join(parts[:first_meaningful_idx])

        return None

    @staticmethod
    def extract_resource_path(api_path: str) -> Optional[str]:
        """
        提取资源路径（去掉前两段后的路径）

        例如: /inspect/login/checkCode/getCheckCode
        返回: /checkCode/getCheckCode
        """
        if not api_path:
            return None

        path = api_path.strip('/')
        parts = path.split('/')

        if len(parts) >= 3:
            return '/' + '/'.join(parts[2:])

        return api_path

    API_PREFIXES = [
        'api', 'prod-api', 'test-api', 'dev-api',
        'v1', 'v2', 'v3', 'v4', 'v5',
        'rest', 'graphql', 'rpc', 'soap', 'grpc',
        'gateway', 'proxy', 'service',
        'admin', 'manage', 'system',
    ]

    @staticmethod
    def find_api_prefix_index(path: str) -> Optional[int]:
        """
        查找路径中 API 前缀的位置

        例如: /inspect/prod-api/checkCode/getCheckCode
        返回: 1 (prod-api 在 parts[1])
        """
        if not path:
            return None

        parts = path.strip('/').split('/')

        for i, part in enumerate(parts):
            if part.lower() in UnifiedFusionEngine.API_PREFIXES:
                return i

        return None

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
        'checkCode', 'captcha', 'captchas',
    ]

    COMMON_METHODS = [
        'list', 'add', 'create', 'delete', 'remove', 'detail', 'info', 'update', 'edit',
        'get', 'set', 'save', 'query', 'search', 'filter', 'export', 'import',
        'login', 'logout', 'register', 'reset', 'verify', 'refresh',
        'enable', 'disable', 'status', 'config', 'upload', 'download',
        'getCheckCode', 'getCheckcode', 'check', 'validate',
    ]

    PREFIX_PATTERNS = [
        r'/([a-zA-Z][a-zA-Z0-9_-]+)/',
        r'/([a-zA-Z]+_[a-zA-Z0-9_]+)/',
        r'["\']/([a-zA-Z][a-zA-Z0-9_-]+)/',
        r'baseUrl\s*[=:+]\s*["\']/([^"\']+)',
        r'API_PREFIX\s*[=:+]\s*["\']/([^"\']+)',
        r'BASE_URL\s*[=:+]\s*["\']/([^"\']+)',
        r'prefix\s*[=:+]\s*["\']/([^"\']+)',
        r'"([a-zA-Z]+-[a-zA-Z]+)"\s*:\s*["\']/([^"\']+)',
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
            r'/([a-zA-Z][a-zA-Z0-9_-]+)/',
            r'/([a-zA-Z]+_[a-zA-Z0-9_]+)/',
            r'baseUrl\s*[=:+]\s*["\']/([^"\']+)',
            r'API_PREFIX\s*[=:+]\s*["\']/([^"\']+)',
            r'BASE_URL\s*[=:+]\s*["\']/([^"\']+)',
            r'prefix\s*[=:+]\s*["\']/([^"\']+)',
            r'"([a-zA-Z]+-[a-zA-Z]+)"\s*:\s*["\']/([^"\']+)',
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
            r'\+\s*["\']/([a-zA-Z][a-zA-Z0-9_-]+)["\']',
            r'["\']/([a-zA-Z][a-zA-Z0-9_-]+)["\']\s*\+',
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

        if prefix_clean in [p.lower() for p in UnifiedFusionEngine.VERSION_PREFIXES]:
            return False

        if prefix_clean in [p.lower() for p in UnifiedFusionEngine.API_PREFIXES]:
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
        return prefix.strip('/').lower() in [p.lower() for p in UnifiedFusionEngine.VERSION_PREFIXES]

    @staticmethod
    def generate_path_variants(api_path: str, base_url_path: str = "") -> Dict[str, Any]:
        """
        生成路径变体 - 基于正确的语义组合

        对于 /inspect/prod-api/checkCode/getCheckCode，base_url_path = /inspect/：
        - base_url 路径 = /inspect/
        - 相对路径 = /prod-api/checkCode/getCheckCode
        - 微服务前缀 (api_prefix) = prod-api
        - 资源路径 = /checkCode/getCheckCode

        生成 fuzzing 变体:
        1. 原始相对路径: /prod-api/checkCode/getCheckCode
        2. 微服务前缀 + 常见资源 + 常见方法: /prod-api/user/add, /prod-api/order/list
        3. 尝试 /api 前缀: /api/checkCode/getCheckCode
        4. 去掉微服务前缀: /checkCode/getCheckCode
        """
        if not api_path:
            return {}

        path = api_path.strip('/')
        parts = path.split('/')

        api_prefix_index = UnifiedFusionEngine.find_api_prefix_index(api_path)

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

        api_prefixes = UnifiedFusionEngine.API_PREFIXES
        common_resources = UnifiedFusionEngine.COMMON_RESOURCES
        common_methods = UnifiedFusionEngine.COMMON_METHODS

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

    def _normalize_and_fuse_url(self, raw_path: str, base_url: str = "") -> List[str]:
        """
        规范化并融合 URL - 生成多版本完整 URL

        使用新的变体语义，支持版本号前缀结合
        """
        full_urls = []
        variants = self.generate_path_variants(raw_path)

        v1 = variants.get('v1', '')
        v2 = variants.get('v2', '')
        first_parent = variants.get('first_parent', '')
        parents = variants.get('parents', {})

        if v1:
            full_urls.append(v1)
        if v2:
            full_urls.append(v2)
        full_urls.append(raw_path)

        if first_parent and base_url:
            parsed = urlparse(base_url)
            base_path = parsed.path

            version_prefixes = ['/v1', '/v2', '/v3', '/v4', '/v5']
            api_prefixes = ['/api', '/rest', '/graphql', '/rpc']

            for parent, resource in parents.items():
                for version in version_prefixes:
                    for api_prefix in api_prefixes:
                        full_url = f"{parsed.scheme}://{parsed.netloc}{parent}{base_path}{api_prefix}{version}{resource}"
                        full_urls.append(full_url)

                full_url = f"{parsed.scheme}://{parsed.netloc}{parent}{base_path}{resource}"
                full_urls.append(full_url)

            for api_prefix in api_prefixes:
                for version in version_prefixes:
                    full_url = f"{parsed.scheme}://{parsed.netloc}{first_parent}{api_prefix}{version}{v2 if v2 else '/user/list'}"
                    full_urls.append(full_url)

        return list(set(full_urls))

    def add_endpoint_with_variants(self, url: str, method: str = "GET",
                                    source_type: SourceType = SourceType.UNKNOWN,
                                    base_url: str = "",
                                    source_url: str = "",
                                    confidence: float = 0.5,
                                    runtime_observed: bool = False,
                                    **kwargs) -> Optional[FusedEndpoint]:
        """
        带变体生成的端点添加方法

        自动生成路径变体并融合，解决 /inspect/login 前缀问题
        """
        from urllib.parse import urlparse

        parsed = urlparse(url)
        path = parsed.path if parsed.path else kwargs.get('path', '/')

        url_variants = self._normalize_and_fuse_url(path, base_url)

        primary_endpoint = None
        for variant_url in url_variants:
            endpoint = self.add_endpoint(
                url=variant_url,
                method=method,
                source_type=source_type,
                source_url=source_url,
                confidence=confidence,
                runtime_observed=runtime_observed,
                **kwargs
            )
            if primary_endpoint is None:
                primary_endpoint = endpoint

        return primary_endpoint
    
    def add_ai_result(self, url: str, method: str = "GET", evidence: str = ""):
        """
        添加AI分析结果
        
        AI分析置信度: 0.8-0.95
        """
        key = f"{method}:{url}".lower()
        
        if key not in self.endpoints:
            self.endpoints[key] = FusedEndpoint(
                url=url,
                method=method,
                endpoint_type=self._classify_endpoint(url),
            )
        
        self.endpoints[key].add_evidence(EndpointEvidence(
            source_type=SourceType.AI_INFERRED,
            confidence=0.85,
            raw_evidence=evidence,
            discovery_method="ai_semantic_analysis",
        ))
        
        self._ai_results[key] = [url]
        self.fusion_stats['ai_contributed'] += 1
    
    def add_kb_result(self, url: str, method: str = "GET", evidence: str = ""):
        """
        添加知识库匹配结果
        
        知识库匹配置信度: 0.7-0.9
        """
        key = f"{method}:{url}".lower()
        
        if key not in self.endpoints:
            self.endpoints[key] = FusedEndpoint(
                url=url,
                method=method,
                endpoint_type=self._classify_endpoint(url),
            )
        
        self.endpoints[key].add_evidence(EndpointEvidence(
            source_type=SourceType.KNOWLEDGE_BASE,
            confidence=0.8,
            raw_evidence=evidence,
            discovery_method="knowledge_base_match"
        ))
        
        self._kb_results[key] = [url]
        self.fusion_stats['kb_contributed'] += 1
    
    def add_stat_result(self, url: str, method: str = "GET", evidence: str = ""):
        """
        添加统计推断结果
        
        统计推断置信度: 0.3-0.6
        """
        key = f"{method}:{url}".lower()
        
        if key not in self.endpoints:
            self.endpoints[key] = FusedEndpoint(
                url=url,
                method=method,
                endpoint_type=self._classify_endpoint(url),
            )
        
        self.endpoints[key].add_evidence(EndpointEvidence(
            source_type=SourceType.STATISTICAL,
            confidence=0.4,
            raw_evidence=evidence,
            discovery_method="statistical_inference"
        ))
        
        self._stat_results[key] = [url]
        self.fusion_stats['stat_contributed'] += 1
    
    def add_runtime_result(self, url: str, method: str = "GET", 
                           status_code: int = 200, content_type: str = ""):
        """添加运行时确认结果（最高置信度）"""
        key = f"{method}:{url}".lower()
        
        if key not in self.endpoints:
            self.endpoints[key] = FusedEndpoint(
                url=url,
                method=method,
                endpoint_type=self._classify_endpoint(url),
                runtime_observed=True,
                runtime_status=status_code,
                runtime_content_type=content_type,
            )
        
        self.endpoints[key].runtime_observed = True
        self.endpoints[key].runtime_status = status_code
        self.endpoints[key].runtime_content_type = content_type
        self.endpoints[key].add_evidence(EndpointEvidence(
            source_type=SourceType.RUNTIME_FETCH,
            confidence=0.95,
            raw_evidence=f"status={status_code}",
            discovery_method="runtime_verification"
        ))
    
    def add_endpoint(self, url: str, method: str = "GET",
                     source_type: SourceType = SourceType.UNKNOWN,
                     source_url: str = "",
                     confidence: float = 0.5,
                     runtime_observed: bool = False,
                     **kwargs) -> Optional[FusedEndpoint]:
        """通用端点添加方法"""
        key = f"{method}:{url}".lower()
        
        if key not in self.endpoints:
            self.endpoints[key] = FusedEndpoint(
                url=url,
                method=method,
                endpoint_type=self._classify_endpoint(url),
                runtime_observed=runtime_observed,
                runtime_status=kwargs.get('status_code', 0),
                runtime_content_type=kwargs.get('content_type', ''),
            )
        
        self.endpoints[key].add_evidence(EndpointEvidence(
            source_type=source_type,
            source_url=source_url,
            confidence=confidence,
            raw_evidence=kwargs.get('raw_evidence', ''),
            discovery_method=kwargs.get('discovery_method', 'unknown'),
        ))
        
        self.fusion_stats['total_discovered'] += 1
        return self.endpoints[key]
    
    def get_all_endpoints(self, min_confidence: str = "low") -> List[FusedEndpoint]:
        """获取所有融合后的端点，按置信度排序"""
        confidence_order = {"high": 3, "medium": 2, "low": 1}
        min_level = confidence_order.get(min_confidence, 0)
        
        filtered = [
            ep for ep in self.endpoints.values()
            if confidence_order.get(ep.confidence_level.value, 0) >= min_level
        ]
        
        return sorted(filtered, key=lambda x: (
            x.runtime_observed,
            -x.confidence_score,
            x.url
        ), reverse=True)
    
    def get_api_endpoints(self) -> List[FusedEndpoint]:
        return [ep for ep in self.endpoints.values() 
                if ep.endpoint_type == EndpointType.API_ENDPOINT]
    
    def get_high_confidence_endpoints(self) -> List[FusedEndpoint]:
        return [ep for ep in self.endpoints.values()
                if ep.confidence_level == ConfidenceLevel.HIGH]
    
    def get_fusion_report(self) -> Dict:
        """生成融合报告"""
        self.fusion_stats['after_fusion'] = len(self.endpoints)
        
        type_dist = defaultdict(int)
        for ep in self.endpoints.values():
            type_dist[ep.endpoint_type.value] += 1
        
        source_dist = defaultdict(int)
        for ep in self.endpoints.values():
            for src in ep.sources:
                source_dist[src.value] += 1
        
        return {
            'stats': dict(self.fusion_stats),
            'type_distribution': dict(type_dist),
            'source_distribution': dict(source_dist),
            'confidence_distribution': {
                'high': len([e for e in self.endpoints.values() if e.confidence_level == ConfidenceLevel.HIGH]),
                'medium': len([e for e in self.endpoints.values() if e.confidence_level == ConfidenceLevel.MEDIUM]),
                'low': len([e for e in self.endpoints.values() if e.confidence_level == ConfidenceLevel.LOW]),
            },
            'total_endpoints': len(self.endpoints),
            'ai_only': len([e for e in self.endpoints.values() if e.sources == {SourceType.AI_INFERRED}]),
            'kb_only': len([e for e in self.endpoints.values() if e.sources == {SourceType.KNOWLEDGE_BASE}]),
            'hybrid': len([e for e in self.endpoints.values() if len(e.sources) > 1]),
        }
    
    def _classify_endpoint(self, url: str) -> EndpointType:
        url_lower = url.lower()
        
        for pattern in self.STATIC_PATTERNS:
            if re.search(pattern, url_lower):
                return EndpointType.STATIC_RESOURCE
        
        for pattern in self.ADMIN_PATTERNS:
            if re.search(pattern, url_lower):
                return EndpointType.ADMIN_PANEL
        
        for pattern in self.AI_PATTERNS:
            if re.search(pattern, url_lower):
                return EndpointType.AI_INTERFACE
        
        for pattern in self.API_PATTERNS:
            if re.search(pattern, url_lower):
                return EndpointType.API_ENDPOINT
        
        return EndpointType.UNKNOWN


def ensemble_fuse_endpoints(
    ai_results: List[Dict] = None,
    kb_results: List[Dict] = None,
    stat_results: List[Dict] = None,
    runtime_results: List[Dict] = None
) -> Tuple[List[FusedEndpoint], Dict]:
    """
    集成融合函数 - 混合多种方法的结果
    
    所有方法的结果同时融合，不是串联回退
    
    Args:
        ai_results: AI分析结果列表 [{url, method, evidence}, ...]
        kb_results: 知识库匹配结果列表
        stat_results: 统计推断结果列表
        runtime_results: 运行时确认结果列表
        
    Returns:
        (融合后的端点列表, 融合报告)
    """
    engine = UnifiedFusionEngine()
    
    if ai_results:
        for ep in ai_results:
            engine.add_ai_result(
                url=ep.get('url', ''),
                method=ep.get('method', 'GET'),
                evidence=ep.get('evidence', '')
            )
    
    if kb_results:
        for ep in kb_results:
            engine.add_kb_result(
                url=ep.get('url', ''),
                method=ep.get('method', 'GET'),
                evidence=ep.get('evidence', '')
            )
    
    if stat_results:
        for ep in stat_results:
            engine.add_stat_result(
                url=ep.get('url', ''),
                method=ep.get('method', 'GET'),
                evidence=ep.get('evidence', '')
            )
    
    if runtime_results:
        for ep in runtime_results:
            engine.add_runtime_result(
                url=ep.get('url', ''),
                method=ep.get('method', 'GET'),
                status_code=ep.get('status_code', 200),
                content_type=ep.get('content_type', '')
            )
    
    return engine.get_all_endpoints(), engine.get_fusion_report()


class HybridClassification:
    """
    混合分类 - 真正的并行多方法融合
    
    同时并行调用AI、知识库、统计三种方法：
    - 任一方法成功即产出结果
    - 多个方法都识别到了 → 高置信度
    - 只有AI识别到了 → 考虑AI幻觉降权
    - 只有知识库识别到了 → 标准置信度
    - 只有统计识别到了 → 较低置信度
    """
    
    def __init__(
        self,
        llm_client=None,
        knowledge_base: Optional[Dict[str, Any]] = None,
        statistical_weights: Optional[Dict[str, float]] = None
    ):
        self.llm_client = llm_client
        self.knowledge_base = knowledge_base or {}
        self.statistical_weights = statistical_weights or {}
        self._cache: Dict[str, Any] = {}
    
    async def classify(self, urls: List[str]) -> Dict[str, Any]:
        """
        并行执行三种分类方法并融合结果
        
        Args:
            urls: URL列表
            
        Returns:
            融合后的分类结果
        """
        import asyncio
        
        ai_task = asyncio.create_task(self._ai_classify(urls))
        kb_task = asyncio.create_task(self._kb_classify(urls))
        stat_task = asyncio.create_task(self._stat_classify(urls))
        
        results = await asyncio.gather(
            ai_task,
            kb_task,
            stat_task,
            return_exceptions=True
        )
        
        ai_result, kb_result, stat_result = results
        
        if isinstance(ai_result, Exception):
            ai_result = {}
        if isinstance(kb_result, Exception):
            kb_result = {}
        if isinstance(stat_result, Exception):
            stat_result = {}
        
        return self._ensemble_fuse(ai_result, kb_result, stat_result, urls)
    
    async def _ai_classify(self, urls: List[str]) -> Dict[str, Any]:
        """AI语义分类"""
        if not self.llm_client:
            return {}
        
        try:
            from ..collectors.api_collector import LLMUrlClassifier
            classifier = LLMUrlClassifier.get_instance("hybrid")
            classifier.llm_client = self.llm_client
            
            api_prefixes, _, method = await classifier.classify(urls)
            
            if method == 'failed':
                return {}
            
            return {'api_prefixes': api_prefixes, 'method': method}
        except Exception as e:
            logger.debug(f"AI classification failed: {e}")
            return {}
    
    async def _kb_classify(self, urls: List[str]) -> Dict[str, Any]:
        """知识库分类"""
        return self._kb_classify_sync(urls)
    
    def _kb_classify_sync(self, urls: List[str]) -> Dict[str, Any]:
        """知识库分类（同步版本）"""
        api_prefixes = set()
        
        for url in urls:
            segments = url.split('/')
            for seg in segments:
                if seg.lower() in self.knowledge_base:
                    api_prefixes.add(seg)
        
        return {'api_prefixes': api_prefixes} if api_prefixes else {}
    
    async def _stat_classify(self, urls: List[str]) -> Dict[str, Any]:
        """统计分类 - 频率分析"""
        return self._stat_classify_sync(urls)
    
    def _stat_classify_sync(self, urls: List[str]) -> Dict[str, Any]:
        """统计分类（同步版本）"""
        from collections import Counter
        
        segment_freq = Counter()
        segment_positions = defaultdict(set)
        
        for url in urls:
            segments = url.split('/')
            for i, seg in enumerate(segments):
                if seg:
                    segment_freq[seg] += 1
                    segment_positions[seg].add(i)
        
        api_prefixes = set()
        threshold = max(2, len(urls) * 0.1)
        
        for seg, freq in segment_freq.items():
            if freq >= threshold:
                positions = segment_positions[seg]
                avg_pos = sum(positions) / len(positions)
                if avg_pos <= 2:
                    api_prefixes.add(seg)
        
        return {'api_prefixes': api_prefixes} if api_prefixes else {}
    
    def _ensemble_fuse(
        self,
        ai_result: Dict[str, Any],
        kb_result: Dict[str, Any],
        stat_result: Dict[str, Any],
        urls: List[str]
    ) -> Dict[str, Any]:
        """融合三种方法的结果"""
        ai_prefixes = ai_result.get('api_prefixes', set()) if isinstance(ai_result, dict) else set()
        kb_prefixes = kb_result.get('api_prefixes', set()) if isinstance(kb_result, dict) else set()
        stat_prefixes = stat_result.get('api_prefixes', set()) if isinstance(stat_result, dict) else set()
        
        all_prefixes = ai_prefixes | kb_prefixes | stat_prefixes
        
        prefix_confidence = {}
        
        for prefix in all_prefixes:
            sources = 0
            confidence = 0.0
            
            if prefix in ai_prefixes:
                sources += 1
                confidence += 0.9
            
            if prefix in kb_prefixes:
                sources += 1
                confidence += 0.8
            
            if prefix in stat_prefixes:
                sources += 1
                confidence += 0.3
            
            if sources >= 2:
                confidence *= 1.2
            elif sources == 1 and prefix in ai_prefixes:
                confidence *= 0.8
            
            prefix_confidence[prefix] = min(1.0, confidence)
        
        identified_api_keywords = {
            prefix for prefix, conf in prefix_confidence.items()
            if conf >= 0.5
        }
        
        method = 'hybrid'
        if ai_prefixes and not kb_prefixes and not stat_prefixes:
            method = 'ai_only'
        elif kb_prefixes and not ai_prefixes and not stat_prefixes:
            method = 'kb_only'
        elif stat_prefixes and not ai_prefixes and not kb_prefixes:
            method = 'stat_only'
        elif not ai_prefixes and not kb_prefixes and not stat_prefixes:
            method = 'none'
        
        return {
            'api_prefixes': identified_api_keywords,
            'prefix_confidence': prefix_confidence,
            'method': method,
            'sources': {
                'ai': len(ai_prefixes),
                'kb': len(kb_prefixes),
                'stat': len(stat_prefixes),
            }
        }


__all__ = [
    'UnifiedFusionEngine',
    'FusedEndpoint',
    'EndpointEvidence',
    'SourceType',
    'EndpointType',
    'ConfidenceLevel',
    'ensemble_fuse_endpoints',
    'HybridClassification',
]
