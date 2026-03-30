"""
智能过滤与优先级排序模块

核心功能:
1. 端点优先级计算
2. 智能过滤 - 减少冗余测试
3. 差异化 Fuzzing 策略
4. 响应聚类去重

提升 Fuzzing ROI 的关键模块
"""

import hashlib
import re
import logging
from typing import Dict, List, Set, Optional, Any, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, Counter
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class EndpointValue(Enum):
    """端点价值等级"""
    CRITICAL = "critical"    # admin, console, config
    HIGH = "high"          # user, order, auth, login
    MEDIUM = "medium"       # common resources
    LOW = "low"             # static resources
    SKIP = "skip"          # 明显无效的路径


@dataclass
class ScoredEndpoint:
    """带分数的端点"""
    url: str
    method: str
    path: str
    confidence: float
    value_level: EndpointValue
    priority_score: float
    source: str
    is_static: bool = False
    has_params: bool = False
    content_hash: str = ""


class SmartFilter:
    """
    智能过滤器
    
    核心原理：根据置信度和价值智能排序，减少无效测试
    """

    HIGH_VALUE_KEYWORDS = {
        'critical': [
            'admin', 'console', 'dashboard', 'config', 'setting',
            'management', 'monitor', 'actuator', 'jolokia',
            'management', 'admin', 'cgi-bin', 'remote',
        ],
        'high': [
            'user', 'users', 'account', 'auth', 'login', 'logout',
            'order', 'orders', 'payment', 'transaction', 'invoice',
            'api', 'token', 'oauth', 'sso', 'cas', 'saml',
            'role', 'permission', 'access', 'privilege',
            'customer', 'client', 'member', 'profile',
        ],
        'medium': [
            'list', 'detail', 'info', 'query', 'search', 'filter',
            'product', 'goods', 'item', 'category', 'catalog',
            'article', 'news', 'content', 'post', 'comment',
            'file', 'document', 'upload', 'download',
            'resource', 'service', 'data', 'record',
        ],
    }

    STATIC_EXTENSIONS = {
        '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg',
        '.ico', '.woff', '.woff2', '.ttf', '.eot', '.map',
        '.html', '.htm', '.xml', '.json', '.txt', '.md',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.zip', '.tar',
    }

    BLACKLIST_PATTERNS = [
        r'^/$', r'^/[^/]*$', r'^/[a-z]$', r'^/[A-Z]$',
        r'\.color$', r'\.style$', r'\.background$',
        r'chrome-extension', r'webpack://', r'Mozilla/',
    ]

    def __init__(self, max_endpoints: int = 1000):
        self._max_endpoints = max_endpoints
        self._url_cache: Dict[str, str] = {}
        self._hash_seen: Set[str] = set()
        self._stats = {
            'total_input': 0,
            'total_output': 0,
            'filtered_static': 0,
            'filtered_blacklist': 0,
            'filtered_duplicate': 0,
        }

    def score_endpoints(
        self,
        endpoints: List[Dict[str, Any]],
        source_weights: Optional[Dict[str, float]] = None
    ) -> List[ScoredEndpoint]:
        """
        对端点列表进行评分和排序
        
        Args:
            endpoints: 端点列表 [{url, method, confidence, source, ...}]
            source_weights: 来源权重
            
        Returns:
            排序后的 ScoredEndpoint 列表
        """
        if source_weights is None:
            source_weights = {
                'js_parse': 0.8,
                'api_doc': 0.9,
                'wayback': 0.6,
                'runtime': 0.95,
                'fuzz': 0.3,
                'ai': 0.7,
                'default': 0.5,
            }

        scored = []
        for ep in endpoints:
            url = ep.get('url', ep.get('path', ''))
            if not url:
                continue

            method = ep.get('method', 'GET').upper()
            confidence = ep.get('confidence', 0.5)
            source = ep.get('source', 'default')

            value_level = self._classify_value(url)
            is_static = self._is_static_path(url)

            if is_static:
                value_score = 0.1
            elif value_level == EndpointValue.CRITICAL:
                value_score = 1.0
            elif value_level == EndpointValue.HIGH:
                value_score = 0.8
            elif value_level == EndpointValue.MEDIUM:
                value_score = 0.5
            else:
                value_score = 0.3

            source_weight = source_weights.get(source, source_weights['default'])
            priority_score = confidence * source_weight * value_score

            scored.append(ScoredEndpoint(
                url=url,
                method=method,
                path=url,
                confidence=confidence,
                value_level=value_level,
                priority_score=priority_score,
                source=source,
                is_static=is_static,
                has_params='?' in url or '{' in url,
            ))

        scored.sort(key=lambda x: (
            x.value_level.value,
            -x.priority_score,
            not x.has_params,
        ), reverse=True)

        self._stats['total_input'] = len(endpoints)
        self._stats['total_output'] = len(scored)

        return scored

    def smart_filter(
        self,
        endpoints: List[ScoredEndpoint],
        strategy: str = "balanced"
    ) -> List[ScoredEndpoint]:
        """
        智能过滤 - 差异化策略
        
        Args:
            endpoints: 已评分的端点
            strategy: 过滤策略
                - "aggressive": 激进过滤，保留最少
                - "balanced": 平衡策略
                - "conservative": 保守策略，保留较多
        
        Returns:
            过滤后的端点
        """
        if strategy == "aggressive":
            max_keep = self._max_endpoints // 4
        elif strategy == "conservative":
            max_keep = self._max_endpoints
        else:
            max_keep = self._max_endpoints // 2

        filtered = []
        seen_paths = set()
        seen_hashes = set()

        for ep in endpoints:
            if len(filtered) >= max_keep:
                break

            if self._is_blacklisted(ep.url):
                self._stats['filtered_blacklist'] += 1
                continue

            path_hash = self._compute_path_similarity(ep.url)
            if path_hash in seen_hashes:
                self._stats['filtered_duplicate'] += 1
                continue

            if ep.is_static:
                self._stats['filtered_static'] += 1
                if strategy != "conservative":
                    continue

            filtered.append(ep)
            seen_paths.add(ep.url)
            seen_hashes.add(path_hash)

        return filtered

    def _classify_value(self, url: str) -> EndpointValue:
        """分类端点价值"""
        url_lower = url.lower()
        parsed = urlparse(url)
        path = parsed.path.lower()

        for keyword in self.HIGH_VALUE_KEYWORDS['critical']:
            if keyword in path:
                return EndpointValue.CRITICAL

        for keyword in self.HIGH_VALUE_KEYWORDS['high']:
            if keyword in path:
                return EndpointValue.HIGH

        for keyword in self.HIGH_VALUE_KEYWORDS['medium']:
            if keyword in path:
                return EndpointValue.MEDIUM

        return EndpointValue.LOW

    def _is_static_path(self, url: str) -> bool:
        """判断是否为静态资源路径"""
        parsed = urlparse(url)
        path_lower = parsed.path.lower()

        if any(path_lower.endswith(ext) for ext in self.STATIC_EXTENSIONS):
            return True

        if any(path_lower.startswith(prefix) for prefix in ['/static/', '/assets/', '/images/', '/css/', '/js/']):
            return True

        return False

    def _is_blacklisted(self, url: str) -> bool:
        """判断是否在黑名单"""
        url_lower = url.lower()
        for pattern in self.BLACKLIST_PATTERNS:
            if re.match(pattern, url_lower):
                return True
        return False

    def _compute_path_similarity(self, url: str) -> str:
        """计算路径相似度哈希"""
        parsed = urlparse(url)
        path = parsed.path.lower()

        parts = path.strip('/').split('/')
        normalized_parts = []
        for part in parts:
            if part.isdigit():
                normalized_parts.append('{id}')
            elif re.match(r'^[a-f0-9-]{36}$', part):
                normalized_parts.append('{uuid}')
            elif re.match(r'^[a-f0-9]{8,}$', part):
                normalized_parts.append('{hash}')
            else:
                normalized_parts.append(part)

        normalized_path = '/'.join(normalized_parts)
        return hashlib.md5(normalized_path.encode()).hexdigest()

    def get_different_endpoints(
        self,
        responses: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        从响应列表中提取差异化端点
        
        基于响应内容哈希去重，返回真正有差异的端点
        """
        hash_groups = defaultdict(list)

        for resp in responses:
            content = resp.get('content', b'')
            if isinstance(content, str):
                content = content.encode()

            content_hash = hashlib.sha256(content).hexdigest()
            resp['content_hash'] = content_hash
            hash_groups[content_hash].append(resp)

        unique = []
        for content_hash, group in hash_groups.items():
            representative = group[0]
            representative['response_count'] = len(group)
            representative['response_group'] = content_hash[:8]
            unique.append(representative)

        unique.sort(key=lambda x: (
            x.get('status_code', 0),
            -x.get('response_count', 0),
        ), reverse=True)

        return unique

    def filter_by_content_diff(
        self,
        responses: List[Dict[str, Any]],
        baseline: Optional[Dict[str, Any]] = None,
        min_diff_ratio: float = 0.1
    ) -> List[Dict[str, Any]]:
        """
        基于内容差异过滤响应
        
        返回与基线响应明显不同的端点
        """
        if not responses:
            return []

        if not baseline:
            baseline = responses[0]

        baseline_content = baseline.get('content', b'')
        if isinstance(baseline_content, str):
            baseline_content = baseline_content.encode()
        baseline_hash = hashlib.sha256(baseline_content).hexdigest()

        different = []
        for resp in responses:
            content = resp.get('content', b'')
            if isinstance(content, str):
                content = content.encode()

            content_hash = hashlib.sha256(content).hexdigest()
            resp['content_hash'] = content_hash

            if content_hash != baseline_hash:
                resp['is_different'] = True
                different.append(resp)

        return different

    def adaptive_batch_size(
        self,
        target: str,
        current_batch_size: int,
        success_rate: float,
        avg_response_time: float
    ) -> int:
        """
        自适应批大小调整
        
        根据目标表现动态调整批大小
        """
        if success_rate > 0.8 and avg_response_time < 1.0:
            new_batch_size = int(current_batch_size * 1.2)
        elif success_rate > 0.5 and avg_response_time < 2.0:
            new_batch_size = int(current_batch_size * 1.1)
        elif success_rate < 0.3:
            new_batch_size = int(current_batch_size * 0.5)
        elif avg_response_time > 5.0:
            new_batch_size = int(current_batch_size * 0.7)
        else:
            new_batch_size = current_batch_size

        return max(10, min(new_batch_size, 500))

    def get_stats(self) -> Dict[str, int]:
        """获取过滤统计"""
        return self._stats.copy()


class ResponseClusterAnalyzer:
    """
    响应聚类分析器
    
    功能:
    1. 按响应状态码聚类
    2. 按响应内容哈希聚类
    3. 识别异常响应
    4. 发现隐藏接口
    """

    INTERESTING_STATUS_CODES = {200, 201, 204, 301, 302, 401, 403, 500, 502, 503}

    INTERESTING_CONTENT_PATTERNS = [
        r'"(error|message|result|status|data|response)"\s*:',
        r'<(error|message|result|status)>',
        r'(application|content)-type\s*:\s*application/json',
        r'{(.*)',
        r'\[(.*)',
    ]

    def __init__(self):
        self.clusters: Dict[str, List[Dict]] = defaultdict(list)
        self.anomaly_clusters: List[Dict] = []

    def analyze_responses(
        self,
        responses: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        分析响应列表
        
        Returns:
            {
                'clusters': 按状态码分组的响应,
                'anomalies': 异常响应,
                'api_indicators': API 端点指示,
            }
        """
        status_clusters = defaultdict(list)
        hash_clusters = defaultdict(list)

        for resp in responses:
            status = resp.get('status_code', 0)
            content_hash = resp.get('content_hash', '')

            status_clusters[status].append(resp)
            if content_hash:
                hash_clusters[content_hash].append(resp)

        api_indicators = self._find_api_indicators(responses)

        anomalies = []
        for status, group in status_clusters.items():
            if status in self.INTERESTING_STATUS_CODES:
                for resp in group[:5]:
                    if self._is_anomaly(resp):
                        anomalies.append(resp)

        return {
            'status_clusters': dict(status_clusters),
            'hash_clusters': {k: len(v) for k, v in hash_clusters.items()},
            'anomalies': anomalies,
            'api_indicators': api_indicators,
        }

    def _is_anomaly(self, resp: Dict[str, Any]) -> bool:
        """判断是否为异常响应"""
        content = resp.get('content', b'')
        if isinstance(content, bytes):
            content = content.decode('utf-8', errors='ignore')

        content_lower = content.lower()

        if 'error' in content_lower or 'exception' in content_lower:
            return True
        if 'unauthorized' in content_lower or 'forbidden' in content_lower:
            return True
        if 'not found' in content_lower or '404' in content_lower:
            return True

        return False

    def _find_api_indicators(
        self,
        responses: List[Dict[str, Any]]
    ) -> List[str]:
        """发现 API 端点指示"""
        indicators = set()

        for resp in responses:
            content = resp.get('content', b'')
            if isinstance(content, bytes):
                content = content.decode('utf-8', errors='ignore')

            for pattern in self.INTERESTING_CONTENT_PATTERNS:
                matches = re.findall(pattern, content, re.IGNORECASE)
                indicators.update(matches[:5])

        return list(indicators)[:50]


def prioritize_endpoints(
    endpoints: List[Dict[str, Any]],
    strategy: str = "roi"
) -> List[ScoredEndpoint]:
    """
    便捷函数: 端点优先级排序
    
    Args:
        endpoints: 端点列表
        strategy: 策略
            - "roi": ROI 优先
            - "coverage": 覆盖率优先
            - "speed": 速度优先
    
    Returns:
        排序后的端点
    """
    filter_instance = SmartFilter()

    if strategy == "coverage":
        source_weights = {
            'js_parse': 0.9,
            'api_doc': 0.95,
            'wayback': 0.8,
            'runtime': 0.9,
            'fuzz': 0.5,
            'ai': 0.7,
            'default': 0.6,
        }
    elif strategy == "speed":
        source_weights = {
            'js_parse': 0.9,
            'api_doc': 0.95,
            'wayback': 0.7,
            'runtime': 0.9,
            'fuzz': 0.2,
            'ai': 0.5,
            'default': 0.5,
        }
    else:
        source_weights = {
            'js_parse': 0.8,
            'api_doc': 0.9,
            'wayback': 0.6,
            'runtime': 0.95,
            'fuzz': 0.3,
            'ai': 0.7,
            'default': 0.5,
        }

    scored = filter_instance.score_endpoints(endpoints, source_weights)

    if strategy == "coverage":
        filtered = filter_instance.smart_filter(scored, strategy="conservative")
    elif strategy == "speed":
        filtered = filter_instance.smart_filter(scored, strategy="aggressive")
    else:
        filtered = filter_instance.smart_filter(scored, strategy="balanced")

    return filtered


if __name__ == "__main__":
    print("Smart Filter - Endpoint Prioritization")
    print("Core: Confidence * Value * Source weighting + Deduplication")
