"""
API置信度评分系统

功能：
1. 根据API来源和特征计算置信度
2. 对API端点进行优先级排序
3. 识别高价值目标
"""

import re
import logging
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class SourceType(Enum):
    """API来源类型"""
    JS_DIRECT = "js_direct"           # JS代码直接调用
    JS_INFERRED = "js_inferred"       # JS代码推测
    HTML_INLINE = "html_inline"        # HTML内联JS
    RESPONSE_HINT = "response_hint"   # HTTP响应中发现
    SWAGGER = "swagger"               # OpenAPI/Swagger
    HAR_IMPORT = "har_import"         # HAR/Burp导入
    GRAPHQL = "graphql"              # GraphQL introspection
    MANUAL = "manual"                 # 手动指定
    FUZZ = "fuzz"                    # Fuzzing生成


@dataclass
class ConfidenceFactors:
    """置信度因素"""
    source_weight: float = 1.0
    pattern_match: float = 1.0
    context_hint: float = 1.0
    response_confirmed: bool = False
    has_params: bool = False
    is_restful: bool = False
    has_auth_indicator: bool = False


@dataclass
class ScoredEndpoint:
    """评分后的端点"""
    url: str
    method: str
    confidence_score: float
    source_type: SourceType
    factors: ConfidenceFactors
    is_high_value: bool = False
    category: str = ""


class APISourceWeighter:
    """API来源权重计算器"""

    SOURCE_WEIGHTS = {
        SourceType.JS_DIRECT: 1.0,
        SourceType.HTML_INLINE: 0.85,
        SourceType.RESPONSE_HINT: 0.80,
        SourceType.SWAGGER: 0.95,
        SourceType.GRAPHQL: 0.90,
        SourceType.HAR_IMPORT: 0.85,
        SourceType.JS_INFERRED: 0.50,
        SourceType.FUZZ: 0.30,
        SourceType.MANUAL: 0.70,
    }

    HIGH_VALUE_PATTERNS = [
        r'/admin', r'/manage', r'/console',
        r'/user', r'/account', r'/auth', r'/login', r'/logout',
        r'/api', r'/v\d+/',
        r'/order', r'/payment', r'/transaction',
        r'/config', r'/setting', r'/profile',
    ]

    SENSITIVE_METHODS = ['POST', 'PUT', 'DELETE', 'PATCH']

    @classmethod
    def get_base_weight(cls, source: SourceType) -> float:
        """获取来源基础权重"""
        return cls.SOURCE_WEIGHTS.get(source, 0.5)

    @classmethod
    def is_high_value_pattern(cls, url: str, method: str = "GET") -> bool:
        """判断是否匹配高价值模式"""
        url_lower = url.lower()

        for pattern in cls.HIGH_VALUE_PATTERNS:
            if re.search(pattern, url_lower):
                return True

        if method.upper() in cls.SENSITIVE_METHODS:
            return True

        return False


class APIPatternAnalyzer:
    """API模式分析器"""

    RESTFUL_PATTERNS = [
        r'/(list|get|add|create|update|edit|delete|remove)/',
        r'/(query|search|filter)/',
        r'/(detail|info|view)/',
        r'/(export|import|upload|download)/',
    ]

    AUTH_PATTERNS = [
        r'/login', r'/logout', r'/auth', r'/token',
        r'/register', r'/signup', r'/signin',
        r'/password', r'/reset', r'/verify',
        r'/captcha', r'/sms', r'/mfa',
    ]

    SENSITIVE_DATA_PATTERNS = [
        r'/user', r'/account', r'/profile',
        r'/order', r'/payment', r'/transaction',
        r'/credit', r'/bank', r'/card',
        r'/address', r'/phone', r'/email',
        r'/admin', r'/manage', r'/console',
        r'/config', r'/setting', r'/secret',
    ]

    PARAM_PATTERNS = [
        r'\{[^}]+\}',
        r':[a-zA-Z_][a-zA-Z0-9_]*',
        r'/[0-9]+',
        r'/[a-f0-9-]{36}',
    ]

    @classmethod
    def analyze_restful_score(cls, url: str) -> float:
        """分析RESTful符合度"""
        score = 0.5

        for pattern in cls.RESTFUL_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                score += 0.15

        path_parts = urlparse(url).path.strip('/').split('/')
        has_id_segment = any(
            re.match(p, part) for part in path_parts
            for p in cls.PARAM_PATTERNS
        )
        if has_id_segment:
            score += 0.2

        return min(score, 1.0)

    @classmethod
    def has_auth_indicator(cls, url: str) -> bool:
        """判断是否包含认证相关标识"""
        url_lower = url.lower()
        return any(re.search(p, url_lower) for p in cls.AUTH_PATTERNS)

    @classmethod
    def has_sensitive_data(cls, url: str) -> bool:
        """判断是否涉及敏感数据"""
        url_lower = url.lower()
        return any(re.search(p, url_lower) for p in cls.SENSITIVE_DATA_PATTERNS)

    @classmethod
    def extract_parameters(cls, url: str) -> List[str]:
        """从URL中提取参数"""
        params = []

        for pattern in cls.PARAM_PATTERNS:
            matches = re.findall(pattern, url)
            params.extend(matches)

        parsed = urlparse(url)
        if parsed.query:
            query_params = parsed.query.split('&')
            params.extend([p.split('=')[0] for p in query_params if p])

        return list(set(params))


class ResponseValidator:
    """响应验证器"""

    VALID_RESPONSE_CODES = [200, 201, 204]

    ERROR_RESPONSE_PATTERNS = [
        r'<title>404',
        r'"error"',
        r'"message":\s*"not found"',
        r'"status":\s*404',
        r'document\.not\.found',
    ]

    @classmethod
    def is_valid_api_response(cls, status_code: int, content: str) -> bool:
        """判断是否为有效的API响应"""
        if status_code in cls.VALID_RESPONSE_CODES:
            return True

        for pattern in cls.ERROR_RESPONSE_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                return False

        if 400 <= status_code < 500:
            return True

        return False

    @classmethod
    def calculate_response_score(cls, status_code: int, content: str, size: int) -> float:
        """计算响应质量分数"""
        score = 0.5

        if status_code == 200:
            score += 0.3
        elif 200 <= status_code < 300:
            score += 0.2
        elif status_code == 401 or status_code == 403:
            score += 0.1
        elif status_code >= 500:
            score -= 0.2

        if len(content) > 100:
            score += 0.1

        if 'json' in content.lower():
            score += 0.1

        if not any(re.search(p, content, re.IGNORECASE) for p in cls.ERROR_RESPONSE_PATTERNS):
            score += 0.1

        return max(0.0, min(1.0, score))


class APIScoringEngine:
    """
    API评分引擎
    
    综合考虑多个因素计算API端点的置信度分数
    """

    BASE_SCORE = 0.3

    SOURCE_BONUS = {
        SourceType.JS_DIRECT: 0.25,
        SourceType.HTML_INLINE: 0.20,
        SourceType.SWAGGER: 0.25,
        SourceType.GRAPHQL: 0.20,
        SourceType.RESPONSE_HINT: 0.15,
        SourceType.HAR_IMPORT: 0.15,
        SourceType.JS_INFERRED: 0.05,
        SourceType.FUZZ: 0.0,
        SourceType.MANUAL: 0.10,
    }

    PATTERN_BONUS = {
        'restful': 0.10,
        'has_params': 0.05,
        'has_auth': 0.10,
        'has_sensitive_data': 0.10,
        'is_high_value': 0.15,
    }

    RESPONSE_BONUS = {
        'response_confirmed': 0.20,
        'response_score': 0.0,
    }

    def __init__(self):
        self.scored_endpoints: List[ScoredEndpoint] = []
        self._response_cache: Dict[str, Tuple[int, str]] = {}

    def score_endpoint(
        self,
        url: str,
        method: str = "GET",
        source: SourceType = SourceType.FUZZ,
        response_status: Optional[int] = None,
        response_content: Optional[str] = None,
        response_size: int = 0
    ) -> ScoredEndpoint:
        """
        对API端点进行评分
        
        Args:
            url: API URL
            method: HTTP方法
            source: 来源类型
            response_status: 响应状态码
            response_content: 响应内容
            response_size: 响应大小
            
        Returns:
            ScoredEndpoint对象
        """
        score = self.BASE_SCORE

        score += self.SOURCE_BONUS.get(source, 0.0)

        if APISourceWeighter.is_high_value_pattern(url, method):
            score += self.PATTERN_BONUS['is_high_value']
            high_value = True
        else:
            high_value = False

        restful_score = APIPatternAnalyzer.analyze_restful_score(url)
        if restful_score > 0.7:
            score += self.PATTERN_BONUS['restful']

        params = APIPatternAnalyzer.extract_parameters(url)
        if params:
            score += self.PATTERN_BONUS['has_params']

        if APIPatternAnalyzer.has_auth_indicator(url):
            score += self.PATTERN_BONUS['has_auth']

        if APIPatternAnalyzer.has_sensitive_data(url):
            score += self.PATTERN_BONUS['has_sensitive_data']

        factors = ConfidenceFactors(
            source_weight=self.SOURCE_BONUS.get(source, 0.0),
            pattern_match=restful_score,
            is_restful=restful_score > 0.7,
            has_params=len(params) > 0,
            has_auth_indicator=APIPatternAnalyzer.has_auth_indicator(url),
        )

        if response_status is not None:
            factors.response_confirmed = True

            response_score = ResponseValidator.calculate_response_score(
                response_status,
                response_content or "",
                response_size
            )
            if response_score > 0.6:
                score += self.RESPONSE_BONUS['response_confirmed']
                score += response_score * 0.2

        score = max(0.0, min(1.0, score))

        category = self._categorize_endpoint(url, method)

        endpoint = ScoredEndpoint(
            url=url,
            method=method.upper(),
            confidence_score=score,
            source_type=source,
            factors=factors,
            is_high_value=high_value or score > 0.7,
            category=category
        )

        self.scored_endpoints.append(endpoint)
        return endpoint

    def _categorize_endpoint(self, url: str, method: str) -> str:
        """对端点进行分类"""
        url_lower = url.lower()

        if any(p in url_lower for p in ['/login', '/auth', '/logout', '/register']):
            return "authentication"
        elif any(p in url_lower for p in ['/user', '/account', '/profile', '/password']):
            return "user_management"
        elif any(p in url_lower for p in ['/order', '/payment', '/transaction', '/cart']):
            return "commerce"
        elif any(p in url_lower for p in ['/admin', '/manage', '/console', '/dashboard']):
            return "administration"
        elif any(p in url_lower for p in ['/config', '/setting', '/system']):
            return "configuration"
        elif any(p in url_lower for p in ['/file', '/upload', '/download', '/document']):
            return "file_management"
        elif any(p in url_lower for p in ['/api', '/v1', '/v2', '/rest']):
            return "api_endpoint"
        else:
            return "general"

    def get_prioritized_list(
        self,
        min_score: float = 0.0,
        limit: Optional[int] = None
    ) -> List[ScoredEndpoint]:
        """
        获取按优先级排序的端点列表
        
        Args:
            min_score: 最低分数阈值
            limit: 返回数量限制
            
        Returns:
            排序后的端点列表
        """
        filtered = [e for e in self.scored_endpoints if e.confidence_score >= min_score]

        filtered.sort(
            key=lambda e: (
                -e.confidence_score,
                -e.is_high_value,
                e.source_type.value != SourceType.JS_DIRECT.value
            )
        )

        if limit:
            return filtered[:limit]

        return filtered

    def get_high_value_endpoints(self) -> List[ScoredEndpoint]:
        """获取高价值端点"""
        return [e for e in self.scored_endpoints if e.is_high_value]

    def get_statistics(self) -> Dict[str, Any]:
        """获取评分统计"""
        if not self.scored_endpoints:
            return {
                'total': 0,
                'avg_score': 0,
                'high_value_count': 0,
            }

        scores = [e.confidence_score for e in self.scored_endpoints]

        return {
            'total': len(self.scored_endpoints),
            'avg_score': sum(scores) / len(scores),
            'high_value_count': len([e for e in self.scored_endpoints if e.is_high_value]),
            'by_category': self._count_by_category(),
            'by_source': self._count_by_source(),
            'by_method': self._count_by_method(),
        }

    def _count_by_category(self) -> Dict[str, int]:
        """按类别统计"""
        counts: Dict[str, int] = defaultdict(int)
        for e in self.scored_endpoints:
            counts[e.category] += 1
        return dict(counts)

    def _count_by_source(self) -> Dict[str, int]:
        """按来源统计"""
        counts: Dict[str, int] = defaultdict(int)
        for e in self.scored_endpoints:
            counts[e.source_type.value] += 1
        return dict(counts)

    def _count_by_method(self) -> Dict[str, int]:
        """按方法统计"""
        counts: Dict[str, int] = defaultdict(int)
        for e in self.scored_endpoints:
            counts[e.method] += 1
        return dict(counts)


def create_scoring_engine() -> APIScoringEngine:
    """创建评分引擎"""
    return APIScoringEngine()


from collections import defaultdict
