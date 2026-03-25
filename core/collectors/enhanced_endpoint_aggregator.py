#!/usr/bin/env python3
"""
端点融合聚合器 - ApiRed + FLUX 深度融合
结合 APIAggregator 的简洁性与 EndpointFusionEngine 的智能评分

设计原则:
1. 保留 APIAggregator 接口兼容性 - 现有代码无缝迁移
2. 集成 EndpointFusionEngine 置信度评分 - ROI提升
3. 集成证据链管理 - 可追溯分析
4. 集成运行时确认 - 优先测试存活端点
5. 添加自动端点分类 - 高价值目标优先
"""

import re
import hashlib
import logging
from typing import List, Dict, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin
from enum import Enum

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
    """端点证据链 - 记录端点发现过程"""
    source_type: SourceType
    source_url: str = ""
    discovery_method: str = ""
    confidence: str = "low"
    raw_evidence: str = ""
    context: Dict = field(default_factory=dict)


@dataclass
class EnhancedEndpoint:
    """
    增强端点 - 融合数据结构
    
    融合了 APIAggregator.APIFindResult 的简洁性
    和 EndpointFusionEngine.FusedEndpoint 的智能评分
    """
    path: str
    method: str = "GET"
    source_type: str = "regex"
    base_url: str = ""
    context: Optional[str] = None
    url_type: str = "api_path"
    
    full_url: str = ""
    endpoint_type: EndpointType = EndpointType.UNKNOWN
    evidence_chain: List[EndpointEvidence] = field(default_factory=list)
    primary_source: Optional[SourceType] = None
    confidence_score: float = 0.0
    confidence_level: ConfidenceLevel = ConfidenceLevel.LOW
    runtime_observed: bool = False
    runtime_status: int = 0
    runtime_content_type: str = ""
    description: str = ""
    risk_hints: List[str] = field(default_factory=list)
    params: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    _fusion_key: str = ""
    
    def __post_init__(self):
        if not self.full_url and self.base_url and self.path:
            self.full_url = urljoin(self.base_url.rstrip('/'), self.path.lstrip('/'))
        elif not self.full_url:
            self.full_url = self.path
        
        if not self._fusion_key:
            self._fusion_key = self._generate_fusion_key()
        
        if not self.endpoint_type or self.endpoint_type == EndpointType.UNKNOWN:
            self.endpoint_type = self._classify_endpoint()
    
    def _generate_fusion_key(self) -> str:
        key = f"{self.method.upper()}:{self.full_url.lower()}"
        return hashlib.md5(key.encode()).hexdigest()[:16]
    
    @property
    def fusion_key(self) -> str:
        return self._fusion_key
    
    def _classify_endpoint(self) -> EndpointType:
        url_lower = self.full_url.lower()
        path_lower = self.path.lower()
        
        STATIC_PATTERNS = [
            r'\.(js|css|png|jpg|jpeg|gif|svg|woff|woff2|ttf|eot|ico|map)$',
            r'/static/', r'/assets/', r'/images/', r'/fonts/',
        ]
        for pattern in STATIC_PATTERNS:
            if re.search(pattern, url_lower):
                return EndpointType.STATIC_RESOURCE
        
        ADMIN_PATTERNS = [
            r'/admin', r'/manage', r'/dashboard', r'/console',
            r'/backend', r'/system', r'/control',
        ]
        for pattern in ADMIN_PATTERNS:
            if re.search(pattern, url_lower):
                return EndpointType.ADMIN_PANEL
        
        AI_PATTERNS = [
            r'/ai/', r'/llm/', r'/chat/', r'/embed',
            r'/vector', r'/model', r'/predict', r'/inference',
            r'/nlp/', r'/vision/', r'/speech/',
        ]
        for pattern in AI_PATTERNS:
            if re.search(pattern, url_lower):
                return EndpointType.AI_INTERFACE
        
        API_PATTERNS = [
            r'/api/', r'/v\d+/', r'/graphql', r'/rest/',
            r'/swagger', r'/openapi', r'/rpc/', r'/endpoint',
        ]
        for pattern in API_PATTERNS:
            if re.search(pattern, url_lower):
                return EndpointType.API_ENDPOINT
        
        DOC_PATTERNS = [
            r'/doc', r'/docs', r'/documentation', r'/apidoc',
            r'/swagger', r'/openapi', r'/redoc',
        ]
        for pattern in DOC_PATTERNS:
            if re.search(pattern, url_lower):
                return EndpointType.DOC_PAGE
        
        return EndpointType.UNKNOWN
    
    def add_evidence(self, evidence: EndpointEvidence):
        """添加证据链"""
        self.evidence_chain.append(evidence)
        self._recalculate_confidence()
    
    def add_source(self, source_type: SourceType, source_url: str = "", **kwargs):
        """便捷方法：添加来源"""
        evidence = EndpointEvidence(
            source_type=source_type,
            source_url=source_url,
            discovery_method=kwargs.get('discovery_method', 'unknown'),
            confidence=kwargs.get('confidence', 'low'),
            raw_evidence=kwargs.get('raw_evidence', ''),
            context=kwargs.get('context', {})
        )
        self.add_evidence(evidence)
    
    def _recalculate_confidence(self):
        """重新计算置信度评分"""
        if not self.evidence_chain:
            self.confidence_score = 0.0
            self.confidence_level = ConfidenceLevel.LOW
            return
        
        if self.runtime_observed:
            base_score = 0.9
        else:
            base_score = 0.0
        
        source_scores = {
            SourceType.RUNTIME_XHR: 0.6,
            SourceType.RUNTIME_FETCH: 0.6,
            SourceType.RENDER_DOM: 0.4,
            SourceType.API_DOC: 0.5,
            SourceType.WEBPACK: 0.3,
            SourceType.JS_AST: 0.3,
            SourceType.JS_STRING: 0.2,
            SourceType.JS_CONCAT: 0.2,
            SourceType.JS_FUZZ: 0.15,
            SourceType.AI_INFERRED: 0.2,
            SourceType.FINGERPRINT: 0.4,
            SourceType.STATIC: 0.1,
            SourceType.REGEX: 0.15,
            SourceType.UNKNOWN: 0.05,
        }
        
        for evidence in self.evidence_chain:
            try:
                source_type = evidence.source_type if isinstance(evidence.source_type, SourceType) else SourceType(evidence.source_type)
            except ValueError:
                source_type = SourceType.UNKNOWN
            base_score += source_scores.get(source_type, 0.02)
        
        base_score += min(len(self.evidence_chain) * 0.02, 0.1)
        
        self.confidence_score = min(base_score, 1.0)
        
        if self.confidence_score >= 0.7:
            self.confidence_level = ConfidenceLevel.HIGH
        elif self.confidence_score >= 0.4:
            self.confidence_level = ConfidenceLevel.MEDIUM
        else:
            self.confidence_level = ConfidenceLevel.LOW
    
    def mark_runtime_confirmed(self, status_code: int = 200, content_type: str = ""):
        """标记运行时确认"""
        self.runtime_observed = True
        self.runtime_status = status_code
        self.runtime_content_type = content_type
        self._recalculate_confidence()
    
    def add_risk_hint(self, hint: str):
        """添加风险提示"""
        if hint not in self.risk_hints:
            self.risk_hints.append(hint)
    
    def add_tag(self, tag: str):
        """添加标签"""
        if tag not in self.tags:
            self.tags.append(tag)
    
    def to_dict(self) -> Dict:
        """转换为字典"""
        return {
            'path': self.path,
            'method': self.method,
            'source_type': self.source_type,
            'base_url': self.base_url,
            'context': self.context,
            'url_type': self.url_type,
            'full_url': self.full_url,
            'endpoint_type': self.endpoint_type.value if isinstance(self.endpoint_type, EndpointType) else self.endpoint_type,
            'confidence_score': round(self.confidence_score, 2),
            'confidence_level': self.confidence_level.value,
            'runtime_observed': self.runtime_observed,
            'runtime_status': self.runtime_status,
            'description': self.description,
            'risk_hints': self.risk_hints,
            'tags': self.tags,
            'params': self.params,
            'evidence_count': len(self.evidence_chain),
        }
    
    @classmethod
    def from_api_find_result(cls, api_result: 'APIFindResult') -> 'EnhancedEndpoint':
        """从 APIFindResult 创建 EnhancedEndpoint"""
        endpoint = cls(
            path=api_result.path,
            method=api_result.method,
            source_type=api_result.source_type,
            base_url=api_result.base_url,
            context=api_result.context,
            url_type=api_result.url_type,
        )
        
        try:
            source_type = SourceType(api_result.source_type)
        except ValueError:
            source_type = SourceType.UNKNOWN
        
        endpoint.primary_source = source_type
        endpoint.add_evidence(EndpointEvidence(
            source_type=source_type,
            discovery_method=api_result.source_type,
            confidence='medium'
        ))
        
        return endpoint


class EnhancedEndpointAggregator:
    """
    增强端点聚合器 - 融合 APIAggregator 和 EndpointFusionEngine
    
    设计原则:
    1. APIAggregator 接口兼容 - add_api(), get_all(), get_by_source(), merge()
    2. EndpointFusionEngine 智能评分 - 置信度、证据链、运行时确认
    3. 自动端点分类 - API/ADMIN/AI/STATIC
    4. 多维度去重 - method:url MD5 融合键
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
    
    def __init__(self):
        self.endpoints: Dict[str, EnhancedEndpoint] = {}
        self.sources: Dict[str, List[Dict]] = {}
        self.stats = {
            'total_discovered': 0,
            'after_fusion': 0,
            'runtime_confirmed': 0,
            'high_confidence': 0,
            'by_type': {},
        }
    
    def add_api(self, api: Any, source_info: Optional[Dict] = None) -> EnhancedEndpoint:
        """
        添加API - APIAggregator 接口兼容
        
        支持两种调用方式:
        1. add_api(APIFindResult, source_info)
        2. add_api(EnhancedEndpoint, source_info)
        """
        if isinstance(api, EnhancedEndpoint):
            endpoint = api
            if not endpoint.full_url and endpoint.base_url:
                endpoint.full_url = urljoin(endpoint.base_url.rstrip('/'), endpoint.path.lstrip('/'))
        elif isinstance(api, dict):
            endpoint = EnhancedEndpoint(
                path=api.get('path', ''),
                method=api.get('method', 'GET'),
                source_type=api.get('source_type', 'regex'),
                base_url=api.get('base_url', ''),
                context=api.get('context'),
                url_type=api.get('url_type', 'api_path'),
            )
        else:
            endpoint = EnhancedEndpoint.from_api_find_result(api)
        
        endpoint.full_url = endpoint.full_url or urljoin(endpoint.base_url.rstrip('/'), endpoint.path.lstrip('/'))
        fusion_key = endpoint.fusion_key
        
        if fusion_key in self.endpoints:
            existing = self.endpoints[fusion_key]
            
            if source_info:
                self.sources[fusion_key].append(source_info)
            
            try:
                source_type = SourceType(source_info.get('source_type', 'unknown')) if source_info else SourceType.UNKNOWN
            except ValueError:
                source_type = SourceType.UNKNOWN
            
            existing.add_evidence(EndpointEvidence(
                source_type=source_type,
                source_url=source_info.get('source_url', '') if source_info else '',
                discovery_method=source_info.get('discovery_method', 'unknown') if source_info else 'unknown',
                confidence='medium',
                raw_evidence=source_info.get('raw_evidence', '') if source_info else '',
            ))
            
            if hasattr(api, 'params') and api.params:
                for p in api.params:
                    if p not in existing.params:
                        existing.params.append(p)
            
            return existing
        
        endpoint.endpoint_type = self._classify_endpoint(endpoint.full_url)
        
        if source_info:
            self.sources[fusion_key] = [source_info]
        else:
            self.sources[fusion_key] = []
        
        self.endpoints[fusion_key] = endpoint
        self.stats['total_discovered'] += 1
        
        return endpoint
    
    def add_endpoint(self, url: str, method: str = "GET",
                     source_type: SourceType = None,
                     source_url: str = "",
                     confidence: str = "low",
                     runtime_observed: bool = False,
                     **kwargs) -> Optional[EnhancedEndpoint]:
        """添加端点 - EndpointFusionEngine 风格接口"""
        parsed = urlparse(url)
        path = parsed.path or kwargs.get('path', '/')
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        endpoint = EnhancedEndpoint(
            path=path,
            method=method,
            source_type=source_type.value if source_type else SourceType.UNKNOWN.value,
            base_url=base_url,
            full_url=url,
            context=kwargs.get('context'),
            description=kwargs.get('description', ''),
        )
        
        endpoint.endpoint_type = self._classify_endpoint(url)
        
        if source_type:
            endpoint.primary_source = source_type
            endpoint.add_evidence(EndpointEvidence(
                source_type=source_type,
                source_url=source_url,
                discovery_method=kwargs.get('discovery_method', 'unknown'),
                confidence=confidence,
                raw_evidence=kwargs.get('raw_evidence', ''),
            ))
        
        if runtime_observed:
            endpoint.mark_runtime_confirmed(
                status_code=kwargs.get('status_code', 200),
                content_type=kwargs.get('content_type', '')
            )
        
        if kwargs.get('params'):
            endpoint.params.extend(kwargs.get('params', []))
        
        return self.add_api(endpoint, {'source_type': source_type.value if source_type else 'unknown'})
    
    def _classify_endpoint(self, url: str) -> EndpointType:
        url_lower = url.lower()
        
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
    
    def get_all(self) -> List[EnhancedEndpoint]:
        """获取所有端点 - APIAggregator 接口"""
        return list(self.endpoints.values())
    
    def get_by_source(self, source_type: str) -> List[EnhancedEndpoint]:
        """按来源筛选 - APIAggregator 接口"""
        results = []
        for endpoint in self.endpoints.values():
            if endpoint.source_type == source_type:
                results.append(endpoint)
        return results
    
    def get_by_confidence(self, min_level: str = "low") -> List[EnhancedEndpoint]:
        """按置信度筛选 - Enhanced"""
        confidence_order = {"high": 3, "medium": 2, "low": 1}
        min_value = confidence_order.get(min_level, 0)
        
        return [
            ep for ep in self.endpoints.values()
            if confidence_order.get(ep.confidence_level.value, 0) >= min_value
        ]
    
    def get_by_type(self, endpoint_type: EndpointType) -> List[EnhancedEndpoint]:
        """按类型筛选"""
        return [
            ep for ep in self.endpoints.values()
            if ep.endpoint_type == endpoint_type
        ]
    
    def get_high_confidence(self) -> List[EnhancedEndpoint]:
        """获取高置信度端点"""
        return self.get_by_confidence("high")
    
    def get_runtime_confirmed(self) -> List[EnhancedEndpoint]:
        """获取运行时确认的端点"""
        return [ep for ep in self.endpoints.values() if ep.runtime_observed]
    
    def get_high_value(self) -> List[EnhancedEndpoint]:
        """获取高价值端点 (高置信度 + 运行时确认 + 高风险类型)"""
        high_value_types = {EndpointType.ADMIN_PANEL, EndpointType.AI_INTERFACE, EndpointType.API_ENDPOINT}
        return [
            ep for ep in self.endpoints.values()
            if (ep.confidence_level == ConfidenceLevel.HIGH or ep.runtime_observed)
            and ep.endpoint_type in high_value_types
        ]
    
    def merge(self, other: 'EnhancedEndpointAggregator'):
        """合并另一个聚合器 - APIAggregator 接口"""
        for endpoint in other.get_all():
            source_info = {'source_type': endpoint.source_type}
            self.add_api(endpoint, source_info)
    
    def update_stats(self):
        """更新统计信息"""
        self.stats['after_fusion'] = len(self.endpoints)
        self.stats['runtime_confirmed'] = len(self.get_runtime_confirmed())
        self.stats['high_confidence'] = len(self.get_high_confidence())
        
        type_counts = {}
        for ep in self.endpoints.values():
            et = ep.endpoint_type.value if isinstance(ep.endpoint_type, EndpointType) else ep.endpoint_type
            type_counts[et] = type_counts.get(et, 0) + 1
        self.stats['by_type'] = type_counts
    
    def get_stats(self) -> Dict:
        """获取统计信息"""
        self.update_stats()
        return self.stats
    
    def get_fusion_report(self) -> Dict:
        """获取融合报告"""
        self.update_stats()
        return {
            'stats': self.stats,
            'high_confidence_endpoints': [ep.to_dict() for ep in self.get_high_confidence()[:20]],
            'runtime_confirmed_count': self.stats['runtime_confirmed'],
            'total_endpoints': len(self.endpoints),
            'by_type': self.stats['by_type'],
        }


class APIFindResult:
    """APIFindResult - 保持向后兼容"""
    def __init__(self, path: str, method: str = "GET", source_type: str = "regex",
                 base_url: str = "", context: Optional[str] = None, url_type: str = "api_path"):
        self.path = path
        self.method = method
        self.source_type = source_type
        self.base_url = base_url
        self.context = context
        self.url_type = url_type


__all__ = [
    'EnhancedEndpointAggregator',
    'EnhancedEndpoint',
    'EndpointEvidence',
    'SourceType',
    'EndpointType',
    'ConfidenceLevel',
    'APIFindResult',
]
