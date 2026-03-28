#!/usr/bin/env python3
"""
端点融合引擎 - 基于 FLUX v5.2.1
整合多种来源的端点发现，统一去重和置信度评分

.. deprecated::
    此模块已被 core.unified_fusion.UnifiedFusionEngine 替代。
    请使用 UnifiedFusionEngine 获取更好的混合模式支持和置信度评分。
"""

import warnings
warnings.warn(
    "endpoint_fusion.py is deprecated, use core.unified_fusion.UnifiedFusionEngine instead",
    DeprecationWarning,
    stacklevel=2
)

import re
import hashlib
import logging
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin
from enum import Enum

logger = logging.getLogger(__name__)


class SourceType(Enum):
    """端点来源类型（已废弃，请使用 core.unified_fusion 中的 SourceType）"""
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
    KNOWLEDGE_BASE = "knowledge_base"
    STATISTICAL = "statistical"
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
    """端点证据链"""
    source_type: SourceType
    source_url: str = ""
    discovery_method: str = ""
    confidence: str = "low"
    raw_evidence: str = ""
    context: Dict = field(default_factory=dict)


@dataclass
class FusedEndpoint:
    """融合后端点"""
    url: str
    method: str = "GET"
    path: str = ""
    endpoint_type: EndpointType = EndpointType.UNKNOWN
    sources: List[EndpointEvidence] = field(default_factory=list)
    primary_source: Optional[SourceType] = None
    confidence_score: float = 0.0
    confidence_level: ConfidenceLevel = ConfidenceLevel.LOW
    runtime_observed: bool = False
    runtime_status: int = 0
    runtime_content_type: str = ""
    description: str = ""
    risk_hints: List[str] = field(default_factory=list)
    params: List[str] = field(default_factory=list)
    _fusion_key: str = ""

    def __post_init__(self):
        if not self._fusion_key:
            self._fusion_key = self._generate_fusion_key()
        if not self.path:
            self.path = urlparse(self.url).path

    def _generate_fusion_key(self) -> str:
        key = f"{self.method.upper()}:{self.url.lower()}"
        return hashlib.md5(key.encode()).hexdigest()[:16]

    @property
    def fusion_key(self) -> str:
        return self._fusion_key

    def add_evidence(self, evidence: EndpointEvidence):
        self.sources.append(evidence)
        self._recalculate_confidence()

    def _recalculate_confidence(self):
        if not self.sources:
            self.confidence_score = 0.0
            self.confidence_level = ConfidenceLevel.LOW
            return

        if self.runtime_observed:
            base_score = 0.9
        else:
            base_score = 0.0

        source_scores = {
            SourceType.RUNTIME_XHR: 0.3,
            SourceType.RUNTIME_FETCH: 0.3,
            SourceType.RENDER_DOM: 0.2,
            SourceType.API_DOC: 0.2,
            SourceType.WEBPACK: 0.15,
            SourceType.JS_AST: 0.1,
            SourceType.JS_STRING: 0.05,
            SourceType.JS_CONCAT: 0.05,
            SourceType.JS_FUZZ: 0.03,
            SourceType.AI_INFERRED: 0.02,
            SourceType.FINGERPRINT: 0.02,
            SourceType.STATIC: 0.01,
        }

        for source in self.sources:
            base_score += source_scores.get(source.source_type, 0.02)

        base_score += min(len(self.sources) * 0.02, 0.1)

        self.confidence_score = min(base_score, 1.0)

        if self.confidence_score >= 0.7:
            self.confidence_level = ConfidenceLevel.HIGH
        elif self.confidence_score >= 0.4:
            self.confidence_level = ConfidenceLevel.MEDIUM
        else:
            self.confidence_level = ConfidenceLevel.LOW


class EndpointFusionEngine:
    """端点融合引擎"""

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

    def __init__(self):
        self.endpoints: Dict[str, FusedEndpoint] = {}
        self.fusion_stats = {
            'total_discovered': 0,
            'after_fusion': 0,
            'runtime_confirmed': 0,
        }

    def add_endpoint(self, url: str, method: str = "GET",
                     source_type: SourceType = None,
                     source_url: str = "",
                     confidence: str = "low",
                     runtime_observed: bool = False,
                     **kwargs) -> Optional[FusedEndpoint]:
        url = self._normalize_url(url)
        if not url:
            return None

        temp_ep = FusedEndpoint(url=url, method=method)
        fusion_key = temp_ep.fusion_key

        if fusion_key in self.endpoints:
            existing = self.endpoints[fusion_key]

            if source_type:
                evidence = EndpointEvidence(
                    source_type=source_type,
                    source_url=source_url,
                    discovery_method=kwargs.get('discovery_method', 'unknown'),
                    confidence=confidence,
                    raw_evidence=kwargs.get('raw_evidence', ''),
                    context=kwargs.get('context', {})
                )
                existing.add_evidence(evidence)

            if runtime_observed and not existing.runtime_observed:
                existing.runtime_observed = True
                existing.runtime_status = kwargs.get('status_code', 0)
                existing.runtime_content_type = kwargs.get('content_type', '')
                existing._recalculate_confidence()

            if kwargs.get('params'):
                for p in kwargs.get('params', []):
                    if p not in existing.params:
                        existing.params.append(p)

            return existing

        endpoint_type = self._classify_endpoint(url)

        new_ep = FusedEndpoint(
            url=url,
            method=method,
            endpoint_type=endpoint_type,
            runtime_observed=runtime_observed,
            runtime_status=kwargs.get('status_code', 0),
            runtime_content_type=kwargs.get('content_type', ''),
            description=kwargs.get('description', ''),
            params=kwargs.get('params', []),
        )

        if source_type:
            evidence = EndpointEvidence(
                source_type=source_type,
                source_url=source_url,
                discovery_method=kwargs.get('discovery_method', 'unknown'),
                confidence=confidence,
                raw_evidence=kwargs.get('raw_evidence', ''),
                context=kwargs.get('context', {})
            )
            new_ep.add_evidence(evidence)
            new_ep.primary_source = source_type

        self.endpoints[fusion_key] = new_ep
        self.fusion_stats['total_discovered'] += 1

        return new_ep

    def get_all_endpoints(self, min_confidence: str = "low") -> List[FusedEndpoint]:
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

    def get_endpoints_by_type(self, endpoint_type: EndpointType) -> List[FusedEndpoint]:
        return [
            ep for ep in self.endpoints.values()
            if ep.endpoint_type == endpoint_type
        ]

    def get_api_endpoints(self) -> List[FusedEndpoint]:
        return self.get_endpoints_by_type(EndpointType.API_ENDPOINT)

    def get_admin_endpoints(self) -> List[FusedEndpoint]:
        return self.get_endpoints_by_type(EndpointType.ADMIN_PANEL)

    def get_runtime_confirmed(self) -> List[FusedEndpoint]:
        return [
            ep for ep in self.endpoints.values()
            if ep.runtime_observed
        ]

    def get_high_value_endpoints(self) -> List[FusedEndpoint]:
        return [
            ep for ep in self.endpoints.values()
            if ep.endpoint_type in [EndpointType.API_ENDPOINT, EndpointType.ADMIN_PANEL]
            and ep.confidence_level == ConfidenceLevel.HIGH
        ]

    def _normalize_url(self, url: str) -> Optional[str]:
        if not url:
            return None

        url = url.strip()

        if '#' in url:
            url = url.split('#')[0]

        if url.startswith('./'):
            url = url[1:]

        return url if url else None

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

    def get_fusion_report(self) -> Dict:
        self.fusion_stats['after_fusion'] = len(self.endpoints)
        self.fusion_stats['runtime_confirmed'] = len(self.get_runtime_confirmed())

        type_distribution = {}
        for ep in self.endpoints.values():
            et = ep.endpoint_type.value
            type_distribution[et] = type_distribution.get(et, 0) + 1

        source_distribution = {}
        for ep in self.endpoints.values():
            for source in ep.sources:
                st = source.source_type.value
                source_distribution[st] = source_distribution.get(st, 0) + 1

        return {
            'stats': self.fusion_stats,
            'type_distribution': type_distribution,
            'source_distribution': source_distribution,
            'confidence_distribution': {
                'high': len([e for e in self.endpoints.values() if e.confidence_level == ConfidenceLevel.HIGH]),
                'medium': len([e for e in self.endpoints.values() if e.confidence_level == ConfidenceLevel.MEDIUM]),
                'low': len([e for e in self.endpoints.values() if e.confidence_level == ConfidenceLevel.LOW]),
            },
            'total_endpoints': len(self.endpoints),
            'api_endpoints': len(self.get_api_endpoints()),
            'admin_endpoints': len(self.get_admin_endpoints()),
            'runtime_confirmed_count': self.fusion_stats['runtime_confirmed'],
        }


def fuse_endpoints(endpoints_list: List[Dict]) -> List[FusedEndpoint]:
    """便捷函数：融合端点列表"""
    engine = EndpointFusionEngine()

    for ep in endpoints_list:
        source_type = ep.get('source_type')
        if isinstance(source_type, str):
            try:
                source_type = SourceType(source_type)
            except ValueError:
                source_type = None

        engine.add_endpoint(
            url=ep.get('url', ''),
            method=ep.get('method', 'GET'),
            source_type=source_type,
            source_url=ep.get('source_url', ''),
            confidence=ep.get('confidence', 'low'),
            runtime_observed=ep.get('runtime_observed', False),
        )

    return engine.get_all_endpoints()


__all__ = [
    'EndpointFusionEngine',
    'FusedEndpoint',
    'EndpointEvidence',
    'SourceType',
    'EndpointType',
    'ConfidenceLevel',
    'fuse_endpoints',
]
