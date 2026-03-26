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


__all__ = [
    'UnifiedFusionEngine',
    'FusedEndpoint',
    'EndpointEvidence',
    'SourceType',
    'EndpointType',
    'ConfidenceLevel',
    'ensemble_fuse_endpoints',
]
