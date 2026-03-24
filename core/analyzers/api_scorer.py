"""
API Scorer Module
API评分模型 - 多源证据聚合与统一评分
"""

import json
import re
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from collections import defaultdict
from urllib.parse import urlparse


@dataclass
class APIEvidence:
    """API证据"""
    path: str
    normalized_path: str
    sources: List[Dict[str, Any]] = field(default_factory=list)
    score: int = 0
    is_high_value: bool = False
    http_access: Optional[Dict] = None
    js_occurrences: int = 0
    sensitive_keywords: List[str] = field(default_factory=list)
    ai_high_value: bool = False


class APIScorer:
    """API评分器"""
    
    SENSITIVE_KEYWORDS = [
        'admin', 'token', 'secret', 'password', 'auth', 'login',
        'user', 'account', 'role', 'permission', 'config', 'key',
        'private', 'internal', 'upload', 'download', 'exec', 'cmd'
    ]
    
    HIGH_VALUE_PATTERNS = [
        r'/admin', r'/user/.*/password', r'/api/.*/token',
        r'/config', r'/secret', r'/debug', r'/actuator',
        r'/swagger', r'/api-docs', r'/upload', r'/download'
    ]
    
    HIGH_VALUE_PATTERNS_COMPILED = [
        re.compile(p, re.IGNORECASE) for p in HIGH_VALUE_PATTERNS
    ]
    
    def __init__(self, min_high_value_score: int = 5):
        self.min_high_value_score = min_high_value_score
        self._evidence_store: Dict[str, APIEvidence] = {}
    
    def add_evidence(
        self,
        api_path: str,
        source_type: str,
        source_data: Dict[str, Any],
        http_info: Optional[Dict] = None
    ):
        """添加API证据"""
        normalized = self._normalize_path(api_path)
        key = normalized
        
        if key not in self._evidence_store:
            self._evidence_store[key] = APIEvidence(
                path=api_path,
                normalized_path=normalized
            )
        
        evidence = self._evidence_store[key]
        evidence.sources.append({
            'type': source_type,
            'data': source_data
        })
        
        if source_type == 'js_regex':
            evidence.js_occurrences += 1
        elif source_type == 'js_ast':
            evidence.js_occurrences += 1
        elif source_type in ('http_log', 'http_test') and http_info:
            evidence.http_access = http_info
        
        self._check_sensitive_keywords(evidence, api_path)
        self._calculate_score(evidence)
    
    def _normalize_path(self, path: str) -> str:
        """规范化路径"""
        path = path.strip().lower()
        
        prefixes = ['/api', '/v1', '/v2', '/v3', '/rest', '/restapi']
        for prefix in prefixes:
            if path.startswith(prefix):
                parts = path[len(prefix):].lstrip('/')
                if parts:
                    return f"{prefix}/{parts}"
                return prefix
        
        return path if path.startswith('/') else f'/{path}'
    
    def _check_sensitive_keywords(self, evidence: APIEvidence, path: str):
        """检查敏感关键字"""
        path_lower = path.lower()
        
        for keyword in self.SENSITIVE_KEYWORDS:
            if keyword in path_lower:
                if keyword not in evidence.sensitive_keywords:
                    evidence.sensitive_keywords.append(keyword)
    
    def _calculate_score(self, evidence: APIEvidence):
        """计算评分"""
        score = 0
        
        if evidence.http_access:
            status = evidence.http_access.get('status', 0)
            if status == 200:
                score += 3
            elif 200 <= status < 400:
                score += 2
            elif status == 401 or status == 403:
                score += 1
        
        score += min(evidence.js_occurrences, 3)
        
        score += len(evidence.sensitive_keywords)
        
        if evidence.ai_high_value:
            score += 2
        
        for compiled_pattern in self.HIGH_VALUE_PATTERNS_COMPILED:
            if compiled_pattern.search(evidence.path):
                score += 1
                break
        
        evidence.score = score
        evidence.is_high_value = score >= self.min_high_value_score
    
    def get_all(self) -> List[APIEvidence]:
        """获取所有评分后的API证据"""
        return list(self._evidence_store.values())
    
    def get_high_value(self) -> List[APIEvidence]:
        """获取高价值API"""
        return [e for e in self._evidence_store.values() if e.is_high_value]
    
    def get_sorted(self) -> List[APIEvidence]:
        """获取按评分排序的API"""
        return sorted(
            self._evidence_store.values(),
            key=lambda x: x.score,
            reverse=True
        )
    
    def to_dict(self) -> List[Dict]:
        """导出为字典"""
        return [
            {
                'path': e.path,
                'normalized_path': e.normalized_path,
                'score': e.score,
                'is_high_value': e.is_high_value,
                'sources_count': len(e.sources),
                'js_occurrences': e.js_occurrences,
                'sensitive_keywords': e.sensitive_keywords,
                'http_access': e.http_access
            }
            for e in self.get_sorted()
        ]


class APIEvidenceAggregator:
    """API证据聚合器"""
    
    def __init__(self, scorer: Optional[APIScorer] = None):
        self.scorer = scorer or APIScorer()
        self._apis_by_source: Dict[str, List[Dict]] = defaultdict(list)
    
    def aggregate_from_sources(
        self,
        js_regex_apis: List[Dict],
        js_ast_apis: List[Dict],
        http_log_apis: List[Dict],
        ai_apis: List[Dict]
    ):
        """从多源聚合API"""
        for api in js_regex_apis:
            self.scorer.add_evidence(
                api.get('path', ''),
                'js_regex',
                api
            )
            self._apis_by_source['js_regex'].append(api)
        
        for api in js_ast_apis:
            self.scorer.add_evidence(
                api.get('path', ''),
                'js_ast',
                api
            )
            self._apis_by_source['js_ast'].append(api)
        
        for api in http_log_apis:
            self.scorer.add_evidence(
                api.get('path', ''),
                'http_log',
                api,
                http_info={'status': api.get('status')}
            )
            self._apis_by_source['http_log'].append(api)
        
        for api in ai_apis:
            if api.get('is_high_value'):
                evidence = self.scorer._evidence_store.get(
                    self.scorer._normalize_path(api.get('path', ''))
                )
                if evidence:
                    evidence.ai_high_value = True
                    self.scorer._calculate_score(evidence)
            self._apis_by_source['ai'].append(api)
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取聚合统计"""
        all_apis = self.scorer.get_all()
        
        return {
            'total_apis': len(all_apis),
            'high_value_apis': len(self.scorer.get_high_value()),
            'sources_breakdown': {
                source: len(apis)
                for source, apis in self._apis_by_source.items()
            },
            'score_distribution': self._get_score_distribution(all_apis)
        }
    
    def _get_score_distribution(self, apis: List[APIEvidence]) -> Dict[str, int]:
        """获取评分分布"""
        dist = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for api in apis:
            if api.score >= 10:
                dist['critical'] += 1
            elif api.score >= 7:
                dist['high'] += 1
            elif api.score >= 5:
                dist['medium'] += 1
            elif api.score >= 3:
                dist['low'] += 1
            else:
                dist['info'] += 1
        
        return dist
