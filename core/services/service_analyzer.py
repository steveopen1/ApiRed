"""
Services Module
服务分析模块 - 微服务识别、风险地图、策略路由
"""

import re
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from collections import defaultdict
from urllib.parse import urlparse


@dataclass
class ServiceInfo:
    """服务信息"""
    service_key: str
    service_name: str
    base_url: str
    api_count: int = 0
    high_value_count: int = 0
    unauth_candidates: int = 0
    sensitive_count: int = 0
    vuln_count: int = 0
    risk_score: float = 0.0
    risk_level: str = "low"
    characteristics: List[str] = field(default_factory=list)
    apis: List[str] = field(default_factory=list)
    
    def calculate_risk_score(self) -> float:
        """计算风险分数"""
        score = 0.0
        
        score += min(self.api_count * 0.1, 20.0)
        
        score += self.high_value_count * 5.0
        
        score += self.unauth_candidates * 8.0
        
        score += self.sensitive_count * 10.0
        
        score += self.vuln_count * 15.0
        
        if 'actuator' in self.service_name.lower():
            score += 20.0
        if 'admin' in self.service_name.lower():
            score += 10.0
        if 'debug' in self.service_name.lower():
            score += 15.0
        
        self.risk_score = min(score, 100.0)
        
        if self.risk_score >= 70:
            self.risk_level = "critical"
        elif self.risk_score >= 50:
            self.risk_level = "high"
        elif self.risk_score >= 30:
            self.risk_level = "medium"
        else:
            self.risk_level = "low"
        
        return self.risk_score


class ServicePathExtractor:
    """服务路径提取器"""
    
    SERVICE_PATTERNS = [
        r'^/([a-zA-Z][a-zA-Z0-9_-]*?)(?:/|$)',
        r'^/([a-zA-Z]+)(?:/v\d+)?(?:/|$)',
        r'^/([a-z]{2,}(?:-[a-z]+)*)(?:/|$)',
    ]
    
    ADMIN_PATTERNS = [
        r'admin', r'manage', r'console', r'control', r'system',
        r'cms', r'bms', r'ums', r'rms'
    ]
    
    SENSITIVE_PATTERNS = [
        r'actuator', r'debug', r'env', r'config', r'monitor',
        r'heapdump', r'threaddump', r'prometheus'
    ]
    
    def __init__(self):
        self.service_prefixes: Set[str] = set()
    
    def extract_from_path(self, api_path: str) -> Optional[str]:
        """从API路径提取服务前缀"""
        parts = api_path.strip('/').split('/')
        
        if not parts:
            return None
        
        first_segment = parts[0]
        
        if self._is_likely_service(first_segment):
            return first_segment
        
        for pattern in self.SERVICE_PATTERNS:
            match = re.match(pattern, api_path)
            if match:
                return match.group(1)
        
        return first_segment if len(first_segment) > 2 else None
    
    def _is_likely_service(self, segment: str) -> bool:
        """判断是否为服务路径"""
        if len(segment) < 2:
            return False
        
        if segment.isdigit():
            return False
        
        common_words = {'api', 'v1', 'v2', 'v3', 'rest', 'graphql', 'file', 'upload', 'download', 'static', 'assets'}
        if segment.lower() in common_words:
            return False
        
        return True
    
    def is_admin_service(self, service_name: str) -> bool:
        """判断是否为管理服务"""
        name_lower = service_name.lower()
        return any(re.search(p, name_lower) for p in self.ADMIN_PATTERNS)
    
    def is_sensitive_service(self, service_name: str) -> bool:
        """判断是否为敏感服务"""
        name_lower = service_name.lower()
        return any(re.search(p, name_lower) for p in self.SENSITIVE_PATTERNS)
    
    def build_service_key(
        self,
        base_url: str,
        base_api_path: str,
        service_path: str
    ) -> str:
        """构建服务键"""
        parts = []
        
        if base_url:
            parsed = urlparse(base_url)
            parts.append(parsed.netloc)
        
        if base_api_path:
            clean_path = base_api_path.strip('/')
            if clean_path:
                parts.append(clean_path)
        
        if service_path:
            parts.append(service_path)
        
        return '/'.join(parts) if parts else 'unknown'


class ServiceAggregator:
    """服务聚合器"""
    
    def __init__(self):
        self.extractor = ServicePathExtractor()
        self.services: Dict[str, ServiceInfo] = {}
        self.api_to_service: Dict[str, str] = {}
    
    def add_api(
        self,
        api_path: str,
        base_url: str = "",
        base_api_path: str = "",
        is_high_value: bool = False,
        has_sensitive: bool = False
    ):
        """添加API到服务"""
        service_path = self.extractor.extract_from_path(api_path)
        
        if not service_path:
            service_path = 'default'
        
        service_key = self.extractor.build_service_key(
            base_url, base_api_path, service_path
        )
        
        self.api_to_service[api_path] = service_key
        
        if service_key not in self.services:
            self.services[service_key] = ServiceInfo(
                service_key=service_key,
                service_name=service_path,
                base_url=base_url,
                characteristics=self._extract_characteristics(service_path)
            )
        
        service = self.services[service_key]
        service.api_count += 1
        service.apis.append(api_path)
        
        if is_high_value:
            service.high_value_count += 1
        
        if has_sensitive:
            service.sensitive_count += 1
    
    def _extract_characteristics(self, service_name: str) -> List[str]:
        """提取服务特征"""
        chars = []
        
        if self.extractor.is_admin_service(service_name):
            chars.append("管理后台")
        
        if self.extractor.is_sensitive_service(service_name):
            chars.append("敏感接口")
        
        if 'user' in service_name.lower():
            chars.append("用户相关")
        if 'order' in service_name.lower():
            chars.append("订单相关")
        if 'product' in service_name.lower() or 'goods' in service_name.lower():
            chars.append("商品相关")
        if 'pay' in service_name.lower() or 'payment' in service_name.lower():
            chars.append("支付相关")
        
        return chars
    
    def mark_unauth_candidate(self, api_path: str):
        """标记未授权候选"""
        if api_path in self.api_to_service:
            service_key = self.api_to_service[api_path]
            if service_key in self.services:
                self.services[service_key].unauth_candidates += 1
    
    def mark_vuln(self, api_path: str):
        """标记漏洞"""
        if api_path in self.api_to_service:
            service_key = self.api_to_service[api_path]
            if service_key in self.services:
                self.services[service_key].vuln_count += 1
    
    def calculate_all_risks(self):
        """计算所有服务风险"""
        for service in self.services.values():
            service.calculate_risk_score()
    
    def get_risk_map(self) -> Dict[str, Any]:
        """获取风险地图"""
        self.calculate_all_risks()
        
        return {
            'total_services': len(self.services),
            'risk_distribution': {
                'critical': len([s for s in self.services.values() if s.risk_level == 'critical']),
                'high': len([s for s in self.services.values() if s.risk_level == 'high']),
                'medium': len([s for s in self.services.values() if s.risk_level == 'medium']),
                'low': len([s for s in self.services.values() if s.risk_level == 'low'])
            },
            'top_risky_services': sorted(
                [
                    {
                        'service_key': s.service_key,
                        'risk_score': s.risk_score,
                        'risk_level': s.risk_level,
                        'api_count': s.api_count,
                        'unauth_candidates': s.unauth_candidates,
                        'sensitive_count': s.sensitive_count,
                        'vuln_count': s.vuln_count,
                        'characteristics': s.characteristics
                    }
                    for s in self.services.values()
                ],
                key=lambda x: x['risk_score'],
                reverse=True
            )[:10],
            'services': [
                {
                    'service_key': s.service_key,
                    'service_name': s.service_name,
                    'api_count': s.api_count,
                    'risk_score': s.risk_score,
                    'risk_level': s.risk_level
                }
                for s in sorted(self.services.values(), key=lambda x: x.risk_score, reverse=True)
            ]
        }


class ServiceStrategyRouter:
    """服务策略路由器"""
    
    HIGH_RISK_RULES = {
        'admin': ['actuator_test', 'weak_password_test', 'sensitive_config_test'],
        'management': ['actuator_test', 'sensitive_config_test'],
        'user': ['privacy_data_test', 'idnr_test'],
        'auth': ['bypass_test', 'token_test']
    }
    
    def __init__(self):
        self.strategies: Dict[str, List[str]] = defaultdict(list)
    
    def get_strategies_for_service(self, service_name: str) -> List[str]:
        """获取服务对应的策略"""
        service_lower = service_name.lower()
        strategies = []
        
        for keyword, keyword_strategies in self.HIGH_RISK_RULES.items():
            if keyword in service_lower:
                strategies.extend(keyword_strategies)
        
        if not strategies:
            strategies = ['basic_vuln_test']
        
        return list(set(strategies))
    
    def add_custom_strategy(self, keyword: str, strategies: List[str]):
        """添加自定义策略"""
        self.HIGH_RISK_RULES[keyword] = strategies


class ServiceRiskMapGenerator:
    """服务风险地图生成器"""
    
    def __init__(self, aggregator: ServiceAggregator):
        self.aggregator = aggregator
    
    def generate_visual_map(self) -> Dict[str, Any]:
        """生成可视化风险地图"""
        risk_map = self.aggregator.get_risk_map()
        
        nodes = []
        edges = []
        
        for service_data in risk_map.get('services', []):
            nodes.append({
                'id': service_data['service_key'],
                'label': service_data['service_name'],
                'size': min(service_data['api_count'] * 10, 100),
                'color': self._get_risk_color(service_data['risk_level']),
                'risk_score': service_data['risk_score'],
                'api_count': service_data['api_count']
            })
        
        service_keys = [s['service_key'] for s in nodes]
        for i, key1 in enumerate(service_keys):
            for key2 in service_keys[i+1:]:
                if any(s in key1 and s in key2 for s in ['api', 'v1', 'v2']):
                    edges.append({
                        'source': key1,
                        'target': key2
                    })
        
        return {
            'nodes': nodes,
            'edges': edges,
            'summary': risk_map
        }
    
    def _get_risk_color(self, risk_level: str) -> str:
        """获取风险颜色"""
        colors = {
            'critical': '#dc3545',
            'high': '#fd7e14',
            'medium': '#ffc107',
            'low': '#28a745'
        }
        return colors.get(risk_level, '#6c757d')
