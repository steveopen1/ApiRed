"""
Reflect Agent Module
反思代理 - 负责结果分析、误报过滤、优先级排序、攻击链分析
"""

import asyncio
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlparse
import logging
import re

from .orchestrator import AgentInterface, ScanContext
from ..knowledge_base import KnowledgeBase, APIEndpoint, Finding

logger = logging.getLogger(__name__)


class CVSSCalculator:
    """
    CVSS 风格漏洞优先级计算器
    基于通用漏洞评分系统计算漏洞优先级
    """

    SEVERITY_SCORES = {
        'critical': 9.0,
        'high': 7.0,
        'medium': 5.0,
        'low': 2.5,
        'info': 0.0
    }

    VULN_TYPE_WEIGHTS = {
        'sql_injection': 9.5,
        'rce': 9.8,
        'xxe': 9.2,
        'ssrf': 8.5,
        'csrf': 7.0,
        'idor': 6.5,
        'idor': 6.5,
        'xss': 6.1,
        'bypass': 5.0,
        'sensitive_data': 5.5,
        'information_disclosure': 4.0,
        'missing_auth': 7.5,
        'broken_auth': 8.0,
    }

    @classmethod
    def calculate_cvss(cls, vuln_type: str, severity: str, context_factors: Dict = None) -> Tuple[float, str]:
        """
        计算 CVSS 风格评分

        Returns: (score, rating)
        """
        base_score = cls.VULN_TYPE_WEIGHTS.get(vuln_type.lower(), 5.0)

        if severity.lower() in cls.SEVERITY_SCORES:
            severity_score = cls.SEVERITY_SCORES[severity.lower()]
            base_score = (base_score + severity_score) / 2

        if context_factors:
            if context_factors.get('has_auth_bypass', False):
                base_score = min(10.0, base_score + 1.5)
            if context_factors.get('network_access', False):
                base_score = min(10.0, base_score + 0.5)
            if context_factors.get('user_interaction', False):
                base_score = max(0.0, base_score - 0.5)

        rating = cls._score_to_rating(base_score)
        return round(base_score, 1), rating

    @classmethod
    def _score_to_rating(cls, score: float) -> str:
        """将分数转换为评级"""
        if score >= 9.0:
            return 'critical'
        elif score >= 7.0:
            return 'high'
        elif score >= 4.0:
            return 'medium'
        elif score >= 0.1:
            return 'low'
        else:
            return 'info'


class ErrorPageFilter:
    """
    错误页面过滤器
    识别并过滤误报中的错误页面响应
    """

    ERROR_PATTERNS = [
        r'(404\s*Not\s*Found)',
        r'(500\s*Internal\s*Server\s*Error)',
        r'(502\s*Bad\s*Gateway)',
        r'(503\s*Service\s*Unavailable)',
        r'(504\s*Gateway\s*Timeout)',
        r'(400\s*Bad\s*Request)',
        r'(403\s*Forbidden)',
        r'(401\s*Unauthorized)',
        r'(Not Found)',
        r'(Page\s*Not\s*Found)',
        r'(Error\s*404)',
        r'(404\s*error)',
        r'(Object\s*not\s*found)',
        r'(The\s*requested\s*URL.*was\s*not\s*found)',
        r'(Unable\s*to\s*process)',
        r'(invalid\s*request)',
        r'(Request\s*Error)',
        r'(default error page)',
        r'(error page)',
        r'(Whitelabel Error Page)',
        r'(nginx.*404)',
        r'(Apache.*404)',
    ]

    GENERIC_ERROR_PATTERNS = [
        r'(exception|Exception)',
        r'(error|Error)',
        r'(failed|Failed|FAILURE)',
        r'(invalid|Invalid)',
        r'(denied|Denied|DENIED)',
        r'(unauthorized|Unauthorized)',
        r'(forbidden|Forbidden)',
    ]

    @classmethod
    def is_error_page(cls, content: str, status_code: int = 0) -> bool:
        """判断是否为错误页面"""
        if status_code >= 400:
            return True

        content_lower = content.lower()

        for pattern in cls.ERROR_PATTERNS:
            if re.search(pattern, content_lower, re.IGNORECASE):
                return True

        generic_count = sum(
            1 for pattern in cls.GENERIC_ERROR_PATTERNS
            if re.search(pattern, content_lower, re.IGNORECASE)
        )

        if generic_count >= 3:
            return True

        return False

    @classmethod
    def filter_error_endpoints(cls, endpoints: List[Dict]) -> List[Dict]:
        """过滤错误页面端点"""
        filtered = []

        for ep in endpoints:
            content = ep.get('response_content', '')
            status = ep.get('status_code', 0)

            if cls.is_error_page(content, status):
                ep['filtered_reason'] = 'error_page'
                ep['is_false_positive'] = True
            else:
                filtered.append(ep)

        return filtered


class AttackChainAnalyzer:
    """
    攻击链分析器
    分析漏洞之间的关联关系，构建攻击路径
    """

    CHAIN_PATTERNS = [
        {
            'name': 'auth_bypass_chain',
            'steps': ['login', 'auth', 'session', 'user', 'profile'],
            'attack_vector': 'authentication_bypass'
        },
        {
            'name': 'sql_injection_chain',
            'steps': ['sql_error', 'parameter', 'query', 'database'],
            'attack_vector': 'sql_injection'
        },
        {
            'name': 'idor_chain',
            'steps': ['user_id', 'profile', 'order', 'data'],
            'attack_vector': 'idor'
        },
        {
            'name': 'ssrf_chain',
            'steps': ['url', 'fetch', 'redirect', 'internal'],
            'attack_vector': 'ssrf'
        },
    ]

    @classmethod
    def analyze_chain(cls, findings: List[Finding], endpoints: List[APIEndpoint]) -> List[Dict]:
        """分析攻击链"""
        chains = []

        vulnerability_findings = [f for f in findings if f.finding_type == 'vulnerability']

        for pattern in cls.CHAIN_PATTERNS:
            matching_findings = []

            for finding in vulnerability_findings:
                title_lower = finding.title.lower()
                desc_lower = finding.description.lower()

                for step in pattern['steps']:
                    if step in title_lower or step in desc_lower:
                        matching_findings.append(finding)
                        break

            if len(matching_findings) >= 2:
                chain = {
                    'chain_name': pattern['name'],
                    'attack_vector': pattern['attack_vector'],
                    'findings': [f.to_dict() for f in matching_findings],
                    'severity': 'high' if len(matching_findings) >= 3 else 'medium',
                    'description': f"发现 {len(matching_findings)} 个关联漏洞，可能形成 {pattern['attack_vector']} 攻击链"
                }
                chains.append(chain)

        return chains


@dataclass
class PrioritizedFinding:
    """带优先级的发现"""
    finding: Finding
    cvss_score: float
    cvss_rating: str
    chain_id: Optional[str] = None


class ReflectAgent(AgentInterface):
    """
    反思代理
    负责结果分析、误报过滤、优先级排序、攻击链分析
    """

    def __init__(self):
        super().__init__("reflect")
        self.error_filter = ErrorPageFilter()
        self.cvss_calc = CVSSCalculator()
        self.chain_analyzer = AttackChainAnalyzer()
        self._filtered_count = 0
        self._vuln_count = 0

    async def execute(self, context: ScanContext) -> Dict[str, Any]:
        """
        执行反思分析

        分析流程:
        1. 获取知识库数据
        2. 误报过滤 (Error Page)
        3. 重复响应去重
        4. 漏洞优先级排序 (CVSS)
        5. 攻击链分析
        """
        logger.info("ReflectAgent: Starting reflection analysis")

        findings = self.knowledge_base.get_findings() if self.knowledge_base else []
        endpoints = self.knowledge_base.get_endpoints() if self.knowledge_base else []
        vulnerabilities = self.knowledge_base.get_vulnerabilities() if self.knowledge_base else []

        filtered_findings = await self._filter_false_positives(findings)
        self._filtered_count = len(findings) - len(filtered_findings)

        deduplicated_findings = await self._deduplicate_responses(filtered_findings)

        prioritized_findings = await self._prioritize(deduplicated_findings)

        attack_chains = await self._analyze_attack_chains(prioritized_findings, endpoints)

        self._vuln_count = len([f for f in prioritized_findings if f.finding.finding_type == 'vulnerability'])

        result = {
            'total_findings': len(findings),
            'filtered_count': self._filtered_count,
            'deduplicated_count': len(deduplicated_findings),
            'prioritized_findings': [
                {
                    'finding': f.finding.to_dict(),
                    'cvss_score': f.cvss_score,
                    'cvss_rating': f.cvss_rating,
                    'chain_id': f.chain_id
                }
                for f in prioritized_findings
            ],
            'attack_chains': attack_chains,
            'summary': {
                'critical_count': len([f for f in prioritized_findings if f.cvss_rating == 'critical']),
                'high_count': len([f for f in prioritized_findings if f.cvss_rating == 'high']),
                'medium_count': len([f for f in prioritized_findings if f.cvss_rating == 'medium']),
                'low_count': len([f for f in prioritized_findings if f.cvss_rating == 'low']),
                'chain_count': len(attack_chains)
            }
        }

        logger.info(f"ReflectAgent: Analysis complete. Filtered: {self._filtered_count}, "
                   f"Vulnerabilities: {self._vuln_count}, Chains: {len(attack_chains)}")

        return result

    async def _filter_false_positives(self, findings: List[Finding]) -> List[Finding]:
        """过滤误报"""
        filtered = []

        for finding in findings:
            if 'error' in finding.title.lower() and 'error page' in finding.description.lower():
                continue

            if finding.finding_type == 'vulnerability':
                if '404' in finding.evidence or 'not found' in finding.evidence.lower():
                    continue

            filtered.append(finding)

        logger.debug(f"Filtered {len(findings) - len(filtered)} false positives")
        return filtered

    async def _deduplicate_responses(self, findings: List[Finding]) -> List[Finding]:
        """去重重复响应"""
        seen_signatures = {}
        deduplicated = []

        for finding in findings:
            signature = f"{finding.finding_type}:{finding.title}:{len(finding.evidence)}"

            if signature not in seen_signatures:
                seen_signatures[signature] = finding
                deduplicated.append(finding)
            else:
                existing = seen_signatures[signature]
                if finding.severity == 'critical' and existing.severity != 'critical':
                    seen_signatures[signature] = finding
                    deduplicated = [f if f != existing else finding for f in deduplicated]

        logger.debug(f"Deduplicated {len(findings) - len(deduplicated)} findings")
        return deduplicated

    async def _prioritize(self, findings: List[Finding]) -> List[PrioritizedFinding]:
        """漏洞优先级排序"""
        prioritized = []

        for finding in findings:
            context_factors = {
                'has_auth_bypass': 'bypass' in finding.title.lower(),
                'network_access': True,
                'user_interaction': False
            }

            score, rating = self.cvss_calc.calculate_cvss(
                finding.finding_type,
                finding.severity,
                context_factors
            )

            prioritized_finding = PrioritizedFinding(
                finding=finding,
                cvss_score=score,
                cvss_rating=rating
            )
            prioritized.append(prioritized_finding)

        prioritized.sort(key=lambda x: x.cvss_score, reverse=True)

        logger.debug(f"Prioritized {len(prioritized)} findings")
        return prioritized

    async def _analyze_attack_chains(
        self,
        prioritized_findings: List[PrioritizedFinding],
        endpoints: List[APIEndpoint]
    ) -> List[Dict]:
        """分析攻击链"""
        findings = [pf.finding for pf in prioritized_findings]
        chains = self.chain_analyzer.analyze_chain(findings, endpoints)

        for i, chain in enumerate(chains):
            chain['chain_id'] = f"CHAIN-{i+1:03d}"

            for pf in prioritized_findings:
                if pf.finding in chain['findings']:
                    pf.chain_id = chain['chain_id']

        logger.debug(f"Found {len(chains)} attack chains")
        return chains

    async def cleanup(self) -> None:
        """清理资源"""
        pass
