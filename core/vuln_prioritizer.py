#!/usr/bin/env python3
"""
高价值漏洞候选识别模块 - 基于 FLUX v5.2.1
基于上下文、资产重要性和可利用性的漏洞优先级排序
"""

import re
import logging
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class VulnPriority(Enum):
    """漏洞优先级"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnCategory(Enum):
    """漏洞类别"""
    AUTH_BYPASS = "auth_bypass"
    IDOR = "idor"
    SSRF = "ssrf"
    SQLI = "sqli"
    XSS = "xss"
    RCE = "rce"
    INFO_LEAK = "info_leak"
    CONFIG_EXPOSE = "config_expose"
    CLOUD_LEAK = "cloud_leak"
    API_VULN = "api_vuln"
    CMD_INJ = "cmd_inj"
    LFI = "lfi"
    XXE = "xxe"
    SSTI = "ssti"


@dataclass
class VulnCandidate:
    """漏洞候选"""
    vuln_type: str
    category: VulnCategory
    priority: VulnPriority
    url: str
    param: str = ""
    evidence: str = ""
    confidence: float = 0.0
    exploit_likelihood: float = 0.0
    impact_score: float = 0.0
    context_score: float = 0.0
    total_score: float = 0.0
    reasons: List[str] = field(default_factory=list)
    suggested_actions: List[str] = field(default_factory=list)
    request: str = ""
    response: str = ""
    cve_id: str = ""
    verified: bool = False

    def to_dict(self) -> Dict:
        return {
            'vuln_type': self.vuln_type,
            'category': self.category.value if self.category else '',
            'priority': self.priority.value if self.priority else 'info',
            'url': self.url,
            'param': self.param,
            'evidence': self.evidence[:200] if self.evidence else "",
            'confidence': round(self.confidence, 2),
            'exploit_likelihood': round(self.exploit_likelihood, 2),
            'impact_score': round(self.impact_score, 2),
            'context_score': round(self.context_score, 2),
            'total_score': round(self.total_score, 2),
            'reasons': self.reasons,
            'suggested_actions': self.suggested_actions,
            'cve_id': self.cve_id,
            'verified': self.verified,
        }


class VulnPrioritizer:
    """漏洞优先级排序器"""

    HIGH_VALUE_TARGETS = {
        'auth': ['login', 'signin', 'auth', 'oauth', 'token', 'session', 'jwt', 'logout', 'register'],
        'admin': ['admin', 'manage', 'dashboard', 'system', 'console', 'backend', 'control'],
        'api': ['api', 'graphql', 'rest', 'swagger', 'openapi', 'rpc', 'gateway'],
        'payment': ['pay', 'payment', 'order', 'checkout', 'billing', 'invoice', 'transaction'],
        'user': ['user', 'account', 'profile', 'settings', 'password', 'email', 'phone'],
        'upload': ['upload', 'file', 'import', 'export', 'download', 'attachment'],
        'config': ['config', 'setting', 'env', 'properties', 'yaml', 'json', 'xml', 'ini'],
        'database': ['database', 'db', 'mysql', 'postgres', 'mongodb', 'redis', 'elastic'],
        'cloud': ['aws', 'azure', 'gcp', 'aliyun', 'oss', 's3', 'bucket', 'storage'],
        'internal': ['internal', 'intranet', 'corp', 'office', 'staff', 'employee'],
    }

    EXPLOIT_RULES = {
        'SQL Injection': {
            'base_score': 0.9,
            'indicators': ['union', 'select', 'insert', 'update', 'delete', 'drop', 'exec', 'eval', 'benchmark', 'sleep'],
            'context_boost': ['database', 'query', 'sql', 'mysql', 'postgresql', 'oracle'],
        },
        'XSS': {
            'base_score': 0.8,
            'indicators': ['<script>', 'javascript:', 'onerror=', 'onload=', 'alert(', 'eval(', 'innerHTML'],
            'context_boost': ['input', 'search', 'comment', 'reflect', 'post', 'message'],
        },
        'SSRF': {
            'base_score': 0.85,
            'indicators': ['http://', 'https://', 'file://', 'dict://', 'gopher://', '169.254', '127.0'],
            'context_boost': ['url', 'link', 'redirect', 'proxy', 'fetch', 'image', 'preview'],
        },
        'IDOR': {
            'base_score': 0.75,
            'indicators': ['id=', 'user_id=', 'order_id=', 'file_id=', 'post_id=', 'comment_id=', 'category_id='],
            'context_boost': ['api', 'get', 'view', 'detail', 'user', 'profile', 'account'],
        },
        'RCE': {
            'base_score': 0.95,
            'indicators': ['eval(', 'exec(', 'system(', 'shell_exec', 'passthru', 'proc_open', 'popen'],
            'context_boost': ['command', 'shell', 'exec', 'run', 'ping', 'cmd', 'script'],
        },
        'Command Injection': {
            'base_score': 0.95,
            'indicators': [';', '|', '&', '&&', '||', '`', '$(', '${', '\n', '\r'],
            'context_boost': ['command', 'shell', 'exec', 'ping', 'nslookup', 'traceroute'],
        },
        'LFI': {
            'base_score': 0.8,
            'indicators': ['../', '..\\', '/etc/', '/var/', '/proc/', 'file=', 'path=', 'include='],
            'context_boost': ['file', 'page', 'template', 'view', 'load', 'read'],
        },
        'RFI': {
            'base_score': 0.85,
            'indicators': ['http://', 'https://', 'file://', 'include=', 'require=', 'include_once='],
            'context_boost': ['file', 'page', 'template', 'load', 'request'],
        },
        'XXE': {
            'base_score': 0.85,
            'indicators': ['<!DOCTYPE', '<!ENTITY', 'xml', 'xmldata', 'xsd', 'xslt'],
            'context_boost': ['xml', 'upload', 'parse', 'soap', 'rest'],
        },
        'SSTI': {
            'base_score': 0.85,
            'indicators': ['{{', '}}', '{%', '%}', '${', '}}', 'jinja', 'freemarker', 'velocity'],
            'context_boost': ['template', 'render', 'view', 'page', 'mail'],
        },
        'Information Disclosure': {
            'base_score': 0.6,
            'indicators': ['password', 'secret', 'key', 'token', 'credential', 'api_key', 'private'],
            'context_boost': ['config', 'env', 'backup', 'log', 'debug', 'error'],
        },
        'Cloud Key Leak': {
            'base_score': 0.9,
            'indicators': ['AKIA', 'AKID', 'LTAI', 'AIza', 'ghp_', 'xoxb-', 'glpat-', 'sk-'],
            'context_boost': ['aws', 'aliyun', 'tencent', 'gcp', 'github', 'slack', 'docker'],
        },
        'Path Traversal': {
            'base_score': 0.75,
            'indicators': ['../', '..\\', '/etc/passwd', '/windows/', '/boot.ini'],
            'context_boost': ['file', 'path', 'download', 'read', 'include'],
        },
    }

    CATEGORY_MAP = {
        'SQL Injection': VulnCategory.SQLI,
        'XSS': VulnCategory.XSS,
        'SSRF': VulnCategory.SSRF,
        'IDOR': VulnCategory.IDOR,
        'RCE': VulnCategory.RCE,
        'Command Injection': VulnCategory.CMD_INJ,
        'LFI': VulnCategory.LFI,
        'RFI': VulnCategory.RFI,
        'XXE': VulnCategory.XXE,
        'SSTI': VulnCategory.SSTI,
        'Information Disclosure': VulnCategory.INFO_LEAK,
        'Cloud Key Leak': VulnCategory.CLOUD_LEAK,
        'Path Traversal': VulnCategory.LFI,
    }

    def __init__(self):
        self.candidates: List[VulnCandidate] = []

    def analyze_findings(self, findings: List[Dict], context: Dict = None) -> List[VulnCandidate]:
        self.candidates = []

        for finding in findings:
            try:
                candidate = self._analyze_single_finding(finding, context)
                if candidate:
                    self.candidates.append(candidate)
            except Exception as e:
                logger.debug(f"分析发现结果失败: {e}")

        self.candidates.sort(key=lambda x: x.total_score, reverse=True)

        return self.candidates

    def _analyze_single_finding(self, finding: Dict, context: Dict = None) -> Optional[VulnCandidate]:
        vuln_type = finding.get('vuln_type', '')
        url = finding.get('url', '')
        param = finding.get('param', '')
        evidence = finding.get('evidence', '')
        detail = finding.get('detail', '')

        category = self._classify_vuln(vuln_type, detail)

        confidence = self._calculate_confidence(finding)
        exploit_likelihood = self._calculate_exploit_likelihood(vuln_type, evidence, detail)
        impact_score = self._calculate_impact(vuln_type, url, category)
        context_score = self._calculate_context_score(url, param, evidence, context)

        total_score = (
            confidence * 0.25 +
            exploit_likelihood * 0.35 +
            impact_score * 0.25 +
            context_score * 0.15
        )

        priority = self._determine_priority(total_score, category)

        reasons = self._generate_reasons(finding, category, confidence, exploit_likelihood)
        suggested_actions = self._generate_suggestions(category, url, param)

        return VulnCandidate(
            vuln_type=vuln_type,
            category=category,
            priority=priority,
            url=url,
            param=param,
            evidence=evidence,
            confidence=confidence,
            exploit_likelihood=exploit_likelihood,
            impact_score=impact_score,
            context_score=context_score,
            total_score=total_score,
            reasons=reasons,
            suggested_actions=suggested_actions,
            request=finding.get('request', ''),
            response=finding.get('response', ''),
            cve_id=finding.get('cve_id', ''),
            verified=finding.get('verified', False),
        )

    def _classify_vuln(self, vuln_type: str, detail: str = '') -> VulnCategory:
        type_upper = vuln_type.upper()
        detail_lower = detail.lower()

        for key, category in self.CATEGORY_MAP.items():
            if key.upper() in type_upper or key.lower() in detail_lower:
                return category

        if 'SQL' in type_upper or '注入' in detail_lower:
            return VulnCategory.SQLI
        if 'XSS' in type_upper or '跨站' in detail_lower:
            return VulnCategory.XSS
        if 'SSRF' in type_upper or '请求伪造' in detail_lower:
            return VulnCategory.SSRF
        if 'IDOR' in type_upper or '越权' in detail_lower:
            return VulnCategory.IDOR
        if 'RCE' in type_upper or '远程代码执行' in detail_lower:
            return VulnCategory.RCE
        if '信息泄露' in detail_lower or 'INFO' in type_upper:
            return VulnCategory.INFO_LEAK

        return VulnCategory.API_VULN

    def _calculate_confidence(self, finding: Dict) -> float:
        confidence = finding.get('confidence', 0.5)

        if finding.get('verified'):
            confidence = min(confidence + 0.2, 1.0)

        if finding.get('evidence'):
            confidence = min(confidence + 0.1, 1.0)

        return confidence

    def _calculate_exploit_likelihood(self, vuln_type: str, evidence: str, detail: str) -> float:
        vuln_type_upper = vuln_type.upper()
        evidence_lower = evidence.lower()
        detail_lower = detail.lower()
        combined = f"{evidence_lower} {detail_lower}"

        rule = None
        for key, rule_info in self.EXPLOIT_RULES.items():
            if key.upper() in vuln_type_upper:
                rule = rule_info
                break

        if not rule:
            return 0.5

        base_score = rule.get('base_score', 0.5)

        indicators = rule.get('indicators', [])
        indicator_count = sum(1 for ind in indicators if ind.lower() in combined)
        indicator_score = min(indicator_count / max(len(indicators), 1), 0.3)

        context_boosts = rule.get('context_boost', [])
        boost_count = sum(1 for boost in context_boosts if boost.lower() in combined)
        boost_score = min(boost_count / max(len(context_boosts), 1), 0.2)

        return min(base_score + indicator_score + boost_score, 1.0)

    def _calculate_impact(self, vuln_type: str, url: str, category: VulnCategory) -> float:
        url_lower = url.lower()

        for target_type, keywords in self.HIGH_VALUE_TARGETS.items():
            if any(kw in url_lower for kw in keywords):
                if target_type in ['auth', 'admin', 'payment', 'cloud']:
                    return 0.9
                elif target_type in ['config', 'database']:
                    return 0.85
                else:
                    return 0.7

        if category == VulnCategory.RCE:
            return 0.95
        elif category == VulnCategory.SQLI:
            return 0.9
        elif category == VulnCategory.CLOUD_LEAK:
            return 0.9
        elif category == VulnCategory.AUTH_BYPASS:
            return 0.85
        elif category == VulnCategory.IDOR:
            return 0.75
        elif category in [VulnCategory.XSS, VulnCategory.SSRF, VulnCategory.LFI]:
            return 0.7
        elif category == VulnCategory.INFO_LEAK:
            return 0.5

        return 0.6

    def _calculate_context_score(self, url: str, param: str, evidence: str, context: Dict = None) -> float:
        score = 0.5

        url_lower = url.lower()
        param_lower = param.lower()
        evidence_lower = evidence.lower()

        if any(k in url_lower for k in ['/admin', '/manage', '/console', '/dashboard']):
            score += 0.2

        if any(k in url_lower for k in ['/api/', '/v1/', '/v2/', '/graphql']):
            score += 0.15

        if any(k in param_lower for k in ['id', 'user', 'order', 'file', 'upload']):
            score += 0.1

        if context:
            scan_type = context.get('scan_type', '')
            if 'full' in scan_type.lower():
                score += 0.1

        return min(score, 1.0)

    def _determine_priority(self, total_score: float, category: VulnCategory) -> VulnPriority:
        if total_score >= 0.8:
            return VulnPriority.CRITICAL
        elif total_score >= 0.65:
            return VulnPriority.HIGH
        elif total_score >= 0.5:
            return VulnPriority.MEDIUM
        elif total_score >= 0.35:
            return VulnPriority.LOW
        else:
            return VulnPriority.INFO

    def _generate_reasons(self, finding: Dict, category: VulnCategory, confidence: float, exploit_likelihood: float) -> List[str]:
        reasons = []

        if confidence >= 0.8:
            reasons.append(f"高置信度 ({confidence:.0%})")
        elif confidence >= 0.5:
            reasons.append(f"中等置信度 ({confidence:.0%})")

        if exploit_likelihood >= 0.8:
            reasons.append("可利用性高")
        elif exploit_likelihood >= 0.5:
            reasons.append("可利用性中等")

        if finding.get('verified'):
            reasons.append("已验证")

        if category in [VulnCategory.RCE, VulnCategory.SQLI, VulnCategory.CLOUD_LEAK]:
            reasons.append("影响严重")

        return reasons

    def _generate_suggestions(self, category: VulnCategory, url: str, param: str) -> List[str]:
        suggestions = []

        if category == VulnCategory.SQLI:
            suggestions.append("使用参数化查询避免SQL注入")
            suggestions.append("对用户输入进行严格验证")
        elif category == VulnCategory.XSS:
            suggestions.append("对输出进行HTML编码")
            suggestions.append("使用CSP内容安全策略")
        elif category == VulnCategory.SSRF:
            suggestions.append("限制请求目标地址")
            suggestions.append("使用allowlist验证用户输入的URL")
        elif category == VulnCategory.IDOR:
            suggestions.append("实施适当的授权检查")
            suggestions.append("使用间接引用避免直接对象引用")
        elif category == VulnCategory.RCE:
            suggestions.append("避免使用eval和exec处理用户输入")
            suggestions.append("使用安全的API处理系统命令")
        elif category == VulnCategory.CLOUD_LEAK:
            suggestions.append("立即轮换泄露的密钥")
            suggestions.append("在代码库中搜索其他泄露的密钥")
            suggestions.append("启用密钥轮换策略")

        return suggestions

    def get_critical_findings(self) -> List[VulnCandidate]:
        return [c for c in self.candidates if c.priority == VulnPriority.CRITICAL]

    def get_high_findings(self) -> List[VulnCandidate]:
        return [c for c in self.candidates if c.priority == VulnPriority.HIGH]

    def get_by_category(self, category: VulnCategory) -> List[VulnCandidate]:
        return [c for c in self.candidates if c.category == category]

    def get_summary(self) -> Dict:
        return {
            'total': len(self.candidates),
            'critical': len(self.get_critical_findings()),
            'high': len(self.get_high_findings()),
            'by_category': {
                cat.value: len(self.get_by_category(cat))
                for cat in VulnCategory
            },
            'verified': sum(1 for c in self.candidates if c.verified),
            'top_10': [c.to_dict() for c in self.candidates[:10]],
        }


def prioritize_findings(findings: List[Dict], context: Dict = None) -> List[VulnCandidate]:
    prioritizer = VulnPrioritizer()
    return prioritizer.analyze_findings(findings, context)


__all__ = ['VulnPrioritizer', 'VulnCandidate', 'VulnPriority', 'VulnCategory', 'prioritize_findings']
