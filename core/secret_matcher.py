#!/usr/bin/env python3
"""
敏感信息智能匹配模块 - 基于 FLUX v5.2.1
结构化规则 + 上下文判断 + 白名单降噪 + 置信度评分
"""

import re
import math
import logging
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    """风险等级"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class SecretType(Enum):
    """敏感信息类型"""
    AWS_KEY = "aws_key"
    AZURE_KEY = "azure_key"
    GCP_KEY = "gcp_key"
    ALIYUN_KEY = "aliyun_key"
    TENCENT_KEY = "tencent_key"
    HUAWEI_KEY = "huawei_key"
    JWT_TOKEN = "jwt_token"
    API_KEY = "api_key"
    PRIVATE_KEY = "private_key"
    PASSWORD = "password"
    DATABASE_URL = "database_url"
    SLACK_TOKEN = "slack_token"
    GITHUB_TOKEN = "github_token"
    GITLAB_TOKEN = "gitlab_token"
    JENKINS_TOKEN = "jenkins_token"
    STRIPE_KEY = "stripe_key"
    SENDGRID_KEY = "sendgrid_key"
    NPM_TOKEN = "npm_token"
    PYPI_TOKEN = "pypi_token"
    DOCKER_TOKEN = "docker_token"
    SONARQUBE_TOKEN = "sonarqube_token"
    CODECOV_TOKEN = "codecov_token"
    SENTRY_DSN = "sentry_dsn"
    GENERIC_SECRET = "generic_secret"


@dataclass
class SecretMatch:
    """敏感信息匹配结果"""
    type: SecretType
    risk_level: RiskLevel
    value: str
    masked_value: str
    confidence: float
    rule_name: str
    context: str
    source: str
    is_likely_false_positive: bool = False
    false_positive_reason: str = ""
    evidence: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            'type': self.type.value,
            'risk_level': self.risk_level.value,
            'masked_value': self.masked_value,
            'confidence': round(self.confidence, 2),
            'rule_name': self.rule_name,
            'context': self.context[:200] if self.context else "",
            'source': self.source,
            'is_likely_false_positive': self.is_likely_false_positive,
            'false_positive_reason': self.false_positive_reason,
        }


class SecretMatcher:
    """敏感信息匹配器"""

    FALSE_POSITIVE_PATTERNS = [
        r'example', r'demo', r'test', r'mock', r'placeholder',
        r'your_', r'my_', r'xxx', r'xxxx', r'123456', r'password123',
        r'admin123', r'key123', r'secret123', r'undefined', r'null',
        r'true', r'false', r'function', r'class', r'return',
        r'const', r'let', r'var', r'strReplace', r'REPLACE_ME',
        r'TODO', r'FIXME', r'CHANGEME', r'CHANGEME',
    ]

    EXAMPLE_VALUES = {
        'aws': ['AKIAIOSFODNN7EXAMPLE', 'AKIA...EXAMPLE'],
        'jwt': ['eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'],
        'generic': ['your-api-key', 'your_api_key', 'YOUR_API_KEY'],
    }

    def __init__(self):
        self.rules = self._init_rules()
        self.mask_char = '*'

    def _init_rules(self) -> List[Dict]:
        rules = [
            {
                'name': 'AWS Access Key ID',
                'type': SecretType.AWS_KEY,
                'risk_level': RiskLevel.CRITICAL,
                'pattern': r'AKIA[0-9A-Z]{16}',
                'entropy_threshold': 0.0,
                'context_patterns': ['aws', 'amazon', 'access_key', 'akid'],
            },
            {
                'name': 'AWS Secret Access Key',
                'type': SecretType.AWS_KEY,
                'risk_level': RiskLevel.CRITICAL,
                'pattern': r'[0-9a-zA-Z/+]{40}',
                'entropy_threshold': 4.5,
                'context_patterns': ['aws', 'secret', 'access_key', 'aws_secret'],
            },
            {
                'name': 'Azure Key',
                'type': SecretType.AZURE_KEY,
                'risk_level': RiskLevel.CRITICAL,
                'pattern': r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
                'entropy_threshold': 0.0,
                'context_patterns': ['azure', 'microsoft', 'subscription', 'tenant'],
            },
            {
                'name': 'GCP API Key',
                'type': SecretType.GCP_KEY,
                'risk_level': RiskLevel.CRITICAL,
                'pattern': r'AIza[0-9A-Za-z_-]{35}',
                'entropy_threshold': 0.0,
                'context_patterns': ['google', 'gcp', 'firebase', 'api_key'],
            },
            {
                'name': '阿里云 AccessKey',
                'type': SecretType.ALIYUN_KEY,
                'risk_level': RiskLevel.CRITICAL,
                'pattern': r'LTAI[a-zA-Z0-9]{12,20}',
                'entropy_threshold': 0.0,
                'context_patterns': ['aliyun', 'alibaba', 'oss', 'accesskey'],
            },
            {
                'name': '腾讯云 SecretId',
                'type': SecretType.TENCENT_KEY,
                'risk_level': RiskLevel.CRITICAL,
                'pattern': r'AKID[a-zA-Z0-9]{32,40}',
                'entropy_threshold': 0.0,
                'context_patterns': ['tencent', 'qcloud', 'secretid', 'secretkey'],
            },
            {
                'name': '华为云 Key',
                'type': SecretType.HUAWEI_KEY,
                'risk_level': RiskLevel.CRITICAL,
                'pattern': r'HW[a-zA-Z0-9]{24,32}',
                'entropy_threshold': 0.0,
                'context_patterns': ['huawei', 'hwcloud', 'cloud'],
            },
            {
                'name': 'JWT Token',
                'type': SecretType.JWT_TOKEN,
                'risk_level': RiskLevel.HIGH,
                'pattern': r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
                'entropy_threshold': 0.0,
                'context_patterns': ['jwt', 'token', 'bearer', 'authorization'],
            },
            {
                'name': 'Private Key',
                'type': SecretType.PRIVATE_KEY,
                'risk_level': RiskLevel.CRITICAL,
                'pattern': r'-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----',
                'entropy_threshold': 0.0,
                'context_patterns': ['private', 'key', 'pem', 'ssh'],
                'multiline': True,
            },
            {
                'name': 'GitHub Token',
                'type': SecretType.GITHUB_TOKEN,
                'risk_level': RiskLevel.CRITICAL,
                'pattern': r'gh[pousr]_[a-zA-Z0-9_]{36,}',
                'entropy_threshold': 0.0,
                'context_patterns': ['github', 'gh_', 'token'],
            },
            {
                'name': 'GitLab Token',
                'type': SecretType.GITLAB_TOKEN,
                'risk_level': RiskLevel.CRITICAL,
                'pattern': r'glpat-[0-9a-zA-Z\-_]{20}',
                'entropy_threshold': 0.0,
                'context_patterns': ['gitlab', 'glpat', 'token'],
            },
            {
                'name': 'Slack Token',
                'type': SecretType.SLACK_TOKEN,
                'risk_level': RiskLevel.HIGH,
                'pattern': r'xox[baprs]-[0-9a-zA-Z-]{10,48}',
                'entropy_threshold': 0.0,
                'context_patterns': ['slack', 'token', 'xoxb'],
            },
            {
                'name': 'NPM Token',
                'type': SecretType.NPM_TOKEN,
                'risk_level': RiskLevel.HIGH,
                'pattern': r'npm_[A-Za-z0-9]{36}',
                'entropy_threshold': 0.0,
                'context_patterns': ['npm', 'registry', 'token'],
            },
            {
                'name': 'PyPI Token',
                'type': SecretType.PYPI_TOKEN,
                'risk_level': RiskLevel.HIGH,
                'pattern': r'pypi-[A-Za-z0-9_-]{40,}',
                'entropy_threshold': 0.0,
                'context_patterns': ['pypi', 'token'],
            },
            {
                'name': 'Docker Token',
                'type': SecretType.DOCKER_TOKEN,
                'risk_level': RiskLevel.CRITICAL,
                'pattern': r'dckr_pat_[0-9a-zA-Z_-]{27,}',
                'entropy_threshold': 0.0,
                'context_patterns': ['docker', 'dckr', 'registry'],
            },
            {
                'name': 'Slack Webhook',
                'type': SecretType.SLACK_TOKEN,
                'risk_level': RiskLevel.MEDIUM,
                'pattern': r'https://hooks\.slack\.com/services/[A-Za-z0-9+/]+',
                'entropy_threshold': 0.0,
                'context_patterns': ['slack', 'webhook', 'hooks'],
            },
            {
                'name': 'Sentry DSN',
                'type': SecretType.SENTRY_DSN,
                'risk_level': RiskLevel.MEDIUM,
                'pattern': r'https://[0-9a-f]{32}@o\d+\.ingest\.sentry\.io/\d+',
                'entropy_threshold': 0.0,
                'context_patterns': ['sentry', 'dsn', 'ingest'],
            },
            {
                'name': 'Generic API Key',
                'type': SecretType.API_KEY,
                'risk_level': RiskLevel.MEDIUM,
                'pattern': r'[a-zA-Z0-9_-]{32,64}',
                'entropy_threshold': 4.0,
                'context_patterns': ['api_key', 'apikey', 'key', 'token'],
            },
            {
                'name': 'Database URL',
                'type': SecretType.DATABASE_URL,
                'risk_level': RiskLevel.CRITICAL,
                'pattern': r'(mysql|postgres|postgresql|mongodb|redis):\/\/[^\s\'"]{10,}',
                'entropy_threshold': 0.0,
                'context_patterns': ['database', 'db', 'connection', 'url'],
            },
        ]
        return rules

    def scan_text(self, text: str, source: str = "") -> List[SecretMatch]:
        matches = []
        if not text:
            return matches

        for rule in self.rules:
            pattern_matches = self._find_pattern(rule, text)
            for match_result in pattern_matches:
                secret_match = self._analyze_match(rule, match_result, text, source)
                if secret_match and not secret_match.is_likely_false_positive:
                    matches.append(secret_match)

        return matches

    def scan_file(self, file_path: str, source: str = "") -> List[SecretMatch]:
        matches = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            matches = self.scan_text(content, source or file_path)
        except Exception as e:
            logger.debug(f"扫描文件失败 {file_path}: {e}")
        return matches

    def _find_pattern(self, rule: Dict, text: str) -> List[Tuple[str, int, int]]:
        matches = []
        pattern = rule.get('pattern', '')
        if not pattern:
            return matches

        flags = re.MULTILINE if rule.get('multiline', False) else 0
        try:
            for match in re.finditer(pattern, text, flags):
                matches.append((match.group(), match.start(), match.end()))
        except Exception:
            pass
        return matches

    def _analyze_match(self, rule: Dict, match_result: Tuple[str, int, int], text: str, source: str) -> Optional[SecretMatch]:
        value, start, end = match_result

        context_start = max(0, start - 50)
        context_end = min(len(text), end + 50)
        context = text[context_start:context_end]

        if self._is_false_positive(value, context, rule):
            return SecretMatch(
                type=rule['type'],
                risk_level=rule['risk_level'],
                value=value,
                masked_value=self._mask_value(value),
                confidence=0.3,
                rule_name=rule['name'],
                context=context,
                source=source,
                is_likely_false_positive=True,
                false_positive_reason="Matched whitelist patterns"
            )

        entropy = self._calculate_entropy(value)
        entropy_threshold = rule.get('entropy_threshold', 0.0)

        if entropy_threshold > 0 and entropy < entropy_threshold:
            return None

        context_boost = self._check_context(context.lower(), rule.get('context_patterns', []))

        confidence = min(0.5 + context_boost * 0.3 + entropy * 0.2, 1.0)

        return SecretMatch(
            type=rule['type'],
            risk_level=rule['risk_level'],
            value=value,
            masked_value=self._mask_value(value),
            confidence=confidence,
            rule_name=rule['name'],
            context=context,
            source=source,
            is_likely_false_positive=False,
            evidence={'entropy': entropy, 'context_boost': context_boost}
        )

    def _is_false_positive(self, value: str, context: str, rule: Dict) -> bool:
        value_lower = value.lower()
        context_lower = context.lower()

        for fp_pattern in self.FALSE_POSITIVE_PATTERNS:
            if fp_pattern.lower() in value_lower:
                return True

        for example_key, example_values in self.EXAMPLE_VALUES.items():
            for example in example_values:
                if example.lower() in value_lower:
                    return True

        if rule['type'] == SecretType.API_KEY:
            if 'example' in context_lower or 'demo' in context_lower:
                return True

        return False

    def _check_context(self, context_lower: str, context_patterns: List[str]) -> float:
        if not context_patterns:
            return 0.0

        matches = sum(1 for p in context_patterns if p.lower() in context_lower)
        return min(matches / len(context_patterns), 1.0)

    def _calculate_entropy(self, text: str) -> float:
        if not text:
            return 0.0

        import math
        freq = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1

        entropy = 0.0
        length = len(text)
        for count in freq.values():
            if count > 0:
                prob = count / length
                entropy -= prob * math.log2(prob)

        normalized = entropy / math.log2(length) if length > 1 else 0.0
        return normalized

    def _mask_value(self, value: str) -> str:
        if len(value) <= 8:
            return self.mask_char * len(value)
        return value[:4] + self.mask_char * (len(value) - 8) + value[-4:]

    def get_matches_by_risk(self, matches: List[SecretMatch], risk_level: RiskLevel) -> List[SecretMatch]:
        return [m for m in matches if m.risk_level == risk_level]

    def get_high_confidence_matches(self, matches: List[SecretMatch], threshold: float = 0.7) -> List[SecretMatch]:
        return [m for m in matches if m.confidence >= threshold and not m.is_likely_false_positive]


__all__ = ['SecretMatcher', 'SecretMatch', 'SecretType', 'RiskLevel']
