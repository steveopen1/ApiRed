"""
Sensitive Data Sanitizer
敏感数据脱敏模块

功能：
1. 扫描结果中的敏感信息自动脱敏
2. 支持多种敏感类型：密码、Token、密钥、信用卡等
3. 可配置的脱敏规则
4. 保留可分析特征用于安全分析
"""

import re
import logging
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class SanitizationLevel(Enum):
    """脱敏级别"""
    NONE = "none"
    PARTIAL = "partial"
    FULL = "full"


@dataclass
class SanitizationRule:
    """脱敏规则"""
    name: str
    pattern: str
    replacement: str
    description: str


@dataclass
class SanitizedFinding:
    """脱敏后的发现"""
    original_value: str
    sanitized_value: str
    rule_applied: str
    preserved_pattern: Optional[str] = None


class SensitiveDataSanitizer:
    """
    敏感数据脱敏器
    
    支持的脱敏类型：
    1. 密码/密钥 - 完全隐藏
    2. Token/JWT - 部分显示
    3. 信用卡/身份证 - 保留格式
    4. IP地址 - 保留段
    5. 邮箱/手机 - 保留域/尾号
    """

    DEFAULT_RULES: List[SanitizationRule] = [
        # 密码类
        SanitizationRule(
            name="password",
            pattern=r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']?([^\s\'"]{4,100})["\']?',
            replacement=r'\1: ***REDACTED***',
            description="密码字段脱敏"
        ),
        # JWT Token
        SanitizationRule(
            name="jwt_token",
            pattern=r'(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9_-]{10,})',
            replacement=r'\1***TRUNCATED***',
            description="JWT Token脱敏"
        ),
        # AWS密钥
        SanitizationRule(
            name="aws_access_key",
            pattern=r'(AKIA[A-Z0-9]{16})',
            replacement=r'\1***TRUNCATED***',
            description="AWS Access Key脱敏"
        ),
        # GitHub Token
        SanitizationRule(
            name="github_token",
            pattern=r'(ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36})',
            replacement=r'\1***TRUNCATED***',
            description="GitHub Token脱敏"
        ),
        # Slack Token
        SanitizationRule(
            name="slack_token",
            pattern=r'(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,})',
            replacement=r'\1***TRUNCATED***',
            description="Slack Token脱敏"
        ),
        # 信用卡号
        SanitizationRule(
            name="credit_card",
            pattern=r'\b(\d{4})[\s-]?(\d{4})[\s-]?(\d{4})[\s-]?(\d{4})\b',
            replacement=r'\1*** *** **** \4',
            description="信用卡号脱敏"
        ),
        # 身份证号
        SanitizationRule(
            name="id_card",
            pattern=r'\b(\d{3})\d{11}(\d{3})\b',
            replacement=r'\1***********\2',
            description="身份证号脱敏"
        ),
        # API Key
        SanitizationRule(
            name="api_key",
            pattern=r'(?i)(api[_-]?key)\s*[:=]\s*["\']?([a-zA-Z0-9]{20,})["\']?',
            replacement=r'\1: ***REDACTED***',
            description="API Key脱敏"
        ),
        # 私钥
        SanitizationRule(
            name="private_key",
            pattern=r'(-----BEGIN [A-Z ]+PRIVATE KEY-----)[\s\S]*?(-----END [A-Z ]+PRIVATE KEY-----)',
            replacement=r'\1\n***REDACTED***\n\2',
            description="私钥脱敏"
        ),
        # Bearer Token
        SanitizationRule(
            name="bearer_token",
            pattern=r'(?i)(bearer\s+)([a-zA-Z0-9_=./+-]{20,})',
            replacement=r'\1***REDACTED***',
            description="Bearer Token脱敏"
        ),
        # 邮箱
        SanitizationRule(
            name="email",
            pattern=r'([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
            replacement=r'***@\2',
            description="邮箱脱敏(保留域名)"
        ),
        # 手机号
        SanitizationRule(
            name="phone",
            pattern=r'(\d{3})\d{4}(\d{4})',
            replacement=r'\1****\2',
            description="手机号脱敏"
        ),
        # IP地址
        SanitizationRule(
            name="ip_address",
            pattern=r'(\d{1,3}\.)(\d{1,3}\.)(\d{1,3}\.)(\d{1,3})',
            replacement=r'\1\2.***',
            description="IP地址脱敏(保留前两段)"
        ),
        # Authorization Header
        SanitizationRule(
            name="auth_header",
            pattern=r'(?i)(authorization)\s*:\s*[^\n]+',
            replacement=r'\1: ***REDACTED***',
            description="Authorization头脱敏"
        ),
        # Cookie
        SanitizationRule(
            name="cookie",
            pattern=r'(?i)(cookie)\s*:\s*[^\n]+',
            replacement=r'\1: ***REDACTED***',
            description="Cookie头脱敏"
        ),
        # 数据库连接字符串
        SanitizationRule(
            name="db_connection",
            pattern=r'(password|pwd)\s*=[^;\s]+',
            replacement=r'\1=***REDACTED***',
            description="数据库密码脱敏"
        ),
        # AWS Secret Key
        SanitizationRule(
            name="aws_secret",
            pattern=r'(?i)(aws_secret_access_key)\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?',
            replacement=r'\1: ***REDACTED***',
            description="AWS Secret Key脱敏"
        ),
    ]

    def __init__(self, level: SanitizationLevel = SanitizationLevel.PARTIAL):
        self.level = level
        self.rules = self.DEFAULT_RULES.copy()
        self._compile_patterns()

    def _compile_patterns(self):
        """编译所有正则表达式"""
        for rule in self.rules:
            try:
                rule.compiled_pattern = re.compile(rule.pattern)
            except re.error as e:
                logger.warning(f"Failed to compile pattern for {rule.name}: {e}")

    def sanitize_text(self, text: str) -> str:
        """
        对文本进行脱敏
        
        Args:
            text: 原始文本
            
        Returns:
            脱敏后的文本
        """
        if self.level == SanitizationLevel.NONE:
            return text

        sanitized = text
        for rule in self.rules:
            if hasattr(rule, 'compiled_pattern'):
                sanitized = rule.compiled_pattern.sub(rule.replacement, sanitized)

        return sanitized

    def sanitize_dict(self, data: Dict[str, Any], keys_to_sanitize: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        对字典进行脱敏
        
        Args:
            data: 原始字典
            keys_to_sanitize: 指定需要脱敏的键名列表
            
        Returns:
            脱敏后的字典
        """
        if self.level == SanitizationLevel.NONE or not data:
            return data

        sanitized = {}
        sensitive_keys = {
            'password', 'passwd', 'pwd', 'token', 'jwt', 'bearer',
            'secret', 'private', 'key', 'api_key', 'apikey',
            'auth', 'credential', 'session', 'cookie', 'authorization',
            'access_token', 'refresh_token', 'csrf_token',
            'x_csrf_token', 'x-xsrf-token',
        }

        for key, value in data.items():
            if keys_to_sanitize:
                should_sanitize = key.lower() in [k.lower() for k in keys_to_sanitize]
            else:
                should_sanitize = key.lower() in sensitive_keys

            if should_sanitize:
                if isinstance(value, str):
                    sanitized[key] = self.sanitize_text(value)
                elif isinstance(value, dict):
                    sanitized[key] = self.sanitize_dict(value)
                elif isinstance(value, list):
                    sanitized[key] = [self.sanitize_text(str(v)) for v in value]
                else:
                    sanitized[key] = value
            else:
                sanitized[key] = value

        return sanitized

    def sanitize_finding(self, finding: Any) -> Any:
        """
        对扫描结果进行脱敏
        
        支持多种发现类型：
        - dict
        - dataclass
        - 自定义对象
        
        Returns:
            脱敏后的发现
        """
        if self.level == SanitizationLevel.NONE:
            return finding

        if isinstance(finding, dict):
            return self.sanitize_dict(finding)

        if hasattr(finding, '__dict__'):
            obj_dict = finding.__dict__.copy()
            sensitive_fields = {
                'value', 'token', 'payload', 'evidence', 'raw_data',
                'password', 'secret', 'key', 'auth', 'credential'
            }

            for field in sensitive_fields:
                if field in obj_dict and obj_dict[field]:
                    if isinstance(obj_dict[field], str):
                        obj_dict[field] = self.sanitize_text(obj_dict[field])

            return obj_dict

        return finding

    def add_rule(self, rule: SanitizationRule):
        """添加自定义脱敏规则"""
        try:
            rule.compiled_pattern = re.compile(rule.pattern)
            self.rules.append(rule)
            logger.info(f"Added sanitization rule: {rule.name}")
        except re.error as e:
            logger.error(f"Failed to add rule {rule.name}: {e}")

    def remove_rule(self, name: str) -> bool:
        """移除脱敏规则"""
        for i, rule in enumerate(self.rules):
            if rule.name == name:
                self.rules.pop(i)
                logger.info(f"Removed sanitization rule: {name}")
                return True
        return False

    def set_level(self, level: SanitizationLevel):
        """设置脱敏级别"""
        self.level = level
        logger.info(f"Sanitization level set to: {level.value}")

    def get_statistics(self) -> Dict[str, Any]:
        """获取脱敏统计"""
        return {
            'level': self.level.value,
            'rules_count': len(self.rules),
            'rules': [r.name for r in self.rules]
        }


class ScanResultSanitizer:
    """
    扫描结果脱敏器
    
    对整个扫描结果进行批量脱敏处理
    """

    def __init__(self, level: SanitizationLevel = SanitizationLevel.PARTIAL):
        self.sanitizer = SensitiveDataSanitizer(level)

    def sanitize_scan_result(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """对扫描结果进行脱敏"""
        sanitized = result.copy()

        if 'vulnerabilities' in sanitized:
            sanitized['vulnerabilities'] = [
                self.sanitizer.sanitize_finding(v)
                for v in sanitized['vulnerabilities']
            ]

        if 'sensitive_findings' in sanitized:
            sanitized['sensitive_findings'] = [
                self.sanitizer.sanitize_finding(f)
                for f in sanitized['sensitive_findings']
            ]

        if 'endpoints' in sanitized:
            sanitized['endpoints'] = [
                self.sanitizer.sanitize_dict(e) if isinstance(e, dict) else e
                for e in sanitized['endpoints']
            ]

        if 'metadata' in sanitized:
            sanitized['metadata'] = self.sanitizer.sanitize_dict(sanitized['metadata'])

        sanitized['_sanitization_applied'] = True
        sanitized['_sanitization_level'] = self.sanitizer.level.value

        return sanitized


def create_sanitizer(level: str = 'partial') -> SensitiveDataSanitizer:
    """创建脱敏器"""
    level_map = {
        'none': SanitizationLevel.NONE,
        'partial': SanitizationLevel.PARTIAL,
        'full': SanitizationLevel.FULL,
    }
    return SensitiveDataSanitizer(level_map.get(level, SanitizationLevel.PARTIAL))
