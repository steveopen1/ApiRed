"""
Sensitive Detector Module
两级敏感信息检测模块
"""

import re
import yaml
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class Severity(Enum):
    """严重程度"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SensitiveFinding:
    """敏感信息发现"""
    data_type: str
    matches: List[str]
    severity: Severity
    evidence: str
    context: str
    location: str
    detection_method: str
    confidence: float


class TwoTierSensitiveDetector:
    """两级敏感信息检测器"""
    
    TIER1_RULES = {
        'aws_access_key': {
            'pattern': r'(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}',
            'severity': Severity.CRITICAL,
            'examples': ['AKIAIOSFODNN7EXAMPLE']
        },
        'aws_secret_key': {
            'pattern': r'(?i)aws_secret_access_key\s*[:=]\s*[\'"]?[A-Za-z0-9/+=]{40}[\'"]?',
            'severity': Severity.CRITICAL,
            'examples': ['wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY']
        },
        'github_token': {
            'pattern': r'ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{22,}',
            'severity': Severity.HIGH,
            'examples': ['ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx']
        },
        'jwt_token': {
            'pattern': r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}={0,2}',
            'severity': Severity.MEDIUM,
            'examples': ['eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...']
        },
        'private_key': {
            'pattern': r'-----BEGIN [A-Z ]+PRIVATE KEY-----',
            'severity': Severity.CRITICAL,
            'examples': ['-----BEGIN RSA PRIVATE KEY-----']
        },
        'api_key': {
            'pattern': r'(?:api[_-]?key|apikey)\s*[:=]\s*[\'"]?[a-zA-Z0-9]{20,}[\'"]?',
            'severity': Severity.HIGH,
            'examples': ['AIzaSyDcFNF7xxxxxxxxxxxxxxx']
        },
        'password': {
            'pattern': r'(?i)(?:password|passwd|pwd)\s*[:=]\s*[\'"]?[^\'"]{4,100}[\'"]?',
            'severity': Severity.HIGH,
            'examples': ['password=admin123']
        },
        'username': {
            'pattern': r'(?i)(?:username|user|login)\s*[:=]\s*[\'"]?[a-zA-Z0-9_]{3,50}[\'"]?',
            'severity': Severity.MEDIUM,
            'examples': ['username=admin']
        },
        'internal_ip': {
            'pattern': r'(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}',
            'severity': Severity.LOW,
            'examples': ['192.168.1.1', '10.0.0.1']
        },
        'cloud_key': {
            'pattern': r'LTAI[a-zA-Z0-9]{12,20}|AKID[a-zA-Z0-9]{13,40}|JDC_[A-Z0-9]{25,}',
            'severity': Severity.HIGH,
            'examples': ['LTAIxxxxxxxxxxxxxxxxxx']
        },
        'database_connection': {
            'pattern': r'jdbc:[a-z]+://[^\s\'"]{10,}',
            'severity': Severity.CRITICAL,
            'examples': ['jdbc:mysql://localhost:3306/db']
        },
        'authorization_header': {
            'pattern': r'(?:bearer|basic)\s+[a-zA-Z0-9_=./+-]{10,}',
            'severity': Severity.MEDIUM,
            'examples': ['Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9']
        }
    }
    
    CLEAR_PATTERNS = [
        'unauthorized', 'not found', 'login required', 'invalid token',
        'session expired', 'access denied', 'forbidden'
    ]
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.tier1_rules = self.TIER1_RULES.copy()
        self._load_custom_rules()
        self.ai_enabled = self.config.get('ai_enabled', False)
        self.min_confidence = self.config.get('min_confidence', 0.8)
    
    def _load_custom_rules(self):
        """加载自定义规则"""
        import json
        import os
        from pathlib import Path
        
        custom_rules_path = Path(__file__).parent.parent.parent / 'config' / 'custom_sensitive_rules.json'
        
        if custom_rules_path.exists():
            try:
                with open(custom_rules_path, 'r', encoding='utf-8') as f:
                    custom_rules = json.load(f)
                
                for rule_name, rule_info in custom_rules.items():
                    if isinstance(rule_info, dict) and 'pattern' in rule_info:
                        self.tier1_rules[rule_name] = rule_info
                        
            except Exception as e:
                logger.warning(f"Failed to load custom rules: {e}")
        
        env_rules = os.environ.get('SENSITIVE_RULES')
        if env_rules:
            try:
                env_custom_rules = json.loads(env_rules)
                for rule_name, rule_info in env_custom_rules.items():
                    if isinstance(rule_info, dict) and 'pattern' in rule_info:
                        self.tier1_rules[rule_name] = rule_info
            except Exception as e:
                logger.warning(f"Failed to load custom rules: {e}")
    
    def tier1_scan(self, content: str, url: str = "") -> List[SensitiveFinding]:
        """第一层：正则扫描"""
        findings = []
        
        for rule_name, rule_info in self.tier1_rules.items():
            pattern = rule_info['pattern']
            matches = re.findall(pattern, content, re.IGNORECASE)
            
            if matches:
                context = self._extract_context(content, matches[0])
                
                finding = SensitiveFinding(
                    data_type=rule_name,
                    matches=matches[:10],
                    severity=rule_info['severity'],
                    evidence=matches[0][:100] if matches else '',
                    context=context,
                    location=url,
                    detection_method='regex',
                    confidence=0.95
                )
                findings.append(finding)
        
        return findings
    
    def _extract_context(self, content: str, match: str, window: int = 50) -> str:
        """提取匹配上下文"""
        start = max(0, content.find(match) - window)
        end = min(len(content), content.find(match) + len(match) + window)
        return content[start:end].strip()
    
    def _is_clear_response(self, content: str) -> bool:
        """判断是否是明确的认证错误等清晰响应"""
        content_lower = content.lower()
        for pattern in self.CLEAR_PATTERNS:
            if pattern in content_lower:
                return True
        return False
    
    def tier2_ai_scan(
        self,
        content: str,
        url: str,
        previous_findings: List[SensitiveFinding],
        ai_analyzer
    ) -> List[SensitiveFinding]:
        """第二层：AI辅助扫描"""
        if not self.ai_enabled or not ai_analyzer:
            return []
        
        candidates = []
        
        for finding in previous_findings:
            if finding.severity == Severity.MEDIUM and not finding.matches:
                candidates.append(finding)
        
        if not candidates:
            return []
        
        ai_results = ai_analyzer.analyze_sensitive(content, url)
        
        return ai_results
    
    def detect(
        self,
        responses: List[Dict],
        high_value_apis: set,
        ai_analyzer=None
    ) -> List[SensitiveFinding]:
        """两级检测入口"""
        all_findings = []
        
        for resp in responses:
            content = resp.get('content', '')
            url = resp.get('url', '')
            api_id = resp.get('api_id', '')
            
            if self._is_clear_response(content):
                continue
            
            tier1_results = self.tier1_scan(content, url)
            all_findings.extend(tier1_results)
            
            if self.ai_enabled and api_id in high_value_apis:
                tier2_results = self.tier2_ai_scan(
                    content, url, tier1_results, ai_analyzer
                )
                all_findings.extend(tier2_results)
        
        return all_findings
    
    def get_high_severity_findings(
        self,
        findings: List[SensitiveFinding]
    ) -> List[SensitiveFinding]:
        """获取高严重性发现"""
        return [
            f for f in findings
            if f.severity in (Severity.HIGH, Severity.CRITICAL)
        ]
    
    def to_dict(self, findings: List[SensitiveFinding]) -> List[Dict]:
        """导出为字典"""
        return [
            {
                'data_type': f.data_type,
                'matches': f.matches,
                'severity': f.severity.value,
                'evidence': f.evidence,
                'context': f.context,
                'location': f.location,
                'detection_method': f.detection_method,
                'confidence': f.confidence
            }
            for f in findings
        ]
