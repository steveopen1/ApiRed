"""
Security Configuration Detector
安全配置检测 - 检测缺失的安全响应头和 CORS 配置
"""

import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass


@dataclass
class SecurityFinding:
    """安全发现"""
    finding_type: str
    severity: str
    title: str
    description: str
    missing_items: List[str] = None
    recommendation: str = ""
    
    def __post_init__(self):
        if self.missing_items is None:
            self.missing_items = []


class SecurityHeadersDetector:
    """安全响应头检测器"""
    
    REQUIRED_HEADERS = {
        'x-frame-options': {
            'description': '防止点击劫持攻击',
            'expected_values': ['DENY', 'SAMEORIGIN'],
            'severity': 'medium'
        },
        'x-content-type-options': {
            'description': '防止 MIME 类型嗅探',
            'expected_values': ['nosniff'],
            'severity': 'low'
        },
        'x-xss-protection': {
            'description': 'XSS 过滤/保护',
            'expected_values': ['1', '1; mode=block', '0'],
            'severity': 'low'
        },
        'strict-transport-security': {
            'description': '强制 HTTPS 连接',
            'expected_values': None,
            'min_length': 10,
            'severity': 'high'
        },
        'content-security-policy': {
            'description': '内容安全策略',
            'expected_values': None,
            'severity': 'medium'
        },
        'referrer-policy': {
            'description': '引用来源策略',
            'expected_values': None,
            'severity': 'low'
        },
        'permissions-policy': {
            'description': '浏览器功能策略',
            'expected_values': None,
            'severity': 'low'
        }
    }
    
    OPTIONAL_HEADERS = {
        'server': {
            'description': '服务器版本信息',
            'severity': 'info'
        },
        'x-powered-by': {
            'description': '技术栈信息泄露',
            'severity': 'low'
        },
        'x-aspnet-version': {
            'description': 'ASP.NET 版本信息泄露',
            'severity': 'low'
        }
    }
    
    def detect(self, headers: Dict[str, str], url: str = "") -> List[SecurityFinding]:
        """
        检测安全响应头
        
        Args:
            headers: HTTP 响应头字典
            url: 请求的 URL
        
        Returns:
            安全发现列表
        """
        findings = []
        
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        for header, config in self.REQUIRED_HEADERS.items():
            if header not in headers_lower:
                findings.append(SecurityFinding(
                    finding_type='missing_security_header',
                    severity=config['severity'],
                    title=f"Missing Security Header: {header}",
                    description=f"缺少 {config['description']}",
                    missing_items=[header],
                    recommendation=f"建议添加 {header} 响应头"
                ))
            elif config.get('expected_values'):
                value = headers_lower[header].lower()
                if not any(v.lower() in value for v in config['expected_values'] if v):
                    findings.append(SecurityFinding(
                        finding_type='weak_security_header',
                        severity=config['severity'],
                        title=f"Weak Security Header: {header}",
                        description=f"{config['description']}，当前值: {headers_lower[header]}",
                        missing_items=[header],
                        recommendation=f"建议使用更安全的值: {', '.join(config['expected_values'])}"
                    ))
        
        for header, config in self.OPTIONAL_HEADERS.items():
            if header in headers_lower:
                findings.append(SecurityFinding(
                    finding_type='information_disclosure',
                    severity=config['severity'],
                    title=f"Information Disclosure: {header}",
                    description=f"{config['description']}: {headers_lower[header]}",
                    missing_items=[header],
                    recommendation="建议移除或模糊化此响应头"
                ))
        
        return findings


class CORSSecurityDetector:
    """CORS 安全检测器"""
    
    def detect(self, headers: Dict[str, str], url: str = "") -> List[SecurityFinding]:
        """
        检测 CORS 配置
        
        Args:
            headers: HTTP 响应头字典
            url: 请求的 URL
        
        Returns:
            安全发现列表
        """
        findings = []
        
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        access_control_allow_origin = headers_lower.get('access-control-allow-origin', '')
        access_control_allow_credentials = headers_lower.get('access-control-allow-credentials', '')
        access_control_allow_methods = headers_lower.get('access-control-allow-methods', '')
        access_control_allow_headers = headers_lower.get('access-control-allow-headers', '')
        
        if access_control_allow_origin == '*':
            findings.append(SecurityFinding(
                finding_type='cors_misconfiguration',
                severity='high',
                title='CORS: Wildcard Origin',
                description='Access-Control-Allow-Origin 设置为 *，允许所有来源访问',
                missing_items=['Access-Control-Allow-Origin'],
                recommendation='如果 API 不需要公开访问，建议限制为特定域名'
            ))
        
        if access_control_allow_origin != '' and access_control_allow_credentials.lower() == 'true':
            findings.append(SecurityFinding(
                finding_type='cors_misconfiguration',
                severity='high',
                title='CORS: Credentials with Wildcard Origin',
                description='同时设置了 * 和 Access-Control-Allow-Credentials: true，这会导致配置无效',
                missing_items=['Access-Control-Allow-Origin', 'Access-Control-Allow-Credentials'],
                recommendation='Access-Control-Allow-Credentials: true 不能与 * 一起使用'
            ))
        
        if access_control_allow_origin and not access_control_allow_methods:
            findings.append(SecurityFinding(
                finding_type='cors_incomplete_config',
                severity='low',
                title='CORS: Incomplete Configuration',
                description='设置了 Access-Control-Allow-Origin 但缺少 Access-Control-Allow-Methods',
                missing_items=['Access-Control-Allow-Methods'],
                recommendation='建议添加 Access-Control-Allow-Methods 明确允许的 HTTP 方法'
            ))
        
        if access_control_allow_origin and not access_control_allow_headers:
            findings.append(SecurityFinding(
                finding_type='cors_incomplete_config',
                severity='low',
                title='CORS: Incomplete Configuration',
                description='设置了 Access-Control-Allow-Origin 但缺少 Access-Control-Allow-Headers',
                missing_items=['Access-Control-Allow-Headers'],
                recommendation='建议添加 Access-Control-Allow-Headers 明确允许的请求头'
            ))
        
        return findings


class SecurityConfigDetector:
    """统一安全配置检测器"""
    
    def __init__(self):
        self.headers_detector = SecurityHeadersDetector()
        self.cors_detector = CORSSecurityDetector()
    
    def detect(self, headers: Dict[str, str], url: str = "") -> List[SecurityFinding]:
        """
        综合检测安全配置
        
        Args:
            headers: HTTP 响应头字典
            url: 请求的 URL
        
        Returns:
            所有安全发现列表
        """
        all_findings = []
        
        all_findings.extend(self.headers_detector.detect(headers, url))
        all_findings.extend(self.cors_detector.detect(headers, url))
        
        return all_findings
    
    def get_high_severity_findings(self, findings: List[SecurityFinding]) -> List[SecurityFinding]:
        """获取高严重性的发现"""
        return [f for f in findings if f.severity in ['high', 'critical']]
    
    def get_summary(self, findings: List[SecurityFinding]) -> Dict[str, Any]:
        """获取安全配置摘要"""
        summary = {
            'total': len(findings),
            'high': len([f for f in findings if f.severity == 'high']),
            'medium': len([f for f in findings if f.severity == 'medium']),
            'low': len([f for f in findings if f.severity == 'low']),
            'by_type': {}
        }
        
        for finding in findings:
            if finding.finding_type not in summary['by_type']:
                summary['by_type'][finding.finding_type] = 0
            summary['by_type'][finding.finding_type] += 1
        
        return summary


def detect_security_config(headers: Dict[str, str], url: str = "") -> List[SecurityFinding]:
    """
    便捷函数：检测安全配置
    
    Args:
        headers: HTTP 响应头字典
        url: 请求的 URL
    
    Returns:
        安全发现列表
    """
    detector = SecurityConfigDetector()
    return detector.detect(headers, url)
