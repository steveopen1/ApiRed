"""
API Security Posture Module
API 安全态势评估模块

功能:
1. API 暴露面评分
2. 安全配置检查
3. 认证/授权覆盖率分析
4. 风险评分和修复建议

参考: Akto API Security Posture
"""

import re
import logging
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)


class PostureCategory(Enum):
    """态势评估类别"""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    RATE_LIMITING = "rate_limiting"
    DATA_EXPOSURE = "data_exposure"
    ENCRYPTION = "encryption"
    SECURITY_HEADERS = "security_headers"
    API_INVENTORY = "api_inventory"
    VULNERABILITY = "vulnerability"


class SecurityLevel(Enum):
    """安全等级"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class PostureScore:
    """态势评分"""
    category: PostureCategory
    score: float  # 0-100
    level: SecurityLevel
    findings: List[Dict[str, Any]]
    recommendations: List[str]


@dataclass
class APIEndpointInfo:
    """API 端点信息"""
    path: str
    method: str
    has_auth: bool
    has_rate_limit: bool
    has_input_validation: bool
    is_sensitive: bool
    response_has_sensitive_data: bool
    security_headers_present: bool


class SecurityPostureAnalyzer:
    """
    API 安全态势分析器
    
    评估维度:
    1. 认证覆盖 (Authentication Coverage)
    2. 授权控制 (Authorization Controls)
    3. 速率限制 (Rate Limiting)
    4. 数据暴露 (Data Exposure)
    5. 传输加密 (Encryption in Transit)
    6. 安全响应头 (Security Headers)
    7. API 清单 (API Inventory)
    8. 漏洞存在 (Vulnerability Presence)
    """

    AUTH_REQUIRED_PATTERNS = [
        r'/auth', r'/login', r'/logout', r'/register', r'/signup',
        r'/user', r'/account', r'/profile', r'/password', r'/token',
        r'/oauth', r'/saml', r'/cas', r'/session',
        r'/admin', r'/manage', r'/dashboard', r'/console',
    ]

    SENSITIVE_DATA_PATTERNS = [
        r'password', r'secret', r'key', r'token', r'credential',
        r'ssn', r'credit_card', r'cvv', r'pin',
        r'api_key', r'api_secret', r'access_token',
    ]

    SENSITIVE_ENDPOINT_PATTERNS = [
        r'/admin', r'/user/(\d+)', r'/order/(\d+)', r'/account',
        r'/finance', r'/payment', r'/transaction', r'/invoice',
        r'/config', r'/settings', r'/secret', r'/private',
        r'/internal', r'/debug', r'/actuator',
    ]

    SECURITY_HEADER_REQUIRED = [
        'X-Content-Type-Options',
        'X-Frame-Options',
        'Strict-Transport-Security',
        'Content-Security-Policy',
        'X-XSS-Protection',
    ]

    RATE_LIMIT_PATTERNS = [
        r'rate.*limit', r'too.*many.*request', r'429',
        r'x-ratelimit', r'x-rate-limit',
        r'retry-after', r'quota.*exceeded',
    ]

    def __init__(self):
        self.endpoint_info: List[APIEndpointInfo] = []
        self.posture_scores: Dict[PostureCategory, PostureScore] = {}

    def analyze_endpoints(self, endpoints: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        分析 API 端点安全态势
        
        Args:
            endpoints: API 端点列表
            
        Returns:
            态势评估结果
        """
        self.endpoint_info = []
        
        for ep in endpoints:
            info = self._analyze_single_endpoint(ep)
            self.endpoint_info.append(info)
        
        self._calculate_posture_scores()
        
        return self._generate_posture_report()

    def _analyze_single_endpoint(self, endpoint: Dict[str, Any]) -> APIEndpointInfo:
        """分析单个端点"""
        path = endpoint.get('path', endpoint.get('url', ''))
        method = endpoint.get('method', 'GET').upper()
        
        return APIEndpointInfo(
            path=path,
            method=method,
            has_auth=self._requires_auth(path),
            has_rate_limit=self._has_rate_limit_indicator(endpoint),
            has_input_validation=self._has_input_validation(endpoint),
            is_sensitive=self._is_sensitive_endpoint(path),
            response_has_sensitive_data=self._has_sensitive_response(endpoint),
            security_headers_present=self._has_security_headers(endpoint),
        )

    def _requires_auth(self, path: str) -> bool:
        """判断端点是否需要认证"""
        path_lower = path.lower()
        for pattern in self.AUTH_REQUIRED_PATTERNS:
            if re.search(pattern, path_lower):
                return True
        return False

    def _has_rate_limit_indicator(self, endpoint: Dict[str, Any]) -> bool:
        """判断是否有速率限制"""
        headers = endpoint.get('headers', {})
        response = endpoint.get('response', {})
        
        headers_text = str(headers).lower()
        response_text = str(response).lower()
        
        for pattern in self.RATE_LIMIT_PATTERNS:
            if re.search(pattern, headers_text) or re.search(pattern, response_text):
                return True
        return False

    def _has_input_validation(self, endpoint: Dict[str, Any]) -> bool:
        """判断是否有输入验证"""
        params = endpoint.get('parameters', endpoint.get('params', []))
        return len(params) > 0

    def _is_sensitive_endpoint(self, path: str) -> bool:
        """判断是否为敏感端点"""
        path_lower = path.lower()
        for pattern in self.SENSITIVE_ENDPOINT_PATTERNS:
            if re.search(pattern, path_lower):
                return True
        return False

    def _has_sensitive_response(self, endpoint: Dict[str, Any]) -> bool:
        """判断响应是否包含敏感数据"""
        response = endpoint.get('response', endpoint.get('content', ''))
        if isinstance(response, dict):
            response = str(response)
        
        response_lower = response.lower()
        for pattern in self.SENSITIVE_DATA_PATTERNS:
            if re.search(pattern, response_lower):
                return True
        return False

    def _has_security_headers(self, endpoint: Dict[str, Any]) -> bool:
        """判断是否有安全响应头"""
        headers = endpoint.get('headers', {})
        if isinstance(headers, dict):
            header_names = set(k.lower() for k in headers.keys())
            for required in self.SECURITY_HEADER_REQUIRED:
                if required.lower() in header_names:
                    return True
        return False

    def _calculate_posture_scores(self):
        """计算各维度安全评分"""
        total_endpoints = len(self.endpoint_info)
        if total_endpoints == 0:
            return

        auth_covered = sum(1 for ep in self.endpoint_info if ep.has_auth)
        rate_limited = sum(1 for ep in self.endpoint_info if ep.has_rate_limit)
        input_validated = sum(1 for ep in self.endpoint_info if ep.has_input_validation)
        sensitive_with_protection = sum(
            1 for ep in self.endpoint_info 
            if ep.is_sensitive and ep.has_auth and ep.has_rate_limit
        )
        security_headers_covered = sum(1 for ep in self.endpoint_info if ep.security_headers_present)

        self.posture_scores = {
            PostureCategory.AUTHENTICATION: self._make_score(
                PostureCategory.AUTHENTICATION,
                (auth_covered / total_endpoints) * 100,
                [
                    f"Authentication covered: {auth_covered}/{total_endpoints}"
                ],
                [
                    "Implement authentication for all sensitive endpoints",
                    "Use OAuth 2.0 or JWT for API authentication",
                ]
            ),
            PostureCategory.RATE_LIMITING: self._make_score(
                PostureCategory.RATE_LIMITING,
                (rate_limited / total_endpoints) * 100,
                [
                    f"Rate limiting covered: {rate_limited}/{total_endpoints}"
                ],
                [
                    "Implement rate limiting for all endpoints",
                    "Use Redis or similar for distributed rate limiting",
                ]
            ),
            PostureCategory.DATA_EXPOSURE: self._make_score(
                PostureCategory.DATA_EXPOSURE,
                ((total_endpoints - sum(1 for ep in self.endpoint_info if ep.response_has_sensitive_data)) / total_endpoints) * 100,
                [
                    f"Endpoints with sensitive data: {sum(1 for ep in self.endpoint_info if ep.response_has_sensitive_data)}"
                ],
                [
                    "Implement field-level encryption for sensitive data",
                    "Use data masking for logs and responses",
                ]
            ),
            PostureCategory.SECURITY_HEADERS: self._make_score(
                PostureCategory.SECURITY_HEADERS,
                (security_headers_covered / total_endpoints) * 100,
                [
                    f"Security headers covered: {security_headers_covered}/{total_endpoints}"
                ],
                [
                    "Add all required security headers",
                    "Implement HSTS, CSP, and X-Frame-Options",
                ]
            ),
        }

    def _make_score(
        self, 
        category: PostureCategory, 
        score: float,
        findings: List[str],
        recommendations: List[str]
    ) -> PostureScore:
        """创建评分对象"""
        if score >= 80:
            level = SecurityLevel.INFO
        elif score >= 60:
            level = SecurityLevel.LOW
        elif score >= 40:
            level = SecurityLevel.MEDIUM
        elif score >= 20:
            level = SecurityLevel.HIGH
        else:
            level = SecurityLevel.CRITICAL
        
        return PostureScore(
            category=category,
            score=score,
            level=level,
            findings=[{'finding': f} for f in findings],
            recommendations=recommendations
        )

    def _generate_posture_report(self) -> Dict[str, Any]:
        """生成态势评估报告"""
        overall_score = 0
        if self.posture_scores:
            overall_score = sum(s.score for s in self.posture_scores.values()) / len(self.posture_scores)
        
        critical_issues = []
        high_issues = []
        medium_issues = []
        
        for category, score in self.posture_scores.items():
            if score.level == SecurityLevel.CRITICAL:
                critical_issues.extend(score.findings)
                critical_issues.extend([{'recommendation': r} for r in score.recommendations])
            elif score.level == SecurityLevel.HIGH:
                high_issues.extend(score.findings)
                high_issues.extend([{'recommendation': r} for r in score.recommendations])
            elif score.level == SecurityLevel.MEDIUM:
                medium_issues.extend(score.findings)
        
        return {
            'overall_score': round(overall_score, 2),
            'security_level': self._get_overall_level(overall_score),
            'endpoint_count': len(self.endpoint_info),
            'category_scores': {
                category.value: {
                    'score': round(score.score, 2),
                    'level': score.level.value,
                    'findings': score.findings,
                    'recommendations': score.recommendations,
                }
                for category, score in self.posture_scores.items()
            },
            'critical_issues': critical_issues,
            'high_issues': high_issues,
            'medium_issues': medium_issues,
            'summary': self._generate_summary(overall_score),
        }

    def _get_overall_level(self, score: float) -> str:
        """获取整体安全等级"""
        if score >= 80:
            return "SECURE"
        elif score >= 60:
            return "LOW_RISK"
        elif score >= 40:
            return "MEDIUM_RISK"
        elif score >= 20:
            return "HIGH_RISK"
        else:
            return "CRITICAL_RISK"

    def _generate_summary(self, score: float) -> str:
        """生成安全态势摘要"""
        if score >= 80:
            return "API security posture is strong. Continue monitoring and maintaining security controls."
        elif score >= 60:
            return "API security posture is acceptable. Some improvements recommended."
        elif score >= 40:
            return "API security posture needs improvement. Address high-priority issues."
        else:
            return "API security posture is critical. Immediate action required."


class APICoverageAnalyzer:
    """
    API 覆盖率分析器
    
    分析:
    1. 已发现 vs 未发现端点
    2. 已测试 vs 未测试端点
    3. 高价值端点覆盖率
    """

    HIGH_VALUE_PATTERNS = [
        r'/auth', r'/login', r'/user', r'/admin',
        r'/order', r'/payment', r'/transaction',
        r'/config', r'/secret', r'/key',
        r'/oauth', r'/token', r'/session',
        r'/profile', r'/account',
    ]

    def __init__(self):
        self.discovered_endpoints: Set[str] = set()
        self.tested_endpoints: Set[str] = set()
        self.vulnerable_endpoints: Set[str] = set()

    def add_discovered(self, path: str, method: str = "GET"):
        """添加已发现的端点"""
        key = f"{method.upper()}:{path}"
        self.discovered_endpoints.add(key)

    def add_tested(self, path: str, method: str = "GET"):
        """添加已测试的端点"""
        key = f"{method.upper()}:{path}"
        self.tested_endpoints.add(key)

    def add_vulnerable(self, path: str, method: str = "GET"):
        """添加有漏洞的端点"""
        key = f"{method.upper()}:{path}"
        self.vulnerable_endpoints.add(key)

    def get_coverage_report(self) -> Dict[str, Any]:
        """获取覆盖率报告"""
        all_endpoints = self.discovered_endpoints | self.tested_endpoints
        high_value_discovered = {
            ep for ep in all_endpoints
            if any(re.search(p, ep.lower()) for p in self.HIGH_VALUE_PATTERNS)
        }
        high_value_tested = high_value_discovered & self.tested_endpoints

        return {
            'total_discovered': len(self.discovered_endpoints),
            'total_tested': len(self.tested_endpoints),
            'discovery_coverage': len(self.tested_endpoints) / len(all_endpoints) * 100 if all_endpoints else 0,
            'high_value_endpoints': {
                'discovered': len(high_value_discovered),
                'tested': len(high_value_tested),
                'coverage': len(high_value_tested) / len(high_value_discovered) * 100 if high_value_discovered else 0,
            },
            'vulnerability_rate': len(self.vulnerable_endpoints) / len(self.tested_endpoints) * 100 if self.tested_endpoints else 0,
            'endpoints': {
                'discovered': list(self.discovered_endpoints),
                'tested': list(self.tested_endpoints),
                'vulnerable': list(self.vulnerable_endpoints),
            }
        }


def analyze_security_posture(
    endpoints: List[Dict[str, Any]],
    vulnerabilities: List[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    便捷函数: 分析 API 安全态势
    
    Args:
        endpoints: API 端点列表
        vulnerabilities: 已发现的漏洞列表
        
    Returns:
        安全态势评估报告
    """
    posture_analyzer = SecurityPostureAnalyzer()
    coverage_analyzer = APICoverageAnalyzer()
    
    for ep in endpoints:
        path = ep.get('path', ep.get('url', ''))
        method = ep.get('method', 'GET')
        coverage_analyzer.add_discovered(path, method)
        coverage_analyzer.add_tested(path, method)
    
    if vulnerabilities:
        for vuln in vulnerabilities:
            path = vuln.get('path', vuln.get('url', ''))
            method = vuln.get('method', 'GET')
            coverage_analyzer.add_vulnerable(path, method)
    
    posture_report = posture_analyzer.analyze_endpoints(endpoints)
    coverage_report = coverage_analyzer.get_coverage_report()
    
    return {
        'security_posture': posture_report,
        'coverage': coverage_report,
        'risk_score': calculate_risk_score(posture_report, coverage_report),
    }


def calculate_risk_score(
    posture_report: Dict[str, Any],
    coverage_report: Dict[str, Any]
) -> Dict[str, Any]:
    """计算综合风险评分"""
    posture_score = posture_report.get('overall_score', 0)
    vuln_rate = coverage_report.get('vulnerability_rate', 0)
    coverage_score = coverage_report.get('discovery_coverage', 0)
    
    risk_score = (
        (100 - posture_score) * 0.4 +
        vuln_rate * 0.4 +
        (100 - coverage_score) * 0.2
    )
    
    if risk_score >= 75:
        risk_level = "CRITICAL"
    elif risk_score >= 50:
        risk_level = "HIGH"
    elif risk_score >= 25:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"
    
    return {
        'score': round(risk_score, 2),
        'level': risk_level,
        'components': {
            'posture_score': posture_score,
            'vulnerability_rate': vuln_rate,
            'coverage_score': coverage_score,
        }
    }


if __name__ == "__main__":
    print("API Security Posture Analyzer")
    analyzer = SecurityPostureAnalyzer()
    report = analyzer.analyze_endpoints([])
    print(f"Overall Score: {report['overall_score']}")
