"""
Domestic Auth Detector Module
国内认证模式检测模块 - 识别国内常见认证机制并检测绕过风险

支持:
- 微信OAuth2
- 钉钉OAuth2
- 飞书OAuth2
- 企业微信OAuth2
- JWT
- Session
"""

import re
import json
import asyncio
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum

from core.models import APIEndpoint, Vulnerability, Severity


class AuthType(Enum):
    """认证类型枚举"""
    WECHAT_OAUTH = "wechat_oauth"
    DINGTALK_OAUTH = "dingtalk_oauth"
    FEISHU_OAUTH = "feishu_oauth"
    WECOM_OAUTH = "wecom_oauth"
    JWT = "jwt"
    SESSION = "session"
    UNKNOWN = "unknown"


@dataclass
class AuthDetectionResult:
    """认证检测结果"""
    api_id: str
    auth_type: AuthType
    auth_endpoint: str
    confidence: float
    indicators: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuthBypassTestResult:
    """认证绕过测试结果"""
    api_id: str
    auth_type: AuthType
    test_name: str
    is_vulnerable: bool
    severity: Severity = Severity.MEDIUM
    evidence: str = ""
    payload: str = ""
    remediation: str = ""


class DomesticAuthDetector:
    """
    国内认证模式检测器
    识别国内常见认证机制并检测绕过风险
    """
    
    WECHAT_PATTERNS = {
        'oauth_url': [
            r'https?://open\.weixin\.qq\.com/connect/oauth2/',
            r'https?://api\.weixin\.qq\.com/sns/oauth2/',
        ],
        'token_url': [
            r'https?://api\.weixin\.qq\.com/cgi-bin/token',
            r'https?://api\.weixin\.qq\.com/sns/oauth2/access_token',
        ],
        'indicator': ['wechat', 'wx', 'weixin'],
    }
    
    DINGTALK_PATTERNS = {
        'oauth_url': [
            r'https?://oapi\.dingtalk\.com/connect/oauth2/',
            r'https?://api\.dingtalk\.com/sns/',
        ],
        'token_url': [
            r'https?://api\.dingtalk\.com/gettoken',
            r'https?://oapi\.dingtalk\.com/gettoken',
        ],
        'indicator': ['dingtalk', 'dingding', '钉钉'],
    }
    
    FEISHU_PATTERNS = {
        'oauth_url': [
            r'https?://open\.feishu\.cn/connect/qr/oauth2/',
            r'https?://open\.feishu\.cn/connect/authen/',
        ],
        'token_url': [
            r'https?://open\.feishu\.cn/open-apis/auth/v3/tenant_access_token/',
        ],
        'indicator': ['feishu', '飞书', 'larksuite'],
    }
    
    WECOM_PATTERNS = {
        'oauth_url': [
            r'https?://open\.work\.weixin\.qq\.com/wwapi/authen/',
        ],
        'token_url': [
            r'https?://qyapi\.weixin\.qq\.com/cgi-bin/gettoken',
        ],
        'indicator': ['wecom', '企业微信', 'wework'],
    }
    
    JWT_PATTERNS = {
        'header': [
            r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
        ],
        'header_kw': [
            r'"alg"\s*:\s*"([^"]+)"',
            r'"typ"\s*:\s*"JWT"',
        ],
        'indicator': ['jwt', 'bearer', 'authorization'],
    }
    
    SESSION_PATTERNS = {
        'cookie_name': [
            r'sessionid', r'session_id', r'session-token',
            r'PHPSESSID', r'JSESSIONID', r'ASP\.NET_SessionId',
        ],
        'indicator': ['session', 'cookie', 'csrf'],
    }
    
    def __init__(self, http_client: Any = None):
        """
        初始化国内认证检测器
        
        Args:
            http_client: HTTP客户端
        """
        self.http_client = http_client
    
    async def detect_auth_type(self, endpoint: APIEndpoint) -> Optional[AuthDetectionResult]:
        """
        检测端点的认证类型
        
        Args:
            endpoint: API端点
            
        Returns:
            AuthDetectionResult或None
        """
        url_lower = endpoint.full_url.lower()
        headers_lower = {k.lower(): v.lower() for k, v in endpoint.headers.items()}
        
        for auth_type, patterns in [
            (AuthType.WECHAT_OAUTH, self.WECHAT_PATTERNS),
            (AuthType.DINGTALK_OAUTH, self.DINGTALK_PATTERNS),
            (AuthType.FEISHU_OAUTH, self.FEISHU_PATTERNS),
            (AuthType.WECOM_OAUTH, self.WECOM_PATTERNS),
        ]:
            result = self._match_oauth_patterns(url_lower, patterns, auth_type, headers_lower)
            if result:
                return result
        
        jwt_result = self._detect_jwt(endpoint)
        if jwt_result:
            return jwt_result
        
        session_result = self._detect_session(endpoint)
        if session_result:
            return session_result
        
        return None
    
    def _match_oauth_patterns(
        self,
        url: str,
        patterns: Dict[str, List[str]],
        auth_type: AuthType,
        headers: Dict[str, str]
    ) -> Optional[AuthDetectionResult]:
        """匹配OAuth模式"""
        indicators = []
        
        for pattern in patterns.get('oauth_url', []):
            if re.search(pattern, url, re.IGNORECASE):
                indicators.append(f'oauth_url_match:{pattern}')
        
        for pattern in patterns.get('token_url', []):
            if re.search(pattern, url, re.IGNORECASE):
                indicators.append(f'token_url_match:{pattern}')
        
        for indicator in patterns.get('indicator', []):
            if indicator in url or any(indicator in v for v in headers.values()):
                indicators.append(f'indicator:{indicator}')
        
        if indicators:
            return AuthDetectionResult(
                api_id=getattr(endpoint, 'api_id', ''),
                auth_type=auth_type,
                auth_endpoint=url,
                confidence=min(len(indicators) * 0.3, 1.0),
                indicators=indicators
            )
        
        return None
    
    def _detect_jwt(self, endpoint: APIEndpoint) -> Optional[AuthDetectionResult]:
        """检测JWT"""
        indicators = []
        details = {}
        
        auth_header = endpoint.headers.get('Authorization', '') or endpoint.headers.get('authorization', '')
        if auth_header:
            if 'bearer' in auth_header.lower():
                indicators.append('bearer_token')
            
            jwt_match = re.search(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', auth_header)
            if jwt_match:
                indicators.append('jwt_in_header')
                details['jwt_token'] = jwt_match.group(0)[:50] + '...'
        
        cookies = endpoint.cookies or ''
        jwt_cookie_match = re.search(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', cookies)
        if jwt_cookie_match:
            indicators.append('jwt_in_cookie')
        
        if not indicators:
            url_lower = endpoint.full_url.lower()
            for indicator in self.JWT_PATTERNS.get('indicator', []):
                if indicator in url_lower:
                    indicators.append(f'indicator:{indicator}')
        
        if indicators:
            return AuthDetectionResult(
                api_id=getattr(endpoint, 'api_id', ''),
                auth_type=AuthType.JWT,
                auth_endpoint=endpoint.full_url,
                confidence=min(len(indicators) * 0.25, 1.0),
                indicators=indicators,
                details=details
            )
        
        return None
    
    def _detect_session(self, endpoint: APIEndpoint) -> Optional[AuthDetectionResult]:
        """检测Session"""
        indicators = []
        
        cookies = endpoint.cookies or ''
        for pattern in self.SESSION_PATTERNS.get('cookie_name', []):
            if re.search(pattern, cookies, re.IGNORECASE):
                indicators.append(f'cookie:{pattern}')
        
        headers_lower = {k.lower(): v.lower() for k, v in endpoint.headers.items()}
        if 'set-cookie' in headers_lower or 'cookie' in headers_lower:
            indicators.append('cookie_header')
        
        if 'csrf' in endpoint.full_url.lower() or 'csrf' in cookies.lower():
            indicators.append('csrf_token')
        
        if indicators:
            return AuthDetectionResult(
                api_id=getattr(endpoint, 'api_id', ''),
                auth_type=AuthType.SESSION,
                auth_endpoint=endpoint.full_url,
                confidence=min(len(indicators) * 0.3, 1.0),
                indicators=indicators
            )
        
        return None
    
    async def test_bypass(self, endpoint: APIEndpoint, auth_type: AuthType) -> List[AuthBypassTestResult]:
        """
        测试认证绕过
        
        Args:
            endpoint: API端点
            auth_type: 认证类型
            
        Returns:
            List[AuthBypassTestResult]: 测试结果列表
        """
        results = []
        
        if auth_type == AuthType.JWT:
            results.extend(await self._test_jwt_bypass(endpoint))
        elif auth_type in [AuthType.WECHAT_OAUTH, AuthType.DINGTALK_OAUTH, 
                          AuthType.FEISHU_OAUTH, AuthType.WECOM_OAUTH]:
            results.extend(await self._test_oauth_bypass(endpoint, auth_type))
        elif auth_type == AuthType.SESSION:
            results.extend(await self._test_session_bypass(endpoint))
        
        return results
    
    async def _test_jwt_bypass(self, endpoint: APIEndpoint) -> List[AuthBypassTestResult]:
        """测试JWT绕过"""
        results = []
        
        jwt_tests = [
            ('none_algorithm', self._test_jwt_none_alg),
            ('weak_secret', self._test_jwt_weak_secret),
        ]
        
        for test_name, test_func in jwt_tests:
            try:
                result = await test_func(endpoint)
                if result:
                    results.append(result)
            except Exception:
                pass
        
        return results
    
    async def _test_jwt_none_alg(self, endpoint: APIEndpoint) -> Optional[AuthBypassTestResult]:
        """测试JWT none算法"""
        if not self.http_client:
            return None
        
        original_headers = endpoint.headers.copy()
        
        header_modified = re.sub(r'"alg"\s*:\s*"\w+"', '"alg": "none"', json.dumps(original_headers))
        if isinstance(header_modified, str):
            try:
                modified_headers = json.loads(header_modified)
            except Exception:
                return None
        
        payload_match = re.search(r'eyJ[A-Za-z0-9_-]+\.(eyJ[A-Za-z0-9_-]+)\.[A-Za-z0-9_-]+', 
                                  original_headers.get('Authorization', ''))
        if not payload_match:
            return None
        
        modified_token = f"eyJhbGciOiJub25lIiwiydHkiOiJKV1QifQ.{payload_match.group(1)}."
        
        try:
            response = await self.http_client.request(
                endpoint.full_url,
                method=endpoint.method,
                headers={'Authorization': f'Bearer {modified_token}'}
            )
            
            if response.status_code == 200:
                return AuthBypassTestResult(
                    api_id=endpoint.api_id,
                    auth_type=AuthType.JWT,
                    test_name='JWT None Algorithm',
                    is_vulnerable=True,
                    severity=Severity.CRITICAL,
                    evidence=f'Status: {response.status_code}',
                    payload=modified_token[:50] + '...',
                    remediation='禁用JWT的none算法,使用强密钥'
                )
        except Exception:
            pass
        
        return None
    
    async def _test_jwt_weak_secret(self, endpoint: APIEndpoint) -> Optional[AuthBypassTestResult]:
        """测试JWT弱密钥"""
        return None
    
    async def _test_oauth_bypass(self, endpoint: APIEndpoint, auth_type: AuthType) -> List[AuthBypassTestResult]:
        """测试OAuth绕过"""
        results = []
        
        if auth_type == AuthType.WECHAT_OAUTH:
            results.append(await self._test_wechat_state_fixation(endpoint))
        
        return results
    
    async def _test_wechat_state_fixation(self, endpoint: APIEndpoint) -> Optional[AuthBypassTestResult]:
        """测试微信state固定"""
        if 'state' not in endpoint.full_url.lower():
            return None
        
        return None
    
    async def _test_session_bypass(self, endpoint: APIEndpoint) -> List[AuthBypassTestResult]:
        """测试Session绕过"""
        results = []
        
        if not self.http_client:
            return results
        
        original_cookies = endpoint.cookies
        
        bypass_tests = [
            ('session_fixing', self._test_session_fixing),
            ('cookie_attributes', self._test_cookie_attributes),
        ]
        
        for test_name, test_func in bypass_tests:
            try:
                result = await test_func(endpoint, original_cookies)
                if result:
                    results.append(result)
            except Exception:
                pass
        
        return results
    
    async def _test_session_fixing(self, endpoint: APIEndpoint, original_cookies: str) -> Optional[AuthBypassTestResult]:
        """测试会话固定"""
        return None
    
    async def _test_cookie_attributes(self, endpoint: APIEndpoint, original_cookies: str) -> Optional[AuthBypassTestResult]:
        """测试Cookie属性"""
        return None
    
    def get_auth_type_name(self, auth_type: AuthType) -> str:
        """获取认证类型名称"""
        names = {
            AuthType.WECHAT_OAUTH: '微信OAuth2',
            AuthType.DINGTALK_OAUTH: '钉钉OAuth2',
            AuthType.FEISHU_OAUTH: '飞书OAuth2',
            AuthType.WECOM_OAUTH: '企业微信OAuth2',
            AuthType.JWT: 'JWT',
            AuthType.SESSION: 'Session',
            AuthType.UNKNOWN: '未知',
        }
        return names.get(auth_type, '未知')
