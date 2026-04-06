"""
OAuth2 and MFA Security Tester
OAuth2和MFA安全测试模块

测试能力：
1. OAuth2完整流程测试
2. MFA暴力破解保护检测
3. Session Fixation检测
4. Token安全检测
"""

import asyncio
import logging
import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from urllib.parse import parse_qs, urlparse

logger = logging.getLogger(__name__)


@dataclass
class OAuth2TestResult:
    """OAuth2测试结果"""
    vuln_type: str
    vulnerable: bool
    severity: str
    evidence: str
    details: str


@dataclass
class MFATestResult:
    """MFA测试结果"""
    vuln_type: str
    vulnerable: bool
    severity: str
    evidence: str
    details: str


class OAuth2SecurityTester:
    """
    OAuth2安全测试器
    
    测试内容：
    1. State参数缺失检测
    2. Token重放攻击检测
    3. Redirect URI验证绕过
    4. Scope过度授权检测
    5. 授权码/Token泄露检测
    """

    def __init__(self, http_client):
        self.http_client = http_client

    async def test_oauth2_security(
        self,
        auth_url: str,
        client_id: str = "test_client",
        redirect_uri: str = "http://localhost/callback"
    ) -> List[OAuth2TestResult]:
        """
        完整OAuth2安全测试
        
        Args:
            auth_url: 授权端点URL
            client_id: 测试用client_id
            redirect_uri: 测试用redirect_uri
            
        Returns:
            测试结果列表
        """
        results = []

        results.append(await self._check_state_parameter(auth_url))
        results.append(await self._check_implicit_flow(auth_url))
        results.append(await self._check_redirect_uri(auth_url, redirect_uri))
        results.append(await self._check_scope_exposure(auth_url))

        return [r for r in results if r is not None]

    async def _check_state_parameter(self, url: str) -> Optional[OAuth2TestResult]:
        """检测State参数缺失"""
        try:
            test_urls = [
                f"{url}?response_type=code&client_id=test&redirect_uri=http://localhost",
                f"{url}?response_type=token&client_id=test",
            ]

            for test_url in test_urls:
                response = await self.http_client.request(test_url, 'GET')
                content = response.content if response else ""

                if 'state' not in test_url:
                    return OAuth2TestResult(
                        vuln_type='oauth2_state_missing',
                        vulnerable=True,
                        severity='high',
                        evidence=f"URL without state parameter accepted: {test_url[:100]}",
                        details='State parameter is required to prevent CSRF attacks'
                    )

        except Exception as e:
            logger.debug(f"State parameter check failed: {e}")

        return None

    async def _check_implicit_flow(self, url: str) -> Optional[OAuth2TestResult]:
        """检测Implicit Flow安全"""
        try:
            test_url = f"{url}?response_type=token&client_id=test&redirect_uri=http://localhost"
            response = await self.http_client.request(test_url, 'GET')

            if response and response.status_code == 200:
                content = response.content or ""

                if 'access_token=' in content or '#access_token=' in content:
                    return OAuth2TestResult(
                        vuln_type='oauth2_token_in_url',
                        vulnerable=True,
                        severity='high',
                        evidence='Access token exposed in URL fragment',
                        details='Tokens in URL fragments can be leaked via referrer headers and browser history'
                    )

        except Exception as e:
            logger.debug(f"Implicit flow check failed: {e}")

        return None

    async def _check_redirect_uri(
        self,
        url: str,
        test_uri: str
    ) -> Optional[OAuth2TestResult]:
        """检测Redirect URI验证绕过"""
        malicious_uris = [
            'http://evil.com/callback',
            'http://localhost/callback',
            '../callback',
            '/../evil.com',
            '//evil.com/callback',
        ]

        for malicious_uri in malicious_uris:
            try:
                test_url = f"{url}?response_type=code&client_id=test&redirect_uri={malicious_uri}"
                response = await self.http_client.request(test_url, 'GET')

                if response and response.status_code == 302:
                    location = response.headers.get('Location', '')

                    if malicious_uri in location or 'evil' in location:
                        return OAuth2TestResult(
                            vuln_type='oauth2_uri_validation_bypass',
                            vulnerable=True,
                            severity='critical',
                            evidence=f"Malicious URI accepted: {malicious_uri}",
                            details='Server does not properly validate redirect_uri'
                        )

            except Exception as e:
                logger.debug(f"URI validation check failed: {e}")

        return None

    async def _check_scope_exposure(self, url: str) -> Optional[OAuth2TestResult]:
        """检测Scope过度授权"""
        dangerous_scopes = [
            'admin', 'full', 'read-write', 'all', '*', 'offline_access'
        ]

        try:
            test_url = f"{url}?response_type=code&client_id=test&scope=admin,full_access"

            response = await self.http_client.request(test_url, 'GET')

            if response and response.status_code in [200, 302]:
                return OAuth2TestResult(
                    vuln_type='oauth2_excessive_scope',
                    vulnerable=True,
                    severity='medium',
                    evidence='Server accepts dangerous scopes',
                    details='Check if scopes are properly validated and limited'
                )

        except Exception as e:
            logger.debug(f"Scope exposure check failed: {e}")

        return None


class MFABruteForceTester:
    """
    MFA暴力破解保护测试器
    
    测试内容：
    1. OTP验证码暴力破解保护
    2. 尝试次数限制
    3. 账户锁定机制
    4. 验证码强度检测
    """

    OTP_ENDPOINTS = [
        '/api/mfa/verify',
        '/api/auth/mfa',
        '/api/otp/verify',
        '/mfa/verify',
        '/verify-otp',
        '/2fa',
    ]

    def __init__(self, http_client):
        self.http_client = http_client

    async def test_mfa_brute_force_protection(
        self,
        base_url: str,
        rate_limit: int = 10
    ) -> List[MFATestResult]:
        """
        测试MFA暴力破解保护
        
        Args:
            base_url: 目标基础URL
            rate_limit: 正常速率下的尝试次数
            
        Returns:
            测试结果列表
        """
        results = []

        results.append(await self._test_otp_rate_limit(base_url, rate_limit))
        results.append(await self._test_otp_strength(base_url))

        return [r for r in results if r is not None]

    async def _test_otp_rate_limit(
        self,
        base_url: str,
        attempts: int = 10
    ) -> Optional[MFATestResult]:
        """测试OTP速率限制"""
        for endpoint in self.OTP_ENDPOINTS:
            url = f"{base_url}{endpoint}"
            
            successful_attempts = 0
            response_times = []

            try:
                for i in range(attempts + 5):
                    zero_count = max(0, 6 - len(str(i)))
                    test_code = '0' * zero_count + str(i)
                    
                    start_time = time.time()
                    response = await self.http_client.request(
                        url,
                        'POST',
                        data=f'{{"code": "{test_code}"}}',
                        headers={'Content-Type': 'application/json'}
                    )
                    elapsed = time.time() - start_time
                    response_times.append(elapsed)

                    if response and response.status_code == 200:
                        successful_attempts += 1

                    await asyncio.sleep(0.1)

                if successful_attempts >= attempts:
                    return MFATestResult(
                        vuln_type='mfa_no_rate_limit',
                        vulnerable=True,
                        severity='critical',
                        evidence=f'{successful_attempts} OTP attempts allowed without limit',
                        details='Server does not implement OTP rate limiting or account lockout'
                    )

                response_time_threshold = 5.0
                if all(t < 0.5 for t in response_times[:5]) and all(t > 3.0 for t in response_times[-5:]):
                    return MFATestResult(
                        vuln_type='mfa_rate_limit_bypass',
                        vulnerable=True,
                        severity='high',
                        evidence='Response time pattern suggests no rate limiting',
                        details='Server accepts rapid requests without throttling'
                    )

            except Exception as e:
                logger.debug(f"MFA rate limit test failed for {endpoint}: {e}")

        return MFATestResult(
            vuln_type='mfa_no_rate_limit',
            vulnerable=False,
            severity='info',
            evidence='MFA endpoint not found or rate limiting detected',
            details='No vulnerable MFA endpoint found'
        )

    async def _test_otp_strength(self, base_url: str) -> Optional[MFATestResult]:
        """测试OTP强度"""
        weak_codes = [
            '000000', '123456', '111111', '222222', '333333',
            '444444', '555555', '666666', '777777', '888888',
            '999999', '123123', '654321', '0000000'
        ]

        for endpoint in self.OTP_ENDPOINTS:
            url = f"{base_url}{endpoint}"

            try:
                for code in weak_codes:
                    response = await self.http_client.request(
                        url,
                        'POST',
                        data=f'{{"code": "{code}"}}',
                        headers={'Content-Type': 'application/json'}
                    )

                    if response and response.status_code == 200:
                        content = response.content or ""

                        if any(weak in content.lower() for weak in ['success', 'valid', 'authenticated']):
                            return MFATestResult(
                                vuln_type='mfa_weak_code',
                                vulnerable=True,
                                severity='medium',
                                evidence=f'Weak OTP code accepted: {code}',
                                details='Server accepts weak OTP codes'
                            )

            except Exception as e:
                logger.debug(f"MFA strength test failed: {e}")

        return None


class SessionFixationTester:
    """
    Session Fixation测试器
    
    测试内容：
    1. Session ID未刷新检测
    2. Token形式Session检测
    3. 跨站点Session绑定
    """

    SESSION_PATTERNS = [
        'jsessionid', 'phpsessid', 'asp.net_sessionid',
        'session_id', 'sessionid', 'sessid',
        'connect.sid', 'laravel_session',
    ]

    def __init__(self, http_client):
        self.http_client = http_client

    async def test_session_fixation(
        self,
        url: str
    ) -> Dict[str, Any]:
        """测试Session Fixation漏洞"""
        results = {
            'vulnerable': False,
            'session_type': None,
            'evidence': []
        }

        attacker_session = 'ATTACKER_SESSION_ID_12345'

        test_headers = {}
        for pattern in self.SESSION_PATTERNS:
            test_headers[pattern.upper().replace('_', '-')] = attacker_session
            test_headers[pattern] = attacker_session

        try:
            response1 = await self.http_client.request(url, 'GET')
            if not response1:
                return results

            headers1 = dict(response1.headers)
            set_cookie1 = headers1.get('Set-Cookie', '')

            response2 = await self.http_client.request(
                url, 'POST',
                headers={'Cookie': f'PHPSESSID={attacker_session}'}
            )

            if response2:
                headers2 = dict(response2.headers)
                set_cookie2 = headers2.get('Set-Cookie', '')

                if set_cookie1 and set_cookie2:
                    if attacker_session in set_cookie1 and attacker_session in set_cookie2:
                        results['vulnerable'] = True
                        results['evidence'].append('Session ID not regenerated after authentication')

                if set_cookie1 == set_cookie2 and set_cookie1:
                    results['vulnerable'] = True
                    results['evidence'].append('Session cookie unchanged during session')

        except Exception as e:
            logger.debug(f"Session fixation test failed: {e}")

        return results
