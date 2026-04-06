"""
Enhanced CSRF Testing Module
增强CSRF测试模块

增强功能：
1. CSRF Token自动发现与提取
2. SameSite Cookie属性检测
3. Token验证机制检测
4. Double-Submit Cookie模式测试
5. Authorization Header vs Cookie对比
"""

import re
import logging
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class CSRFTestResult:
    """CSRF测试结果"""
    vulnerable: bool
    csrf_protection: str  # 'token', 'samesite', 'none', 'double_submit', 'header_auth'
    evidence: str
    token_name: Optional[str]
    token_found: bool
    samesite_detected: Optional[str]
    confidence: float  # 0.0 - 1.0


class EnhancedCSRFTester:
    """
    增强型CSRF测试器
    
    检测多种CSRF防护机制：
    1. Anti-CSRF Token (form字段)
    2. SameSite Cookie属性
    3. Authorization Header (Bearer/JSON)
    4. Double-Submit Cookie
    5. Custom Header检查
    """

    CSRF_TOKEN_PATTERNS = [
        r'<input[^>]+name=["\']?(?:csrf|xsrf|_token|csrf_token|xsrf_token)["\']?[^>]+value=["\']([^"\']+)["\']?',
        r'(?:csrf|xsrf|_token|csrf_token|xsrf_token)["\']?\s*:\s*["\']([^"\']+)["\']?',
        r'meta[^>]+name=["\']?(?:csrf|xsrf)["\']?[^>]+content=["\']([^"\']+)["\']?',
        r'window\.csrf\s*=\s*["\']([^"\']+)["\']?',
        r'window\.xsrf\s*=\s*["\']([^"\']+)["\']?',
    ]

    SENSITIVE_COOKIE_PATTERNS = [
        r'(?:session|token|auth|login|user|id)[^=]*=([^;]+)',
    ]

    CUSTOM_HEADER_PATTERNS = [
        'X-CSRF-Token',
        'X-XSRF-Token',
        'X-CSRFToken',
        'X-XSRFToken',
        'X-Requested-With',
        'X-Api-Token',
        'Authorization',
    ]

    def __init__(self, http_client):
        self.http_client = http_client
        self.results: List[CSRFTestResult] = []

    async def test_csrf_comprehensive(
        self,
        url: str,
        method: str = 'POST',
        form_data: Optional[Dict] = None,
        cookies: Optional[str] = None
    ) -> CSRFTestResult:
        """
        综合CSRF测试
        
        Args:
            url: 目标URL
            method: HTTP方法
            form_data: 表单数据
            cookies: Cookie字符串
            
        Returns:
            CSRFTestResult
        """
        result = CSRFTestResult(
            vulnerable=False,
            csrf_protection='unknown',
            evidence='',
            token_name=None,
            token_found=False,
            samesite_detected=None,
            confidence=0.0
        )

        try:
            page_resp = await self.http_client.request(url, 'GET', headers={'Cookie': cookies} if cookies else None)

            result = await self._check_samesite_cookie(url, cookies, result)

            if not result.token_found:
                result = await self._check_csrf_token_in_page(url, page_resp.content, result)

            result = await self._check_header_auth(url, method, form_data, result)

            result = await self._test_token_validation(url, method, form_data, cookies, result)

        except Exception as e:
            logger.debug(f"CSRF test failed: {e}")

        self.results.append(result)
        return result

    async def _check_samesite_cookie(
        self,
        url: str,
        cookies: Optional[str],
        result: CSRFTestResult
    ) -> CSRFTestResult:
        """检查SameSite Cookie属性"""
        try:
            resp = await self.http_client.request(url, 'GET')

            set_cookie_headers = []
            for header_name, header_value in resp.headers.items():
                if header_name.lower() in ['set-cookie', 'set-cookie2']:
                    set_cookie_headers.append(header_value)

            samesite_found = False
            for cookie_header in set_cookie_headers:
                cookie_upper = cookie_header.upper()
                if 'SAMESITE=STRICT' in cookie_upper:
                    result.samesite_detected = 'Strict'
                    result.csrf_protection = 'samesite'
                    result.evidence = 'SameSite=Strict cookie detected'
                    result.confidence = 0.8
                    samesite_found = True
                    break
                elif 'SAMESITE=LAX' in cookie_upper:
                    result.samesite_detected = 'Lax'
                    result.csrf_protection = 'samesite'
                    result.evidence = 'SameSite=Lax cookie detected'
                    result.confidence = 0.7
                    samesite_found = True
                    break

            if not samesite_found:
                for cookie_header in set_cookie_headers:
                    if '=' in cookie_header and 'EXPIRES' not in cookie_header.upper():
                        if 'SAMESITE' not in cookie_header.upper():
                            result.vulnerable = True
                            result.csrf_protection = 'none'
                            result.evidence = 'Cookie without SameSite attribute detected - CSRF possible'
                            result.confidence = 0.6
                            return result

        except Exception as e:
            logger.debug(f"SameSite check failed: {e}")

        return result

    async def _check_csrf_token_in_page(
        self,
        url: str,
        page_content: bytes,
        result: CSRFTestResult
    ) -> CSRFTestResult:
        """检查页面中是否存在CSRF Token"""
        try:
            content = page_content.decode('utf-8', errors='ignore')

            for pattern in self.CSRF_TOKEN_PATTERNS:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    result.token_found = True
                    result.token_name = self._extract_token_name(pattern)
                    result.evidence = f'CSRF token found in page (pattern: {result.token_name})'
                    result.confidence = max(result.confidence, 0.7)
                    break

            if not result.token_found:
                token_names = ['csrf', 'xsrf', '_token', 'csrf_token']
                for name in token_names:
                    if name in content.lower():
                        input_pattern = rf'<input[^>]+name=["\']?{name}["\']?[^>]+>'
                        if re.search(input_pattern, content, re.IGNORECASE):
                            result.token_found = True
                            result.token_name = name
                            result.evidence = f'Potential CSRF token field: {name}'
                            result.confidence = max(result.confidence, 0.5)
                            break

        except Exception as e:
            logger.debug(f"CSRF token check failed: {e}")

        return result

    async def _check_header_auth(
        self,
        url: str,
        method: str,
        form_data: Optional[Dict],
        result: CSRFTestResult
    ) -> CSRFTestResult:
        """检查是否使用Header认证"""
        try:
            test_headers = {
                'Authorization': 'Bearer test-token-12345',
                'X-Requested-With': 'XMLHttpRequest',
            }

            resp_with_header = await self.http_client.request(
                url, method,
                headers=test_headers,
                data=form_data
            )

            resp_without_header = await self.http_client.request(
                url, method,
                data=form_data
            )

            if resp_with_header.status_code != resp_without_header.status_code:
                result.csrf_protection = 'header_auth'
                result.evidence = 'Request with Authorization header processed differently'
                result.confidence = 0.75

        except Exception as e:
            logger.debug(f"Header auth check failed: {e}")

        return result

    async def _test_token_validation(
        self,
        url: str,
        method: str,
        form_data: Optional[Dict],
        cookies: Optional[str],
        result: CSRFTestResult
    ) -> CSRFTestResult:
        """测试Token验证机制"""
        if not result.token_found:
            return result

        try:
            headers_with_token = {
                'Cookie': cookies or '',
                result.token_name: 'valid-token-from-page'
            }

            headers_without_token = {
                'Cookie': cookies or '',
            }

            resp_with_token = await self.http_client.request(
                url, method,
                headers=headers_with_token,
                data=form_data
            )

            resp_without_token = await self.http_client.request(
                url, method,
                headers=headers_without_token,
                data=form_data
            )

            resp_no_auth = await self.http_client.request(
                url, method,
                data=form_data
            )

            if resp_no_auth.status_code == resp_without_token.status_code:
                if resp_no_auth.status_code != resp_with_token.status_code:
                    result.vulnerable = False
                    result.csrf_protection = 'token'
                    result.evidence = 'CSRF token is validated - requests without token are rejected'
                    result.confidence = 0.9
                else:
                    result.vulnerable = True
                    result.csrf_protection = 'token_but_invalidated'
                    result.evidence = 'CSRF token field exists but is not properly validated'
                    result.confidence = 0.8

        except Exception as e:
            logger.debug(f"Token validation test failed: {e}")

        return result

    def _extract_token_name(self, pattern: str) -> str:
        """从正则表达式中提取Token名称"""
        match = re.search(r'\(?\:([^)]+)\)?', pattern)
        if match:
            return match.group(1)
        return 'csrf_token'

    async def test_double_submit(
        self,
        url: str,
        cookies: Optional[str] = None
    ) -> CSRFTestResult:
        """测试Double-Submit Cookie模式"""
        result = CSRFTestResult(
            vulnerable=False,
            csrf_protection='double_submit',
            evidence='',
            token_name=None,
            token_found=True,
            samesite_detected=None,
            confidence=0.0
        )

        try:
            csrf_cookie = None
            for cookie_part in (cookies or '').split(';'):
                if 'csrf' in cookie_part.lower() or 'xsrf' in cookie_part.lower():
                    csrf_cookie = cookie_part.split('=')[-1].strip()
                    break

            if not csrf_cookie:
                result.vulnerable = True
                result.csrf_protection = 'none'
                result.evidence = 'No CSRF cookie found - double-submit pattern not implemented'
                result.confidence = 0.5
            else:
                result.evidence = f'CSRF cookie found: {csrf_cookie[:20]}...'
                result.confidence = 0.6

        except Exception as e:
            logger.debug(f"Double-submit test failed: {e}")

        return result


async def test_csrf(url: str, http_client, method: str = 'POST') -> CSRFTestResult:
    """便捷函数：测试CSRF"""
    tester = EnhancedCSRFTester(http_client)
    return await tester.test_csrf_comprehensive(url, method)
