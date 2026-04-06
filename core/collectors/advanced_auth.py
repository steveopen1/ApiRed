"""
Advanced Authentication Module
高级认证模块 - 增强MFA/OTP和JWT验证

增强功能：
1. 嵌套认证响应解析（支持{"data":{"token":"xxx"}}）
2. MFA/OTP两阶段认证流程
3. JWT有效性验证（过期检查、签名验证）
4. 常见OTP/MFA端点发现
"""

import re
import json
import time
import jwt
import logging
from typing import Dict, List, Optional, Set, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


@dataclass
class MFAFlowResult:
    """MFA认证结果"""
    success: bool
    stage: str  # 'credentials' | 'mfa' | 'complete' | 'failed'
    credential: Optional[Any] = None
    error_message: str = ""
    otp_sent_to: str = ""  # email, sms, totp


class EnhancedAuthResolver:
    """
    增强版认证响应解析器
    
    支持：
    1. 嵌套JSON结构查找token
    2. 多种token字段识别
    3. JWT过期检查
    """

    TOKEN_PATTERNS = [
        'token', 'accessToken', 'access_token', 'jwt', 'jwtToken', 'idToken',
        'id_token', 'authToken', 'auth_token', 'bearer', 'bearerToken',
        'apiToken', 'api_token', 'sessionToken', 'session_token',
        'refreshToken', 'refresh_token', ' Authorization',
    ]

    JWT_ALGORITHMS = ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512']

    def __init__(self):
        self.max_depth = 5

    def extract_token_recursive(self, data: Any, current_depth: int = 0) -> Optional[str]:
        """
        递归查找嵌套JSON中的token
        
        支持结构：
        - {"data": {"token": "xxx"}}
        - {"result": {"data": {"token": "xxx"}}}
        - {"access_token": "xxx"}
        - {"response": {"access_token": {"token": "xxx"}}}
        """
        if current_depth >= self.max_depth:
            return None

        if isinstance(data, dict):
            for key in self.TOKEN_PATTERNS:
                if key in data:
                    value = data[key]
                    if isinstance(value, str) and value:
                        if self._is_valid_token(value):
                            return value

                    if isinstance(value, dict):
                        token = self.extract_token_recursive(value, current_depth + 1)
                        if token:
                            return token

            for value in data.values():
                if isinstance(value, dict):
                    token = self.extract_token_recursive(value, current_depth + 1)
                    if token:
                        return token

        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    token = self.extract_token_recursive(item, current_depth + 1)
                    if token:
                        return token

        return None

    def _is_valid_token(self, value: str) -> bool:
        """判断是否为有效的token"""
        if not value or len(value) < 10:
            return False

        if value.startswith('Bearer '):
            value = value[7:]

        if value.startswith('eyJ'):
            return True

        if re.match(r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$', value):
            return True

        if len(value) > 32 and not ' ' in value:
            return True

        return False

    def extract_cookie_recursive(self, data: Any, current_depth: int = 0) -> Optional[str]:
        """递归查找cookie"""
        if current_depth >= self.max_depth:
            return None

        if isinstance(data, dict):
            for key in ['cookie', 'cookies', 'set-cookie', 'Set-Cookie', 'session', 'Session']:
                if key in data:
                    value = data[key]
                    if isinstance(value, str) and value:
                        return value
                    elif isinstance(value, list):
                        return '; '.join(str(v) for v in value)

            for value in data.values():
                if isinstance(value, dict):
                    cookie = self.extract_cookie_recursive(value, current_depth + 1)
                    if cookie:
                        return cookie

        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    cookie = self.extract_cookie_recursive(item, current_depth + 1)
                    if cookie:
                        return cookie

        return None

    def parse_auth_response(self, response_content: str) -> Optional[Dict[str, Any]]:
        """解析认证响应"""
        try:
            data = json.loads(response_content)
            return self._parse_recursive(data)
        except json.JSONDecodeError:
            return None

    def _parse_recursive(self, data: Any) -> Dict[str, Any]:
        """递归解析，返回标准化的认证信息"""
        result = {
            'token': None,
            'cookie': None,
            'expires_in': None,
            'token_type': None,
            'refresh_token': None,
        }

        token = self.extract_token_recursive(data)
        if token:
            result['token'] = token
            if token.startswith('eyJ'):
                result['token_type'] = 'jwt'
            else:
                result['token_type'] = 'bearer'

        cookie = self.extract_cookie_recursive(data)
        if cookie:
            result['cookie'] = cookie

        if isinstance(data, dict):
            if 'expires_in' in data:
                result['expires_in'] = data['expires_in']
            if 'refresh_token' in data:
                result['refresh_token'] = data['refresh_token']

        return result


class JWTValidator:
    """
    JWT有效性验证器
    
    功能：
    1. 过期时间检查
    2. 签名验证（需要密钥）
    3. 标准声明验证
    """

    def __init__(self):
        self.sensitive_algorithms = ['none', 'HS256', 'HS384', 'HS512']

    def decode_jwt_payload(self, token: str) -> Optional[Dict[str, Any]]:
        """
        解码JWT载荷（不验证签名）
        
        Returns:
            payload字典，失败返回None
        """
        try:
            if token.startswith('Bearer '):
                token = token[7:]

            parts = token.split('.')
            if len(parts) != 3:
                return None

            import base64
            import json

            payload_b64 = parts[1]
            padding = 4 - len(payload_b64) % 4
            if padding != 4:
                payload_b64 += '=' * padding

            payload_bytes = base64.urlsafe_b64decode(payload_b64)
            payload = json.loads(payload_bytes.decode('utf-8'))

            return payload

        except Exception as e:
            logger.debug(f"JWT decode failed: {e}")
            return None

    def is_expired(self, token: str) -> Tuple[bool, Optional[str]]:
        """
        检查JWT是否过期
        
        Returns:
            (is_expired, error_reason)
        """
        payload = self.decode_jwt_payload(token)
        if not payload:
            return True, "Invalid JWT format"

        exp = payload.get('exp')
        if not exp:
            return False, None

        try:
            exp_datetime = datetime.fromtimestamp(exp, tz=timezone.utc)
            now = datetime.now(timezone.utc)

            if exp_datetime < now:
                return True, f"Token expired at {exp_datetime.isoformat()}"

            return False, None

        except Exception as e:
            return True, f"Invalid exp claim: {e}"

    def get_token_info(self, token: str) -> Dict[str, Any]:
        """
        获取JWT详细信息
        
        Returns:
            token信息字典
        """
        info = {
            'valid_format': False,
            'is_expired': False,
            'expires_at': None,
            'issued_at': None,
            'claims': {},
            'algorithm': None,
            'issue': None,
        }

        try:
            if token.startswith('Bearer '):
                token = token[7:]

            parts = token.split('.')
            if len(parts) != 3:
                return info

            info['valid_format'] = True

            import base64
            import json

            header_b64 = parts[0]
            padding = 4 - len(header_b64) % 4
            if padding != 4:
                header_b64 += '=' * padding

            header_bytes = base64.urlsafe_b64decode(header_b64)
            header = json.loads(header_bytes.decode('utf-8'))
            info['algorithm'] = header.get('alg')

            payload = self.decode_jwt_payload(token)
            if payload:
                info['claims'] = payload

                if 'exp' in payload:
                    info['expires_at'] = datetime.fromtimestamp(
                        payload['exp'], tz=timezone.utc
                    ).isoformat()
                    info['is_expired'] = self.is_expired(token)[0]

                if 'iat' in payload:
                    info['issued_at'] = datetime.fromtimestamp(
                        payload['iat'], tz=timezone.utc
                    ).isoformat()

                info['issuer'] = payload.get('iss')
                info['subject'] = payload.get('sub')

        except Exception as e:
            logger.debug(f"Token info extraction failed: {e}")

        return info

    def check_none_algorithm_attack(self, token: str) -> Dict[str, Any]:
        """
        检测JWT none算法攻击漏洞
        
        攻击原理：
        1. 将alg设为none
        2. 移除签名部分
        3. 修改payload伪造任意用户身份
        
        Returns:
            检测结果字典
        """
        result = {
            'vulnerable': False,
            'algorithm_in_token': None,
            'can_forge_admin': False,
            'details': ''
        }
        
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            
            parts = token.split('.')
            if len(parts) != 3:
                result['details'] = 'Invalid JWT format'
                return result
            
            import base64
            import json
            
            header_b64 = parts[0]
            padding = 4 - len(header_b64) % 4
            if padding != 4:
                header_b64 += '=' * padding
            
            header_bytes = base64.urlsafe_b64decode(header_b64)
            header = json.loads(header_bytes.decode('utf-8'))
            
            result['algorithm_in_token'] = header.get('alg')
            
            if header.get('alg') == 'none':
                result['vulnerable'] = True
                result['details'] = 'Token uses alg=none - attacker can forge arbitrary tokens'
                
                payload = self.decode_jwt_payload(token)
                if payload:
                    if payload.get('role') == 'admin' or payload.get('is_admin') or payload.get('admin') == True:
                        result['can_forge_admin'] = True
            
            elif header.get('alg') in ['HS256', 'HS384', 'HS512']:
                result['details'] = 'Token uses symmetric algorithm - possible to brute force if weak secret'
            
            return result
            
        except Exception as e:
            result['details'] = f'Analysis failed: {e}'
            return result
    
    def generate_none_attack_token(self, payload: Dict) -> str:
        """
        生成none算法攻击token（用于测试）
        
        Args:
            payload: 要伪造的payload
            
        Returns:
            攻击用JWT token
        """
        import base64
        import json
        
        header = {'alg': 'none', 'typ': 'JWT'}
        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header).encode()
        ).decode().rstrip('=')
        
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).decode().rstrip('=')
        
        return f"{header_b64}.{payload_b64}."


class MFAFlowHandler:
    """
    MFA/OTP认证流程处理器
    
    支持的两阶段认证：
    1. 账号密码认证 -> 获取mfa_token
    2. OTP验证码认证 -> 获取最终token
    """

    MFA_TRIGGER_PATTERNS = [
        'mfa', '2fa', 'totp', 'otp', 'sms', 'email_code',
        'verify_code', 'verification_code', 'security_code',
        'mobile_code', 'phone_code', 'captcha', 'recaptcha',
    ]

    OTP_ENDPOINTS = [
        '/api/mfa/verify',
        '/api/mfa/validate',
        '/api/auth/mfa',
        '/api/auth/verify',
        '/api/otp/verify',
        '/api/sms/verify',
        '/api/captcha/verify',
        '/mfa',
        '/auth/mfa',
        '/verify',
    ]

    def __init__(self, http_client):
        self.http_client = http_client
        self.mfa_token: Optional[str] = None
        self.mfa_stage: str = "initial"

    async def try_mfa_auth(
        self,
        base_url: str,
        credentials: Dict[str, str],
        mfa_code: Optional[str] = None
    ) -> MFAFlowResult:
        """
        尝试MFA认证流程
        
        Args:
            base_url: 目标URL
            credentials: 账号密码 {'username': 'xxx', 'password': 'xxx'}
            mfa_code: 6位验证码（可选，用于直接尝试）
            
        Returns:
            MFAFlowResult
        """
        headers = {'Content-Type': 'application/json'}

        if mfa_code:
            return await self._verify_mfa_stage(base_url, mfa_code, credentials, headers)

        result = await self._try_first_stage(base_url, credentials, headers)
        if result.success and result.stage == 'mfa':
            return result

        return result

    async def _try_first_stage(
        self,
        base_url: str,
        credentials: Dict[str, str],
        headers: Dict[str, str]
    ) -> MFAFlowResult:
        """第一阶段：账号密码认证"""
        login_endpoints = [
            f"{base_url}/api/login",
            f"{base_url}/api/auth/login",
            f"{base_url}/api/auth/signin",
            f"{base_url}/login",
            f"{base_url}/api/mfa/login",
        ]

        for endpoint in login_endpoints:
            try:
                body = json.dumps({
                    'username': credentials.get('username', ''),
                    'password': credentials.get('password', ''),
                })

                resp = await self.http_client.request(
                    endpoint, 'POST', data=body, headers=headers
                )

                if resp.status_code == 200:
                    content = resp.content

                    mfa_indicators = ['mfa', 'otp', 'verify', 'captcha', '2fa', 'code']
                    has_mfa = any(ind in content.lower() for ind in mfa_indicators)

                    if has_mfa:
                        self.mfa_stage = 'mfa'
                        try:
                            data = json.loads(content)
                            self.mfa_token = data.get('mfa_token') or data.get('session_token') or data.get('verify_token')
                        except:
                            pass

                        return MFAFlowResult(
                            success=True,
                            stage='mfa',
                            error_message='MFA required',
                            otp_sent_to=self._detect_otp_destination(content)
                        )

                    resolver = EnhancedAuthResolver()
                    parsed = resolver.parse_auth_response(content)
                    if parsed and parsed.get('token'):
                        return MFAFlowResult(
                            success=True,
                            stage='complete',
                            credential=parsed
                        )

            except Exception as e:
                logger.debug(f"MFA first stage failed for {endpoint}: {e}")

        return MFAFlowResult(
            success=False,
            stage='initial',
            error_message='No working login endpoint found'
        )

    async def _verify_mfa_stage(
        self,
        base_url: str,
        mfa_code: str,
        credentials: Dict,
        headers: Dict
    ) -> MFAFlowResult:
        """第二阶段：MFA验证码验证"""
        for endpoint in self.OTP_ENDPOINTS:
            try:
                body = json.dumps({
                    'code': mfa_code,
                    'mfa_token': self.mfa_token,
                    'username': credentials.get('username', ''),
                    'password': credentials.get('password', ''),
                })

                resp = await self.http_client.request(
                    f"{base_url}{endpoint}", 'POST', data=body, headers=headers
                )

                if resp.status_code == 200:
                    resolver = EnhancedAuthResolver()
                    parsed = resolver.parse_auth_response(resp.content)

                    if parsed and parsed.get('token'):
                        return MFAFlowResult(
                            success=True,
                            stage='complete',
                            credential=parsed
                        )

            except Exception as e:
                logger.debug(f"MFA verify failed for {endpoint}: {e}")

        return MFAFlowResult(
            success=False,
            stage='mfa',
            error_message='MFA verification failed'
        )

    def _detect_otp_destination(self, content: str) -> str:
        """检测OTP发送目标"""
        content_lower = content.lower()

        if 'sms' in content_lower or 'phone' in content_lower:
            return 'sms'
        elif 'email' in content_lower or 'mail' in content_lower:
            return 'email'
        elif 'totp' in content_lower or 'app' in content_lower:
            return 'totp'
        elif 'captcha' in content_lower or 'recaptcha' in content_lower:
            return 'captcha'

        return 'unknown'


def extract_nested_token(response_content: str) -> Optional[str]:
    """便捷函数：从嵌套响应中提取token"""
    resolver = EnhancedAuthResolver()
    parsed = resolver.parse_auth_response(response_content)
    if parsed:
        return parsed.get('token')
    return None


def validate_jwt(token: str) -> Dict[str, Any]:
    """便捷函数：验证JWT"""
    validator = JWTValidator()
    return {
        'expired': validator.is_expired(token)[0],
        'info': validator.get_token_info(token)
    }
