"""
Auto Auth Module - 自动化认证模块
从 JS 中提取认证信息，自动发现登录接口，执行认证
"""

import re
import json
import asyncio
import logging
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class AuthType(Enum):
    """认证类型"""
    NONE = "none"
    BEARER_TOKEN = "bearer_token"
    JWT = "jwt"
    BASIC_AUTH = "basic_auth"
    API_KEY = "api_key"
    COOKIE_SESSION = "cookie_session"
    MOBILE_OTP = "mobile_otp"


@dataclass
class AuthCredential:
    """认证凭据"""
    auth_type: AuthType = AuthType.NONE
    token: str = ""
    username: str = ""
    password: str = ""
    mobile: str = ""
    cookie: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    source: str = ""


@dataclass
class LoginEndpoint:
    """登录接口"""
    path: str
    method: str = "POST"
    param_names: List[str] = field(default_factory=list)
    param_types: Dict[str, str] = field(default_factory=dict)
    body_template: Dict[str, Any] = field(default_factory=dict)
    source: str = ""


class AuthInfoExtractor:
    """
    从 JavaScript 代码中提取认证信息
    支持提取：
    1. JWT Token
    2. 用户名/手机号
    3. 密码（测试账号）
    4. 登录接口
    5. API Key
    """
    
    LOGIN_PATH_PATTERNS = [
        r'''["\']([/a-zA-Z0-9_-]*login[/a-zA-Z0-9_-]*)["\']''',
        r'''["\']([/a-zA-Z0-9_-]*auth[/a-zA-Z0-9_-]*)["\']''',
        r'''["\']([/a-zA-Z0-9_-]*signin[/a-zA-Z0-9_-]*)["\']''',
        r'''["\']([/a-zA-Z0-9_-]*oauth[/a-zA-Z0-9_-]*)["\']''',
        r'''["\']([/a-zA-Z0-9_-]*token[/a-zA-Z0-9_-]*)["\']''',
        r'''["\']([/a-zA-Z0-9_-]*passport[/a-zA-Z0-9_-]*)["\']''',
    ]
    
    AUTH_KEYWORDS = {
        'token': ['token', 'jwt', 'accessToken', 'access_token', 'Authorization'],
        'username': ['username', 'userName', 'user_name', 'account', 'loginName', 'login_name'],
        'password': ['password', 'pwd', 'passwd', 'secret'],
        'mobile': ['mobile', 'phone', 'telephone', 'cellphone', 'cell_phone'],
        'sms': ['sms', 'verifyCode', 'verify_code', 'captcha', 'otp', 'vcode'],
    }
    
    COMMON_TEST_USERS = [
        'admin', 'test', 'testuser', 'demo', 'guest',
        '13800138000', '13900139000', '18800188000',
        'admin@admin.com', 'test@test.com', 'demo@demo.com',
    ]
    
    COMMON_TEST_PASSWORDS = [
        '123456', '12345678', '123456789', 'password', 'password123',
        'admin', 'admin123', 'test', 'test123', '000000',
    ]
    
    def __init__(self):
        self.found_credentials: List[AuthCredential] = []
        self.found_login_endpoints: List[LoginEndpoint] = []
        self.found_tokens: Set[str] = set()
        self.found_usernames: Set[str] = set()
        self.found_passwords: Set[str] = set()
        self.found_mobiles: Set[str] = set()
    
    def extract_from_js(self, js_content: str) -> Tuple[List[AuthCredential], List[LoginEndpoint]]:
        """
        从 JS 代码中提取认证信息和登录接口
        
        Args:
            js_content: JavaScript 代码内容
            
        Returns:
            (凭据列表, 登录接口列表)
        """
        self.found_tokens = self._extract_tokens(js_content)
        self.found_usernames = self._extract_usernames(js_content)
        self.found_passwords = self._extract_passwords(js_content)
        self.found_mobiles = self._extract_mobiles(js_content)
        
        credentials = self._build_credentials()
        login_endpoints = self._extract_login_endpoints(js_content)
        
        return credentials, login_endpoints
    
    def _extract_tokens(self, content: str) -> Set[str]:
        """提取 Token"""
        tokens = set()
        
        patterns = [
            r'''(?:token|jwt|accessToken|access_token|authorization)\s*[=:]\s*["\']([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)["\']''',
            r'''Bearer\s+([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)''',
            r'''["\'](eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)["\']''',
            r'''token\s*[=:]\s*["\']([a-zA-Z0-9_]{16,})["\']''',
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                if match.lastindex:
                    token = match.group(1)
                    if len(token) > 10:
                        tokens.add(token)
        
        return tokens
    
    def _extract_usernames(self, content: str) -> Set[str]:
        """提取用户名"""
        usernames = set()
        
        patterns = [
            r'''(?:username|userName|user_name|account|loginName)\s*[=:]\s*["\']([^"\']+)["\']''',
            r'''user\s*[=:]\s*\{[^}]*?name\s*:\s*["\']([^"\']+)["\']''',
            r'''user\s*[=:]\s*\{[^}]*?account\s*:\s*["\']([^"\']+)["\']''',
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                if match.lastindex:
                    username = match.group(1)
                    if username and len(username) >= 3:
                        usernames.add(username)
        
        return usernames
    
    def _extract_passwords(self, content: str) -> Set[str]:
        """提取密码（测试账号）"""
        passwords = set()
        
        patterns = [
            r'''(?:password|pwd|passwd)\s*[=:]\s*["\']([^"\']{4,20})["\']''',
            r'''pass\s*[=:]\s*["\']([^"\']{4,20})["\']''',
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                if match.lastindex:
                    pwd = match.group(1)
                    if pwd and not any(c in pwd for c in ['{', '}', '$', '\\']):
                        passwords.add(pwd)
        
        return passwords
    
    def _extract_mobiles(self, content: str) -> Set[str]:
        """提取手机号"""
        mobiles = set()
        
        pattern = r'''1[3-9]\d{9}'''
        for match in re.finditer(pattern, content):
            mobile = match.group(0)
            mobiles.add(mobile)
        
        return mobiles
    
    def _build_credentials(self) -> List[AuthCredential]:
        """构建凭据对象"""
        credentials = []
        
        for token in self.found_tokens:
            if token.startswith('eyJ'):
                cred = AuthCredential(
                    auth_type=AuthType.JWT,
                    token=token,
                    source="js_extracted"
                )
            else:
                cred = AuthCredential(
                    auth_type=AuthType.BEARER_TOKEN,
                    token=token,
                    source="js_extracted"
                )
            credentials.append(cred)
            self.found_credentials.append(cred)
        
        if self.found_usernames and self.found_passwords:
            for username in list(self.found_usernames)[:5]:
                for password in list(self.found_passwords)[:3]:
                    cred = AuthCredential(
                        auth_type=AuthType.BASIC_AUTH,
                        username=username,
                        password=password,
                        source="js_extracted"
                    )
                    credentials.append(cred)
                    self.found_credentials.append(cred)
        
        return credentials
    
    def _extract_login_endpoints(self, content: str) -> List[LoginEndpoint]:
        """提取登录接口"""
        endpoints = []
        found_paths = set()
        
        for pattern in self.LOGIN_PATH_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                if match.lastindex:
                    path = match.group(1)
                    if path and path not in found_paths:
                        found_paths.add(path)
                        
                        param_names = self._extract_param_names_from_context(content, match.start())
                        
                        endpoint = LoginEndpoint(
                            path=path,
                            method="POST",
                            param_names=param_names,
                            body_template=self._build_body_template(param_names),
                            source="js_extracted"
                        )
                        endpoints.append(endpoint)
                        self.found_login_endpoints.append(endpoint)
        
        return endpoints
    
    def _extract_param_names_from_context(self, content: str, position: int) -> List[str]:
        """从上下文提取参数名"""
        context_start = max(0, position - 200)
        context_end = min(len(content), position + 200)
        context = content[context_start:context_end]
        
        param_names = []
        
        for auth_key, keywords in self.AUTH_KEYWORDS.items():
            for keyword in keywords:
                if keyword.lower() in context.lower():
                    param_names.append(keyword)
        
        if not param_names:
            param_names = ['username', 'password']
        
        return list(set(param_names))
    
    def _build_body_template(self, param_names: List[str]) -> Dict[str, Any]:
        """构建请求体模板"""
        template = {}
        
        for name in param_names:
            name_lower = name.lower()
            if 'password' in name_lower or 'pwd' in name_lower:
                template[name] = '123456'
            elif 'username' in name_lower or 'account' in name_lower:
                template[name] = 'admin'
            elif 'mobile' in name_lower or 'phone' in name_lower:
                template[name] = '13800138000'
            elif 'token' in name_lower:
                template[name] = ''
            else:
                template[name] = 'test'
        
        return template


class LoginInterfaceDiscoverer:
    """登录接口发现器"""
    
    LOGIN_PATTERNS = [
        r'''/api/v\d*/auth/login''',
        r'''/api/v\d*/login''',
        r'''/api/v\d*/auth/signin''',
        r'''/api/v\d*/user/login''',
        r'''/api/v\d*/account/login''',
        r'''/auth/login''',
        r'''/login''',
        r'''/signin''',
        r'''/oauth/login''',
        r'''/passport/login''',
        r'''/api/login''',
        r'''/m/login''',
        r'''/wap/login''',
        r'''/app/login''',
        r'''/v\d*/login''',
    ]
    
    def __init__(self):
        self.discovered_endpoints: List[LoginEndpoint] = []
    
    def discover_from_paths(self, api_paths: List[str]) -> List[LoginEndpoint]:
        """从 API 路径列表中发现登录接口"""
        endpoints = []
        
        for path in api_paths:
            path_lower = path.lower()
            
            for pattern in self.LOGIN_PATTERNS:
                if re.search(pattern, path_lower):
                    param_names = self._infer_param_names(path)
                    endpoint = LoginEndpoint(
                        path=path,
                        method="POST",
                        param_names=param_names,
                        body_template=self._build_login_body(param_names),
                        source="path_discovery"
                    )
                    endpoints.append(endpoint)
                    self.discovered_endpoints.append(endpoint)
                    break
        
        return endpoints
    
    def _infer_param_names(self, path: str) -> List[str]:
        """根据路径推断参数名"""
        path_lower = path.lower()
        
        if 'mobile' in path_lower or 'phone' in path_lower:
            return ['mobile', 'password', 'smsCode']
        elif 'sms' in path_lower or 'otp' in path_lower:
            return ['mobile', 'smsCode']
        elif 'oauth' in path_lower or 'social' in path_lower:
            return ['code', 'state']
        else:
            return ['username', 'password']
    
    def _build_login_body(self, param_names: List[str]) -> Dict[str, Any]:
        """构建登录请求体"""
        body = {}
        
        for name in param_names:
            name_lower = name.lower()
            if 'password' in name_lower:
                body[name] = 'admin123'
            elif 'username' in name_lower:
                body[name] = 'admin'
            elif 'mobile' in name_lower or 'phone' in name_lower:
                body[name] = '13800138000'
            elif 'smscode' in name_lower or 'vcode' in name_lower:
                body[name] = '123456'
            elif 'code' in name_lower:
                body[name] = ''
            else:
                body[name] = 'test'
        
        return body


class AutoAuthenticator:
    """
    自动认证器
    执行自动化登录流程
    """
    
    def __init__(self, http_client):
        self.http_client = http_client
        self.current_auth: Optional[AuthCredential] = None
        self.token = ""
        self.cookies = ""
        self.headers: Dict[str, str] = {}
    
    async def try_authenticate(
        self,
        base_url: str,
        credentials: List[AuthCredential],
        login_endpoints: List[LoginEndpoint],
        discovered_paths: List[str] = None
    ) -> Optional[AuthCredential]:
        """
        尝试多种认证方式
        
        Args:
            base_url: 目标 base URL
            credentials: 从 JS 提取的凭据
            login_endpoints: 发现的登录接口
            discovered_paths: 已发现的 API 路径列表（用于父路径探测）
            
        Returns:
            成功的认证凭据，失败返回 None
        """
        base = base_url.rstrip('/')
        
        for cred in credentials:
            if cred.token:
                result = await self._try_token_auth(base, cred)
                if result:
                    return result
        
        for endpoint in login_endpoints:
            result = await self._try_login_endpoint(base, endpoint)
            if result:
                return result
        
        result = await self._try_common_login_endpoints(base, discovered_paths)
        if result:
            return result
        
        return None
    
    async def _try_token_auth(self, base_url: str, cred: AuthCredential) -> Optional[AuthCredential]:
        """尝试 Token 认证"""
        headers = {}
        if cred.auth_type == AuthType.JWT:
            headers['Authorization'] = f'Bearer {cred.token}'
        else:
            headers['Authorization'] = f'Token {cred.token}'
        
        test_url = f"{base_url}/api/v1/user/info"
        try:
            response = await self.http_client.request(
                test_url,
                method='GET',
                headers=headers,
                timeout=10
            )
            if response and 200 <= response.status_code < 300:
                cred.headers = headers
                cred.token = cred.token
                self.current_auth = cred
                self.token = cred.token
                self.headers = headers
                logger.info(f"[AutoAuth] Token 认证成功")
                return cred
        except Exception as e:
            logger.debug(f"[AutoAuth] Token 认证失败: {e}")
        
        return None
    
    async def _try_login_endpoint(
        self,
        base_url: str,
        endpoint: LoginEndpoint
    ) -> Optional[AuthCredential]:
        """尝试登录接口"""
        url = f"{base_url}{endpoint.path}"
        
        test_bodies = self._generate_test_bodies(endpoint)
        
        for body in test_bodies:
            try:
                response = await self.http_client.request(
                    url,
                    method='POST',
                    json=body,
                    timeout=10
                )
                
                if response and 200 <= response.status_code < 300:
                    auth_result = self._parse_auth_response(response, endpoint)
                    if auth_result:
                        self.current_auth = auth_result
                        logger.info(f"[AutoAuth] 登录成功: {endpoint.path}")
                        return auth_result
                
                if response and response.status_code == 401:
                    continue
                    
            except Exception as e:
                logger.debug(f"[AutoAuth] 登录失败 {endpoint.path}: {e}")
        
        return None
    
    async def _try_common_login_endpoints(
        self,
        base_url: str,
        discovered_paths: List[str] = None
    ) -> Optional[AuthCredential]:
        """尝试常见登录接口，并基于父路径探测"""
        common_endpoints = [
            ('/api/v1/auth/login', ['username', 'password']),
            ('/api/v1/login', ['username', 'password']),
            ('/api/v2/auth/login', ['username', 'password']),
            ('/auth/login', ['username', 'password']),
            ('/login', ['username', 'password']),
            ('/api/mobile/login', ['mobile', 'password']),
            ('/api/sms/login', ['mobile', 'smsCode']),
        ]
        
        tried_paths = set()
        
        if discovered_paths:
            for path in discovered_paths:
                parent_paths = self._get_parent_paths(path)
                for parent in parent_paths:
                    for suffix in ['/auth/login', '/login', '/signin', '/oauth/login', '/passport/login']:
                        combined = parent + suffix
                        if combined not in tried_paths:
                            tried_paths.add(combined)
                            endpoint = LoginEndpoint(
                                path=combined,
                                method='POST',
                                param_names=['username', 'password'],
                                body_template={'username': 'test', 'password': 'test'},
                                source="parent_path_discovery"
                            )
                            result = await self._try_login_endpoint(base_url, endpoint)
                            if result:
                                return result
        
        for path, param_names in common_endpoints:
            if path not in tried_paths:
                tried_paths.add(path)
                endpoint = LoginEndpoint(
                    path=path,
                    method='POST',
                    param_names=param_names,
                    body_template={n: 'test' for n in param_names},
                    source="common_discovery"
                )
                result = await self._try_login_endpoint(base_url, endpoint)
                if result:
                    return result
        
        return None
    
    def _get_parent_paths(self, path: str) -> List[str]:
        """获取路径的所有父路径"""
        parents = []
        segments = path.strip('/').split('/')
        
        for i in range(1, len(segments)):
            parent = '/' + '/'.join(segments[:i])
            parents.append(parent)
        
        return parents
    
    def _generate_test_bodies(self, endpoint: LoginEndpoint) -> List[Dict[str, Any]]:
        """生成测试请求体"""
        bodies = []
        param_names = endpoint.param_names
        
        test_combinations = [
            {'username': 'admin', 'password': 'admin123'},
            {'username': 'admin', 'password': '123456'},
            {'username': 'test', 'password': 'test123'},
            {'username': '13800138000', 'password': '123456'},
            {'mobile': '13800138000', 'password': '123456'},
            {'mobile': '13800138000', 'smsCode': '123456'},
            {'phone': '13800138000', 'password': '123456'},
        ]
        
        for combo in test_combinations:
            body = {}
            for param in param_names:
                param_lower = param.lower()
                for key, value in combo.items():
                    if key.lower() in param_lower:
                        body[param] = value
                        break
                else:
                    body[param] = 'test'
            bodies.append(body)
        
        return bodies
    
    def _parse_auth_response(
        self,
        response,
        endpoint: LoginEndpoint
    ) -> Optional[AuthCredential]:
        """解析认证响应"""
        try:
            content = response.content
            if isinstance(content, bytes):
                content = content.decode('utf-8')
            
            data = json.loads(content)
            
            token = ""
            cookie = ""
            headers = {}
            
            if isinstance(data, dict):
                for key in ['token', 'accessToken', 'access_token', 'jwt', 'Authorization', 'authToken', 'auth_token']:
                    if key in data:
                        token = str(data[key])
                        break
                
                for key in ['cookie', 'set-cookie', 'session', 'Session']:
                    if key in data:
                        cookie = str(data[key])
                        break
                
                if token:
                    headers['Authorization'] = f'Bearer {token}'
                    return AuthCredential(
                        auth_type=AuthType.JWT if token.startswith('eyJ') else AuthType.BEARER_TOKEN,
                        token=token,
                        headers=headers,
                        source=f"login_{endpoint.path}"
                    )
                
                if cookie:
                    return AuthCredential(
                        auth_type=AuthType.COOKIE_SESSION,
                        cookie=cookie,
                        headers={'Cookie': cookie},
                        source=f"login_{endpoint.path}"
                    )
            
        except Exception as e:
            logger.debug(f"[AutoAuth] 解析响应失败: {e}")
        
        return None
    
    def get_auth_headers(self) -> Dict[str, str]:
        """获取认证头"""
        return self.headers.copy()
    
    def get_auth_cookie(self) -> str:
        """获取认证 Cookie"""
        return self.cookies


async def auto_authenticate(
    http_client,
    base_url: str,
    js_contents: List[str] = None,
    discovered_paths: List[str] = None
) -> Optional[AuthCredential]:
    """
    自动化认证入口函数
    
    Args:
        http_client: HTTP 客户端
        base_url: 目标 URL
        js_contents: 可选的 JS 内容列表
        discovered_paths: 已发现的 API 路径列表
        
    Returns:
        认证成功的凭据，失败返回 None
    """
    extractor = AuthInfoExtractor()
    discoverer = LoginInterfaceDiscoverer()
    authenticator = AutoAuthenticator(http_client)
    
    credentials = []
    login_endpoints = []
    
    if js_contents:
        for js in js_contents:
            creds, endpoints = extractor.extract_from_js(js)
            credentials.extend(creds)
            login_endpoints.extend(endpoints)
    
    if login_endpoints:
        logger.info(f"[AutoAuth] 发现 {len(login_endpoints)} 个登录接口")
    
    result = await authenticator.try_authenticate(
        base_url,
        credentials,
        login_endpoints,
        discovered_paths
    )
    
    if result:
        logger.info(f"[AutoAuth] 认证成功")
    else:
        logger.info(f"[AutoAuth] 认证失败")
    
    return result