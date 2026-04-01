"""
Browser Interaction Enhancement Module
增强浏览器交互能力 - 超时处理、表单自动填充、登录流程
"""

import asyncio
import logging
import re
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin

logger = logging.getLogger(__name__)


@dataclass
class FormField:
    """表单字段"""
    name: str
    field_type: str  # input, select, textarea, checkbox, radio
    input_type: str  # text, password, email, tel, etc.
    label: str = ""
    value: str = ""
    options: List[str] = field(default_factory=list)
    required: bool = False
    selector: str = ""


@dataclass
class LoginForm:
    """登录表单"""
    username_field: Optional[FormField] = None
    password_field: Optional[FormField] = None
    captcha_field: Optional[FormField] = None
    submit_button: str = ""
    form_url: str = ""
    form_selector: str = ""


@dataclass
class SensitiveInfo:
    """敏感信息"""
    info_type: str  # ip, email, phone, key, credential
    value: str
    source: str  # js, response, header
    context: str = ""  # 上下文


class BrowserInteractionEnhancer:
    """浏览器交互增强器"""
    
    def __init__(self, page=None):
        self.page = page
        self.forms: List[LoginForm] = []
        self.session_cookies: Dict[str, str] = {}
        self.session_headers: Dict[str, str] = {}
    
    async def set_page(self, page):
        """设置页面对象"""
        self.page = page
    
    async def smart_navigate(self, url: str, timeout: int = 30000) -> bool:
        """智能导航 - 多种策略处理超时"""
        if not self.page:
            return False
        
        strategies = [
            {'wait_until': 'networkidle', 'timeout': timeout},
            {'wait_until': 'load', 'timeout': timeout},
            {'wait_until': 'domcontentloaded', 'timeout': timeout * 2},
            {'wait_until': 'commit', 'timeout': timeout},
        ]
        
        for i, strategy in enumerate(strategies):
            try:
                await self.page.goto(url, **strategy)
                logger.info(f"Navigation succeeded with strategy {i+1}: {strategy['wait_until']}")
                return True
            except Exception as e:
                logger.warning(f"Strategy {i+1} failed: {str(e)[:50]}")
                if i == len(strategies) - 1:
                    try:
                        await self.page.goto(url, wait_until='commit', timeout=5000)
                        return True
                    except:
                        pass
        
        return False
    
    async def discover_login_forms(self) -> List[LoginForm]:
        """发现页面中的登录表单"""
        if not self.page:
            return []
        
        forms = []
        
        try:
            form_selectors = [
                'form[action*="login"]',
                'form[id*="login"]', 
                'form[class*="login"]',
                'form[action*="auth"]',
                'form[class*="auth"]',
                'form[id*="auth"]',
                'form',
            ]
            
            for selector in form_selectors:
                try:
                    elements = await self.page.query_selector_all(selector)
                    for element in elements:
                        form = await self._analyze_form_element(element, selector)
                        if form and self._is_login_form(form):
                            forms.append(form)
                except:
                    pass
                
        except Exception as e:
            logger.debug(f"Login form discovery error: {e}")
        
        self.forms = forms
        return forms
    
    async def _analyze_form_element(self, element, base_selector: str) -> Optional[LoginForm]:
        """分析表单元素"""
        try:
            form = LoginForm(form_selector=base_selector)
            
            inputs = await element.query_selector_all('input')
            for inp in inputs:
                field_type = await inp.get_attribute('type') or 'text'
                name = await inp.get_attribute('name') or ''
                placeholder = await inp.get_attribute('placeholder') or ''
                id_attr = await inp.get_attribute('id') or ''
                label = await inp.get_attribute('aria-label') or ''
                
                field = FormField(
                    name=name,
                    field_type='input',
                    input_type=field_type,
                    label=label or placeholder,
                    selector=f"input[name='{name}']" if name else f"input[type='{field_type}']"
                )
                
                if field_type in ['text', 'email', 'tel']:
                    if 'user' in (name + placeholder).lower():
                        form.username_field = field
                    elif 'phone' in (name + placeholder).lower():
                        form.username_field = field
                elif field_type == 'password':
                    if 'password' in (name + placeholder).lower():
                        if 'new' in (name + placeholder).lower() or 'confirm' in (name + placeholder).lower():
                            pass
                        else:
                            form.password_field = field
                elif field_type in ['submit', 'button']:
                    form.submit_button = field.selector
            
            buttons = await element.query_selector_all('button')
            if not form.submit_button and buttons:
                form.submit_button = 'button[type="submit"]'
            
            return form
            
        except Exception as e:
            logger.debug(f"Form analysis error: {e}")
            return None
    
    def _is_login_form(self, form: LoginForm) -> bool:
        """判断是否是登录表单"""
        has_password = form.password_field is not None
        has_user = form.username_field is not None
        
        return has_password and has_user
    
    async def auto_fill_login(self, username: str, password: str) -> bool:
        """自动填充登录表单"""
        if not self.page:
            return False
        
        await self.discover_login_forms()
        
        if not self.forms:
            logger.warning("No login form found")
            return False
        
        form = self.forms[0]
        
        try:
            if form.username_field and form.username_field.selector:
                await self.page.fill(form.username_field.selector, username)
            
            if form.password_field and form.password_field.selector:
                await self.page.fill(form.password_field.selector, password)
            
            return True
            
        except Exception as e:
            logger.warning(f"Auto fill failed: {e}")
            return False
    
    async def submit_login(self, captcha: str = "") -> Tuple[bool, str]:
        """提交登录表单"""
        if not self.page:
            return False, "No page"
        
        await self.discover_login_forms()
        
        if not self.forms:
            return False, "No login form"
        
        form = self.forms[0]
        
        try:
            if captcha and form.captcha_field and form.captcha_field.selector:
                await self.page.fill(form.captcha_field.selector, captcha)
            
            if form.submit_button:
                await self.page.click(form.submit_button)
            else:
                await self.page.press('body', 'Enter')
            
            await self.page.wait_for_timeout(2000)
            
            return True, "Submitted"
            
        except Exception as e:
            return False, str(e)
    
    async def get_session_info(self) -> Dict[str, Any]:
        """获取会话信息"""
        info = {
            'cookies': {},
            'headers': {},
            'localStorage': {},
            'sessionStorage': {}
        }
        
        if not self.page:
            return info
        
        try:
            cookies = await self.context.cookies() if self.context else []
            for cookie in cookies:
                info['cookies'][cookie['name']] = cookie['value']
            
            storage_script = """
            () => {
                const ls = {};
                for (let i = 0; i < localStorage.length; i++) {
                    const key = localStorage.key(i);
                    ls[key] = localStorage.getItem(key);
                }
                const ss = {};
                for (let i = 0; i < sessionStorage.length; i++) {
                    const key = sessionStorage.key(i);
                    ss[key] = sessionStorage.getItem(key);
                }
                return { ls, ss };
            }
            """
            storage = await self.page.evaluate(storage_script)
            info['localStorage'] = storage.get('ls', {})
            info['sessionStorage'] = storage.get('ss', {})
            
        except Exception as e:
            logger.debug(f"Session info error: {e}")
        
        return info
    
    async def extract_auth_token(self) -> Optional[str]:
        """提取认证 Token"""
        info = await self.get_session_info()
        
        for key, value in {**info['localStorage'], **info['sessionStorage']}.items():
            key_lower = key.lower()
            if any(x in key_lower for x in ['token', 'auth', 'jwt', 'bearer', 'session']):
                if value and len(value) > 10:
                    return value
        
        for cookie in info['cookies'].items():
            if any(x in cookie[0].lower() for x in ['token', 'auth', 'session']):
                return cookie[1]
        
        return None


class SensitiveInfoExtractor:
    """敏感信息提取器"""
    
    INTERNAL_IP_PATTERN = re.compile(
        r'(192\.168\.\d{1,3}\.\d{1,3}|'
        r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
        r'172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3})'
    )
    
    PHONE_PATTERN = re.compile(r'\b1[3-9]\d{9}\b')
    
    EMAIL_PATTERN = re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')
    
    API_KEY_PATTERNS = [
        re.compile(r'apiKey\s*[:=]\s*["\']([^"\']{16,})["\']', re.I),
        re.compile(r'api_key\s*[:=]\s*["\']([^"\']{16,})["\']', re.I),
        re.compile(r'accessKey\s*[:=]\s*["\']([^"\']{16,})["\']', re.I),
    ]
    
    SECRET_PATTERNS = [
        re.compile(r'secret\s*[:=]\s*["\']([^"\']{16,})["\']', re.I),
        re.compile(r'secretKey\s*[:=]\s*["\']([^"\']{16,})["\']', re.I),
        re.compile(r'password\s*[:=]\s*["\']([^"\']{8,})["\']', re.I),
    ]
    
    TOKEN_PATTERNS = [
        re.compile(r'Bearer\s+([a-zA-Z0-9\-_\.]+)', re.I),
        re.compile(r'token["\']?\s*[:=]\s*["\']([a-zA-Z0-9\-_\.]+)["\']', re.I),
        re.compile(r'jwt["\']?\s*[:=]\s*["\']([a-zA-Z0-9\-_\.]+)["\']', re.I),
    ]
    
    def __init__(self):
        self.findings: List[SensitiveInfo] = []
    
    def extract_from_js(self, js_content: str, source_url: str = "") -> List[SensitiveInfo]:
        """从 JS 内容提取敏感信息"""
        findings = []
        
        internal_ips = self.INTERNAL_IP_PATTERN.findall(js_content)
        for ip in set(internal_ips):
            findings.append(SensitiveInfo(
                info_type='internal_ip',
                value=ip,
                source='js',
                context=f"Found in {source_url}"
            ))
        
        phones = self.PHONE_PATTERN.findall(js_content)
        for phone in set(phones):
            findings.append(SensitiveInfo(
                info_type='phone',
                value=phone,
                source='js',
                context=f"Found in {source_url}"
            ))
        
        emails = self.EMAIL_PATTERN.findall(js_content)
        for email in set(emails):
            if not email.endswith(('@example.com')):
                findings.append(SensitiveInfo(
                    info_type='email',
                    value=email,
                    source='js',
                    context=f"Found in {source_url}"
                ))
        
        for pattern in self.API_KEY_PATTERNS:
            matches = pattern.findall(js_content)
            for match in matches:
                findings.append(SensitiveInfo(
                    info_type='api_key',
                    value=match[:50] + '...' if len(match) > 50 else match,
                    source='js',
                    context=f"Found in {source_url}"
                ))
        
        for pattern in self.SECRET_PATTERNS:
            matches = pattern.findall(js_content)
            for match in matches:
                findings.append(SensitiveInfo(
                    info_type='secret',
                    value=match[:50] + '...' if len(match) > 50 else match,
                    source='js',
                    context=f"Found in {source_url}"
                ))
        
        for pattern in self.TOKEN_PATTERNS:
            matches = pattern.findall(js_content)
            for match in matches:
                if len(match) > 20:
                    findings.append(SensitiveInfo(
                        info_type='token',
                        value=match[:50] + '...' if len(match) > 50 else match,
                        source='js',
                        context=f"Found in {source_url}"
                    ))
        
        self.findings.extend(findings)
        return findings
    
    def extract_from_response(self, content: str, url: str = "") -> List[SensitiveInfo]:
        """从响应内容提取敏感信息"""
        findings = []
        
        internal_ips = self.INTERNAL_IP_PATTERN.findall(content)
        for ip in set(internal_ips):
            findings.append(SensitiveInfo(
                info_type='internal_ip',
                value=ip,
                source='response',
                context=f"Found in {url}"
            ))
        
        phones = self.PHONE_PATTERN.findall(content)
        for phone in set(phones):
            findings.append(SensitiveInfo(
                info_type='phone',
                value=phone,
                source='response',
                context=f"Found in {url}"
            ))
        
        emails = self.EMAIL_PATTERN.findall(content)
        for email in set(emails):
            if not email.endswith('@example.com'):
                findings.append(SensitiveInfo(
                    info_type='email',
                    value=email,
                    source='response',
                    context=f"Found in {url}"
                ))
        
        self.findings.extend(findings)
        return findings
    
    def extract_from_headers(self, headers: Dict, url: str = "") -> List[SensitiveInfo]:
        """从响应头提取敏感信息"""
        findings = []
        
        header_str = str(headers)
        internal_ips = self.INTERNAL_IP_PATTERN.findall(header_str)
        for ip in set(internal_ips):
            findings.append(SensitiveInfo(
                info_type='internal_ip',
                value=ip,
                source='header',
                context=f"Found in headers from {url}"
            ))
        
        self.findings.extend(findings)
        return findings
    
    def get_all_findings(self) -> List[SensitiveInfo]:
        """获取所有发现"""
        return self.findings
    
    def get_by_type(self, info_type: str) -> List[SensitiveInfo]:
        """按类型获取"""
        return [f for f in self.findings if f.info_type == info_type]
    
    def get_summary(self) -> Dict[str, int]:
        """获取摘要"""
        summary = {}
        for finding in self.findings:
            if finding.info_type not in summary:
                summary[finding.info_type] = 0
            summary[finding.info_type] += 1
        return summary
    
    def clear(self):
        """清空发现"""
        self.findings = []


class WAFDetector:
    """WAF 检测器"""
    
    WAF_FINGERPRINTS = {
        '阿里云盾': [
            'aliyundun',
            'AliyunDun',
            'CDNUA',
        ],
        '腾讯云': [
            'qcloud',
            'Tencent',
            'qcloud_acl',
        ],
        'AWS WAF': [
            'aws-waf',
            'awswaf',
        ],
        'Cloudflare': [
            'cf-ray',
            'CF-RAY',
            '__cfduid',
        ],
        'Akamai': [
            'AkamaiGHost',
            'AkamaiIPrerouting',
        ],
        'F5 BIG-IP': [
            'BigIP',
            'X-F5-Authentication',
        ],
        'ModSecurity': [
            'ModSecurity',
            'mod_security',
        ],
        'D盾': [
            'D盾',
            'd盾',
        ],
        '云锁': [
            'yunlock',
            '云锁',
        ],
        '安全狗': [
            'SafeDog',
            '安全狗',
        ],
    }
    
    BLOCK_PATTERNS = [
        re.compile(r' access denied ', re.I),
        re.compile(r' forbidden ', re.I),
        re.compile(r' 403 forbidden', re.I),
        re.compile(r' security check ', re.I),
        re.compile(r'被防火墙拦截', re.I),
        re.compile(r'请求过于频繁', re.I),
        re.compile(r'操作频繁', re.I),
        re.compile(r'验证码', re.I),
        re.compile(r' captcha ', re.I),
    ]
    
    def __init__(self):
        self.detected_wafs: Set[str] = set()
        self.block_count: int = 0
        self.total_requests: int = 0
    
    def detect_from_response(self, content: str, headers: Dict = None) -> List[str]:
        """从响应检测 WAF"""
        detected = []
        content_str = content + str(headers) if headers else content
        
        for waf_name, fingerprints in self.WAF_FINGERPRINTS.items():
            for fp in fingerprints:
                if fp.lower() in content_str.lower():
                    detected.append(waf_name)
                    self.detected_wafs.add(waf_name)
        
        for pattern in self.BLOCK_PATTERNS:
            if pattern.search(content_str):
                self.block_count += 1
                break
        
        return detected
    
    def is_blocked(self, content: str, status_code: int = None) -> bool:
        """判断是否被拦截"""
        if status_code in [403, 405, 429]:
            return True
        
        for pattern in self.BLOCK_PATTERNS:
            if pattern.search(content):
                return True
        
        return False
    
    def get_waf_list(self) -> List[str]:
        """获取检测到的 WAF 列表"""
        return list(self.detected_wafs)
    
    def get_block_rate(self) -> float:
        """获取拦截率"""
        if self.total_requests == 0:
            return 0.0
        return self.block_count / self.total_requests


class PathPrefixLearner:
    """API 路径前缀学习器"""
    
    def __init__(self):
        self.learned_prefixes: Set[str] = set()
        self.path_mappings: Dict[str, str] = {}
        self.base_urls: Set[str] = set()
    
    def learn_from_intercept(self, js_path: str, real_url: str):
        """从拦截学习路径映射"""
        parsed = urlparse(real_url)
        real_path = parsed.path
        
        if real_path != js_path:
            self.path_mappings[js_path] = real_path
        
        prefix = self._extract_prefix(real_path)
        if prefix:
            self.learned_prefixes.add(prefix)
    
    def learn_from_js(self, js_content: str):
        """从 JS 内容学习前缀"""
        patterns = [
            r'baseURL\s*[:=]\s*["\']([^"\']+)["\']',
            r'axios\.create\(\s*\{\s*baseURL\s*:\s*["\']([^"\']+)["\']',
            r'apiUrl\s*[:=]\s*["\']([^"\']+)["\']',
            r'root\s*[:=]\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, js_content, re.I)
            for match in matches:
                if match and not match.startswith('http'):
                    self.base_urls.add(match)
                    prefix = self._extract_prefix(match)
                    if prefix:
                        self.learned_prefixes.add(prefix)
    
    def learn_from_url(self, url: str):
        """从 URL 学习前缀"""
        parsed = urlparse(url)
        path = parsed.path
        
        parts = path.strip('/').split('/')
        if len(parts) >= 2:
            prefix = '/' + '/'.join(parts[:2])
            self.learned_prefixes.add(prefix)
    
    def _extract_prefix(self, path: str) -> str:
        """提取路径前缀"""
        if not path or not path.startswith('/'):
            return ''
        
        parts = path.strip('/').split('/')
        if len(parts) >= 2:
            return '/' + '/'.join(parts[:2])
        return ''
    
    def transform_path(self, js_path: str) -> List[str]:
        """转换路径为可能的真实路径"""
        results = set()
        results.add(js_path)
        
        if js_path.startswith('/'):
            for prefix in self.learned_prefixes:
                if prefix not in js_path:
                    new_path = prefix + js_path
                    results.add(new_path)
        
        for js_p, real_p in self.path_mappings.items():
            if js_p in js_path:
                results.add(js_path.replace(js_p, real_p))
            if js_path in real_p:
                results.add(js_path.replace(real_p, js_p))
        
        return list(results)
    
    def get_all_prefixes(self) -> Set[str]:
        """获取所有学习到的前缀"""
        return self.learned_prefixes.copy()
    
    def get_mappings(self) -> Dict[str, str]:
        """获取路径映射"""
        return self.path_mappings.copy()
