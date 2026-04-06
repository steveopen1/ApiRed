"""
IDOR Tester Module
IDOR 专项测试器 - 实现参数替换/值替换测试
参考 Bugcrowd/HackerOne 众测实战技巧
参考 tomnomnom/gf 模式匹配
"""

import json
import hashlib
import re
import logging
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass
from urllib.parse import urlparse, parse_qs

from .bypass_techniques import encode_params_with_arrays

logger = logging.getLogger(__name__)


@dataclass
class IDORTestResult:
    """IDOR 测试结果"""
    original_response: Dict[str, Any]
    modified_response: Dict[str, Any]
    bypass_technique: str
    is_vulnerable: bool
    severity: str
    evidence: str
    leaked_data_type: Optional[str] = None
    leaked_fields: Optional[List[str]] = None


class IDORTester:
    """
    IDOR 专项测试器
    
    支持的测试策略:
    1. 参数值替换 - 将 user_id=123 替换为 user_id=456
    2. 参数类型混淆 - id=123 → id=abc
    3. JSON 嵌套混淆 - {"user_id": {"value": 123}}
    4. 数组包装 - user_id[]=123
    5. 参数污染 - 同一参数多个值
    6. 响应差异分析 - 判断真假绕过
    7. GF 模式库支持 - 自定义 IDOR 参数规则
    """
    
    SENSITIVE_PARAM_NAMES = {
        'user_id', 'uid', 'userid', 'user', 'id', 'account_id',
        'profile_id', 'order_id', 'transaction_id', 'invoice_id',
        'payment_id', 'member_id', 'customer_id', 'client_id',
        'resource_id', 'object_id', 'item_id', 'document_id',
        'file_id', 'post_id', 'comment_id', 'message_id',
        'session_id', 'token_id', 'address_id', 'card_id',
        'uuid', 'guid', 'uuid_id', 'unique_id', 'serial',
        '用户id', '用户编号', '订单号', '订单id', '流水号', '交易号',
        '会员id', '客户id', '账号id', '编号', '标识', '记录id',
        'ddh', 'ddh_id', 'task_id', 'record_id', 'entry_id',
    }
    
    UUID_PATTERNS = [
        r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
        r'[0-9a-f]{32}',
        r'[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}',
        r'\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}',
    ]
    
    SENSITIVE_DATA_PATTERNS = {
        'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        'phone': r'1[3-9]\d{9}',
        'ssn': r'\d{3}-\d{2}-\d{4}',
        'credit_card': r'\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}',
        'password': r'(?i)(password|passwd|pwd)\s*[:=]\s*[\'"]?[^\'"]{4,}',
        'api_key': r'(?i)(api[_-]?key|apikey)\s*[:=]\s*[\'"]?[a-zA-Z0-9]{20,}',
        'jwt': r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
        'ip': r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
        'address': r'\d{1,5}\s+[\w\s]+(?:street|st|avenue|ave|road|rd|blvd)',
    }
    
    def __init__(self, http_client, custom_patterns: Optional[List[str]] = None):
        self.http_client = http_client
        self._test_results: List[IDORTestResult] = []
        self._url_greper = None
        self._custom_patterns = custom_patterns or []
        self._init_gf_patterns()
    
    def _init_gf_patterns(self):
        """初始化 GF 模式支持"""
        try:
            from ..utils.url_greper import URLGreper
            self._url_greper = URLGreper()
        except ImportError:
            self._url_greper = None
    
    def set_custom_patterns(self, patterns: List[str]):
        """
        设置自定义 IDOR 参数模式
        
        Args:
            patterns: 正则表达式模式列表，例如:
                - r"user_\d+_id"
                - r"record_\d+"
                - r"item_\d+"
        """
        self._custom_patterns = patterns
    
    async def test_idor(
        self,
        url: str,
        method: str = 'GET',
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[str] = None,
        auth_token: Optional[str] = None
    ) -> List[IDORTestResult]:
        """
        测试 IDOR 漏洞
        
        Args:
            url: 目标 URL
            method: HTTP 方法
            params: 请求参数
            headers: 请求头
            cookies: Cookie
            auth_token: 认证 Token
        
        Returns:
            IDOR 测试结果列表
        """
        results = []
        
        original_response = await self._send_request(
            url, method, params, headers, cookies, auth_token
        )
        
        if not original_response:
            return results
        
        id_params = self._extract_id_params(params or {}, url)
        
        if not id_params:
            return results
        
        for param_name, param_value in id_params.items():
            alternative_values = self._generate_alternative_values(param_value)
            
            for alt_value in alternative_values:
                modified_params = self._replace_param(params or {}, param_name, alt_value)
                
                modified_response = await self._send_request(
                    url, method, modified_params, headers, cookies, auth_token
                )
                
                if not modified_response:
                    continue
                
                result = self._analyze_idor(
                    original_response,
                    modified_response,
                    param_name,
                    alt_value
                )
                
                if result:
                    results.append(result)
                    self._test_results.append(result)
        
        return results
    
    async def test_idor_with_bypass(
        self,
        url: str,
        method: str = 'GET',
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[str] = None,
        auth_token: Optional[str] = None
    ) -> List[IDORTestResult]:
        """
        使用绕过技术测试 IDOR (组合测试)
        
        组合策略:
        1. 参数值替换 + 绕过技术
        2. 参数类型混淆 + 绕过技术
        3. JSON 嵌套 + 绕过技术
        """
        from .bypass_techniques import BypassTechniques
        
        results = []
        
        original_response = await self._send_request(
            url, method, params, headers, cookies, auth_token
        )
        
        if not original_response:
            return results
        
        id_params = self._extract_id_params(params or {}, url)
        
        bypass_techniques = BypassTechniques.get_all_techniques()
        idor_techniques = [t for t in bypass_techniques if t.category == 'idor']
        
        for param_name, param_value in id_params.items():
            for technique in idor_techniques[:10]:
                try:
                    original_config = {
                        'url': url,
                        'path': urlparse(url).path,
                        'params': params or {},
                        'method': method,
                        'data': ''
                    }
                    
                    bypass_config = technique.apply_func(original_config)
                    
                    if bypass_config.get('params'):
                        modified_params = bypass_config['params']
                    else:
                        modified_params = params.copy() if params else {}
                        modified_params[param_name] = param_value
                    
                    modified_method = bypass_config.get('method', method)
                    modified_headers = {**(headers or {}), **bypass_config.get('headers', {})}
                    
                    modified_response = await self._send_request(
                        url, modified_method, modified_params,
                        modified_headers, cookies, auth_token
                    )
                    
                    if not modified_response:
                        continue
                    
                    result = self._analyze_idor(
                        original_response,
                        modified_response,
                        param_name,
                        technique.name
                    )
                    
                    if result:
                        result.bypass_technique = technique.name
                        results.append(result)
                        self._test_results.append(result)
                        
                except Exception as e:
                    logger.debug(f"IDOR bypass technique failed for {technique.name}: {e}")
                    continue
        
        return results
    
    def _extract_id_params(
        self,
        params: Dict[str, Any],
        url: str
    ) -> Dict[str, Any]:
        """提取可能的 IDOR 相关参数"""
        id_params = {}
        import re
        
        for key, value in params.items():
            key_lower = key.lower()
            if any(sensitive in key_lower for sensitive in self.SENSITIVE_PARAM_NAMES):
                id_params[key] = value
        
        parsed = urlparse(url)
        path_parts = parsed.path.split('/')
        for i, part in enumerate(path_parts):
            if part.isdigit() and i > 0:
                prev_part = path_parts[i - 1].rstrip('s')
                id_params[f'path_{prev_part}_id'] = part
            
            for uuid_pattern in self.UUID_PATTERNS:
                if re.match(uuid_pattern, part, re.IGNORECASE):
                    prev_part = path_parts[i - 1].rstrip('s') if i > 0 else 'resource'
                    id_params[f'path_{prev_part}_uuid'] = part
                    break
        
        return id_params
    
    def _generate_alternative_values(self, original_value: Any) -> List[Any]:
        """生成替代测试值"""
        alternatives = []
        
        if isinstance(original_value, int):
            alternatives.extend([
                original_value + 1,
                original_value - 1,
                0, 1, 999999
            ])
        elif isinstance(original_value, str):
            if original_value.isdigit():
                alternatives.extend([
                    str(int(original_value) + 1),
                    str(int(original_value) - 1),
                    '0', '1', '999999'
                ])
            alternatives.extend([
                'abc',
                original_value * 2,
                '',
                'null',
                'undefined'
            ])
        
        return list(set(str(v) for v in alternatives))[:6]
    
    def _replace_param(
        self,
        params: Dict[str, Any],
        param_name: str,
        new_value: Any
    ) -> Dict[str, Any]:
        """替换参数值"""
        modified = params.copy()
        modified[param_name] = new_value
        return modified
    
    async def _send_request(
        self,
        url: str,
        method: str,
        params: Optional[Dict[str, Any]],
        headers: Optional[Dict[str, str]],
        cookies: Optional[str],
        auth_token: Optional[str],
        bypass_headers: Optional[Dict[str, str]] = None
    ) -> Optional[Dict[str, Any]]:
        """发送请求并返回响应"""
        try:
            if params and method == 'GET':
                query_string = encode_params_with_arrays(params)
                separator = '&' if '?' in url else '?'
                full_url = f"{url}{separator}{query_string}"
            else:
                full_url = url
            
            request_headers = {**(headers or {}), **(bypass_headers or {})}
            if auth_token:
                request_headers['Authorization'] = f'Bearer {auth_token}'
            if cookies:
                request_headers['Cookie'] = cookies
            
            response = await self.http_client.request(
                full_url,
                method,
                params=params if method != 'GET' else None,
                headers=request_headers
            )
            
            return {
                'status_code': response.status_code,
                'content': response.content,
                'headers': dict(response.headers) if hasattr(response, 'headers') else {},
                'url': full_url
            }
        except Exception as e:
            logger.debug(f"Request failed for {url}: {e}")
            return None
    
    def _analyze_idor(
        self,
        original_response: Dict[str, Any],
        modified_response: Dict[str, Any],
        param_name: str,
        test_value: str
    ) -> Optional[IDORTestResult]:
        """分析 IDOR 漏洞"""
        orig_status = original_response.get('status_code', 0)
        mod_status = modified_response.get('status_code', 0)
        
        orig_content = original_response.get('content', '')
        mod_content = modified_response.get('content', '')
        
        is_vulnerable = False
        severity = 'info'
        evidence = ''
        leaked_data_type = None
        leaked_fields = []
        
        if mod_status == 200 and orig_status in [401, 403]:
            is_vulnerable = True
            severity = 'critical'
            evidence = f"参数 {param_name}={test_value} 成功绕过认证"
        
        elif mod_status == 200 and orig_status == 200:
            if self._content_differs_significantly(orig_content, mod_content):
                leaked = self._detect_leaked_data(orig_content, mod_content)
                if leaked:
                    is_vulnerable = True
                    severity = 'high'
                    evidence = f"成功访问其他用户数据: {leaked['type']}"
                    leaked_data_type = leaked['type']
                    leaked_fields = leaked.get('fields', [])
        
        elif mod_status != orig_status:
            if self._is_false_positive(mod_status, orig_status, mod_content):
                evidence = f"状态码变化: {orig_status} → {mod_status}, 但无实际数据泄露"
                severity = 'info'
            else:
                is_vulnerable = True
                severity = 'medium'
                evidence = f"响应异常: {orig_status} → {mod_status}"
        
        if is_vulnerable or severity != 'info':
            return IDORTestResult(
                original_response=original_response,
                modified_response=modified_response,
                bypass_technique=param_name,
                is_vulnerable=is_vulnerable,
                severity=severity,
                evidence=evidence,
                leaked_data_type=leaked_data_type,
                leaked_fields=leaked_fields
            )
        
        return None
    
    def _content_differs_significantly(
        self,
        orig_content: str,
        mod_content: str
    ) -> bool:
        """判断内容是否显著不同"""
        if not orig_content or not mod_content:
            return False
        
        orig_lower = orig_content.lower()
        mod_lower = mod_content.lower()
        
        if 'unauthorized' in orig_lower and 'unauthorized' not in mod_lower:
            return True
        if 'access denied' in orig_lower and 'access denied' not in mod_lower:
            return True
        if 'forbidden' in orig_lower and 'forbidden' not in mod_lower:
            return True
        
        orig_len = len(orig_content)
        mod_len = len(mod_content)
        if abs(orig_len - mod_len) > max(100, orig_len * 0.5):
            return True
        
        return False
    
    def _detect_leaked_data(
        self,
        orig_content: str,
        mod_content: str
    ) -> Optional[Dict[str, Any]]:
        """检测泄露的数据类型"""
        result = {'type': None, 'fields': []}
        
        for data_type, pattern in self.SENSITIVE_DATA_PATTERNS.items():
            matches = re.findall(pattern, mod_content)
            if matches and data_type not in orig_content.lower():
                result['type'] = data_type
                result['fields'] = list(set(matches))[:5]
                return result
        
        try:
            orig_json = json.loads(orig_content) if orig_content.startswith('{') else {}
            mod_json = json.loads(mod_content) if mod_content.startswith('{') else {}
            
            if isinstance(orig_json, dict) and isinstance(mod_json, dict):
                orig_keys = set(orig_json.keys())
                mod_keys = set(mod_json.keys())
                
                new_keys = mod_keys - orig_keys
                sensitive_keys = {'email', 'phone', 'address', 'password', 'ssn', 'card'}
                
                if new_keys & sensitive_keys:
                    result['type'] = 'personal_data'
                    result['fields'] = list(new_keys & sensitive_keys)
                    return result
                    
        except (json.JSONDecodeError, TypeError):
            pass
        
        return None
    
    def _is_false_positive(
        self,
        new_status: int,
        orig_status: int,
        content: str
    ) -> bool:
        """判断是否为假阳性"""
        if new_status == 302 or new_status == 301:
            return True
        
        if 'login' in content.lower() or 'signin' in content.lower():
            return True
        
        if 'redirect' in content.lower() and len(content) < 500:
            return True
        
        return False
    
    def get_test_results(self) -> List[IDORTestResult]:
        """获取所有测试结果"""
        return self._test_results
    
    def get_vulnerable_results(self) -> List[IDORTestResult]:
        """获取存在漏洞的结果"""
        return [r for r in self._test_results if r.is_vulnerable]
