"""
Fuzz Tester Module
模糊测试模块
"""

import random
import string
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin


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
        command_payloads: Optional[List[str]] = None
    ):
        self.http_client = http_client
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
