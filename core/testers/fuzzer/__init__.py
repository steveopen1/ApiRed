"""
Smart Parameter Fuzzer
智能参数模糊测试模块
参考 ApiHunter 的多格式测试和智能填充
"""

import re
import json
import logging
from typing import Dict, List, Any, Optional, Set
from urllib.parse import urlencode

logger = logging.getLogger(__name__)


class SmartFuzzer:
    """
    智能模糊测试器
    
    功能:
    1. 多格式测试 - POST 请求支持 JSON/Form/URL 三种格式
    2. 智能参数填充 - 根据参数名自动生成测试数据
    3. 安全模式 - 拦截高危方法和参数
    """
    
    HIGH_RISK_METHODS = {'DELETE', 'PUT', 'PATCH'}
    HIGH_RISK_PARAMS = {
        'delete', 'remove', 'drop', 'destroy', 'erase',
        'admin', 'root', 'password', 'passwd',
        'eval', 'exec', 'system', 'shell',
        'sql', 'query', 'script',
    }
    
    PARAM_TYPE_PATTERNS = {
        'id': {
            'patterns': [r'(?:^|_)(?:id|uid|user_id|product_id|order_id|post_id)', r'.*(?:_id|id)$'],
            'examples': ['1', '100', '999999'],
        },
        'email': {
            'patterns': [r'.*(?:email|e-mail|mail|user_email)', r'.*'],
            'examples': ['test@example.com', 'admin@test.com'],
        },
        'phone': {
            'patterns': [r'.*(?:phone|mobile|tel|cell)', r'.*'],
            'examples': ['13800138000', '10086'],
        },
        'username': {
            'patterns': [r'.*(?:user|account|name|login|uname|username)', r'.*'],
            'examples': ['admin', 'test', 'user'],
        },
        'password': {
            'patterns': [r'.*(?:pass|pwd|secret)', r'.*'],
            'examples': ['admin123', 'password', '123456'],
        },
        'page': {
            'patterns': [r'.*(?:page|num|offset)', r'.*'],
            'examples': ['1', '0', '10'],
        },
        'size': {
            'patterns': [r'.*(?:size|limit|count|length)', r'.*'],
            'examples': ['10', '20', '100'],
        },
        'file': {
            'patterns': [r'.*(?:file|path|filename|doc)', r'.*'],
            'examples': ['test.txt', 'config.json', 'data.xml'],
        },
        'token': {
            'patterns': [r'.*(?:token|key|api_key|apikey|auth)', r'.*'],
            'examples': ['test_token', 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'],
        },
        'id_list': {
            'patterns': [r'.*(?:ids|ids\[\]|id_list)', r'.*'],
            'examples': ['1,2,3', '[1,2,3]', '1'],
        },
    }
    
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "'\"><script>alert('XSS')</script>",
    ]
    
    SQLI_PAYLOADS = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "1' AND '1'='1",
        "'; DROP TABLE users--",
        "1' OR '1'='1' UNION SELECT NULL--",
    ]
    
    def __init__(self, safe_mode: bool = True):
        """
        Args:
            safe_mode: 安全模式，启用时拦截高危方法
        """
        self.safe_mode = safe_mode
    
    def is_safe_method(self, method: str) -> bool:
        """检查方法是否安全"""
        if not self.safe_mode:
            return True
        return method.upper() not in self.HIGH_RISK_METHODS
    
    def is_safe_param(self, param_name: str) -> bool:
        """检查参数是否安全"""
        if not self.safe_mode:
            return True
        param_lower = param_name.lower()
        return not any(risky in param_lower for risky in self.HIGH_RISK_PARAMS)
    
    def guess_param_type(self, param_name: str) -> Optional[str]:
        """
        根据参数名猜测参数类型
        
        Returns:
            参数类型: id, email, phone, username, password, page, size, file, token, id_list
        """
        param_lower = param_name.lower()
        
        for ptype, info in self.PARAM_TYPE_PATTERNS.items():
            for pattern in info['patterns']:
                if re.search(pattern, param_lower, re.IGNORECASE):
                    return ptype
        
        return None
    
    def generate_param_value(self, param_name: str) -> str:
        """
        根据参数名生成测试值
        
        Args:
            param_name: 参数名
        
        Returns:
            生成的测试值
        """
        ptype = self.guess_param_type(param_name)
        
        if ptype and ptype in self.PARAM_TYPE_PATTERNS:
            examples = self.PARAM_TYPE_PATTERNS[ptype]['examples']
            return examples[0]
        
        return 'test'
    
    def generate_fuzz_payloads(self, param_name: str) -> List[str]:
        """
        根据参数名生成 Fuzzing payload
        
        Returns:
            payload 列表
        """
        payloads = []
        
        ptype = self.guess_param_type(param_name)
        
        if ptype in ('id', 'page', 'size'):
            payloads.extend([
                '0', '-1', '999999',
                '1 OR 1=1',
                '1" OR "1"="1',
            ])
        
        elif ptype in ('username', 'email'):
            payloads.extend([
                "admin'--",
                "admin' OR '1'='1",
                "' OR 1=1--",
            ])
        
        elif ptype in ('password', 'passwd'):
            payloads.extend([
                'admin',
                'password',
                '123456',
                "admin'--",
            ])
        
        elif ptype == 'token':
            payloads.extend([
                'null',
                'undefined',
                'test_token',
                'Bearer eyJhbGciOiJIUzI1NiJ9',
            ])
        
        return list(set(payloads))
    
    def generate_multi_format_requests(
        self,
        method: str,
        url: str,
        params: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        生成多种格式的请求
        
        Args:
            method: HTTP 方法
            url: 请求 URL
            params: 参数字典
        
        Returns:
            请求列表，每种格式一个
        
        支持的格式:
        1. URL 参数模式 (Query String)
        2. JSON Body 模式 (application/json)
        3. Form Body 模式 (x-www-form-urlencoded)
        """
        requests = []
        
        method_upper = method.upper()
        
        if method_upper in ('GET', 'DELETE'):
            query_string = urlencode(params)
            separator = '&' if '?' in url else '?'
            requests.append({
                'method': method_upper,
                'url': f"{url}{separator}{query_string}" if params else url,
                'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
                'body': None,
                'format': 'query',
            })
        
        elif method_upper in ('POST', 'PUT', 'PATCH'):
            if not self.is_safe_method(method_upper) and self.safe_mode:
                logger.debug(f"Skipping unsafe method: {method_upper}")
                return requests
            
            has_unsafe_param = not all(self.is_safe_param(k) for k in params.keys())
            if has_unsafe_param and self.safe_mode:
                logger.debug(f"Skipping request with unsafe params: {params}")
                return requests
            
            requests.extend([
                {
                    'method': method_upper,
                    'url': url,
                    'headers': {'Content-Type': 'application/json'},
                    'body': json.dumps(params, ensure_ascii=False),
                    'format': 'json',
                },
                {
                    'method': method_upper,
                    'url': url,
                    'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
                    'body': urlencode(params),
                    'format': 'form',
                },
                {
                    'method': method_upper,
                    'url': url,
                    'headers': {'Content-Type': 'text/plain'},
                    'body': json.dumps(params, ensure_ascii=False),
                    'format': 'raw',
                },
            ])
        
        return requests
    
    def is_upload_endpoint(self, url: str, params: Dict[str, Any]) -> bool:
        """
        判断是否为文件上传接口
        
        Returns:
            True 表示是上传接口
        """
        url_lower = url.lower()
        param_str = ' '.join(str(k) + ' ' + str(v) for k, v in params.items()).lower()
        
        upload_keywords = ['upload', 'file', 'attach', 'avatar', 'image', 'photo', 'document']
        
        if any(kw in url_lower for kw in upload_keywords):
            return True
        
        if any(kw in param_str for kw in upload_keywords):
            return True
        
        file_params = ['file', 'files', 'upload', 'attachment', 'avatar', 'image', 'photo']
        if any(fp in param_str for fp in file_params):
            return True
        
        return False
    
    def generate_upload_test(self, url: str) -> List[Dict[str, Any]]:
        """
        生成文件上传测试请求
        
        Returns:
            上传测试请求列表
        """
        if not self.safe_mode:
            return []
        
        tests = []
        
        xss_content = b"<script>alert('XSS')</script>"
        txt_content = b"test content"
        
        tests.append({
            'method': 'POST',
            'url': url,
            'headers': {'Content-Type': 'multipart/form-data'},
            'files': {
                'file': ('test.html', xss_content, 'text/html'),
            },
            'format': 'upload_html',
        })
        
        tests.append({
            'method': 'POST',
            'url': url,
            'headers': {'Content-Type': 'multipart/form-data'},
            'files': {
                'file': ('test.txt', txt_content, 'text/plain'),
            },
            'format': 'upload_txt',
        })
        
        return tests
