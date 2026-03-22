"""
Fuzz Learner Module
参数学习器 - 从被动捕获学习参数模式
"""

import re
from typing import Dict, List, Set, Any, Optional
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs
from collections import defaultdict


@dataclass
class ParamPattern:
    """参数模式"""
    name: str
    values: List[str]
    occurrence: int = 0
    contexts: List[str] = field(default_factory=list)
    
    def add_occurrence(self, context: str = ''):
        self.occurrence += 1
        if context and context not in self.contexts:
            self.contexts.append(context)


class FuzzLearner:
    """
    Fuzz参数学习器
    从被动捕获的流量中学习参数命名和值模式
    """
    
    COMMON_PARAMS = {
        'id': ['1', '100', '1000', '999999', 'admin', '0', '-1', 'null'],
        'user_id': ['1', '1001', '10001', '99999', '0', 'admin'],
        'page': ['1', '2', '10', '100', '999', '0', '-1'],
        'page_num': ['1', '2', '10', '100'],
        'page_size': ['10', '20', '50', '100', '999', '-1'],
        'size': ['10', '20', '50', '100', '500'],
        'limit': ['10', '20', '50', '100', '1000'],
        'offset': ['0', '1', '10', '100', '1000'],
        'keyword': ['test', 'admin', 'select', 'update'],
        'query': ['test', 'admin', 'select', 'update'],
        'search': ['test', 'admin', 'select'],
        'q': ['test', 'admin', '123456', '1=1'],
        'order': ['asc', 'desc', 'ASC', 'DESC'],
        'sort': ['asc', 'desc', 'id', 'create_time'],
        'status': ['0', '1', 'true', 'false'],
        'type': ['1', '2', '10', '100', 'admin', 'vip'],
        'category': ['1', '2', '10', '100'],
        'tag': ['1', '2', '10', 'test'],
        'channel': ['1', '2', '10', '100'],
        'level': ['1', '2', '10', '100', 'admin'],
        'role': ['1', '2', 'admin', 'user', 'vip'],
        'vip': ['0', '1', 'true', 'false'],
        'admin': ['0', '1', 'true', 'false'],
        'phone': ['13800138000', '13900139000', '12345678901'],
        'email': ['test@test.com', 'admin@test.com'],
        'code': ['1234', '123456', '000000'],
        'token': ['test', 'admin', 'eyJhbGciOiJIUzI1NiJ9'],
        'uid': ['1', '1001', '10001'],
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
        ],
        'xss': [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
        ],
        'ssrf': [
            "http://localhost",
            "http://127.0.0.1",
            "http://0.0.0.0",
            "http://169.254.169.254",
        ],
        'idor': [
            "999999",
            "0",
            "-1",
            "1000000",
            "../admin",
        ],
    }
    
    def __init__(self):
        self.param_patterns: Dict[str, List[ParamPattern]] = {}
        self.domain_patterns: Dict[str, Dict[str, List[ParamPattern]]] = defaultdict(dict)
        self.learned_params: Set[str] = set()
    
    def learn_from_url(self, url: str, context: str = '') -> List[str]:
        """
        从URL学习参数
        
        Args:
            url: URL
            context: 上下文信息
            
        Returns:
            List[str]: 学习到的参数列表
        """
        try:
            parsed = urlparse(url)
            
            if parsed.query:
                params = parse_qs(parsed.query)
                for name, values in params.items():
                    self.learn_param(name, values[0] if values else '', context)
                    return list(params.keys())
        
        except Exception:
            pass
        
        return []
    
    def learn_from_params(self, params: Dict[str, Any], context: str = ''):
        """
        从参数字典学习
        
        Args:
            params: 参数字典
            context: 上下文信息
        """
        for name, value in params.items():
            if isinstance(value, str):
                self.learn_param(name, value, context)
            elif isinstance(value, list) and value:
                self.learn_param(name, str(value[0]) if value else '', context)
            elif value is not None:
                self.learn_param(name, str(value), context)
    
    def learn_param(self, name: str, value: str, context: str = ''):
        """
        学习单个参数
        
        Args:
            name: 参数名
            value: 参数值
            context: 上下文信息
        """
        self.learned_params.add(name)
        
        if name not in self.param_patterns:
            self.param_patterns[name] = []
        
        patterns = self.param_patterns[name]
        
        existing = next((p for p in patterns if p.values and p.values[0] == value), None)
        if existing:
            existing.add_occurrence(context)
        else:
            pattern = ParamPattern(name=name, values=[value], occurrence=1)
            if context:
                pattern.contexts.append(context)
            patterns.append(pattern)
        
        patterns.sort(key=lambda p: p.occurrence, reverse=True)
    
    def learn_from_captures(self, captures: List[Any]):
        """
        从捕获列表批量学习
        
        Args:
            captures: 捕获列表 (可以是字典或对象)
        """
        for capture in captures:
            try:
                url = getattr(capture, 'request_url', None) or capture.get('request_url', '')
                
                params = getattr(capture, 'request_content', None) or capture.get('request_content', '')
                
                if isinstance(params, str):
                    try:
                        import json
                        params = json.loads(params)
                    except Exception:
                        params_dict = {}
                        for pair in params.split('&'):
                            if '=' in pair:
                                k, v = pair.split('=', 1)
                                params_dict[k] = v
                        params = params_dict
                
                if isinstance(params, dict):
                    self.learn_from_params(params, url)
                
                self.learn_from_url(url, '')
            
            except Exception as e:
                print(f'Learn from capture error: {e}')
    
    def get_params_for_domain(self, domain: str) -> Dict[str, List[str]]:
        """
        获取域名的参数模式
        
        Args:
            domain: 域名
            
        Returns:
            Dict[str, List[str]]: 参数名到值的映射
        """
        if domain in self.domain_patterns:
            result = {}
            for name, patterns in self.domain_patterns[domain].items():
                if patterns:
                    result[name] = list(patterns[0].values)
            return result
        
        return {}
    
    def add_domain_pattern(self, domain: str, name: str, values: List[str]):
        """
        添加域名特定参数
        
        Args:
            domain: 域名
            name: 参数名
            values: 参数值列表
        """
        if domain not in self.domain_patterns:
            self.domain_patterns[domain] = {}
        
        pattern = ParamPattern(name=name, values=values, occurrence=1)
        self.domain_patterns[domain][name] = pattern
    
    def export_params(self) -> Dict[str, List[str]]:
        """
        导出所有学习的参数
        
        Returns:
            Dict[str, List[str]]: 参数名到值的映射
        """
        result = {}
        
        for name, patterns in self.param_patterns.items():
            if patterns:
                result[name] = list(patterns[0].values)
        
        return result
    
    def export_all_payloads(self) -> Dict[str, List[str]]:
        """
        导出所有Fuzz payload
        
        Returns:
            Dict[str, List[str]]: 类别到payload列表的映射
        """
        return self.FUZZ_PAYLOADS.copy()
    
    def get_fuzz_payloads(self, category: str = 'sql_injection') -> List[str]:
        """
        获取指定类别的Fuzz payload
        
        Args:
            category: payload类别
            
        Returns:
            List[str]: payload列表
        """
        return self.FUZZ_PAYLOADS.get(category, [])
    
    def generate_fuzz_dict(self) -> Dict[str, List[str]]:
        """
        生成完整的Fuzz字典
        
        Returns:
            Dict[str, List[str]]: 完整字典
        """
        result = self.COMMON_PARAMS.copy()
        
        for name, patterns in self.param_patterns.items():
            if patterns:
                result[name] = list(patterns[0].values)[:10]
        
        return result
    
    def merge(self, other: 'FuzzLearner'):
        """
        合并另一个学习器的结果
        
        Args:
            other: 另一个FuzzLearner
        """
        for name, patterns in other.param_patterns.items():
            for pattern in patterns:
                for value in pattern.values:
                    self.learn_param(name, value, '')
        
        for domain, patterns_dict in other.domain_patterns.items():
            for name, pattern in patterns_dict.items():
                if domain not in self.domain_patterns:
                    self.domain_patterns[domain] = {}
                self.domain_patterns[domain][name] = pattern
