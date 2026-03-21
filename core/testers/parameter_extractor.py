"""
API Parameter Extractor
API 参数提取器 - 从响应中智能提取参数
参考 0x727/ChkApi getParameter.py
"""

import re
import json
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass


@dataclass
class ExtractedParameter:
    """提取的参数"""
    name: str
    param_type: str  # path, query, body, json
    source: str  # response_key, error_message, request
    confidence: float  # 0.0-1.0
    example_value: Optional[str] = None


class APIParameterExtractor:
    """
    API 参数提取器
    
    支持三种参数提取方式：
    1. 从 JSON 响应中提取 key 作为参数
    2. 从错误信息中提取参数名
    3. 从请求参数中学习
    """
    
    def __init__(self):
        self.extracted_params: Set[str] = set()
        self.param_types: Dict[str, str] = {}
        
        self.error_patterns = [
            (r"'(.+?)' (?:is required|must be provided)", "required_field"),
            (r"parameter '(.+?)'", "parameter"),
            (r"field (.+?) is required", "required_field"),
            (r"(.+?) cannot be null", "not_null"),
            (r"(.+?) is missing", "missing_field"),
            (r"invalid (.+?)", "invalid_field"),
            (r"'(.+?)' parameter", "parameter"),
        ]
        
        self.value_patterns = [
            (r'"param"\s*:\s*"([^"]+)"', "param_value"),
            (r'"parameter"\s*:\s*"([^"]+)"', "parameter_value"),
        ]
    
    def extract_from_response(self, response_text: str) -> List[ExtractedParameter]:
        """
        从响应中提取参数
        
        Args:
            response_text: 响应文本
        
        Returns:
            提取的参数列表
        """
        params = []
        
        try:
            json_obj = json.loads(response_text)
            params.extend(self._extract_from_json(json_obj))
        except json.JSONDecodeError:
            params.extend(self._extract_from_text(response_text))
        
        return params
    
    def _extract_from_json(self, json_obj, path: str = "") -> List[ExtractedParameter]:
        """从 JSON 对象中提取参数"""
        params = []
        
        if isinstance(json_obj, dict):
            for key, value in json_obj.items():
                param_name = key
                
                if param_name not in self.extracted_params:
                    self.extracted_params.add(param_name)
                    
                    param_type = self._guess_param_type(key, value)
                    
                    params.append(ExtractedParameter(
                        name=param_name,
                        param_type=param_type,
                        source="response_key",
                        confidence=0.9 if value else 0.5,
                        example_value=str(value)[:50] if value else None
                    ))
                
                if isinstance(value, (dict, list)):
                    params.extend(self._extract_from_json(value, f"{path}.{key}"))
        
        elif isinstance(json_obj, list) and json_obj:
            params.extend(self._extract_from_json(json_obj[0], f"{path}[0]"))
        
        return params
    
    def _extract_from_text(self, text: str) -> List[ExtractedParameter]:
        """从文本中提取参数"""
        params = []
        
        for pattern, pattern_type in self.error_patterns:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                param_name = match.group(1).strip()
                
                if param_name and param_name not in self.extracted_params:
                    self.extracted_params.add(param_name)
                    
                    params.append(ExtractedParameter(
                        name=param_name,
                        param_type="error",
                        source=f"error_{pattern_type}",
                        confidence=0.7,
                        example_value=None
                    ))
        
        return params
    
    def extract_from_error(self, error_text: str) -> List[ExtractedParameter]:
        """从错误信息中提取参数"""
        params = []
        
        for pattern, pattern_type in self.error_patterns:
            matches = re.finditer(pattern, error_text, re.IGNORECASE)
            for match in matches:
                param_name = match.group(1).strip()
                
                if len(param_name) > 2 and len(param_name) < 50:
                    if param_name not in self.extracted_params:
                        self.extracted_params.add(param_name)
                        
                        params.append(ExtractedParameter(
                            name=param_name,
                            param_type="error",
                            source="error_message",
                            confidence=0.8,
                            example_value=None
                        ))
        
        return params
    
    def _guess_param_type(self, key: str, value: Any) -> str:
        """猜测参数类型"""
        key_lower = key.lower()
        
        if 'id' in key_lower:
            return 'path'
        elif 'name' in key_lower or 'title' in key_lower:
            return 'query'
        elif 'list' in key_lower or 'page' in key_lower:
            return 'query'
        elif isinstance(value, bool):
            return 'body'
        elif isinstance(value, (int, float)):
            return 'body'
        elif isinstance(value, str):
            if len(value) < 100:
                return 'body'
            return 'query'
        
        return 'body'
    
    def get_all_params(self) -> List[str]:
        """获取所有提取的参数名"""
        return list(self.extracted_params)
    
    def get_params_by_type(self, param_type: str) -> List[str]:
        """按类型获取参数"""
        return [p for p, t in self.param_types.items() if t == param_type]
    
    def merge(self, other: 'APIParameterExtractor'):
        """合并另一个提取器的结果"""
        self.extracted_params.update(other.extracted_params)
        self.param_types.update(other.param_types)


class DangerousAPIFilter:
    """
    危险 API 过滤器
    过滤可能造成破坏的 API 操作
    参考 0x727/ChkApi 规则
    """

    DANGEROUS_PATTERNS = [
        r'delete',
        r'drop',
        r'truncate',
        r'shutdown',
        r'reboot',
        r'restore',
        r'reset',
        r'backup',
        r'export',
        r'import',
        r'execute',
        r'run',
        r'stop',
        r'kill',
        r'abort',
        r'cancel',
        r'remove',
        r'uninstall',
        r'disable',
        r'enable',
        r'update',
        r'upgrade',
        r'create',
        r'add',
        r'edit',
        r'modify',
        r'change',
        r'replace',
        r'upload',
        r'download',
        r'submit',
        r'publish',
        r'unpublish',
        r'clear',
        r'wipe',
        r'destroy',
        r'revoke',
        r'黑名单',
        r'白名单',
        r'ban',
        r'unban',
        r'lock',
        r'unlock',
        r'close',
        r'open',
        r'start',
        r'suspend',
        r'resume',
        r'approve',
        r'reject',
        r'confirm',
        r'verify',
        r'sync',
        r'push',
        r'pull',
        r'connect',
        r'disconnect',
        r'install',
        r'deploy',
        r'undeploy',
        r'compile',
        r'build',
        r'test',
        r'debug',
    ]

    SAFE_PATTERNS = [
        r'get',
        r'list',
        r'query',
        r'search',
        r'fetch',
        r'read',
        r'view',
        r'show',
        r'detail',
        r'info',
        r'profile',
        r'status',
        r'check',
        r'validate',
        r'verify',
        r'stats',
        r'stastics',
        r'metrics',
        r'health',
        r'ping',
        r'count',
        r'sum',
        r'avg',
        r'min',
        r'max',
        r'config',
        r'setting',
        r'options',
        r'preferences',
    ]

    CRITICAL_DANGEROUS_PATTERNS = [
        r'delete\s*all',
        r'drop\s*table',
        r'drop\s*database',
        r'shutdown\s*now',
        r'reboot\s*now',
        r'truncate\s*table',
        r'exec\s*\(',
        r'execute\s*\(',
        r'shell_exec',
        r'eval\s*\(',
        r'system\s*\(',
    ]

    @classmethod
    def is_critical_dangerous(cls, api_path: str) -> bool:
        """判断是否为极度危险的API（直接拒绝）"""
        path_lower = api_path.lower()
        for pattern in cls.CRITICAL_DANGEROUS_PATTERNS:
            if re.search(pattern, path_lower):
                return True
        return False

    @classmethod
    def is_dangerous(cls, api_path: str) -> bool:
        """判断 API 是否危险"""
        if cls.is_critical_dangerous(api_path):
            return True

        path_lower = api_path.lower()
        dangerous_count = 0
        safe_count = 0

        for pattern in cls.DANGEROUS_PATTERNS:
            if re.search(pattern, path_lower):
                dangerous_count += 1

        for pattern in cls.SAFE_PATTERNS:
            if re.search(pattern, path_lower):
                safe_count += 1

        if dangerous_count > safe_count:
            return True

        return False

    @classmethod
    def is_safe(cls, api_path: str) -> bool:
        """判断 API 是否安全"""
        return not cls.is_dangerous(api_path)

    @classmethod
    def get_danger_level(cls, api_path: str) -> str:
        """获取危险等级: safe/low/medium/high/critical"""
        if cls.is_critical_dangerous(api_path):
            return "critical"
        if cls.is_dangerous(api_path):
            return "high"
        return "safe"


def create_parameter_extractor() -> APIParameterExtractor:
    """创建参数提取器"""
    return APIParameterExtractor()
