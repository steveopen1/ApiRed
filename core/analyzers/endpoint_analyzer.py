"""
Endpoint Analyzer - 端点特征分析器
分析API端点的特征，用于智能选择测试用例
"""

import re
from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass, field
from enum import Enum


class EndpointFeature(Enum):
    """端点特征类型"""
    HAS_URL_PARAM = "has_url_param"
    HAS_FILE_PARAM = "has_file_param"
    HAS_SEARCH_PARAM = "has_search_param"
    HAS_ID_PARAM = "has_id_param"
    HAS_USER_PARAM = "has_user_param"
    HAS_QUERY_PARAM = "has_query_param"
    HAS_BODY_PARAM = "has_body_param"
    HAS_AUTH_HEADER = "has_auth_header"
    HAS_JSON_RESPONSE = "has_json_response"
    HAS_HTML_RESPONSE = "has_html_response"
    IS_LOGIN_ENDPOINT = "is_login_endpoint"
    IS_ADMIN_ENDPOINT = "is_admin_endpoint"
    IS_USER_ENDPOINT = "is_user_endpoint"
    IS_SEARCH_ENDPOINT = "is_search_endpoint"
    IS_UPLOAD_ENDPOINT = "is_upload_endpoint"
    IS_DOWNLOAD_ENDPOINT = "is_download_endpoint"
    IS_API_ENDPOINT = "is_api_endpoint"
    HAS_SENSITIVE_DATA = "has_sensitive_data"
    IS_SENSITIVE_ENDPOINT = "is_sensitive_endpoint"


@dataclass
class EndpointFeatures:
    """端点特征集合"""
    path: str
    method: str
    features: Set[EndpointFeature] = field(default_factory=set)
    param_names: List[str] = field(default_factory=list)
    path_segments: List[str] = field(default_factory=list)
    response_content_type: str = ""
    detected_tech: List[str] = field(default_factory=list)
    
    def has_feature(self, feature: EndpointFeature) -> bool:
        return feature in self.features
    
    def has_any_feature(self, features: List[EndpointFeature]) -> bool:
        return bool(self.features & set(features))
    
    def has_all_features(self, features: List[EndpointFeature]) -> bool:
        return set(features).issubset(self.features)


class EndpointAnalyzer:
    """端点特征分析器"""
    
    URL_PARAM_PATTERNS = [
        r'url', r'uri', r'link', r'href', r'src', r'dst',
        r'redirect', r'return', r'callback', r'origin',
        r'request_url', r'image_url', r'file_url'
    ]
    
    FILE_PARAM_PATTERNS = [
        r'file', r'path', r'dir', r'directory', r'folder',
        r'doc', r'document', r'attachment', r'upload',
        r'name', r'filename', r'filepath'
    ]
    
    SEARCH_PARAM_PATTERNS = [
        r'q', r'query', r'search', r'keyword', r'kwd',
        r'search_term', r'search_query', r'qry',
        r'filter', r's', r'searchtext', r'text'
    ]
    
    ID_PARAM_PATTERNS = [
        r'id', r'uuid', r'uid', r'pk', r'key',
        r'object_id', r'resource_id', r'entity_id', r'item_id',
        r'user_id', r'order_id', r'product_id', r'post_id'
    ]
    
    USER_PARAM_PATTERNS = [
        r'user', r'username', r'user_id', r'account',
        r'owner', r'member', r'client', r'customer'
    ]
    
    SENSITIVE_PATH_PATTERNS = [
        r'admin', r'user', r'profile', r'account', r'login',
        r'auth', r'password', r'passwd', r'secret', r'key',
        r'token', r'credential', r'api_key', r'apikey',
        r'config', r'setting', r'private', r'sensitive'
    ]
    
    TECH_DETECTION_PATTERNS = {
        'php': [r'\.php', r'laravel', r'symfony'],
        'java': [r'\.do', r'spring', r'jsp', r'servlet'],
        'python': [r'flask', r'django', r'fastapi', r'__pycache__'],
        'nodejs': [r'node_modules', r'express', r'koa'],
        'ruby': [r'\.rb', r'rails', r'sinatra'],
        'go': [r'\.go', r'golang'],
        'aspnet': [r'\.aspx?', r'aspnet'],
    }
    
    def __init__(self):
        self._compiled_url_patterns = [
            re.compile(p, re.I) for p in self.URL_PARAM_PATTERNS
        ]
        self._compiled_file_patterns = [
            re.compile(p, re.I) for p in self.FILE_PARAM_PATTERNS
        ]
        self._compiled_search_patterns = [
            re.compile(p, re.I) for p in self.SEARCH_PARAM_PATTERNS
        ]
        self._compiled_id_patterns = [
            re.compile(p, re.I) for p in self.ID_PARAM_PATTERNS
        ]
        self._compiled_user_patterns = [
            re.compile(p, re.I) for p in self.USER_PARAM_PATTERNS
        ]
        self._compiled_sensitive_patterns = [
            re.compile(p, re.I) for p in self.SENSITIVE_PATH_PATTERNS
        ]
    
    def analyze(self, path: str, method: str = "GET", 
                parameters: Optional[List[str]] = None,
                response_content_type: str = "") -> EndpointFeatures:
        """
        分析端点特征
        
        Args:
            path: API路径
            method: HTTP方法
            parameters: 参数名列表
            response_content_type: 响应Content-Type
            
        Returns:
            EndpointFeatures: 端点特征集合
        """
        features = EndpointFeatures(
            path=path,
            method=method.upper(),
            param_names=parameters or [],
            path_segments=self._extract_path_segments(path),
            response_content_type=response_content_type
        )
        
        all_params = parameters or []
        
        for param in all_params:
            param_lower = param.lower()
            
            if any(p.match(param_lower) for p in self._compiled_url_patterns):
                features.features.add(EndpointFeature.HAS_URL_PARAM)
            
            if any(p.match(param_lower) for p in self._compiled_file_patterns):
                features.features.add(EndpointFeature.HAS_FILE_PARAM)
            
            if any(p.match(param_lower) for p in self._compiled_search_patterns):
                features.features.add(EndpointFeature.HAS_SEARCH_PARAM)
            
            if any(p.match(param_lower) for p in self._compiled_id_patterns):
                features.features.add(EndpointFeature.HAS_ID_PARAM)
            
            if any(p.match(param_lower) for p in self._compiled_user_patterns):
                features.features.add(EndpointFeature.HAS_USER_PARAM)
        
        path_lower = path.lower()
        
        if any(p in path_lower for p in ['/login', '/auth', '/signin']):
            features.features.add(EndpointFeature.IS_LOGIN_ENDPOINT)
        
        if any(p.search(path_lower) for p in self._compiled_sensitive_patterns):
            features.features.add(EndpointFeature.IS_SENSITIVE_ENDPOINT)
            features.features.add(EndpointFeature.HAS_SENSITIVE_DATA)
        
        if '/admin' in path_lower:
            features.features.add(EndpointFeature.IS_ADMIN_ENDPOINT)
        
        if '/user' in path_lower or '/profile' in path_lower:
            features.features.add(EndpointFeature.IS_USER_ENDPOINT)
        
        if '/search' in path_lower or '/query' in path_lower:
            features.features.add(EndpointFeature.IS_SEARCH_ENDPOINT)
        
        if '/upload' in path_lower or '/file' in path_lower:
            features.features.add(EndpointFeature.IS_UPLOAD_ENDPOINT)
        
        if '/download' in path_lower:
            features.features.add(EndpointFeature.IS_DOWNLOAD_ENDPOINT)
        
        if '/api' in path_lower or path.startswith('/api/'):
            features.features.add(EndpointFeature.IS_API_ENDPOINT)
        
        if method.upper() in ['POST', 'PUT', 'PATCH']:
            features.features.add(EndpointFeature.HAS_BODY_PARAM)
        
        if response_content_type:
            if 'json' in response_content_type.lower():
                features.features.add(EndpointFeature.HAS_JSON_RESPONSE)
            if 'html' in response_content_type.lower():
                features.features.add(EndpointFeature.HAS_HTML_RESPONSE)
        
        features.detected_tech = self._detect_tech(path)
        
        return features
    
    def _extract_path_segments(self, path: str) -> List[str]:
        """提取路径段"""
        segments = []
        for segment in path.split('/'):
            if segment:
                segments.append(segment)
        return segments
    
    def _detect_tech(self, path: str) -> List[str]:
        """检测技术栈"""
        detected = []
        path_lower = path.lower()
        
        for tech, patterns in self.TECH_DETECTION_PATTERNS.items():
            if any(re.search(p, path_lower) for p in patterns):
                detected.append(tech)
        
        return detected


def extract_features_from_endpoint(endpoint) -> EndpointFeatures:
    """
    从APIEndpoint对象提取特征
    
    Args:
        endpoint: APIEndpoint对象
        
    Returns:
        EndpointFeatures: 端点特征集合
    """
    analyzer = EndpointAnalyzer()
    
    parameters = []
    if hasattr(endpoint, 'parameters') and endpoint.parameters:
        if isinstance(endpoint.parameters, list):
            parameters = endpoint.parameters
        elif isinstance(endpoint.parameters, dict):
            parameters = list(endpoint.parameters.keys())
    
    response_content_type = ""
    if hasattr(endpoint, 'response_sample') and endpoint.response_sample:
        if isinstance(endpoint.response_sample, str):
            if '{' in endpoint.response_sample or '"' in endpoint.response_sample:
                response_content_type = "application/json"
    
    return analyzer.analyze(
        path=endpoint.path,
        method=endpoint.method,
        parameters=parameters,
        response_content_type=response_content_type
    )
