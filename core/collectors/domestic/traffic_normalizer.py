"""
Traffic Normalizer Module
流量格式标准化模块 - 统一不同来源的流量格式

支持:
- HAR (HTTP Archive Format)
- BurpSuite JSON
- 通用HTTP请求/响应
"""

import json
import base64
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import parse_qs, urlencode


@dataclass
class NormalizedRequest:
    """标准化请求"""
    url: str
    method: str
    headers: Dict[str, str]
    body: Optional[str] = None
    content_type: str = ""
    cookies: str = ""
    timestamp: float = 0.0
    source: str = ""


@dataclass
class NormalizedResponse:
    """标准化响应"""
    status_code: int
    headers: Dict[str, str]
    body: Optional[str] = None
    content_type: str = ""
    content_length: int = 0
    timestamp: float = 0.0


@dataclass
class NormalizedEntry:
    """标准化流量条目"""
    request: NormalizedRequest
    response: Optional[NormalizedResponse]
    source_type: str


class TrafficNormalizer:
    """
    流量格式标准化器
    将不同来源的流量转换为统一格式
    """
    
    @staticmethod
    def normalize_har_entry(entry: Dict[str, Any]) -> Optional[NormalizedEntry]:
        """
        标准化HAR条目
        
        Args:
            entry: HAR entry字典
            
        Returns:
            NormalizedEntry或None
        """
        try:
            request_data = entry.get('request', {})
            response_data = entry.get('response', {})
            
            headers = TrafficNormalizer._parse_har_headers(request_data.get('headers', []))
            
            body = None
            if request_data.get('postData'):
                post_data = request_data['postData']
                if 'text' in post_data:
                    body = post_data['text']
            
            normalized_request = NormalizedRequest(
                url=request_data.get('url', ''),
                method=request_data.get('method', 'GET'),
                headers=headers,
                body=body,
                content_type=headers.get('Content-Type', ''),
                cookies=request_data.get('cookies', ''),
                timestamp=entry.get('startedDateTime', ''),
                source='har'
            )
            
            normalized_response = None
            if response_data:
                resp_headers = TrafficNormalizer._parse_har_headers(response_data.get('headers', []))
                
                resp_body = None
                if response_data.get('content'):
                    content = response_data['content']
                    if 'text' in content:
                        resp_body = content['text']
                
                normalized_response = NormalizedResponse(
                    status_code=response_data.get('status', 0),
                    headers=resp_headers,
                    body=resp_body,
                    content_type=resp_headers.get('Content-Type', ''),
                    content_length=response_data.get('content', {}).get('size', 0),
                    timestamp=response_data.get('startedDateTime', '')
                )
            
            return NormalizedEntry(
                request=normalized_request,
                response=normalized_response,
                source_type='har'
            )
        except Exception:
            return None
    
    @staticmethod
    def _parse_har_headers(headers: List[Dict[str, str]]) -> Dict[str, str]:
        """解析HAR格式的headers"""
        result = {}
        for header in headers:
            name = header.get('name', '')
            value = header.get('value', '')
            if name:
                result[name.lower()] = value
        return result
    
    @staticmethod
    def normalize_burp_entry(entry: Dict[str, Any]) -> Optional[NormalizedEntry]:
        """
        标准化BurpSuite条目
        
        Args:
            entry: Burp entry字典
            
        Returns:
            NormalizedEntry或None
        """
        try:
            request_data = entry.get('request', {})
            response_data = entry.get('response', {})
            
            url = entry.get('url', '')
            method = entry.get('method', 'GET')
            
            headers = {}
            if isinstance(request_data, dict):
                headers = request_data.get('headers', {})
            else:
                header_str = request_data.decode('utf-8', errors='ignore') if isinstance(request_data, bytes) else str(request_data)
                for line in header_str.split('\r\n'):
                    if ':' in line:
                        key, value = line.split(':', 1)
                        headers[key.strip().lower()] = value.strip()
            
            body = None
            if isinstance(request_data, dict):
                body = request_data.get('body')
            elif isinstance(request_data, bytes):
                body = request_data.decode('utf-8', errors='ignore')
            
            normalized_request = NormalizedRequest(
                url=url,
                method=method,
                headers=headers,
                body=body,
                content_type=headers.get('content-type', ''),
                cookies=headers.get('cookie', ''),
                timestamp=entry.get('timestamp', 0),
                source='burp'
            )
            
            normalized_response = None
            if response_data:
                resp_headers = {}
                resp_body = None
                
                if isinstance(response_data, dict):
                    resp_headers = response_data.get('headers', {})
                    resp_body = response_data.get('body')
                elif isinstance(response_data, bytes):
                    resp_str = response_data.decode('utf-8', errors='ignore')
                    parts = resp_str.split('\r\n\r\n', 1)
                    if len(parts) == 2:
                        header_lines = parts[0].split('\r\n')
                        for line in header_lines:
                            if ':' in line:
                                key, value = line.split(':', 1)
                                resp_headers[key.strip().lower()] = value.strip()
                        resp_body = parts[1]
                
                status_code = 200
                if isinstance(response_data, dict):
                    status_code = response_data.get('status_code', 200)
                
                normalized_response = NormalizedResponse(
                    status_code=status_code,
                    headers=resp_headers,
                    body=resp_body,
                    content_type=resp_headers.get('content-type', ''),
                    content_length=len(resp_body) if resp_body else 0,
                    timestamp=entry.get('timestamp', 0)
                )
            
            return NormalizedEntry(
                request=normalized_request,
                response=normalized_response,
                source_type='burp'
            )
        except Exception:
            return None
    
    @staticmethod
    def extract_params(url: str, body: Optional[str] = None) -> Dict[str, Any]:
        """
        提取请求参数
        
        Args:
            url: 请求URL
            body: 请求体
            
        Returns:
            参数字典
        """
        params = {}
        
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        if parsed.query:
            query_params = parse_qs(parsed.query)
            for key, values in query_params.items():
                params[key] = values[0] if values else ''
        
        if body:
            try:
                if 'application/json' in str(body)[:100]:
                    import json
                    json_params = json.loads(body)
                    if isinstance(json_params, dict):
                        params.update(json_params)
                elif '&' in body:
                    for pair in body.split('&'):
                        if '=' in pair:
                            key, value = pair.split('=', 1)
                            params[key] = value
            except Exception:
                pass
        
        return params
    
    @staticmethod
    def is_api_url(url: str) -> bool:
        """
        判断是否为API URL
        
        Args:
            url: URL
            
        Returns:
            bool
        """
        from urllib.parse import urlparse
        parsed = urlparse(url.lower())
        path = parsed.path
        
        api_indicators = [
            '/api/', '/v1/', '/v2/', '/v3/',
            '/rest/', '/graphql', '/gql/',
            '/rpc/', '/jsonrpc',
            '/oauth/', '/auth/',
            '/openapi/', '/swagger',
        ]
        
        for indicator in api_indicators:
            if indicator in path:
                return True
        
        static_extensions = ['.js', '.css', '.png', '.jpg', '.gif', '.svg', '.ico', '.woff', '.woff2']
        for ext in static_extensions:
            if path.endswith(ext):
                return False
        
        return True
