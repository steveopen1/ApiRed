"""
HAR Collector Module
HAR文件导入模块 - 解析HAR格式文件,提取API端点

参考: HAR 1.2 Specification https://w3c.github.io/web-performance/specs/HAR/Overview.html
"""

import json
import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin
from datetime import datetime

from core.models import APIEndpoint
from core.storage import DBStorage


@dataclass
class HARParseResult:
    """HAR解析结果"""
    total_requests: int = 0
    domain_groups: Dict[str, List[APIEndpoint]] = field(default_factory=dict)
    endpoints: List[APIEndpoint] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    file_name: str = ""
    file_size: int = 0
    imported_at: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


class HARCollector:
    """
    HAR文件采集器
    支持解析HAR 1.2格式,提取API端点
    """
    
    HTTP_METHODS = {'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'}
    
    API_PATTERNS = [
        r'/api/[^\s"\'<>]+',
        r'/v\d+/[^\s"\'<>]+',
        r'/rest/[^\s"\'<>]+',
        r'/graphql',
        r'/[a-z]+/[a-z]+[^\s"\'<>]*',
    ]
    
    def __init__(self, storage: Optional[DBStorage] = None):
        """
        初始化HAR采集器
        
        Args:
            storage: 数据库存储实例
        """
        self.storage = storage
        self._endpoints: List[APIEndpoint] = []
        self._domain_groups: Dict[str, List[APIEndpoint]] = {}
        self._errors: List[str] = []
        self._seen_urls: set = set()
    
    def parse_file(self, har_path: str) -> HARParseResult:
        """
        解析HAR文件
        
        Args:
            har_path: HAR文件路径
            
        Returns:
            HARParseResult: 解析结果
        """
        import os
        try:
            file_size = os.path.getsize(har_path)
            with open(har_path, 'r', encoding='utf-8') as f:
                har_content = f.read()
            return self.parse_content(har_content, file_name=os.path.basename(har_path))
        except Exception as e:
            self._errors.append(f"Failed to read HAR file: {str(e)}")
            return HARParseResult(errors=self._errors)
    
    def parse_content(self, har_content: str, file_name: str = "") -> HARParseResult:
        """
        解析HAR内容
        
        Args:
            har_content: HAR文件JSON内容
            file_name: 文件名
            
        Returns:
            HARParseResult: 解析结果
        """
        try:
            har_data = json.loads(har_content)
        except json.JSONDecodeError as e:
            self._errors.append(f"Invalid JSON format: {str(e)}")
            return HARParseResult(errors=self._errors)
        
        if 'log' not in har_data:
            self._errors.append("Invalid HAR format: missing 'log' key")
            return HARParseResult(errors=self._errors)
        
        log = har_data['log']
        entries = log.get('entries', [])
        
        self._endpoints = []
        self._domain_groups = {}
        self._seen_urls = set()
        
        for entry in entries:
            try:
                self._parse_entry(entry)
            except Exception as e:
                self._errors.append(f"Failed to parse entry: {str(e)}")
        
        self._deduplicate_endpoints()
        
        for endpoint in self._endpoints:
            domain = urlparse(endpoint.base_url).netloc or urlparse(endpoint.full_url).netloc
            if domain:
                if domain not in self._domain_groups:
                    self._domain_groups[domain] = []
                self._domain_groups[domain].append(endpoint)
        
        return HARParseResult(
            total_requests=len(entries),
            domain_groups=self._domain_groups,
            endpoints=self._endpoints,
            errors=self._errors,
            file_name=file_name,
            file_size=len(har_content.encode('utf-8'))
        )
    
    def _parse_entry(self, entry: Dict[str, Any]) -> None:
        """解析单个HAR条目"""
        request = entry.get('request', {})
        if not request:
            return
        
        url = request.get('url', '')
        if not url:
            return
        
        parsed_url = urlparse(url)
        
        if self._is_static_resource(parsed_url):
            return
        
        method = request.get('method', 'GET').upper()
        if method not in self.HTTP_METHODS:
            method = 'GET'
        
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        path = parsed_url.path
        
        if not path:
            path = '/'
        
        if parsed_url.query:
            path = f"{path}?{parsed_url.query}"
        
        endpoint = APIEndpoint(
            path=path,
            method=method,
            base_url=base_url,
            full_url=url,
            sources=[{'source_type': 'har', 'url': url}],
            headers=dict(request.get('headers', [])) if isinstance(request.get('headers'), list) else {},
            cookies=request.get('cookies', ''),
        )
        
        self._extract_api_from_url(endpoint)
        
        if self.storage:
            self.storage.insert_api(endpoint.to_dict())
    
    def _is_static_resource(self, parsed_url) -> bool:
        """判断是否为静态资源"""
        static_extensions = {
            '.js', '.css', '.scss', '.sass', '.less',
            '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.webp', '.bmp',
            '.woff', '.woff2', '.ttf', '.eot', '.otf',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx',
            '.zip', '.tar', '.gz', '.rar',
        }
        
        path_lower = parsed_url.path.lower()
        for ext in static_extensions:
            if path_lower.endswith(ext):
                return True
        
        query = parsed_url.query.lower()
        static_keywords = ['.min.js', '.min.css', 'favicon', 'data:image']
        for keyword in static_keywords:
            if keyword in path_lower or keyword in query:
                return True
        
        return False
    
    def _extract_api_from_url(self, endpoint: APIEndpoint) -> None:
        """从URL中提取API路径"""
        url_lower = endpoint.full_url.lower()
        
        for pattern in self.API_PATTERNS:
            matches = re.findall(pattern, url_lower)
            for match in matches:
                if match and len(match) > 2:
                    endpoint.path = match
                    break
    
    def _deduplicate_endpoints(self) -> None:
        """去重端点"""
        unique_endpoints = []
        seen = set()
        
        for endpoint in self._endpoints:
            key = f"{endpoint.method}:{endpoint.full_url}"
            if key not in seen:
                seen.add(key)
                unique_endpoints.append(endpoint)
        
        self._endpoints = unique_endpoints
    
    def get_api_endpoints(self) -> List[APIEndpoint]:
        """获取提取的API端点列表"""
        return self._endpoints
    
    def save_to_database(self) -> bool:
        """保存到数据库"""
        if not self.storage:
            return False
        
        try:
            for endpoint in self._endpoints:
                self.storage.insert_api(endpoint.to_dict())
            
            if hasattr(self.storage, 'conn'):
                self.storage.conn.execute("""
                    INSERT INTO har_imports (file_name, file_size, total_requests, total_endpoints, domains)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    '',
                    0,
                    self._parse_result.total_requests if hasattr(self, '_parse_result') else 0,
                    len(self._endpoints),
                    json.dumps(list(self._domain_groups.keys()))
                ))
                self.storage.conn.commit()
            return True
        except Exception as e:
            print(f"Failed to save to database: {e}")
            return False
