"""
BurpSuite Collector Module
BurpSuite联动模块 - 导入BurpSuite导出的流量,支持JSON格式和REST API

参考: BurpSuite REST API Documentation
"""

import json
import base64
import asyncio
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse

from core.models import APIEndpoint
from core.storage import DBStorage


@dataclass
class BurpParseResult:
    """Burp解析结果"""
    total_requests: int = 0
    domain_groups: Dict[str, List[APIEndpoint]] = field(default_factory=dict)
    endpoints: List[APIEndpoint] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    source_type: str = "file"
    source_path: str = ""
    imported_at: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


class BurpCollector:
    """
    BurpSuite流量采集器
    支持:
    - 解析BurpSuite导出的JSON文件
    - 通过REST API实时拉取流量
    """
    
    HTTP_METHODS = {'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'}
    
    def __init__(self, storage: Optional[DBStorage] = None):
        """
        初始化Burp采集器
        
        Args:
            storage: 数据库存储实例
        """
        self.storage = storage
        self._endpoints: List[APIEndpoint] = []
        self._domain_groups: Dict[str, List[APIEndpoint]] = {}
        self._errors: List[str] = []
        self._seen_urls: set = set()
        self._api_base_url: str = ""
        self._api_key: str = ""
        self._client: Optional[Any] = None
    
    def parse_json_file(self, burp_json_path: str) -> BurpParseResult:
        """
        解析BurpSuite导出的JSON文件
        
        Args:
            burp_json_path: Burp JSON文件路径
            
        Returns:
            BurpParseResult: 解析结果
        """
        import os
        try:
            with open(burp_json_path, 'r', encoding='utf-8') as f:
                burp_data = json.load(f)
            return self.parse_json_content(burp_data, file_path=burp_json_path)
        except json.JSONDecodeError as e:
            self._errors.append(f"Invalid JSON format: {str(e)}")
            return BurpParseResult(errors=self._errors)
        except Exception as e:
            self._errors.append(f"Failed to read file: {str(e)}")
            return BurpParseResult(errors=self._errors)
    
    def parse_json_content(self, burp_data: Any, file_path: str = "") -> BurpParseResult:
        """
        解析BurpSuite JSON内容
        
        Args:
            burp_data: Burp数据字典或列表
            file_path: 文件路径
            
        Returns:
            BurpParseResult: 解析结果
        """
        self._endpoints = []
        self._domain_groups = {}
        self._seen_urls = set()
        
        try:
            if isinstance(burp_data, dict):
                if 'messages' in burp_data:
                    entries = burp_data['messages']
                elif 'log' in burp_data:
                    entries = burp_data['log']
                else:
                    entries = [burp_data]
            elif isinstance(burp_data, list):
                entries = burp_data
            else:
                self._errors.append("Unknown Burp data format")
                return BurpParseResult(errors=self._errors)
            
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
            
            return BurpParseResult(
                total_requests=len(entries),
                domain_groups=self._domain_groups,
                endpoints=self._endpoints,
                errors=self._errors,
                source_type="file",
                source_path=file_path
            )
        except Exception as e:
            self._errors.append(f"Failed to parse content: {str(e)}")
            return BurpParseResult(errors=self._errors)
    
    def _parse_entry(self, entry: Dict[str, Any]) -> None:
        """解析单个Burp条目"""
        request = entry.get('request', {})
        if isinstance(request, dict):
            url = request.get('url', '')
            method = request.get('method', 'GET')
        elif isinstance(request, bytes):
            url, method = self._parse_raw_request(request)
        else:
            url = entry.get('url', '')
            method = entry.get('method', 'GET')
        
        if not url:
            return
        
        parsed_url = urlparse(url)
        
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        path = parsed_url.path
        
        if not path:
            path = '/'
        
        if parsed_url.query:
            path = f"{path}?{parsed_url.query}"
        
        endpoint = APIEndpoint(
            path=path,
            method=method.upper(),
            base_url=base_url,
            full_url=url,
            sources=[{'source_type': 'burp', 'url': url}],
        )
        
        if self.storage:
            self.storage.insert_api(endpoint.to_dict())
        
        self._endpoints.append(endpoint)
    
    def _parse_raw_request(self, raw_request: bytes) -> tuple:
        """解析原始请求数据"""
        try:
            decoded = raw_request.decode('utf-8', errors='ignore')
            lines = decoded.split('\r\n')
            if not lines:
                return '', 'GET'
            
            request_line = lines[0]
            parts = request_line.split(' ')
            if len(parts) >= 2:
                method = parts[0].upper()
                url = parts[1]
            else:
                method = 'GET'
                url = ''
            
            return url, method
        except Exception:
            return '', 'GET'
    
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
    
    async def connect_api(self, api_url: str, api_key: str) -> bool:
        """
        连接BurpSuite REST API
        
        Args:
            api_url: BurpSuite API端点 (如 http://localhost:1337)
            api_key: API密钥
            
        Returns:
            bool: 连接是否成功
        """
        self._api_base_url = api_url.rstrip('/')
        self._api_key = api_key
        
        try:
            import aiohttp
            headers = {
                'Authorization': f'Bearer {api_key}',
                'Content-Type': 'application/json'
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f'{self._api_base_url}/v0.1/scan',
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status in [200, 401, 403]:
                        self._client = session
                        return True
                    return False
        except Exception as e:
            self._errors.append(f"Failed to connect to BurpSuite API: {str(e)}")
            return False
    
    async def fetch_traffic(self, limit: int = 1000) -> BurpParseResult:
        """
        从BurpSuite API拉取流量
        
        Args:
            limit: 最大拉取条数
            
        Returns:
            BurpParseResult: 流量数据
        """
        if not self._client:
            self._errors.append("Not connected to BurpSuite API")
            return BurpParseResult(errors=self._errors)
        
        try:
            import aiohttp
            headers = {
                'Authorization': f'Bearer {self._api_key}',
                'Content-Type': 'application/json'
            }
            
            all_entries = []
            offset = 0
            batch_size = 100
            
            while offset < limit:
                async with self._client.get(
                    f'{self._api_base_url}/v0.1/proxy/history',
                    headers=headers,
                    params={'offset': offset, 'size': batch_size},
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status != 200:
                        self._errors.append(f"API returned status {response.status}")
                        break
                    
                    data = await response.json()
                    entries = data.get('messages', [])
                    if not entries:
                        break
                    
                    all_entries.extend(entries)
                    offset += batch_size
            
            self._endpoints = []
            self._domain_groups = {}
            self._seen_urls = set()
            
            for entry in all_entries[:limit]:
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
            
            return BurpParseResult(
                total_requests=len(all_entries),
                domain_groups=self._domain_groups,
                endpoints=self._endpoints,
                errors=self._errors,
                source_type="api",
                source_path=self._api_base_url
            )
        except Exception as e:
            self._errors.append(f"Failed to fetch traffic: {str(e)}")
            return BurpParseResult(errors=self._errors)
    
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
            return True
        except Exception as e:
            print(f"Failed to save to database: {e}")
            return False
