"""
Postman Collection 导入器

支持导入:
1. Postman Collection v2.1 (JSON)
2. Postman Collection v2.0 (JSON)
3. Postman Environment (JSON)

参考: Akto 支持的 Postman 导入
"""

import json
import logging
import re
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


@dataclass
class PostmanRequest:
    """Postman 请求"""
    name: str
    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    content_type: str = ""
    description: str = ""


@dataclass
class PostmanEndpoint:
    """Postman API 端点"""
    name: str
    method: str
    path: str
    full_url: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    params: Dict[str, Any] = field(default_factory=dict)
    description: str = ""
    collection: str = ""
    folder: str = ""


class PostmanCollectionImporter:
    """
    Postman Collection 导入器
    
    支持格式:
    - Postman Collection v2.1
    - Postman Collection v2.0
    - Postman Environment
    """

    def __init__(self):
        self.endpoints: List[PostmanEndpoint] = []
        self.collections: List[str] = []
        self.global_variables: Dict[str, str] = {}

    def import_collection(self, json_content: str) -> List[PostmanEndpoint]:
        """
        导入 Postman Collection
        
        Args:
            json_content: Collection JSON 内容
            
        Returns:
            PostmanEndpoint 列表
        """
        try:
            data = json.loads(json_content)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON: {e}")
            return []
        
        info = data.get('info', {})
        collection_name = info.get('name', 'Unknown Collection')
        self.collections.append(collection_name)
        
        variable = data.get('variable', [])
        for var in variable:
            if 'key' in var and 'value' in var:
                self.global_variables[var['key']] = var['value']
        
        items = data.get('item', [])
        self._parse_items(items, collection_name, '')
        
        logger.info(f"Imported {len(self.endpoints)} endpoints from Postman Collection '{collection_name}'")
        return self.endpoints

    def _parse_items(self, items: List, collection_name: str, folder_path: str):
        """递归解析 Postman items"""
        for item in items:
            if isinstance(item, dict):
                if 'request' in item:
                    endpoint = self._parse_request(item, collection_name, folder_path)
                    if endpoint:
                        self.endpoints.append(endpoint)
                
                elif 'item' in item:
                    item_name = item.get('name', '')
                    new_folder_path = f"{folder_path}/{item_name}" if folder_path else item_name
                    self._parse_items(item['item'], collection_name, new_folder_path)

    def _parse_request(self, item: Dict, collection_name: str, folder_path: str) -> Optional[PostmanEndpoint]:
        """解析单个请求"""
        try:
            request_data = item.get('request', {})
            
            name = item.get('name', request_data.get('name', 'Unnamed'))
            method = request_data.get('method', 'GET').upper()
            
            url_data = request_data.get('url', {})
            if isinstance(url_data, str):
                url = url_data
                params = {}
            else:
                url = url_data.get('raw', '')
                params_list = url_data.get('query', [])
                params = {p.get('key', ''): p.get('value', '') for p in params_list if p.get('key')}
            
            url = self._replace_variables(url)
            
            headers = {}
            headers_list = request_data.get('header', [])
            for h in headers_list:
                key = h.get('key', '')
                value = self._replace_variables(h.get('value', ''))
                if key:
                    headers[key] = value
            
            body = None
            body_data = request_data.get('body')
            if body_data:
                if body_data.get('mode') == 'raw':
                    body = self._replace_variables(body_data.get('raw', ''))
                    if 'content-type' not in [k.lower() for k in headers.keys()]:
                        content_type = body_data.get('options', {}).get('raw', {}).get('contentType', 'application/json')
                        headers['Content-Type'] = content_type
                elif body_data.get('mode') == 'formdata':
                    form_items = body_data.get('formdata', [])
                    body = '&'.join([f"{self._replace_variables(item.get('key', ''))}={self._replace_variables(item.get('value', ''))}" 
                                   for item in form_items if item.get('key')])
            
            description = item.get('request', {}).get('description', '')
            if not description:
                description = item.get('description', '')
            
            parsed = self._parse_url(url)
            
            return PostmanEndpoint(
                name=name,
                method=method,
                path=parsed.get('path', ''),
                full_url=url,
                headers=headers,
                body=body,
                params=params,
                description=self._replace_variables(description),
                collection=collection_name,
                folder=folder_path
            )
            
        except Exception as e:
            logger.debug(f"Failed to parse request: {e}")
            return None

    def _parse_url(self, url: str) -> Dict[str, str]:
        """解析 URL 为各部分"""
        if not url:
            return {'path': '/', 'host': '', 'protocol': 'https'}
        
        url = url.strip()
        
        if not re.match(r'^[a-zA-Z]+://', url):
            url = 'https://' + url
        
        parts = url.split('://')
        protocol = parts[0] if len(parts) > 1 else 'https'
        
        remaining = parts[1] if len(parts) > 1 else parts[0]
        
        host = remaining.split('/')[0] if '/' in remaining else remaining
        path = '/' + '/'.join(remaining.split('/')[1:]) if '/' in remaining else '/'
        
        if '?' in path:
            path = path.split('?')[0]
        
        return {
            'protocol': protocol,
            'host': host,
            'path': path or '/'
        }

    def _replace_variables(self, text: str) -> str:
        """替换 Postman 变量"""
        if not text:
            return text
        
        for var, value in self.global_variables.items():
            text = text.replace(f'{{{{{var}}}}}', str(value))
            text = text.replace(f'{{${var}}}', str(value))
        
        return text

    def import_environment(self, json_content: str) -> Dict[str, str]:
        """
        导入 Postman Environment
        
        Args:
            json_content: Environment JSON 内容
            
        Returns:
            环境变量字典
        """
        try:
            data = json.loads(json_content)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse environment JSON: {e}")
            return {}
        
        values = data.get('values', [])
        env_vars = {}
        
        for item in values:
            key = item.get('key', '')
            value = item.get('value', '')
            if key:
                env_vars[key] = value
        
        self.global_variables.update(env_vars)
        
        logger.info(f"Imported {len(env_vars)} environment variables")
        return env_vars

    def get_endpoints_summary(self) -> Dict[str, Any]:
        """获取端点摘要"""
        methods = {}
        collections = {}
        folders = {}
        
        for ep in self.endpoints:
            methods[ep.method] = methods.get(ep.method, 0) + 1
            collections[ep.collection] = collections.get(ep.collection, 0) + 1
            folders[ep.folder] = folders.get(ep.folder, 0) + 1
        
        return {
            'total_endpoints': len(self.endpoints),
            'methods': methods,
            'collections': collections,
            'folders': folders,
            'global_variables': len(self.global_variables)
        }

    def get_api_endpoints(self) -> List[Dict[str, Any]]:
        """获取 API 端点列表（兼容格式）"""
        return [
            {
                'name': ep.name,
                'method': ep.method,
                'path': ep.path,
                'full_url': ep.full_url,
                'headers': ep.headers,
                'body': ep.body,
                'params': ep.params,
                'description': ep.description,
                'collection': ep.collection,
                'folder': ep.folder,
                'source': 'postman_import'
            }
            for ep in self.endpoints
        ]

    def filter_by_method(self, method: str) -> List[PostmanEndpoint]:
        """按 HTTP 方法过滤"""
        return [ep for ep in self.endpoints if ep.method.upper() == method.upper()]

    def filter_by_collection(self, collection: str) -> List[PostmanEndpoint]:
        """按 Collection 过滤"""
        return [ep for ep in self.endpoints if ep.collection == collection]

    def filter_by_folder(self, folder: str) -> List[PostmanEndpoint]:
        """按文件夹过滤"""
        return [ep for ep in self.endpoints if ep.folder == folder]


def import_postman_file(file_path: str) -> PostmanCollectionImporter:
    """
    便捷函数: 导入 Postman 文件
    
    Args:
        file_path: 文件路径
        
    Returns:
        PostmanCollectionImporter 实例
    """
    importer = PostmanCollectionImporter()
    
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    if 'postman' in file_path.lower() or 'collection' in file_path.lower():
        importer.import_collection(content)
    elif 'environment' in file_path.lower() or 'env' in file_path.lower():
        importer.import_environment(content)
    else:
        try:
            importer.import_collection(content)
        except Exception:
            importer.import_environment(content)
    
    return importer


def convert_to_openapi(endpoints: List[PostmanEndpoint]) -> Dict[str, Any]:
    """
    将 Postman Collection 转换为 OpenAPI 格式
    
    Args:
        endpoints: PostmanEndpoint 列表
        
    Returns:
        OpenAPI 格式的字典
    """
    paths = {}
    
    for ep in endpoints:
        path = ep.path
        if path not in paths:
            paths[path] = {}
        
        method = ep.method.lower()
        
        operation = {
            'summary': ep.name,
            'description': ep.description,
            'responses': {
                '200': {
                    'description': 'Successful response'
                }
            }
        }
        
        if ep.headers:
            operation['parameters'] = [
                {'name': k, 'in': 'header', 'required': False, 'schema': {'type': 'string'}}
                for k in ep.headers.keys()
            ]
        
        if ep.body:
            operation['requestBody'] = {
                'content': {
                    'application/json': {
                        'schema': {'type': 'object'}
                    }
                }
            }
        
        if ep.params:
            if 'parameters' not in operation:
                operation['parameters'] = []
            operation['parameters'].extend([
                {'name': k, 'in': 'query', 'required': False, 'schema': {'type': 'string'}}
                for k in ep.params.keys()
            ])
        
        paths[path][method] = operation
    
    collections = list(set(ep.collection for ep in endpoints))
    
    return {
        'openapi': '3.0.0',
        'info': {
            'title': f"API from Postman ({', '.join(collections)})",
            'version': '1.0.0'
        },
        'paths': paths
    }


if __name__ == "__main__":
    print("Postman Collection Importer")
    importer = PostmanCollectionImporter()
    print("Supported formats: Postman Collection v2.0/v2.1, Postman Environment")
