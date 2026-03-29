"""
BurpSuite Proxy 流量导入器

支持导入:
1. BurpSuite Professional HTTP History (CSV)
2. BurpSuite JSON 格式
3. BurpSuite Macro 录制
4. HTTP Proxy Log

参考: Akto 支持的 BurpSuite 流量导入
"""

import csv
import json
import logging
import re
from typing import Dict, List, Any, Optional, Set, Iterator
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse, parse_qs, urlencode

logger = logging.getLogger(__name__)


class TrafficSource(Enum):
    """流量来源"""
    BURP_CSV = "burp_csv"
    BURP_JSON = "burp_json"
    BURP_XML = "burp_xml"
    PROXY_LOG = "proxy_log"
    HAR = "har"  # HTTP Archive Format
    OPENAPI = "openapi"
    POSTMAN = "postman"


@dataclass
class ProxyRequest:
    """代理请求"""
    url: str
    method: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    content_type: str = ""
    timestamp: float = 0
    host: str = ""
    path: str = ""
    query: str = ""
    source: TrafficSource = TrafficSource.BURP_JSON


@dataclass
class ProxyResponse:
    """代理响应"""
    status_code: int
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    content_type: str = ""
    content_length: int = 0
    timestamp: float = 0


@dataclass
class ProxyTransaction:
    """代理事务（请求+响应）"""
    request: ProxyRequest
    response: Optional[ProxyResponse] = None
    request_line: str = ""
    response_line: str = ""


class BurpSuiteImporter:
    """
    BurpSuite 流量导入器
    
    支持格式:
    1. CSV (HTTP History)
    2. JSON (Burp Suite Enterprise)
    3. XML (Burp Suite Macro)
    4. HAR (HTTP Archive)
    """

    BURP_CSV_COLUMNS = [
        '#', 'Time', 'URL', 'Method', 'Status', 'Response length',
        'Content-type', 'Comment'
    ]

    def __init__(self):
        self.transactions: List[ProxyTransaction] = []
        self.api_endpoints: Set[str] = set()
        self.hostnames: Set[str] = set()

    def import_csv(self, csv_content: str) -> List[ProxyTransaction]:
        """
        导入 BurpSuite CSV 格式的 HTTP History
        
        Args:
            csv_content: CSV 文件内容
            
        Returns:
            ProxyTransaction 列表
        """
        transactions = []
        lines = csv_content.strip().split('\n')
        
        if len(lines) < 2:
            logger.warning("CSV content is empty or invalid")
            return transactions
        
        reader = csv.DictReader(lines)
        
        for row in reader:
            try:
                url = row.get('URL', '').strip()
                if not url:
                    continue
                
                method = row.get('Method', 'GET').strip().upper()
                status_code = int(row.get('Status', 0))
                
                parsed = urlparse(url)
                
                request = ProxyRequest(
                    url=url,
                    method=method,
                    host=parsed.netloc,
                    path=parsed.path,
                    query=parsed.query,
                    source=TrafficSource.BURP_CSV
                )
                
                response = None
                if status_code > 0:
                    response = ProxyResponse(
                        status_code=status_code,
                        content_length=int(row.get('Response length', 0)),
                        content_type=row.get('Content-type', ''),
                        source=TrafficSource.BURP_CSV if 'Burp' in str(row) else TrafficSource.PROXY_LOG
                    )
                
                transaction = ProxyTransaction(
                    request=request,
                    response=response
                )
                transactions.append(transaction)
                self._extract_api_endpoints(request)
                
            except Exception as e:
                logger.debug(f"Failed to parse CSV row: {e}")
                continue
        
        self.transactions.extend(transactions)
        logger.info(f"Imported {len(transactions)} transactions from CSV")
        return transactions

    def import_json(self, json_content: str) -> List[ProxyTransaction]:
        """
        导入 BurpSuite JSON 格式
        
        Args:
            json_content: JSON 文件内容
            
        Returns:
            ProxyTransaction 列表
        """
        transactions = []
        
        try:
            data = json.loads(json_content)
            
            if isinstance(data, list):
                items = data
            elif isinstance(data, dict):
                items = data.get('transactions', data.get('proxy_history', [data]))
            else:
                logger.warning("Unknown JSON format")
                return transactions
            
            for item in items:
                transaction = self._parse_json_item(item)
                if transaction:
                    transactions.append(transaction)
                    self._extract_api_endpoints(transaction.request)
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON: {e}")
        
        self.transactions.extend(transactions)
        logger.info(f"Imported {len(transactions)} transactions from JSON")
        return transactions

    def _parse_json_item(self, item: Dict) -> Optional[ProxyTransaction]:
        """解析 JSON 条目"""
        try:
            request_data = item.get('request', item)
            response_data = item.get('response', {})
            
            url = request_data.get('url', request_data.get('path', ''))
            if not url:
                return None
            
            method = request_data.get('method', 'GET').upper()
            headers = request_data.get('headers', {})
            body = request_data.get('body', request_data.get('content', ''))
            
            if isinstance(headers, list):
                headers = {h.get('name', ''): h.get('value', '') for h in headers}
            
            parsed = urlparse(url)
            
            request = ProxyRequest(
                url=url,
                method=method,
                headers=headers,
                body=body,
                content_type=headers.get('Content-Type', headers.get('content-type', '')),
                host=parsed.netloc,
                path=parsed.path,
                query=parsed.query,
                source=TrafficSource.BURP_JSON
            )
            
            response = None
            if response_data:
                response = ProxyResponse(
                    status_code=response_data.get('status_code', response_data.get('status', 0)),
                    headers=response_data.get('headers', {}),
                    body=response_data.get('body', response_data.get('content', '')),
                    content_type=response_data.get('content_type', ''),
                    content_length=response_data.get('content_length', len(response_data.get('body', '')))
                )
            
            return ProxyTransaction(request=request, response=response)
            
        except Exception as e:
            logger.debug(f"Failed to parse JSON item: {e}")
            return None

    def import_har(self, har_content: str) -> List[ProxyTransaction]:
        """
        导入 HAR (HTTP Archive) 格式
        
        Args:
            har_content: HAR 文件内容
            
        Returns:
            ProxyTransaction 列表
        """
        transactions = []
        
        try:
            data = json.loads(har_content)
            entries = data.get('log', {}).get('entries', [])
            
            for entry in entries:
                transaction = self._parse_har_entry(entry)
                if transaction:
                    transactions.append(transaction)
                    self._extract_api_endpoints(transaction.request)
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse HAR: {e}")
        
        self.transactions.extend(transactions)
        logger.info(f"Imported {len(transactions)} transactions from HAR")
        return transactions

    def _parse_har_entry(self, entry: Dict) -> Optional[ProxyTransaction]:
        """解析 HAR 条目"""
        try:
            request_data = entry.get('request', {})
            response_data = entry.get('response', {})
            
            url = request_data.get('url', '')
            if not url:
                return None
            
            method = request_data.get('method', 'GET').upper()
            
            headers = {}
            for header in request_data.get('headers', []):
                name = header.get('name', '')
                value = header.get('value', '')
                if name:
                    headers[name] = value
            
            body = ''
            post_data = request_data.get('postData', {})
            if post_data:
                if isinstance(post_data, dict):
                    body = post_data.get('text', '')
                else:
                    body = str(post_data)
            
            parsed = urlparse(url)
            
            request = ProxyRequest(
                url=url,
                method=method,
                headers=headers,
                body=body,
                content_type=headers.get('Content-Type', ''),
                host=parsed.netloc,
                path=parsed.path,
                query=parsed.query,
                timestamp=entry.get('time', 0),
                source=TrafficSource.HAR
            )
            
            resp_headers = {}
            for header in response_data.get('headers', []):
                name = header.get('name', '')
                value = header.get('value', '')
                if name:
                    resp_headers[name] = value
            
            response = ProxyResponse(
                status_code=response_data.get('status', 0),
                headers=resp_headers,
                body=response_data.get('content', {}).get('text', ''),
                content_type=resp_headers.get('Content-Type', ''),
                content_length=response_data.get('content', {}).get('size', 0),
                timestamp=entry.get('time', 0),
            )
            
            return ProxyTransaction(request=request, response=response)
            
        except Exception as e:
            logger.debug(f"Failed to parse HAR entry: {e}")
            return None

    def import_xml(self, xml_content: str) -> List[ProxyTransaction]:
        """
        导入 BurpSuite XML 格式
        
        Args:
            xml_content: XML 文件内容
            
        Returns:
            ProxyTransaction 列表
        """
        transactions = []
        
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml_content)
            
            items = root.findall('.//item')
            for item in items:
                transaction = self._parse_xml_item(item)
                if transaction:
                    transactions.append(transaction)
                    self._extract_api_endpoints(transaction.request)
            
        except Exception as e:
            logger.error(f"Failed to parse XML: {e}")
        
        self.transactions.extend(transactions)
        logger.info(f"Imported {len(transactions)} transactions from XML")
        return transactions

    def _parse_xml_item(self, item) -> Optional[ProxyTransaction]:
        """解析 XML 条目"""
        try:
            def get_text(elem, tag, default=''):
                child = elem.find(tag)
                return child.text if child is not None else default
            
            url = get_text(item, 'url')
            method = get_text(item, 'method', 'GET').upper()
            
            request = ProxyRequest(
                url=url,
                method=method,
                source=TrafficSource.BURP_XML
            )
            
            status_elem = item.find('status')
            status_code = int(status_elem.text) if status_elem is not None else 0
            
            response = None
            if status_code > 0:
                response = ProxyResponse(
                    status_code=status_code
                )
            
            return ProxyTransaction(request=request, response=response)
            
        except Exception as e:
            logger.debug(f"Failed to parse XML item: {e}")
            return None

    def import_proxy_log(self, log_content: str) -> List[ProxyTransaction]:
        """
        导入通用代理日志格式
        
        Args:
            log_content: 日志文件内容
            
        Returns:
            ProxyTransaction 列表
        """
        transactions = []
        lines = log_content.strip().split('\n')
        
        current_request = None
        
        for line in lines:
            line = line.strip()
            
            if line.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'PATCH ', 'HEAD ', 'OPTIONS ')):
                parts = line.split(' ', 2)
                if len(parts) >= 2:
                    method = parts[0]
                    url = parts[1]
                    
                    current_request = ProxyRequest(
                        url=url,
                        method=method,
                        source=TrafficSource.PROXY_LOG
                    )
            
            elif line.startswith('HTTP/') and current_request:
                parts = line.split(' ', 1)
                if len(parts) >= 2:
                    status_code = int(parts[1].split(' ')[0])
                    response = ProxyResponse(status_code=status_code)
                    transactions.append(ProxyTransaction(
                        request=current_request,
                        response=response
                    ))
                    self._extract_api_endpoints(current_request)
                    current_request = None
        
        self.transactions.extend(transactions)
        logger.info(f"Imported {len(transactions)} transactions from proxy log")
        return transactions

    def _extract_api_endpoints(self, request: ProxyRequest):
        """从请求中提取 API 端点"""
        if not request.path:
            return
        
        self.hostnames.add(request.host)
        
        if any(indicator in request.path.lower() for indicator in ['/api/', '/v1/', '/v2/', '/rest/', '/graphql']):
            self.api_endpoints.add(f"{request.method}:{request.path}")

    def get_api_endpoints(self) -> List[Dict[str, Any]]:
        """
        获取提取的 API 端点
        
        Returns:
            API 端点列表
        """
        endpoints = []
        
        for ep in self.api_endpoints:
            parts = ep.split(':', 1)
            if len(parts) == 2:
                method, path = parts
                
                endpoints.append({
                    'method': method,
                    'path': path,
                    'source': 'burp_import'
                })
        
        return endpoints

    def get_traffic_summary(self) -> Dict[str, Any]:
        """获取流量摘要"""
        methods = {}
        status_codes = {}
        content_types = {}
        
        for t in self.transactions:
            m = t.request.method
            methods[m] = methods.get(m, 0) + 1
            
            if t.response:
                sc = t.response.status_code
                status_codes[sc] = status_codes.get(sc, 0) + 1
                
                ct = t.response.content_type
                if ct:
                    content_types[ct.split(';')[0].strip()] = content_types.get(ct, 0) + 1
        
        return {
            'total_transactions': len(self.transactions),
            'methods': methods,
            'status_codes': status_codes,
            'content_types': content_types,
            'unique_hosts': len(self.hostnames),
            'api_endpoints': len(self.api_endpoints)
        }

    def filter_api_only(self) -> List[ProxyTransaction]:
        """过滤出仅 API 相关的流量"""
        api_transactions = []
        
        api_indicators = [
            '/api/', '/v1/', '/v2/', '/v3/',
            '/rest/', '/graphql', '/oauth', '/auth/',
            '/json', '/xml', '/soap'
        ]
        
        for t in self.transactions:
            url_lower = t.request.url.lower()
            if any(indicator in url_lower for indicator in api_indicators):
                api_transactions.append(t)
        
        logger.info(f"Filtered {len(api_transactions)} API transactions from {len(self.transactions)} total")
        return api_transactions


def import_burp_file(file_path: str) -> BurpSuiteImporter:
    """
    便捷函数: 根据文件扩展名自动识别格式并导入
    
    Args:
        file_path: 文件路径
        
    Returns:
        BurpSuiteImporter 实例
    """
    importer = BurpSuiteImporter()
    
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    
    if file_path.endswith('.csv'):
        importer.import_csv(content)
    elif file_path.endswith('.json'):
        importer.import_json(content)
    elif file_path.endswith('.xml'):
        importer.import_xml(content)
    elif file_path.endswith('.har'):
        importer.import_har(content)
    else:
        for format_handler, name in [
            (importer.import_csv, 'CSV'),
            (importer.import_json, 'JSON'),
            (importer.import_xml, 'XML'),
        ]:
            try:
                import copy
                test_importer = BurpSuiteImporter()
                test_importer.import_csv = lambda c: copy.deepcopy(importer.import_csv(c))
                format_handler(content)
                break
            except Exception:
                continue
    
    return importer


def convert_burp_to_openapi(transactions: List[ProxyTransaction]) -> Dict[str, Any]:
    """
    将 BurpSuite 流量转换为 OpenAPI 格式
    
    Args:
        transactions: ProxyTransaction 列表
        
    Returns:
        OpenAPI 格式的字典
    """
    paths = {}
    
    for t in transactions:
        path = t.request.path
        if not path or path == '/':
            continue
        
        if path not in paths:
            paths[path] = {}
        
        method = t.request.method.lower()
        
        paths[path][method] = {
            'summary': f'Auto-generated from BurpSuite traffic',
            'responses': {
                str(t.response.status_code if t.response else 200): {
                    'description': 'Default response'
                }
            }
        }
        
        if t.request.body:
            paths[path][method]['requestBody'] = {
                'content': {
                    t.request.content_type or 'application/json': {
                        'schema': {'type': 'object'}
                    }
                }
            }
    
    return {
        'openapi': '3.0.0',
        'info': {
            'title': 'Imported from BurpSuite',
            'version': '1.0.0'
        },
        'paths': paths
    }


if __name__ == "__main__":
    print("BurpSuite Proxy Importer")
    importer = BurpSuiteImporter()
    print(f"Supported formats: CSV, JSON, XML, HAR")
