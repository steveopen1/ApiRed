"""
mitmproxy Addon Module
mitmproxy插件 - 被动流量捕获处理
"""

import json
import uuid
import sqlite3
from datetime import datetime
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
import asyncio

try:
    from mitmproxy import http, websocket
    from mitmproxy.tools import master
    from mitmproxy.options import Options
    HAS_MITMPROXY = True
except ImportError:
    HAS_MITMPROXY = False


@dataclass
class CapturedFlow:
    """捕获的流量"""
    id: str
    request_url: str
    request_method: str
    request_headers: Dict[str, str]
    request_content: Optional[bytes]
    response_status: int
    response_headers: Dict[str, str]
    response_content: Optional[bytes]
    timestamp: float
    is_api: bool = False
    is_sensitive: bool = False
    domain: str = ""
    duration: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'request_url': self.request_url,
            'request_method': self.request_method,
            'request_headers': self.request_headers,
            'request_content': self.request_content.decode('utf-8', errors='ignore') if self.request_content else None,
            'response_status': self.response_status,
            'response_headers': self.response_headers,
            'response_content': self.response_content.decode('utf-8', errors='ignore') if self.response_content else None,
            'timestamp': self.timestamp,
            'is_api': self.is_api,
            'is_sensitive': self.is_sensitive,
            'domain': self.domain,
            'duration': self.duration
        }


class ApiRedMitmproxyAddon:
    """
    ApiRed mitmproxy插件
    用于捕获HTTP/HTTPS流量并提取API端点
    """
    
    API_PATTERNS = [
        '/api/', '/v1/', '/v2/', '/v3/', '/v4/',
        '/rest/', '/graphql', '/gql/', '/rpc/',
        '/oauth/', '/auth/', '/openapi/', '/swagger'
    ]
    
    SENSITIVE_PATTERNS = [
        '/admin', '/login', '/logout', '/auth',
        '/api_keys', '/apikey', '/secret', '/password',
        '/user', '/profile', '/account', '/settings',
        '/upload', '/download', '/debug', '/health',
        '/swagger', '/openapi', '/console'
    ]
    
    EXCLUDED_EXTENSIONS = [
        '.js', '.css', '.scss', '.sass', '.less',
        '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', '.bmp',
        '.woff', '.woff2', '.ttf', '.eot', '.otf',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx',
        '.zip', '.tar', '.gz', '.rar'
    ]
    
    def __init__(self, db_path: str = None, max_flows: int = 10000):
        """
        初始化插件
        
        Args:
            db_path: SQLite数据库路径
            max_flows: 最大保存流量数
        """
        self.db_path = db_path or ':memory:'
        self.max_flows = max_flows
        self.flows: List[CapturedFlow] = []
        self.flow_count = 0
        
        self._init_database()
        
        self._observers: List[callable] = []
    
    def _init_database(self):
        """初始化数据库"""
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS captured_flows (
                id TEXT PRIMARY KEY,
                request_url TEXT NOT NULL,
                request_method TEXT,
                request_headers TEXT,
                request_content BLOB,
                response_status INTEGER,
                response_headers TEXT,
                response_content BLOB,
                timestamp REAL,
                is_api INTEGER DEFAULT 0,
                is_sensitive INTEGER DEFAULT 0,
                domain TEXT,
                duration REAL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        self.conn.execute('CREATE INDEX IF NOT EXISTS idx_flows_domain ON captured_flows(domain)')
        self.conn.execute('CREATE INDEX IF NOT EXISTS idx_flows_api ON captured_flows(is_api)')
        self.conn.execute('CREATE INDEX IF NOT EXISTS idx_flows_timestamp ON captured_flows(timestamp)')
        self.conn.commit()
    
    def add_observer(self, callback: callable):
        """添加流量观察者"""
        self._observers.append(callback)
    
    def remove_observer(self, callback: callable):
        """移除流量观察者"""
        if callback in self._observers:
            self._observers.remove(callback)
    
    def _notify_observers(self, flow: CapturedFlow):
        """通知观察者新流量"""
        for observer in self._observers:
            try:
                observer(flow)
            except Exception as e:
                print(f'Observer error: {e}')
    
    def request(self, flow: http.HTTPFlow):
        """处理请求"""
        url = flow.request.url
        method = flow.request.method
        
        if self._should_capture(url):
            flow_id = str(uuid.uuid4())
            domain = self._extract_domain(url)
            
            headers = {}
            for name, value in flow.request.headers.items():
                headers[name.lower()] = value
            
            captured = CapturedFlow(
                id=flow_id,
                request_url=url,
                request_method=method,
                request_headers=headers,
                request_content=flow.request.content,
                response_status=0,
                response_headers={},
                response_content=None,
                timestamp=datetime.now().timestamp(),
                is_api=self._is_api_url(url),
                is_sensitive=self._is_sensitive_url(url),
                domain=domain
            )
            
            self._save_flow(captured)
            self.flows.append(captured)
            self.flow_count += 1
            self._notify_observers(captured)
    
    def response(self, flow: http.HTTPFlow):
        """处理响应"""
        url = flow.request.url
        
        if self._should_capture(url):
            for captured in reversed(self.flows):
                if captured.request_url == url:
                    captured.response_status = flow.response.status_code
                    captured.response_headers = {
                        name.lower(): value for name, value in flow.response.headers.items()
                    }
                    captured.response_content = flow.response.content
                    captured.duration = flow.response.timestamp - flow.request.timestamp if hasattr(flow.response, 'timestamp') else 0
                    
                    self._update_flow(captured)
                    break
    
    def _should_capture(self, url: str) -> bool:
        """判断是否应该捕获"""
        try:
            parsed_url = url.lower()
            
            for ext in self.EXCLUDED_EXTENSIONS:
                if ext in parsed_url:
                    return False
            
            return True
        except Exception:
            return False
    
    def _is_api_url(self, url: str) -> bool:
        """判断是否为API URL"""
        url_lower = url.lower()
        return any(pattern in url_lower for pattern in self.API_PATTERNS)
    
    def _is_sensitive_url(self, url: str) -> bool:
        """判断是否为敏感URL"""
        url_lower = url.lower()
        return any(pattern in url_lower for pattern in self.SENSITIVE_PATTERNS)
    
    def _extract_domain(self, url: str) -> str:
        """提取域名"""
        try:
            from urllib.parse import urlparse
            return urlparse(url).netloc
        except Exception:
            return ''
    
    def _save_flow(self, flow: CapturedFlow):
        """保存流量到数据库"""
        try:
            self.conn.execute('''
                INSERT INTO captured_flows 
                (id, request_url, request_method, request_headers, request_content,
                 response_status, response_headers, response_content, timestamp,
                 is_api, is_sensitive, domain, duration)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                flow.id,
                flow.request_url,
                flow.request_method,
                json.dumps(flow.request_headers),
                flow.request_content,
                flow.response_status,
                json.dumps(flow.response_headers),
                flow.response_content,
                flow.timestamp,
                int(flow.is_api),
                int(flow.is_sensitive),
                flow.domain,
                flow.duration
            ))
            self.conn.commit()
        except Exception as e:
            print(f'Failed to save flow: {e}')
    
    def _update_flow(self, flow: CapturedFlow):
        """更新流量"""
        try:
            self.conn.execute('''
                UPDATE captured_flows SET
                    response_status = ?,
                    response_headers = ?,
                    response_content = ?,
                    duration = ?
                WHERE id = ?
            ''', (
                flow.response_status,
                json.dumps(flow.response_headers),
                flow.response_content,
                flow.duration,
                flow.id
            ))
            self.conn.commit()
        except Exception as e:
            print(f'Failed to update flow: {e}')
    
    def get_flows(self, domain: str = None, limit: int = 100) -> List[CapturedFlow]:
        """获取流量列表"""
        try:
            if domain:
                cursor = self.conn.execute(
                    'SELECT * FROM captured_flows WHERE domain = ? ORDER BY timestamp DESC LIMIT ?',
                    (domain, limit)
                )
            else:
                cursor = self.conn.execute(
                    'SELECT * FROM captured_flows ORDER BY timestamp DESC LIMIT ?',
                    (limit,)
                )
            
            rows = cursor.fetchall()
            flows = []
            for row in rows:
                flows.append(self._row_to_flow(row))
            return flows
        except Exception as e:
            print(f'Failed to get flows: {e}')
            return []
    
    def _row_to_flow(self, row: tuple) -> CapturedFlow:
        """数据库行转换为CapturedFlow"""
        return CapturedFlow(
            id=row[0],
            request_url=row[1],
            request_method=row[2],
            request_headers=json.loads(row[3]) if row[3] else {},
            request_content=row[4],
            response_status=row[5],
            response_headers=json.loads(row[6]) if row[6] else {},
            response_content=row[7],
            timestamp=row[8],
            is_api=bool(row[9]),
            is_sensitive=bool(row[10]),
            domain=row[11] or '',
            duration=row[12] or 0.0
        )
    
    def get_api_endpoints(self, domain: str = None) -> List[Dict[str, Any]]:
        """获取API端点列表"""
        flows = self.get_flows(domain=domain, limit=1000)
        endpoints = []
        
        seen = set()
        for flow in flows:
            if flow.is_api:
                key = f'{flow.request_method}:{flow.request_url}'
                if key not in seen:
                    seen.add(key)
                    endpoints.append({
                        'url': flow.request_url,
                        'method': flow.request_method,
                        'domain': flow.domain,
                        'status': flow.response_status,
                        'is_sensitive': flow.is_sensitive,
                        'timestamp': flow.timestamp
                    })
        
        return endpoints
    
    def export_har(self, domain: str = None) -> str:
        """导出HAR格式"""
        flows = self.get_flows(domain=domain, limit=10000)
        
        har = {
            'log': {
                'version': '1.2',
                'creator': {
                    'name': 'ApiRed mitmproxy addon',
                    'version': '4.0.0'
                },
                'entries': []
            }
        }
        
        for flow in flows:
            entry = {
                'startedDateTime': datetime.fromtimestamp(flow.timestamp).isoformat(),
                'time': flow.duration * 1000,
                'request': {
                    'method': flow.request_method,
                    'url': flow.request_url,
                    'httpVersion': 'HTTP/1.1',
                    'headers': [
                        {'name': k, 'value': v} for k, v in flow.request_headers.items()
                    ],
                    'queryString': [],
                    'cookies': [],
                    'headersSize': -1,
                    'bodySize': len(flow.request_content) if flow.request_content else 0,
                },
                'response': {
                    'status': flow.response_status,
                    'statusText': '',
                    'httpVersion': 'HTTP/1.1',
                    'headers': [
                        {'name': k, 'value': v} for k, v in flow.response_headers.items()
                    ],
                    'cookies': [],
                    'content': {
                        'size': len(flow.response_content) if flow.response_content else 0,
                        'mimeType': flow.response_headers.get('content-type', 'application/octet-stream'),
                        'text': flow.response_content.decode('utf-8', errors='ignore') if flow.response_content else ''
                    },
                    'redirectURL': '',
                    'headersSize': -1,
                    'bodySize': len(flow.response_content) if flow.response_content else 0
                },
                'cache': {},
                'timings': {
                    'send': 0,
                    'wait': flow.duration * 1000,
                    'receive': 0
                }
            }
            
            if flow.request_content:
                entry['request']['postData'] = {
                    'mimeType': flow.request_headers.get('content-type', 'application/octet-stream'),
                    'text': flow.request_content.decode('utf-8', errors='ignore')
                }
            
            har['log']['entries'].append(entry)
        
        return json.dumps(har, indent=2, ensure_ascii=False)
    
    def get_stats(self, domain: str = None) -> Dict[str, int]:
        """获取统计信息"""
        try:
            if domain:
                cursor = self.conn.execute(
                    'SELECT COUNT(*), SUM(is_api), SUM(is_sensitive) FROM captured_flows WHERE domain = ?',
                    (domain,)
                )
            else:
                cursor = self.conn.execute(
                    'SELECT COUNT(*), SUM(is_api), SUM(is_sensitive) FROM captured_flows'
                )
            
            row = cursor.fetchone()
            return {
                'total': row[0] or 0,
                'apis': row[1] or 0,
                'sensitive': row[2] or 0
            }
        except Exception as e:
            print(f'Failed to get stats: {e}')
            return {'total': 0, 'apis': 0, 'sensitive': 0}
    
    def clear_flows(self, domain: str = None):
        """清空流量"""
        try:
            if domain:
                self.conn.execute('DELETE FROM captured_flows WHERE domain = ?', (domain,))
            else:
                self.conn.execute('DELETE FROM captured_flows')
            self.conn.commit()
            self.flows = []
        except Exception as e:
            print(f'Failed to clear flows: {e}')
    
    def close(self):
        """关闭连接"""
        if self.conn:
            self.conn.close()
