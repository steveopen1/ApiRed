"""
Traffic Monitor Module
实时流量监控 - WebSocket实时流推送
"""

import asyncio
import json
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

try:
    import websockets
    HAS_WEBSOCKET = True
except ImportError:
    HAS_WEBSOCKET = False


class AlertLevel(Enum):
    """告警级别"""
    INFO = 'info'
    WARNING = 'warning'
    CRITICAL = 'critical'


@dataclass
class Alert:
    """告警"""
    id: str
    level: AlertLevel
    title: str
    message: str
    flow_id: str
    timestamp: float = field(default_factory=lambda: datetime.now().timestamp())
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'level': self.level.value,
            'title': self.title,
            'message': self.message,
            'flow_id': self.flow_id,
            'timestamp': self.timestamp
        }


class TrafficMonitor:
    """
    实时流量监控器
    支持WebSocket实时推送、敏感端点检测、告警
    """
    
    SENSITIVE_PATTERNS = [
        ('/admin', '管理后台'),
        ('/login', '登录页面'),
        ('/api_keys', 'API密钥泄露'),
        ('/password', '密码相关'),
        ('/oauth', 'OAuth认证'),
        ('/swagger', 'Swagger文档'),
        ('/debug', '调试接口'),
        ('/config', '配置文件'),
        ('.env', '环境变量'),
        ('/backup', '备份文件'),
    ]
    
    def __init__(self):
        self._subscribers: List['websockets.WebSocketServerProtocol'] = []
        self._alerts: List[Alert] = []
        self._alert_callbacks: List[Callable[[Alert], None]] = []
        self._flow_callbacks: List[Callable[[Dict], None]] = []
        
        self._stats = {
            'total': 0,
            'apis': 0,
            'sensitive': 0,
            'alerts': 0
        }
    
    async def start_websocket_server(self, host: str = '127.0.0.1', port: int = 8765):
        """
        启动WebSocket服务器
        
        Args:
            host: 监听地址
            port: 端口
        """
        if not HAS_WEBSOCKET:
            raise ImportError('websockets library is required: pip install websockets')
        
        async with websockets.serve(self._handle_client, host, port):
            print(f'Traffic monitor WebSocket server started on ws://{host}:{port}')
            await asyncio.Future()
    
    async def _handle_client(self, websocket, path):
        """处理客户端连接"""
        self._subscribers.append(websocket)
        print(f'Client connected, total subscribers: {len(self._subscribers)}')
        
        try:
            await websocket.send(json.dumps({
                'type': 'connected',
                'message': 'Connected to ApiRed Traffic Monitor'
            }))
            
            await websocket.send(json.dumps({
                'type': 'stats',
                'data': self._stats
            }))
            
            async for message in websocket:
                try:
                    data = json.loads(message)
                    await self._handle_message(websocket, data)
                except json.JSONDecodeError:
                    pass
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            if websocket in self._subscribers:
                self._subscribers.remove(websocket)
            print(f'Client disconnected, total subscribers: {len(self._subscribers)}')
    
    async def _handle_message(self, websocket, data: Dict):
        """处理客户端消息"""
        msg_type = data.get('type')
        
        if msg_type == 'get_stats':
            await websocket.send(json.dumps({
                'type': 'stats',
                'data': self._stats
            }))
        elif msg_type == 'get_alerts':
            await websocket.send(json.dumps({
                'type': 'alerts',
                'data': [a.to_dict() for a in self._alerts[-50:]]
            }))
    
    def on_flow(self, flow: Any):
        """
        新流量到达回调
        
        Args:
            flow: CapturedFlow对象或字典
        """
        self._stats['total'] += 1
        
        if hasattr(flow, 'is_api') and flow.is_api:
            self._stats['apis'] += 1
        
        is_sensitive, alert_info = self._check_sensitive(flow)
        if is_sensitive:
            self._stats['sensitive'] += 1
        
        flow_dict = flow.to_dict() if hasattr(flow, 'to_dict') else flow
        
        for callback in self._flow_callbacks:
            try:
                callback(flow_dict)
            except Exception as e:
                print(f'Flow callback error: {e}')
        
        self._broadcast({
            'type': 'flow',
            'data': flow_dict
        })
        
        if is_sensitive and alert_info:
            alert = self._create_alert(flow, alert_info)
            self._handle_alert(alert)
    
    def _check_sensitive(self, flow: Any) -> tuple:
        """
        检查敏感端点
        
        Returns:
            (is_sensitive, alert_info)
        """
        url = flow.request_url if hasattr(flow, 'request_url') else flow.get('request_url', '')
        url_lower = url.lower()
        
        for pattern, description in self.SENSITIVE_PATTERNS:
            if pattern in url_lower:
                return True, description
        
        return False, None
    
    def _create_alert(self, flow: Any, alert_info: str) -> Alert:
        """创建告警"""
        url = flow.request_url if hasattr(flow, 'request_url') else flow.get('request_url', '')
        flow_id = flow.id if hasattr(flow, 'id') else flow.get('id', '')
        
        method = flow.request_method if hasattr(flow, 'request_method') else flow.get('request_method', '')
        
        alert = Alert(
            id=f'alert_{flow_id}',
            level=AlertLevel.WARNING,
            title=f'敏感端点: {alert_info}',
            message=f'{method} {url}',
            flow_id=flow_id
        )
        
        return alert
    
    def _handle_alert(self, alert: Alert):
        """处理告警"""
        self._alerts.append(alert)
        self._stats['alerts'] += 1
        
        if len(self._alerts) > 1000:
            self._alerts = self._alerts[-1000:]
        
        for callback in self._alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                print(f'Alert callback error: {e}')
        
        self._broadcast({
            'type': 'alert',
            'data': alert.to_dict()
        })
    
    async def _broadcast(self, message: Dict):
        """广播消息到所有订阅者"""
        if not self._subscribers:
            return
        
        message_str = json.dumps(message)
        
        disconnected = []
        for websocket in self._subscribers:
            try:
                await websocket.send(message_str)
            except Exception:
                disconnected.append(websocket)
        
        for ws in disconnected:
            if ws in self._subscribers:
                self._subscribers.remove(ws)
    
    def add_alert_callback(self, callback: Callable[[Alert], None]):
        """添加告警回调"""
        self._alert_callbacks.append(callback)
    
    def add_flow_callback(self, callback: Callable[[Dict], None]):
        """添加流量回调"""
        self._flow_callbacks.append(callback)
    
    def get_stats(self) -> Dict[str, int]:
        """获取统计信息"""
        return self._stats.copy()
    
    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """获取告警列表"""
        return [a.to_dict() for a in self._alerts[-limit:]]
    
    def clear_alerts(self):
        """清空告警"""
        self._alerts = []
        self._stats['alerts'] = 0
    
    def subscribe(self, websocket):
        """手动订阅WebSocket"""
        if websocket not in self._subscribers:
            self._subscribers.append(websocket)
    
    def unsubscribe(self, websocket):
        """取消订阅WebSocket"""
        if websocket in self._subscribers:
            self._subscribers.remove(websocket)
