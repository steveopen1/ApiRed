"""
WebSocket Security Tester
WebSocket 安全测试模块

测试能力：
1. WebSocket连接发现与验证
2. 未授权访问测试
3. 消息注入测试
4. 订阅者隔离测试
5. 跨协议攻击测试
"""

from .websocket_tester import WebSocketTester, WebSocketTestResult, WebSocketVulnerability

__all__ = ['WebSocketTester', 'WebSocketTestResult', 'WebSocketVulnerability']
