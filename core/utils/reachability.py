#!/usr/bin/env python3
"""
Target Reachability Checker - 目标可达性检测器
在扫描前快速检测目标是否可达
"""

import asyncio
import socket
import logging
from typing import Dict, Optional, Tuple
from dataclasses import dataclass
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


@dataclass
class ReachabilityResult:
    """可达性检测结果"""
    target: str
    is_reachable: bool
    host: str
    port: int
    protocol: str
    response_code: Optional[int] = None
    response_time: Optional[float] = None
    error_message: Optional[str] = None
    suggestions: list = None

    def __post_init__(self):
        if self.suggestions is None:
            self.suggestions = []


class TargetReachabilityChecker:
    """目标可达性检测器"""

    COMMON_PORTS = {
        'http': 80,
        'https': 443,
        'http_alt': 8080,
        'https_alt': 8443,
    }

    TIMEOUT = 5

    def __init__(self):
        self.results: Dict[str, ReachabilityResult] = {}

    async def check_target(self, target: str) -> ReachabilityResult:
        """
        检测目标是否可达
        
        Args:
            target: 目标 URL (如 http://example.com 或 https://example.com:8080)
        
        Returns:
            ReachabilityResult: 检测结果
        """
        if target in self.results:
            return self.results[target]

        try:
            parsed = urlparse(target)
            host = parsed.hostname or ''
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            protocol = parsed.scheme or 'http'

            if not host:
                result = ReachabilityResult(
                    target=target,
                    is_reachable=False,
                    host='',
                    port=0,
                    protocol='',
                    error_message='无法解析主机名',
                    suggestions=['检查 URL 格式是否正确']
                )
                self.results[target] = result
                return result

            result = await self._check_connectivity(
                target, host, port, protocol
            )

            self.results[target] = result
            return result

        except Exception as e:
            result = ReachabilityResult(
                target=target,
                is_reachable=False,
                host='',
                port=0,
                protocol='',
                error_message=str(e),
                suggestions=['检查网络连接', '确认目标是否在线']
            )
            self.results[target] = result
            return result

    async def _check_connectivity(self, target: str, host: str, port: int, protocol: str) -> ReachabilityResult:
        """检测网络连接"""
        suggestions = []

        is_port_open = await self._check_port(host, port)
        
        if not is_port_open:
            if port in [80, 443]:
                for alt_port in [8080, 8443, 8000, 3000]:
                    if alt_port != port:
                        alt_check = await self._check_port(host, alt_port)
                        if alt_check:
                            suggestions.append(f'常用端口 {alt_port} 可达，尝试使用 {protocol}://{host}:{alt_port}')
                            port = alt_port
                            is_port_open = True
                            break

            if not is_port_open:
                return ReachabilityResult(
                    target=target,
                    is_reachable=False,
                    host=host,
                    port=port,
                    protocol=protocol,
                    error_message=f'端口 {port} 连接超时',
                    suggestions=[
                        '确认目标服务是否启动',
                        '检查防火墙设置',
                        '确认端口是否正确',
                        f'常用端口: 80, 443, 8080, 8443'
                    ]
                )

        response_code, response_time = await self._check_http(target)

        if response_code is None:
            return ReachabilityResult(
                target=target,
                is_reachable=True,
                host=host,
                port=port,
                protocol=protocol,
                response_time=response_time,
                error_message='无法获取 HTTP 响应',
                suggestions=[
                    '目标可能需要 HTTPS',
                    '检查 Web 服务器配置',
                    '尝试不同的协议'
                ]
            )

        if response_code >= 500:
            return ReachabilityResult(
                target=target,
                is_reachable=True,
                host=host,
                port=port,
                protocol=protocol,
                response_code=response_code,
                response_time=response_time,
                error_message=f'HTTP {response_code} 服务器内部错误',
                suggestions=[
                    '目标服务器可能配置错误',
                    '后端服务可能未正常启动'
                ]
            )

        return ReachabilityResult(
            target=target,
            is_reachable=True,
            host=host,
            port=port,
            protocol=protocol,
            response_code=response_code,
            response_time=response_time,
            suggestions=['目标可达，可以开始扫描']
        )

    async def _check_port(self, host: str, port: int) -> bool:
        """检查端口是否开放"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.TIMEOUT)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    async def _check_http(self, target: str) -> Tuple[Optional[int], Optional[float]]:
        """检查 HTTP 响应"""
        try:
            import time
            import urllib.request
            import urllib.error
            
            start_time = time.time()
            
            req = urllib.request.Request(
                target,
                headers={'User-Agent': 'TargetReachabilityChecker/1.0'}
            )
            
            try:
                response = urllib.request.urlopen(req, timeout=self.TIMEOUT)
                code = response.getcode()
                elapsed = time.time() - start_time
                return code, elapsed
            except urllib.error.HTTPError as e:
                elapsed = time.time() - start_time
                return e.code, elapsed
            except urllib.error.URLError:
                return None, None
                
        except Exception:
            return None, None

    def generate_report(self) -> Dict:
        """生成可达性报告"""
        report = {
            'total_targets': len(self.results),
            'reachable': sum(1 for r in self.results.values() if r.is_reachable),
            'unreachable': sum(1 for r in self.results.values() if not r.is_reachable),
            'details': []
        }
        
        for target, result in self.results.items():
            report['details'].append({
                'target': result.target,
                'reachable': result.is_reachable,
                'host': result.host,
                'port': result.port,
                'protocol': result.protocol,
                'response_code': result.response_code,
                'response_time': result.response_time,
                'error': result.error_message,
                'suggestions': result.suggestions
            })
        
        return report


async def check_target_reachability(target: str) -> ReachabilityResult:
    """便捷函数：快速检测目标可达性"""
    checker = TargetReachabilityChecker()
    return await checker.check_target(target)


def print_reachability_result(result: ReachabilityResult):
    """打印可达性检测结果"""
    print(f"\n{'='*60}")
    print(f"目标: {result.target}")
    print(f"{'='*60}")
    print(f"可达性: {'Yes' if result.is_reachable else 'No'}")
    print(f"主机: {result.host}:{result.port}")
    print(f"协议: {result.protocol}")
    
    if result.response_code:
        print(f"HTTP 状态码: {result.response_code}")
    
    if result.response_time:
        print(f"响应时间: {result.response_time:.3f}s")
    
    if result.error_message:
        print(f"错误: {result.error_message}")
    
    if result.suggestions:
        print(f"建议:")
        for suggestion in result.suggestions:
            print(f"  - {suggestion}")
    
    print(f"{'='*60}\n")


__all__ = ['TargetReachabilityChecker', 'ReachabilityResult', 'check_target_reachability', 'print_reachability_result']
