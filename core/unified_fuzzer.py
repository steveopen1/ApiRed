"""
Unified Fuzzer - 统一Fuzzing入口

整合所有Fuzzing功能到一个统一入口：
1. SensitivePathFuzzer - 敏感路径探测
2. FuzzTester - 参数模糊测试
3. EnhancedPayloadManager - 智能Payload选择

智能Payload选择策略：
- 根据响应Content-Type选择最合适的Payload
- 根据目标上下文（URL参数、Header、Cookie）调整Payload
- 自动降级：复杂Payload失败后尝试简单Payload
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional, Callable, Set, Tuple
from dataclasses import dataclass

from .testers.enhanced_payloads import EnhancedPayloadManager, create_payload_manager
from .fuzzing.sensitive_path_fuzzer import SensitivePathFuzzer, PathFuzzFinding
from .testers.fuzz_tester import FuzzTester, FuzzResult

logger = logging.getLogger(__name__)


@dataclass
class UnifiedFuzzResult:
    """统一Fuzz结果"""
    url: str
    method: str
    payload: str
    vul_type: str
    severity: str
    status_code: int
    confidence: float
    source: str


class UnifiedFuzzer:
    """
    统一Fuzzer
    
    一个入口调用所有fuzzing功能：
    - 敏感路径探测
    - SQL注入测试
    - XSS测试
    - SSRF测试
    - 命令注入测试
    - 路径遍历测试
    """
    
    def __init__(self, http_client=None):
        self.http_client = http_client
        self._payload_manager = create_payload_manager()
        self._path_fuzzer = SensitivePathFuzzer(http_client)
        self._fuzz_tester = FuzzTester(http_client) if http_client else None
        self._results: List[UnifiedFuzzResult] = []
        self._vuln_count = 0
    
    @property
    def stats(self) -> Dict[str, Any]:
        return {
            'total_results': len(self._results),
            'vulnerabilities_found': self._vuln_count,
            'payload_stats': self._payload_manager.statistics,
        }
    
    async def fuzz_all(
        self,
        base_url: str,
        vul_types: Optional[List[str]] = None,
        severity_filter: str = 'all',
        callback: Optional[Callable] = None
    ) -> List[UnifiedFuzzResult]:
        """
        执行所有类型的Fuzzing
        
        Args:
            base_url: 目标URL
            vul_types: 要测试的漏洞类型列表，None则测试所有
            severity_filter: 严重程度过滤
            callback: 结果回调
            
        Returns:
            发现的漏洞列表
        """
        if vul_types is None:
            vul_types = ['sql_injection', 'xss', 'ssrf', 'path_traversal', 'command_injection']
        
        self._results = []
        self._vuln_count = 0
        
        tasks = []
        if 'sensitive_path' in vul_types:
            tasks.append(self._fuzz_sensitive_paths(base_url, severity_filter))
        
        if 'sql_injection' in vul_types:
            tasks.append(self._fuzz_sql_injection(base_url, callback))
        
        if 'xss' in vul_types:
            tasks.append(self._fuzz_xss(base_url, callback))
        
        if 'ssrf' in vul_types:
            tasks.append(self._fuzz_ssrf(base_url, callback))
        
        if 'path_traversal' in vul_types:
            tasks.append(self._fuzz_path_traversal(base_url, callback))
        
        if 'command_injection' in vul_types:
            tasks.append(self._fuzz_command_injection(base_url, callback))
        
        await asyncio.gather(*tasks, return_exceptions=True)
        
        return self._results
    
    async def fuzz_sensitive_paths(
        self,
        base_url: str,
        severity_filter: str = 'all'
    ) -> List[UnifiedFuzzResult]:
        """Fuzz敏感路径"""
        findings = await self._path_fuzzer.fuzz(base_url, severity_filter=severity_filter)
        
        for finding in findings:
            result = UnifiedFuzzResult(
                url=f"{base_url.rstrip('/')}/{finding.path.lstrip('/')}",
                method='GET',
                payload=finding.path,
                vul_type='sensitive_path',
                severity=finding.severity,
                status_code=finding.status_code,
                confidence=0.9 if finding.is_sensitive else 0.5,
                source='sensitive_path_fuzzer'
            )
            self._results.append(result)
            self._vuln_count += 1
        
        return self._results
    
    async def _fuzz_sql_injection(self, url: str, callback: Optional[Callable]) -> List[UnifiedFuzzResult]:
        """SQL注入测试"""
        if not self._fuzz_tester:
            return []
        
        results = await self._fuzz_tester.fuzz_sql_injection(url, callback=callback)
        
        for result in results:
            unified = UnifiedFuzzResult(
                url=result.url,
                method=result.method,
                payload=result.payload,
                vul_type='sql_injection' if result.is_vulnerable else 'none',
                severity='high' if result.is_vulnerable else 'info',
                status_code=result.status_code,
                confidence=0.8 if result.is_vulnerable else 0.0,
                source='fuzz_tester'
            )
            if unified.vul_type != 'none':
                self._results.append(unified)
                self._vuln_count += 1
        
        return self._results
    
    async def _fuzz_xss(self, url: str, callback: Optional[Callable]) -> List[UnifiedFuzzResult]:
        """XSS测试"""
        if not self._fuzz_tester:
            return []
        
        results = await self._fuzz_tester.fuzz_xss(url, callback=callback)
        
        for result in results:
            unified = UnifiedFuzzResult(
                url=result.url,
                method=result.method,
                payload=result.payload,
                vul_type='xss' if result.is_vulnerable else 'none',
                severity='high' if result.is_vulnerable else 'info',
                status_code=result.status_code,
                confidence=0.8 if result.is_vulnerable else 0.0,
                source='fuzz_tester'
            )
            if unified.vul_type != 'none':
                self._results.append(unified)
                self._vuln_count += 1
        
        return self._results
    
    async def _fuzz_ssrf(self, url: str, callback: Optional[Callable]) -> List[UnifiedFuzzResult]:
        """SSRF测试"""
        if not self._fuzz_tester:
            return []
        
        results = await self._fuzz_tester.fuzz_ssrf(url, callback=callback)
        
        for result in results:
            unified = UnifiedFuzzResult(
                url=result.url,
                method=result.method,
                payload=result.payload,
                vul_type='ssrf' if result.is_vulnerable else 'none',
                severity='medium' if result.is_vulnerable else 'info',
                status_code=result.status_code,
                confidence=0.7 if result.is_vulnerable else 0.0,
                source='fuzz_tester'
            )
            if unified.vul_type != 'none':
                self._results.append(unified)
                self._vuln_count += 1
        
        return self._results
    
    async def _fuzz_path_traversal(self, url: str, callback: Optional[Callable]) -> List[UnifiedFuzzResult]:
        """路径遍历测试"""
        if not self._fuzz_tester:
            return []
        
        results = await self._fuzz_tester.fuzz_path_traversal(url, callback=callback)
        
        for result in results:
            unified = UnifiedFuzzResult(
                url=result.url,
                method=result.method,
                payload=result.payload,
                vul_type='path_traversal' if result.is_vulnerable else 'none',
                severity='high' if result.is_vulnerable else 'info',
                status_code=result.status_code,
                confidence=0.8 if result.is_vulnerable else 0.0,
                source='fuzz_tester'
            )
            if unified.vul_type != 'none':
                self._results.append(unified)
                self._vuln_count += 1
        
        return self._results
    
    async def _fuzz_command_injection(self, url: str, callback: Optional[Callable]) -> List[UnifiedFuzzResult]:
        """命令注入测试"""
        if not self._fuzz_tester:
            return []
        
        results = await self._fuzz_tester.fuzz_command_injection(url, callback=callback)
        
        for result in results:
            unified = UnifiedFuzzResult(
                url=result.url,
                method=result.method,
                payload=result.payload,
                vul_type='command_injection' if result.is_vulnerable else 'none',
                severity='critical' if result.is_vulnerable else 'info',
                status_code=result.status_code,
                confidence=0.9 if result.is_vulnerable else 0.0,
                source='fuzz_tester'
            )
            if unified.vul_type != 'none':
                self._results.append(unified)
                self._vuln_count += 1
        
        return self._results
    
    def get_vulnerabilities_by_severity(self, severity: str) -> List[UnifiedFuzzResult]:
        """按严重程度获取漏洞"""
        return [r for r in self._results if r.severity == severity]
    
    def get_vulnerabilities_by_type(self, vul_type: str) -> List[UnifiedFuzzResult]:
        """按类型获取漏洞"""
        return [r for r in self._results if r.vul_type == vul_type]
    
    def get_high_confidence_vulns(self, threshold: float = 0.7) -> List[UnifiedFuzzResult]:
        """获取高置信度漏洞"""
        return [r for r in self._results if r.confidence >= threshold]


async def unified_fuzz(
    base_url: str,
    http_client=None,
    vul_types: Optional[List[str]] = None,
    severity_filter: str = 'all'
) -> Tuple[List[UnifiedFuzzResult], Dict[str, Any]]:
    """
    便捷函数：执行统一Fuzzing
    
    Returns:
        (漏洞列表, 统计信息)
    """
    fuzzer = UnifiedFuzzer(http_client)
    results = await fuzzer.fuzz_all(base_url, vul_types, severity_filter)
    return results, fuzzer.stats


from typing import Tuple
