"""
Performance Benchmark Tests
性能基准测试
"""

import pytest
import time
import asyncio
import tracemalloc
from typing import List


def get_memory_usage_mb() -> float:
    """获取当前内存使用量（MB）"""
    if tracemalloc.is_tracing():
        current, peak = tracemalloc.get_traced_memory()
        return current / 1024 / 1024
    else:
        tracemalloc.start()
        return 0


@pytest.fixture(autouse=True)
def memory_tracking():
    """自动跟踪内存使用"""
    tracemalloc.start()
    yield
    tracemalloc.stop()


@pytest.mark.asyncio
async def test_scanner_memory_usage():
    """测试扫描器内存占用"""
    from core.scanner import ChkApiScanner, ScannerConfig
    
    tracemalloc.start()
    
    config = ScannerConfig(target="http://example.com")
    scanner = ChkApiScanner(config)
    
    await scanner.initialize()
    
    current, peak = tracemalloc.get_traced_memory()
    memory_mb = current / 1024 / 1024
    
    tracemalloc.stop()
    
    assert memory_mb < 100  # 初始化应该小于 100MB


@pytest.mark.asyncio
async def test_api_scorer_performance():
    """测试 API 评分器性能"""
    from core.analyzers.api_scorer import APIScorer
    
    scorer = APIScorer()
    
    start_time = time.time()
    
    for i in range(1000):
        path = f"/api/test/endpoint_{i}"
        scorer.add_evidence(path, 'js_regex', {'source': f'test_{i}'})
        scorer.add_evidence(path, 'http_test', {'status': 200})
    
    elapsed = time.time() - start_time
    
    assert elapsed < 1.0  # 1000次评分应该在1秒内完成


@pytest.mark.asyncio
async def test_response_cluster_performance():
    """测试响应聚类性能"""
    from core.analyzers.response_cluster import ResponseCluster, ResponseFingerprint
    
    cluster = ResponseCluster()
    
    start_time = time.time()
    
    for i in range(500):
        fingerprint = ResponseFingerprint(
            status_code=200 if i % 10 != 0 else 404,
            length_bucket="small",
            template_hash=f"hash_{i % 10}",
            raw_hash=f"raw_{i}",
            content_preview="test content",
            url=f"endpoint_{i}"
        )
        cluster.add_response(fingerprint)
    
    cluster.analyze_clusters()
    
    elapsed = time.time() - start_time
    
    assert elapsed < 0.5  # 500次聚类分析应该在0.5秒内完成


@pytest.mark.asyncio
async def test_concurrent_http_requests():
    """测试并发 HTTP 请求性能"""
    from core.utils.http_client import AsyncHttpClient
    
    client = AsyncHttpClient(max_concurrent=10)
    
    start_time = time.time()
    
    tasks = []
    for i in range(20):
        task = client.request(f"http://httpbin.org/delay/0?id={i}")
        tasks.append(task)
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    elapsed = time.time() - start_time
    
    assert elapsed < 5.0  # 20个并发请求（延迟0秒）应该在5秒内完成
    assert len(results) == 20


@pytest.mark.asyncio
async def test_plugin_registry_performance():
    """测试插件注册表性能"""
    from core.plugins import PluginRegistry
    
    class DummyCollector:
        pass
    
    start_time = time.time()
    
    for i in range(100):
        PluginRegistry.register_collector(f'test_{i}', DummyCollector)
    
    elapsed = time.time() - start_time
    
    assert elapsed < 0.1  # 100次注册应该在0.1秒内完成


@pytest.mark.asyncio
async def test_model_serialization_performance():
    """测试模型序列化性能"""
    from core.models import ScanResult, APIEndpoint, Vulnerability, Severity
    
    start_time = time.time()
    
    result = ScanResult(target_url="http://test.com")
    
    for i in range(100):
        endpoint = APIEndpoint(
            path=f"/api/test/{i}",
            method="GET",
            base_url="http://test.com",
            full_url=f"http://test.com/api/test/{i}"
        )
        result.api_endpoints.append(endpoint)
    
    for i in range(50):
        vuln = Vulnerability(
            api_id=f"api_{i}",
            vuln_type="SQL_INJECTION",
            severity=Severity.HIGH,
            evidence=f"evidence_{i}"
        )
        result.vulnerabilities.append(vuln)
    
    result_dict = result.to_dict()
    
    elapsed = time.time() - start_time
    
    assert elapsed < 0.1  # 序列化应该在0.1秒内完成
    assert len(result_dict['api_endpoints']) == 100
    assert len(result_dict['vulnerabilities']) == 50


class TestPerformanceMetrics:
    """性能指标测试类"""
    
    def test_import_speed(self):
        """测试模块导入速度"""
        import sys
        
        start_time = time.time()
        
        # 清除缓存重新导入
        modules_to_test = [
            'core.scanner',
            'core.engine',
            'core.agents.scanner_agent',
            'core.analyzers.api_scorer',
            'core.exporters.openapi_exporter'
        ]
        
        for mod in modules_to_test:
            if mod in sys.modules:
                del sys.modules[mod]
        
        for mod in modules_to_test:
            __import__(mod)
        
        elapsed = time.time() - start_time
        
        assert elapsed < 2.0  # 所有模块导入应该在2秒内完成
    
    def test_scanner_config_creation_speed(self):
        """测试配置创建速度"""
        from core.scanner import ScannerConfig
        
        start_time = time.time()
        
        for i in range(1000):
            config = ScannerConfig(
                target=f"http://test{i}.com",
                attack_mode="all",
                concurrency=50
            )
        
        elapsed = time.time() - start_time
        
        assert elapsed < 0.5  # 1000次配置创建应该在0.5秒内完成
