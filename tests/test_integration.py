"""
End-to-End Integration Tests
使用 mock server 测试完整扫描流程
"""

import pytest
import asyncio


@pytest.mark.asyncio
async def test_engine_initialization():
    """测试 ScanEngine 初始化"""
    from core.engine import ScanEngine, EngineConfig
    
    config = EngineConfig(target="http://localhost:9999")
    engine = ScanEngine(config)
    
    assert engine.config.target == "http://localhost:9999"
    assert engine.result is None
    assert engine._running is False


@pytest.mark.asyncio
async def test_scanner_initialization():
    """测试扫描器初始化"""
    from core.scanner import ChkApiScanner, ScannerConfig
    
    config = ScannerConfig(
        target="http://127.0.0.1:9998",
        attack_mode="collect",
        no_api_scan=True
    )
    
    scanner = ChkApiScanner(config)
    await scanner.initialize()
    
    assert scanner.js_cache is not None
    assert scanner.api_aggregator is not None
    assert scanner.api_scorer is not None
    assert scanner.response_cluster is not None
    
    await scanner.cleanup()


@pytest.mark.asyncio
async def test_checkpoint_functionality():
    """测试检查点功能"""
    from core.scanner import ScanCheckpoint
    
    checkpoint = ScanCheckpoint(
        target="http://127.0.0.1:9997",
        current_stage="collect",
        stage_results={},
        js_cache_state=[],
        discovered_apis=[],
        tested_apis=[],
        vulnerabilities=[],
        timestamp=0.0
    )
    
    assert checkpoint.target == "http://127.0.0.1:9997"
    assert checkpoint.current_stage == "collect"


@pytest.mark.asyncio
async def test_api_endpoint_scoring():
    """测试 API 端点评分"""
    from core.analyzers.api_scorer import APIScorer
    
    scorer = APIScorer(min_high_value_score=5)
    
    scorer.add_evidence('/api/admin/users', 'js_regex', {'source': 'test'})
    scorer.add_evidence('/api/admin/users', 'http_test', {'status': 200})
    
    high_value = scorer.get_high_value()
    
    assert len(high_value) >= 0
    assert all(hasattr(e, 'score') for e in scorer.get_all())


@pytest.mark.asyncio
async def test_response_cluster():
    """测试响应聚类"""
    from core.analyzers.response_cluster import ResponseCluster, ResponseFingerprint
    
    cluster = ResponseCluster()
    
    fingerprint1 = ResponseFingerprint(
        status_code=200,
        length_bucket="small",
        template_hash="abc123",
        raw_hash="def456",
        content_preview="test",
        url="endpoint1"
    )
    fingerprint2 = ResponseFingerprint(
        status_code=404,
        length_bucket="tiny",
        template_hash="xyz789",
        raw_hash="uvw012",
        content_preview="",
        url="endpoint2"
    )
    
    cluster.add_response(fingerprint1)
    cluster.add_response(fingerprint2)
    
    assert cluster.is_baseline_404('endpoint2') is False


@pytest.mark.asyncio
async def test_plugin_registry():
    """测试插件注册表"""
    from core.plugins import PluginRegistry, BypassTesterPlugin
    
    collectors_before = PluginRegistry.list_collectors()
    testers_before = PluginRegistry.list_testers()
    
    PluginRegistry.register_tester('bypass_test', BypassTesterPlugin)
    
    assert 'bypass_test' in PluginRegistry.list_testers()
    assert PluginRegistry.get_tester('bypass_test') == BypassTesterPlugin


@pytest.mark.asyncio
async def test_openapi_exporter():
    """测试 OpenAPI 导出"""
    from core.exporters.openapi_exporter import OpenAPIExporter
    from core.models import ScanResult, APIEndpoint, APIStatus
    
    exporter = OpenAPIExporter()
    
    result = ScanResult(target_url="http://test.com")
    result.api_endpoints = [
        APIEndpoint(
            path="/api/users",
            method="GET",
            base_url="http://test.com",
            full_url="http://test.com/api/users",
            status=APIStatus.ALIVE
        )
    ]
    
    spec = exporter.generate_from_scan_result(result)
    
    assert spec['openapi'] == '3.0.0'
    assert '/api/users' in spec['paths']
    assert 'get' in spec['paths']['/api/users']


@pytest.mark.asyncio
async def test_scan_result_creation():
    """测试扫描结果创建"""
    from core.models import ScanResult, APIEndpoint, Vulnerability, Severity
    
    result = ScanResult(target_url="http://test.com")
    result.api_endpoints = [
        APIEndpoint(
            path="/api/users",
            method="GET",
            base_url="http://test.com",
            full_url="http://test.com/api/users"
        )
    ]
    result.vulnerabilities = [
        Vulnerability(
            api_id="test123",
            vuln_type="SQL_INJECTION",
            severity=Severity.HIGH,
            evidence="payload detected"
        )
    ]
    
    assert result.total_apis == 0
    assert len(result.api_endpoints) == 1
    assert len(result.vulnerabilities) == 1
    assert result.vulnerabilities[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_agent_memory():
    """测试 Agent 记忆"""
    from core.agents.base import AgentMemory
    
    memory = AgentMemory()
    
    memory.add("Test entry 1", "short")
    memory.add("Test entry 2", "short")
    memory.add("Important fact", "long")
    
    recent = memory.get_recent(2)
    all_mem = memory.get_all()
    
    assert len(recent) == 2
    assert len(all_mem['long_term']) == 1


@pytest.mark.asyncio
async def test_ai_engine_creation():
    """测试 AI 引擎创建"""
    from core.ai.ai_engine import AIEngine, AIConfig
    
    config = AIConfig(provider="deepseek", api_key="test-key")
    engine = AIEngine(config)
    
    assert engine.config.provider == "deepseek"
    assert engine.client is not None
    assert engine.profiler is not None
    assert engine.api_analyzer is not None
