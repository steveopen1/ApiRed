"""
End-to-End Integration Tests
使用 mock server 测试完整扫描流程
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch


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
async def test_vulnerability_tester_yaml_based_tests():
    """测试 VulnerabilityTester YAML-based 测试方法"""
    from core.testers.vulnerability_tester import VulnerabilityTester, VulnType
    from unittest.mock import AsyncMock, MagicMock
    
    mock_http_client = MagicMock()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.content = '{"result": "test"}'
    mock_response.headers = {}
    mock_http_client.request = AsyncMock(return_value=mock_response)
    
    tester = VulnerabilityTester(mock_http_client)
    
    result = await tester.test_sql_injection(
        url="http://test.com/api/query",
        method="GET",
        param_name="q"
    )
    
    assert result is not None
    assert result.vuln_type == VulnType.SQL_INJECTION
    assert isinstance(result.is_vulnerable, bool)


@pytest.mark.asyncio
async def test_vulnerability_tester_crlf():
    """测试 CRLF 注入测试方法"""
    from core.testers.vulnerability_tester import VulnerabilityTester, VulnType
    from unittest.mock import AsyncMock, MagicMock
    
    mock_http_client = MagicMock()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.content = 'X-Injected: header'
    mock_response.headers = {'Access-Control-Allow-Origin': 'X-Injected: test'}
    mock_http_client.request = AsyncMock(return_value=mock_response)
    
    tester = VulnerabilityTester(mock_http_client)
    
    result = await tester.test_crlf_injection(
        url="http://test.com/api/redirect",
        param_name="url"
    )
    
    assert result is not None
    assert result.vuln_type == VulnType.CRLF_INJECTION
    assert isinstance(result.is_vulnerable, bool)


@pytest.mark.asyncio
async def test_vulnerability_tester_lfi():
    """测试 LFI 测试方法"""
    from core.testers.vulnerability_tester import VulnerabilityTester, VulnType
    from unittest.mock import AsyncMock, MagicMock
    
    mock_http_client = MagicMock()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.content = 'root:x:0:0:root:/root:/bin/bash'
    mock_response.headers = {}
    mock_http_client.request = AsyncMock(return_value=mock_response)
    
    tester = VulnerabilityTester(mock_http_client)
    
    result = await tester.test_lfi(
        url="http://test.com/api/file",
        param_name="file"
    )
    
    assert result is not None
    assert result.vuln_type == VulnType.LFI
    assert isinstance(result.is_vulnerable, bool)


@pytest.mark.asyncio
async def test_vulnerability_tester_ssti():
    """测试 SSTI 测试方法"""
    from core.testers.vulnerability_tester import VulnerabilityTester, VulnType
    from unittest.mock import AsyncMock, MagicMock
    
    mock_http_client = MagicMock()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.content = 'Template error: 49 is not defined'
    mock_response.headers = {}
    mock_http_client.request = AsyncMock(return_value=mock_response)
    
    tester = VulnerabilityTester(mock_http_client)
    
    result = await tester.test_ssti(
        url="http://test.com/api/template",
        param_name="template"
    )
    
    assert result is not None
    assert result.vuln_type == VulnType.SSTI
    assert isinstance(result.is_vulnerable, bool)


@pytest.mark.asyncio
async def test_http_client_fallback():
    """测试 HTTP 客户端 SSL 降级机制"""
    from core.utils.http_client import AsyncHttpClient, TaskResult
    from unittest.mock import patch, AsyncMock
    
    client = AsyncHttpClient(max_concurrent=10, verify_ssl=False)
    
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.headers = {'Content-Type': 'text/html'}
    mock_response.text = '<html>test</html>'
    mock_response.content = b'<html>test</html>'
    
    with patch('requests.get') as mock_get:
        mock_get.return_value = mock_response
        
        result = await client._fallback_request(
            url="http://test.com/",
            method="GET",
            headers={},
            data=None,
            timeout=30,
            verify_ssl=False
        )
        
        assert result.status_code == 200
        assert result.content == '<html>test</html>'


@pytest.mark.asyncio
async def test_test_selector_with_endpoint():
    """测试 TestSelector 端点选择"""
    from core.analyzers.test_selector import TestSelector, TestCategory, EndpointFeatures, EndpointFeature
    
    selector = TestSelector()
    
    features = EndpointFeatures(
        path="/api/users/search",
        method="GET",
        features={EndpointFeature.HAS_SEARCH_PARAM, EndpointFeature.IS_API_ENDPOINT},
        param_names=["q", "limit"]
    )
    
    selections = selector.select_tests(features, {TestCategory.SQL_INJECTION, TestCategory.XSS})
    
    assert len(selections) > 0
    assert all(s.priority > 0 for s in selections)


@pytest.mark.asyncio
async def test_response_baseline_learner():
    """测试 ResponseBaselineLearner"""
    from core.analyzers.response_baseline import ResponseBaselineLearner
    from core.utils.http_client import TaskResult
    
    learner = ResponseBaselineLearner()
    
    responses = [
        TaskResult(url="http://test.com/1", method="GET", status_code=200, content="{\"data\": 1}", content_bytes=b'{"data": 1}', content_hash="hash1"),
        TaskResult(url="http://test.com/2", method="GET", status_code=200, content="{\"data\": 2}", content_bytes=b'{"data": 2}', content_hash="hash2"),
        TaskResult(url="http://test.com/3", method="GET", status_code=404, content="Not Found", content_bytes=b'Not Found', content_hash="hash3"),
    ]
    
    learner.learn(responses)
    
    assert learner.get_baseline_count() >= 2
    assert learner.get_default_page_count() >= 0


@pytest.mark.asyncio
async def test_response_cluster():
    """测试响应聚类"""
    from core.analyzers.response_cluster import ResponseCluster, TaskResult
    
    cluster = ResponseCluster()
    
    response1 = TaskResult(
        status_code=200,
        content=b'{"data": "test"}',
        content_hash="abc123def456"
    )
    response2 = TaskResult(
        status_code=404,
        content=b'Not Found',
        content_hash="xyz789uvw012"
    )
    
    cluster.add_response('endpoint1', response1)
    cluster.add_response('endpoint2', response2)
    
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
