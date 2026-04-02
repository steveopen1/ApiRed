"""
ScanEngine - 统一扫描引擎
提供Collector → Analyzer → Tester的标准化流程
"""

import asyncio
import time
import os
import re
import json
import logging
from enum import Enum
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

from .utils.config import Config
from .storage import DBStorage, FileStorage, RealtimeOutput, OutputManager, get_output_manager
from .collectors import JSFingerprintCache, JSParser, APIAggregator, HeadlessBrowserCollector
from .collectors.api_collector import APIPathCombiner, ServiceAnalyzer
from .collectors.js_ast_analyzer import JavaScriptASTAnalyzer
from .collectors.swagger_discoverer import SwaggerDiscoverer, discover_swagger
from .collectors.api_bypass import APIBypasser, SmartBypasser
from .collectors.passive_sources import PassiveSourceCollector
from .collectors.smart_filter import SmartFilter, prioritize_endpoints
from .analyzers import APIScorer, APIEvidenceAggregator, ResponseCluster, TwoTierSensitiveDetector
from .analyzers.response_baseline import ResponseBaselineLearner
from .testers import FuzzTester, VulnerabilityTester, APIRequestTester, APIBypassTester
from .testers.idor_tester import IDORTester
from .utils.url_greper import URLGreper
from .utils.gf import GFLibrary
from .utils.adaptive_scheduler import AdaptiveBatchScheduler
from .utils.error_handler import (
    ErrorSeverity,
    FuzzingError,
    NetworkError,
    DNSError,
    HTTPError,
    ConfigurationError,
    FatalError,
    ErrorHandler,
    CircuitBreaker
)
from .agents import ScannerAgent, AnalyzerAgent, TesterAgent, AgentConfig
from .agents import Orchestrator, DiscoverAgent, TestAgent, ReflectAgent
from .agents.orchestrator import ScanContext
from .knowledge_base import KnowledgeBase
from .models import ScanResult, APIEndpoint, Severity
from .framework import FrameworkDetector
from .exporters import ReportExporter, OpenAPIExporter, AttackChainExporter
from .observability import RunProfiler

from .fingerprint import FingerprintEngine, FingerprintResult
from .unified_fuzzer import UnifiedFuzzer
from .unified_fusion import UnifiedFusionEngine, FusedEndpoint, SourceType, EndpointType, ConfidenceLevel
from .secret_matcher import SecretMatcher, SecretMatch, SecretType, RiskLevel
from .vuln_prioritizer import VulnPrioritizer, VulnCandidate, VulnPriority, VulnCategory
from .waf_detector import WAFDetector, WAFBypass, WAFResult
from .differential_tester import DifferentialTester, DifferentialResult, BaselineResponse
from .js_resolver import JSResolver, JSDiscoveryRecord, extract_js_urls
from .render_state import StateBudget, StateDeduplicator, StateQueue, ClickTargetEvaluator, PageState
from .route_tracker import RouteTracker, RouteChange, StorageSync, ResponseCapture
from .ai_security import AISecurityTester, AIVulnResult
from .kubernetes_security import K8sSecurityTester, K8sVulnResult
from .container_security import ContainerSecurityTester, ContainerVulnResult
from .cicd_scanner import CICDScanner, CICDVulnResult
from .cloud_security import CloudBucketTester, CloudSecretScanner, CloudVulnResult
from .api_posture import SecurityPostureAnalyzer, analyze_security_posture, APICoverageAnalyzer
from .config.api_patterns import COMMON_API_PATHS, RESTFUL_SUFFIXES, FUZZ_SUFFIXES, PATH_FRAGMENTS
from .config.probe_patterns import ACTION_SUFFIXES, RESOURCE_WORDS, CRUD_SUFFIXES
from .collectors.oss_collector import OSSCollector, OSSEndpoint, get_oss_collector, CloudProvider
from .testers.oss_vuln_tester import OSSVulnTester, OSSVulnResult as OSSVulnTestResult, OSSVulnType, RiskLevel as OSSRiskLevel
from .collectors.browser_enhancer import SensitiveInfoExtractor, PathPrefixLearner


@dataclass
class EngineConfig:
    """引擎配置"""
    target: str
    collectors: Optional[List[str]] = None
    analyzers: Optional[List[str]] = None
    testers: Optional[List[str]] = None
    ai_enabled: bool = False
    checkpoint_enabled: bool = True
    cookies: str = ""
    concurrency: int = 50
    concurrency_probe: bool = False
    proxy: Optional[str] = None
    js_depth: int = 3
    output_dir: str = "./results"
    attack_mode: str = "all"
    no_api_scan: bool = False
    chrome: bool = True
    verify_ssl: bool = True
    resume: bool = False
    targets: List[str] = field(default_factory=list)
    concurrent_targets: int = 5
    aggregate: bool = False
    agent_mode: bool = False
    incremental: bool = False
    # 漏洞测试开关
    enable_sql_test: bool = True
    enable_xss_test: bool = True
    enable_ssrf_test: bool = True
    enable_bypass_test: bool = True
    enable_jwt_test: bool = True
    enable_idor_test: bool = True
    enable_unauthorized_test: bool = True
    enable_info_disclosure_test: bool = True
    # 报告格式
    report_formats: List[str] = field(default_factory=lambda: ['json', 'html'])

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EngineConfig':
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered_data = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered_data)


@dataclass
class ScanCheckpoint:
    """扫描检查点"""
    target: str
    current_stage: str
    stage_index: int
    collector_results: Dict[str, Any]
    analyzer_results: Dict[str, Any]
    tester_results: Dict[str, Any]
    discovered_apis: List[Dict]
    vulnerabilities: List[Dict]
    timestamp: float


class ScanEngine:
    """统一扫描引擎"""
    
    _HREF_PATTERN = re.compile(r'href=["\']([^"\']+)["\']')
    _SRC_PATTERN = re.compile(r'src=["\']([^"\']+)["\']')
    _ACTION_PATTERN = re.compile(r'action=["\']([^"\']+)["\']')
    _URL_PATTERN = re.compile(r'url:\s*["\']([^"\']+)["\']')
    _API_URL_PATTERN = re.compile(r'["\'](\/api\/[^"\']+)["\']')
    _GENERIC_API_PATTERN = re.compile(r'["\'](/[a-zA-Z0-9_/-]+)["\']')
    _CONFIG_PATTERN = re.compile(r'(?:baseURL|apiUrl|api_base)\s*[:=]\s*["\']([^"\']+)["\']')
    _ROUTER_PATTERN = re.compile(r'router(?:\.push|\.replace)\(["\']([^"\']+)["\']')
    
    def __init__(self, config: EngineConfig):
        self.config = config
        self.cfg = Config()
        
        self._http_client = None
        self.db_storage: Optional[DBStorage] = None
        self.file_storage: Optional[FileStorage] = None
        
        self._js_cache: Optional[JSFingerprintCache] = None
        self._api_aggregator: Optional[APIAggregator] = None
        self._api_scorer: Optional[APIScorer] = None
        self._evidence_aggregator: Optional[APIEvidenceAggregator] = None
        self._response_cluster: Optional[ResponseCluster] = None
        self._sensitive_detector: Optional[TwoTierSensitiveDetector] = None
        self._fuzz_tester: Optional[FuzzTester] = None
        self._unified_fuzzer: Optional[UnifiedFuzzer] = None
        self._vulnerability_tester: Optional[VulnerabilityTester] = None
        self._api_request_tester: Optional[APIRequestTester] = None
        self._profiler: Optional[RunProfiler] = None
        
        self.scanner_agent: Optional[ScannerAgent] = None
        self.analyzer_agent: Optional[AnalyzerAgent] = None
        self.tester_agent: Optional[TesterAgent] = None
        
        self._orchestrator: Optional[Orchestrator] = None
        self._knowledge_base: Optional[KnowledgeBase] = None
        self._realtime_output: Optional[RealtimeOutput] = None
        
        self.result: Optional[ScanResult] = None
        self._current_stage = 0
        self._running = False
        self._checkpoint: Optional[ScanCheckpoint] = None
        self._collector_results: Dict[str, Any] = {}
        self._oss_collector = None
        self._sensitive_info_extractor = SensitiveInfoExtractor()
        self._path_prefix_learner = PathPrefixLearner()
        self._callbacks: Dict[str, List[Any]] = {
            'stage_start': [],
            'stage_progress': [],
            'stage_complete': [],
            'finding': [],
            'error': []
        }
        
        self._stage_names = ["collect", "analyze", "test"]
        
        self._active_tasks: Set[asyncio.Task] = set()
        self._tasks_lock = asyncio.Lock()
        self._last_progress_time: float = 0
        self._progress_interval: float = 5.0
        self._total_apis_found: int = 0
        self._vulns_found: int = 0
    
    def _register_task(self, task: asyncio.Task):
        """注册进行中的任务"""
        self._active_tasks.add(task)
        task.add_done_callback(self._unregister_task)
    
    def _unregister_task(self, task: asyncio.Task):
        """取消注册完成的任务"""
        self._active_tasks.discard(task)
    
    def on(self, event: str, callback: Any):
        """注册事件回调"""
        if event in self._callbacks:
            self._callbacks[event].append(callback)
    
    def _emit(self, event: str, data: Any):
        """触发事件"""
        for callback in self._callbacks.get(event, []):
            try:
                callback(data)
            except Exception as e:
                logger.warning(f"Callback error for event '{event}': {e}")

    def _emit_progress(self, stage: str = "", phase: str = ""):
        """触发进度更新事件"""
        now = time.time()
        if now - self._last_progress_time < self._progress_interval:
            return
        self._last_progress_time = now

        total_apis = 0
        alive_apis = 0
        high_value_apis = 0
        vulnerabilities = 0

        if self.result:
            total_apis = getattr(self.result, 'total_apis', 0)
            alive_apis = getattr(self.result, 'alive_apis', 0)
            high_value_apis = getattr(self.result, 'high_value_apis', 0)
            vulnerabilities = len(getattr(self.result, 'vulnerabilities', []))

        stage_progress = 0
        if stage == 'collect':
            stage_progress = 25
        elif stage == 'analyze':
            stage_progress = 50
        elif stage == 'test':
            stage_progress = 75
        elif stage == 'reporting':
            stage_progress = 95

        progress_data = {
            'stage': stage or self.current_stage_name,
            'current_phase': phase,
            'progress': stage_progress,
            'total_apis': total_apis,
            'alive_apis': alive_apis,
            'high_value_apis': high_value_apis,
            'vulnerabilities_found': vulnerabilities,
            'sensitive_found': 0,
            'timestamp': datetime.now().isoformat()
        }

        self._emit('progress_update', progress_data)

    def _emit_finding(self, finding_type: str, data: Dict[str, Any]):
        """触发发现事件"""
        finding_data = {
            'type': finding_type,
            'data': data,
            'timestamp': datetime.now().isoformat()
        }
        self._emit('finding', finding_data)
    
    @property
    def current_stage_name(self) -> str:
        """获取当前阶段名称"""
        if 0 <= self._current_stage < len(self._stage_names):
            return self._stage_names[self._current_stage]
        return "unknown"
    
    async def initialize(self):
        """初始化引擎"""
        self._running = True
        
        target_parsed = urlparse(self.config.target)
        
        self._output_manager = get_output_manager(self.config.output_dir)
        self._output_manager.setup_for_target(self.config.target)
        
        target_dir = os.path.join(self.config.output_dir, self._output_manager.target_name)
        
        if not os.path.exists(target_dir):
            os.makedirs(target_dir, exist_ok=True)
        
        self.db_storage = DBStorage(
            db_path=self._output_manager.get_checkpoint_db_path(),
            wal_mode=True
        )
        
        self.file_storage = FileStorage(base_dir=target_dir)
        
        self._realtime_output = RealtimeOutput(output_dir=self._output_manager.real_time_dir)
        
        from .utils.http_client import AsyncHttpClient
        self._http_client = AsyncHttpClient(
            max_concurrent=self.config.concurrency,
            max_retries=3,
            timeout=30,
            proxy=self.config.proxy,
            verify_ssl=getattr(self.config, 'verify_ssl', True)
        )
        
        self._js_cache = JSFingerprintCache(self.db_storage)
        self._api_aggregator = APIAggregator(use_fusion=True)
        self._api_scorer = APIScorer(
            min_high_value_score=self.cfg.get('ai.thresholds.high_value_api_score', 3)
        )
        self._evidence_aggregator = APIEvidenceAggregator(self._api_scorer)
        self._response_cluster = ResponseCluster()
        self._response_baseline = ResponseBaselineLearner()
        self._framework_detector = FrameworkDetector()
        self._detected_framework = None
        self._sensitive_detector = TwoTierSensitiveDetector(
            config={'ai_enabled': self.config.ai_enabled}
        )
        
        self._fuzz_tester = FuzzTester(self._http_client)
        from .unified_fuzzer import UnifiedFuzzer
        self._unified_fuzzer = UnifiedFuzzer(self._http_client)
        
        patterns_dir = os.path.join(os.path.dirname(__file__), 'utils', 'patterns')
        if os.path.exists(patterns_dir):
            self._gf_library = GFLibrary(patterns_dir)
            logger.info(f"GF Library initialized with patterns from {patterns_dir}")
        else:
            self._gf_library = GFLibrary()
            logger.info("GF Library initialized with default patterns")
        
        self._vulnerability_tester = VulnerabilityTester(self._http_client, self._gf_library)
        self._idor_tester = IDORTester(self._http_client)
        self._url_greper = URLGreper()
        self._api_request_tester = APIRequestTester(self._http_client)
        self._bypass_tester = APIBypassTester(self._http_client)
        self._profiler = RunProfiler()
        self._fuzz_batch_scheduler = AdaptiveBatchScheduler(
            initial_batch_size=50,
            min_batch_size=10,
            max_batch_size=100,
            fast_threshold=0.5,
            slow_threshold=2.0
        )
        self._error_handler = ErrorHandler(max_retries=3)
        self._fuzz_circuit_breaker = CircuitBreaker(
            failure_threshold=10,
            recovery_timeout=60.0,
            expected_exception=Exception
        )
        
        self._fingerprint_engine: Optional[FingerprintEngine] = None
        self._endpoint_fusion_engine: Optional[UnifiedFusionEngine] = None
        self._secret_matcher: Optional[SecretMatcher] = None
        self._vuln_prioritizer: Optional[VulnPrioritizer] = None
        self._waf_detector: Optional[WAFDetector] = None
        self._differential_tester: Optional[DifferentialTester] = None
        self._js_resolver: Optional[JSResolver] = None
        self._route_tracker: Optional[RouteTracker] = None
        self._storage_sync: Optional[StorageSync] = None
        self._response_capture: Optional[ResponseCapture] = None
        self._ai_security_tester: Optional[AISecurityTester] = None
        self._k8s_security_tester: Optional[K8sSecurityTester] = None
        self._container_security_tester: Optional[ContainerSecurityTester] = None
        self._cicd_scanner: Optional[CICDScanner] = None
        self._cloud_bucket_tester: Optional[CloudBucketTester] = None
        self._cloud_secret_scanner: Optional[CloudSecretScanner] = None
        
        self._plugins_initialized = False
        self._plugin_registry = None
        try:
            from .plugins import PluginRegistry
            self._plugin_registry = PluginRegistry
            PluginRegistry.discover_plugins('core.plugins')
            self._plugins_initialized = True
            logger.info(f"Plugins loaded: collectors={PluginRegistry.list_collectors()}, testers={PluginRegistry.list_testers()}, exporters={PluginRegistry.list_exporters()}")
        except Exception as e:
            logger.debug(f"Plugin system initialization skipped: {e}")
            self._plugins_initialized = False
        
        self._browser_collector: Optional[HeadlessBrowserCollector] = None
        self._browser_fallback_mode = False
        self._browser_enabled = getattr(self.config, 'chrome', False)
        
        if self._browser_enabled:
            browser_initialized = False
            retry_count = 0
            max_retries = 2
            
            while not browser_initialized and retry_count < max_retries:
                try:
                    self._browser_collector = HeadlessBrowserCollector()
                    ignore_ssl = not getattr(self.config, 'verify_ssl', True)
                    browser_initialized = await self._browser_collector.initialize(headless=True, ignore_ssl_errors=ignore_ssl)
                    
                    if not browser_initialized:
                        retry_count += 1
                        if retry_count < max_retries:
                            logger.warning(f"Browser initialization failed, retrying ({retry_count}/{max_retries})...")
                            await asyncio.sleep(1)
                        else:
                            logger.warning("Browser initialization failed, enabling fallback mode")
                            self._browser_fallback_mode = True
                            self._browser_collector = None
                except Exception as e:
                    retry_count += 1
                    if retry_count < max_retries:
                        logger.warning(f"Browser not available: {e}, retrying ({retry_count}/{max_retries})...")
                        await asyncio.sleep(1)
                    else:
                        logger.warning(f"Browser not available after {max_retries} retries, enabling fallback mode: {e}")
                        self._browser_fallback_mode = True
                        self._browser_collector = None
                        break
        
        self._incremental_scanner = None
        self._url_deduplicator = None
        if getattr(self.config, 'resume', False) or getattr(self.config, 'incremental', False):
            storage_path = self._output_manager.get_checkpoint_db_path() if hasattr(self, '_output_manager') else os.path.join(self.config.output_dir, "incremental.db")
            try:
                from .incremental_scanner import IncrementalScanner, URLDeduplicator
                self._incremental_scanner = IncrementalScanner(storage_path)
                self._url_deduplicator = URLDeduplicator()
                latest = self._incremental_scanner.get_latest_snapshot(self.config.target)
                if latest:
                    logger.info(f"Found previous scan snapshot: {latest.api_count} APIs, {latest.js_count} JS files")
            except Exception as e:
                logger.debug(f"Incremental scanner init error: {e}")
                self._incremental_scanner = None
                self._url_deduplicator = None
        
        self.result = ScanResult(
            target_url=self.config.target,
            start_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        
        await self._initialize_flux_modules()
    
    async def _initialize_flux_modules(self):
        """初始化FLUX移植模块"""
        try:
            requests_session = None
            if hasattr(self._http_client, '_session'):
                requests_session = self._http_client._session  # type: ignore[reportOptionalMemberAccess]
            elif hasattr(self._http_client, 'session'):
                requests_session = self._http_client.session  # type: ignore[reportOptionalMemberAccess]
                
            self._fingerprint_engine = FingerprintEngine(session=requests_session)
            logger.info(f"指纹引擎已加载: {len(self._fingerprint_engine.get_fingerprints())} 条规则")
            
            self._endpoint_fusion_engine = UnifiedFusionEngine()
            self._secret_matcher = SecretMatcher()
            self._vuln_prioritizer = VulnPrioritizer()
            self._waf_detector = WAFDetector()
            self._js_resolver = JSResolver(base_url=self.config.target)
            
            if requests_session:
                self._differential_tester = DifferentialTester(session=requests_session)
                self._ai_security_tester = AISecurityTester(session=requests_session)
                self._k8s_security_tester = K8sSecurityTester(session=requests_session)
                self._container_security_tester = ContainerSecurityTester(session=requests_session)
                self._cicd_scanner = CICDScanner(session=requests_session)
                self._cloud_bucket_tester = CloudBucketTester(session=requests_session)
            
            self._cloud_secret_scanner = CloudSecretScanner()
            
            self._route_tracker = RouteTracker()
            self._storage_sync = StorageSync()
            self._response_capture = ResponseCapture()
            
            logger.info("FLUX移植模块初始化完成")
        except Exception as e:
            logger.warning(f"FLUX模块初始化部分失败: {e}")
    
    async def run(self) -> ScanResult:
        """运行扫描流程"""
        agent_mode = getattr(self.config, 'agent_mode', False)
        
        if agent_mode:
            return await self._run_agent_mode()
        
        await self.initialize()
        
        assert self._api_aggregator is not None, "_api_aggregator not initialized"
        assert self._http_client is not None, "_http_client not initialized"
        assert self._fuzz_tester is not None, "_fuzz_tester not initialized"
        assert self._vulnerability_tester is not None, "_vulnerability_tester not initialized"
        assert self._sensitive_detector is not None, "_sensitive_detector not initialized"
        assert self._response_cluster is not None, "_response_cluster not initialized"
        
        if self._profiler:
            self._profiler.tracker.start_stage('initialization', input_count=1)
            self._profiler.tracker.finish_stage()
        
        attack_mode = getattr(self.config, 'attack_mode', 'all')
        no_api_scan = getattr(self.config, 'no_api_scan', False)
        
        self._emit('stage_start', {'stage': 'initialization', 'status': 'complete'})
        self._last_progress_time = time.time()

        try:
            if attack_mode in ['collect', 'all']:
                self._emit('stage_start', {'stage': 'collect', 'status': 'running'})
                if self._profiler:
                    self._profiler.tracker.start_stage('js_collection', input_count=0)
                await self._run_collectors()
                self._emit_progress('collect', 'js_collection')
                if self._profiler:
                    self._profiler.tracker.finish_stage()
                if self.config.checkpoint_enabled:
                    await self._save_checkpoint()
                self._emit('stage_complete', {'stage': 'collect', 'status': 'complete'})
            
            if attack_mode in ['scan', 'all'] and not no_api_scan:
                self._emit('stage_start', {'stage': 'analyze', 'status': 'running'})
                if self._profiler:
                    self._profiler.tracker.start_stage('api_scoring', input_count=0)
                await self._run_analyzers()
                self._emit_progress('analyze', 'api_scoring')
                if self._profiler:
                    self._profiler.tracker.finish_stage()
                if self.config.checkpoint_enabled:
                    await self._save_checkpoint()
                self._emit('stage_complete', {'stage': 'analyze', 'status': 'complete'})
            elif attack_mode == 'collect':
                await self._score_apis()
                self._emit('stage_start', {'stage': 'analyze', 'status': 'running'})
                if self._profiler:
                    self._profiler.tracker.start_stage('api_scoring', input_count=0)
                await self._run_analyzers()
                self._emit_progress('analyze', 'api_scoring')
                if self._profiler:
                    self._profiler.tracker.finish_stage()
                if self.config.checkpoint_enabled:
                    await self._save_checkpoint()
                self._emit('stage_complete', {'stage': 'analyze', 'status': 'complete'})

                self._emit('stage_start', {'stage': 'test', 'status': 'running'})
                if self._profiler:
                    self._profiler.tracker.start_stage('vuln_testing', input_count=0)
                await self._run_testers()
                self._emit_progress('test', 'vuln_testing')
                if self._profiler:
                    self._profiler.tracker.finish_stage()
                if self.config.checkpoint_enabled:
                    await self._save_checkpoint()
                self._emit('stage_complete', {'stage': 'test', 'status': 'complete'})

            self._emit('stage_start', {'stage': 'reporting', 'status': 'running'})
            if self._profiler:
                self._profiler.tracker.start_stage('reporting', input_count=0)
            await self._stage_reporting()
            self._emit_progress('reporting', 'report_generation')
            if self._profiler:
                self._profiler.tracker.finish_stage()
            self._emit('stage_complete', {'stage': 'reporting', 'status': 'complete'})
            
            if self.result:
                self.result.status = "completed"
            
            if self._profiler:
                profiler_report = self._profiler.generate_profile()
                logger.info(f"Profiler Report: {json.dumps(profiler_report, indent=2)}")
        
        except Exception as e:
            if self._profiler:
                self._profiler.finish()
            if self.result:
                self.result.errors.append(str(e))
                self.result.status = "failed"
            self._emit('error', {'error': str(e)})
        
        finally:
            await self.cleanup()
        
        if self.result is None:
            self.result = ScanResult(target_url=self.config.target)
        return self.result
    
    async def _run_agent_mode(self) -> ScanResult:
        """
        使用 Agent 系统运行扫描（规则+AI双引擎）
        
        架构:
        ┌─────────────────────────────────────────────────────────┐
        │  Phase 1: 规则引擎（快速发现，不耗 AI token）              │
        │  ├── DiscoverAgent - 快速端点发现                       │
        │  ├── TestAgent - 快速漏洞测试                          │
        │  └── ReflectAgent - 快速结果去重                       │
        ├─────────────────────────────────────────────────────────┤
        │  Phase 2: AI 引擎（深度分析，需要 AI key）             │
        │  ├── ScannerAgent - AI 驱动的智能 JS 分析             │
        │  ├── AnalyzerAgent - AI 漏洞分析和风险评估             │
        │  └── TesterAgent - AI 辅助渗透测试                     │
        └─────────────────────────────────────────────────────────┘
        """
        from .agents.orchestrator import check_ai_config, print_ai_config_guide
        from .agents.base import AgentConfig, BaseAgent
        
        missing_config = check_ai_config()
        
        if missing_config:
            logger.warning("Agent 模式: AI API Key 未配置，将使用纯规则模式")
            logger.info("如需启用 AI 模式，请配置以下环境变量:")
            print_ai_config_guide()
            ai_client = None
            self.result = ScanResult(
                target_url=self.config.target,
                start_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                status="running_with_rules_only",
                errors=["AI API key not configured - using rule-based mode"]
            )
        else:
            from .ai import LLMClient, AIConfig
            ai_config = AIConfig()
            ai_client = LLMClient(ai_config)
            self.result = ScanResult(
                target_url=self.config.target,
                start_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            )
        
        self._knowledge_base = KnowledgeBase.get_instance(self.config.target)
        
        context = ScanContext(
            target=self.config.target,
            cookies=self.config.cookies or "",
            concurrency=self.config.concurrency,
            ai_enabled=(ai_client is not None),
            knowledge_base=self._knowledge_base
        )
        
        self._emit('stage_start', {'stage': 'agent_mode', 'status': 'running'})
        
        try:
            # Phase 1: 规则引擎（快速，不耗 AI token）
            logger.info("=" * 60)
            logger.info("Phase 1: 规则引擎 - 快速发现与测试")
            logger.info("=" * 60)
            
            orchestrator = Orchestrator(context)
            orchestrator.register_agent(DiscoverAgent())
            orchestrator.register_agent(TestAgent())
            orchestrator.register_agent(ReflectAgent())
            
            rule_based_tasks = [
                {'agent': 'discover', 'task_type': 'js_collect', 'params': {'depth': self.config.js_depth}},
                {'agent': 'test', 'task_type': 'vuln_test', 'params': {}},
                {'agent': 'reflect', 'task_type': 'analysis', 'params': {}},
            ]
            
            await orchestrator.run(rule_based_tasks)
            
            logger.info(f"Phase 1 完成: 发现 {len(self._knowledge_base.get_endpoints())} 个端点")
            
            # Phase 2: AI 引擎（深度分析，需要 AI key）
            if ai_client:
                logger.info("=" * 60)
                logger.info("Phase 2: AI 引擎 - 深度分析与智能测试")
                logger.info("=" * 60)
                
                await self._run_ai_analysis_phase(context, ai_client)
            
            # 收集结果
            kb_data = self._knowledge_base.export()
            
            self.result.api_endpoints = kb_data.get('endpoints', [])
            self.result.total_apis = kb_data.get('summary', {}).get('total_endpoints', 0)
            self.result.vulnerabilities = kb_data.get('vulnerabilities', [])
            self.result.sensitive_data = kb_data.get('sensitive_data', [])
            self.result.status = "completed"
            
            self._emit('stage_complete', {'stage': 'agent_mode', 'status': 'completed'})
            
        except Exception as e:
            if self.result:
                self.result.errors.append(str(e))
                self.result.status = "failed"
            self._emit('error', {'error': str(e)})
        
        return self.result
    
    async def _run_ai_analysis_phase(self, context: ScanContext, ai_client) -> None:
        """
        AI 分析阶段 - 使用 LLM 进行深度分析
        
        ScannerAgent: 智能 JS 分析
        AnalyzerAgent: 漏洞分析和风险评估  
        TesterAgent: AI 辅助渗透测试
        """
        from .agents.base import AgentConfig
        from .agents.scanner_agent import ScannerAgent
        from .agents.analyzer_agent import AnalyzerAgent
        from .agents.tester_agent import TesterAgent
        
        endpoints = self._knowledge_base.get_endpoints() if self._knowledge_base else []
        
        if not endpoints:
            logger.info("Phase 2: 无端点，跳过 AI 分析")
            return
        
        # ScannerAgent - AI 驱动的 JS 分析
        scanner_config = AgentConfig(
            name="AIScanner",
            model="deepseek-chat",
            system_prompt="你是一个专业的 JavaScript 安全分析专家，负责从 JS 代码中提取 API 路径和敏感信息。"
        )
        scanner_agent = ScannerAgent(scanner_config, ai_client)
        scanner_agent.knowledge_base = self._knowledge_base
        
        logger.info(f"Phase 2a: ScannerAgent 分析 {len(endpoints)} 个端点")
        js_content = "\n".join([f"{ep.path} {ep.method}" for ep in endpoints[:50]])
        scanner_context = {'target': context.target, 'js_content': js_content}
        await scanner_agent.run(scanner_context)
        
        # AnalyzerAgent - AI 驱动的漏洞分析
        analyzer_config = AgentConfig(
            name="AIAnalyzer",
            model="deepseek-chat",
            system_prompt="你是一个专业的 API 安全分析专家，负责评估漏洞风险等级和提出修复建议。"
        )
        analyzer_agent = AnalyzerAgent(analyzer_config, ai_client)
        
        logger.info(f"Phase 2b: AnalyzerAgent 分析漏洞")
        for endpoint in endpoints[:20]:
            api_info = {
                'path': endpoint.path,
                'method': endpoint.method,
                'source': getattr(endpoint, 'source', 'unknown')
            }
            response_data = {'content': '', 'status_code': 200}
            risk = await analyzer_agent.assess_risk(api_info, response_data)
            if risk in ['high', 'critical']:
                tests = await analyzer_agent.suggest_tests(api_info)
                logger.info(f"  {endpoint.path}: {risk} risk, suggested {len(tests)} tests")
        
        # TesterAgent - AI 辅助渗透测试
        tester_config = AgentConfig(
            name="AITester",
            model="deepseek-chat",
            system_prompt="你是一个专业的渗透测试专家，负责生成有效的攻击载荷。"
        )
        tester_agent = TesterAgent(tester_config, ai_client)
        
        logger.info(f"Phase 2c: TesterAgent 生成智能载荷")
        for endpoint in endpoints[:10]:
            api_info = {'path': endpoint.path, 'method': endpoint.method}
            payloads = await tester_agent.generate_payloads('sql_injection', api_info)
            if payloads:
                logger.debug(f"  {endpoint.path}: generated {len(payloads)} SQL injection payloads")
        
        logger.info("Phase 2 完成")

    async def _run_collectors(self):
        """运行采集阶段"""
        self._current_stage = 0

        active_collectors = self.config.collectors or ['js', 'api']

        collector_results = {}

        oss_collector = get_oss_collector()
        oss_collector.reset()

        # === 新增: Swagger/OpenAPI 发现 ===
        if 'swagger' in active_collectors:
            collector_results['swagger'] = await self._collect_swagger()
            if 'swagger_endpoints' in collector_results['swagger']:
                for ep in collector_results['swagger']['swagger_endpoints']:
                    oss_collector.on_swagger_parsed(ep)

        # === 新增: 被动源采集 ===
        if 'passive' in active_collectors:
            collector_results['passive'] = await self._collect_passive()
            if 'api_urls' in collector_results['passive']:
                oss_collector.on_path_extracted(collector_results['passive']['api_urls'])

        if 'js' in active_collectors:
            collector_results['js'] = await self._collect_js()
            if 'js_content_all' in collector_results['js']:
                oss_collector.on_js_collected(collector_results['js']['js_content_all'])
            if 'js_urls' in collector_results['js']:
                for js_url in collector_results['js']['js_urls']:
                    oss_collector.collect("js_url", js_url)

        self._collector_results = collector_results

        if 'api' in active_collectors:
            collector_results['api'] = await self._extract_apis()

        self._collector_results = collector_results

        # === 新增: 智能过滤 ===
        collector_results = self._apply_smart_filter(collector_results)

        self._collector_results = collector_results

        oss_summary = oss_collector.get_summary()
        logger.info(f"[OSS Collector] Found {oss_summary['total_count']} OSS endpoints: {oss_summary['by_provider']}")

        self._oss_collector = oss_collector
        
        await self._try_auto_auth()
    
    async def _try_auto_auth(self):
        """尝试自动认证"""
        try:
            from .collectors.auto_auth import auto_authenticate, AuthInfoExtractor, LoginInterfaceDiscoverer
            
            if self.config.cookies:
                logger.info("[AutoAuth] 已提供 cookies，跳过自动认证")
                return
            
            js_contents = []
            if self._collector_results:
                js_result = self._collector_results.get('js', {})
                if 'js_content_all' in js_result:
                    js_contents.append(js_result['js_content_all'])
            
            all_api_paths = []
            if self._collector_results:
                for key in ['api', 'swagger', 'passive']:
                    if key in self._collector_results:
                        paths = self._collector_results[key].get('api_paths', [])
                        all_api_paths.extend(paths)
            
            extractor = AuthInfoExtractor()
            discoverer = LoginInterfaceDiscoverer()
            
            credentials = []
            for js in js_contents:
                creds, _ = extractor.extract_from_js(js)
                credentials.extend(creds)
            
            login_endpoints = discoverer.discover_from_paths(all_api_paths)
            
            if not login_endpoints and not credentials:
                logger.info("[AutoAuth] 未发现登录接口或凭据，跳过自动认证")
                return
            
            logger.info(f"[AutoAuth] 发现 {len(credentials)} 个凭据, {len(login_endpoints)} 个登录接口")
            
            auth_result = await auto_authenticate(
                self._http_client,
                self.config.target,
                js_contents
            )
            
            if auth_result and auth_result.headers:
                self.config.cookies = auth_result.cookie
                if auth_result.token:
                    logger.info(f"[AutoAuth] 认证成功，获得 Token")
                    self.result.statistics['auto_auth'] = {
                        'success': True,
                        'auth_type': auth_result.auth_type.value,
                        'token_prefix': auth_result.token[:20] + '...' if len(auth_result.token) > 20 else auth_result.token
                    }
                else:
                    logger.info(f"[AutoAuth] 认证成功，获得 Cookie")
                    self.result.statistics['auto_auth'] = {
                        'success': True,
                        'auth_type': auth_result.auth_type.value,
                        'cookie': auth_result.cookie[:50] + '...' if len(auth_result.cookie) > 50 else auth_result.cookie
                    }
            else:
                logger.info("[AutoAuth] 自动认证失败")
                self.result.statistics['auto_auth'] = {'success': False}
                
        except Exception as e:
            logger.debug(f"[AutoAuth] 自动认证异常: {e}")
    
    async def _collect_swagger(self) -> Dict[str, Any]:
        """采集 Swagger/OpenAPI 文档"""
        discoverer = SwaggerDiscoverer(self._http_client)
        swagger_endpoints = []
        
        try:
            resp = await self._http_client.request(self.config.target, timeout=10)  # type: ignore[reportOptionalMemberAccess]
            if resp and resp.status_code == 200:
                content = resp.content if hasattr(resp, 'content') else ''
                swagger_urls = await discoverer.discover_from_html(content, self.config.target)
                
                for swagger_url in swagger_urls[:10]:
                    doc = await discoverer.fetch_and_parse(swagger_url)
                    if doc:
                        swagger_endpoints.extend(doc.endpoints)
        except Exception as e:
            logger.debug(f"Swagger discovery error: {e}")
        
        common_urls = await discoverer.discover_common_paths(self.config.target)
        for common_url in common_urls:
            if any(e.url == common_url for e in swagger_endpoints):
                continue
            doc = await discoverer.fetch_and_parse(common_url)
            if doc:
                swagger_endpoints.extend(doc.endpoints)
        
        logger.info(f"Swagger discovered {len(swagger_endpoints)} endpoints")
        
        return {
            'swagger_endpoints': [
                {'path': e.path, 'method': e.method, 'summary': e.summary}
                for e in swagger_endpoints
            ],
            'swagger_docs': len(discoverer.discovered_docs)
        }
    
    async def _collect_passive(self) -> Dict[str, Any]:
        """从被动源采集 URL"""
        parsed = urlparse(self.config.target)
        domain = parsed.netloc
        
        collector = PassiveSourceCollector(self._http_client)
        urls = await collector.collect_from_all(domain)
        
        api_urls = collector.filter_api_urls(urls)
        
        logger.info(f"Passive collection: {len(urls)} total, {len(api_urls)} API URLs")
        
        return {
            'total_urls': len(urls),
            'api_urls': api_urls,
            'source_stats': collector.get_stats()
        }
    
    def _apply_smart_filter(self, collector_results: Dict) -> Dict:
        """应用智能过滤减少冗余"""
        all_endpoints = []
        
        if 'api' in collector_results:
            for ep in collector_results['api'].get('endpoints', []):
                all_endpoints.append({
                    'url': ep.get('url', ep.get('path', '')),
                    'method': ep.get('method', 'GET'),
                    'confidence': ep.get('confidence', 0.5),
                    'source': ep.get('source', 'default')
                })
        
        if all_endpoints:
            filter_instance = SmartFilter(max_endpoints=1000)
            scored = filter_instance.score_endpoints(all_endpoints)
            filtered = filter_instance.smart_filter(scored, strategy='balanced')
            
            logger.info(f"Smart filter: {len(all_endpoints)} -> {len(filtered)} endpoints "
                        f"(removed {len(all_endpoints) - len(filtered)} duplicates)")
        
        return collector_results
    
    async def _collect_js(self) -> Dict[str, Any]:
        """采集JS资源 + 框架检测 + 浏览器动态采集 + 内联JS解析"""
        from .utils.http_client import AsyncHttpClient
        from .collectors.inline_js_parser import InlineJSParser, ResponseBasedAPIDiscovery
        from .collectors.api_path_finder import ApiPathFinder, ApiPathCombiner
        
        js_urls = []
        alive_js = []
        js_content_all = ""
        browser_routes = []
        browser_api_endpoints = []
        
        inline_parser = InlineJSParser()
        response_discovery = ResponseBasedAPIDiscovery(
            target_domain=self.config.target,
            realtime_output=self._realtime_output
        )
        api_path_finder = ApiPathFinder()
        api_combiner = ApiPathCombiner()
        
        js_params = set()
        websocket_endpoints = set()
        env_configs = {}
        ast_routes = set()
        
        if self._browser_collector:
            try:
                browser_result = await self._collect_with_browser()
                if browser_result:
                    js_urls.extend(browser_result.get('js_urls', []))
                    alive_js.extend(browser_result.get('alive_js', []))
                    browser_routes = browser_result.get('spa_routes', [])
                    browser_api_endpoints = browser_result.get('browser_apis', [])
                    
                    for js_item in browser_result.get('alive_js', []):
                        if isinstance(js_item, dict) and 'content' in js_item:
                            js_content = js_item['content']
                            js_url = js_item.get('url', '')
                            api_path_finder.find_api_paths_in_text(js_content, js_url)
            except Exception as e:
                logger.warning(f"Browser collection failed: {e}")
        
        response = await self._http_client.request(  # type: ignore[reportOptionalMemberAccess]
            self.config.target,
            headers={'Cookie': self.config.cookies} if self.config.cookies else None
        )
        
        content_type = response.headers.get('Content-Type', 'text/html')
        
        inline_results = inline_parser.parse_html(response.content)
        if inline_results['api_paths'] or inline_results['routes']:
            logger.info(f"Found {len(inline_results['api_paths'])} API paths and {len(inline_results['routes'])} routes from inline JS")
        
        discovered_from_response = response_discovery.discover_from_response(
            self.config.target,
            response.content,
            content_type
        )
        if discovered_from_response:
            logger.info(f"Discovered {len(discovered_from_response)} API paths from response analysis")
        
        http_js_urls = self._extract_js_urls(response.content)
        js_parser = JSParser(self._js_cache)
        
        from urllib.parse import urljoin
        for js_url in http_js_urls:
            if js_url.startswith('http://') or js_url.startswith('https://'):
                absolute_js_url = js_url
            else:
                absolute_js_url = urljoin(self.config.target, js_url)
            
            if absolute_js_url not in js_urls:
                js_urls.append(absolute_js_url)
                try:
                    js_response = await self._http_client.request(absolute_js_url)  # type: ignore[reportOptionalMemberAccess]
                    if js_response.status_code == 200:
                        js_content = js_response.content
                        js_content_all += js_content + "\n"
                        alive_js.append({'url': js_url, 'content': js_content})
                        
                        inline_parser.parse_html(f'<script>{js_content}</script>')
                        response_discovery.discover_from_response(
                            js_url, js_content,
                            js_response.headers.get('Content-Type', 'application/javascript')
                        )
                        
                        api_path_finder.find_api_paths_in_text(js_content, js_url)
                        
                        ast_analyzer = JavaScriptASTAnalyzer()
                        ast_result = ast_analyzer.parse(js_content)
                        
                        for param in ast_result.parameter_names:
                            if param and len(param) > 1:
                                js_params.add(param)
                        
                        for endpoint in ast_result.endpoints:
                            if endpoint.params:
                                for p in endpoint.params:
                                    js_params.add(p)
                        
                        for ws_endpoint in ast_result.websocket_endpoints:
                            websocket_endpoints.add(ws_endpoint)
                        
                        for key, value in ast_result.env_configs.items():
                            env_configs[key] = value
                        
                        for route in ast_result.routes:
                            ast_routes.add(route)
                        
                        try:
                            js_parser.parse(js_content, js_url)
                        except Exception as e:
                            logger.debug(f"JS parse error for {js_url}: {e}")
                        
                        if self._js_resolver:
                            try:
                                js_resolver_records = self._js_resolver.extract_from_js(js_content, js_url)
                                if js_resolver_records:
                                    for record in js_resolver_records[:50]:
                                        js_resolver_url = record.url
                                        if js_resolver_url and js_resolver_url not in js_urls:
                                            js_urls.append(js_resolver_url)
                                            try:
                                                js_resolver_response = await self._http_client.request(js_resolver_url)  # type: ignore[reportOptionalMemberAccess]
                                                if js_resolver_response.status_code == 200:
                                                    resolver_content = js_resolver_response.content
                                                    if isinstance(resolver_content, str):
                                                        resolver_content = resolver_content.encode('utf-8')
                                                    js_content_all += resolver_content.decode('utf-8', errors='ignore') + "\n"
                                                    alive_js.append({
                                                        'url': js_resolver_url,
                                                        'content': resolver_content
                                                    })
                                            except Exception as e:
                                                logger.debug(f"JSResolver fetch error for {js_resolver_url}: {e}")
                            except Exception as e:
                                logger.debug(f"JSResolver error for {js_url}: {e}")
                except Exception as e:
                    logger.debug(f"JS request error for {js_url}: {e}")
        
        target_info = {
            'js_files': ','.join(js_urls),
            'api_paths': js_content_all[:1000] + ','.join(browser_api_endpoints),
            'response_content': response.content[:500] if response.content else '',
            'headers': str(response.headers) if hasattr(response, 'headers') else ''
        }
        
        framework_match = self._framework_detector.detect_best(target_info)
        if framework_match:
            self._detected_framework = framework_match.name
        
        all_extracted = inline_parser.get_all_extracted()
        all_discovered = response_discovery.get_all_discovered()
        
        inline_api_paths = list(all_extracted.get('api_paths', []))
        inline_routes = list(all_extracted.get('routes', []))
        
        finder_api_paths = api_path_finder.get_all_paths()
        
        logger.info(f"ApiPathFinder discovered {len(finder_api_paths)} API paths from JS")
        logger.info(f"Discovered {len(js_params)} JS parameters for fuzzing: {list(js_params)[:20]}")
        
        if js_content_all:
            sensitive_findings = self._sensitive_info_extractor.extract_from_js(js_content_all, self.config.target)
            if sensitive_findings:
                logger.info(f"Extracted {len(sensitive_findings)} sensitive findings from JS")
                for finding in sensitive_findings[:10]:
                    logger.debug(f"  [{finding.info_type}] {finding.value} from {finding.source}")
        
        if browser_api_endpoints:
            for api in browser_api_endpoints:
                self._path_prefix_learner.learn_from_url(api)
        
        response_sensitive = self._sensitive_info_extractor.extract_from_response(response.content, self.config.target)
        if response_sensitive:
            logger.info(f"Extracted {len(response_sensitive)} sensitive findings from response")
        
        return {
            'total_js': len(js_urls),
            'alive_js': len(alive_js),
            'js_urls': alive_js,
            'detected_framework': self._detected_framework,
            'inline_api_paths': inline_api_paths,
            'inline_routes': inline_routes,
            'response_discovered_paths': all_discovered,
            'probe_paths': inline_parser.generate_probe_paths(),
            'browser_api_endpoints': list(browser_api_endpoints) if browser_api_endpoints else [],
            'finder_api_paths': finder_api_paths,
            'js_params': list(js_params),
            'ast_routes': list(ast_routes),
            'env_configs': dict(env_configs),
            'sensitive_resources': list(all_extracted.get('sensitive_resources', [])),
            'response_sensitive_resources': list(all_discovered.get('sensitive_resources', [])),
            'sensitive_findings': self._sensitive_info_extractor.get_all_findings(),
            'path_prefixes': list(self._path_prefix_learner.get_all_prefixes()),
            'path_mappings': self._path_prefix_learner.get_mappings()
        }
    
    async def _collect_with_browser(self) -> Optional[Dict[str, Any]]:
        """使用无头浏览器采集 JS 和 API"""
        if not self._browser_collector:
            return None
        
        js_urls = []
        api_endpoints = []
        spa_routes = []
        alive_js = []
        intercepted_apis = []
        base_urls = set()
        
        try:
            await self._browser_collector.navigate(self.config.target)
            
            await self._browser_collector.add_api_interceptor()
            
            await self._browser_collector.scroll_page()
            
            page_content = await self._browser_collector.collect_page_content()
            
            intercepted = await self._browser_collector.get_intercepted_apis()
            intercepted_apis.extend(intercepted)
            
            discovered_bases = self._browser_collector.get_discovered_base_urls()
            base_urls.update(discovered_bases)
            
            js_urls = page_content.get('js_files', [])
            api_endpoints = page_content.get('api_endpoints', [])
            spa_routes = page_content.get('routes', [])
            
            intercepted_from_page = await self._browser_collector.get_all_intercepted_apis()
            intercepted_apis.extend(intercepted_from_page)
            
            for js_url in js_urls:
                try:
                    js_response = await self._http_client.request(js_url)  # type: ignore[reportOptionalMemberAccess]
                    if js_response.status_code == 200:
                        alive_js.append({
                            'url': js_url,
                            'content': js_response.content
                        })
                except Exception as e:
                    logger.debug(f"Browser JS request error: {e}")
            
            logger.info(f"[Browser Collector] Intercepted {len(intercepted_apis)} API calls, discovered {len(base_urls)} baseURLs")
        
        except Exception as e:
            logger.warning(f"Browser collection error: {e}")
        
        return {
            'js_urls': js_urls,
            'alive_js': alive_js,
            'spa_routes': spa_routes,
            'browser_apis': api_endpoints,
            'intercepted_apis': intercepted_apis,
            'base_urls': list(base_urls),
            'detected_framework': self._detected_framework
        }
    
    COMMON_API_PATHS = COMMON_API_PATHS
    RESTFUL_SUFFIXES = RESTFUL_SUFFIXES
    FUZZ_SUFFIXES = FUZZ_SUFFIXES
    PATH_FRAGMENTS = PATH_FRAGMENTS
    
    async def _probe_parent_paths(self, js_results: List, additional_paths: Optional[List[str]] = None) -> Dict[str, Set[str]]:
        """
        探测父路径是否可访问，并进一步探测常见 RESTful 端点、业务后缀和JS路径模板
        
        探测策略:
        1. 父路径 + RESTful 后缀 (/list, /add, /detail 等)
        2. 父路径 + 业务API词 (/user, /order, /product 等)  
        3. 父路径 + JS路径模板片段 (从JS提取的 /users/{id} -> /users)
        4. 父路径 + 资源 + 后缀组合探测 (/admin/role/list)
        5. JS提取的后缀和资源片段进行智能拼接
        
        Args:
            js_results: ParsedJSResult 对象列表
            additional_paths: 额外的API路径列表（用于生成父路径）
        
        Returns:
            {探测到的有效父路径: 该路径下探测到的额外端点}
        """
        probed_results = {}
        base_url = self.config.target.rstrip('/')
        
        parent_paths_to_probe = set()
        path_templates = set()
        js_suffixes = set()
        js_resources = set()
        
        for js_result in js_results:
            if hasattr(js_result, 'parent_paths') and js_result.parent_paths:
                for original_path, parents in js_result.parent_paths.items():
                    for parent in parents:
                        if parent not in parent_paths_to_probe:
                            parent_paths_to_probe.add(parent)
            
            if hasattr(js_result, 'path_templates') and js_result.path_templates:
                for template in js_result.path_templates:
                    path_templates.add(template)
            
            if hasattr(js_result, 'extracted_suffixes') and js_result.extracted_suffixes:
                for suffix in js_result.extracted_suffixes:
                    js_suffixes.add(suffix)
            
            if hasattr(js_result, 'resource_fragments') and js_result.resource_fragments:
                for resource in js_result.resource_fragments:
                    js_resources.add(resource)
        
        if additional_paths:
            for path in additional_paths:
                if not isinstance(path, str) or len(path) < 3:
                    continue
                parts = path.strip('/').split('/')
                if len(parts) <= 2:
                    continue
                for i in range(1, min(len(parts), 4)):
                    parent = '/' + '/'.join(parts[:-i])
                    if parent and len(parent) > 1:
                        parent_paths_to_probe.add(parent)
        
        max_parent_paths = 50
        if len(parent_paths_to_probe) > max_parent_paths:
            parent_list = list(parent_paths_to_probe)[:max_parent_paths]
            parent_paths_to_probe = set(parent_list)
        
        if not parent_paths_to_probe:
            return probed_results
        
        logger.info(f"Probing {len(parent_paths_to_probe)} parent paths + {len(path_templates)} templates + {len(js_suffixes)} suffixes + {len(js_resources)} resources...")
        
        probed_results = await self._do_probe_parent_paths(
            base_url, parent_paths_to_probe, path_templates, js_suffixes, js_resources
        )
        
        return probed_results
    
    async def _do_probe_parent_paths(
        self, 
        base_url: str, 
        parent_paths_to_probe: Set[str],
        path_templates: Optional[Set[str]] = None,
        js_suffixes: Optional[Set[str]] = None,
        js_resources: Optional[Set[str]] = None
    ) -> Dict[str, Set[str]]:
        """执行父路径探测（合并后的统一实现）"""
        if path_templates is None:
            path_templates = set()
        if js_suffixes is None:
            js_suffixes = set()
        if js_resources is None:
            js_resources = set()
        probed_results = {}
        
        all_suffixes = set()
        all_suffixes.update(self.RESTFUL_SUFFIXES)
        all_suffixes.update([f'/{p}' for p in self.COMMON_API_PATHS])
        all_suffixes.update([f'/{p}' for p in self.PATH_FRAGMENTS])
        all_suffixes.update([f'/{s}' for s in js_suffixes])
        
        template_fragments = set()
        for template in path_templates:
            parts = template.strip('/').split('/')
            for part in parts:
                if part and not part.startswith('{') and len(part) > 1:
                    template_fragments.add(part)
        all_suffixes.update([f'/{f}' for f in template_fragments])
        
        max_concurrent = 100 if self.config.concurrency_probe else 5
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def try_request(url: str, method: str = 'HEAD') -> Optional[int]:
            try:
                response = await self._http_client.request(url, method=method, timeout=5)  # type: ignore[reportOptionalMemberAccess]
                return response.status_code
            except Exception:
                if method == 'HEAD':
                    return await try_request(url, 'GET')
            return None
        
        async def probe_parent_path(parent_path: str) -> Tuple[str, Set[str], int]:
            async with semaphore:
                full_url = base_url + parent_path
                status_code = await try_request(full_url)
                sub_endpoints = set()
                
                async def do_probe():
                    for suffix in list(all_suffixes)[:100]:
                        if '/' in suffix.lstrip('/'):
                            sub_path = suffix.lstrip('/')
                            sub_url = base_url + '/' + sub_path
                        else:
                            sub_path = parent_path.rstrip('/') + '/' + suffix.lstrip('/') if suffix else parent_path
                            sub_url = base_url + sub_path
                        sub_status = await try_request(sub_url)
                        if sub_status and 200 <= sub_status < 400:
                            sub_endpoints.add('/' + sub_path.lstrip('/'))
                            logger.debug(f"  Found: {sub_path} (status: {sub_status})")
                    
                    for resource in list(js_resources)[:30]:
                        for suffix in list(self.RESTFUL_SUFFIXES)[:20]:
                            combined = f'/{resource}{suffix}' if suffix else f'/{resource}'
                            sub_url = base_url + parent_path.rstrip('/') + combined
                            sub_status = await try_request(sub_url)
                            if sub_status and 200 <= sub_status < 400:
                                sub_endpoints.add(parent_path.rstrip('/') + combined)
                
                if status_code and 200 <= status_code < 400:
                    logger.info(f"Parent path accessible: {parent_path} (status: {status_code})")
                    await do_probe()
                elif status_code in (401, 403):
                    logger.info(f"Parent path exists (auth required): {parent_path} (status: {status_code})")
                    await do_probe()
                elif status_code == 404:
                    logger.info(f"Parent path returns 404, probing sub-paths: {parent_path}")
                    await do_probe()
                else:
                    if status_code:
                        logger.debug(f"Parent path returns {status_code}, probing sub-paths: {parent_path}")
                        await do_probe()
                    else:
                        logger.debug(f"Parent path not reachable, probing sub-paths: {parent_path}")
                        await do_probe()
                
                return (parent_path, sub_endpoints, status_code if status_code else 0)
        
        tasks = [probe_parent_path(p) for p in parent_paths_to_probe]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, tuple) and len(result) == 3:
                parent_path, sub_endpoints, status_code = result
                if sub_endpoints:
                    probed_results[parent_path] = sub_endpoints
                    logger.info(f"Found {len(sub_endpoints)} sub-endpoints via parent path: {parent_path}")
        
        return probed_results
    
    async def _fuzz_api_paths(self, js_results: List) -> Dict[str, Set[str]]:
        """
        使用 JS 提取的后缀和资源片段进行智能 API 路径 fuzzing
        
        探测策略:
        1. 父路径 + JS后缀 组合
        2. 父路径 + JS资源 + RESTful后缀 组合
        3. 独立资源 + 后缀 组合
        4. 使用 FUZZ_SUFFIXES 生成更多变体
        5. 带参数的路径组合 (父路径 + 资源 + ?param=value)
        
        Returns:
            {探测到的有效路径: 该路径下探测到的额外端点}
        """
        fuzzed_results = {}
        base_url = self.config.target.rstrip('/')
        
        js_params = set()
        for key, value in (self._collector_results.get('js', {}).get('env_configs', {}).items() if self._collector_results else []):
            if key and len(key) > 1:
                js_params.add(key)
        if self._collector_results and 'js' in self._collector_results:
            for p in self._collector_results['js'].get('js_params', []):
                if p and len(p) > 1:
                    js_params.add(p)
        
        common_params = ['id', 'page', 'pageNum', 'pageSize', 'limit', 'offset', 'count', 
                         'userId', 'user_id', 'orderId', 'order_id', 'productId', 'product_id',
                         'category', 'type', 'status', 'action', 'mode', 'q', 'query', 'search',
                         'keyword', 'name', 'title', 'email', 'phone', 'code', 'token', 'lang']
        for p in common_params:
            js_params.add(p)
        
        js_result_count = len(js_results)
        suffix_limit = min(1000, max(300, js_result_count * 80))
        resource_limit = min(200, max(100, js_result_count * 20))
        independent_suffix_limit = min(500, max(200, js_result_count * 50))
        
        parent_paths = set()
        js_suffixes = set()
        js_resources = set()
        existing_apis = set()
        
        for js_result in js_results:
            if hasattr(js_result, 'parent_paths') and js_result.parent_paths:
                for original_path, parents in js_result.parent_paths.items():
                    for parent in parents:
                        parent_paths.add(parent)
                    existing_apis.add(original_path)
            
            if hasattr(js_result, 'extracted_suffixes') and js_result.extracted_suffixes:
                for suffix in js_result.extracted_suffixes:
                    if len(js_suffixes) < suffix_limit:
                        js_suffixes.add(suffix)
            
            if hasattr(js_result, 'resource_fragments') and js_result.resource_fragments:
                for resource in js_result.resource_fragments:
                    if len(js_resources) < resource_limit:
                        js_resources.add(resource)
            
            if hasattr(js_result, 'apis'):
                for api in js_result.apis:
                    existing_apis.add(api)
        
        if not parent_paths:
            return fuzzed_results
        
        fuzz_targets = []
        seen_targets = set()
        
        for parent in parent_paths:
            parent_clean = parent.strip('/')
            if not parent_clean:
                parent_clean = parent.strip()
            if parent_clean in seen_targets:
                continue
            seen_targets.add(parent_clean)
            
            parent_base = '/' + parent_clean.lstrip('/')
            fuzz_targets.append((parent_base, ''))
            
            for suffix in js_suffixes:
                if len(fuzz_targets) >= 5000:
                    break
                suffix_clean = suffix.strip('/').lstrip('/')
                if not suffix_clean:
                    continue
                if '/' in suffix_clean:
                    target = '/' + suffix_clean
                else:
                    target = f"{parent_base}/{suffix_clean}"
                if target not in seen_targets and target not in existing_apis:
                    seen_targets.add(target)
                    fuzz_targets.append((target, ''))
            
            for resource in js_resources:
                if len(fuzz_targets) >= 5000:
                    break
                resource_clean = resource.strip('/').lstrip('/')
                if not resource_clean:
                    continue
                target = f"{parent_base}/{resource_clean}"
                if target not in seen_targets and target not in existing_apis:
                    seen_targets.add(target)
                    fuzz_targets.append((parent_base, f"/{resource_clean}"))
                
                for rest_suffix in list(self.RESTFUL_SUFFIXES)[:20]:
                    rest_clean = rest_suffix.strip('/').lstrip('/')
                    combo = f"{parent_base}/{resource_clean}/{rest_clean}" if rest_clean else f"{parent_base}/{resource_clean}"
                    if combo not in seen_targets and combo not in existing_apis:
                        seen_targets.add(combo)
                        rest_suffix_part = f"/{rest_clean}" if rest_clean else ""
                        fuzz_targets.append((parent_base, f"/{resource_clean}{rest_suffix_part}"))
                        if len(fuzz_targets) >= 5000:
                            break
        
        for api in list(existing_apis)[:200]:
            api_clean = api.strip('/')
            if not api_clean:
                continue
            api_base = '/' + api_clean.lstrip('/')
            if js_params and len(fuzz_targets) < 3000:
                for param in list(js_params)[:10]:
                    param_clean = param.strip()
                    if not param_clean:
                        continue
                    param_combo = f"{api_base}?{param_clean}=1"
                    if param_combo not in seen_targets:
                        seen_targets.add(param_combo)
                        fuzz_targets.append((api_base, f"?{param_clean}=1"))
                    
                    param_combo2 = f"{api_base}/{param_clean}/1"
                    if param_combo2 not in seen_targets:
                        seen_targets.add(param_combo2)
                        fuzz_targets.append((api_base, f"/{param_clean}/1"))
        
        async def probe_target(base: str, suffix: str) -> Optional[Tuple[str, str, float]]:
            full_url = base_url + base + suffix
            start_time = time.time()
            try:
                response = await self._http_client.request(full_url, method='HEAD', timeout=5)  # type: ignore[reportOptionalMemberAccess]
                elapsed = time.time() - start_time
                if response.status_code and 200 <= response.status_code < 400:
                    self._fuzz_batch_scheduler.record_success(elapsed)
                    return (base, suffix, elapsed)
            except Exception:
                elapsed = time.time() - start_time
                try:
                    response = await self._http_client.request(full_url, method='GET', timeout=5)  # type: ignore[reportOptionalMemberAccess]
                    elapsed = time.time() - start_time
                    if response.status_code and 200 <= response.status_code < 400:
                        self._fuzz_batch_scheduler.record_success(elapsed)
                        return (base, suffix, elapsed)
                except Exception:
                    self._fuzz_batch_scheduler.record_failure()
                    pass
            return None
        
        for i in range(0, len(fuzz_targets), self._fuzz_batch_scheduler.batch_size):
            batch = fuzz_targets[i:i+self._fuzz_batch_scheduler.batch_size]
            tasks = [probe_target(base, suffix) for base, suffix in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if result and isinstance(result, tuple) and len(result) == 3:
                    parent_path, found_suffix, elapsed = result
                    found_path = parent_path + found_suffix
                    if found_path not in fuzzed_results:
                        fuzzed_results[found_path] = set()
                    fuzzed_results[found_path].add(found_suffix)
        
        logger.info(f"API path fuzzing found {len(fuzzed_results)} valid paths")
        return fuzzed_results
    
    async def _cross_source_fuzz(self) -> Dict[str, Set[str]]:
        """
        跨来源智能路径组合Fuzzing
        
        从所有HTTP响应中提取路径片段进行智能组合：
        1. 从主页面响应中提取链接
        2. 从JS响应中提取API路径
        3. 从API响应中提取关联路径
        4. 跨来源路径片段组合
        
        例如:
        - 来源1: /api/users (来自JS)
        - 来源2: /user/list (来自HTML)
        - 组合: /api/users/list, /api/user/list
        
        Returns:
            {探测到的有效路径: 来源信息}
        """
        fuzzed_results = {}
        base_url = self.config.target.rstrip('/')
        
        all_path_segments = set()
        all_suffixes = set(self.RESTFUL_SUFFIXES)
        all_suffixes.update(self.FUZZ_SUFFIXES)
        
        await self._collect_all_path_segments(all_path_segments, all_suffixes)
        
        if not all_path_segments:
            return fuzzed_results
        
        logger.info(f"Cross-source fuzzing with {len(all_path_segments)} path segments...")
        
        fuzz_targets = self._generate_cross_fuzz_targets(all_path_segments, all_suffixes)
        
        logger.info(f"Generated {len(fuzz_targets)} fuzz targets")
        
        async def probe_target(base: str, path: str) -> Optional[Tuple[str, float]]:
            full_url = base_url + base + path
            start_time = time.time()
            try:
                response = await self._http_client.request(full_url, method='HEAD', timeout=5)  # type: ignore[reportOptionalMemberAccess]
                elapsed = time.time() - start_time
                if response.status_code and 200 <= response.status_code < 400:
                    self._fuzz_batch_scheduler.record_success(elapsed)
                    return (base + path, elapsed)
            except Exception:
                elapsed = time.time() - start_time
                try:
                    response = await self._http_client.request(full_url, method='GET', timeout=5)  # type: ignore[reportOptionalMemberAccess]
                    elapsed = time.time() - start_time
                    if response.status_code and 200 <= response.status_code < 400:
                        self._fuzz_batch_scheduler.record_success(elapsed)
                        return (base + path, elapsed)
                except Exception:
                    self._fuzz_batch_scheduler.record_failure()
                    pass
            return None
        
        for i in range(0, len(fuzz_targets), self._fuzz_batch_scheduler.batch_size):
            batch = fuzz_targets[i:i+self._fuzz_batch_scheduler.batch_size]
            tasks = [probe_target(base, path) for base, path in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if result and isinstance(result, tuple) and len(result) == 2:
                    found_path, elapsed = result
                    fuzzed_results[found_path] = {'source': 'cross_fuzz'}
        
        return fuzzed_results
    
    async def _collect_all_path_segments(self, path_segments: set, suffixes: set):
        """
        从所有HTTP响应中收集路径片段
        
        收集来源:
        1. 主页HTML中的链接
        2. 所有JS文件内容
        3. 所有API响应
        4. 响应中的URL
        """
        try:
            main_response = await self._http_client.request(self.config.target, timeout=10)  # type: ignore[reportOptionalMemberAccess]
            if main_response and main_response.status_code == 200:
                content = main_response.content
                
                for match in self._HREF_PATTERN.findall(content):
                    if self._is_valid_path_segment(match):
                        path_segments.add(self._normalize_path_segment(match))
                
                for match in self._SRC_PATTERN.findall(content):
                    if self._is_valid_path_segment(match):
                        path_segments.add(self._normalize_path_segment(match))
                
                for match in self._ACTION_PATTERN.findall(content):
                    if self._is_valid_path_segment(match):
                        path_segments.add(self._normalize_path_segment(match))
                
                for match in self._URL_PATTERN.findall(content):
                    if self._is_valid_path_segment(match):
                        path_segments.add(self._normalize_path_segment(match))
                
                for match in self._API_URL_PATTERN.findall(content):
                    if self._is_valid_path_segment(match):
                        path_segments.add(self._normalize_path_segment(match))
                        
        except Exception as e:
            logger.debug(f"Failed to collect from main page: {e}")
        
        try:
            js_urls = await self._extract_all_js_urls()
            for js_url in js_urls:
                try:
                    js_response = await self._http_client.request(js_url, timeout=10)  # type: ignore[reportOptionalMemberAccess]
                    if js_response and js_response.status_code == 200:
                        content = js_response.content
                        
                        for match in self._GENERIC_API_PATTERN.findall(content):
                            if self._is_valid_path_segment(match):
                                path_segments.add(self._normalize_path_segment(match))
                        
                        for match in self._CONFIG_PATTERN.findall(content):
                            if match.startswith('/'):
                                path_segments.add(self._normalize_path_segment(match))
                        
                        for match in self._ROUTER_PATTERN.findall(content):
                            if self._is_valid_path_segment(match):
                                path_segments.add(self._normalize_path_segment(match))
                                
                except Exception:
                    pass
        except Exception:
            pass
        
        return path_segments
    
    async def _recursive_js_extract(self, initial_js_urls: List[str], max_depth: int = 3) -> Dict[str, str]:
        """
        递归提取JS文件中的JS引用
        
        从JS内容中提取动态import/require引入的新JS模块，
        递归获取直到达到最大深度或没有新JS
        
        Args:
            initial_js_urls: 初始JS URL列表
            max_depth: 最大递归深度
            
        Returns:
            {js_url: js_content}
        """
        all_js_content = {}
        visited_urls = set()
        pending_urls = list(initial_js_urls)
        
        for depth in range(max_depth):
            if not pending_urls:
                break
            
            current_batch = pending_urls[:50]
            pending_urls = pending_urls[50:]
            
            logger.info(f"Recursive JS extraction depth {depth+1}, processing {len(current_batch)} URLs...")
            
            tasks = [self._http_client.request(url, timeout=10) for url in current_batch]  # type: ignore[reportOptionalMemberAccess]
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            new_pending = []
            for url, response in zip(current_batch, responses):
                if url in visited_urls:
                    continue
                if response and not isinstance(response, Exception) and getattr(response, 'status_code', 0) == 200:
                    visited_urls.add(url)
                    all_js_content[url] = getattr(response, 'content', '')
                    
                    new_js_urls = self._extract_js_imports_from_content(getattr(response, 'content', ''))
                    for new_url in new_js_urls:
                        normalized = self._normalize_js_url(new_url)
                        if normalized and normalized not in visited_urls and normalized not in pending_urls:
                            new_pending.append(normalized)
            
            pending_urls.extend(new_pending)
        
        return all_js_content
    
    def _normalize_js_url(self, js_url: str) -> Optional[str]:
        """规范化JS URL"""
        if not js_url or not isinstance(js_url, str):
            return None
        
        js_url = js_url.strip()
        
        if js_url.startswith('//'):
            js_url = 'https:' + js_url
        elif js_url.startswith('/'):
            base = self.config.target.rstrip('/')
            js_url = base + js_url
        elif not js_url.startswith('http'):
            base = self.config.target.rstrip('/')
            js_url = base + '/' + js_url.lstrip('/')
        
        if not js_url.endswith('.js'):
            return None
        
        return js_url
    
    def _extract_js_imports_from_content(self, js_content: str) -> List[str]:
        """从JS内容中提取import/require引入的JS模块路径"""
        imports = []
        if not js_content:
            return imports
        
        import_patterns = [
            r'import\s+["\']([^"\']+\.js)["\']',
            r'import\s+\(["\']([^"\']+\.js)["\']\)',
            r'require\(["\']([^"\']+\.js)["\']\)',
            r'import\(["\']([^"\']+\.js)["\']\)',
            r'export\s+from\s+["\']([^"\']+\.js)["\']',
            r'webpackChunkName\s*:\s*["\']([^"\']+\.js)["\']',
            r'chunkFilename\s*:\s*["\']([^"\']+\.js)["\']',
            r'\.lazyLoad\(["\']([^"\']+\.js)["\']',
            r'webpackMagicComments.*?\.js',
        ]
        
        for pattern in import_patterns:
            matches = re.findall(pattern, js_content)
            imports.extend(matches)
        
        return list(set(imports))
    
    async def _extract_all_js_urls(self) -> List[str]:
        """提取所有JS URL"""
        js_urls = []
        try:
            response = await self._http_client.request(self.config.target, timeout=10)  # type: ignore[reportOptionalMemberAccess]
            if response and response.status_code == 200:
                script_pattern = re.compile(r'<script[^>]+src=["\']([^"\']+\.js)["\']', re.IGNORECASE)
                for match in script_pattern.findall(response.content):
                    if match.startswith('http'):
                        js_urls.append(match)
                    elif match.startswith('//'):
                        js_urls.append('https:' + match)
                    else:
                        base = self.config.target.rstrip('/')
                        js_urls.append(base + match if match.startswith('/') else base + '/' + match)
        except Exception:
            pass
        return js_urls
    
    def _is_valid_path_segment(self, path: str) -> bool:
        """判断路径片段是否有效"""
        if not path or len(path) < 2:
            return False
        
        if path.startswith('http') or path.startswith('//') or path.startswith('javascript'):
            return False
        
        if path.startswith('./') or path.startswith('../'):
            return False
        
        invalid_ext = ('.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2')
        if any(path.lower().endswith(ext) for ext in invalid_ext):
            return False
        
        if re.match(r'^[\w]+://', path):
            return False
        
        if re.search(r'[\(\)\<\>\[\]{}"]', path):
            return False
        
        return True
    
    def _normalize_path_segment(self, path: str) -> str:
        """规范化路径片段"""
        path = path.strip()
        
        if path.startswith('"') or path.startswith("'"):
            path = path[1:]
        if path.endswith('"') or path.endswith("'"):
            path = path[:-1]
        
        path = path.split('?')[0]
        path = path.split('#')[0]
        
        if path.startswith('/'):
            path = path[1:]
        
        return path
    
    def _detect_response_type(self, response) -> str:
        """检测响应类型"""
        content_type = ""
        if hasattr(response, 'headers') and response.headers:
            content_type = response.headers.get('Content-Type', '') or response.headers.get('content-type', '')
        
        if not content_type and hasattr(response, 'content') and response.content:
            content = response.content[:200] if len(response.content) > 200 else response.content
            if isinstance(content, bytes):
                content = content.decode('utf-8', errors='ignore')
            
            if content.startswith('{') or content.startswith('['):
                return "JSON"
            elif content.startswith('<!DOCTYPE') or content.startswith('<html'):
                return "HTML"
            elif content.startswith('<?xml'):
                return "XML"
            elif content.startswith('<'):
                return "XML"
        
        content_type_lower = content_type.lower()
        if 'json' in content_type_lower:
            return "JSON"
        elif 'html' in content_type_lower:
            return "HTML"
        elif 'xml' in content_type_lower:
            return "XML"
        elif 'text' in content_type_lower:
            return "TEXT"
        elif 'javascript' in content_type_lower:
            return "JS"
        elif 'css' in content_type_lower:
            return "CSS"
        elif 'image' in content_type_lower:
            return "IMAGE"
        elif 'font' in content_type_lower:
            return "FONT"
        elif 'octet-stream' in content_type_lower or 'binary' in content_type_lower:
            return "BINARY"
        elif content_type:
            return content_type.split(';')[0].strip()
        
        return "UNKNOWN"
    
    def _generate_cross_fuzz_targets(self, path_segments: set, suffixes: set) -> List[Tuple[str, str]]:
        """
        生成跨来源Fuzzing目标组合 - 扩展词表策略
        
        覆盖：认证/搜索/支付/状态/社交/配置/媒体/位置等场景
        """
        targets = []
        priority_targets = []
        
        segments = sorted(list(path_segments), key=len, reverse=True)
        
        def get_segment_priority(seg: str) -> int:
            seg_lower = seg.lower()
            if seg_lower in CRUD_SUFFIXES:
                return 3
            if seg_lower in RESOURCE_WORDS:
                return 2
            if any(kw in seg_lower for kw in ['user', 'order', 'product', 'account', 'admin']):
                return 1
            return 0
        
        for segment in segments:
            seg_lower = segment.lower()
            seg_priority = get_segment_priority(segment)
            
            for suffix in list(suffixes)[:30]:
                suffix_lower = suffix.lower().lstrip('/')
                
                if suffix_lower in ACTION_SUFFIXES:
                    if seg_priority >= 1:
                        target = (segment, '/' + suffix)
                        priority_targets.append((3, target))
                        continue
                
                if segment and suffix.startswith('/'):
                    targets.append((segment, suffix))
                elif segment:
                    targets.append((segment, '/' + suffix))
        
        api_prefixes = ['api', 'v1', 'v2', 'v3', 'rest', 'rpc', 'graphql', 'svc', 'service', 'gateway']
        for prefix in api_prefixes:
            for segment in segments:
                if prefix not in segment.lower() and not segment.lower().startswith(prefix):
                    target1 = ('', '/' + prefix + '/' + segment.lstrip('/'))
                    target2 = ('/' + prefix, '/' + segment.lstrip('/'))
                    
                    if get_segment_priority(segment) >= 1:
                        priority_targets.append((2, target1))
                        priority_targets.append((2, target2))
                    else:
                        targets.append(target1)
                        targets.append(target2)
        
        all_targets = []
        seen = set()
        
        priority_targets.sort(key=lambda x: -x[0])
        
        for _, target in priority_targets[:1000]:
            key = target[0] + target[1]
            if key not in seen:
                seen.add(key)
                all_targets.append(target)
        
        for target in targets[:3000]:
            key = target[0] + target[1]
            if key not in seen:
                seen.add(key)
                all_targets.append(target)
        
        return all_targets[:5000]
    
    def _is_likely_api_segment(self, segment: str) -> bool:
        """判断路径片段是否是API相关"""
        api_keywords = [
            'user', 'users', 'order', 'orders', 'product', 'products',
            'admin', 'login', 'logout', 'auth', 'token', 'api', 'menu',
            'role', 'permission', 'config', 'system', 'dict', 'dept',
            'menu', 'dict', 'log', 'monitor', 'tool', 'gen'
        ]
        
        segment_lower = segment.lower()
        
        for keyword in api_keywords:
            if keyword in segment_lower:
                return True
        
        return False
    
    async def _extract_apis(self) -> Dict[str, Any]:
        """提取API端点 + 基于框架生成更多端点"""
        from .utils.api_spec_parser import APISpecParser
        from core.scanner import is_api_spec_url
        
        # Check if target URL is an API spec and parse it
        if is_api_spec_url(self.config.target):
            try:
                logger.info(f"Detected API spec URL: {self.config.target}, using APISpecParser")
                parser = APISpecParser(self._http_client)
                spec_result = await parser.discover_and_parse(self.config.target)
                if spec_result:
                    logger.info(f"Parsed {len(spec_result.endpoints)} endpoints from API spec")
                    for api_endpoint in spec_result.endpoints:
                        from .collectors.api_collector import APIFindResult
                        api_find_result = APIFindResult(
                            path=api_endpoint.path,
                            method=api_endpoint.method,
                            source_type="api_spec_parser",
                            base_url=spec_result.base_url or "",
                            url_type="api_path"
                        )
                        self._api_aggregator.add_api(  # type: ignore[reportOptionalMemberAccess]
                            api_find_result,
                            source_info={'source': f'api_spec:{spec_result.spec_type}'}
                        )
                else:
                    logger.warning(f"Failed to parse API spec from {self.config.target}")
            except Exception as e:
                logger.error(f"Error parsing API spec: {e}")
        
        js_results = self._js_cache.get_all()  # type: ignore[reportOptionalMemberAccess]
        existing_paths = set()
        
        from .collectors.inline_js_parser import PathValidationConstants
        
        def _is_likely_echarts_config(path: str) -> bool:
            """判断路径是否像 ECharts 配置"""
            if not path or len(path) < 2:
                return False
            segment_count = path.count('/')
            if segment_count > 2:
                return False
            if '/' not in path:
                return False
            segments = path.split('/')
            last_segment = segments[-1]
            if not last_segment:
                return False
            if '.' in last_segment:
                return False
            last_segment_lower = last_segment.lower()
            has_camel_case = sum(1 for c in last_segment if c.isupper()) >= 2
            keyword_match = sum(1 for kw in PathValidationConstants.ECHARTS_CONFIG_KEYWORDS if kw in last_segment_lower)
            if has_camel_case and keyword_match >= 1:
                return True
            return False
        
        def _is_valid_path(path: str) -> bool:
            """Validate API path"""
            if not path or len(path) < 2:
                return False
            path_lower = path.lower()
            for ext in PathValidationConstants.STATIC_FILE_EXTENSIONS:
                if path_lower.endswith(ext):
                    return False
            for prefix in PathValidationConstants.GARBAGE_PATH_PREFIXES:
                if path.startswith(prefix):
                    return False
            for pattern in PathValidationConstants.GARBAGE_PATH_PATTERNS:
                if pattern.lower() in path_lower:
                    return False
            garbage_count = sum(1 for kw in PathValidationConstants.GARBAGE_PATH_KEYWORDS if kw in path_lower)
            if garbage_count >= 1:
                return False
            if _is_likely_echarts_config(path):
                return False
            if '/' not in path:
                if path_lower not in ['api', 'v1', 'v2', 'v3', 'rest', 'restapi', 'service', 'gateway']:
                    return False
            has_valid_kw = any(kw in path_lower for kw in PathValidationConstants.VALID_API_KEYWORDS)
            if not has_valid_kw:
                return False
            return True
        
        for js_result in js_results:
            try:
                for api_path in js_result.apis:
                    if not _is_valid_path(api_path):
                        continue
                    existing_paths.add(api_path)
                    from .collectors.api_collector import APIFindResult
                    api_find_result = APIFindResult(
                        path=api_path,
                        method="GET",
                        source_type="js_parser",
                        base_url="",
                        url_type="api_path"
                    )
                    self._api_aggregator.add_api(  # type: ignore[reportOptionalMemberAccess]
                        api_find_result,
                        source_info={'source': 'js_fingerprint_cache'}
                    )
            except Exception as e:
                logger.debug(f"API extraction from JS cache error: {e}")
        
        if self._detected_framework and self._framework_detector:
            framework_endpoints = self._framework_detector.generate_endpoints(self._detected_framework)
            
            verified_framework_endpoints = []
            if framework_endpoints and self._http_client:
                try:
                    verified_framework_endpoints = await self._framework_detector.verify_endpoints(
                        framework_endpoints,
                        self._http_client,
                        self.config.target
                    )
                except Exception as e:
                    logger.debug(f"Framework endpoint verification error: {e}")
                    verified_framework_endpoints = framework_endpoints
            
            for endpoint in verified_framework_endpoints:
                if endpoint not in existing_paths:
                    existing_paths.add(endpoint)
                    from .collectors.api_collector import APIFindResult
                    api_find_result = APIFindResult(
                        path=endpoint,
                        method="GET",
                        source_type="framework_pattern",
                        base_url="",
                        url_type="generated"
                    )
                    self._api_aggregator.add_api(  # type: ignore[reportOptionalMemberAccess]
                        api_find_result,
                        source_info={'source': f'framework_{self._detected_framework}'}
                    )
        
        if self._collector_results and 'js' in self._collector_results:
            js_result = self._collector_results['js']
            
            inline_api_paths = js_result.get('inline_api_paths', [])
            if inline_api_paths:
                logger.info(f"Adding {len(inline_api_paths)} API paths from inline JS parser")
                for api_path in inline_api_paths:
                    if not _is_valid_path(api_path):
                        continue
                    if api_path not in existing_paths:
                        existing_paths.add(api_path)
                        from .collectors.api_collector import APIFindResult
                        api_find_result = APIFindResult(
                            path=api_path,
                            method="GET",
                            source_type="inline_js_parser",
                            base_url="",
                            url_type="discovered"
                        )
                        self._api_aggregator.add_api(  # type: ignore[reportOptionalMemberAccess]
                            api_find_result,
                            source_info={'source': 'inline_js_parser'}
                        )
            
            inline_routes = js_result.get('inline_routes', [])
            if inline_routes:
                logger.info(f"Adding {len(inline_routes)} routes from inline JS parser")
                for route in inline_routes:
                    normalized_route = route if route.startswith('/') else f'/{route}'
                    if not _is_valid_path(normalized_route):
                        continue
                    if normalized_route not in existing_paths:
                        existing_paths.add(normalized_route)
                        from .collectors.api_collector import APIFindResult
                        api_find_result = APIFindResult(
                            path=normalized_route,
                            method="GET",
                            source_type="inline_js_route",
                            base_url="",
                            url_type="route"
                        )
                        self._api_aggregator.add_api(  # type: ignore[reportOptionalMemberAccess]
                            api_find_result,
                            source_info={'source': 'inline_js_parser'}
                        )
            
            response_discovered = js_result.get('response_discovered_paths', [])
            if response_discovered:
                logger.info(f"Adding {len(response_discovered)} paths from response discovery")
                for path in response_discovered:
                    if not _is_valid_path(path):
                        continue
                    if path not in existing_paths:
                        existing_paths.add(path)
                        from .collectors.api_collector import APIFindResult
                        api_find_result = APIFindResult(
                            path=path,
                            method="GET",
                            source_type="response_discovery",
                            base_url="",
                            url_type="discovered"
                        )
                        self._api_aggregator.add_api(  # type: ignore[reportOptionalMemberAccess]
                            api_find_result,
                            source_info={'source': 'response_discovery'}
                        )
            
            browser_apis = js_result.get('browser_api_endpoints', [])
            if browser_apis:
                logger.info(f"Adding {len(browser_apis)} API endpoints from browser collector")
                for api_path in browser_apis:
                    from urllib.parse import urlparse
                    if api_path.startswith('http://') or api_path.startswith('https://'):
                        parsed = urlparse(api_path)
                        path = parsed.path
                        base_url = f"{parsed.scheme}://{parsed.netloc}"
                    elif api_path.startswith('/'):
                        path = api_path
                        base_url = ""
                    else:
                        path = '/' + api_path
                        base_url = ""
                    
                    if not _is_valid_path(path):
                        continue
                    if path not in existing_paths:
                        existing_paths.add(path)
                        from .collectors.api_collector import APIFindResult
                        api_find_result = APIFindResult(
                            path=path,
                            method="GET",
                            source_type="browser_collector",
                            base_url=base_url,
                            url_type="discovered"
                        )
                        self._api_aggregator.add_api(  # type: ignore[reportOptionalMemberAccess]
                            api_find_result,
                            source_info={'source': 'browser_collector'}
                        )
            
            finder_api_paths = js_result.get('finder_api_paths', [])
            if finder_api_paths:
                logger.info(f"Adding {len(finder_api_paths)} API paths from ApiPathFinder")
                for api_path in finder_api_paths:
                    if not _is_valid_path(api_path):
                        continue
                    if api_path not in existing_paths and len(api_path) > 1:
                        existing_paths.add(api_path)
                        from .collectors.api_collector import APIFindResult
                        api_find_result = APIFindResult(
                            path=api_path,
                            method="GET",
                            source_type="api_path_finder",
                            base_url="",
                            url_type="finder"
                        )
                        self._api_aggregator.add_api(  # type: ignore[reportOptionalMemberAccess]
                            api_find_result,
                            source_info={'source': 'api_path_finder'}
                        )
        
        all_api_paths = list(existing_paths)
        logger.info(f"Starting bypass fuzzing with {len(all_api_paths)} discovered paths")
        
        bypasser = APIBypasser()
        fuzz_added_count = 0
        for discovered_path in all_api_paths:
            full_url = f"{self.config.target.rstrip('/')}/{discovered_path.lstrip('/')}"
            fuzz_results = bypasser.fuzz_parent_child_paths(full_url, "GET")
            for fuzz_result in fuzz_results[:50]:
                fuzzed_path = fuzz_result.bypassed_url.replace(self.config.target.rstrip('/'), '')
                if fuzzed_path not in existing_paths:
                    existing_paths.add(fuzzed_path)
                    from .collectors.api_collector import APIFindResult
                    api_find_result = APIFindResult(
                        path=fuzzed_path,
                        method="GET",
                        source_type="bypass_fuzz",
                        base_url="",
                        url_type="fuzzed"
                    )
                    self._api_aggregator.add_api(
                        api_find_result,
                        source_info={'source': f'bypass_fuzz:{discovered_path}'}
                    )
                    fuzz_added_count += 1
        
        logger.info(f"Bypass fuzzing added {fuzz_added_count} new paths")
        
        all_api_paths = list(existing_paths)
        probed_parent_paths = await self._probe_parent_paths(js_results, additional_paths=all_api_paths)
        
        for parent_path, sub_endpoints in probed_parent_paths.items():
            for sub_path in sub_endpoints:
                if sub_path not in existing_paths:
                    existing_paths.add(sub_path)
                    from .collectors.api_collector import APIFindResult
                    api_find_result = APIFindResult(
                        path=sub_path,
                        method="GET",
                        source_type="parent_path_probe",
                        base_url="",
                        url_type="probed"
                    )
                    self._api_aggregator.add_api(  # type: ignore[reportOptionalMemberAccess]
                        api_find_result,
                        source_info={'source': f'probed_parent:{parent_path}'}
                    )
        
        fuzzed_paths = await self._fuzz_api_paths(js_results)
        
        for parent_path, sub_endpoints in fuzzed_paths.items():
            for sub_path in sub_endpoints:
                if sub_path not in existing_paths:
                    existing_paths.add(sub_path)
                    from .collectors.api_collector import APIFindResult
                    api_find_result = APIFindResult(
                        path=sub_path,
                        method="GET",
                        source_type="fuzz_api",
                        base_url="",
                        url_type="fuzzed"
                    )
                    self._api_aggregator.add_api(  # type: ignore[reportOptionalMemberAccess]
                        api_find_result,
                        source_info={'source': f'fuzz_api:{parent_path}'}
                    )
        
        logger.info("Starting cross-source fuzzing for additional API discovery...")
        cross_fuzz_results = await self._cross_source_fuzz()
        
        for fuzzed_path, info in cross_fuzz_results.items():
            if fuzzed_path not in existing_paths:
                existing_paths.add(fuzzed_path)
                from .collectors.api_collector import APIFindResult
                api_find_result = APIFindResult(
                    path=fuzzed_path,
                    method="GET",
                    source_type="cross_source_fuzz",
                    base_url="",
                    url_type="fuzzed"
                )
                self._api_aggregator.add_api(  # type: ignore[reportOptionalMemberAccess]
                    api_find_result,
                    source_info={'source': 'cross_source_fuzz'}
                )
        
        raw_endpoints = self._api_aggregator.get_all()  # type: ignore[reportOptionalMemberAccess]
        final_endpoints = []
        
        for endpoint in raw_endpoints:
            if not APIPathCombiner.is_valid_api_path(endpoint.path):
                logger.debug(f"过滤无效路径: {endpoint.path}")
                continue
            
            full_url = APIPathCombiner.combine_base_and_path(
                endpoint.base_url or "",
                endpoint.path,
                default_base=self.config.target if hasattr(self.config, 'target') else ""
            )
            api_endpoint = APIEndpoint(
                path=endpoint.path,
                method=endpoint.method,
                base_url=endpoint.base_url,
                full_url=full_url,
                sources=[],
                service_key=ServiceAnalyzer.extract_service_key(full_url, endpoint.path)
            )
            final_endpoints.append(api_endpoint)
            
            if self.db_storage:
                self.db_storage.insert_api({
                    'api_id': api_endpoint.api_id,
                    'path': api_endpoint.path,
                    'method': api_endpoint.method,
                    'base_url': api_endpoint.base_url,
                    'full_url': api_endpoint.full_url,
                    'status': 'discovered',
                    'score': 0,
                    'is_high_value': 0,
                    'service_key': api_endpoint.service_key,
                    'created_at': api_endpoint.created_at
                })
        
        if self.result:
            self.result.api_endpoints = final_endpoints
            self.result.total_apis = len(final_endpoints)
        
        if self._incremental_scanner:
            try:
                js_urls = []
                if self._js_cache:
                    all_js_results = self._js_cache.get_all()
                    for js_result in all_js_results:
                        if hasattr(js_result, 'urls'):
                            js_urls.extend(js_result.urls)
                snapshot_id = self._incremental_scanner.save_snapshot(
                    target=self.config.target,
                    apis=[{'path': e.path, 'method': e.method, 'status': getattr(e, 'status', '')} for e in final_endpoints],
                    js_urls=js_urls
                )
                logger.info(f"Saved incremental snapshot: {snapshot_id}")
            except Exception as e:
                logger.debug(f"Failed to save incremental snapshot: {e}")
        
        if self._api_aggregator and hasattr(self._api_aggregator, 'get_fusion_stats'):
            try:
                fusion_stats = self._api_aggregator.get_fusion_stats()
                if fusion_stats.get('fusion_enabled'):
                    logger.info(f"[Fusion] 端点融合统计: 总API={fusion_stats.get('total_apis', 0)}, 融合后={fusion_stats.get('after_fusion', 0)}, 高置信度={fusion_stats.get('high_confidence', 0)}, 运行时确认={fusion_stats.get('runtime_confirmed', 0)}")
                    by_type = fusion_stats.get('by_type', {})
                    if by_type:
                        logger.info(f"[Fusion] 端点类型分布: {', '.join(f'{k}:{v}' for k,v in by_type.items())}")
            except Exception as e:
                logger.debug(f"Fusion stats error: {e}")
        
        return {
            'total_endpoints': len(final_endpoints),
            'endpoints': [e.to_dict() for e in final_endpoints]
        }
    
    async def _run_analyzers(self):
        """运行分析阶段"""
        self._current_stage = 1
        
        active_analyzers = self.config.analyzers or ['scorer', 'sensitive']
        
        analyzer_results = {}
        
        if 'scorer' in active_analyzers:
            analyzer_results['scorer'] = await self._score_apis()
        
        if 'sensitive' in active_analyzers:
            analyzer_results['sensitive'] = await self._detect_sensitive()
        
        self._process_browser_enhancer_findings()
        
        self._analyzer_results = analyzer_results
        
        flux_results = await self._flux_enhanced_detection()
        self._flux_results = flux_results
    
    async def _score_apis(self) -> Dict[str, Any]:
        """API评分 - 渗透测试思维：智能方法推断 + JSON响应验证 + 有参探测"""
        from .collectors.api_collector import APIMethodInferrer
        
        endpoints = self.result.api_endpoints if self.result else []
        
        url_to_endpoint: Dict[str, Any] = {e.full_url: e for e in endpoints}
        
        all_responses: List[Any] = []
        
        COMMON_PARAMS = {
            'page': '1', 'pageNum': '1', 'page_no': '1', 'p': '1',
            'pageSize': '10', 'page_size': '10', 'size': '10', 'limit': '10', 'ps': '10',
            'keyword': 'test', 'kw': 'test', 'search': 'test', 'query': 'test', 'q': 'test',
            'id': '1', 'ids': '1', 'uid': '1', 'userId': '1', 'id': 'admin',
            'name': 'admin', 'username': 'admin', 'user': 'admin',
            'status': '1', 'state': '1', 'type': '1', 'typeId': '1',
            'key': 'test', 'value': 'test', 'val': 'test',
            'token': 'test', 'Authorization': 'Bearer test',
            'file': 'test', 'data': '{"test": 1}',
        }
        
        for endpoint in endpoints:
            methods_to_try = APIMethodInferrer.infer_methods(endpoint.path)
            endpoint_found = False
            
            for method in methods_to_try:
                try:
                    response = await self._http_client.request(  # type: ignore[reportOptionalMemberAccess]
                        endpoint.full_url,
                        method=method
                    )
                    
                    content = response.content if hasattr(response, 'content') else ''
                    content_type = response.headers.get('Content-Type', '') if hasattr(response, 'headers') else ''
                    status_code = response.status_code if hasattr(response, 'status_code') else 0
                    
                    if status_code and 200 <= status_code < 400:
                        endpoint.method = method
                        endpoint.status_code = status_code
                        endpoint.response_type = self._detect_response_type(response)
                        
                        is_json = APIMethodInferrer.is_json_response(content, content_type)
                        is_html = APIMethodInferrer.is_html_response(content, content_type)
                        
                        if is_html:
                            continue
                        
                        from .models import APIStatus
                        endpoint.status = APIStatus.ALIVE
                        endpoint_found = True
                        
                        from .testers.parameter_extractor import APIParameterExtractor
                        param_extractor = APIParameterExtractor()
                        extracted_params = param_extractor.extract_from_response(content)
                        
                        if extracted_params and not endpoint_found:
                            param_dict = {}
                            for p in extracted_params[:5]:
                                if hasattr(p, 'name') and hasattr(p, 'example_value'):
                                    param_dict[p.name] = p.example_value
                                elif hasattr(p, 'name'):
                                    param_dict[p.name] = COMMON_PARAMS.get(p.name, 'test')
                            
                            if param_dict:
                                try:
                                    if method == 'GET':
                                        from urllib.parse import urlencode
                                        params_url = endpoint.full_url + '?' + urlencode(param_dict)
                                        param_response = await self._http_client.request(params_url, method='GET')
                                    else:
                                        param_response = await self._http_client.request(
                                            endpoint.full_url,
                                            method=method,
                                            data=param_dict if method in ['POST', 'PUT'] else None,
                                            json_data=param_dict if method == 'POST' else None
                                        )
                                    
                                    if param_response and hasattr(param_response, 'status_code'):
                                        param_status = param_response.status_code
                                        param_content = param_response.content if hasattr(param_response, 'content') else ''
                                        param_ct = param_response.headers.get('Content-Type', '') if hasattr(param_response, 'headers') else ''
                                        
                                        if param_status and 200 <= param_status < 400:
                                            if APIMethodInferrer.is_json_response(param_content, param_ct):
                                                if not APIMethodInferrer.is_html_response(param_content, param_ct):
                                                    endpoint.status = APIStatus.ALIVE
                                                    endpoint_found = True
                                except Exception:
                                    pass
                        
                        from .utils.http_client import TaskResult
                        task_result = TaskResult(
                            url=endpoint.full_url,
                            method=method,
                            status_code=status_code,
                            content=content,
                            content_bytes=content.encode() if isinstance(content, str) else content,
                            content_hash=getattr(response, 'content_hash', '')
                        )
                        all_responses.append(task_result)
                        
                        from .analyzers.response_cluster import TaskResult as RCTaskResult
                        rc_task_result = RCTaskResult(
                            status_code=status_code,
                            content=content.encode() if isinstance(content, str) else content,
                            content_hash=getattr(response, 'content_hash', '')
                        )
                        self._response_cluster.add_response(endpoint.api_id, rc_task_result)  # type: ignore[reportOptionalMemberAccess]
                        
                        if self._api_scorer:
                            self._api_scorer.add_evidence(
                                endpoint.full_url,
                                'http_test',
                                {},
                                http_info={'status': status_code, 'content': content[:500] if content else '', 'is_json': is_json}
                            )
                        
                        break
                    elif status_code in [401, 403]:
                        endpoint.status_code = status_code
                        endpoint.method = method
                        
                        is_json = APIMethodInferrer.is_json_response(content, content_type)
                        if is_json:
                            from .models import APIStatus
                            endpoint.status = APIStatus.ALIVE
                            endpoint_found = True
                            
                            if self._api_scorer:
                                self._api_scorer.add_evidence(
                                    endpoint.full_url,
                                    'auth_required_api',
                                    {},
                                    http_info={'status': status_code, 'content': content[:500] if content else ''}
                                )
                            break
                    else:
                        from .utils.http_client import TaskResult
                        task_result = TaskResult(
                            url=endpoint.full_url,
                            method=method,
                            status_code=status_code,
                            content=content if content else '',
                            content_bytes=b'',
                            content_hash=''
                        )
                        all_responses.append(task_result)
                
                except Exception:
                    continue
            
            if not endpoint_found:
                from urllib.parse import urlencode
                
                for method in ['POST', 'PUT'] if endpoint.method == 'GET' else ['GET']:
                    for param_key in ['key', 'id', 'page', 'name', 'data']:
                        COMMON_PARAMS_404 = {param_key: 'test', 'value': 'test'}
                        
                        try:
                            if method in ['POST', 'PUT']:
                                response = await self._http_client.request(
                                    endpoint.full_url,
                                    method=method,
                                    data=urlencode(COMMON_PARAMS_404),
                                    headers={'Content-Type': 'application/x-www-form-urlencoded'}
                                )
                            else:
                                response = await self._http_client.request(
                                    endpoint.full_url + '?' + urlencode(COMMON_PARAMS_404),
                                    method=method
                                )
                            
                            if response and hasattr(response, 'status_code'):
                                status = response.status_code
                                if status and 200 <= status < 400:
                                    endpoint.method = method
                                    endpoint.status_code = status
                                    endpoint.response_type = self._detect_response_type(response)
                                    
                                    content = response.content if hasattr(response, 'content') else ''
                                    ct = response.headers.get('Content-Type', '') if hasattr(response, 'headers') else ''
                                    
                                    if APIMethodInferrer.is_json_response(content, ct):
                                        if not APIMethodInferrer.is_html_response(content, ct):
                                            endpoint.status = APIStatus.ALIVE
                                            endpoint_found = True
                                            break
                        except:
                            pass
                    
                    if endpoint_found:
                        break
                
                if not endpoint_found:
                    try:
                        response = await self._http_client.request(  # type: ignore[reportOptionalMemberAccess]
                            endpoint.full_url,
                            method=endpoint.method
                        )
                        from .utils.http_client import TaskResult
                        task_result = TaskResult(
                            url=endpoint.full_url,
                            method=endpoint.method,
                            status_code=response.status_code,
                            content=response.content,
                            content_bytes=response.content.encode() if isinstance(response.content, str) else response.content,
                            content_hash=getattr(response, 'content_hash', '')
                        )
                        all_responses.append(task_result)
                        
                        from .analyzers.response_cluster import TaskResult as RCTaskResult
                        rc_task_result = RCTaskResult(
                            status_code=response.status_code,
                            content=response.content.encode() if isinstance(response.content, str) else response.content,
                            content_hash=response.content_hash
                        )
                        self._response_cluster.add_response(endpoint.api_id, rc_task_result)  # type: ignore[reportOptionalMemberAccess]
                        
                        status_code = response.status_code if hasattr(response, 'status_code') else 0
                        if status_code == 404 or status_code == 410:
                            continue
                        
                        if not self._response_cluster.is_baseline_404(endpoint.api_id):  # type: ignore[reportOptionalMemberAccess]
                            is_valid = self._response_baseline.is_valid_api(task_result) if self._response_baseline else True
                            
                            if is_valid:
                                from .models import APIStatus
                                endpoint.status = APIStatus.ALIVE
                                endpoint.status_code = response.status_code
                                endpoint.response_type = self._detect_response_type(response)
                    except:
                        pass
        
        if self._response_baseline and all_responses:
            try:
                self._response_baseline.learn(all_responses)
                logger.info(f"ResponseBaselineLearner: learned {self._response_baseline.get_baseline_count()} baselines, identified {self._response_baseline.get_default_page_count()} default pages")
            except Exception as e:
                logger.debug(f"Baseline learning error: {e}")
        
        high_value_evidence = self._api_scorer.get_high_value() if self._api_scorer else []
        
        for evidence in high_value_evidence:
            for ep in endpoints:
                ep_path_lower = ep.path.lower() if ep.path else ''
                if ep_path_lower == evidence.normalized_path or \
                   ep.full_url.lower().endswith(evidence.normalized_path):
                    ep.is_high_value = True
                    break
        
        high_value_count = sum(1 for e in endpoints if e.is_high_value)
        from .models import APIStatus
        alive_count = sum(1 for e in endpoints if e.status == APIStatus.ALIVE)
        
        if self.result:
            self.result.alive_apis = alive_count
            self.result.high_value_apis = high_value_count
        
        filtered_endpoints = [e for e in endpoints if e.status == APIStatus.ALIVE and e.response_type and e.response_type != 'HTML']
        if self.result and filtered_endpoints:
            self.result.api_endpoints = filtered_endpoints
            self.result.total_apis = len(filtered_endpoints)
        
        alive_count = len(filtered_endpoints)
        high_value_count = sum(1 for e in filtered_endpoints if e.is_high_value)
        
        if self.result:
            self.result.alive_apis = alive_count
            self.result.high_value_apis = high_value_count
        
        return {
            'alive_apis': alive_count,
            'high_value_apis': high_value_count
        }
    
    async def _detect_sensitive(self) -> Dict[str, Any]:
        """敏感信息检测"""
        responses_collected = []
        high_value_api_ids = set()
        
        for endpoint in self.result.api_endpoints if self.result else []:
            if endpoint.is_high_value:
                high_value_api_ids.add(endpoint.api_id)
            try:
                response = await self._http_client.request(  # type: ignore[reportOptionalMemberAccess]
                    endpoint.full_url,
                    method=endpoint.method
                )
                responses_collected.append({
                    'content': response.content,
                    'url': endpoint.full_url,
                    'api_id': endpoint.api_id
                })
            except Exception as e:
                logger.debug(f"Sensitive detection request error: {e}")
        
        sensitive_findings = self._sensitive_detector.detect(  # type: ignore[reportOptionalMemberAccess]
            responses_collected,
            high_value_api_ids
        )
        
        from .models import SensitiveData, Severity as ModelSeverity
        from .analyzers.sensitive_detector import Severity as DetectorSeverity
        for finding in sensitive_findings:
            try:
                severity_value = finding.severity.value if isinstance(finding.severity, Enum) else finding.severity
                model_severity = ModelSeverity(severity_value)
            except (ValueError, AttributeError):
                model_severity = ModelSeverity.MEDIUM
            sensitive_data = SensitiveData(
                api_id=finding.location,
                data_type=finding.data_type,
                matches=finding.matches,
                severity=model_severity,
                evidence=finding.evidence,
                context=finding.context,
                location=finding.location
            )
            if self.result:
                self.result.sensitive_data.append(sensitive_data)
        
        self._process_sensitive_resources_from_js()
        
        return {
            'sensitive_count': len(sensitive_findings),
            'findings': [asdict(f) for f in sensitive_findings]
        }
    
    def _process_sensitive_resources_from_js(self):
        """处理从 JS/HTML 中提取的敏感资源"""
        if not self._collector_results or 'js' not in self._collector_results:
            return
        
        js_result = self._collector_results['js']
        
        inline_sensitive = js_result.get('sensitive_resources', [])
        response_sensitive = js_result.get('response_sensitive_resources', [])
        
        all_sensitive = set(inline_sensitive + response_sensitive)
        
        if not all_sensitive:
            return
        
        logger.info(f"Found {len(all_sensitive)} sensitive resources from JS/HTML")
        
        from .models import SensitiveData
        for resource_path in all_sensitive:
            if not resource_path:
                continue
            
            sensitive_data = SensitiveData(
                api_id=resource_path,
                data_type='sensitive_resource',
                matches=[resource_path],
                severity=Severity.MEDIUM,
                evidence=resource_path,
                context='JS/HTML extraction',
                location=resource_path
            )
            if self.result:
                self.result.sensitive_data.append(sensitive_data)
    
    def _process_browser_enhancer_findings(self):
        """处理从 browser_enhancer.SensitiveInfoExtractor 提取的敏感信息"""
        if not self._collector_results or 'js' not in self._collector_results:
            return
        
        js_result = self._collector_results['js']
        sensitive_findings = js_result.get('sensitive_findings', [])
        
        if not sensitive_findings:
            return
        
        logger.info(f"Processing {len(sensitive_findings)} sensitive findings from browser_enhancer")
        
        from .models import SensitiveData, Severity as ModelSeverity
        
        for finding in sensitive_findings:
            if not hasattr(finding, 'info_type'):
                continue
            
            severity_map = {
                'credential': ModelSeverity.HIGH,
                'api_key': ModelSeverity.HIGH,
                'secret': ModelSeverity.HIGH,
                'token': ModelSeverity.MEDIUM,
                'internal_ip': ModelSeverity.LOW,
                'phone': ModelSeverity.LOW,
                'email': ModelSeverity.LOW,
            }
            
            severity = severity_map.get(finding.info_type, ModelSeverity.MEDIUM)
            
            sensitive_data = SensitiveData(
                api_id='',
                data_type=finding.info_type,
                matches=[finding.value],
                severity=severity,
                evidence=finding.value,
                context=finding.context or finding.source,
                location=finding.source
            )
            
            if self.result:
                self.result.sensitive_data.append(sensitive_data)
        
        logger.info(f"Added {len(sensitive_findings)} sensitive findings to scan result")
    
    async def _flux_enhanced_detection(self):
        """
        FLUX增强检测 - 在分析阶段后运行，作为补充检测
        保持现有模块不变，FLUX模块作为并行增强
        """
        flux_results = {
            'fingerprints': [],
            'waf_detected': None,
            'flux_sensitive': [],
            'ai_findings': [],
            'k8s_findings': [],
            'container_findings': [],
            'cicd_findings': [],
            'cloud_findings': [],
            'fusion_endpoints': [],
        }
        
        try:
            flux_config = self.cfg.get('flux', {})
            if not flux_config.get('enabled', True):
                return flux_results
            
            target = self.config.target
            if not target:
                return flux_results
            
            logger.info("[FLUX] 开始FLUX增强检测...")
            
            if flux_config.get('fingerprint', {}).get('enabled', True) and self._fingerprint_engine:
                try:
                    fp_response = await self._http_client.request(target)  # type: ignore[reportOptionalMemberAccess]
                    fp_results = self._fingerprint_engine.match(fp_response)
                    flux_results['fingerprints'] = [r.to_dict() for r in fp_results[:20]]
                    logger.info(f"[FLUX] 指纹识别完成: 发现 {len(flux_results['fingerprints'])} 个组件")
                except Exception as e:
                    logger.debug(f"[FLUX] 指纹识别失败: {e}")
            
            if flux_config.get('waf', {}).get('enabled', True) and self._waf_detector:
                try:
                    waf_response = await self._http_client.request(target)  # type: ignore[reportOptionalMemberAccess]
                    waf_result = self._waf_detector.detect(waf_response)
                    if waf_result:
                        flux_results['waf_detected'] = waf_result.waf_name
                        logger.info(f"[FLUX] WAF检测: 发现 {waf_result.waf_name}")
                except Exception as e:
                    logger.debug(f"[FLUX] WAF检测失败: {e}")
            
            if flux_config.get('secret_matching', {}).get('enabled', True) and self._secret_matcher:
                try:
                    for js_result in (self._collector_results.get('js', {})).get('alive_js', []):
                        if isinstance(js_result, dict) and 'content' in js_result:
                            content = js_result['content']
                            if isinstance(content, bytes):
                                content = content.decode('utf-8', errors='ignore')
                            matches = self._secret_matcher.scan_text(content, js_result.get('url', ''))
                            for match in matches:
                                if not match.is_likely_false_positive:
                                    flux_results['flux_sensitive'].append(match.to_dict())
                    logger.info(f"[FLUX] 敏感信息检测完成: 发现 {len(flux_results['flux_sensitive'])} 处")
                except Exception as e:
                    logger.debug(f"[FLUX] 敏感信息检测失败: {e}")
            
            if flux_config.get('ai_security', {}).get('enabled', True) and self._ai_security_tester:
                try:
                    ai_findings = self._ai_security_tester.scan_ai_components(target)
                    flux_results['ai_findings'] = [f.__dict__ for f in ai_findings]
                    logger.info(f"[FLUX] AI安全检测完成: 发现 {len(ai_findings)} 个问题")
                except Exception as e:
                    logger.debug(f"[FLUX] AI安全检测失败: {e}")
            
            if flux_config.get('kubernetes_security', {}).get('enabled', True) and self._k8s_security_tester:
                try:
                    k8s_findings = self._k8s_security_tester.scan_k8s_components(target)
                    flux_results['k8s_findings'] = [f.__dict__ for f in k8s_findings]
                    logger.info(f"[FLUX] K8s安全检测完成: 发现 {len(k8s_findings)} 个问题")
                except Exception as e:
                    logger.debug(f"[FLUX] K8s安全检测失败: {e}")
            
            if flux_config.get('container_security', {}).get('enabled', True) and self._container_security_tester:
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(target)
                    container_findings = self._container_security_tester.scan_container_runtimes(parsed.hostname or parsed.path)
                    flux_results['container_findings'] = [f.__dict__ for f in container_findings]
                    logger.info(f"[FLUX] 容器安全检测完成: 发现 {len(container_findings)} 个问题")
                except Exception as e:
                    logger.debug(f"[FLUX] 容器安全检测失败: {e}")
            
            if flux_config.get('cicd_security', {}).get('enabled', True) and self._cicd_scanner:
                try:
                    cicd_findings = self._cicd_scanner.scan_cicd_configs(target)
                    flux_results['cicd_findings'] = [f.__dict__ for f in cicd_findings]
                    logger.info(f"[FLUX] CI/CD安全检测完成: 发现 {len(cicd_findings)} 个问题")
                except Exception as e:
                    logger.debug(f"[FLUX] CI/CD安全检测失败: {e}")
            
            if flux_config.get('cloud_security', {}).get('enabled', True) and self._cloud_bucket_tester:
                try:
                    cloud_findings = self._cloud_bucket_tester.test_bucket_access(target)
                    flux_results['cloud_findings'] = [f.__dict__ for f in cloud_findings]
                    logger.info(f"[FLUX] 云安全检测完成: 发现 {len(cloud_findings)} 个问题")
                except Exception as e:
                    logger.debug(f"[FLUX] 云安全检测失败: {e}")
            
            if self._api_aggregator and hasattr(self._api_aggregator, '_fusion_engine') and self._api_aggregator._fusion_engine:
                try:
                    fusion_engine = self._api_aggregator._fusion_engine
                    from .unified_fusion import SourceType as FusionSourceType
                    for endpoint in (self.result.api_endpoints if self.result else []):
                        source_type_val = getattr(endpoint, 'source_type', 'unknown')
                        try:
                            source_type = FusionSourceType(source_type_val) if source_type_val else FusionSourceType.UNKNOWN
                        except (ValueError, AttributeError):
                            source_type = FusionSourceType.UNKNOWN
                        
                        is_high_value = getattr(endpoint, 'is_high_value', False)
                        status_code_val = getattr(endpoint, 'status_code', 0) if is_high_value else 0
                        
                        ep = fusion_engine.add_endpoint(
                            url=endpoint.full_url,
                            method=endpoint.method,
                            source_type=source_type,
                            source_url='',
                            confidence=0.5,
                            runtime_observed=is_high_value,
                            status_code=status_code_val,
                        )
                    fusion_report = fusion_engine.get_fusion_report()
                    flux_results['fusion_endpoints'] = fusion_report
                    
                    high_value_count = len(fusion_report.get('high_confidence_endpoints', []))
                    runtime_count = fusion_report.get('runtime_confirmed_count', 0)
                    logger.info(f"[FLUX] 端点融合完成: 融合后 {fusion_report.get('total_endpoints', 0)} 个端点, 高置信度 {high_value_count}, 运行时确认 {runtime_count}")
                except Exception as e:
                    logger.debug(f"[FLUX] 端点融合失败: {e}")
            
            if flux_config.get('vuln_prioritizer', {}).get('enabled', True) and self._vuln_prioritizer and self.result:
                try:
                    if self.result.vulnerabilities:
                        vuln_dicts = [v.to_dict() if hasattr(v, 'to_dict') else v for v in self.result.vulnerabilities]
                        vuln_dicts_only = [d for d in vuln_dicts if isinstance(d, dict)]
                        candidates = self._vuln_prioritizer.analyze_findings(vuln_dicts_only)
                        prioritized = [c.to_dict() if hasattr(c, 'to_dict') else c for c in candidates[:30]]
                        flux_results['prioritized_vulns'] = prioritized
                        logger.info(f"[FLUX] 漏洞优先级排序完成: {len(prioritized)} 个漏洞")
                except Exception as e:
                    logger.debug(f"[FLUX] 漏洞优先级排序失败: {e}")
            
            logger.info("[FLUX] FLUX增强检测完成")
            
        except Exception as e:
            logger.warning(f"[FLUX] 增强检测过程出错: {e}")
        
        return flux_results
    
    async def _run_testers(self):
        """运行测试阶段"""
        self._current_stage = 2
        
        active_testers = self.config.testers or ['fuzz', 'vuln', 'bypass']
        
        tester_results = {}
        
        if 'fuzz' in active_testers:
            tester_results['fuzz'] = await self._run_fuzz_test()
        
        if 'vuln' in active_testers:
            tester_results['vuln'] = await self._run_vuln_test()
        
        if 'bypass' in active_testers:
            tester_results['bypass'] = await self._run_bypass_test()

        if 'oss' in active_testers:
            tester_results['oss'] = await self._run_oss_test()

        self._tester_results = tester_results

    async def _run_oss_test(self) -> Dict[str, Any]:
        """OSS 存储桶漏洞测试 (终极测试项)"""
        oss_results = {
            'total_buckets': 0,
            'vulnerabilities': [],
            'by_provider': {}
        }

        oss_collector = getattr(self, '_oss_collector', None)
        if not oss_collector:
            oss_collector = get_oss_collector()

        oss_endpoints = oss_collector.get_all_endpoints()

        if not oss_endpoints:
            logger.info("[OSS Tester] No OSS endpoints found, skipping OSS vulnerability testing")
            return oss_results

        oss_results['total_buckets'] = len(oss_endpoints)
        logger.info(f"[OSS Tester] Testing {len(oss_endpoints)} OSS endpoints")

        oss_tester = OSSVulnTester(self._http_client)

        all_vulns = []

        for endpoint in oss_endpoints:
            try:
                vulns = await oss_tester.test_bucket(
                    bucket_url=endpoint.full_url,
                    bucket_name=endpoint.bucket,
                    region=endpoint.region,
                    provider=endpoint.provider.value
                )

                for vuln in vulns:
                    vuln_dict = {
                        'type': vuln.vuln_type.value if hasattr(vuln.vuln_type, 'value') else str(vuln.vuln_type),
                        'bucket': vuln.bucket,
                        'region': vuln.region,
                        'provider': vuln.provider,
                        'url': vuln.url,
                        'risk_level': vuln.risk_level.value if hasattr(vuln.risk_level, 'value') else str(vuln.risk_level),
                        'verified': vuln.verified,
                        'payload': vuln.payload,
                        'description': vuln.description,
                        'poc': vuln.poc,
                        'remediation': vuln.remediation
                    }
                    all_vulns.append(vuln_dict)

                    logger.warning(f"[OSS Vuln] {vuln.bucket} ({vuln.provider}): {vuln.description}")

                    provider_key = vuln.provider
                    if provider_key not in oss_results['by_provider']:
                        oss_results['by_provider'][provider_key] = []
                    oss_results['by_provider'][provider_key].append(vuln.description)

            except Exception as e:
                logger.debug(f"[OSS Tester] Error testing {endpoint.full_url}: {e}")

        oss_results['vulnerabilities'] = all_vulns

        logger.info(f"[OSS Tester] Found {len(all_vulns)} OSS vulnerabilities")

        return oss_results
    
    async def _run_fuzz_test(self) -> Dict[str, Any]:
        """模糊测试"""
        high_value_apis = [e for e in self.result.api_endpoints if e.is_high_value] if self.result else []
        
        discovered_params = set()
        if self._collector_results and 'js' in self._collector_results:
            js_result = self._collector_results['js']
            discovered_params.update(js_result.get('js_params', []))
            for route in js_result.get('ast_routes', []):
                if '{' in route:
                    import re
                    param_patterns = re.findall(r'\{(\w+)\}', route)
                    discovered_params.update(param_patterns)
        
        common_params = ['id', 'page', 'pageNum', 'pageSize', 'limit', 'offset', 'count',
                        'userId', 'user_id', 'orderId', 'order_id', 'productId', 'product_id',
                        'category', 'type', 'status', 'action', 'mode', 'q', 'query', 'search',
                        'keyword', 'name', 'title', 'email', 'phone', 'code', 'token', 'lang',
                        'start', 'end', 'startDate', 'endDate', 'sort', 'order', 'filter']
        discovered_params.update(common_params)
        
        fuzz_count = 0
        fuzz_results = []
        
        for endpoint in high_value_apis:
            try:
                base_params = set(endpoint.parameters) if endpoint.parameters else set()
                all_params = list(base_params.union(discovered_params))
                if not all_params:
                    all_params = ['id', 'page']
                
                results = await self._fuzz_tester.fuzz_parameters(  # type: ignore[reportOptionalMemberAccess]
                    endpoint.full_url,
                    endpoint.method,
                    all_params
                )
                fuzz_count += len(results)
                fuzz_results.extend(results)
            except Exception as e:
                logger.debug(f"Fuzz test error: {e}")
        
        logger.info(f"Fuzz testing: discovered {len(discovered_params)} params, performed {fuzz_count} fuzz operations")
        
        return {
            'fuzz_count': fuzz_count,
            'discovered_params': list(discovered_params),
            'results': [r.to_dict() if hasattr(r, 'to_dict') else str(r) for r in fuzz_results]
        }
    
    async def _run_vuln_test(self) -> Dict[str, Any]:
        """
        基于 Akto 风格的智能漏洞测试
        
        改进：
        1. 使用 EndpointAnalyzer 分析端点特征
        2. 使用 TestSelector 基于端点特征智能选择测试
        3. 只执行匹配的测试，减少误报
        4. 使用 TrafficAnalyzer 学习API行为模式
        """
        from .analyzers import (
            EndpointAnalyzer, TestSelector, TestCategory, TestSelection,
            TrafficAnalyzer, create_traffic_analyzer_from_endpoints
        )
        
        high_value_apis = [e for e in self.result.api_endpoints if e.is_high_value] if self.result else []
        
        if self._url_greper and high_value_apis:
            try:
                urls_to_scan = [api.full_url for api in high_value_apis]
                url_matches = self._url_greper.scan_urls(urls_to_scan)
                
                if url_matches:
                    matched_urls = {m.url for m in url_matches}
                    high_value_apis = [
                        api for api in high_value_apis 
                        if api.full_url in matched_urls
                    ]
                    
                    stats = self._url_greper.get_statistics(url_matches)
                    print(f"[IDOR Scan] Filtered {stats['total']} high-risk URLs for IDOR testing")
            except Exception as e:
                logger.debug(f"URL greper error: {e}")
        
        analyzer = EndpointAnalyzer()
        selector = TestSelector()
        traffic_analyzer = create_traffic_analyzer_from_endpoints(high_value_apis)
        
        enabled_categories = set()
        cfg = self.config
        
        if getattr(cfg, 'enable_ssrf_test', True):
            enabled_categories.add(TestCategory.SSRF)
        if getattr(cfg, 'enable_sql_test', True):
            enabled_categories.add(TestCategory.SQL_INJECTION)
        if getattr(cfg, 'enable_xss_test', True):
            enabled_categories.add(TestCategory.XSS)
        if getattr(cfg, 'enable_bypass_test', True):
            enabled_categories.add(TestCategory.RATE_LIMIT)
        if getattr(cfg, 'enable_jwt_test', True):
            enabled_categories.add(TestCategory.JWT_SECURITY)
        if getattr(cfg, 'enable_unauthorized_test', True):
            enabled_categories.add(TestCategory.AUTH_BYPASS)
        if getattr(cfg, 'enable_idor_test', True):
            enabled_categories.add(TestCategory.IDOR)
            enabled_categories.add(TestCategory.BOLA)
        if getattr(cfg, 'enable_cors_test', True):
            enabled_categories.add(TestCategory.CORS)
        if getattr(cfg, 'enable_crlf_test', True):
            enabled_categories.add(TestCategory.CRLF)
        if getattr(cfg, 'enable_lfi_test', True):
            enabled_categories.add(TestCategory.LFI)
        if getattr(cfg, 'enable_ssti_test', True):
            enabled_categories.add(TestCategory.SSTI)
        if getattr(cfg, 'enable_verbose_error_test', True):
            enabled_categories.add(TestCategory.VERBOSE_ERROR)
        if getattr(cfg, 'enable_command_injection_test', True):
            enabled_categories.add(TestCategory.COMMAND_INJECTION)
        if getattr(cfg, 'enable_info_disclosure_test', True):
            enabled_categories.add(TestCategory.INFORMATION_DISCLOSURE)
        if getattr(cfg, 'enable_bfla_test', True):
            enabled_categories.add(TestCategory.BFLA)
        if getattr(cfg, 'enable_injection_attacks_test', True):
            enabled_categories.add(TestCategory.INJECTION_ATTACKS)
        if getattr(cfg, 'enable_input_validation_test', True):
            enabled_categories.add(TestCategory.INPUT_VALIDATION)
        if getattr(cfg, 'enable_http_headers_test', True):
            enabled_categories.add(TestCategory.HTTP_HEADERS)
        if getattr(cfg, 'enable_security_misconfig_test', True):
            enabled_categories.add(TestCategory.SECURITY_MISCONFIG)
        if getattr(cfg, 'enable_version_disclosure_test', True):
            enabled_categories.add(TestCategory.VERSION_DISCLOSURE)
        if getattr(cfg, 'enable_mass_assignment_test', True):
            enabled_categories.add(TestCategory.MASS_ASSIGNMENT)
        if getattr(cfg, 'enable_graphql_test', True):
            enabled_categories.add(TestCategory.GRAPHQL)
        if getattr(cfg, 'enable_spring_boot_actuator_test', True):
            enabled_categories.add(TestCategory.SPRING_BOOT_ACTUATOR)
        if getattr(cfg, 'enable_xss_reflected_test', True):
            enabled_categories.add(TestCategory.XSS_REFLECTED)
        if getattr(cfg, 'enable_csrf_test', True):
            enabled_categories.add(TestCategory.CSRF)
        if getattr(cfg, 'enable_session_fixation_test', True):
            enabled_categories.add(TestCategory.SESSION_FIXATION)
        if getattr(cfg, 'enable_cloud_config_test', True):
            enabled_categories.add(TestCategory.CLOUD_CONFIG)
        if getattr(cfg, 'enable_devops_config_test', True):
            enabled_categories.add(TestCategory.DEV_OPS_CONFIG)
        
        vuln_count = 0
        test_stats = {
            'total_tests': 0,
            'skipped_tests': 0,
            'vulnerabilities_found': 0,
            'by_category': {}
        }
        
        from .models import Severity
        
        method_mapping = {
            TestCategory.SQL_INJECTION: 'test_sql_injection',
            TestCategory.XSS: 'test_xss',
            TestCategory.COMMAND_INJECTION: 'test_command_injection',
            TestCategory.SSRF: 'test_ssrf',
            TestCategory.IDOR: '_test_idor_endpoint',
            TestCategory.BOLA: '_test_idor_endpoint',
            TestCategory.CORS: 'test_cors_misconfiguration',
            TestCategory.CRLF: 'test_crlf_injection',
            TestCategory.LFI: 'test_lfi',
            TestCategory.SSTI: 'test_ssti',
            TestCategory.VERBOSE_ERROR: 'test_verbose_error',
            TestCategory.AUTH_BYPASS: 'test_unauthorized_access',
            TestCategory.JWT_SECURITY: 'test_jwt_security',
            TestCategory.RATE_LIMIT: 'test_rate_limiting',
            TestCategory.INFORMATION_DISCLOSURE: 'test_information_disclosure',
            TestCategory.BFLA: 'test_bfla',
            TestCategory.INJECTION_ATTACKS: 'test_injection_attacks',
            TestCategory.INPUT_VALIDATION: 'test_input_validation',
            TestCategory.HTTP_HEADERS: 'test_http_headers',
            TestCategory.SECURITY_MISCONFIG: 'test_security_misconfig',
            TestCategory.VERSION_DISCLOSURE: 'test_version_disclosure',
            TestCategory.MASS_ASSIGNMENT: 'test_mass_assignment',
            TestCategory.GRAPHQL: 'test_graphql_security',
            TestCategory.SPRING_BOOT_ACTUATOR: 'test_spring_boot_actuator',
            TestCategory.XSS_REFLECTED: 'test_xss_reflected',
            TestCategory.CSRF: 'test_csrf',
            TestCategory.SESSION_FIXATION: 'test_session_fixation',
            TestCategory.CLOUD_CONFIG: 'test_cloud_config_exposure',
            TestCategory.DEV_OPS_CONFIG: 'test_devops_config_exposure',
        }
        
        for endpoint in high_value_apis:
            try:
                features = analyzer.analyze(
                    path=endpoint.path,
                    method=endpoint.method,
                    parameters=endpoint.parameters if hasattr(endpoint, 'parameters') else None
                )
                
                should_test, reason = traffic_analyzer.should_test_endpoint(
                    endpoint.path, endpoint.method
                )
                
                if not should_test:
                    logger.debug(f"Skipping {endpoint.path}: {reason}")
                    continue
                
                selections = selector.select_tests(features, enabled_categories)
                
                logger.debug(f"Endpoint {endpoint.path}: selected {len(selections)} tests")
                
                for selection in selections:
                    test_stats['total_tests'] += 1
                    category = selection.test_category
                    
                    if category not in test_stats['by_category']:
                        test_stats['by_category'][category.value] = {
                            'tests': 0,
                            'vulnerabilities': 0
                        }
                    test_stats['by_category'][category.value]['tests'] += 1
                    
                    try:
                        result = await self._execute_smart_test(
                            endpoint, selection, features
                        )
                        
                        if result and result.is_vulnerable:
                            vuln_count += 1
                            test_stats['vulnerabilities_found'] += 1
                            test_stats['by_category'][category.value]['vulnerabilities'] += 1
                            
                            from .models import Vulnerability
                            vuln = Vulnerability(
                                api_id=endpoint.api_id,
                                vuln_type=result.vuln_type.value if hasattr(result.vuln_type, 'value') else str(result.vuln_type),
                                severity=Severity[result.severity.upper()] if isinstance(result.severity, str) else result.severity,
                                evidence=result.evidence,
                                payload=result.payload,
                                remediation=result.remediation,
                                cwe_id=result.cwe_id
                            )
                            if self.result:
                                self.result.vulnerabilities.append(vuln)
                            
                            if self._realtime_output:
                                severity_str = result.severity.upper() if isinstance(result.severity, str) else 'medium'
                                self._realtime_output.output_vulnerability(
                                    vuln_type=result.vuln_type.value if hasattr(result.vuln_type, 'value') else str(result.vuln_type),
                                    endpoint=endpoint.full_url,
                                    severity=severity_str,
                                    details=result.evidence[:200] if result.evidence else '',
                                    payload=result.payload
                                )
                    except Exception as e:
                        logger.debug(f"Test {selection.test_name} failed for {endpoint.path}: {e}")
            except Exception as e:
                logger.warning(f"Vulnerability test error for endpoint {endpoint.api_id}: {e}")
        
        logger.info(f"Smart vulnerability testing completed: {test_stats['total_tests']} tests executed, {vuln_count} vulnerabilities found")
        
        return {
            'vuln_count': vuln_count,
            'vulnerabilities': [v.to_dict() for v in self.result.vulnerabilities] if self.result else [],
            'test_stats': test_stats
        }
    
    async def _execute_smart_test(self, endpoint, selection, features):
        """执行智能选择的测试"""
        from .analyzers import TestCategory
        
        category = selection.test_category
        param_name = selection.param_name
        
        if self._vulnerability_tester is None:
            return None
        
        if category == TestCategory.SQL_INJECTION:
            return await self._vulnerability_tester.test_sql_injection(
                endpoint.full_url, 
                endpoint.method,
                param_name or 'q'
            )
        elif category == TestCategory.XSS:
            return await self._vulnerability_tester.test_xss(
                endpoint.full_url,
                endpoint.method,
                param_name or 'q'
            )
        elif category == TestCategory.COMMAND_INJECTION:
            return await self._vulnerability_tester.test_command_injection(
                endpoint.full_url,
                param_name or 'q'
            )
        elif category == TestCategory.SSRF:
            return await self._vulnerability_tester.test_ssrf(endpoint.full_url)
        elif category in [TestCategory.IDOR, TestCategory.BOLA]:
            return await self._test_idor_smart(endpoint, features)
        elif category == TestCategory.CORS:
            return await self._vulnerability_tester.test_cors_misconfiguration(endpoint.full_url)
        elif category == TestCategory.CRLF:
            return await self._vulnerability_tester.test_crlf_injection(
                endpoint.full_url,
                param_name or 'q'
            )
        elif category == TestCategory.LFI:
            return await self._vulnerability_tester.test_lfi(
                endpoint.full_url,
                param_name or 'file'
            )
        elif category == TestCategory.SSTI:
            return await self._vulnerability_tester.test_ssti(
                endpoint.full_url,
                param_name or 'q'
            )
        elif category == TestCategory.VERBOSE_ERROR:
            return await self._vulnerability_tester.test_verbose_error(
                endpoint.full_url,
                param_name or 'q'
            )
        elif category == TestCategory.AUTH_BYPASS:
            return await self._vulnerability_tester.test_unauthorized_access(
                endpoint.full_url,
                endpoint.method
            )
        elif category == TestCategory.JWT_SECURITY:
            return await self._vulnerability_tester.test_jwt_security(endpoint.full_url, token='')
        elif category == TestCategory.RATE_LIMIT:
            return await self._vulnerability_tester.test_bypass_techniques(
                endpoint.full_url,
                endpoint.method
            )
        elif category == TestCategory.INFORMATION_DISCLOSURE:
            return await self._vulnerability_tester.test_information_disclosure(endpoint.full_url)
        elif category == TestCategory.BFLA:
            return await self._vulnerability_tester.test_bfla(
                endpoint.full_url,
                endpoint.method
            )
        elif category == TestCategory.INJECTION_ATTACKS:
            return await self._vulnerability_tester.test_injection_attacks(
                endpoint.full_url,
                param_name or 'q'
            )
        elif category == TestCategory.INPUT_VALIDATION:
            return await self._vulnerability_tester.test_input_validation(
                endpoint.full_url,
                param_name or 'q'
            )
        elif category == TestCategory.HTTP_HEADERS:
            return await self._vulnerability_tester.test_http_headers(endpoint.full_url)
        elif category == TestCategory.SECURITY_MISCONFIG:
            return await self._vulnerability_tester.test_security_misconfig(endpoint.full_url)
        elif category == TestCategory.VERSION_DISCLOSURE:
            return await self._vulnerability_tester.test_version_disclosure(endpoint.full_url)
        elif category == TestCategory.MASS_ASSIGNMENT:
            return await self._vulnerability_tester.test_mass_assignment(
                endpoint.full_url,
                endpoint.method
            )
        elif category == TestCategory.GRAPHQL:
            return await self._vulnerability_tester.test_graphql_security(endpoint.full_url)
        elif category == TestCategory.SPRING_BOOT_ACTUATOR:
            return await self._vulnerability_tester.test_spring_boot_actuator(endpoint.full_url)
        elif category == TestCategory.XSS_REFLECTED:
            return await self._vulnerability_tester.test_xss_reflected(
                endpoint.full_url,
                param_name or 'q'
            )
        elif category == TestCategory.CSRF:
            return await self._vulnerability_tester.test_csrf(
                endpoint.full_url,
                endpoint.method
            )
        elif category == TestCategory.SESSION_FIXATION:
            return await self._vulnerability_tester.test_session_fixation(endpoint.full_url)
        elif category == TestCategory.CLOUD_CONFIG:
            return await self._vulnerability_tester.test_cloud_config_exposure(endpoint.full_url)
        elif category == TestCategory.DEV_OPS_CONFIG:
            return await self._vulnerability_tester.test_devops_config_exposure(endpoint.full_url)
        
        return None
    
    async def _test_idor_smart(self, endpoint, features):
        """智能IDOR测试"""
        from .analyzers import EndpointFeature
        
        idor_params = {}
        if hasattr(endpoint, 'parameters') and endpoint.parameters:
            if isinstance(endpoint.parameters, list):
                for param in endpoint.parameters:
                    if isinstance(param, dict) and param.get('name'):
                        idor_params[param['name']] = param.get('default', param.get('example', 'test'))
                    elif isinstance(param, str):
                        idor_params[param] = 'test'
            elif isinstance(endpoint.parameters, dict):
                for k, v in endpoint.parameters.items():
                    idor_params[k] = v
        
        if features.has_feature(EndpointFeature.HAS_ID_PARAM):
            for param in features.param_names:
                if 'id' in param.lower():
                    if param not in idor_params:
                        idor_params[param] = '999999'
                    break
        
        return await self._idor_tester.test_idor(
            url=endpoint.full_url,
            method=endpoint.method,
            params=idor_params if idor_params else None,
            headers={'Cookie': self.config.cookies} if self.config.cookies else None
        )
    
    async def _run_bypass_test(self) -> Dict[str, Any]:
        """
        Bypass 测试 - 尝试绕过 API 访问限制
        
        当 API 返回 401/403/404/500 等状态码时，尝试多种绕过技术：
        - 401: 认证头绕过
        - 403: IP 欺骗、请求头操纵绕过
        - 404: URL 变换绕过
        - 500: Content-Type 绕过
        """
        bypass_count = 0
        bypass_results = []
        
        for endpoint in self.result.api_endpoints if self.result else []:
            try:
                response = await self._http_client.request(  # type: ignore[reportOptionalMemberAccess]
                    endpoint.full_url,
                    method=endpoint.method,
                    headers={'Cookie': self.config.cookies} if self.config.cookies else None
                )
                
                original_status = response.status_code if response else None
                
                if original_status in [401, 403, 404, 405, 500, 502, 503]:
                    bypass_findings = await self._bypass_tester.test_bypass(
                        url=endpoint.full_url,
                        method=endpoint.method,
                        original_status=original_status,
                        headers={'Cookie': self.config.cookies} if self.config.cookies else {}
                    )
                    
                    for finding in bypass_findings:
                        bypass_count += 1
                        bypass_results.append({
                            'endpoint': endpoint.full_url,
                            'method': endpoint.method,
                            'original_status': finding.original_status,
                            'bypassed_status': finding.bypassed_status,
                            'technique': finding.technique,
                            'category': finding.category,
                            'details': finding.details
                        })
                        
                        if finding.bypassed and self.result:
                            endpoint_bypass = {
                                'api_id': endpoint.api_id,
                                'vuln_type': 'bypass',
                                'severity': 'medium',
                                'evidence': f"Bypassed with {finding.technique}",
                                'payload': finding.technique,
                                'remediation': f"Block bypass techniques: {finding.category}"
                            }
                            from .models import Vulnerability
                            vuln = Vulnerability(
                                api_id=endpoint.api_id,
                                vuln_type='bypass',
                                severity=Severity.MEDIUM,
                                evidence=finding.details,
                                payload=finding.technique,
                                remediation=f"Implement bypass protection for {finding.category} techniques"
                            )
                            self.result.vulnerabilities.append(vuln)
                            
                            if self._realtime_output:
                                severity_str = Severity.MEDIUM.value if hasattr(Severity.MEDIUM, 'value') else 'medium'
                                self._realtime_output.output_vulnerability(
                                    vuln_type='bypass',
                                    endpoint=endpoint.full_url,
                                    severity=severity_str,
                                    details=finding.details,
                                    payload=finding.technique
                                )
                            
            except Exception as e:
                logger.debug(f"Bypass test error for {endpoint.full_url}: {e}")
        
        logger.info(f"Bypass testing completed: {bypass_count} bypasses found")
        
        return {
            'bypass_count': bypass_count,
            'bypass_results': bypass_results
        }
    
    async def _verify_apis_for_report(self):
        """API验证阶段 - 验证有效JSON响应和唯一内容"""
        if not self.result or not self.result.api_endpoints:
            return
        
        try:
            from .collectors.api_verifier import APIVerifier
            
            api_paths = [ep.path for ep in self.result.api_endpoints]
            
            if not api_paths:
                return
            
            verifier = APIVerifier(
                http_client=self._http_client,
                base_url=self.config.target,
                timeout=10.0,
                cookies=self.config.cookies
            )
            
            verification_result = await verifier.verify_apis(api_paths)
            
            self.result.statistics['api_verification'] = verification_result.to_dict()
            
            extracted_from_verification = []
            for verified_api in verification_result.valid_json_apis + verification_result.sensitive_apis:
                if hasattr(verified_api, 'extracted_urls') and verified_api.extracted_urls:
                    extracted_from_verification.extend(verified_api.extracted_urls)
            
            if extracted_from_verification:
                logger.info(f"[Discovery] 从验证阶段提取到 {len(extracted_from_verification)} 个新路径")
                for new_path in set(extracted_from_verification):
                    if new_path not in existing_paths if 'existing_paths' in dir() else True:
                        logger.info(f"  -> 发现新路径: {new_path}")
            
            output_mgr = self._output_manager if hasattr(self, '_output_manager') else None
            results_base = output_mgr.results_dir if output_mgr else self.config.output_dir
            
            verifier.save_results(verification_result, results_base)
            
            verifier.print_categorized_results(verification_result)
            
            logger.info(
                f"[API Verifier] 验证完成: 总API={verification_result.total_apis}, "
                f"有效JSON={len(verification_result.valid_json_apis)}, "
                f"唯一内容={len(verification_result.unique_content_apis)}"
            )
            
        except Exception as e:
            logger.debug(f"API verification error: {e}")
    
    async def _stage_reporting(self):
        """报告生成阶段"""
        if not self.file_storage or not self.result:
            return
        
        await self._verify_apis_for_report()
        
        scan_dict = self.result.to_dict()
        
        if hasattr(self, '_flux_results') and self._flux_results:
            scan_dict['flux_enhanced'] = {
                'fingerprints': self._flux_results.get('fingerprints', []),
                'waf_detected': self._flux_results.get('waf_detected'),
                'sensitive_data': self._flux_results.get('flux_sensitive', []),
                'ai_security': self._flux_results.get('ai_findings', []),
                'k8s_security': self._flux_results.get('k8s_findings', []),
                'container_security': self._flux_results.get('container_findings', []),
                'cicd_security': self._flux_results.get('cicd_findings', []),
                'cloud_security': self._flux_results.get('cloud_findings', []),
                'endpoint_fusion': self._flux_results.get('fusion_endpoints', {}),
                'prioritized_vulns': self._flux_results.get('prioritized_vulns', []),
            }
            logger.info(f"[FLUX] 增强数据已合并到报告: {len(self._flux_results.get('fingerprints', []))} 指纹, {len(self._flux_results.get('flux_sensitive', []))} 敏感信息")
        
        try:
            posture_report = analyze_security_posture(
                endpoints=scan_dict.get('api_endpoints', []),
                vulnerabilities=scan_dict.get('vulnerabilities', [])
            )
            scan_dict['security_posture'] = posture_report
            logger.info(f"[Posture] 安全态势评分: {posture_report.get('security_posture', {}).get('overall_score', 0)}")
        except Exception as e:
            logger.debug(f"Security posture analysis skipped: {e}")
        
        self.file_storage.save_json(scan_dict, 'scan_result.json')
        
        output_mgr = self._output_manager if hasattr(self, '_output_manager') else None
        results_base = output_mgr.results_dir if output_mgr else self.config.output_dir
        
        report_exporter = ReportExporter(output_dir=results_base)
        formats = getattr(self.config, 'report_formats', ['json', 'html'])
        
        try:
            report_exporter.export(
                scan_result=scan_dict,
                target=self.result.target_url,
                formats=formats
            )
        except Exception as e:
                logger.error(f"Report export error: {e}")
        
        try:
            attack_chain_exporter = AttackChainExporter()
            html_path = self._output_manager.get_attack_chain_path() if output_mgr else os.path.join(self.config.output_dir, 'attack_chain.html')
            if self.result:
                endpoints_data = [e.to_dict() if hasattr(e, 'to_dict') else e for e in self.result.api_endpoints]
                endpoints_data_only = [d for d in endpoints_data if isinstance(d, dict)]
                vulns_data = [v.to_dict() if hasattr(v, 'to_dict') else v for v in self.result.vulnerabilities]
                vulns_data_only = [d for d in vulns_data if isinstance(d, dict)]
                chains = attack_chain_exporter.generate_chains(endpoints_data_only, vulns_data_only)
                attack_chain_exporter.generate_html(chains, target=self.config.target)
            logger.info(f"Attack chain report generated: {html_path}")
        except Exception as e:
                logger.error(f"Attack chain export error: {e}")
        
        try:
            from .exporters.report_exporter import FLUXHtmlReporter
            flux_html_path = self._output_manager.get_flux_report_path() if output_mgr else os.path.join(self.config.output_dir, 'flux_report.html')
            flux_reporter = FLUXHtmlReporter()
            flux_reporter.export(scan_dict, flux_html_path)
            logger.info(f"[FLUX] FLUX HTML 报告已生成: {flux_html_path}")
        except Exception as e:
            logger.error(f"FLUX HTML export error: {e}")
    
    async def _save_checkpoint(self):
        """保存检查点"""
        if not self.config.checkpoint_enabled:
            return
        
        discovered_apis = []
        if self.result and self.result.api_endpoints:
            for api in self.result.api_endpoints:
                discovered_apis.append({
                    'path': api.path,
                    'method': api.method,
                    'full_url': api.full_url,
                    'api_id': api.api_id,
                    'is_high_value': api.is_high_value
                })
        
        vulnerabilities = []
        if self.result:
            for vuln in self.result.vulnerabilities:
                vulnerabilities.append({
                    'api_id': vuln.api_id,
                    'vuln_type': vuln.vuln_type,
                    'severity': vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity),
                    'evidence': vuln.evidence,
                    'payload': vuln.payload
                })
        
        self._checkpoint = ScanCheckpoint(
            target=self.config.target,
            current_stage=self.current_stage_name,
            stage_index=self._current_stage,
            collector_results=getattr(self, '_collector_results', {}),
            analyzer_results=getattr(self, '_analyzer_results', {}),
            tester_results=getattr(self, '_tester_results', {}),
            discovered_apis=discovered_apis,
            vulnerabilities=vulnerabilities,
            timestamp=time.time()
        )
    
    async def load_checkpoint(self, checkpoint_path: str) -> bool:
        """加载检查点"""
        if not os.path.exists(checkpoint_path):
            return False
        
        try:
            import json
            with open(checkpoint_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            self._checkpoint = ScanCheckpoint(
                target=data.get('target', ''),
                current_stage=data.get('current_stage', 'collect'),
                stage_index=data.get('stage_index', 0),
                collector_results=data.get('collector_results', {}),
                analyzer_results=data.get('analyzer_results', {}),
                tester_results=data.get('tester_results', {}),
                discovered_apis=data.get('discovered_apis', []),
                vulnerabilities=data.get('vulnerabilities', []),
                timestamp=data.get('timestamp', 0.0)
            )
            return True
        except Exception:
            return False
    
    async def cleanup(self):
        """清理资源"""
        self._running = False
        
        if self._active_tasks:
            try:
                pending = [t for t in self._active_tasks if not t.done()]
                if pending:
                    logger.info(f"Waiting for {len(pending)} tasks to complete...")
                    await asyncio.wait_for(
                        asyncio.shield(asyncio.gather(*pending, return_exceptions=True)),
                        timeout=5.0
                    )
            except asyncio.TimeoutError:
                logger.warning(f"Task wait timeout, cancelling {len(self._active_tasks)} remaining tasks")
                for task in self._active_tasks:
                    if not task.done():
                        task.cancel()
            except Exception as e:
                logger.debug(f"Task cleanup error: {e}")
        
        if self._http_client:
            if self._http_client.session and not self._http_client.session.closed:
                await self._http_client.session.close()
            self._http_client.session = None
        
        if self.db_storage:
            self.db_storage.close()
        
        if self.result:
            self.result.end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            if self.result.start_time and self.result.end_time:
                start = datetime.strptime(self.result.start_time, "%Y-%m-%d %H:%M:%S")
                end = datetime.strptime(self.result.end_time, "%Y-%m-%d %H:%M:%S")
                self.result.duration = (end - start).total_seconds()
    
    def _extract_js_urls(self, html_content: str) -> List[str]:
        """从HTML提取JS URL"""
        import re
        script_pattern = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
        script_pattern_no_quote = re.compile(r'<script[^>]+src=([^\s>]+)', re.IGNORECASE)
        
        urls = script_pattern.findall(html_content)
        if not urls:
            urls = script_pattern_no_quote.findall(html_content)
        return urls
    
    @property
    def is_running(self) -> bool:
        """是否正在运行"""
        return self._running


class CollectorFactory:
    """采集器工厂"""
    
    _collectors: Dict[str, type] = {}
    
    @classmethod
    def register(cls, name: str, collector_class: type):
        """注册采集器"""
        cls._collectors[name] = collector_class
    
    @classmethod
    def create(cls, name: str, config: Dict) -> Any:
        """创建采集器实例"""
        if name not in cls._collectors:
            raise ValueError(f"Collector {name} not registered")
        return cls._collectors[name](**config)
    
    @classmethod
    def listCollectors(cls) -> List[str]:
        """列出所有注册的采集器"""
        return list(cls._collectors.keys())


class AnalyzerFactory:
    """分析器工厂"""
    
    _analyzers: Dict[str, type] = {}
    
    @classmethod
    def register(cls, name: str, analyzer_class: type):
        """注册分析器"""
        cls._analyzers[name] = analyzer_class
    
    @classmethod
    def create(cls, name: str, config: Dict) -> Any:
        """创建分析器实例"""
        if name not in cls._analyzers:
            raise ValueError(f"Analyzer {name} not registered")
        return cls._analyzers[name](**config)
    
    @classmethod
    def listAnalyzers(cls) -> List[str]:
        """列出所有注册的分析器"""
        return list(cls._analyzers.keys())


class TesterFactory:
    """测试器工厂"""
    
    _testers: Dict[str, type] = {}
    
    @classmethod
    def register(cls, name: str, tester_class: type):
        """注册测试器"""
        cls._testers[name] = tester_class
    
    @classmethod
    def create(cls, name: str, config: Dict) -> Any:
        """创建测试器实例"""
        if name not in cls._testers:
            raise ValueError(f"Tester {name} not registered")
        return cls._testers[name](**config)
    
    @classmethod
    def listTesters(cls) -> List[str]:
        """列出所有注册的测试器"""
        return list(cls._testers.keys())


async def run_engine(config: EngineConfig) -> ScanResult:
    """运行扫描引擎的便捷函数"""
    engine = ScanEngine(config)
    return await engine.run()


async def run_multi_target(targets: List[str], base_config: EngineConfig) -> List[ScanResult]:
    """并行扫描多个目标"""
    semaphore = asyncio.Semaphore(getattr(base_config, 'concurrent_targets', 5))
    
    async def scan_with_limit(target: str) -> ScanResult:
        async with semaphore:
            config = EngineConfig(
                target=target,
                collectors=base_config.collectors,
                analyzers=base_config.analyzers,
                testers=base_config.testers,
                ai_enabled=base_config.ai_enabled,
                checkpoint_enabled=base_config.checkpoint_enabled,
                cookies=base_config.cookies,
                concurrency=base_config.concurrency,
                proxy=base_config.proxy,
                js_depth=base_config.js_depth,
                output_dir=base_config.output_dir,
                attack_mode=base_config.attack_mode,
                no_api_scan=base_config.no_api_scan,
                chrome=base_config.chrome,
                verify_ssl=base_config.verify_ssl
            )
            engine = ScanEngine(config)
            return await engine.run()
    
    results = await asyncio.gather(*[scan_with_limit(t) for t in targets], return_exceptions=True)
    
    processed_results = []
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            error_result = ScanResult(
                target_url=targets[i],
                status="failed",
                errors=[str(result)]
            )
            processed_results.append(error_result)
        else:
            processed_results.append(result)
    
    return processed_results


class ScanResultAggregator:
    """扫描结果聚合器"""
    
    def aggregate(self, results: List[ScanResult]) -> Dict[str, Any]:
        """聚合多个扫描结果"""
        high_value_endpoints = self._aggregate_high_value_endpoints(results)
        vulnerability_summary = self._aggregate_vulnerabilities(results)
        
        return {
            'total_targets': len(results),
            'successful_scans': sum(1 for r in results if r.status != "failed" and not r.errors),
            'failed_scans': sum(1 for r in results if r.errors or r.status == "failed"),
            'total_apis': sum(r.total_apis for r in results),
            'alive_apis': sum(r.alive_apis for r in results),
            'high_value_apis': sum(r.high_value_apis for r in results),
            'total_vulnerabilities': sum(len(r.vulnerabilities) for r in results),
            'total_sensitive_data': sum(len(r.sensitive_data) for r in results),
            'high_value_endpoints': high_value_endpoints,
            'vulnerability_summary': vulnerability_summary,
            'target_results': [r.to_dict() for r in results]
        }
    
    def _aggregate_high_value_endpoints(self, results: List[ScanResult]) -> List[Dict[str, Any]]:
        """聚合高价值端点"""
        high_value_endpoints = []
        seen_urls = set()
        
        for result in results:
            for endpoint in result.api_endpoints:
                if endpoint.is_high_value and endpoint.full_url not in seen_urls:
                    seen_urls.add(endpoint.full_url)
                    high_value_endpoints.append({
                        'target': result.target_url,
                        'path': endpoint.path,
                        'method': endpoint.method,
                        'full_url': endpoint.full_url,
                        'api_id': endpoint.api_id
                    })
        
        return high_value_endpoints[:50]
    
    def _aggregate_vulnerabilities(self, results: List[ScanResult]) -> Dict[str, Any]:
        """聚合漏洞信息"""
        vuln_by_type: Dict[str, int] = {}
        vuln_by_severity: Dict[str, int] = {}
        vuln_by_target: Dict[str, List[str]] = {}
        
        for result in results:
            for vuln in result.vulnerabilities:
                vuln_type = vuln.vuln_type
                severity = vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity)
                
                vuln_by_type[vuln_type] = vuln_by_type.get(vuln_type, 0) + 1
                vuln_by_severity[severity] = vuln_by_severity.get(severity, 0) + 1
                
                if result.target_url not in vuln_by_target:
                    vuln_by_target[result.target_url] = []
                vuln_by_target[result.target_url].append(vuln_type)
        
        return {
            'by_type': vuln_by_type,
            'by_severity': vuln_by_severity,
            'by_target': vuln_by_target
        }
