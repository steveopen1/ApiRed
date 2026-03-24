"""
ScanEngine - 统一扫描引擎
提供Collector → Analyzer → Tester的标准化流程
"""

import asyncio
import time
import os
import re
import logging
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

from .utils.config import Config
from .storage import DBStorage, FileStorage
from .collectors import JSFingerprintCache, JSParser, APIAggregator, HeadlessBrowserCollector
from .collectors.api_collector import APIPathCombiner, ServiceAnalyzer
from .collectors.js_ast_analyzer import JavaScriptASTAnalyzer
from .analyzers import APIScorer, APIEvidenceAggregator, ResponseCluster, TwoTierSensitiveDetector
from .analyzers.response_baseline import ResponseBaselineLearner
from .testers import FuzzTester, VulnerabilityTester
from .testers.idor_tester import IDORTester
from .utils.url_greper import URLGreper
from .agents import ScannerAgent, AnalyzerAgent, TesterAgent, AgentConfig
from .agents import Orchestrator, DiscoverAgent, TestAgent, ReflectAgent
from .agents.orchestrator import ScanContext
from .knowledge_base import KnowledgeBase
from .models import ScanResult, APIEndpoint
from .framework import FrameworkDetector
from .exporters import ReportExporter, OpenAPIExporter, AttackChainExporter


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
        self._vulnerability_tester: Optional[VulnerabilityTester] = None
        
        self.scanner_agent: Optional[ScannerAgent] = None
        self.analyzer_agent: Optional[AnalyzerAgent] = None
        self.tester_agent: Optional[TesterAgent] = None
        
        self._orchestrator: Optional[Orchestrator] = None
        self._knowledge_base: Optional[KnowledgeBase] = None
        
        self.result: Optional[ScanResult] = None
        self._current_stage = 0
        self._running = False
        self._checkpoint: Optional[ScanCheckpoint] = None
        self._collector_results: Dict[str, Any] = {}
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
        folder_name = self.config.target.replace('://', '_').replace('/', '_').replace('.', '_')
        results_dir = os.path.join(self.config.output_dir, folder_name)
        
        if not os.path.exists(results_dir):
            os.makedirs(results_dir, exist_ok=True)
        
        self.db_storage = DBStorage(
            db_path=os.path.join(results_dir, "results.db"),
            wal_mode=True
        )
        
        self.file_storage = FileStorage(base_dir=results_dir)
        
        from .utils.http_client import AsyncHttpClient
        self._http_client = AsyncHttpClient(
            max_concurrent=self.config.concurrency,
            max_retries=3,
            timeout=30,
            proxy=self.config.proxy,
            verify_ssl=getattr(self.config, 'verify_ssl', True)
        )
        
        self._js_cache = JSFingerprintCache(self.db_storage)
        self._api_aggregator = APIAggregator()
        self._api_scorer = APIScorer(
            min_high_value_score=self.cfg.get('ai.thresholds.high_value_api_score', 5)
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
        self._vulnerability_tester = VulnerabilityTester(self._http_client)
        self._idor_tester = IDORTester(self._http_client)
        self._url_greper = URLGreper()
        
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
                    browser_initialized = await self._browser_collector.initialize(headless=True)
                    
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
        
        if self.config.ai_enabled:
            from .ai.ai_engine import AIEngine
            llm_client = AIEngine()
            scanner_config = AgentConfig(name="ScannerAgent")
            analyzer_config = AgentConfig(name="AnalyzerAgent")
            tester_config = AgentConfig(name="TesterAgent")
            self.scanner_agent = ScannerAgent(scanner_config, llm_client)
            self.analyzer_agent = AnalyzerAgent(analyzer_config, llm_client)
            self.tester_agent = TesterAgent(tester_config, llm_client)
        
        self._incremental_scanner = None
        self._url_deduplicator = None
        if getattr(self.config, 'resume', False) or getattr(self.config, 'incremental', False):
            storage_path = os.path.join(results_dir, "incremental.db")
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
    
    async def run(self) -> ScanResult:
        """运行扫描流程"""
        agent_mode = getattr(self.config, 'agent_mode', False)
        
        if agent_mode:
            return await self._run_agent_mode()
        
        await self.initialize()
        
        attack_mode = getattr(self.config, 'attack_mode', 'all')
        no_api_scan = getattr(self.config, 'no_api_scan', False)
        
        self._emit('stage_start', {'stage': 'initialization', 'status': 'complete'})
        
        try:
            if attack_mode in ['collect', 'all']:
                await self._run_collectors()
                if self.config.checkpoint_enabled:
                    await self._save_checkpoint()
                self._emit('stage_complete', {'stage': 'collect', 'status': 'complete'})
            
            if attack_mode in ['scan', 'all'] and not no_api_scan:
                await self._run_analyzers()
                if self.config.checkpoint_enabled:
                    await self._save_checkpoint()
                self._emit('stage_complete', {'stage': 'analyze', 'status': 'complete'})
                
                await self._run_testers()
                if self.config.checkpoint_enabled:
                    await self._save_checkpoint()
                self._emit('stage_complete', {'stage': 'test', 'status': 'complete'})
            
            await self._stage_reporting()
            self._emit('stage_complete', {'stage': 'reporting', 'status': 'complete'})
            
            if self.result:
                self.result.status = "completed"
        
        except Exception as e:
            if self.result:
                self.result.errors.append(str(e))
                self.result.status = "failed"
            self._emit('error', {'error': str(e)})
        
        finally:
            await self.cleanup()
        
        return self.result
    
    async def _run_agent_mode(self) -> ScanResult:
        """使用 Agent 系统运行扫描"""
        from .agents.orchestrator import check_ai_config, print_ai_config_guide
        
        missing_config = check_ai_config()
        if missing_config:
            print_ai_config_guide()
            logger.warning(f"错误: Agent 模式需要配置 AI API 密钥")
            logger.warning(f"缺少: {', '.join(missing_config.keys())}")
            logger.info("提示: 也可以使用传统模式，无需配置 AI:")
            logger.info(f"  python main.py scan -u {self.config.target}")
            
            self.result = ScanResult(
                target_url=self.config.target,
                start_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                status="failed",
                errors=["AI API key not configured"]
            )
            return self.result
        
        self._knowledge_base = KnowledgeBase.get_instance(self.config.target)
        
        context = ScanContext(
            target=self.config.target,
            cookies=self.config.cookies or "",
            concurrency=self.config.concurrency,
            ai_enabled=self.config.ai_enabled,
            knowledge_base=self._knowledge_base
        )
        
        self._orchestrator = Orchestrator(context)
        self._orchestrator.register_agent(DiscoverAgent())
        self._orchestrator.register_agent(TestAgent())
        self._orchestrator.register_agent(ReflectAgent())
        
        self.result = ScanResult(
            target_url=self.config.target,
            start_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        
        self._emit('stage_start', {'stage': 'agent_mode', 'status': 'running'})
        
        try:
            task_definitions = [
                {'agent': 'discover', 'task_type': 'js_collect', 'params': {'depth': self.config.js_depth}},
                {'agent': 'test', 'task_type': 'vuln_test', 'params': {}},
                {'agent': 'reflect', 'task_type': 'analysis', 'params': {}},
            ]
            
            result = await self._orchestrator.run(task_definitions)
            
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
    
    async def _run_collectors(self):
        """运行采集阶段"""
        self._current_stage = 0
        
        active_collectors = self.config.collectors or ['js', 'api']
        
        collector_results = {}
        
        if 'js' in active_collectors:
            collector_results['js'] = await self._collect_js()
        
        self._collector_results = collector_results
        
        if 'api' in active_collectors:
            collector_results['api'] = await self._extract_apis()
        
        self._collector_results = collector_results
    
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
        response_discovery = ResponseBasedAPIDiscovery()
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
        
        response = await self._http_client.request(
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
                    js_response = await self._http_client.request(absolute_js_url)
                    if js_response.status_code == 200:
                        js_content = js_response.content
                        js_content_all += js_content + "\n"
                        alive_js.append({'url': js_url, 'content': js_content})
                        
                        inline_parser.parse_html(js_content)
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
            'env_configs': dict(env_configs)
        }
    
    async def _collect_with_browser(self) -> Optional[Dict[str, Any]]:
        """使用无头浏览器采集 JS 和 API"""
        if not self._browser_collector:
            return None
        
        js_urls = []
        api_endpoints = []
        spa_routes = []
        alive_js = []
        
        try:
            await self._browser_collector.navigate(self.config.target)
            await self._browser_collector.scroll_page()
            
            page_content = await self._browser_collector.collect_page_content()
            
            js_urls = page_content.get('js_files', [])
            api_endpoints = page_content.get('api_endpoints', [])
            spa_routes = page_content.get('routes', [])
            
            for js_url in js_urls:
                try:
                    js_response = await self._http_client.request(js_url)
                    if js_response.status_code == 200:
                        alive_js.append({
                            'url': js_url,
                            'content': js_response.content
                        })
                except Exception as e:
                    logger.debug(f"Browser JS request error: {e}")
        except Exception as e:
            logger.warning(f"Browser collection error: {e}")
        
        return {
            'js_urls': js_urls,
            'alive_js': alive_js,
            'spa_routes': spa_routes,
            'browser_apis': api_endpoints,
            'detected_framework': self._detected_framework
        }
    
    COMMON_API_PATHS = [
        'add', 'ls', 'focus', 'calc', 'download', 'bind', 'execute',
        'logininfo', 'create', 'decrypt', 'new', 'update', 'click',
        'shell', 'export', 'menu', 'retrieve', 'on', 'message', 'admin',
        'calculate', 'append', 'check', 'crypt', 'rename', 'exec', 'detail',
        'clone', 'query', 'verify', 'is', 'authenticate', 'move', 'toggle',
        'make', 'modify', 'upload', 'help', 'demo', 'with', 'alert', 'mode',
        'gen', 'msg', 'edit', 'vrfy', 'enable', 'run', 'open', 'post',
        'proxy', 'subtract', 'initiate', 'read', 'encrypt', 'auth', 'snd',
        'view', 'save', 'config', 'get', 'alter', 'forceLogout', 'build',
        'list', 'show', 'online', 'test', 'pull', 'notice', 'change',
        'put', 'to', 'status', 'search', 'mod', '0', 'send', 'load',
        'login', 'logout', 'register', 'info', 'detail', 'delete', 'remove',
        'insert', 'select', 'update', 'user', 'users', 'order', 'orders',
        'product', 'products', 'goods', 'item', 'items', 'category', 'cart',
        'shop', 'payment', 'account', 'profile', 'setting', 'settings',
        'dashboard', 'home', 'index', 'about', 'contact', 'service',
        'news', 'article', 'blog', 'comment', 'file', 'files', 'upload',
        'download', 'image', 'images', 'video', 'videos', 'audio',
    ]

    RESTFUL_SUFFIXES = [
        '', '/', '/list', '/page', '/all', '/count', '/total', '/sum',
        '/add', '/create', '/new', '/edit', '/update', '/modify', '/save',
        '/delete', '/remove', '/del', '/batch', '/batchAdd', '/batchUpdate', '/batchDelete',
        '/detail', '/info', '/get', '/show', '/find', '/fetch', '/load',
        '/enable', '/disable', '/toggle', '/status', '/state',
        '/config', '/configuration', '/settings', '/preferences', '/params',
        '/export', '/exportExcel', '/exportCsv', '/import', '/importExcel', '/upload', '/download',
        '/search', '/query', '/filter', '/sort', '/order', '/page', '/pagination',
        '/listJsonData', '/listData', '/listAll', '/json', '/xml', '/tree', '/treeData', '/treeList',
        '/options', '/select', '/combo', '/combobox', '/autocomplete', '/suggest',
        '/submit', '/reset', '/init', '/initialize', '/refresh', '/reload', '/sync', '/merge',
        '/login', '/logout', '/register', '/signup', '/signin', '/signout', '/resetPwd', '/forgotPwd',
        '/auth', '/authorize', '/token', '/refreshToken', '/verify', '/validate', '/captcha',
        '/menu', '/nav', '/navigation', '/sidebar', '/routes', '/permissions', '/access',
        '/permission', '/permissions', '/perms', '/role', '/roles', '/roleId', '/roleName',
        '/user', '/users', '/userList', '/userInfo', '/profile', '/account', '/current', '/own',
        '/dashboard', '/home', '/index', '/welcome', '/main', '/console', '/workspace',
        '/log', '/logs', '/logging', '/audit', '/history', '/record', '/records', '/track',
        '/stat', '/stats', '/statistics', '/analytics', '/report', '/reports', '/summary',
        '/dict', '/dicts', '/dictionary', '/enum', '/enums', '/constants', '/configs',
        '/area', '/region', '/province', '/city', '/district', '/street', '/address',
        '/org', '/organization', '/orgId', '/dept', '/department', '/deptId', '/company',
        '/category', '/categories', '/catalog', '/type', '/types', '/kind', '/class',
        '/tag', '/tags', '/label', '/labels', '/classify', '/group', '/groups',
        '/attachment', '/attachments', '/file', '/files', '/document', '/documents', '/doc',
        '/image', '/images', '/img', '/pictures', '/picture', '/photo', '/photos', '/avatar',
        '/video', '/videos', '/audio', '/media', '/uploads', '/resource', '/resources',
        '/comment', '/comments', '/reply', '/replies', '/message', '/messages', '/msg',
        '/notice', '/notices', '/notification', '/notifications', '/notify', '/alert', '/alerts', '/announce',
        '/news', '/article', '/articles', '/blog', '/post', '/posts', '/topic', '/topics',
        '/product', '/products', '/goods', '/item', '/items', '/sku', '/merchandise',
        '/order', '/orders', '/orderId', '/cart', '/shop', '/store', '/payment', '/transaction', '/trans',
        '/invoice', '/refund', '/return', '/exchange', '/coupon', '/promo', '/discount',
        '/workflow', '/process', '/processId', '/task', '/tasks', '/taskId', '/approve', '/approval', '/reject',
        '/schedule', '/calendar', '/booking', '/appointment', '/reservation', '/resourceId',
        '/validate', '/validation', '/verify', '/verification', '/check', '/inspect', '/test',
        '/loginLog', '/operationLog', '/accessLog', '/errorLog', '/trace', '/debug',
        '/excel', '/pdf', '/csv', '/zip', '/tar', '/archive', '/backup', '/restore',
        '/copy', '/move', '/rename', '/share', '/link', '/unlink', '/bind', '/unbind',
        '/logininfo', '/loginlog', '/logoutinfo', '/online', '/onlineUsers', '/active',
        '/build', '/compile', '/deploy', '/publish', '/release', '/version', '/versions',
    ]

    FUZZ_SUFFIXES = [
        'List', 'ListJson', 'ListJsonData', 'ListData', 'ListAll', 'ListByPage', 'ListPage',
        'GetList', 'GetAll', 'GetPage', 'GetById', 'GetByCode', 'GetByName', 'GetInfo', 'GetDetail',
        'Save', 'SaveOrUpdate', 'Update', 'Add', 'Create', 'Delete', 'Remove', 'BatchDelete',
        'JsonData', 'Json', 'TreeList', 'TreeData', 'Tree', 'Select', 'SelectById',
        'Combo', 'ComboData', 'ComboBox', 'Option', 'Options', 'Autocomplete', 'Suggest',
        'Export', 'ExportExcel', 'Import', 'ImportExcel', 'Download', 'Upload',
        'Page', 'PageData', 'PageList', 'PageJson', 'Pagination', 'Query',
        'Count', 'Total', 'Sum', 'Stat', 'Statistics', 'Summary', 'Analytics',
        'Info', 'Detail', 'Details', 'View', 'Show', 'Fetch', 'Load', 'Get',
        'Login', 'Logout', 'Register', 'Signin', 'Signout', 'ResetPwd', 'ForgotPwd',
        'Auth', 'Token', 'RefreshToken', 'Verify', 'Captcha', 'Validate', 'Validation',
        'Menu', 'Nav', 'NavMenu', 'Routes', 'Permissions', 'Access', 'Permission',
        'User', 'UserList', 'UserInfo', 'UserPage', 'Profile', 'Account', 'Current',
        'Role', 'RoleList', 'RoleInfo', 'Dept', 'DeptList', 'Org', 'OrgList',
        'Product', 'ProductList', 'Order', 'OrderList', 'Category', 'CategoryList',
        'Config', 'ConfigList', 'Settings', 'Dict', 'DictList', 'Enum', 'EnumList',
        'Log', 'LogList', 'LogPage', 'Audit', 'History', 'Record', 'Records',
        'Article', 'ArticleList', 'News', 'NewsList', 'Comment', 'CommentList',
        'File', 'FileList', 'Image', 'ImageList', 'Video', 'VideoList',
        'Notice', 'NoticeList', 'Notification', 'Notify', 'Alert', 'Message', 'Msg',
        'Search', 'Query', 'Filter', 'Sort', 'Order', 'Export', 'Import',
        'Enable', 'Disable', 'Toggle', 'Status', 'State', 'Check', 'Verify',
        'Submit', 'Reset', 'Init', 'Initialize', 'Refresh', 'Reload', 'Sync', 'Merge',
        'Approve', 'Reject', 'Process', 'Task', 'Schedule', 'Booking', 'Appointment',
        'Customer', 'Supplier', 'Employee', 'Member', 'Partner', 'Admin',
    ]

    PATH_FRAGMENTS = [
        'user', 'users', 'userinfo', 'userlist', 'userpage', 'profile', 'account',
        'order', 'orders', 'orderdetail', 'orderlist', 'cart', 'payment', 'transaction',
        'product', 'products', 'productlist', 'goods', 'item', 'items', 'sku', 'merchandise',
        'role', 'roles', 'permission', 'permissions', 'menu', 'menus', 'resource', 'resources',
        'dept', 'depts', 'department', 'departments', 'org', 'orgs', 'organization', 'company',
        'category', 'categories', 'catalog', 'tag', 'tags', 'label', 'labels', 'group', 'groups',
        'config', 'configs', 'configuration', 'settings', 'dict', 'dicts', 'dictionary',
        'admin', 'system', 'auth', 'login', 'logout', 'register', 'captcha', 'validcode',
        'api', 'apis', 'v1', 'v2', 'v3', 'v4', 'rest', 'soap', 'graphql',
        'file', 'files', 'document', 'documents', 'attachment', 'attachments',
        'image', 'images', 'img', 'picture', 'pictures', 'photo', 'photos', 'avatar',
        'video', 'videos', 'audio', 'media', 'upload', 'uploads', 'download',
        'article', 'articles', 'news', 'blog', 'post', 'posts', 'topic', 'topics', 'comment', 'comments',
        'notice', 'notices', 'notification', 'notifications', 'message', 'messages', 'msg',
        'workflow', 'process', 'task', 'tasks', 'schedule', 'calendar', 'booking',
        'area', 'region', 'province', 'city', 'district', 'address', 'location',
        'log', 'logs', 'logging', 'audit', 'history', 'record', 'records', 'track',
        'stat', 'stats', 'statistics', 'analytics', 'report', 'reports', 'summary',
        'customer', 'customers', 'supplier', 'suppliers', 'employee', 'employees', 'member', 'members',
        'invoice', 'refund', 'return', 'exchange', 'coupon', 'promo', 'discount',
        'backup', 'restore', 'export', 'import', 'migrate', 'transfer',
        'dashboard', 'home', 'index', 'main', 'workspace', 'console', 'welcome',
    ]
    
    async def _probe_parent_paths(self, js_results: List) -> Dict[str, Set[str]]:
        """
        探测父路径是否可访问，并进一步探测常见 RESTful 端点、业务后缀和JS路径模板
        
        探测策略:
        1. 父路径 + RESTful 后缀 (/list, /add, /detail 等)
        2. 父路径 + 业务API词 (/user, /order, /product 等)  
        3. 父路径 + JS路径模板片段 (从JS提取的 /users/{id} -> /users)
        4. 父路径 + 资源 + 后缀组合探测 (/admin/role/list)
        5. JS提取的后缀和资源片段进行智能拼接
        
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
        
        if not parent_paths_to_probe:
            return probed_results
        
        logger.info(f"Probing {len(parent_paths_to_probe)} parent paths + {len(path_templates)} templates + {len(js_suffixes)} suffixes + {len(js_resources)} resources...")
        
        if self.config.concurrency_probe:
            probed_results = await self._probe_parent_paths_concurrent(
                base_url, parent_paths_to_probe, path_templates, js_suffixes, js_resources
            )
        else:
            probed_results = await self._probe_parent_paths_serial(
                base_url, parent_paths_to_probe, path_templates, js_suffixes, js_resources
            )
        
        return probed_results
    
    async def _probe_parent_paths_serial(
        self, 
        base_url: str, 
        parent_paths_to_probe: Set[str],
        path_templates: Set[str] = None,
        js_suffixes: Set[str] = None,
        js_resources: Set[str] = None
    ) -> Dict[str, Set[str]]:
        """并发探测父路径（使用 Semaphore 控制并发数）"""
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
        
        semaphore = asyncio.Semaphore(5)
        
        async def try_request(url: str, method: str = 'HEAD') -> Optional[int]:
            try:
                response = await self._http_client.request(url, method=method, timeout=5)
                return response.status_code
            except Exception:
                if method == 'HEAD':
                    return await try_request(url, 'GET')
            return None
        
        async def probe_with_semaphore(parent_path: str) -> Tuple[str, Set[str], int]:
            async with semaphore:
                full_url = base_url + parent_path
                status_code = await try_request(full_url)
                sub_endpoints = set()
                
                if status_code and 200 <= status_code < 400:
                    logger.info(f"Parent path accessible: {parent_path} (status: {status_code})")
                    
                    for suffix in list(all_suffixes)[:100]:
                        sub_path = parent_path.rstrip('/') + suffix if suffix else parent_path
                        sub_url = base_url + sub_path
                        sub_status = await try_request(sub_url)
                        if sub_status and 200 <= sub_status < 400:
                            sub_endpoints.add(sub_path)
                            logger.debug(f"  Found: {sub_path} (status: {sub_status})")
                    
                    for resource in list(js_resources)[:30]:
                        for suffix in list(self.RESTFUL_SUFFIXES)[:20]:
                            combined = f'/{resource}{suffix}' if suffix else f'/{resource}'
                            sub_url = base_url + parent_path.rstrip('/') + combined
                            sub_status = await try_request(sub_url)
                            if sub_status and 200 <= sub_status < 400:
                                sub_endpoints.add(parent_path.rstrip('/') + combined)
                
                elif status_code in (401, 403):
                    logger.info(f"Parent path exists (auth required): {parent_path} (status: {status_code})")
                    
                    for suffix in list(all_suffixes)[:100]:
                        sub_path = parent_path.rstrip('/') + suffix if suffix else parent_path
                        sub_url = base_url + sub_path
                        sub_status = await try_request(sub_url)
                        if sub_status and 200 <= sub_status < 400:
                            sub_endpoints.add(sub_path)
                            logger.debug(f"  Found (auth): {sub_path} (status: {sub_status})")
                    
                    for resource in list(js_resources)[:30]:
                        for suffix in list(self.RESTFUL_SUFFIXES)[:20]:
                            combined = f'/{resource}{suffix}' if suffix else f'/{resource}'
                            sub_url = base_url + parent_path.rstrip('/') + combined
                            sub_status = await try_request(sub_url)
                            if sub_status and 200 <= sub_status < 400:
                                sub_endpoints.add(parent_path.rstrip('/') + combined)
                
                return (parent_path, sub_endpoints, status_code if status_code else 0)
        
        tasks = [probe_with_semaphore(p) for p in parent_paths_to_probe]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, tuple) and len(result) == 3:
                parent_path, sub_endpoints, status_code = result
                if status_code in (200, 401, 403):
                    probed_results[parent_path] = sub_endpoints
        
        return probed_results
    
    async def _probe_parent_paths_concurrent(
        self, 
        base_url: str, 
        parent_paths_to_probe: Set[str],
        path_templates: Set[str] = None,
        js_suffixes: Set[str] = None,
        js_resources: Set[str] = None
    ) -> Dict[str, Set[str]]:
        """并发探测父路径"""
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
        
        async def try_request(url: str, method: str = 'HEAD') -> Optional[int]:
            try:
                response = await self._http_client.request(url, method=method, timeout=5)
                return response.status_code
            except Exception:
                if method == 'HEAD':
                    return await try_request(url, 'GET')
            return None
        
        async def probe_single_path(parent_path: str) -> Tuple[str, Set[str], int]:
            full_url = base_url + parent_path
            sub_endpoints = set()
            status_code = await try_request(full_url)
            
            if status_code and 200 <= status_code < 400:
                logger.info(f"Parent path accessible: {parent_path} (status: {status_code})")
                
                async def probe_sub_path(suffix: str) -> Optional[str]:
                    sub_path = parent_path.rstrip('/') + suffix if suffix else parent_path
                    sub_url = base_url + sub_path
                    sub_status = await try_request(sub_url)
                    if sub_status and 200 <= sub_status < 400:
                        return sub_path
                    return None
                
                sub_tasks = [probe_sub_path(s) for s in list(all_suffixes)[:100]]
                sub_results = await asyncio.gather(*sub_tasks, return_exceptions=True)
                
                for result in sub_results:
                    if result and isinstance(result, str):
                        sub_endpoints.add(result)
                
                for resource in list(js_resources)[:30]:
                    for suffix in list(self.RESTFUL_SUFFIXES)[:20]:
                        combined = f'/{resource}{suffix}' if suffix else f'/{resource}'
                        sub_url = base_url + parent_path.rstrip('/') + combined
                        sub_status = await try_request(sub_url)
                        if sub_status and 200 <= sub_status < 400:
                            sub_endpoints.add(parent_path.rstrip('/') + combined)
            
            elif status_code in (401, 403):
                logger.info(f"Parent path exists (auth required): {parent_path} (status: {status_code})")
                
                async def probe_auth_sub_path(suffix: str) -> Optional[str]:
                    sub_path = parent_path.rstrip('/') + suffix if suffix else parent_path
                    sub_url = base_url + sub_path
                    sub_status = await try_request(sub_url)
                    if sub_status and 200 <= sub_status < 400:
                        return sub_path
                    return None
                
                sub_tasks = [probe_auth_sub_path(s) for s in list(all_suffixes)[:100]]
                sub_results = await asyncio.gather(*sub_tasks, return_exceptions=True)
                
                for result in sub_results:
                    if result and isinstance(result, str):
                        sub_endpoints.add(result)
                
                for resource in list(js_resources)[:30]:
                    for suffix in list(self.RESTFUL_SUFFIXES)[:20]:
                        combined = f'/{resource}{suffix}' if suffix else f'/{resource}'
                        sub_url = base_url + parent_path.rstrip('/') + combined
                        sub_status = await try_request(sub_url)
                        if sub_status and 200 <= sub_status < 400:
                            sub_endpoints.add(parent_path.rstrip('/') + combined)
            
            return (parent_path, sub_endpoints, status_code if status_code else 0)
        
        tasks = [probe_single_path(p) for p in parent_paths_to_probe]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, tuple) and len(result) == 3:
                parent_path, sub_endpoints, status_code = result
                if status_code in (200, 401, 403):
                    probed_results[parent_path] = sub_endpoints
        
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
            parent_clean = parent.rstrip('/')
            if parent_clean in seen_targets:
                continue
            seen_targets.add(parent_clean)
            fuzz_targets.append((parent_clean, ''))
            
            for suffix in js_suffixes:
                if len(fuzz_targets) >= 5000:
                    break
                suffix_clean = suffix.lstrip('/')
                target = f"{parent_clean}/{suffix_clean}"
                if target not in seen_targets and target not in existing_apis:
                    seen_targets.add(target)
                    fuzz_targets.append((parent_clean, f"/{suffix_clean}"))
            
            for resource in js_resources:
                if len(fuzz_targets) >= 5000:
                    break
                resource_clean = resource.lstrip('/')
                target = f"{parent_clean}/{resource_clean}"
                if target not in seen_targets and target not in existing_apis:
                    seen_targets.add(target)
                    fuzz_targets.append((parent_clean, f"/{resource_clean}"))
                
                for rest_suffix in list(self.RESTFUL_SUFFIXES)[:20]:
                    combo = f"{parent_clean}/{resource_clean}/{rest_suffix}"
                    if combo not in seen_targets and combo not in existing_apis:
                        seen_targets.add(combo)
                        fuzz_targets.append((parent_clean, f"/{resource_clean}/{rest_suffix}"))
                        if len(fuzz_targets) >= 5000:
                            break
        
        for api in list(existing_apis)[:200]:
            api_clean = api.rstrip('/')
            if js_params and len(fuzz_targets) < 3000:
                for param in list(js_params)[:10]:
                    param_combo = f"{api_clean}?{param}=1"
                    if param_combo not in seen_targets:
                        seen_targets.add(param_combo)
                        fuzz_targets.append((api_clean, f"?{param}=1"))
                    
                    param_combo2 = f"{api_clean}/{param}/1"
                    if param_combo2 not in seen_targets:
                        seen_targets.add(param_combo2)
                        fuzz_targets.append((api_clean, f"/{param}/1"))
        
        async def probe_target(base: str, suffix: str) -> Optional[Tuple[str, str]]:
            full_url = base_url + base + suffix
            try:
                response = await self._http_client.request(full_url, method='HEAD', timeout=5)
                if response.status_code and 200 <= response.status_code < 400:
                    return (base, suffix)
            except Exception:
                try:
                    response = await self._http_client.request(full_url, method='GET', timeout=5)
                    if response.status_code and 200 <= response.status_code < 400:
                        return (base, suffix)
                except Exception:
                    pass
            return None
        
        batch_size = 50
        for i in range(0, len(fuzz_targets), batch_size):
            batch = fuzz_targets[i:i+batch_size]
            tasks = [probe_target(base, suffix) for base, suffix in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if result and isinstance(result, tuple):
                    parent_path, found_suffix = result
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
        
        async def probe_target(base: str, path: str) -> Optional[str]:
            full_url = base_url + base + path
            try:
                response = await self._http_client.request(full_url, method='HEAD', timeout=5)
                if response.status_code and 200 <= response.status_code < 400:
                    return base + path
            except Exception:
                try:
                    response = await self._http_client.request(full_url, method='GET', timeout=5)
                    if response.status_code and 200 <= response.status_code < 400:
                        return base + path
                except Exception:
                    pass
            return None
        
        batch_size = 50
        for i in range(0, len(fuzz_targets), batch_size):
            batch = fuzz_targets[i:i+batch_size]
            tasks = [probe_target(base, path) for base, path in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if result and isinstance(result, str):
                    fuzzed_results[result] = {'source': 'cross_fuzz'}
        
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
            main_response = await self._http_client.request(self.config.target, timeout=10)
            if main_response and main_response.status_code == 200:
                content = main_response.content
                
                href_pattern = re.compile(r'href=["\']([^"\']+)["\']')
                for match in href_pattern.findall(content):
                    if self._is_valid_path_segment(match):
                        path_segments.add(self._normalize_path_segment(match))
                
                src_pattern = re.compile(r'src=["\']([^"\']+)["\']')
                for match in src_pattern.findall(content):
                    if self._is_valid_path_segment(match):
                        path_segments.add(self._normalize_path_segment(match))
                
                action_pattern = re.compile(r'action=["\']([^"\']+)["\']')
                for match in action_pattern.findall(content):
                    if self._is_valid_path_segment(match):
                        path_segments.add(self._normalize_path_segment(match))
                
                url_pattern = re.compile(r'url:\s*["\']([^"\']+)["\']')
                for match in url_pattern.findall(content):
                    if self._is_valid_path_segment(match):
                        path_segments.add(self._normalize_path_segment(match))
                
                api_url_pattern = re.compile(r'["\'](\/api\/[^"\']+)["\']')
                for match in api_url_pattern.findall(content):
                    if self._is_valid_path_segment(match):
                        path_segments.add(self._normalize_path_segment(match))
                        
        except Exception as e:
            logger.debug(f"Failed to collect from main page: {e}")
        
        try:
            js_urls = await self._extract_all_js_urls()
            for js_url in js_urls:
                try:
                    js_response = await self._http_client.request(js_url, timeout=10)
                    if js_response and js_response.status_code == 200:
                        content = js_response.content
                        
                        api_pattern = re.compile(r'["\'](/[a-zA-Z0-9_/-]+)["\']')
                        for match in api_pattern.findall(content):
                            if self._is_valid_path_segment(match):
                                path_segments.add(self._normalize_path_segment(match))
                        
                        config_pattern = re.compile(r'(?:baseURL|apiUrl|api_base)\s*[:=]\s*["\']([^"\']+)["\']')
                        for match in config_pattern.findall(content):
                            if match.startswith('/'):
                                path_segments.add(self._normalize_path_segment(match))
                        
                        router_pattern = re.compile(r'router(?:\.push|\.replace)\(["\']([^"\']+)["\']')
                        for match in router_pattern.findall(content):
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
            
            tasks = [self._http_client.request(url, timeout=10) for url in current_batch]
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            new_pending = []
            for url, response in zip(current_batch, responses):
                if url in visited_urls:
                    continue
                if response and not isinstance(response, Exception) and hasattr(response, 'status_code') and response.status_code == 200:
                    visited_urls.add(url)
                    all_js_content[url] = response.content
                    
                    new_js_urls = self._extract_js_imports_from_content(response.content)
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
            response = await self._http_client.request(self.config.target, timeout=10)
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
    
    def _generate_cross_fuzz_targets(self, path_segments: set, suffixes: set) -> List[Tuple[str, str]]:
        """
        生成跨来源Fuzzing目标组合
        
        策略:
        1. 路径片段 + RESTful后缀 (/user + /list -> /user/list)
        2. API前缀 + 路径片段 (/api + /users -> /api/users)
        3. 完整路径拼接 (/users + /profile -> /users/profile)
        4. 去重单复数组合 (user <-> users)
        """
        targets = set()
        
        segments = sorted(list(path_segments), key=len, reverse=True)
        
        for i, seg1 in enumerate(segments):
            for seg2 in segments[i+1:]:
                if seg1 == seg2:
                    continue
                
                if '/' not in seg1 and '/' not in seg2:
                    continue
                
                candidates = [
                    (seg1, '/' + seg2),
                    (seg2, '/' + seg1),
                ]
                
                if self._is_likely_api_segment(seg1) and not self._is_likely_api_segment(seg2):
                    candidates.append((seg1, '/' + seg2))
                elif self._is_likely_api_segment(seg2) and not self._is_likely_api_segment(seg1):
                    candidates.append((seg2, '/' + seg1))
                
                for base, path in candidates:
                    if base and path:
                        targets.add((base, path))
        
        for segment in segments:
            for suffix in list(suffixes)[:50]:
                if suffix.startswith('/'):
                    targets.add((segment, suffix))
                else:
                    targets.add((segment, '/' + suffix))
        
        api_prefixes = ['api', 'v1', 'v2', 'v3', 'rest', 'rpc', 'graphql']
        for prefix in api_prefixes:
            for segment in segments:
                if prefix not in segment and not segment.startswith(prefix):
                    targets.add(('', '/' + prefix + '/' + segment))
                    targets.add(('api', '/' + prefix + '/' + segment))
        
        return list(targets)[:5000]
    
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
                        self._api_aggregator.add_api(
                            api_find_result,
                            source_info={'source': f'api_spec:{spec_result.spec_type}'}
                        )
                else:
                    logger.warning(f"Failed to parse API spec from {self.config.target}")
            except Exception as e:
                logger.error(f"Error parsing API spec: {e}")
        
        js_results = self._js_cache.get_all()
        existing_paths = set()
        
        for js_result in js_results:
            try:
                for api_path in js_result.apis:
                    existing_paths.add(api_path)
                    from .collectors.api_collector import APIFindResult
                    api_find_result = APIFindResult(
                        path=api_path,
                        method="GET",
                        source_type="js_parser",
                        base_url="",
                        url_type="api_path"
                    )
                    self._api_aggregator.add_api(
                        api_find_result,
                        source_info={'source': 'js_fingerprint_cache'}
                    )
            except Exception as e:
                logger.debug(f"API extraction from JS cache error: {e}")
        
        if self._detected_framework and self._framework_detector:
            framework_endpoints = self._framework_detector.generate_endpoints(self._detected_framework)
            for endpoint in framework_endpoints:
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
                    self._api_aggregator.add_api(
                        api_find_result,
                        source_info={'source': f'framework_{self._detected_framework}'}
                    )
        
        if self._collector_results and 'js' in self._collector_results:
            js_result = self._collector_results['js']
            
            inline_api_paths = js_result.get('inline_api_paths', [])
            if inline_api_paths:
                logger.info(f"Adding {len(inline_api_paths)} API paths from inline JS parser")
                for api_path in inline_api_paths:
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
                        self._api_aggregator.add_api(
                            api_find_result,
                            source_info={'source': 'inline_js_parser'}
                        )
            
            inline_routes = js_result.get('inline_routes', [])
            if inline_routes:
                logger.info(f"Adding {len(inline_routes)} routes from inline JS parser")
                for route in inline_routes:
                    normalized_route = route if route.startswith('/') else f'/{route}'
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
                        self._api_aggregator.add_api(
                            api_find_result,
                            source_info={'source': 'inline_js_parser'}
                        )
            
            response_discovered = js_result.get('response_discovered_paths', [])
            if response_discovered:
                logger.info(f"Adding {len(response_discovered)} paths from response discovery")
                for path in response_discovered:
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
                        self._api_aggregator.add_api(
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
                        self._api_aggregator.add_api(
                            api_find_result,
                            source_info={'source': 'browser_collector'}
                        )
            
            finder_api_paths = js_result.get('finder_api_paths', [])
            if finder_api_paths:
                logger.info(f"Adding {len(finder_api_paths)} API paths from ApiPathFinder")
                for api_path in finder_api_paths:
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
                        self._api_aggregator.add_api(
                            api_find_result,
                            source_info={'source': 'api_path_finder'}
                        )
        
        probed_parent_paths = await self._probe_parent_paths(js_results)
        
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
                    self._api_aggregator.add_api(
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
                    self._api_aggregator.add_api(
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
                self._api_aggregator.add_api(
                    api_find_result,
                    source_info={'source': 'cross_source_fuzz'}
                )
        
        raw_endpoints = self._api_aggregator.get_all()
        final_endpoints = []
        
        for endpoint in raw_endpoints:
            full_url = APIPathCombiner.combine_base_and_path(
                endpoint.base_url or "",
                endpoint.path
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
        
        self._analyzer_results = analyzer_results
    
    async def _score_apis(self) -> Dict[str, Any]:
        """API评分"""
        endpoints = self.result.api_endpoints if self.result else []
        
        # 建立 URL -> endpoint 映射，用于后续更新 is_high_value
        url_to_endpoint: Dict[str, Any] = {e.full_url: e for e in endpoints}
        
        for endpoint in endpoints:
            try:
                response = await self._http_client.request(
                    endpoint.full_url,
                    method=endpoint.method
                )
                from .analyzers.response_cluster import TaskResult as RCTaskResult
                rc_task_result = RCTaskResult(
                    status_code=response.status_code,
                    content=response.content.encode() if isinstance(response.content, str) else response.content,
                    content_hash=response.content_hash
                )
                self._response_cluster.add_response(endpoint.api_id, rc_task_result)
                
                if not self._response_cluster.is_baseline_404(endpoint.api_id):
                    from .models import APIStatus
                    endpoint.status = APIStatus.ALIVE
                    
                    if self._api_scorer:
                        self._api_scorer.add_evidence(
                            endpoint.full_url,
                            'http_test',
                            {},
                            http_info={'status': response.status_code, 'content': response.content[:500] if response.content else ''}
                        )
            except Exception as e:
                logger.debug(f"API scoring error: {e}")
        
        # 从评分器获取高价值 API 证据
        high_value_evidence = self._api_scorer.get_high_value() if self._api_scorer else []
        
        # 更新端点的 is_high_value 标志
        # evidence.normalized_path 是 lowercased 路径（如 '/areacare/delete'）
        # 需要匹配到 full_url 的路径部分
        for evidence in high_value_evidence:
            for ep in endpoints:
                # 检查 full_url 的路径部分是否与 normalized_path 匹配
                ep_path_lower = ep.path.lower() if ep.path else ''
                if ep_path_lower == evidence.normalized_path or \
                   ep.full_url.lower().endswith(evidence.normalized_path):
                    ep.is_high_value = True
                    break
        
        # 统计高价值端点数量
        high_value_count = sum(1 for e in endpoints if e.is_high_value)
        
        if self.result:
            self.result.alive_apis = high_value_count
            self.result.high_value_apis = high_value_count
        
        return {
            'alive_apis': high_value_count,
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
                response = await self._http_client.request(
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
        
        sensitive_findings = self._sensitive_detector.detect(
            responses_collected,
            high_value_api_ids
        )
        
        from .models import SensitiveData, Severity
        for finding in sensitive_findings:
            sensitive_data = SensitiveData(
                api_id=finding.location,
                data_type=finding.data_type,
                matches=finding.matches,
                severity=finding.severity,
                evidence=finding.evidence,
                context=finding.context,
                location=finding.location
            )
            if self.result:
                self.result.sensitive_data.append(sensitive_data)
        
        return {
            'sensitive_count': len(sensitive_findings),
            'findings': [f.to_dict() for f in sensitive_findings]
        }
    
    async def _run_testers(self):
        """运行测试阶段"""
        self._current_stage = 2
        
        active_testers = self.config.testers or ['fuzz', 'vuln']
        
        tester_results = {}
        
        if 'fuzz' in active_testers:
            tester_results['fuzz'] = await self._run_fuzz_test()
        
        if 'vuln' in active_testers:
            tester_results['vuln'] = await self._run_vuln_test()
        
        self._tester_results = tester_results
    
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
                
                results = await self._fuzz_tester.fuzz_parameters(
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
            TestCategory.RATE_LIMIT: 'test_bypass_techniques',
            TestCategory.INFORMATION_DISCLOSURE: 'test_information_disclosure',
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
            return await self._vulnerability_tester.test_jwt_security(endpoint.full_url)
        elif category == TestCategory.RATE_LIMIT:
            return await self._vulnerability_tester.test_bypass_techniques(
                endpoint.full_url,
                endpoint.method
            )
        elif category == TestCategory.INFORMATION_DISCLOSURE:
            return await self._vulnerability_tester.test_information_disclosure(endpoint.full_url)
        
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
    
    async def _stage_reporting(self):
        """报告生成阶段"""
        if not self.file_storage or not self.result:
            return
        
        scan_dict = self.result.to_dict()
        
        self.file_storage.save_json(scan_dict, 'scan_result.json')
        
        report_exporter = ReportExporter(output_dir=self.config.output_dir)
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
            folder_name = self.result.target_url.replace('://', '_').replace('/', '_').replace('.', '_')
            html_path = os.path.join(self.config.output_dir, folder_name, 'attack_chain.html')
            attack_chain_exporter.generate_html_report(self.result, html_path)
        except Exception as e:
                logger.error(f"Attack chain export error: {e}")
    
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
