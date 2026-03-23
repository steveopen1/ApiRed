"""
ScanEngine - 统一扫描引擎
提供Collector → Analyzer → Tester的标准化流程
"""

import asyncio
import time
import os
import logging
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field, asdict
from datetime import datetime
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

from .utils.config import Config
from .storage import DBStorage, FileStorage
from .collectors import JSFingerprintCache, JSParser, APIAggregator, HeadlessBrowserCollector
from .collectors.api_collector import APIPathCombiner, ServiceAnalyzer
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
        self._callbacks: Dict[str, List[Any]] = {
            'stage_start': [],
            'stage_progress': [],
            'stage_complete': [],
            'finding': [],
            'error': []
        }
        
        self._stage_names = ["collect", "analyze", "test"]
    
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
        self._browser_enabled = getattr(self.config, 'chrome', False)
        
        if self._browser_enabled:
            try:
                self._browser_collector = HeadlessBrowserCollector()
                browser_initialized = await self._browser_collector.initialize(headless=True)
                if not browser_initialized:
                    self._browser_collector = None
                    print("Warning: Browser initialization failed, continuing without browser")
            except Exception as e:
                print(f"Warning: Browser not available: {e}")
                self._browser_collector = None
        
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
                    print(f"Found previous scan snapshot: {latest.api_count} APIs, {latest.js_count} JS files")
            except Exception as e:
                print(f"Incremental scanner init error: {e}")
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
            print(f"错误: Agent 模式需要配置 AI API 密钥")
            print(f"缺少: {', '.join(missing_config.keys())}")
            print()
            print("提示: 也可以使用传统模式，无需配置 AI:")
            print(f"  python main.py scan -u {self.config.target}")
            
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
        
        if 'api' in active_collectors:
            collector_results['api'] = await self._extract_apis()
        
        self._collector_results = collector_results
    
    async def _collect_js(self) -> Dict[str, Any]:
        """采集JS资源 + 框架检测 + 浏览器动态采集"""
        from .utils.http_client import AsyncHttpClient
        
        js_urls = []
        alive_js = []
        js_content_all = ""
        browser_routes = []
        browser_api_endpoints = []
        
        if self._browser_collector:
            try:
                browser_result = await self._collect_with_browser()
                if browser_result:
                    js_urls.extend(browser_result.get('js_urls', []))
                    alive_js.extend(browser_result.get('alive_js', []))
                    browser_routes = browser_result.get('spa_routes', [])
                    browser_api_endpoints = browser_result.get('browser_apis', [])
            except Exception as e:
                print(f"Browser collection failed: {e}")
        
        response = await self._http_client.request(
            self.config.target,
            headers={'Cookie': self.config.cookies} if self.config.cookies else None
        )
        
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
        
        return {
            'total_js': len(js_urls),
            'alive_js': len(alive_js),
            'js_urls': alive_js,
            'detected_framework': self._detected_framework
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
    
    RESTFUL_SUFFIXES = [
        '', '/list', '/listJson', '/listJsonData', '/listData', '/listPage', '/listAll',
        '/page', '/pageList', '/pageData', '/pager', '/pagination',
        '/all', '/allList', '/allData', '/count', '/total', '/sum',
        '/detail', '/detail/{id}', '/detailJson', '/detailInfo', '/info', '/info/{id}',
        '/add', '/addPage', '/addForm', '/create', '/create/{id}', '/new', '/insert',
        '/edit', '/edit/{id}', '/editForm', '/update', '/update/{id}', '/modify', '/modify/{id}',
        '/delete', '/delete/{id}', '/del/{id}', '/del', '/remove', '/remove/{id}', '/batch/delete',
        '/enable', '/enable/{id}', '/disable', '/disable/{id}', '/status', '/status/{id}', '/state', '/state/{id}',
        '/config', '/config/{id}', '/settings', '/settings/{id}', '/options', '/option',
        '/export', '/exportAll', '/exportExcel', '/exportFile', '/import', '/importExcel', '/importFile', '/importTemplate', '/importData',
        '/download', '/download/{id}', '/upload', '/uploadFile', '/uploadImage',
        '/search', '/search/{keyword}', '/query', '/query/{id}', '/filter', '/filter/{condition}',
        '/sort', '/sort/{field}', '/tree', '/treeList', '/treeData', '/treeJson',
        '/select', '/select/{id}', '/selects', '/choices', '/options', '/cascader', '/region',
        '/submit', '/submit/{id}', '/cancel', '/cancel/{id}', '/reset', '/reset/{id}',
        '/refresh', '/refresh/{id}', '/init', '/init/{id}', '/default', '/load', '/load/{id}',
        '/permission', '/permission/{id}', '/permissions', '/perm', '/perm/{id}', '/perms',
        '/role', '/role/{id}', '/roles', '/menu', '/menu/{id}', '/menus',
        '/user', '/user/{id}', '/users', '/account', '/account/{id}', '/profile', '/profile/{id}',
        '/login', '/loginIn', '/loginOut', '/logout', '/register', '/signup', '/signup/{id}',
        '/forget', '/forgetPwd', '/resetPwd', '/reset/{id}/pwd',
        '/captcha', '/captcha/{id}', '/verify', '/verifyCode', '/sendCode', '/send/{type}/code',
        '/token', '/token/{id}', '/refreshToken', '/refresh/{id}/token',
        '/dict', '/dict/{type}', '/dictData', '/dictType', '/dict/{type}/data',
        '/log', '/logs', '/log/{id}', '/history', '/history/{id}', '/operation', '/operation/{id}', '/record', '/records',
        '/monitor', '/monitor/{id}', '/statistics', '/statistics/{id}', '/stat', '/stats', '/stat/{id}',
        '/chart', '/chart/{type}', '/dashboard', '/dashboard/{id}', '/summary', '/summary/{id}',
        '/report', '/report/{id}', '/reports', '/analytics', '/analytics/{type}',
        '/area', '/area/{id}', '/areas', '/city', '/city/{id}', '/province', '/province/{id}',
        '/region', '/region/{id}', '/location', '/location/{id}', '/address', '/address/{id}',
        '/category', '/category/{id}', '/categories', '/type', '/type/{id}', '/types',
        '/tag', '/tag/{id}', '/tags', '/brand', '/brand/{id}', '/brands',
        '/model', '/model/{id}', '/models', '/spec', '/spec/{id}', '/specs',
        '/product', '/product/{id}', '/products', '/goods', '/goods/{id}', '/item', '/item/{id}', '/items',
        '/sku', '/sku/{id}', '/spu', '/spu/{id}', '/price', '/price/{id}', '/stock', '/stock/{id}', '/inventory', '/inventory/{id}',
        '/order', '/order/{id}', '/orders', '/orderInfo', '/orderInfo/{id}', '/orderList', '/orderList/{id}',
        '/createOrder', '/create/order', '/pay', '/pay/{id}', '/payment', '/payment/{id}',
        '/cart', '/cart/{id}', '/wishlist', '/wishlist/{id}', '/favorites', '/favorites/{id}',
        '/collect', '/collect/{id}', '/coupon', '/coupon/{id}', '/coupons',
        '/wallet', '/wallet/{id}', '/balance', '/balance/{id}',
        '/message', '/message/{id}', '/messages', '/notification', '/notification/{id}', '/notifications',
        '/notice', '/notice/{id}', '/notices', '/announcement', '/announcement/{id}', '/announcements',
        '/inbox', '/inbox/{id}', '/outbox', '/outbox/{id}',
        '/comment', '/comment/{id}', '/comments', '/review', '/review/{id}', '/reviews',
        '/rating', '/rating/{id}', '/feedback', '/feedback/{id}', '/suggest', '/suggest/{id}',
        '/suggestion', '/suggestion/{id}', '/report', '/report/{id}', '/complaint', '/complaint/{id}',
        '/attachment', '/attachment/{id}', '/attachments', '/file', '/file/{id}', '/files',
        '/image', '/image/{id}', '/images', '/video', '/video/{id}', '/videos', '/media', '/media/{id}',
        '/company', '/company/{id}', '/organization', '/organization/{id}', '/org', '/org/{id}',
        '/department', '/department/{id}', '/dept', '/dept/{id}', '/departments',
    ]
    
    PATH_FRAGMENTS = [
        'admin', 'manage', 'manager', 'system', 'config', 'setting', 'settings',
        'user', 'users', 'account', 'accounts', 'profile', 'profiles', 'person', 'persons', 'employee', 'employees',
        'role', 'roles', 'permission', 'permissions', 'perm', 'perms', 'menu', 'menus',
        'dict', 'dicts', 'dictionary', 'type', 'types', 'category', 'categories', 'tag', 'tags',
        'order', 'orders', 'product', 'products', 'goods', 'item', 'items', 'sku', 'spu',
        'dept', 'department', 'departments', 'org', 'organization', 'organizations', 'company', 'companies',
        'area', 'areas', 'region', 'regions', 'province', 'provinces', 'city', 'cities', 'district', 'districts',
        'log', 'logs', 'operation', 'operations', 'history', 'record', 'records',
        'monitor', 'monitors', 'statistics', 'stats', 'stat', 'charts', 'chart', 'dashboard', 'dashboards',
        'file', 'files', 'upload', 'uploads', 'download', 'downloads', 'attachment', 'attachments', 'media',
        'message', 'messages', 'notice', 'notices', 'notification', 'notifications', 'announcement', 'announcements',
        'comment', 'comments', 'feedback', 'suggest', 'suggestions', 'report', 'reports', 'complaint', 'complaints',
        'brand', 'brands', 'model', 'models', 'spec', 'specs', 'category', 'categories',
        'price', 'prices', 'stock', 'stocks', 'inventory', 'inventories',
        'coupon', 'coupons', 'wallet', 'wallets', 'balance', 'balances',
        'captcha', 'captchas', 'token', 'tokens',
    ]
    
    FUZZ_SUFFIXES = [
        'Json', 'JsonData', 'JsonList', 'JsonResult', 'JsonResponse',
        'List', 'ListView', 'ListData', 'ListAll', 'ListJson', 'ListJsonData',
        'Tree', 'TreeList', 'TreeData', 'TreeJson', 'TreeTable',
        'Page', 'PageList', 'PageData', 'PageInfo', 'PageResult', 'Pager',
        'Data', 'DataList', 'DataGrid', 'DataTable', 'DataSource',
        'Info', 'InfoList', 'InfoData', 'Detail', 'Details', 'DetailInfo', 'DetailData',
        'Query', 'QueryList', 'QueryData', 'QueryById', 'QueryInfo',
        'Search', 'SearchList', 'SearchData', 'SearchByKeyword',
        'Select', 'SelectList', 'SelectData', 'SelectOptions', 'SelectAll',
        'Options', 'Choices', 'Cascade', 'Cascader', 'Region',
        'Init', 'InitList', 'InitData', 'Initialize', 'Load', 'LoadList', 'LoadData', 'LoadAll',
        'Refresh', 'RefreshList', 'RefreshData', 'Reload', 'ReloadData',
        'Submit', 'SubmitForm', 'Save', 'SaveData', 'SaveInfo', 'Commit', 'CommitData',
        'Update', 'UpdateData', 'UpdateInfo', 'Edit', 'EditData', 'EditInfo', 'EditForm',
        'Modify', 'ModifyData', 'Remove', 'RemoveData', 'Delete', 'DeleteData', 'Del', 'DelData',
        'Export', 'ExportExcel', 'ExportData', 'ExportFile', 'Import', 'ImportExcel', 'ImportData', 'ImportTemplate',
        'Upload', 'UploadFile', 'UploadImage', 'Download', 'DownloadFile', 'DownloadExcel',
        'Config', 'Configs', 'Settings', 'Setting', 'Options', 'Option',
        'Index', 'Home', 'Main', 'Default', 'Base', 'Common',
        'Grid', 'GridData', 'Table', 'TableData', 'TableList',
        'Card', 'CardList', 'CardData', 'Modal', 'ModalData',
        'Form', 'FormData', 'FormInfo', 'EditForm', 'AddForm', 'SearchForm',
        'Result', 'ResultData', 'Response', 'ResponseData', 'Ajax', 'AjaxData',
        'All', 'AllList', 'AllData', 'AllJson', 'Count', 'Total', 'Sum',
        'Status', 'State', 'Enable', 'Disable', 'Active', 'Inactive',
        'Login', 'Logout', 'Register', 'Signup', 'Captcha', 'Verify', 'SendCode',
        'Menu', 'Perm', 'Permission', 'Role', 'User', 'Account', 'Token', 'Profile',
    ]
    
    async def _probe_parent_paths(self, js_results: List) -> Dict[str, Set[str]]:
        """
        探测父路径是否可访问，并进一步探测常见 RESTful 端点
        
        使用从JS中提取的后缀和常见后缀进行智能fuzzing组合探测
        
        Returns:
            {探测到的有效父路径: 该路径下探测到的额外端点}
        """
        probed_results = {}
        base_url = self.config.target.rstrip('/')
        
        parent_paths_to_probe = set()
        all_js_suffixes = set()
        all_js_resources = set()
        existing_apis = set()
        
        for js_result in js_results:
            if hasattr(js_result, 'parent_paths') and js_result.parent_paths:
                for original_path, parents in js_result.parent_paths.items():
                    existing_apis.add(original_path)
                    for parent in parents:
                        if parent not in parent_paths_to_probe:
                            parent_paths_to_probe.add(parent)
            
            if hasattr(js_result, 'extracted_suffixes') and js_result.extracted_suffixes:
                all_js_suffixes.update(js_result.extracted_suffixes)
            
            if hasattr(js_result, 'resource_fragments') and js_result.resource_fragments:
                all_js_resources.update(js_result.resource_fragments)
            
            if hasattr(js_result, 'apis'):
                existing_apis.update(js_result.apis)
        
        js_suffix_list = list(all_js_suffixes)[:30]
        js_resource_list = list(all_js_resources)[:30]
        
        combined_suffixes = []
        
        for suffix in self.RESTFUL_SUFFIXES:
            clean_suffix = suffix.strip('/')
            if clean_suffix:
                combined_suffixes.append('/' + clean_suffix)
            combined_suffixes.append(suffix)
        
        for js_suffix in js_suffix_list:
            if js_suffix not in ('', '/'):
                combined_suffixes.append('/' + js_suffix)
                if not js_suffix.endswith('s'):
                    combined_suffixes.append('/' + js_suffix + 's')
                plural = js_suffix + 's' if not js_suffix.endswith('s') else js_suffix
                combined_suffixes.append('/' + plural)
        
        for fuzz_suffix in self.FUZZ_SUFFIXES[:20]:
            combined_suffixes.append('/' + fuzz_suffix.lower())
            combined_suffixes.append('/' + fuzz_suffix)
        
        combined_suffixes = list(set(combined_suffixes))
        
        if not parent_paths_to_probe:
            return probed_results
        
        logger.info(f"Probing {len(parent_paths_to_probe)} parent paths with {len(combined_suffixes)} suffixes...")
        
        for parent_path in parent_paths_to_probe:
            full_url = base_url + parent_path
            
            try:
                response = await self._http_client.request(
                    full_url,
                    method='HEAD',
                    timeout=5
                )
                
                if 200 <= response.status_code < 400:
                    logger.info(f"Parent path accessible: {parent_path} (status: {response.status_code})")
                    probed_results[parent_path] = set()
                    
                    probed_suffixes = set()
                    
                    for suffix in combined_suffixes:
                        if suffix.startswith('//'):
                            continue
                        
                        if suffix.startswith('/'):
                            sub_path = parent_path.rstrip('/') + suffix
                        else:
                            sub_path = parent_path.rstrip('/') + '/' + suffix
                        
                        if sub_path in existing_apis or sub_path in probed_suffixes:
                            continue
                        
                        sub_url = base_url + sub_path
                        
                        try:
                            sub_response = await self._http_client.request(
                                sub_url,
                                method='HEAD',
                                timeout=3
                            )
                            
                            if 200 <= sub_response.status_code < 400:
                                probed_results[parent_path].add(sub_path)
                                probed_suffixes.add(sub_path)
                                existing_apis.add(sub_path)
                                logger.debug(f"  Found: {sub_path} (status: {sub_response.status_code})")
                        except Exception:
                            pass
                    
                    for js_resource in js_resource_list[:10]:
                        for js_suffix in js_suffix_list[:5]:
                            combo_path = parent_path.rstrip('/') + '/' + js_resource + '/' + js_suffix
                            
                            if combo_path in existing_apis or combo_path in probed_suffixes:
                                continue
                            
                            combo_url = base_url + combo_path
                            
                            try:
                                combo_response = await self._http_client.request(
                                    combo_url,
                                    method='HEAD',
                                    timeout=3
                                )
                                
                                if 200 <= combo_response.status_code < 400:
                                    probed_results[parent_path].add(combo_path)
                                    probed_suffixes.add(combo_path)
                                    existing_apis.add(combo_path)
                                    logger.debug(f"  Found (combo): {combo_path} (status: {combo_response.status_code})")
                            except Exception:
                                pass
                
                elif response.status_code == 401 or response.status_code == 403:
                    probed_results[parent_path] = set()
                    logger.info(f"Parent path exists (auth required): {parent_path} (status: {response.status_code})")
            
            except Exception as e:
                logger.debug(f"Parent path probe failed: {parent_path} - {e}")
        
        return probed_results
    
    async def _fuzz_api_paths(self, js_results: List) -> Set[str]:
        """基于 JS 中发现的 API 路径进行智能 fuzzing 探测"""
        discovered_paths = set()
        base_url = self.config.target.rstrip('/')
        
        all_apis = set()
        all_fragments = set()
        all_suffixes = set()
        all_resources = set()
        all_parent_paths = set()
        
        for js_result in js_results:
            for api in js_result.apis:
                all_apis.add(api)
                parts = api.strip('/').split('/')
                for part in parts:
                    if len(part) >= 2:
                        all_fragments.add(part.lower())
                
                if hasattr(js_result, 'parent_paths') and api in js_result.parent_paths:
                    for parent in js_result.parent_paths[api]:
                        all_parent_paths.add(parent)
            
            if hasattr(js_result, 'extracted_suffixes'):
                all_suffixes.update(js_result.extracted_suffixes)
            
            if hasattr(js_result, 'resource_fragments'):
                all_resources.update(js_result.resource_fragments)
        
        api_fragments = list(all_fragments)[:50]
        js_suffix_list = list(all_suffixes)[:30]
        js_resource_list = list(all_resources)[:30]
        parent_paths_list = list(all_parent_paths)[:30]
        
        paths_to_probe = []
        probed_set = set()
        
        for fragment in api_fragments:
            for suffix in self.FUZZ_SUFFIXES[:15]:
                fuzz_path = '/' + fragment.lower() + suffix.lower()
                if fuzz_path not in all_apis and fuzz_path not in probed_set:
                    paths_to_probe.append(fuzz_path)
                    probed_set.add(fuzz_path)
            
            for js_suffix in js_suffix_list[:10]:
                fuzz_path = '/' + fragment.lower() + '/' + js_suffix.lower()
                if fuzz_path not in all_apis and fuzz_path not in probed_set:
                    paths_to_probe.append(fuzz_path)
                    probed_set.add(fuzz_path)
        
        for parent_path in parent_paths_list:
            for js_suffix in js_suffix_list[:15]:
                fuzz_path = parent_path.rstrip('/') + '/' + js_suffix.lower()
                if fuzz_path not in all_apis and fuzz_path not in probed_set:
                    paths_to_probe.append(fuzz_path)
                    probed_set.add(fuzz_path)
                
                fuzz_path = parent_path.rstrip('/') + '/' + js_suffix.lower() + 's'
                if fuzz_path not in all_apis and fuzz_path not in probed_set:
                    paths_to_probe.append(fuzz_path)
                    probed_set.add(fuzz_path)
            
            for fuzz_suffix in self.FUZZ_SUFFIXES[:10]:
                fuzz_path = parent_path.rstrip('/') + '/' + fuzz_suffix.lower()
                if fuzz_path not in all_apis and fuzz_path not in probed_set:
                    paths_to_probe.append(fuzz_path)
                    probed_set.add(fuzz_path)
            
            for js_resource in js_resource_list[:5]:
                for js_suffix in js_suffix_list[:5]:
                    combo_path = parent_path.rstrip('/') + '/' + js_resource.lower() + '/' + js_suffix.lower()
                    if combo_path not in all_apis and combo_path not in probed_set:
                        paths_to_probe.append(combo_path)
                        probed_set.add(combo_path)
        
        for js_resource in js_resource_list[:10]:
            for js_suffix in js_suffix_list[:10]:
                fuzz_path = '/' + js_resource.lower() + '/' + js_suffix.lower()
                if fuzz_path not in all_apis and fuzz_path not in probed_set:
                    paths_to_probe.append(fuzz_path)
                    probed_set.add(fuzz_path)
        
        frag_count = min(len(api_fragments), 20)
        for i in range(frag_count):
            for j in range(i + 1, frag_count):
                frag1 = api_fragments[i]
                frag2 = api_fragments[j] if j < len(api_fragments) else None
                if frag2:
                    new_path = '/' + frag1.lower() + '/' + frag2.lower()
                    if new_path not in all_apis and new_path not in probed_set:
                        paths_to_probe.append(new_path)
                        probed_set.add(new_path)
        
        paths_to_probe = list(set(paths_to_probe))[:200]
        
        for path in paths_to_probe:
            full_url = base_url + path
            try:
                response = await self._http_client.request(full_url, method='GET', timeout=3)
                if 200 <= response.status_code < 400:
                    discovered_paths.add(path)
                    logger.info(f"Fuzz found: {path} (status: {response.status_code})")
                elif response.status_code in (401, 403):
                    discovered_paths.add(path)
                    logger.info(f"Fuzz found (auth): {path} (status: {response.status_code})")
            except Exception:
                pass
        
        return discovered_paths
    
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
        
        for fuzz_path in fuzzed_paths:
            if fuzz_path not in existing_paths:
                existing_paths.add(fuzz_path)
                from .collectors.api_collector import APIFindResult
                api_find_result = APIFindResult(
                    path=fuzz_path,
                    method="GET",
                    source_type="fuzz_probe",
                    base_url="",
                    url_type="fuzzed"
                )
                self._api_aggregator.add_api(
                    api_find_result,
                    source_info={'source': 'api_fuzzing'}
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
        
        fuzz_count = 0
        fuzz_results = []
        
        for endpoint in high_value_apis:
            try:
                fuzz_params = endpoint.parameters if endpoint.parameters else ['id', 'page']
                results = await self._fuzz_tester.fuzz_parameters(
                    endpoint.full_url,
                    endpoint.method,
                    fuzz_params
                )
                fuzz_count += len(results)
                fuzz_results.extend(results)
            except Exception as e:
                logger.debug(f"Fuzz test error: {e}")
        
        return {
            'fuzz_count': fuzz_count,
            'results': [r.to_dict() if hasattr(r, 'to_dict') else str(r) for r in fuzz_results]
        }
    
    async def _run_vuln_test(self) -> Dict[str, Any]:
        """漏洞测试"""
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
                print(f"URL greper error: {e}")
        
        vuln_count = 0
        from .models import Severity
        
        cfg = self.config
        
        for endpoint in high_value_apis:
            try:
                # SSRF 测试
                if getattr(cfg, 'enable_ssrf_test', True):
                    ssrf_result = await self._vulnerability_tester.test_ssrf(endpoint.full_url)
                    if ssrf_result.is_vulnerable:
                        from .models import Vulnerability
                        vuln = Vulnerability(
                            api_id=endpoint.api_id,
                            vuln_type=ssrf_result.vuln_type.value,
                            severity=Severity[ssrf_result.severity.upper()] if isinstance(ssrf_result.severity, str) else ssrf_result.severity,
                            evidence=ssrf_result.evidence,
                            payload=ssrf_result.payload,
                            remediation=ssrf_result.remediation,
                            cwe_id=ssrf_result.cwe_id
                        )
                        if self.result:
                            self.result.vulnerabilities.append(vuln)
                        vuln_count += 1
                
                # 信息泄露测试
                if getattr(cfg, 'enable_info_disclosure_test', True):
                    info_disclosure = await self._vulnerability_tester.test_information_disclosure(endpoint.full_url)
                    if info_disclosure.is_vulnerable:
                        from .models import Vulnerability
                        vuln = Vulnerability(
                            api_id=endpoint.api_id,
                            vuln_type=info_disclosure.vuln_type.value,
                            severity=Severity[info_disclosure.severity.upper()] if isinstance(info_disclosure.severity, str) else info_disclosure.severity,
                            evidence=info_disclosure.evidence,
                            payload=info_disclosure.payload,
                            remediation=info_disclosure.remediation,
                            cwe_id=info_disclosure.cwe_id
                        )
                        if self.result:
                            self.result.vulnerabilities.append(vuln)
                        vuln_count += 1
                
                # SQL 注入测试
                if getattr(cfg, 'enable_sql_test', True):
                    sql_result = await self._vulnerability_tester.test_sql_injection(endpoint.full_url, endpoint.method)
                    if sql_result and sql_result.is_vulnerable:
                        from .models import Vulnerability
                        vuln = Vulnerability(
                            api_id=endpoint.api_id,
                            vuln_type=sql_result.vuln_type.value,
                            severity=Severity[sql_result.severity.upper()] if isinstance(sql_result.severity, str) else sql_result.severity,
                            evidence=sql_result.evidence,
                            payload=sql_result.payload,
                            remediation=sql_result.remediation,
                            cwe_id=sql_result.cwe_id
                        )
                        if self.result:
                            self.result.vulnerabilities.append(vuln)
                        vuln_count += 1
                
                # XSS 测试
                if getattr(cfg, 'enable_xss_test', True):
                    xss_result = await self._vulnerability_tester.test_xss(endpoint.full_url, endpoint.method)
                    if xss_result and xss_result.is_vulnerable:
                        from .models import Vulnerability
                        vuln = Vulnerability(
                            api_id=endpoint.api_id,
                            vuln_type=xss_result.vuln_type.value,
                            severity=Severity[xss_result.severity.upper()] if isinstance(xss_result.severity, str) else xss_result.severity,
                            evidence=xss_result.evidence,
                            payload=xss_result.payload,
                            remediation=xss_result.remediation,
                            cwe_id=xss_result.cwe_id
                        )
                        if self.result:
                            self.result.vulnerabilities.append(vuln)
                        vuln_count += 1
                
                # Bypass 技术测试
                if getattr(cfg, 'enable_bypass_test', True):
                    bypass_result = await self._vulnerability_tester.test_bypass_techniques(endpoint.full_url, endpoint.method)
                    if bypass_result and bypass_result.is_vulnerable:
                        from .models import Vulnerability
                        vuln = Vulnerability(
                            api_id=endpoint.api_id,
                            vuln_type=bypass_result.vuln_type.value,
                            severity=Severity[bypass_result.severity.upper()] if isinstance(bypass_result.severity, str) else bypass_result.severity,
                            evidence=bypass_result.evidence,
                            payload=bypass_result.payload,
                            remediation=bypass_result.remediation,
                            cwe_id=bypass_result.cwe_id
                        )
                        if self.result:
                            self.result.vulnerabilities.append(vuln)
                        vuln_count += 1
                
                # JWT 弱密钥测试
                if getattr(cfg, 'enable_jwt_test', True):
                    jwt_result = await self._vulnerability_tester.test_jwt_weak(endpoint.full_url)
                    if jwt_result and jwt_result.is_vulnerable:
                        from .models import Vulnerability
                        vuln = Vulnerability(
                            api_id=endpoint.api_id,
                            vuln_type=jwt_result.vuln_type.value,
                            severity=Severity[jwt_result.severity.upper()] if isinstance(jwt_result.severity, str) else jwt_result.severity,
                            evidence=jwt_result.evidence,
                            payload=jwt_result.payload,
                            remediation=jwt_result.remediation,
                            cwe_id=jwt_result.cwe_id
                        )
                        if self.result:
                            self.result.vulnerabilities.append(vuln)
                        vuln_count += 1
                
                # 未授权访问测试
                if getattr(cfg, 'enable_unauthorized_test', True):
                    auth_result = await self._vulnerability_tester.test_unauthorized_access(endpoint.full_url, endpoint.method)
                    if auth_result and auth_result.is_vulnerable:
                        from .models import Vulnerability
                        vuln = Vulnerability(
                            api_id=endpoint.api_id,
                            vuln_type=auth_result.vuln_type.value,
                            severity=Severity[auth_result.severity.upper()] if isinstance(auth_result.severity, str) else auth_result.severity,
                            evidence=auth_result.evidence,
                            payload=auth_result.payload,
                            remediation=auth_result.remediation,
                            cwe_id=auth_result.cwe_id
                        )
                        if self.result:
                            self.result.vulnerabilities.append(vuln)
                        vuln_count += 1
                
                # IDOR 专项测试
                if getattr(cfg, 'enable_idor_test', True):
                    try:
                        idor_params = {}
                        if endpoint.parameters:
                            for param in endpoint.parameters:
                                if param.get('name'):
                                    idor_params[param['name']] = param.get('default', param.get('example', 'test'))
                        
                        idor_results = await self._idor_tester.test_idor(
                            url=endpoint.full_url,
                            method=endpoint.method,
                            params=idor_params if idor_params else None,
                            headers={'Cookie': self.config.cookies} if self.config.cookies else None
                        )
                        
                        for idor_result in idor_results:
                            if idor_result.is_vulnerable:
                                from .models import Vulnerability
                                vuln = Vulnerability(
                                    api_id=endpoint.api_id,
                                    vuln_type='IDOR',
                                    severity=Severity.HIGH if idor_result.severity == 'high' else Severity.MEDIUM,
                                    evidence=idor_result.evidence,
                                    payload=f"technique={idor_result.bypass_technique}",
                                    remediation="实施对象级访问控制，验证用户是否有权访问请求的资源",
                                    cwe_id="CWE-639"
                                )
                                if self.result:
                                    self.result.vulnerabilities.append(vuln)
                                vuln_count += 1
                    except Exception as e:
                        logger.debug(f"IDOR test error for {endpoint.full_url}: {e}")
                        
            except Exception as e:
                logger.warning(f"Vulnerability test error for endpoint {endpoint.api_id}: {e}")
        
        return {
            'vuln_count': vuln_count,
            'vulnerabilities': [v.to_dict() for v in self.result.vulnerabilities] if self.result else []
        }
    
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
            print(f"Report export error: {e}")
        
        try:
            attack_chain_exporter = AttackChainExporter()
            folder_name = self.result.target_url.replace('://', '_').replace('/', '_').replace('.', '_')
            html_path = os.path.join(self.config.output_dir, folder_name, 'attack_chain.html')
            attack_chain_exporter.generate_html_report(self.result, html_path)
        except Exception as e:
            print(f"Attack chain export error: {e}")
    
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
        
        if self._http_client:
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
        return script_pattern.findall(html_content)
    
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
