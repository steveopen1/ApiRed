"""
Scanner Module
主扫描器模块
"""

import asyncio
import time
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse

from .utils.config import Config
from .utils.http_client import AsyncHttpClient, AsyncTask
from .utils.concurrency import ThreadPool, RateLimiter
from .storage import DBStorage, FileStorage
from .collectors.js_collector import JSFingerprintCache, JSParser
from .collectors.api_collector import APIAggregator, APIPathCombiner
from .analyzers.api_scorer import APIScorer, APIEvidenceAggregator
from .analyzers.response_cluster import ResponseCluster
from .analyzers.sensitive_detector import TwoTierSensitiveDetector
from .testers.fuzz_tester import FuzzTester
from .testers.vulnerability_tester import VulnerabilityTester
from .models import ScanResult, APIEndpoint, Vulnerability, SensitiveData


@dataclass
class ScannerConfig:
    """扫描器配置"""
    target: str
    cookies: str = ""
    chrome: bool = True
    attack_mode: str = "all"
    no_api_scan: bool = False
    dedupe: bool = True
    store: str = "all"
    proxy: Optional[str] = None
    js_depth: int = 3
    ai_scan: bool = False
    concurrency: int = 50
    output_format: str = "json"


class ChkApiScanner:
    """主扫描器"""
    
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.cfg = Config()
        
        self.http_client: Optional[AsyncHttpClient] = None
        self.db_storage: Optional[DBStorage] = None
        self.file_storage: Optional[FileStorage] = None
        
        self.js_cache: Optional[JSFingerprintCache] = None
        self.api_aggregator: Optional[APIAggregator] = None
        self.api_scorer: Optional[APIScorer] = None
        self.evidence_aggregator: Optional[APIEvidenceAggregator] = None
        self.response_cluster: Optional[ResponseCluster] = None
        self.sensitive_detector: Optional[TwoTierSensitiveDetector] = None
        
        self.result: Optional[ScanResult] = None
        self._running = False
        self._callbacks: Dict[str, List[Callable]] = {
            'stage_start': [],
            'stage_progress': [],
            'stage_complete': [],
            'finding': []
        }
    
    def on(self, event: str, callback: Callable):
        """注册事件回调"""
        if event in self._callbacks:
            self._callbacks[event].append(callback)
    
    def _emit(self, event: str, data: Any):
        """触发事件"""
        for callback in self._callbacks.get(event, []):
            try:
                callback(data)
            except Exception:
                pass
    
    async def initialize(self):
        """初始化扫描器"""
        self._running = True
        
        target_parsed = urlparse(self.config.target)
        folder_name = self.config.target.replace('://', '_').replace('/', '_').replace('.', '_')
        
        self.db_storage = DBStorage(
            db_path=f"./results/{folder_name}/results.db",
            wal_mode=True
        )
        
        self.file_storage = FileStorage(
            base_dir=f"./results/{folder_name}"
        )
        
        self.http_client = AsyncHttpClient(
            max_concurrent=self.config.concurrency,
            max_retries=3,
            timeout=30,
            proxy=self.config.proxy
        )
        
        self.js_cache = JSFingerprintCache(self.db_storage)
        self.api_aggregator = APIAggregator()
        self.api_scorer = APIScorer(
            min_high_value_score=self.cfg.get('ai.thresholds.high_value_api_score', 5)
        )
        self.evidence_aggregator = APIEvidenceAggregator(self.api_scorer)
        self.response_cluster = ResponseCluster()
        self.sensitive_detector = TwoTierSensitiveDetector(
            config={'ai_enabled': self.config.ai_scan}
        )
        
        self.result = ScanResult(
            target_url=self.config.target,
            start_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
    
    async def run(self) -> ScanResult:
        """执行扫描"""
        await self.initialize()
        
        try:
            self._emit('stage_start', {'stage': 'initialization', 'status': 'complete'})
            
            if self.config.attack_mode in ['collect', 'all']:
                await self._stage1_js_collection()
                await self._stage2_api_extraction()
            
            if self.config.attack_mode in ['scan', 'all'] and not self.config.no_api_scan:
                await self._stage3_api_testing()
                await self._stage4_vulnerability_testing()
            
            await self._stage5_reporting()
            
        except Exception as e:
            self.result.errors.append(str(e))
        
        finally:
            await self.cleanup()
        
        return self.result
    
    async def _stage1_js_collection(self):
        """阶段1：JS采集"""
        self._emit('stage_start', {'stage': 'js_collection', 'status': 'running'})
        
        start_time = time.time()
        
        response = await self.http_client.request(
            self.config.target,
            headers={'Cookie': self.config.cookies} if self.config.cookies else None
        )
        
        js_urls = self._extract_js_urls(response.content)
        
        alive_js = []
        for js_url in js_urls:
            js_response = await self.http_client.request(js_url)
            if js_response.status_code == 200:
                alive_js.append({
                    'url': js_url,
                    'content': js_response.content
                })
        
        duration = time.time() - start_time
        
        self._record_stage_stats(
            'stage1_js_collection',
            start_time,
            time.time(),
            len(js_urls),
            len(alive_js),
            0
        )
        
        self._emit('stage_complete', {
            'stage': 'js_collection',
            'duration': duration,
            'found': len(alive_js)
        })
    
    async def _stage2_api_extraction(self):
        """阶段2：API提取"""
        self._emit('stage_start', {'stage': 'api_extraction', 'status': 'running'})
        
        start_time = time.time()
        
        pass
        
        duration = time.time() - start_time
        
        self._emit('stage_complete', {
            'stage': 'api_extraction',
            'duration': duration
        })
    
    async def _stage3_api_testing(self):
        """阶段3：API测试"""
        self._emit('stage_start', {'stage': 'api_testing', 'status': 'running'})
        
        start_time = time.time()
        
        pass
        
        duration = time.time() - start_time
        
        self._emit('stage_complete', {
            'stage': 'api_testing',
            'duration': duration
        })
    
    async def _stage4_vulnerability_testing(self):
        """阶段4：漏洞测试"""
        self._emit('stage_start', {'stage': 'vulnerability_testing', 'status': 'running'})
        
        start_time = time.time()
        
        pass
        
        duration = time.time() - start_time
        
        self._emit('stage_complete', {
            'stage': 'vulnerability_testing',
            'duration': duration
        })
    
    async def _stage5_reporting(self):
        """阶段5：报告生成"""
        self._emit('stage_start', {'stage': 'reporting', 'status': 'running'})
        
        if self.file_storage:
            self.file_storage.save_json(
                self.result.to_dict(),
                'scan_result.json'
            )
        
        self._emit('stage_complete', {'stage': 'reporting', 'status': 'complete'})
    
    def _extract_js_urls(self, html_content: str) -> List[str]:
        """从HTML提取JS URL"""
        import re
        script_pattern = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
        return script_pattern.findall(html_content)
    
    def _record_stage_stats(
        self,
        stage_name: str,
        start_time: float,
        end_time: float,
        input_count: int,
        output_count: int,
        error_count: int
    ):
        """记录阶段统计"""
        stats = {
            'stage_name': stage_name,
            'start_time': start_time,
            'end_time': end_time,
            'duration': end_time - start_time,
            'input_count': input_count,
            'output_count': output_count,
            'error_count': error_count
        }
        
        if self.db_storage:
            self.db_storage.record_stage_stats(stats)
        
        if self.result:
            if 'stage_stats' not in self.result.statistics:
                self.result.statistics['stage_stats'] = []
            self.result.statistics['stage_stats'].append(stats)
    
    async def cleanup(self):
        """清理资源"""
        self._running = False
        
        if self.http_client:
            self.http_client.session = None
        
        if self.db_storage:
            self.db_storage.close()
        
        if self.result:
            self.result.end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            if self.result.start_time and self.result.end_time:
                start = datetime.strptime(self.result.start_time, "%Y-%m-%d %H:%M:%S")
                end = datetime.strptime(self.result.end_time, "%Y-%m-%d %H:%M:%S")
                self.result.duration = (end - start).total_seconds()
    
    @property
    def is_running(self) -> bool:
        """是否正在运行"""
        return self._running


async def run_scan(config: ScannerConfig) -> ScanResult:
    """运行扫描的便捷函数"""
    scanner = ChkApiScanner(config)
    return await scanner.run()
