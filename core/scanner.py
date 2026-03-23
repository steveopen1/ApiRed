"""
Scanner Module
主扫描器模块
"""

import asyncio
import json
import time
import logging
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field, asdict
from datetime import datetime
from urllib.parse import urlparse
import os

logger = logging.getLogger(__name__)

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
from .models import ScanResult, APIEndpoint, Vulnerability, SensitiveData, APIStatus
from .utils.api_spec_parser import APISpecParser


# API Spec URL patterns that indicate the target is an API specification
API_SPEC_PATTERNS = [
    r'/swagger\.json$',
    r'/swagger\.yaml$',
    r'/swagger\.yml$',
    r'/openapi\.json$',
    r'/openapi\.yaml$',
    r'/openapi\.yml$',
    r'/api-docs\.json$',
    r'/api-docs\.yaml$',
    r'/api-docs\.yml$',
    r'/v1/api-docs$',
    r'/v2/api-docs$',
    r'/v3/api-docs$',
    r'/docs\.json$',
    r'/swagger-ui',
    r'/swagger-ui\.html$',
    r'/swagger-resources',
    r'/swagger-resources/v1',
    r'/grub/swagger',
]


def is_api_spec_url(url: str) -> bool:
    """检查 URL 是否可能是 API 规范"""
    import re
    url_lower = url.lower()
    for pattern in API_SPEC_PATTERNS:
        if re.search(pattern, url_lower):
            return True
    return False


@dataclass
class ScanCheckpoint:
    """扫描检查点"""
    target: str
    current_stage: str
    stage_results: Dict[str, Any]
    js_cache_state: List[Dict]
    discovered_apis: List[Dict]
    tested_apis: List[Dict]
    vulnerabilities: List[Dict]
    timestamp: float


@dataclass
class MultiTargetConfig:
    """多目标扫描配置"""
    targets: List[str] = field(default_factory=list)
    target_file: Optional[str] = None
    max_concurrent_targets: int = 5
    share_cache: bool = True


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
    resume: bool = False
    checkpoint_file: Optional[str] = None
    verify_ssl: bool = True
    targets: List[str] = field(default_factory=list)
    concurrent_targets: int = 5
    aggregate: bool = False


class ChkApiScanner:
    """
    主扫描器

    .. deprecated::
        ChkApiScanner 已废弃，请使用 ScanEngine 代替。
        ScanEngine 提供了更完整的架构、更好的性能和更多功能。
        
        示例::
            from core.engine import ScanEngine, EngineConfig
            config = EngineConfig(target="http://example.com")
            engine = ScanEngine(config)
            result = await engine.run()
    """
    
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
        self.fuzz_tester: Optional[FuzzTester] = None
        self.vulnerability_tester: Optional[VulnerabilityTester] = None
        
        self.result: Optional[ScanResult] = None
        self._running = False
        self._current_stage: str = "initialization"
        self._checkpoint: Optional[ScanCheckpoint] = None
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
            except Exception as e:
                logger.debug(f"Callback error for event '{event}': {e}")
    
    async def initialize(self):
        """初始化扫描器"""
        self._running = True
        
        target_parsed = urlparse(self.config.target)
        folder_name = self.config.target.replace('://', '_').replace('/', '_').replace('.', '_')
        results_dir = f"./results/{folder_name}"
        
        if not os.path.exists(results_dir):
            os.makedirs(results_dir, exist_ok=True)
        
        if self.config.checkpoint_file is None:
            self.config.checkpoint_file = os.path.join(results_dir, "scan_state.json")
        
        self.db_storage = DBStorage(
            db_path=f"{results_dir}/results.db",
            wal_mode=True
        )
        
        self.file_storage = FileStorage(
            base_dir=results_dir
        )
        
        self.http_client = AsyncHttpClient(
            max_concurrent=self.config.concurrency,
            max_retries=3,
            timeout=30,
            proxy=self.config.proxy,
            verify_ssl=self.config.verify_ssl
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
        
        self.fuzz_tester = FuzzTester(self.http_client)
        self.vulnerability_tester = VulnerabilityTester(self.http_client)
        
        self.result = ScanResult(
            target_url=self.config.target,
            start_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
    
    async def run(self) -> ScanResult:
        """执行扫描"""
        await self.initialize()
        
        if self.config.resume and self.config.checkpoint_file:
            checkpoint = self._load_checkpoint()
            if checkpoint:
                self._restore_from_checkpoint(checkpoint)
        
        try:
            self._emit('stage_start', {'stage': 'initialization', 'status': 'complete'})
            
            stages_to_run = []
            
            if self.config.attack_mode in ['collect', 'all']:
                if self._current_stage in ['initialization', 'js_collection']:
                    stages_to_run.append(self._stage1_js_collection)
                if self._current_stage in ['initialization', 'js_collection', 'api_extraction']:
                    stages_to_run.append(self._stage2_api_extraction)
            
            if self.config.attack_mode in ['scan', 'all'] and not self.config.no_api_scan:
                if self._current_stage in ['initialization', 'js_collection', 'api_extraction', 'api_testing']:
                    stages_to_run.append(self._stage3_api_testing)
                if self._current_stage in ['initialization', 'js_collection', 'api_extraction', 'api_testing', 'vulnerability_testing']:
                    stages_to_run.append(self._stage4_vulnerability_testing)
            
            if self._current_stage in ['initialization', 'js_collection', 'api_extraction', 'api_testing', 'vulnerability_testing', 'reporting']:
                stages_to_run.append(self._stage5_reporting)
            
            for stage_method in stages_to_run:
                await stage_method()
                await self._save_checkpoint()
            
            if not stages_to_run:
                await self._stage5_reporting()
                await self._save_checkpoint()

        except Exception as e:
            self.result.errors.append(str(e))
        
        finally:
            await self._save_checkpoint()
            await self.cleanup()
        
        return self.result
    
    async def _stage1_js_collection(self):
        """阶段1：JS采集"""
        self._current_stage = 'js_collection'
        self._emit('stage_start', {'stage': 'js_collection', 'status': 'running'})
        
        start_time = time.time()
        
        response = await self.http_client.request(
            self.config.target,
            headers={'Cookie': self.config.cookies} if self.config.cookies else None
        )
        
        js_urls = self._extract_js_urls(response.content)
        
        alive_js = []
        js_parser = JSParser(self.js_cache)
        for js_url in js_urls:
            js_response = await self.http_client.request(js_url)
            if js_response.status_code == 200:
                js_content = js_response.content
                alive_js.append({
                    'url': js_url,
                    'content': js_content
                })
                try:
                    js_parser.parse(js_content, js_url)
                except Exception as e:
                    logger.debug(f"JS parse error for {js_url}: {e}")
        
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
        self._current_stage = 'api_extraction'
        self._emit('stage_start', {'stage': 'api_extraction', 'status': 'running'})
        
        start_time = time.time()
        
        # Check if target URL is an API spec and parse it
        spec_endpoints_count = 0
        if is_api_spec_url(self.config.target):
            try:
                logger.info(f"Detected API spec URL: {self.config.target}, using APISpecParser")
                parser = APISpecParser(self.http_client)
                spec_result = await parser.discover_and_parse(self.config.target)
                if spec_result:
                    logger.info(f"Parsed {len(spec_result.endpoints)} endpoints from API spec")
                    for api_endpoint in spec_result.endpoints:
                        from .collectors.api_collector import APIFindResult
                        api_find_result = APIFindResult(
                            path=api_endpoint.path,
                            method=api_endpoint.method,
                            source_type="api_spec_parser",
                            base_url=spec_result.api_base_path or "",
                            url_type="api_path"
                        )
                        self.api_aggregator.add_api(
                            api_find_result,
                            source_info={'source': f'api_spec:{spec_result.spec_type}'}
                        )
                        spec_endpoints_count += 1
                else:
                    logger.warning(f"Failed to parse API spec from {self.config.target}")
            except Exception as e:
                logger.error(f"Error parsing API spec: {e}")
        
        js_results = self.js_cache.get_all()
        input_count = len(js_results)
        error_count = 0
        
        for js_result in js_results:
            try:
                for api_path in js_result.apis:
                    from .collectors.api_collector import APIFindResult
                    api_find_result = APIFindResult(
                        path=api_path,
                        method="GET",
                        source_type="js_parser",
                        base_url="",
                        url_type="api_path"
                    )
                    self.api_aggregator.add_api(
                        api_find_result,
                        source_info={'source': 'js_fingerprint_cache'}
                    )
            except Exception as e:
                logger.debug(f"API extraction error: {e}")
        
        raw_endpoints = self.api_aggregator.get_all()
        
        from .collectors.api_collector import APIPathCombiner, BaseURLAnalyzer, ServiceAnalyzer
        final_endpoints = []
        for endpoint in raw_endpoints:
            full_url = APIPathCombiner.combine_base_and_path(
                endpoint.base_url or "",
                endpoint.path
            )
            
            from .models import APIEndpoint as APIEndpointModel
            api_endpoint = APIEndpointModel(
                path=endpoint.path,
                method=endpoint.method,
                base_url=endpoint.base_url,
                full_url=full_url,
                sources=[],
                service_key=ServiceAnalyzer.extract_service_key(full_url, endpoint.path)
            )
            final_endpoints.append(api_endpoint)
        
        if self.result:
            self.result.api_endpoints = final_endpoints
        
        duration = time.time() - start_time
        
        self._record_stage_stats(
            'stage2_api_extraction',
            start_time,
            time.time(),
            input_count,
            len(final_endpoints),
            error_count
        )
        
        self._emit('stage_complete', {
            'stage': 'api_extraction',
            'duration': duration,
            'extracted': len(final_endpoints)
        })
    
    async def _stage3_api_testing(self):
        """阶段3：API测试"""
        self._current_stage = 'api_testing'
        self._emit('stage_start', {'stage': 'api_testing', 'status': 'running'})
        
        start_time = time.time()
        
        endpoints = self.result.api_endpoints if self.result else []
        input_count = len(endpoints)
        tested_endpoints = []
        error_count = 0
        
        for endpoint in endpoints:
            for method in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                try:
                    response = await self.http_client.request(
                        endpoint.full_url,
                        method=method
                    )
                    
                    from core.analyzers.response_cluster import TaskResult as RCTaskResult
                    rc_task_result = RCTaskResult(
                        status_code=response.status_code,
                        content=response.content.encode() if isinstance(response.content, str) else response.content,
                        content_hash=response.content_hash
                    )
                    self.response_cluster.add_response(endpoint.api_id, rc_task_result)
                    
                    if not self.response_cluster.is_baseline_404(endpoint.api_id):
                        endpoint.method = method
                        endpoint.status = APIStatus.ALIVE
                        tested_endpoints.append(endpoint)
                        
                        self.api_scorer.add_evidence(
                            endpoint.full_url,
                            'http_test',
                            {'status': response.status_code, 'content': response.content[:500] if response.content else ''}
                        )
                        break
                except Exception as e:
                    logger.debug(f"API testing error for {endpoint.full_url}: {e}")
        
        high_value_apis = self.api_scorer.get_high_value() if self.api_scorer else []
        
        end_time = time.time()
        self._record_stage_stats(
            'stage3_api_testing',
            start_time,
            end_time,
            input_count,
            len(tested_endpoints),
            error_count
        )
        
        self._emit('stage_complete', {
            'stage': 'api_testing',
            'duration': end_time - start_time,
            'tested': len(tested_endpoints),
            'high_value': len(high_value_apis)
        })
    
    async def _stage4_vulnerability_testing(self):
        """阶段4：漏洞测试"""
        self._current_stage = 'vulnerability_testing'
        self._emit('stage_start', {'stage': 'vulnerability_testing', 'status': 'running'})
        
        start_time = time.time()
        
        high_value_apis = [e for e in self.result.api_endpoints if e.is_high_value]
        high_value_api_ids = {e.api_id for e in high_value_apis}
        
        input_count = len(high_value_apis)
        vulnerability_count = 0
        sensitive_count = 0
        error_count = 0
        responses_collected = []
        
        for endpoint in high_value_apis:
            try:
                response = await self.http_client.request(
                    endpoint.full_url,
                    method=endpoint.method
                )
                
                responses_collected.append({
                    'content': response.content,
                    'url': endpoint.full_url,
                    'api_id': endpoint.api_id
                })
                
                fuzz_params = endpoint.parameters if endpoint.parameters else ['id', 'page']
                fuzz_results = await self.fuzz_tester.fuzz_parameters(
                    endpoint.full_url,
                    endpoint.method,
                    fuzz_params
                )
                
                for fuzz_result in fuzz_results:
                    if fuzz_result.is_different:
                        vuln_result = await self.vulnerability_tester.test_unauthorized_access(
                            fuzz_result.url,
                            fuzz_result.method
                        )
                        
                        if vuln_result.is_vulnerable:
                            from .models import Vulnerability, Severity
                            
                            vuln = Vulnerability(
                                api_id=endpoint.api_id,
                                vuln_type=vuln_result.vuln_type.value,
                                severity=Severity[vuln_result.severity.upper()] if isinstance(vuln_result.severity, str) else vuln_result.severity,
                                evidence=vuln_result.evidence,
                                payload=vuln_result.payload,
                                remediation=vuln_result.remediation,
                                cwe_id=vuln_result.cwe_id
                            )
                            self.result.vulnerabilities.append(vuln)
                            vulnerability_count += 1
                            
                            self._emit('finding', {
                                'type': 'vulnerability',
                                'vuln_type': vuln.vuln_type,
                                'api_id': vuln.api_id,
                                'severity': vuln.severity.value
                            })
                
                ssrf_result = await self.vulnerability_tester.test_ssrf(endpoint.full_url)
                if ssrf_result.is_vulnerable:
                    from .models import Vulnerability, Severity
                    
                    vuln = Vulnerability(
                        api_id=endpoint.api_id,
                        vuln_type=ssrf_result.vuln_type.value,
                        severity=Severity[ssrf_result.severity.upper()] if isinstance(ssrf_result.severity, str) else ssrf_result.severity,
                        evidence=ssrf_result.evidence,
                        payload=ssrf_result.payload,
                        remediation=ssrf_result.remediation,
                        cwe_id=ssrf_result.cwe_id
                    )
                    self.result.vulnerabilities.append(vuln)
                    vulnerability_count += 1
                    
                    self._emit('finding', {
                        'type': 'vulnerability',
                        'vuln_type': vuln.vuln_type,
                        'api_id': vuln.api_id,
                        'severity': vuln.severity.value
                    })
                
                info_disclosure = await self.vulnerability_tester.test_information_disclosure(
                    endpoint.full_url
                )
                if info_disclosure.is_vulnerable:
                    from .models import Vulnerability, Severity
                    
                    vuln = Vulnerability(
                        api_id=endpoint.api_id,
                        vuln_type=info_disclosure.vuln_type.value,
                        severity=Severity[info_disclosure.severity.upper()] if isinstance(info_disclosure.severity, str) else info_disclosure.severity,
                        evidence=info_disclosure.evidence,
                        payload=info_disclosure.payload,
                        remediation=info_disclosure.remediation,
                        cwe_id=info_disclosure.cwe_id
                    )
                    self.result.vulnerabilities.append(vuln)
                    vulnerability_count += 1
                    
                    self._emit('finding', {
                        'type': 'vulnerability',
                        'vuln_type': vuln.vuln_type,
                        'api_id': vuln.api_id,
                        'severity': vuln.severity.value
                    })
            
            except Exception as e:
                logger.debug(f"API extraction error: {e}")
        
        sensitive_findings = await self.sensitive_detector.detect(
            responses_collected,
            high_value_api_ids
        )
        sensitive_count = len(sensitive_findings)
        
        for finding in sensitive_findings:
            from .models import SensitiveData
            
            sensitive_data = SensitiveData(
                api_id=finding.location,
                data_type=finding.data_type,
                matches=finding.matches,
                severity=finding.severity,
                evidence=finding.evidence,
                context=finding.context,
                location=finding.location
            )
            self.result.sensitive_data.append(sensitive_data)
            
            self._emit('finding', {
                'type': 'sensitive_data',
                'data_type': finding.data_type,
                'location': finding.location,
                'severity': finding.severity.value
            })
        
        end_time = time.time()
        self._record_stage_stats(
            'stage4_vulnerability_testing',
            start_time,
            end_time,
            input_count,
            vulnerability_count + sensitive_count,
            error_count
        )
        
        self._emit('stage_complete', {
            'stage': 'vulnerability_testing',
            'duration': end_time - start_time,
            'vulnerabilities': vulnerability_count,
            'sensitive_data': sensitive_count
        })
    
    async def _stage5_reporting(self):
        """阶段5：报告生成"""
        self._current_stage = 'reporting'
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
    
    async def _save_checkpoint(self):
        """保存扫描检查点"""
        if not self.config.checkpoint_file:
            return
        
        js_cache_state = []
        if self.js_cache:
            js_results = self.js_cache.get_all() if hasattr(self.js_cache, 'get_all') else []
            for js_result in js_results:
                js_cache_state.append({
                    'url': getattr(js_result, 'url', ''),
                    'apis': getattr(js_result, 'apis', []),
                    'endpoints': getattr(js_result, 'endpoints', [])
                })
        
        discovered_apis = []
        if self.result and self.result.api_endpoints:
            for api in self.result.api_endpoints:
                discovered_apis.append({
                    'path': api.path,
                    'method': api.method,
                    'base_url': api.base_url,
                    'full_url': api.full_url,
                    'api_id': api.api_id,
                    'is_high_value': api.is_high_value
                })
        
        tested_apis = []
        if self.api_scorer and hasattr(self.api_scorer, 'get_high_value'):
            for api in self.api_scorer.get_high_value():
                tested_apis.append({
                    'path': api.path,
                    'method': api.method,
                    'full_url': api.full_url,
                    'api_id': api.api_id
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
            current_stage=self._current_stage,
            stage_results=dict(self.result.statistics) if self.result else {},
            js_cache_state=js_cache_state,
            discovered_apis=discovered_apis,
            tested_apis=tested_apis,
            vulnerabilities=vulnerabilities,
            timestamp=time.time()
        )
        
        checkpoint_path = self.config.checkpoint_file
        os.makedirs(os.path.dirname(checkpoint_path), exist_ok=True)
        with open(checkpoint_path, 'w', encoding='utf-8') as f:
            json.dump(asdict(self._checkpoint), f, indent=2, ensure_ascii=False)
    
    def _load_checkpoint(self) -> Optional[ScanCheckpoint]:
        """从文件加载检查点"""
        if not self.config.checkpoint_file or not os.path.exists(self.config.checkpoint_file):
            return None
        
        try:
            with open(self.config.checkpoint_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            checkpoint = ScanCheckpoint(
                target=data.get('target', ''),
                current_stage=data.get('current_stage', 'initialization'),
                stage_results=data.get('stage_results', {}),
                js_cache_state=data.get('js_cache_state', []),
                discovered_apis=data.get('discovered_apis', []),
                tested_apis=data.get('tested_apis', []),
                vulnerabilities=data.get('vulnerabilities', []),
                timestamp=data.get('timestamp', 0.0)
            )
            return checkpoint
        except Exception as e:
            logger.warning(f"Failed to load checkpoint: {e}")
            return None
    
    def _restore_from_checkpoint(self, checkpoint: ScanCheckpoint):
        """从检查点恢复状态"""
        self._current_stage = checkpoint.current_stage
        
        if self.result:
            self.result.statistics = checkpoint.stage_results
            
            self.result.vulnerabilities = []
            for vuln_data in checkpoint.vulnerabilities:
                from .models import Vulnerability, Severity
                vuln = Vulnerability(
                    api_id=vuln_data.get('api_id', ''),
                    vuln_type=vuln_data.get('vuln_type', ''),
                    severity=Severity[vuln_data.get('severity', 'MEDIUM').upper()] if isinstance(vuln_data.get('severity'), str) else vuln_data.get('severity', Severity.MEDIUM),
                    evidence=vuln_data.get('evidence', ''),
                    payload=vuln_data.get('payload'),
                    remediation=vuln_data.get('remediation', ''),
                    cwe_id=vuln_data.get('cwe_id')
                )
                self.result.vulnerabilities.append(vuln)
    
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
    
    async def run_single_target(self, target: str) -> ScanResult:
        """扫描单个目标"""
        config = ScannerConfig(
            target=target,
            cookies=self.config.cookies,
            chrome=self.config.chrome,
            attack_mode=self.config.attack_mode,
            no_api_scan=self.config.no_api_scan,
            dedupe=self.config.dedupe,
            store=self.config.store,
            proxy=self.config.proxy,
            js_depth=self.config.js_depth,
            ai_scan=self.config.ai_scan,
            concurrency=self.config.concurrency,
            output_format=self.config.output_format,
            resume=self.config.resume
        )
        scanner = ChkApiScanner(config)
        return await scanner.run()
    
    async def run_multiple(self, targets: List[str]) -> List[ScanResult]:
        """扫描多个目标"""
        semaphore = asyncio.Semaphore(self.config.concurrency)
        
        async def scan_with_limit(target):
            async with semaphore:
                return await self.run_single_target(target)
        
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


async def run_multi_target(targets: List[str], config: MultiTargetConfig) -> List[ScanResult]:
    """
    并行扫描多个目标
    
    .. deprecated::
        此函数已废弃，请使用 engine.run_multi_target 代替。
    
    Args:
        targets: 目标 URL 列表
        config: 多目标配置
    
    Returns:
        所有扫描结果的列表
    """
    import warnings
    warnings.warn(
        "scanner.run_multi_target 已废弃，请使用 engine.run_multi_target 代替",
        DeprecationWarning,
        stacklevel=2
    )
    
    scanner_config = ScannerConfig(
        target=targets[0] if targets else "",
        cookies="",
        chrome=True,
        attack_mode="all",
        concurrency=config.max_concurrent_targets
    )
    
    scanner = ChkApiScanner(scanner_config)
    return await scanner.run_multiple(targets)


async def run_scan(config: ScannerConfig) -> ScanResult:
    """
    运行扫描的便捷函数
    
    .. deprecated::
        此函数已废弃，请使用 ScanEngine 代替。
    """
    import warnings
    warnings.warn(
        "scanner.run_scan 已废弃，请使用 ScanEngine 代替",
        DeprecationWarning,
        stacklevel=2
    )
    
    scanner = ChkApiScanner(config)
    return await scanner.run()
