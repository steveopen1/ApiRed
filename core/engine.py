"""
ScanEngine - 统一扫描引擎
提供Collector → Analyzer → Tester的标准化流程
"""

import asyncio
import time
import os
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime
from urllib.parse import urlparse

from .utils.config import Config
from .storage import DBStorage, FileStorage
from .collectors import JSFingerprintCache, JSParser, APIAggregator
from .collectors.api_collector import APIPathCombiner, ServiceAnalyzer
from .analyzers import APIScorer, APIEvidenceAggregator, ResponseCluster, TwoTierSensitiveDetector
from .analyzers.response_baseline import ResponseBaselineLearner
from .testers import FuzzTester, VulnerabilityTester
from .agents import ScannerAgent, AnalyzerAgent, TesterAgent, AgentConfig
from .models import ScanResult, APIEndpoint
from .framework import FrameworkRuleEngine


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
        
        self.result: Optional[ScanResult] = None
        self._current_stage = 0
        self._running = False
        self._checkpoint: Optional[ScanCheckpoint] = None
        
        self._stage_names = ["collect", "analyze", "test"]
    
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
            proxy=self.config.proxy
        )
        
        self._js_cache = JSFingerprintCache(self.db_storage)
        self._api_aggregator = APIAggregator()
        self._api_scorer = APIScorer(
            min_high_value_score=self.cfg.get('ai.thresholds.high_value_api_score', 5)
        )
        self._evidence_aggregator = APIEvidenceAggregator(self._api_scorer)
        self._response_cluster = ResponseCluster()
        self._response_baseline = ResponseBaselineLearner()
        self._framework_detector = FrameworkRuleEngine()
        self._detected_framework = None
        self._sensitive_detector = TwoTierSensitiveDetector(
            config={'ai_enabled': self.config.ai_enabled}
        )
        
        self._fuzz_tester = FuzzTester(self._http_client)
        self._vulnerability_tester = VulnerabilityTester(self._http_client)
        
        if self.config.ai_enabled:
            from .ai.ai_engine import AIEngine
            llm_client = AIEngine()
            scanner_config = AgentConfig(name="ScannerAgent")
            analyzer_config = AgentConfig(name="AnalyzerAgent")
            tester_config = AgentConfig(name="TesterAgent")
            self.scanner_agent = ScannerAgent(scanner_config, llm_client)
            self.analyzer_agent = AnalyzerAgent(analyzer_config, llm_client)
            self.tester_agent = TesterAgent(tester_config, llm_client)
        
        self.result = ScanResult(
            target_url=self.config.target,
            start_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
    
    async def run(self) -> ScanResult:
        """运行扫描流程"""
        await self.initialize()
        
        try:
            await self._run_collectors()
            if self.config.checkpoint_enabled:
                await self._save_checkpoint()
            
            await self._run_analyzers()
            if self.config.checkpoint_enabled:
                await self._save_checkpoint()
            
            await self._run_testers()
            if self.config.checkpoint_enabled:
                await self._save_checkpoint()
            
            await self._stage_reporting()
            
            if self.result:
                self.result.status = "completed"
        
        except Exception as e:
            if self.result:
                self.result.errors.append(str(e))
                self.result.status = "failed"
        
        finally:
            await self.cleanup()
        
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
        """采集JS资源 + 框架检测"""
        from .utils.http_client import AsyncHttpClient
        
        response = await self._http_client.request(
            self.config.target,
            headers={'Cookie': self.config.cookies} if self.config.cookies else None
        )
        
        js_urls = self._extract_js_urls(response.content)
        alive_js = []
        js_parser = JSParser(self._js_cache)
        js_content_all = ""
        
        for js_url in js_urls:
            try:
                js_response = await self._http_client.request(js_url)
                if js_response.status_code == 200:
                    js_content = js_response.content
                    js_content_all += js_content + "\n"
                    alive_js.append({'url': js_url, 'content': js_content})
                    try:
                        js_parser.parse(js_content, js_url)
                    except Exception:
                        pass
            except Exception:
                pass
        
        target_info = {
            'js_files': ','.join(js_urls),
            'api_paths': js_content_all[:1000],
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
    
    async def _extract_apis(self) -> Dict[str, Any]:
        """提取API端点 + 基于框架生成更多端点"""
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
            except Exception:
                pass
        
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
                            {'status': response.status_code, 'content': response.content[:500] if response.content else ''}
                        )
            except Exception:
                pass
        
        high_value_apis = self._api_scorer.get_high_value() if self._api_scorer else []
        
        if self.result:
            self.result.alive_apis = len(high_value_apis)
            self.result.high_value_apis = len(high_value_apis)
        
        return {
            'alive_apis': len(high_value_apis),
            'high_value_apis': len(high_value_apis)
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
            except Exception:
                pass
        
        sensitive_findings = await self._sensitive_detector.detect(
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
            except Exception:
                pass
        
        return {
            'fuzz_count': fuzz_count,
            'results': [r.to_dict() if hasattr(r, 'to_dict') else str(r) for r in fuzz_results]
        }
    
    async def _run_vuln_test(self) -> Dict[str, Any]:
        """漏洞测试"""
        high_value_apis = [e for e in self.result.api_endpoints if e.is_high_value] if self.result else []
        
        vuln_count = 0
        from .models import Severity
        
        for endpoint in high_value_apis:
            try:
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
            except Exception:
                pass
        
        return {
            'vuln_count': vuln_count,
            'vulnerabilities': [v.to_dict() for v in self.result.vulnerabilities] if self.result else []
        }
    
    async def _stage_reporting(self):
        """报告生成阶段"""
        if self.file_storage and self.result:
            self.file_storage.save_json(
                self.result.to_dict(),
                'scan_result.json'
            )
    
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
