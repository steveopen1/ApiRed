"""
Pipeline Module
处理流水线模块
"""

import logging
import time
from typing import Dict, List, Any, Optional, Callable, Iterator
from dataclasses import dataclass, field
from enum import Enum
import threading

logger = logging.getLogger(__name__)


class PipelineStage(Enum):
    """流水线阶段"""
    INITIALIZATION = "initialization"
    JS_COLLECTION = "js_collection"
    API_EXTRACTION = "api_extraction"
    API_TESTING = "api_testing"
    VULNERABILITY_TESTING = "vulnerability_testing"
    SENSITIVE_DETECTION = "sensitive_detection"
    REPORTING = "reporting"


@dataclass
class PipelineContext:
    """流水线上下文"""
    target: str
    cookies: str = ""
    proxy: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    js_urls: List[str] = field(default_factory=list)
    alive_js: List[Dict[str, str]] = field(default_factory=list)
    api_paths: List[str] = field(default_factory=list)
    api_endpoints: List[Dict[str, Any]] = field(default_factory=list)
    high_value_apis: List[str] = field(default_factory=list)
    
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    sensitive_data: List[Dict[str, Any]] = field(default_factory=list)
    
    stage_stats: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


@dataclass 
class StageResult:
    """阶段结果"""
    stage: PipelineStage
    success: bool
    duration: float
    input_count: int = 0
    output_count: int = 0
    errors: List[str] = field(default_factory=list)
    data: Dict[str, Any] = field(default_factory=dict)


class PipelineStageHandler:
    """流水线阶段处理器基类"""
    
    def __init__(self, name: PipelineStage):
        self.name = name
        self._next: Optional['PipelineStageHandler'] = None
    
    def set_next(self, handler: 'PipelineStageHandler') -> 'PipelineStageHandler':
        """设置下一个处理器"""
        self._next = handler
        return handler
    
    async def process(self, context: PipelineContext) -> StageResult:
        """处理阶段"""
        raise NotImplementedError
    
    async def execute_next(self, context: PipelineContext) -> Optional[StageResult]:
        """执行下一个阶段"""
        if self._next:
            return await self._next.process(context)
        return None


class InitializationStage(PipelineStageHandler):
    """初始化阶段"""
    
    async def process(self, context: PipelineContext) -> StageResult:
        start_time = time.time()
        
        try:
            context.metadata['start_time'] = time.time()
            
            return StageResult(
                stage=self.name,
                success=True,
                duration=time.time() - start_time,
                data={'initialized': True}
            )
        except Exception as e:
            return StageResult(
                stage=self.name,
                success=False,
                duration=time.time() - start_time,
                errors=[str(e)]
            )


class JSCollectionStage(PipelineStageHandler):
    """JS采集阶段"""
    
    def __init__(self, http_client=None):
        super().__init__(PipelineStage.JS_COLLECTION)
        self.http_client = http_client
    
    async def process(self, context: PipelineContext) -> StageResult:
        start_time = time.time()
        
        try:
            from .utils.http_client import AsyncHttpClient
            
            client = self.http_client or AsyncHttpClient()
            
            response = await client.request(context.target)
            
            if response.status_code == 200:
                import re
                script_pattern = re.compile(
                    r'<script[^>]+src=["\']([^"\']+)["\']',
                    re.IGNORECASE
                )
                js_urls = script_pattern.findall(response.content)
                context.js_urls = js_urls
            
            return StageResult(
                stage=self.name,
                success=True,
                duration=time.time() - start_time,
                input_count=1,
                output_count=len(context.js_urls),
                data={'js_urls': context.js_urls}
            )
        except Exception as e:
            return StageResult(
                stage=self.name,
                success=False,
                duration=time.time() - start_time,
                errors=[str(e)]
            )


class APIExtractionStage(PipelineStageHandler):
    """API提取阶段"""
    
    def __init__(self, js_parser=None):
        super().__init__(PipelineStage.API_EXTRACTION)
        self.js_parser = js_parser
    
    async def process(self, context: PipelineContext) -> StageResult:
        start_time = time.time()
        
        try:
            from .collectors.api_collector import APIAggregator, APIRouter
            
            aggregator = APIAggregator()
            
            for js_info in context.alive_js:
                content = js_info.get('content', '')
                urls = APIRouter.extract_routes(content)
                
                for url in urls:
                    from .collectors.api_collector import APIFindResult
                    aggregator.add_api(APIFindResult(
                        path=url,
                        method='GET',
                        source_type='js_regex'
                    ))
            
            apis = aggregator.get_all()
            context.api_paths = [a.path for a in apis]
            
            return StageResult(
                stage=self.name,
                success=True,
                duration=time.time() - start_time,
                input_count=len(context.alive_js),
                output_count=len(context.api_paths),
                data={'api_paths': context.api_paths}
            )
        except Exception as e:
            return StageResult(
                stage=self.name,
                success=False,
                duration=time.time() - start_time,
                errors=[str(e)]
            )


class APITestingStage(PipelineStageHandler):
    """API测试阶段"""
    
    def __init__(self, http_client=None):
        super().__init__(PipelineStage.API_TESTING)
        self.http_client = http_client
    
    async def process(self, context: PipelineContext) -> StageResult:
        start_time = time.time()
        
        try:
            from .analyzers.response_cluster import ResponseCluster
            
            cluster = ResponseCluster()
            
            return StageResult(
                stage=self.name,
                success=True,
                duration=time.time() - start_time,
                input_count=len(context.api_paths),
                output_count=0,
                data={'tested_apis': len(context.api_paths)}
            )
        except Exception as e:
            return StageResult(
                stage=self.name,
                success=False,
                duration=time.time() - start_time,
                errors=[str(e)]
            )


class SensitiveDetectionStage(PipelineStageHandler):
    """敏感信息检测阶段"""
    
    def __init__(self, detector=None):
        super().__init__(PipelineStage.SENSITIVE_DETECTION)
        self.detector = detector
    
    async def process(self, context: PipelineContext) -> StageResult:
        start_time = time.time()
        
        try:
            from .analyzers.sensitive_detector import TwoTierSensitiveDetector
            
            detector = self.detector or TwoTierSensitiveDetector()
            
            return StageResult(
                stage=self.name,
                success=True,
                duration=time.time() - start_time,
                input_count=len(context.api_endpoints),
                output_count=len(context.sensitive_data),
                data={'sensitive_data': context.sensitive_data}
            )
        except Exception as e:
            return StageResult(
                stage=self.name,
                success=False,
                duration=time.time() - start_time,
                errors=[str(e)]
            )


class ReportingStage(PipelineStageHandler):
    """报告生成阶段"""
    
    def __init__(self, storage=None):
        super().__init__(PipelineStage.REPORTING)
        self.storage = storage
    
    async def process(self, context: PipelineContext) -> StageResult:
        start_time = time.time()
        
        try:
            if self.storage:
                self.storage.save_json(
                    context.metadata,
                    'pipeline_context.json'
                )
            
            return StageResult(
                stage=self.name,
                success=True,
                duration=time.time() - start_time,
                data={'report_generated': True}
            )
        except Exception as e:
            return StageResult(
                stage=self.name,
                success=False,
                duration=time.time() - start_time,
                errors=[str(e)]
            )


class ScanPipeline:
    """扫描流水线"""
    
    def __init__(self):
        self._stages: List[PipelineStageHandler] = []
        self._context: Optional[PipelineContext] = None
        self._results: List[StageResult] = []
        self._listeners: Dict[str, List[Callable]] = {
            'stage_start': [],
            'stage_complete': [],
            'pipeline_complete': []
        }
    
    def add_stage(self, handler: PipelineStageHandler) -> 'ScanPipeline':
        """添加阶段"""
        self._stages.append(handler)
        return self
    
    def on(self, event: str, listener: Callable) -> 'ScanPipeline':
        """注册事件监听"""
        if event in self._listeners:
            self._listeners[event].append(listener)
        return self
    
    def _emit(self, event: str, data: Any):
        """触发事件"""
        for listener in self._listeners.get(event, []):
            try:
                listener(data)
            except Exception as e:
                logger.debug(f"Pipeline error: {e}")
    
    async def run(self, target: str, **kwargs) -> PipelineContext:
        """运行流水线"""
        self._context = PipelineContext(target=target, **kwargs)
        self._results = []
        
        for handler in self._stages:
            self._emit('stage_start', {'stage': handler.name.value})
            
            result = await handler.process(self._context)
            self._results.append(result)
            
            self._context.stage_stats.append({
                'stage': result.stage.value,
                'success': result.success,
                'duration': result.duration,
                'input': result.input_count,
                'output': result.output_count,
                'errors': result.errors
            })
            
            self._emit('stage_complete', {
                'stage': handler.name.value,
                'result': result
            })
            
            if not result.success:
                self._context.errors.extend(result.errors)
        
        self._emit('pipeline_complete', {
            'context': self._context,
            'results': self._results
        })
        
        return self._context
    
    @property
    def context(self) -> Optional[PipelineContext]:
        """获取上下文"""
        return self._context
    
    @property
    def results(self) -> List[StageResult]:
        """获取阶段结果"""
        return self._results


def create_default_pipeline(**kwargs) -> ScanPipeline:
    """创建默认流水线"""
    pipeline = ScanPipeline()
    
    pipeline.add_stage(InitializationStage(PipelineStage.INITIALIZATION))
    pipeline.add_stage(JSCollectionStage())
    pipeline.add_stage(APIExtractionStage())
    pipeline.add_stage(APITestingStage())
    pipeline.add_stage(SensitiveDetectionStage())
    pipeline.add_stage(ReportingStage())
    
    return pipeline
