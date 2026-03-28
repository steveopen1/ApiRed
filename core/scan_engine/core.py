"""
ScanEngine Core Module
核心运行流程、初始化、事件机制、检查点、清理
"""

import asyncio
import time
import os
import logging
from typing import Dict, List, Optional, Any, Set, Callable
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


class ScanEngineCore:
    """
    ScanEngine 核心模块
    
    职责：
    1. 初始化所有组件
    2. 事件机制（注册、触发）
    3. 主运行流程（collect -> analyze -> test -> reporting）
    4. 检查点保存/加载
    5. 资源清理
    """
    
    def __init__(self, config: 'EngineConfig'):
        self.config = config
        self._running = False
        self._stage = "idle"
        self._callbacks: Dict[str, List[Callable]] = {}
        self._tasks: Dict[str, Any] = {}
        
        self._http_client = None
        self._storage = None
        self._output_manager = None
        
        self._collector = None
        self._analyzer = None
        self._tester = None
        self._reporter = None
        
    @property
    def current_stage_name(self) -> str:
        return self._stage
    
    @property
    def is_running(self) -> bool:
        return self._running
    
    def on(self, event: str, callback: Callable):
        """注册事件回调"""
        if event not in self._callbacks:
            self._callbacks[event] = []
        self._callbacks[event].append(callback)
    
    def _emit(self, event: str, data: Any = None):
        """触发事件"""
        if event in self._callbacks:
            for callback in self._callbacks[event]:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        asyncio.create_task(callback(data))
                    else:
                        callback(data)
                except Exception as e:
                    logger.debug(f"Event callback error for {event}: {e}")
    
    def _emit_progress(self, stage: str, percent: int, msg: str = ""):
        """触发进度更新"""
        self._stage = stage
        self._emit('progress', {
            'stage': stage,
            'percent': percent,
            'message': msg,
            'timestamp': datetime.now().isoformat()
        })
    
    def _emit_finding(self, finding_type: str, data: Any):
        """触发发现事件"""
        self._emit('finding', {
            'type': finding_type,
            'data': data,
            'timestamp': datetime.now().isoformat()
        })
    
    def _register_task(self, task_id: str, task: Any):
        """注册进行中的任务"""
        self._tasks[task_id] = task
    
    def _unregister_task(self, task_id: str):
        """取消注册完成的任务"""
        if task_id in self._tasks:
            del self._tasks[task_id]
    
    async def initialize(self) -> bool:
        """
        初始化所有组件
        
        子类或组合模块需要实现自己的初始化逻辑，
        并在完成后调用此方法。
        """
        logger.info(f"Initializing ScanEngine for target: {self.config.target}")
        self._emit_progress("initializing", 5, "Initializing components...")
        
        from ..storage import DBStorage, FileStorage, RealtimeOutput, OutputManager, get_output_manager
        from ..collectors import JSFingerprintCache, JSParser, APIAggregator, HeadlessBrowserCollector
        
        self._http_client = self._create_http_client()
        
        output_dir = getattr(self.config, 'output_dir', './results')
        os.makedirs(output_dir, exist_ok=True)
        
        self._storage = DBStorage(output_dir)
        self._output_manager = get_output_manager(output_dir)
        
        self._collector = self._create_collector()
        self._analyzer = self._create_analyzer()
        self._tester = self._create_tester()
        self._reporter = self._create_reporter()
        
        self._emit_progress("initializing", 10, "Components initialized")
        return True
    
    def _create_http_client(self):
        """创建 HTTP 客户端（子类可覆盖）"""
        from ..utils.http_client import AsyncHttpClient
        return AsyncHttpClient()
    
    def _create_collector(self):
        """创建采集器（子类可覆盖）"""
        from ..collectors import APIAggregator, HeadlessBrowserCollector
        return APIAggregator(self._http_client)
    
    def _create_analyzer(self):
        """创建分析器（子类可覆盖）"""
        from ..analyzers import APIScorer, APIEvidenceAggregator
        return None
    
    def _create_tester(self):
        """创建测试器（子类可覆盖）"""
        from ..testers import FuzzTester, VulnerabilityTester
        return None
    
    def _create_reporter(self):
        """创建报告器（子类可覆盖）"""
        from ..exporters import ReportExporter
        return ReportExporter()
    
    async def run(self) -> 'ScanResult':
        """
        运行扫描流程主方法
        
        流程：collect -> analyze -> test -> reporting
        """
        self._running = True
        task_id = self.config.target
        self._register_task(task_id, asyncio.current_task())
        
        try:
            self._emit_progress("collect", 15, "Starting collection phase...")
            await self._run_collectors()
            
            self._emit_progress("analyze", 50, "Starting analysis phase...")
            await self._run_analyzers()
            
            self._emit_progress("test", 75, "Starting testing phase...")
            await self._run_testers()
            
            self._emit_progress("reporting", 90, "Generating reports...")
            await self._stage_reporting()
            
            self._emit_progress("complete", 100, "Scan completed")
            self._emit('scan_completed', {'target': self.config.target})
            
            return self.result
            
        except Exception as e:
            logger.error(f"Scan error: {e}")
            self._emit('scan_failed', {'target': self.config.target, 'error': str(e)})
            raise
        finally:
            self._running = False
            self._unregister_task(task_id)
    
    async def _run_collectors(self):
        """运行采集阶段（子类实现）"""
        pass
    
    async def _run_analyzers(self):
        """运行分析阶段（子类实现）"""
        pass
    
    async def _run_testers(self):
        """运行测试阶段（子类实现）"""
        pass
    
    async def _stage_reporting(self):
        """报告生成阶段（子类实现）"""
        pass
    
    async def _save_checkpoint(self):
        """保存检查点"""
        if not getattr(self.config, 'checkpoint_enabled', True):
            return
        
        checkpoint_dir = self._output_manager.get_checkpoint_dir() if self._output_manager else './results/checkpoints'
        os.makedirs(checkpoint_dir, exist_ok=True)
        checkpoint_path = os.path.join(checkpoint_dir, f"checkpoint_{self.config.target.replace('://', '_')}.json")
        
        checkpoint_data = {
            'target': self.config.target,
            'stage': self._stage,
            'timestamp': datetime.now().isoformat(),
            'result': self.result.to_dict() if self.result else None
        }
        
        import json
        with open(checkpoint_path, 'w') as f:
            json.dump(checkpoint_data, f)
        
        logger.info(f"Checkpoint saved: {checkpoint_path}")
    
    async def load_checkpoint(self, target: str) -> Optional[Dict]:
        """加载检查点"""
        checkpoint_dir = './results/checkpoints'
        checkpoint_path = os.path.join(checkpoint_dir, f"checkpoint_{target.replace('://', '_')}.json")
        
        if not os.path.exists(checkpoint_path):
            return None
        
        import json
        with open(checkpoint_path, 'r') as f:
            return json.load(f)
    
    async def cleanup(self):
        """清理资源"""
        logger.info("Cleaning up resources...")
        
        for task_id, task in list(self._tasks.items()):
            if asyncio.iscoroutine(task):
                task.cancel()
        
        self._tasks.clear()
        
        if self._http_client:
            await self._http_client.close()
            self._http_client = None
        
        if self._storage:
            self._storage.close()
            self._storage = None
        
        self._emit('cleanup_completed', {})
