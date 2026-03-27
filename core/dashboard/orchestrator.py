"""
ScanOrchestrator - 扫描编排器
管理 ScanEngine 实例的生命周期，注册事件回调，广播扫描进度和发现
"""

import asyncio
import logging
import os
import signal
import time
from datetime import datetime
from typing import Dict, Optional, Any, List, Callable, Awaitable

from .models import (
    ScanTask, TaskStatus, EngineConfig, ScanProgress,
    Finding, FindingType, StageStats, LogLevel
)
from .task_manager import TaskManager
from .events import EventEmitter

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    """扫描编排器 - 管理 ScanEngine 实例的生命周期"""

    def __init__(self, task_manager: TaskManager):
        self.task_manager = task_manager
        self._engines: Dict[str, Any] = {}
        self._tasks: Dict[str, asyncio.Task] = {}
        self._locks: Dict[str, asyncio.Lock] = {}
        self._progress_counters: Dict[str, int] = {}
        self._last_progress_time: Dict[str, float] = {}

    async def start_scan(self, task: ScanTask, config: Optional[EngineConfig] = None) -> str:
        """启动扫描"""
        task_id = task.task_id

        if task_id in self._locks:
            logger.warning(f"Task {task_id} already running")
            return task_id

        self._locks[task_id] = asyncio.Lock()
        self._progress_counters[task_id] = 0
        self._last_progress_time[task_id] = time.time()

        engine_config = config or self._build_engine_config(task)
        task.engine_config = engine_config

        await self.task_manager.update_task(
            task_id,
            status=TaskStatus.RUNNING,
            current_stage="initialization",
            current_phase="initializing"
        )

        asyncio_task = asyncio.create_task(self._run_scan(task_id, engine_config))
        self._tasks[task_id] = asyncio_task
        self._engines[task_id] = None

        logger.info(f"Scan started: {task_id} for target {task.target}")
        return task_id

    def _build_engine_config(self, task: ScanTask) -> EngineConfig:
        """从任务配置构建 EngineConfig"""
        config_dict = task.config_dict or {}

        return EngineConfig(
            target=task.target,
            collectors=config_dict.get('collectors', ['js', 'api']),
            analyzers=config_dict.get('analyzers', ['scorer', 'sensitive']),
            testers=config_dict.get('testers', ['fuzz', 'vuln']),
            ai_enabled=task.scan_mode.value == 'agent' if isinstance(task.scan_mode, type) else task.scan_mode == 'agent',
            checkpoint_enabled=config_dict.get('checkpoint_enabled', True),
            cookies=config_dict.get('cookies', ''),
            concurrency=config_dict.get('concurrency', 50),
            js_depth=config_dict.get('js_depth', 3),
            output_dir=config_dict.get('output_dir', './results'),
            attack_mode=config_dict.get('attack_mode', 'all'),
            no_api_scan=config_dict.get('no_api_scan', False),
            chrome=config_dict.get('chrome', True),
            verify_ssl=config_dict.get('verify_ssl', True),
            resume=config_dict.get('resume', False),
            agent_mode=task.scan_mode.value == 'agent' if isinstance(task.scan_mode, type) else task.scan_mode == 'agent',
            report_formats=config_dict.get('report_formats', ['json', 'html']),
            enable_sql_test=config_dict.get('enable_sql_test', True),
            enable_xss_test=config_dict.get('enable_xss_test', True),
            enable_ssrf_test=config_dict.get('enable_ssrf_test', True),
            enable_bypass_test=config_dict.get('enable_bypass_test', True),
            enable_jwt_test=config_dict.get('enable_jwt_test', True),
            enable_idor_test=config_dict.get('enable_idor_test', True),
        )

    async def _run_scan(self, task_id: str, config: EngineConfig):
        """运行扫描"""
        engine = None
        try:
            from core.engine import ScanEngine
            engine = ScanEngine(config)
            self._engines[task_id] = engine

            self._register_engine_callbacks(engine, task_id)

            result = await engine.run()

            await self._handle_scan_complete(task_id, result)

        except asyncio.CancelledError:
            logger.info(f"Scan cancelled: {task_id}")
            await self.task_manager.update_task(
                task_id,
                status=TaskStatus.STOPPED,
                error_message="Scan was stopped by user"
            )
            raise

        except Exception as e:
            logger.error(f"Scan error: {task_id}, error: {e}")
            await self.task_manager.update_task(
                task_id,
                status=TaskStatus.FAILED,
                error_message=str(e)
            )
            await self.task_manager.broadcast_error(task_id, str(e))

        finally:
            self._engines[task_id] = None
            if task_id in self._tasks:
                del self._tasks[task_id]
            if task_id in self._locks:
                del self._locks[task_id]
            if task_id in self._progress_counters:
                del self._progress_counters[task_id]
            if task_id in self._last_progress_time:
                del self._last_progress_time[task_id]

    def _register_engine_callbacks(self, engine: Any, task_id: str):
        """注册引擎回调"""

        def on_stage_start(data: Dict[str, Any]):
            stage = data.get('stage', '')
            asyncio.create_task(self._handle_stage_start(task_id, stage))

        def on_stage_complete(data: Dict[str, Any]):
            stage = data.get('stage', '')
            asyncio.create_task(self._handle_stage_complete(task_id, stage, data))

        def on_progress(data: Dict[str, Any]):
            asyncio.create_task(self._handle_progress_update(task_id, data))

        def on_finding(data: Dict[str, Any]):
            asyncio.create_task(self._handle_finding(task_id, data))

        def on_error(data: Dict[str, Any]):
            error = data.get('error', 'Unknown error')
            asyncio.create_task(self._handle_error(task_id, error))

        def on_log(data: Dict[str, Any]):
            asyncio.create_task(self._handle_log(task_id, data))

        engine.on('stage_start', on_stage_start)
        engine.on('stage_complete', on_stage_complete)
        engine.on('progress_update', on_progress)
        engine.on('finding', on_finding)
        engine.on('error', on_error)
        engine.on('log', on_log)

    async def _handle_stage_start(self, task_id: str, stage: str):
        """处理阶段开始"""
        stage_map = {
            'initialization': ('init', 0),
            'js_collection': ('collect', 10),
            'api_scoring': ('analyze', 40),
            'vuln_testing': ('test', 70),
            'reporting': ('reporting', 90),
        }

        stage_name, progress = stage_map.get(stage, (stage, 0))

        await self.task_manager.update_task(
            task_id,
            current_stage=stage_name,
            current_phase=stage,
            progress=progress
        )

        await self.task_manager.broadcast_stage_start(task_id, stage_name)
        await self.task_manager.broadcast_log(
            task_id, 'info', f'Stage started: {stage_name}'
        )

    async def _handle_stage_complete(self, task_id: str, stage: str, data: Dict[str, Any]):
        """处理阶段完成"""
        stage_map = {
            'initialization': ('init', 5),
            'js_collection': ('collect', 35),
            'api_scoring': ('analyze', 65),
            'vuln_testing': ('test', 95),
            'reporting': ('reporting', 100),
        }

        stage_name, progress = stage_map.get(stage, (stage, progress))
        duration = data.get('duration', 0.0)

        await self.task_manager.update_task(
            task_id,
            current_stage=stage_name,
            progress=progress
        )

        await self.task_manager.broadcast_stage_complete(task_id, stage_name, duration)
        await self.task_manager.broadcast_log(
            task_id, 'info', f'Stage completed: {stage_name} (took {duration:.2f}s)'
        )

    async def _handle_progress_update(self, task_id: str, data: Dict[str, Any]):
        """处理进度更新"""
        now = time.time()
        last_time = self._last_progress_time.get(task_id, 0)

        self._progress_counters[task_id] = self._progress_counters.get(task_id, 0) + 1
        counter = self._progress_counters[task_id]

        should_broadcast = (
            counter % 10 == 0 or
            now - last_time >= 5.0
        )

        if not should_broadcast:
            return

        self._last_progress_time[task_id] = now

        total_apis = data.get('total_apis', 0)
        alive_apis = data.get('alive_apis', 0)
        high_value_apis = data.get('high_value_apis', 0)
        vulnerabilities = data.get('vulnerabilities_found', 0)
        sensitive = data.get('sensitive_found', 0)
        stage = data.get('stage', 'unknown')
        current_phase = data.get('current_phase', '')

        stage_progress = {
            'initialization': 5,
            'js_collection': 10 + (35 - 10) * data.get('stage_progress', 0) / 100,
            'api_scoring': 40 + (65 - 40) * data.get('stage_progress', 0) / 100,
            'vuln_testing': 70 + (95 - 70) * data.get('stage_progress', 0) / 100,
            'reporting': 95 + (100 - 95) * data.get('stage_progress', 0) / 100,
        }

        progress = int(stage_progress.get(stage, 50))

        await self.task_manager.update_task(
            task_id,
            progress=progress,
            current_stage=stage,
            current_phase=current_phase
        )

        progress_obj = ScanProgress(
            task_id=task_id,
            stage=stage,
            stage_status='running',
            progress_percent=progress,
            current_phase=current_phase,
            total_apis=total_apis,
            alive_apis=alive_apis,
            high_value_apis=high_value_apis,
            vulnerabilities_found=vulnerabilities,
            sensitive_found=sensitive
        )

        await self.task_manager.broadcast_progress(task_id, progress_obj)

    async def _handle_finding(self, task_id: str, data: Dict[str, Any]):
        """处理发现"""
        finding_type = data.get('type', 'api')
        finding_data = data.get('data', {})

        if finding_type == 'api':
            await self.task_manager.save_api_endpoint(task_id, finding_data)
            await self.task_manager.broadcast_log(
                task_id, 'info',
                f"[API] {finding_data.get('method', 'GET')} {finding_data.get('path', '')}"
            )
        elif finding_type == 'vulnerability':
            await self.task_manager.save_vulnerability(task_id, finding_data)
            severity = finding_data.get('severity', 'medium').upper()
            await self.task_manager.broadcast_log(
                task_id, 'warning',
                f"[VULN:{severity}] {finding_data.get('vuln_type', '')} @ {finding_data.get('path', '')}"
            )
        elif finding_type == 'sensitive':
            await self.task_manager.broadcast_log(
                task_id, 'warning',
                f"[SENSITIVE:{finding_data.get('type', '')}] {finding_data.get('content', '')[:50]}..."
            )

        finding = Finding(
            task_id=task_id,
            finding_type=FindingType(finding_type) if finding_type in [e.value for e in FindingType] else FindingType.API,
            data=finding_data
        )

        await self.task_manager.broadcast_finding(task_id, finding)

    async def _handle_error(self, task_id: str, error: str):
        """处理错误"""
        await self.task_manager.broadcast_error(task_id, error)
        await self.task_manager.broadcast_log(task_id, 'error', f'Error: {error}')

    async def _handle_log(self, task_id: str, data: Dict[str, Any]):
        """处理日志"""
        level = data.get('level', 'info')
        message = data.get('message', '')

        await self.task_manager.add_log(task_id, level, message)
        await self.task_manager.broadcast_log(task_id, level, message)

    async def _handle_scan_complete(self, task_id: str, result: Any):
        """处理扫描完成"""
        if result is None:
            await self.task_manager.update_task(
                task_id,
                status=TaskStatus.FAILED,
                error_message="Scan returned no result"
            )
            return

        await self.task_manager.update_task(
            task_id,
            status=TaskStatus.COMPLETED,
            progress=100,
            current_stage='completed'
        )

        total_apis = getattr(result, 'total_apis', 0)
        alive_apis = getattr(result, 'alive_apis', 0)
        high_value_apis = getattr(result, 'high_value_apis', 0)
        vulnerabilities = getattr(result, 'vulnerabilities', [])
        duration = getattr(result, 'duration', 0.0)

        result_data = {
            'result_id': task_id,
            'task_id': task_id,
            'target_url': result.target_url if hasattr(result, 'target_url') else '',
            'total_apis': total_apis,
            'alive_apis': alive_apis,
            'high_value_apis': high_value_apis,
            'total_vulns': len(vulnerabilities),
            'status': 'completed',
            'duration': duration,
            'data': result.to_dict() if hasattr(result, 'to_dict') else {}
        }

        await self.task_manager.save_result(task_id, result_data)

        for vuln in vulnerabilities:
            vuln_data = vuln.to_dict() if hasattr(vuln, 'to_dict') else vuln
            await self.task_manager.save_vulnerability(task_id, vuln_data)

        await self.task_manager.broadcast_log(
            task_id, 'info',
            f"Scan completed: {total_apis} APIs found, {len(vulnerabilities)} vulnerabilities"
        )

        logger.info(f"Scan completed: {task_id}, APIs: {total_apis}, Vulns: {len(vulnerabilities)}")

    async def stop_scan(self, task_id: str) -> bool:
        """停止扫描"""
        if task_id not in self._tasks:
            logger.warning(f"Task {task_id} not found in running tasks")
            return False

        task = await self.task_manager.get_task(task_id)
        if task and task.pid > 0:
            try:
                os.kill(task.pid, signal.SIGTERM)
                await asyncio.sleep(0.5)
                try:
                    os.kill(task.pid, 0)
                except ProcessLookupError:
                    pass
                else:
                    os.kill(task.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError) as e:
                logger.warning(f"Failed to kill process {task.pid}: {e}")

        if task_id in self._tasks:
            scan_task = self._tasks[task_id]
            scan_task.cancel()

            try:
                await asyncio.wait_for(asyncio.shield(scan_task), timeout=5.0)
            except asyncio.CancelledError:
                pass
            except asyncio.TimeoutError:
                scan_task.cancel()

        await self.task_manager.update_task(
            task_id,
            status=TaskStatus.STOPPED
        )

        logger.info(f"Scan stopped: {task_id}")
        return True

    async def get_progress(self, task_id: str) -> Optional[ScanProgress]:
        """获取进度"""
        task = await self.task_manager.get_task(task_id)
        if not task:
            return None

        return ScanProgress(
            task_id=task_id,
            stage=task.current_stage or 'unknown',
            stage_status=task.status.value if hasattr(task.status, 'value') else task.status,
            progress_percent=task.progress,
            current_phase=task.current_phase or ''
        )

    async def resume_scan(self, task_id: str) -> bool:
        """恢复扫描"""
        task = await self.task_manager.get_task(task_id)
        if not task:
            return False

        if task.status != TaskStatus.STOPPED:
            logger.warning(f"Task {task_id} is not stopped, cannot resume")
            return False

        task.config_dict['resume'] = True
        task.status = TaskStatus.PENDING

        await self.task_manager.update_task(task_id, status=TaskStatus.PENDING)

        asyncio_task = asyncio.create_task(self._run_scan(task_id, task.engine_config))
        self._tasks[task_id] = asyncio_task

        logger.info(f"Scan resumed: {task_id}")
        return True

    def get_running_tasks(self) -> List[str]:
        """获取运行中的任务"""
        return list(self._tasks.keys())
