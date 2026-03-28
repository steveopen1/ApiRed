"""
TaskManager - 任务管理器
负责任务状态管理、数据库持久化、WebSocket 连接管理和消息广播
"""

import asyncio
import json
import logging
import os
import sqlite3
import threading
from datetime import datetime
from typing import Dict, List, Optional, Set, Any, Callable, Awaitable

from .models import (
    ScanTask, TaskStatus, ScanMode, EngineConfig,
    ScanProgress, Finding, LogEntry, LogLevel,
    APIEndpoint, Vulnerability, ScanResult, FindingType
)
from .events import (
    WSMessage, TaskUpdateMessage, TaskStartedMessage,
    TaskCompletedMessage, TaskFailedMessage, TaskStoppedMessage,
    FindingMessage, LogMessage, ProgressMessage,
    StageStartMessage, StageCompleteMessage, ErrorMessage,
    EventType
)

logger = logging.getLogger(__name__)


class TaskManager:
    """任务管理器"""

    MAX_TASKS = 100

    def __init__(self, db_path: str = "./results/dashboard.db"):
        self.db_path = db_path
        self._ensure_dir()
        self._tasks: Dict[str, ScanTask] = {}
        self._websockets: Set[Any] = set()
        self._websocket_lock = asyncio.Lock()
        self._tasks_lock = asyncio.Lock()
        self._init_db()

    def _ensure_dir(self):
        """确保目录存在"""
        dir_path = os.path.dirname(self.db_path)
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)

    def _init_db(self):
        """初始化数据库"""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row

        conn.execute("""
            CREATE TABLE IF NOT EXISTS tasks (
                task_id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                scan_mode TEXT DEFAULT 'rule',
                progress INTEGER DEFAULT 0,
                current_stage TEXT,
                current_phase TEXT,
                engine_config TEXT,
                config_dict TEXT,
                created_at TEXT,
                updated_at TEXT,
                started_at TEXT,
                completed_at TEXT,
                error_message TEXT,
                pid INTEGER DEFAULT 0,
                output_path TEXT
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                result_id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL,
                target_url TEXT,
                total_apis INTEGER DEFAULT 0,
                alive_apis INTEGER DEFAULT 0,
                high_value_apis INTEGER DEFAULT 0,
                total_vulns INTEGER DEFAULT 0,
                total_sensitive INTEGER DEFAULT 0,
                status TEXT DEFAULT 'pending',
                duration REAL DEFAULT 0.0,
                data TEXT,
                created_at TEXT,
                FOREIGN KEY (task_id) REFERENCES tasks(task_id)
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS api_endpoints (
                endpoint_id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL,
                path TEXT NOT NULL,
                method TEXT DEFAULT 'GET',
                base_url TEXT,
                full_url TEXT,
                status TEXT,
                status_code INTEGER,
                score INTEGER DEFAULT 0,
                is_high_value INTEGER DEFAULT 0,
                sources TEXT,
                parameters TEXT,
                response_sample TEXT,
                created_at TEXT,
                FOREIGN KEY (task_id) REFERENCES tasks(task_id)
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                vuln_id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL,
                endpoint_id TEXT,
                vuln_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT,
                description TEXT,
                evidence TEXT,
                payload TEXT,
                remediation TEXT,
                cwe_id TEXT,
                created_at TEXT,
                FOREIGN KEY (task_id) REFERENCES tasks(task_id)
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id TEXT NOT NULL,
                level TEXT NOT NULL,
                message TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                source TEXT,
                FOREIGN KEY (task_id) REFERENCES tasks(task_id)
            )
        """)

        conn.execute("CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tasks_target ON tasks(target)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_endpoints_task ON api_endpoints(task_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_endpoints_score ON api_endpoints(score DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_vulns_task ON vulnerabilities(task_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_task ON logs(task_id)")

        conn.commit()
        conn.close()
        logger.info(f"TaskManager database initialized at {self.db_path}")

    def _get_connection(self) -> sqlite3.Connection:
        """获取数据库连接"""
        conn = sqlite3.connect(
            self.db_path,
            check_same_thread=False,
            timeout=30.0
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    async def create_task(self, target: str, config: Optional[Dict[str, Any]] = None,
                         scan_mode: str = "rule") -> ScanTask:
        """创建新任务"""
        config_dict = config or {}
        scan_mode_enum = ScanMode(scan_mode) if scan_mode else ScanMode.RULE

        task = ScanTask(
            target=target,
            status=TaskStatus.PENDING,
            scan_mode=scan_mode_enum,
            config_dict=config_dict,
            created_at=datetime.now().isoformat()
        )

        async with self._tasks_lock:
            self._cleanup_old_tasks()
            self._tasks[task.task_id] = task

        await self._save_task(task)
        logger.info(f"Task created: {task.task_id} for target {target}")
        return task

    def _cleanup_old_tasks(self):
        """清理旧任务"""
        if len(self._tasks) >= self.MAX_TASKS:
            completed = [
                tid for tid, t in self._tasks.items()
                if t.status in (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.STOPPED)
            ]
            completed.sort(key=lambda x: self._tasks[x].completed_at or '')
            for tid in completed[:len(completed) // 2]:
                del self._tasks[tid]

    async def _save_task(self, task: ScanTask):
        """保存任务到数据库"""
        conn = self._get_connection()
        try:
            conn.execute("""
                INSERT OR REPLACE INTO tasks
                (task_id, target, status, scan_mode, progress, current_stage, current_phase,
                 engine_config, config_dict, created_at, updated_at, started_at, completed_at,
                 error_message, pid, output_path)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                task.task_id,
                task.target,
                task.status.value if isinstance(task.status, TaskStatus) else task.status,
                task.scan_mode.value if isinstance(task.scan_mode, ScanMode) else task.scan_mode,
                task.progress,
                task.current_stage,
                task.current_phase,
                json.dumps(task.engine_config.to_dict()) if task.engine_config else None,
                json.dumps(task.config_dict),
                task.created_at,
                task.updated_at,
                task.started_at,
                task.completed_at,
                task.error_message,
                task.pid,
                task.output_path
            ))
            conn.commit()
        finally:
            conn.close()

    async def get_task(self, task_id: str) -> Optional[ScanTask]:
        """获取任务"""
        async with self._tasks_lock:
            if task_id in self._tasks:
                return self._tasks[task_id]

        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM tasks WHERE task_id = ?", (task_id,)
            ).fetchone()
            if row:
                task = self._row_to_task(row)
                async with self._tasks_lock:
                    self._tasks[task_id] = task
                return task
            return None
        finally:
            conn.close()

    def _row_to_task(self, row: sqlite3.Row) -> ScanTask:
        """将数据库行转换为 ScanTask"""
        data = dict(row)
        if data.get('engine_config'):
            try:
                data['engine_config'] = EngineConfig.from_dict(json.loads(data['engine_config']))
            except (json.JSONDecodeError, TypeError, KeyError):
                data['engine_config'] = None
        if data.get('config_dict'):
            try:
                data['config_dict'] = json.loads(data['config_dict'])
            except json.JSONDecodeError:
                data['config_dict'] = {}
        if data.get('status'):
            try:
                data['status'] = TaskStatus(data['status'])
            except ValueError:
                data['status'] = TaskStatus.PENDING
        if data.get('scan_mode'):
            try:
                data['scan_mode'] = ScanMode(data['scan_mode'])
            except ValueError:
                data['scan_mode'] = ScanMode.RULE
        
        valid_fields = {f.name for f in ScanTask.__dataclass_fields__.values()}
        filtered_data = {k: v for k, v in data.items() if k in valid_fields}
        return ScanTask(**filtered_data)

    async def update_task(self, task_id: str, **updates):
        """更新任务状态"""
        task = await self.get_task(task_id)
        if not task:
            return False

        for key, value in updates.items():
            if hasattr(task, key):
                setattr(task, key, value)

        task.updated_at = datetime.now().isoformat()

        if 'status' in updates:
            status = updates['status']
            if isinstance(status, TaskStatus):
                task.status = status
            elif isinstance(status, str):
                task.status = TaskStatus(status)

            if task.status == TaskStatus.RUNNING and not task.started_at:
                task.started_at = datetime.now().isoformat()
            elif task.status in (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.STOPPED):
                task.completed_at = datetime.now().isoformat()

        async with self._tasks_lock:
            self._tasks[task_id] = task

        await self._save_task(task)

        await self.broadcast(TaskUpdateMessage(
            task_id=task_id,
            status=task.status.value if isinstance(task.status, TaskStatus) else task.status,
            progress=task.progress,
            stage=task.current_stage or '',
            current_phase=task.current_phase or ''
        ).to_dict())

        return True

    async def list_tasks(self) -> List[ScanTask]:
        """列出所有任务"""
        async with self._tasks_lock:
            return list(self._tasks.values())

    async def delete_task(self, task_id: str) -> bool:
        """删除任务"""
        async with self._tasks_lock:
            if task_id in self._tasks:
                del self._tasks[task_id]

        conn = self._get_connection()
        try:
            conn.execute("DELETE FROM tasks WHERE task_id = ?", (task_id,))
            conn.execute("DELETE FROM scan_results WHERE task_id = ?", (task_id,))
            conn.execute("DELETE FROM api_endpoints WHERE task_id = ?", (task_id,))
            conn.execute("DELETE FROM vulnerabilities WHERE task_id = ?", (task_id,))
            conn.execute("DELETE FROM logs WHERE task_id = ?", (task_id,))
            conn.commit()
            logger.info(f"Task deleted: {task_id}")
            return True
        finally:
            conn.close()

    async def stop_task(self, task_id: str) -> bool:
        """停止任务"""
        task = await self.get_task(task_id)
        if not task:
            return False

        if task.pid > 0:
            try:
                import signal
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

        await self.update_task(task_id, status=TaskStatus.STOPPED)

        await self.broadcast(TaskStoppedMessage(task_id=task_id).to_dict())
        return True

    async def add_websocket(self, ws: Any):
        """添加 WebSocket 连接"""
        async with self._websocket_lock:
            self._websockets.add(ws)
        logger.debug(f"WebSocket added, total: {len(self._websockets)}")

    async def remove_websocket(self, ws: Any):
        """移除 WebSocket 连接"""
        async with self._websocket_lock:
            self._websockets.discard(ws)
        logger.debug(f"WebSocket removed, total: {len(self._websockets)}")

    async def broadcast(self, message: Dict[str, Any]):
        """广播消息到所有 WebSocket"""
        async with self._websocket_lock:
            websockets = list(self._websockets)

        if not websockets:
            return

        message_json = json.dumps(message, ensure_ascii=False)
        disconnected = []

        for ws in websockets:
            try:
                await ws.send_str(message_json)
            except Exception as e:
                logger.warning(f"Failed to send to WebSocket: {e}")
                disconnected.append(ws)

        for ws in disconnected:
            await self.remove_websocket(ws)

    async def send_to_task(self, task_id: str, message: Dict[str, Any]):
        """发送消息到特定任务"""
        message['task_id'] = task_id
        await self.broadcast(message)

    async def broadcast_progress(self, task_id: str, progress: ScanProgress):
        """广播进度更新"""
        await self.broadcast(ProgressMessage(
            task_id=task_id,
            progress=progress.progress_percent,
            stage=progress.stage,
            current_phase=progress.current_phase,
            total_apis=progress.total_apis,
            alive_apis=progress.alive_apis,
            high_value_apis=progress.high_value_apis,
            vulnerabilities=progress.vulnerabilities_found,
            sensitive=progress.sensitive_found
        ).to_dict())

    async def broadcast_finding(self, task_id: str, finding: Finding):
        """广播发现"""
        await self.broadcast(FindingMessage(
            task_id=task_id,
            finding_type=finding.finding_type.value if isinstance(finding.finding_type, FindingType) else finding.finding_type,
            data=finding.data
        ).to_dict())

    async def broadcast_log(self, task_id: str, level: str, message: str):
        """广播日志"""
        await self.broadcast(LogMessage(
            task_id=task_id,
            level=level,
            message=message
        ).to_dict())

    async def broadcast_stage_start(self, task_id: str, stage: str):
        """广播阶段开始"""
        await self.broadcast(StageStartMessage(
            task_id=task_id,
            stage=stage
        ).to_dict())

    async def broadcast_stage_complete(self, task_id: str, stage: str, duration: float = 0.0):
        """广播阶段完成"""
        await self.broadcast(StageCompleteMessage(
            task_id=task_id,
            stage=stage,
            duration=duration
        ).to_dict())

    async def broadcast_error(self, task_id: str, error: str):
        """广播错误"""
        await self.broadcast(ErrorMessage(
            task_id=task_id,
            error=error
        ).to_dict())

    async def get_results(self, task_id: str) -> Optional[Dict[str, Any]]:
        """获取任务结果"""
        conn = self._get_connection()
        try:
            result_row = conn.execute(
                "SELECT * FROM scan_results WHERE task_id = ?", (task_id,)
            ).fetchone()

            if not result_row:
                return None

            result = dict(result_row)
            if result.get('data'):
                try:
                    result['data'] = json.loads(result['data'])
                except json.JSONDecodeError:
                    pass

            endpoints = conn.execute(
                "SELECT * FROM api_endpoints WHERE task_id = ? ORDER BY score DESC",
                (task_id,)
            ).fetchall()
            result['api_endpoints'] = [dict(row) for row in endpoints]

            vulns = conn.execute(
                "SELECT * FROM vulnerabilities WHERE task_id = ? ORDER BY severity DESC",
                (task_id,)
            ).fetchall()
            result['vulnerabilities'] = [dict(row) for row in vulns]

            return result
        finally:
            conn.close()

    async def save_result(self, task_id: str, result: Dict[str, Any]):
        """保存扫描结果"""
        conn = self._get_connection()
        try:
            conn.execute("""
                INSERT OR REPLACE INTO scan_results
                (result_id, task_id, target_url, total_apis, alive_apis, high_value_apis,
                 total_vulns, total_sensitive, status, duration, data, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                result.get('result_id', task_id),
                task_id,
                result.get('target_url', ''),
                result.get('total_apis', 0),
                result.get('alive_apis', 0),
                result.get('high_value_apis', 0),
                result.get('total_vulns', 0),
                result.get('total_sensitive', 0),
                result.get('status', 'completed'),
                result.get('duration', 0.0),
                json.dumps(result.get('data', {})),
                datetime.now().isoformat()
            ))
            conn.commit()
        finally:
            conn.close()

    async def save_api_endpoint(self, task_id: str, endpoint: Dict[str, Any]):
        """保存 API 端点"""
        conn = self._get_connection()
        try:
            conn.execute("""
                INSERT OR REPLACE INTO api_endpoints
                (endpoint_id, task_id, path, method, base_url, full_url, status,
                 status_code, score, is_high_value, sources, parameters, response_sample, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                endpoint.get('endpoint_id'),
                task_id,
                endpoint.get('path'),
                endpoint.get('method', 'GET'),
                endpoint.get('base_url'),
                endpoint.get('full_url'),
                endpoint.get('status'),
                endpoint.get('status_code'),
                endpoint.get('score', 0),
                endpoint.get('is_high_value', 0),
                json.dumps(endpoint.get('sources', [])),
                json.dumps(endpoint.get('parameters', [])),
                endpoint.get('response_sample'),
                datetime.now().isoformat()
            ))
            conn.commit()
        finally:
            conn.close()

    async def save_vulnerability(self, task_id: str, vuln: Dict[str, Any]):
        """保存漏洞"""
        conn = self._get_connection()
        try:
            conn.execute("""
                INSERT OR REPLACE INTO vulnerabilities
                (vuln_id, task_id, endpoint_id, vuln_type, severity, title,
                 description, evidence, payload, remediation, cwe_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                vuln.get('vuln_id'),
                task_id,
                vuln.get('endpoint_id'),
                vuln.get('vuln_type'),
                vuln.get('severity', 'medium'),
                vuln.get('title'),
                vuln.get('description'),
                vuln.get('evidence'),
                vuln.get('payload'),
                vuln.get('remediation'),
                vuln.get('cwe_id'),
                datetime.now().isoformat()
            ))
            conn.commit()
        finally:
            conn.close()

    async def add_log(self, task_id: str, level: str, message: str, source: str = ""):
        """添加日志"""
        conn = self._get_connection()
        try:
            conn.execute("""
                INSERT INTO logs (task_id, level, message, timestamp, source)
                VALUES (?, ?, ?, ?, ?)
            """, (task_id, level, message, datetime.now().isoformat(), source))
            conn.commit()
        finally:
            conn.close()

    async def get_logs(self, task_id: str, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """获取日志"""
        conn = self._get_connection()
        try:
            rows = conn.execute("""
                SELECT * FROM logs WHERE task_id = ?
                ORDER BY timestamp DESC LIMIT ? OFFSET ?
            """, (task_id, limit, offset)).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    async def get_stats(self) -> Dict[str, Any]:
        """获取全局统计"""
        conn = self._get_connection()
        try:
            total_tasks = conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]
            running_tasks = conn.execute(
                "SELECT COUNT(*) FROM tasks WHERE status = 'running'"
            ).fetchone()[0]
            completed_tasks = conn.execute(
                "SELECT COUNT(*) FROM tasks WHERE status = 'completed'"
            ).fetchone()[0]

            total_apis = conn.execute("SELECT COUNT(*) FROM api_endpoints").fetchone()[0]
            total_vulns = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]

            return {
                "total_tasks": total_tasks,
                "running_tasks": running_tasks,
                "completed_tasks": completed_tasks,
                "total_apis": total_apis,
                "total_vulns": total_vulns
            }
        finally:
            conn.close()

    async def clear_completed(self):
        """清除已完成任务"""
        async with self._tasks_lock:
            completed = [
                tid for tid, t in self._tasks.items()
                if t.status in (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.STOPPED)
            ]
            for tid in completed:
                await self.delete_task(tid)
