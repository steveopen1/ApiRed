"""
Dashboard Events
事件定义 - WebSocket 消息协议和事件类型
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, Any, Optional, List, Callable, Awaitable
from datetime import datetime
from enum import Enum
import json


class EventType(Enum):
    """WebSocket 事件类型"""
    TASK_UPDATE = "task_update"
    TASK_STARTED = "task_started"
    TASK_COMPLETED = "task_completed"
    TASK_FAILED = "task_failed"
    TASK_STOPPED = "task_stopped"
    FINDING = "finding"
    LOG = "log"
    PROGRESS = "progress"
    STAGE_START = "stage_start"
    STAGE_PROGRESS = "stage_progress"
    STAGE_COMPLETE = "stage_complete"
    ERROR = "error"
    STATS_UPDATE = "stats_update"
    CONFIG_UPDATED = "config_updated"
    HEALTH_CHECK = "health_check"


@dataclass
class WSMessage:
    """WebSocket 消息基类"""
    type: str
    task_id: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'WSMessage':
        return cls(**data)

    @classmethod
    def from_json(cls, json_str: str) -> Optional['WSMessage']:
        try:
            data = json.loads(json_str)
            return cls.from_dict(data)
        except (json.JSONDecodeError, TypeError):
            return None


@dataclass
class TaskUpdateMessage(WSMessage):
    """任务状态更新消息"""
    def __init__(self, task_id: str, status: str, progress: int = 0,
                 stage: str = "", current_phase: str = "", **kwargs):
        super().__init__(
            type=EventType.TASK_UPDATE.value,
            task_id=task_id,
            data={
                "status": status,
                "progress": progress,
                "stage": stage,
                "current_phase": current_phase,
                **kwargs
            }
        )


@dataclass
class TaskStartedMessage(WSMessage):
    """任务开始消息"""
    def __init__(self, task_id: str, target: str, scan_mode: str = "rule", **kwargs):
        super().__init__(
            type=EventType.TASK_STARTED.value,
            task_id=task_id,
            data={
                "target": target,
                "scan_mode": scan_mode,
                **kwargs
            }
        )


@dataclass
class TaskCompletedMessage(WSMessage):
    """任务完成消息"""
    def __init__(self, task_id: str, total_apis: int = 0, vulnerabilities: int = 0,
                 duration: float = 0.0, **kwargs):
        super().__init__(
            type=EventType.TASK_COMPLETED.value,
            task_id=task_id,
            data={
                "total_apis": total_apis,
                "vulnerabilities": vulnerabilities,
                "duration": duration,
                **kwargs
            }
        )


@dataclass
class TaskFailedMessage(WSMessage):
    """任务失败消息"""
    def __init__(self, task_id: str, error: str, **kwargs):
        super().__init__(
            type=EventType.TASK_FAILED.value,
            task_id=task_id,
            data={
                "error": error,
                **kwargs
            }
        )


@dataclass
class TaskStoppedMessage(WSMessage):
    """任务停止消息"""
    def __init__(self, task_id: str, **kwargs):
        super().__init__(
            type=EventType.TASK_STOPPED.value,
            task_id=task_id,
            data=kwargs
        )


@dataclass
class FindingMessage(WSMessage):
    """发现消息"""
    def __init__(self, task_id: str, finding_type: str, data: Dict[str, Any], **kwargs):
        super().__init__(
            type=EventType.FINDING.value,
            task_id=task_id,
            data={
                "finding_type": finding_type,
                **data,
                **kwargs
            }
        )


@dataclass
class LogMessage(WSMessage):
    """日志消息"""
    def __init__(self, task_id: str, level: str, message: str, **kwargs):
        super().__init__(
            type=EventType.LOG.value,
            task_id=task_id,
            data={
                "level": level,
                "message": message,
                **kwargs
            }
        )


@dataclass
class ProgressMessage(WSMessage):
    """进度消息"""
    def __init__(self, task_id: str, progress: int, stage: str, current_phase: str = "",
                 total_apis: int = 0, alive_apis: int = 0, high_value_apis: int = 0,
                 vulnerabilities: int = 0, sensitive: int = 0, **kwargs):
        super().__init__(
            type=EventType.PROGRESS.value,
            task_id=task_id,
            data={
                "progress": progress,
                "stage": stage,
                "current_phase": current_phase,
                "total_apis": total_apis,
                "alive_apis": alive_apis,
                "high_value_apis": high_value_apis,
                "vulnerabilities": vulnerabilities,
                "sensitive": sensitive,
                **kwargs
            }
        )


@dataclass
class StageStartMessage(WSMessage):
    """阶段开始消息"""
    def __init__(self, task_id: str, stage: str, **kwargs):
        super().__init__(
            type=EventType.STAGE_START.value,
            task_id=task_id,
            data={
                "stage": stage,
                **kwargs
            }
        )


@dataclass
class StageCompleteMessage(WSMessage):
    """阶段完成消息"""
    def __init__(self, task_id: str, stage: str, duration: float = 0.0,
                 output_count: int = 0, **kwargs):
        super().__init__(
            type=EventType.STAGE_COMPLETE.value,
            task_id=task_id,
            data={
                "stage": stage,
                "duration": duration,
                "output_count": output_count,
                **kwargs
            }
        )


@dataclass
class ErrorMessage(WSMessage):
    """错误消息"""
    def __init__(self, task_id: str, error: str, **kwargs):
        super().__init__(
            type=EventType.ERROR.value,
            task_id=task_id,
            data={
                "error": error,
                **kwargs
            }
        )


@dataclass
class StatsUpdateMessage(WSMessage):
    """统计更新消息"""
    def __init__(self, task_id: str, stats: Dict[str, Any], **kwargs):
        super().__init__(
            type=EventType.STATS_UPDATE.value,
            task_id=task_id,
            data={**stats, **kwargs}
        )


@dataclass
class HealthCheckMessage(WSMessage):
    """健康检查消息"""
    def __init__(self, status: str = "healthy", components: Optional[Dict[str, Any]] = None):
        super().__init__(
            type=EventType.HEALTH_CHECK.value,
            task_id="",
            data={
                "status": status,
                "components": components or {},
                "timestamp": datetime.now().isoformat()
            }
        )


class ClientMessageType(Enum):
    """客户端消息类型"""
    START_SCAN = "start_scan"
    STOP_SCAN = "stop_scan"
    RESUME_SCAN = "resume_scan"
    DELETE_TASK = "delete_task"
    GET_STATUS = "get_status"
    GET_RESULTS = "get_results"
    UPDATE_CONFIG = "update_config"


@dataclass
class ClientMessage:
    """客户端消息"""
    type: str
    task_id: str = ""
    target: str = ""
    config: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ClientMessage':
        return cls(
            type=data.get('type', ''),
            task_id=data.get('task_id', ''),
            target=data.get('target', ''),
            config=data.get('config', {})
        )


class EventEmitter:
    """事件发射器 - 用于 ScanEngine 事件回调"""

    def __init__(self):
        self._listeners: Dict[str, List[Callable]] = {}

    def on(self, event: str, callback: Callable[[Dict[str, Any]], Awaitable]):
        """注册事件监听器"""
        if event not in self._listeners:
            self._listeners[event] = []
        self._listeners[event].append(callback)

    def off(self, event: str, callback: Callable[[Dict[str, Any]], Awaitable]):
        """移除事件监听器"""
        if event in self._listeners:
            self._listeners[event] = [cb for cb in self._listeners[event] if cb != callback]

    async def emit(self, event: str, data: Dict[str, Any]):
        """触发事件"""
        if event in self._listeners:
            for callback in self._listeners[event]:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(data)
                    else:
                        callback(data)
                except Exception as e:
                    import logging
                    logging.getLogger(__name__).warning(f"Event callback error for {event}: {e}")


import asyncio
