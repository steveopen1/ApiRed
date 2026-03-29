"""
Task Queue Manager
任务队列管理器

功能:
- 任务队列管理
- 任务暂停/恢复/取消
- 任务优先级
- 自动重试
- 进度跟踪
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

logger = logging.getLogger(__name__)


class TaskState(Enum):
    """任务状态"""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    CANCELLED = "cancelled"
    COMPLETED = "completed"
    FAILED = "failed"


class TaskPriority(Enum):
    """任务优先级"""
    LOW = 0
    NORMAL = 1
    HIGH = 2
    CRITICAL = 3


@dataclass
class QueuedTask:
    """队列任务"""
    task_id: str
    target: str
    func: Callable
    args: tuple = field(default_factory=tuple)
    kwargs: Dict = field(default_factory=dict)
    state: TaskState = TaskState.PENDING
    priority: TaskPriority = TaskPriority.NORMAL
    progress: float = 0.0
    error: Optional[str] = None
    created_at: float = field(default_factory=lambda: datetime.now().timestamp())
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    retry_count: int = 0
    max_retries: int = 3
    metadata: Dict[str, Any] = field(default_factory=dict)


class TaskQueue:
    """
    任务队列管理器
    
    支持:
    - 暂停/恢复/取消
    - 优先级调度
    - 自动重试
    - 进度跟踪
    """

    def __init__(self, max_concurrent: int = 3):
        self._queue: asyncio.Queue = asyncio.Queue()
        self._tasks: Dict[str, QueuedTask] = {}
        self._running: Dict[str, asyncio.Task] = {}
        self._max_concurrent = max_concurrent
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._paused = False
        self._shutdown = False

    async def add(
        self,
        task_id: str,
        target: str,
        func: Callable,
        *args,
        priority: TaskPriority = TaskPriority.NORMAL,
        max_retries: int = 3,
        **kwargs
    ) -> QueuedTask:
        """添加任务到队列"""
        task = QueuedTask(
            task_id=task_id,
            target=target,
            func=func,
            args=args,
            kwargs=kwargs,
            priority=priority,
            max_retries=max_retries
        )
        
        self._tasks[task_id] = task
        logger.info(f"Task {task_id} added to queue with priority {priority.name}")
        
        if not self._paused and len(self._running) < self._max_concurrent:
            asyncio.create_task(self._run_task(task))
        
        return task

    async def _run_task(self, task: QueuedTask):
        """执行任务"""
        if task.state == TaskState.CANCELLED:
            return
        
        task.state = TaskState.RUNNING
        task.started_at = datetime.now().timestamp()
        self._running[task.task_id] = asyncio.current_task()
        
        try:
            logger.info(f"Starting task {task.task_id}")
            
            result = await task.func(*task.args, **task.kwargs)
            
            task.state = TaskState.COMPLETED
            task.completed_at = datetime.now().timestamp()
            task.progress = 100.0
            logger.info(f"Task {task.task_id} completed")
            
        except asyncio.CancelledError:
            task.state = TaskState.PAUSED
            logger.info(f"Task {task.task_id} paused")
            raise
            
        except Exception as e:
            task.error = str(e)
            task.retry_count += 1
            
            if task.retry_count < task.max_retries:
                logger.warning(f"Task {task.task_id} failed, retry {task.retry_count}/{task.max_retries}: {e}")
                task.state = TaskState.PENDING
                asyncio.create_task(self._run_task(task))
            else:
                task.state = TaskState.FAILED
                logger.error(f"Task {task.task_id} failed after {task.retry_count} retries")
        
        finally:
            if task.task_id in self._running:
                del self._running[task.task_id]

    def pause(self, task_id: str) -> bool:
        """暂停任务"""
        if task_id in self._running:
            task = self._tasks.get(task_id)
            if task:
                task.state = TaskState.PAUSED
                logger.info(f"Task {task_id} paused")
                return True
        return False

    def resume(self, task_id: str) -> bool:
        """恢复任务"""
        task = self._tasks.get(task_id)
        if task and task.state == TaskState.PAUSED:
            task.state = TaskState.PENDING
            if not self._paused:
                asyncio.create_task(self._run_task(task))
                logger.info(f"Task {task_id} resumed")
            return True
        return False

    def cancel(self, task_id: str) -> bool:
        """取消任务"""
        task = self._tasks.get(task_id)
        if not task:
            return False
        
        if task_id in self._running:
            # 发送取消信号
            self._running[task_id].cancel()
        
        task.state = TaskState.CANCELLED
        logger.info(f"Task {task_id} cancelled")
        return True

    def pause_all(self):
        """暂停所有任务"""
        self._paused = True
        for task_id in list(self._running.keys()):
            self.pause(task_id)
        logger.info("All tasks paused")

    def resume_all(self):
        """恢复所有任务"""
        self._paused = False
        for task in self._tasks.values():
            if task.state == TaskState.PAUSED:
                self.resume(task.task_id)
        logger.info("All tasks resumed")

    def get_state(self, task_id: str) -> Optional[TaskState]:
        """获取任务状态"""
        task = self._tasks.get(task_id)
        return task.state if task else None

    def get_progress(self, task_id: str) -> float:
        """获取任务进度"""
        task = self._tasks.get(task_id)
        return task.progress if task else 0.0

    def list_tasks(self) -> List[Dict]:
        """列出所有任务"""
        return [
            {
                'task_id': task.task_id,
                'target': task.target,
                'state': task.state.value,
                'priority': task.priority.name,
                'progress': task.progress,
                'created_at': task.created_at,
                'error': task.error,
                'retry_count': task.retry_count,
            }
            for task in self._tasks.values()
        ]

    def clear_completed(self):
        """清理已完成任务"""
        completed = [tid for tid, t in self._tasks.items() 
                   if t.state in (TaskState.COMPLETED, TaskState.FAILED)]
        for tid in completed:
            del self._tasks[tid]
        logger.info(f"Cleared {len(completed)} completed tasks")

    def shutdown(self):
        """关闭队列"""
        self._shutdown = True
        for task_id in list(self._running.keys()):
            self.cancel(task_id)
        logger.info("Queue shutdown")

    @property
    def stats(self) -> Dict:
        """队列统计"""
        states = {}
        for task in self._tasks.values():
            state = task.state.value
            states[state] = states.get(state, 0) + 1
        
        return {
            'total': len(self._tasks),
            'running': len(self._running),
            'paused': states.get('paused', 0),
            'pending': states.get('pending', 0),
            'completed': states.get('completed', 0),
            'failed': states.get('failed', 0),
            'max_concurrent': self._max_concurrent,
        }


# 全局任务队列实例
_task_queue: Optional[TaskQueue] = None


def get_task_queue() -> TaskQueue:
    """获取全局任务队列"""
    global _task_queue
    if _task_queue is None:
        _task_queue = TaskQueue()
    return _task_queue


if __name__ == "__main__":
    print("Task Queue Manager")
    queue = TaskQueue()
    print(queue.stats)
