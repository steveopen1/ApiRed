"""
Dispatcher Module
任务调度器模块
"""

import asyncio
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
from queue import Queue, Empty
import threading
import time


class TaskPriority(Enum):
    """任务优先级"""
    LOW = 1
    NORMAL = 5
    HIGH = 10
    CRITICAL = 20


@dataclass
class Task:
    """任务定义"""
    task_id: str
    task_type: str
    data: Any
    priority: TaskPriority = TaskPriority.NORMAL
    callback: Optional[Callable] = None
    created_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)


class TaskDispatcher:
    """任务调度器"""
    
    def __init__(
        self,
        max_workers: int = 10,
        max_queue_size: int = 1000
    ):
        self.max_workers = max_workers
        self.max_queue_size = max_queue_size
        
        self._task_queue: Queue = Queue(maxsize=max_queue_size)
        self._result_queue: Queue = Queue()
        self._running = False
        self._workers: List[threading.Thread] = []
        self._stats = {
            'total_tasks': 0,
            'completed_tasks': 0,
            'failed_tasks': 0,
            'pending_tasks': 0
        }
        self._stats_lock = threading.Lock()
        self._handlers: Dict[str, Callable] = {}
    
    def register_handler(self, task_type: str, handler: Callable):
        """注册任务处理器"""
        self._handlers[task_type] = handler
    
    def add_task(self, task: Task) -> bool:
        """添加任务"""
        try:
            self._task_queue.put_nowait(task)
            
            with self._stats_lock:
                self._stats['total_tasks'] += 1
                self._stats['pending_tasks'] += 1
            
            return True
        except:
            return False
    
    def add_tasks(self, tasks: List[Task]) -> int:
        """批量添加任务"""
        added = 0
        for task in tasks:
            if self.add_task(task):
                added += 1
        return added
    
    def get_result(self, timeout: float = 0.1) -> Optional[Any]:
        """获取结果"""
        try:
            return self._result_queue.get(timeout=timeout)
        except Empty:
            return None
    
    def start(self):
        """启动调度器"""
        if self._running:
            return
        
        self._running = True
        
        for i in range(self.max_workers):
            worker = threading.Thread(
                target=self._worker_loop,
                name=f"Dispatcher-Worker-{i}",
                daemon=True
            )
            worker.start()
            self._workers.append(worker)
    
    def stop(self):
        """停止调度器"""
        self._running = False
        
        for worker in self._workers:
            worker.join(timeout=1.0)
        
        self._workers.clear()
    
    def _worker_loop(self):
        """工作线程循环"""
        while self._running:
            try:
                task = self._task_queue.get(timeout=0.1)
                
                try:
                    handler = self._handlers.get(task.task_type)
                    
                    if handler:
                        result = handler(task)
                        
                        if task.callback:
                            task.callback(result)
                        
                        self._result_queue.put({
                            'task_id': task.task_id,
                            'result': result,
                            'success': True
                        })
                    else:
                        self._result_queue.put({
                            'task_id': task.task_id,
                            'result': None,
                            'success': False,
                            'error': f"No handler for task type: {task.task_type}"
                        })
                
                except Exception as e:
                    self._result_queue.put({
                        'task_id': task.task_id,
                        'result': None,
                        'success': False,
                        'error': str(e)
                    })
                
                finally:
                    with self._stats_lock:
                        self._stats['pending_tasks'] -= 1
                        self._stats['completed_tasks'] += 1
                    
                    self._task_queue.task_done()
                    
            except Empty:
                continue
            except Exception as e:
                with self._stats_lock:
                    self._stats['failed_tasks'] += 1
    
    @property
    def stats(self) -> Dict[str, int]:
        """获取统计信息"""
        with self._stats_lock:
            return self._stats.copy()
    
    @property
    def queue_size(self) -> int:
        """获取队列大小"""
        return self._task_queue.qsize()
    
    def wait_completion(self, timeout: float = None):
        """等待所有任务完成"""
        self._task_queue.join()


class AsyncTaskDispatcher:
    """异步任务调度器"""
    
    def __init__(self, max_concurrent: int = 50):
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self._running = False
        self._tasks: List[asyncio.Task] = []
        self._results: List[Any] = []
        self._lock = asyncio.Lock()
    
    @staticmethod
    async def probe_concurrency(
        test_url: str,
        test_requests: int = 20,
        timeout: float = 5.0
    ) -> int:
        """
        探测目标服务器的最大并发承受能力
        
        Args:
            test_url: 测试用的 URL
            test_requests: 发送的测试请求数
            timeout: 单个请求超时时间
            
        Returns:
            建议的最大并发数
        """
        import aiohttp
        
        success_count = 0
        fail_count = 0
        
        async def single_request(session: aiohttp.ClientSession) -> bool:
            try:
                async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                    return resp.status < 500
            except Exception:
                return False
        
        try:
            async with aiohttp.ClientSession() as session:
                tasks = [single_request(session) for _ in range(test_requests)]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for result in results:
                    if isinstance(result, Exception):
                        fail_count += 1
                    elif result:
                        success_count += 1
                    else:
                        fail_count += 1
        except Exception:
            return 10
        
        if success_count == test_requests:
            return min(test_requests, 200)
        elif success_count >= test_requests * 0.8:
            return min(test_requests // 2, 100)
        elif success_count >= test_requests * 0.5:
            return min(test_requests // 4, 50)
        else:
            return min(test_requests // 8, 25)
    
    async def execute(self, coro: Callable, *args, **kwargs) -> Any:
        """执行异步任务"""
        async with self.semaphore:
            return await coro(*args, **kwargs)
    
    async def execute_many(
        self,
        coros: List[Callable],
        progress_callback: Optional[Callable] = None
    ) -> List[Any]:
        """批量执行异步任务"""
        results = []
        
        for i, coro in enumerate(asyncio.as_completed(coros)):
            result = await coro
            
            if progress_callback and (i + 1) % 10 == 0:
                progress_callback(i + 1, len(coros))
            
            results.append(result)
        
        return results
    
    async def execute_with_retry(
        self,
        coro: Callable,
        max_retries: int = 3,
        *args,
        **kwargs
    ) -> Any:
        """带重试的异步执行"""
        for attempt in range(max_retries):
            try:
                return await coro(*args, **kwargs)
            except Exception as e:
                if attempt == max_retries - 1:
                    raise
                await asyncio.sleep(0.5 * (attempt + 1))


class PriorityQueue:
    """优先级队列"""
    
    def __init__(self):
        self._queue: List[Task] = []
        self._lock = threading.Lock()
    
    def put(self, task: Task):
        """添加任务"""
        with self._lock:
            self._queue.append(task)
            self._queue.sort(key=lambda t: t.priority.value, reverse=True)
    
    def get(self) -> Optional[Task]:
        """获取任务"""
        with self._lock:
            if self._queue:
                return self._queue.pop(0)
            return None
    
    def empty(self) -> bool:
        """检查是否为空"""
        with self._lock:
            return len(self._queue) == 0
    
    def size(self) -> int:
        """获取大小"""
        with self._lock:
            return len(self._queue)
