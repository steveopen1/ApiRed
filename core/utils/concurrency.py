"""
Concurrency Control Module
并发控制模块
"""

import asyncio
import threading
from typing import Any, Callable, List, Optional, TypeVar, Generic
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from dataclasses import dataclass, field
from queue import Queue, Empty
import time


T = TypeVar('T')


@dataclass
class WorkerStats:
    """工作器统计"""
    total_processed: int = 0
    total_errors: int = 0
    total_time: float = 0.0
    avg_time: float = 0.0


class SemaphorePool:
    """信号量池"""
    
    def __init__(self, max_workers: int = 10):
        self.semaphore = asyncio.Semaphore(max_workers)
        self.max_workers = max_workers
        self._current = 0
        self._lock = asyncio.Lock()
    
    async def acquire(self):
        """获取信号量"""
        await self.semaphore.acquire()
        async with self._lock:
            self._current += 1
    
    def release(self):
        """释放信号量"""
        self.semaphore.release()
        self._current -= 1
    
    @property
    def current(self) -> int:
        """当前并发数"""
        return self._current


class ThreadPool:
    """线程池封装"""
    
    def __init__(self, max_workers: int = 10, name: str = 'ThreadPool'):
        self.max_workers = max_workers
        self.name = name
        self.executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix=name
        )
        self._stats = WorkerStats()
        self._stats_lock = threading.Lock()
    
    def submit(self, fn: Callable, *args, **kwargs):
        """提交任务"""
        return self.executor.submit(fn, *args, **kwargs)
    
    def map(self, fn: Callable, iterable):
        """批量映射"""
        return self.executor.map(fn, iterable)
    
    def shutdown(self, wait: bool = True):
        """关闭线程池"""
        self.executor.shutdown(wait=wait)
    
    @property
    def stats(self) -> WorkerStats:
        """获取统计信息"""
        return self._stats
    
    def update_stats(self, processed: int = 0, errors: int = 0, time_taken: float = 0.0):
        """更新统计"""
        with self._stats_lock:
            self._stats.total_processed += processed
            self._stats.total_errors += errors
            self._stats.total_time += time_taken
            if self._stats.total_processed > 0:
                self._stats.avg_time = (
                    self._stats.total_time / self._stats.total_processed
                )


class ProcessPool:
    """进程池封装"""
    
    def __init__(self, max_workers: int = 4, name: str = 'ProcessPool'):
        self.max_workers = max_workers
        self.name = name
        self.executor = ProcessPoolExecutor(max_workers=max_workers)
    
    def submit(self, fn: Callable, *args, **kwargs):
        """提交任务"""
        return self.executor.submit(fn, *args, **kwargs)
    
    def map(self, fn: Callable, iterable):
        """批量映射"""
        return self.executor.map(fn, iterable)
    
    def shutdown(self, wait: bool = True):
        """关闭进程池"""
        self.executor.shutdown(wait=wait)


class BatchProcessor(Generic[T]):
    """批处理器"""
    
    def __init__(
        self,
        batch_size: int = 100,
        max_concurrent: int = 10,
        process_fn: Optional[Callable] = None
    ):
        self.batch_size = batch_size
        self.max_concurrent = max_concurrent
        self.process_fn = process_fn
        self.queue: Queue = Queue()
        self.results: List[Any] = []
        self._running = False
        self._lock = threading.Lock()
    
    def add(self, item: T):
        """添加项目"""
        self.queue.put(item)
    
    def add_batch(self, items: List[T]):
        """批量添加"""
        for item in items:
            self.queue.put(item)
    
    def process(self, process_fn: Optional[Callable] = None) -> List[Any]:
        """处理队列中的所有项目"""
        fn = process_fn or self.process_fn
        if not fn:
            raise ValueError("No processing function provided")
        
        self._running = True
        results = []
        batch = []
        
        while self._running:
            try:
                item = self.queue.get(timeout=0.1)
                batch.append(item)
                
                if len(batch) >= self.batch_size:
                    batch_results = self._process_batch(batch, fn)
                    results.extend(batch_results)
                    batch = []
                    
            except Empty:
                if batch:
                    batch_results = self._process_batch(batch, fn)
                    results.extend(batch_results)
                break
        
        with self._lock:
            self.results = results
        
        return results
    
    def _process_batch(self, batch: List[T], fn: Callable) -> List[Any]:
        """处理单个批次"""
        with ThreadPoolExecutor(max_workers=self.max_concurrent) as executor:
            return list(executor.map(fn, batch))
    
    def stop(self):
        """停止处理"""
        self._running = False


class RateLimiter:
    """速率限制器"""
    
    def __init__(self, max_requests: int, time_window: float = 1.0):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests: List[float] = []
        self._lock = threading.Lock()
    
    def acquire(self) -> bool:
        """获取许可"""
        with self._lock:
            now = time.time()
            self.requests = [
                t for t in self.requests if now - t < self.time_window
            ]
            
            if len(self.requests) < self.max_requests:
                self.requests.append(now)
                return True
            return False
    
    async def async_acquire(self) -> bool:
        """异步获取许可"""
        while not self.acquire():
            await asyncio.sleep(0.1)
        return True
    
    @property
    def current_rate(self) -> float:
        """当前速率"""
        with self._lock:
            now = time.time()
            self.requests = [
                t for t in self.requests if now - t < self.time_window
            ]
            return len(self.requests) / self.time_window
