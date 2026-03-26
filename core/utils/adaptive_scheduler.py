"""
Adaptive Batch Scheduler - 自适应批处理调度器

基于目标响应时间动态调整batch_size的调度器。
参考TCP拥塞控制算法实现。
"""

import time
import threading
from collections import deque
from typing import Optional, List, Any, Tuple, Callable, Awaitable
import asyncio
import logging

logger = logging.getLogger(__name__)


class AdaptiveBatchScheduler:
    """
    自适应批处理调度器
    
    根据目标响应时间动态调整batch_size：
    - 快速响应目标 → 增大batch，提高吞吐量
    - 慢速响应目标 → 减小batch，避免漏检
    
    参考TCP拥塞控制算法实现。
    """
    
    def __init__(
        self,
        initial_batch_size: int = 50,
        min_batch_size: int = 10,
        max_batch_size: int = 100,
        fast_threshold: float = 0.5,
        slow_threshold: float = 2.0,
        history_size: int = 20
    ):
        """
        初始化自适应调度器
        
        Args:
            initial_batch_size: 初始batch大小
            min_batch_size: 最小batch大小
            max_batch_size: 最大batch大小
            fast_threshold: 快速响应阈值（秒），低于此值认为是快速响应
            slow_threshold: 慢速响应阈值（秒），高于此值认为是慢速响应
            history_size: 历史记录大小
        """
        self.initial_batch_size = initial_batch_size
        self.min_batch_size = min_batch_size
        self.max_batch_size = max_batch_size
        self.fast_threshold = fast_threshold
        self.slow_threshold = slow_threshold
        self.history_size = history_size
        
        self._current_batch_size = initial_batch_size
        self._fast_response_times: deque = deque(maxlen=history_size)
        self._slow_response_times: deque = deque(maxlen=history_size)
        self._lock = threading.Lock()
        
        self._total_requests = 0
        self._success_count = 0
        self._fail_count = 0
        
    @property
    def batch_size(self) -> int:
        """获取当前batch大小"""
        return self._current_batch_size
    
    @property
    def stats(self) -> dict:
        """获取调度器统计信息"""
        return {
            'current_batch_size': self._current_batch_size,
            'total_requests': self._total_requests,
            'success_count': self._success_count,
            'fail_count': self._fail_count,
            'success_rate': self._success_count / max(1, self._total_requests),
            'avg_fast_response': sum(self._fast_response_times) / max(1, len(self._fast_response_times)) if self._fast_response_times else 0,
            'avg_slow_response': sum(self._slow_response_times) / max(1, len(self._slow_response_times)) if self._slow_response_times else 0,
        }
    
    def record_success(self, elapsed: float):
        """
        记录成功请求及其响应时间
        
        Args:
            elapsed: 响应时间（秒）
        """
        with self._lock:
            self._total_requests += 1
            self._success_count += 1
            
            if elapsed < self.fast_threshold:
                self._fast_response_times.append(elapsed)
                self._adjust_batch_size_increase()
            elif elapsed > self.slow_threshold:
                self._slow_response_times.append(elapsed)
                self._adjust_batch_size_decrease()
    
    def record_failure(self):
        """记录失败请求"""
        with self._lock:
            self._total_requests += 1
            self._fail_count += 1
            self._adjust_batch_size_decrease()
    
    def _adjust_batch_size_increase(self):
        """增加batch大小（基于快速响应）"""
        if len(self._fast_response_times) >= 5:
            avg = sum(self._fast_response_times) / len(self._fast_response_times)
            if avg < self.fast_threshold * 0.5:
                new_size = min(self.max_batch_size, int(self._current_batch_size * 1.2))
                if new_size != self._current_batch_size:
                    logger.debug(f"Batch size increased: {self._current_batch_size} -> {new_size} (avg_response={avg:.3f}s)")
                    self._current_batch_size = new_size
            elif avg < self.fast_threshold:
                new_size = min(self.max_batch_size, self._current_batch_size + 5)
                if new_size != self._current_batch_size:
                    logger.debug(f"Batch size increased: {self._current_batch_size} -> {new_size} (avg_response={avg:.3f}s)")
                    self._current_batch_size = new_size
    
    def _adjust_batch_size_decrease(self):
        """减少batch大小（基于慢速响应或失败）"""
        if len(self._slow_response_times) >= 3 or self._fail_count > 0:
            new_size = max(self.min_batch_size, int(self._current_batch_size * 0.8))
            if new_size != self._current_batch_size:
                logger.debug(f"Batch size decreased: {self._current_batch_size} -> {new_size}")
                self._current_batch_size = new_size
            self._slow_response_times.clear()
    
    def reset(self):
        """重置调度器到初始状态"""
        with self._lock:
            self._current_batch_size = self.initial_batch_size
            self._fast_response_times.clear()
            self._slow_response_times.clear()
            self._total_requests = 0
            self._success_count = 0
            self._fail_count = 0


class AdaptiveDNSResolver:
    """
    自适应DNS解析器
    
    基于DNS服务器响应时间动态调整并发数。
    """
    
    def __init__(
        self,
        base_concurrency: int = 50,
        min_concurrency: int = 10,
        max_concurrency: int = 100,
        fast_threshold: float = 0.1,
        slow_threshold: float = 2.0,
        history_size: int = 20
    ):
        """
        初始化自适应DNS解析器
        
        Args:
            base_concurrency: 基础并发数
            min_concurrency: 最小并发数
            max_concurrency: 最大并发数
            fast_threshold: 快速响应阈值（秒）
            slow_threshold: 慢速响应阈值（秒）
            history_size: 历史记录大小
        """
        self.base_concurrency = base_concurrency
        self.min_concurrency = min_concurrency
        self.max_concurrency = max_concurrency
        self.fast_threshold = fast_threshold
        self.slow_threshold = slow_threshold
        
        self._current_concurrency = base_concurrency
        self._response_times: deque = deque(maxlen=history_size)
        self._timeout_count = 0
        self._total_requests = 0
        self._lock = threading.Lock()
    
    @property
    def concurrency(self) -> int:
        """获取当前并发数"""
        return self._current_concurrency
    
    def record_response_time(self, elapsed: float):
        """
        记录响应时间并调整并发数
        
        Args:
            elapsed: 响应时间（秒）
        """
        with self._lock:
            self._total_requests += 1
            self._response_times.append(elapsed)
            
            if elapsed < self.fast_threshold:
                self._current_concurrency = min(
                    self.max_concurrency,
                    int(self._current_concurrency * 1.2)
                )
            elif elapsed > self.slow_threshold:
                self._current_concurrency = max(
                    self.min_concurrency,
                    int(self._current_concurrency * 0.8)
                )
    
    def record_timeout(self):
        """记录超时事件"""
        with self._lock:
            self._timeout_count += 1
            self._total_requests += 1
            if self._timeout_count >= 3:
                self._current_concurrency = max(
                    self.min_concurrency,
                    int(self._current_concurrency * 0.5)
                )
                self._timeout_count = 0
    
    @property
    def stats(self) -> dict:
        """获取解析器统计信息"""
        return {
            'current_concurrency': self._current_concurrency,
            'total_requests': self._total_requests,
            'timeout_count': self._timeout_count,
            'avg_response_time': sum(self._response_times) / max(1, len(self._response_times)) if self._response_times else 0,
        }
    
    def reset(self):
        """重置解析器到初始状态"""
        with self._lock:
            self._current_concurrency = self.base_concurrency
            self._response_times.clear()
            self._timeout_count = 0
            self._total_requests = 0


async def adaptive_batch_process(
    scheduler: AdaptiveBatchScheduler,
    items: List[Any],
    processor: Callable[[Any], Awaitable[Tuple[Any, bool, float]]],
    break_on_first_success: bool = False
) -> List[Any]:
    """
    使用自适应调度器批量处理项目
    
    Args:
        scheduler: 自适应调度器
        items: 要处理的项目列表
        processor: 异步处理函数，返回 (result, success, elapsed)
        break_on_first_success: 是否在第一次成功后停止
        
    Returns:
        成功处理的结果列表
    """
    results = []
    
    for i in range(0, len(items), scheduler.batch_size):
        batch = items[i:i + scheduler.batch_size]
        tasks = [processor(item) for item in batch]
        
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for item, result in zip(batch, batch_results):
            if isinstance(result, Exception):
                scheduler.record_failure()
                continue
                
            processed_item, success, elapsed = result
            if success:
                scheduler.record_success(elapsed)
                results.append(processed_item)
                if break_on_first_success:
                    return results
            else:
                scheduler.record_failure()
    
    return results
