"""
Circuit Breaker Module
熔断器模块 - 防止级联故障
"""

import asyncio
import time
import logging
from enum import Enum
from typing import Optional, Callable, Any
from dataclasses import dataclass, field
from functools import wraps

logger = logging.getLogger(__name__)


class CircuitState(Enum):
    """熔断器状态"""
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class CircuitStats:
    """熔断器统计"""
    total_calls: int = 0
    successful_calls: int = 0
    failed_calls: int = 0
    rejected_calls: int = 0
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    last_failure_time: Optional[float] = None
    last_success_time: Optional[float] = None
    state_changes: int = 0


class CircuitBreaker:
    """
    熔断器实现
    
    状态转换:
    - CLOSED: 正常状态，请求通过
    - OPEN: 熔断状态，请求被拒绝
    - HALF_OPEN: 半开状态，允许有限请求测试服务
    
    参数:
        failure_threshold: 触发熔断的连续失败次数 (默认: 5)
        success_threshold: 从OPEN转到HALF_OPEN所需的成功次数 (默认: 3)
        timeout: OPEN状态的持续时间(秒) (默认: 30)
        half_open_max_calls: HALF_OPEN状态允许的最大并发调用数 (默认: 3)
    """
    
    def __init__(
        self,
        name: str = "default",
        failure_threshold: int = 5,
        success_threshold: int = 3,
        timeout: float = 30.0,
        half_open_max_calls: int = 3
    ):
        self.name = name
        self.failure_threshold = failure_threshold
        self.success_threshold = success_threshold
        self.timeout = timeout
        self.half_open_max_calls = half_open_max_calls
        
        self._state = CircuitState.CLOSED
        self._stats = CircuitStats()
        self._state_since: float = time.time()
        self._half_open_semaphore: Optional[asyncio.Semaphore] = None
        self._lock = asyncio.Lock()
        
        if half_open_max_calls > 0:
            self._half_open_semaphore = asyncio.Semaphore(half_open_max_calls)
    
    @property
    def state(self) -> CircuitState:
        """获取当前状态"""
        if self._state == CircuitState.OPEN:
            if time.time() - self._state_since >= self.timeout:
                return CircuitState.HALF_OPEN
        return self._state
    
    @property
    def stats(self) -> CircuitStats:
        """获取统计信息"""
        return self._stats
    
    def is_available(self) -> bool:
        """检查是否接受请求"""
        current_state = self.state
        if current_state == CircuitState.CLOSED:
            return True
        if current_state == CircuitState.HALF_OPEN:
            return self._half_open_semaphore is None or self._half_open_semaphore.locked() is False
        return False
    
    async def call(self, func: Callable, *args, **kwargs) -> Any:
        """
        通过熔断器调用函数
        
        Args:
            func: 异步函数
            *args: 位置参数
            **kwargs: 关键字参数
        
        Returns:
            函数返回值
        
        Raises:
            CircuitBreakerOpen: 当熔断器处于OPEN状态时
            Exception: 当函数调用失败时
        """
        current_state = self.state
        
        if current_state == CircuitState.OPEN:
            self._stats.rejected_calls += 1
            raise CircuitBreakerOpen(f"Circuit breaker '{self.name}' is OPEN")
        
        if current_state == CircuitState.HALF_OPEN:
            if self._half_open_semaphore:
                async with self._half_open_semaphore:
                    return await self._do_call(func, *args, **kwargs)
            else:
                return await self._do_call(func, *args, **kwargs)
        
        return await self._do_call(func, *args, **kwargs)
    
    async def _do_call(self, func: Callable, *args, **kwargs) -> Any:
        """执行实际调用"""
        async with self._lock:
            self._stats.total_calls += 1
        
        try:
            result = await func(*args, **kwargs)
            await self._on_success()
            return result
        except Exception as e:
            await self._on_failure()
            raise
    
    async def _on_success(self):
        """记录成功调用"""
        async with self._lock:
            self._stats.successful_calls += 1
            self._stats.consecutive_failures = 0
            self._stats.consecutive_successes += 1
            self._stats.last_success_time = time.time()
            
            if self._state == CircuitState.HALF_OPEN:
                if self._stats.consecutive_successes >= self.success_threshold:
                    await self._transition_to(CircuitState.CLOSED)
    
    async def _on_failure(self):
        """记录失败调用"""
        async with self._lock:
            self._stats.failed_calls += 1
            self._stats.consecutive_successes = 0
            self._stats.consecutive_failures += 1
            self._stats.last_failure_time = time.time()
            
            if self._state == CircuitState.HALF_OPEN:
                await self._transition_to(CircuitState.OPEN)
            elif self._state == CircuitState.CLOSED:
                if self._stats.consecutive_failures >= self.failure_threshold:
                    await self._transition_to(CircuitState.OPEN)
    
    async def _transition_to(self, new_state: CircuitState):
        """状态转换"""
        if self._state == new_state:
            return
        
        old_state = self._state
        self._state = new_state
        self._state_since = time.time()
        self._stats.state_changes += 1
        
        if new_state == CircuitState.HALF_OPEN:
            self._stats.consecutive_successes = 0
        elif new_state == CircuitState.CLOSED:
            self._stats.consecutive_failures = 0
            self._stats.consecutive_successes = 0
        
        logger.warning(
            f"Circuit breaker '{self.name}' state changed: {old_state.value} -> {new_state.value}"
        )
    
    async def reset(self):
        """重置熔断器"""
        async with self._lock:
            self._state = CircuitState.CLOSED
            self._stats = CircuitStats()
            self._state_since = time.time()
            logger.info(f"Circuit breaker '{self.name}' reset")
    
    def get_health_report(self) -> dict:
        """获取健康报告"""
        current_state = self.state
        return {
            'name': self.name,
            'state': current_state.value,
            'state_since': self._state_since,
            'stats': {
                'total_calls': self._stats.total_calls,
                'successful_calls': self._stats.successful_calls,
                'failed_calls': self._stats.failed_calls,
                'rejected_calls': self._stats.rejected_calls,
                'consecutive_failures': self._stats.consecutive_failures,
                'consecutive_successes': self._stats.consecutive_successes,
                'failure_rate': (
                    self._stats.failed_calls / self._stats.total_calls
                    if self._stats.total_calls > 0 else 0
                )
            }
        }


class CircuitBreakerOpen(Exception):
    """熔断器开启异常"""
    pass


def circuit_breaker(
    failure_threshold: int = 5,
    success_threshold: int = 3,
    timeout: float = 30.0,
    name: Optional[str] = None
):
    """
    熔断器装饰器
    
    用法:
        @circuit_breaker(name="my_service", failure_threshold=3)
        async def my_function():
            ...
    """
    def decorator(func: Callable) -> Callable:
        _name = name or func.__name__
        breaker = CircuitBreaker(
            name=_name,
            failure_threshold=failure_threshold,
            success_threshold=success_threshold,
            timeout=timeout
        )
        
        @wraps(func)
        async def wrapper(*args, **kwargs):
            return await breaker.call(func, *args, **kwargs)
        
        wrapper._circuit_breaker = breaker
        wrapper.circuit_breaker = breaker
        return wrapper
    
    return decorator
