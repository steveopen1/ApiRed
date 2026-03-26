"""
Error Handler Module - 错误处理分级模块

提供分级错误处理机制：
- RECOVERABLE: 可恢复，记录但不中断
- CONFIGURATION: 配置错误，立即终止
- FATAL: 致命错误，程序退出
"""

from enum import Enum
from typing import Optional, Callable, Any, TypeVar, Generic
import logging
import traceback

logger = logging.getLogger(__name__)


class ErrorSeverity(Enum):
    """错误严重级别"""
    RECOVERABLE = "recoverable"
    CONFIGURATION = "configuration"
    FATAL = "fatal"


class FuzzingError(Exception):
    """
    Fuzzing专用异常类
    
    支持错误分级和重试计数：
    - RECOVERABLE: 可恢复错误，记录并重试
    - CONFIGURATION: 配置错误，立即终止
    - FATAL: 致命错误，程序退出
    """
    
    def __init__(
        self,
        message: str,
        severity: ErrorSeverity = ErrorSeverity.RECOVERABLE,
        retry_count: int = 0,
        context: str = ""
    ):
        super().__init__(message)
        self.message = message
        self.severity = severity
        self.retry_count = retry_count
        self.context = context
    
    def __str__(self):
        if self.context:
            return f"[{self.severity.value}] {self.context}: {self.message}"
        return f"[{self.severity.value}] {self.message}"
    
    def is_recoverable(self) -> bool:
        """是否可恢复"""
        return self.severity == ErrorSeverity.RECOVERABLE
    
    def is_fatal(self) -> bool:
        """是否致命"""
        return self.severity == ErrorSeverity.FATAL


class NetworkError(FuzzingError):
    """网络相关错误"""
    def __init__(self, message: str, retry_count: int = 0, context: str = ""):
        super().__init__(
            message=message,
            severity=ErrorSeverity.RECOVERABLE,
            retry_count=retry_count,
            context=context or "network"
        )


class DNSError(FuzzingError):
    """DNS解析错误"""
    def __init__(self, message: str, retry_count: int = 0, context: str = ""):
        super().__init__(
            message=message,
            severity=ErrorSeverity.RECOVERABLE,
            retry_count=retry_count,
            context=context or "dns"
        )


class HTTPError(FuzzingError):
    """HTTP请求错误"""
    def __init__(self, message: str, status_code: Optional[int] = None, 
                 retry_count: int = 0, context: str = ""):
        super().__init__(
            message=message,
            severity=ErrorSeverity.RECOVERABLE,
            retry_count=retry_count,
            context=context or "http"
        )
        self.status_code = status_code


class ConfigurationError(FuzzingError):
    """配置错误"""
    def __init__(self, message: str, context: str = ""):
        super().__init__(
            message=message,
            severity=ErrorSeverity.CONFIGURATION,
            retry_count=0,
            context=context or "configuration"
        )


class FatalError(FuzzingError):
    """致命错误"""
    def __init__(self, message: str, context: str = ""):
        super().__init__(
            message=message,
            severity=ErrorSeverity.FATAL,
            retry_count=0,
            context=context or "fatal"
        )


class ErrorHandler:
    """
    错误处理器
    
    提供分级错误处理策略：
    - 根据错误严重级别决定是否重试
    - 记录错误日志
    - 触发回调函数
    """
    
    def __init__(self, max_retries: int = 3):
        self.max_retries = max_retries
        self._error_counts = {}
        self._error_handlers = {}
        self._recovery_handlers = {}
    
    def register_handler(self, error_type: type, handler: Callable[['FuzzingError'], bool]):
        """
        注册错误处理器
        
        Args:
            error_type: 错误类型
            handler: 处理函数，返回True表示已处理，False表示未处理
        """
        self._error_handlers[error_type] = handler
    
    def register_recovery(self, error_type: type, recovery: Callable):
        """
        注册恢复函数
        
        Args:
            error_type: 错误类型
            recovery: 恢复函数
        """
        self._recovery_handlers[error_type] = recovery
    
    def handle_error(self, error: Exception, context: str = "") -> bool:
        """
        处理错误
        
        Args:
            error: 错误对象
            context: 错误上下文
            
        Returns:
            True if error is recoverable and operation should retry
            False if error is fatal and should terminate
        """
        error_key = f"{context}:{type(error).__name__}"
        self._error_counts[error_key] = self._error_counts.get(error_key, 0) + 1
        
        if isinstance(error, FuzzingError):
            if error.severity == ErrorSeverity.FATAL:
                logger.error(f"[FATAL] {context}: {error}")
                return False
            elif error.severity == ErrorSeverity.CONFIGURATION:
                logger.error(f"[CONFIGURATION] {context}: {error}")
                raise error
            else:
                logger.warning(f"[RECOVERABLE] {context}: {error}")
                
                recovery_handler = self._recovery_handlers.get(type(error))
                if recovery_handler:
                    try:
                        recovery_handler(error)
                    except Exception as e:
                        logger.debug(f"Recovery handler failed: {e}")
                
                return True
        
        error_type = type(error)
        if error_type in self._error_handlers:
            return self._error_handlers[error_type](error)
        
        logger.warning(f"[UNKNOWN] {context}: {error}")
        return True
    
    def should_retry(self, error: FuzzingError, current_retry: int) -> bool:
        """
        判断是否应该重试
        
        Args:
            error: 错误对象
            current_retry: 当前重试次数
            
        Returns:
            True if should retry, False otherwise
        """
        if error.is_fatal():
            return False
        
        if current_retry >= self.max_retries:
            return False
        
        if error.retry_count >= self.max_retries:
            return False
        
        return True
    
    @property
    def error_stats(self) -> dict:
        """获取错误统计信息"""
        return dict(self._error_counts)


def handle_error(error: Exception, context: str = "") -> bool:
    """
    全局错误处理函数
    
    便捷函数，用于快速处理错误。
    
    Args:
        error: 错误对象
        context: 错误上下文
        
    Returns:
        True if error is recoverable and operation should retry
        False if error is fatal and should terminate
    """
    default_handler = ErrorHandler()
    return default_handler.handle_error(error, context)


def retry_with_backoff(
    max_retries: int = 3,
    initial_delay: float = 1.0,
    backoff_factor: float = 2.0,
    max_delay: float = 30.0
):
    """
    指数退避重试装饰器
    
    Args:
        max_retries: 最大重试次数
        initial_delay: 初始延迟（秒）
        backoff_factor: 退避因子
        max_delay: 最大延迟（秒）
    """
    def decorator(func):
        async def wrapper(*args, **kwargs):
            import asyncio
            
            delay = initial_delay
            last_error = None
            
            for attempt in range(max_retries):
                try:
                    return await func(*args, **kwargs)
                except FuzzingError as e:
                    last_error = e
                    if e.is_fatal():
                        raise
                    if attempt < max_retries - 1:
                        logger.warning(f"Attempt {attempt + 1} failed: {e}, retrying in {delay}s...")
                        await asyncio.sleep(delay)
                        delay = min(delay * backoff_factor, max_delay)
                    else:
                        logger.error(f"All {max_retries} attempts failed")
                except Exception as e:
                    last_error = e
                    logger.warning(f"Attempt {attempt + 1} failed: {e}")
                    if attempt < max_retries - 1:
                        await asyncio.sleep(delay)
                        delay = min(delay * backoff_factor, max_delay)
                    else:
                        logger.error(f"All {max_retries} attempts failed")
            
            if last_error:
                raise last_error
        
        return wrapper
    return decorator


class CircuitBreaker:
    """
    熔断器
    
    当错误率超过阈值时，熔断后续请求，避免雪崩效应。
    """
    
    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
        expected_exception: type = Exception
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception
        
        self._failure_count = 0
        self._last_failure_time = None
        self._is_open = False
    
    @property
    def is_open(self) -> bool:
        """熔断器是否打开"""
        if not self._is_open:
            return False
        
        import time
        if time.time() - self._last_failure_time > self.recovery_timeout:
            self._is_open = False
            self._failure_count = 0
            return False
        
        return True
    
    def record_success(self):
        """记录成功"""
        self._failure_count = 0
        self._is_open = False
    
    def record_failure(self):
        """记录失败"""
        import time
        
        self._failure_count += 1
        self._last_failure_time = time.time()
        
        if self._failure_count >= self.failure_threshold:
            self._is_open = True
            logger.warning(f"Circuit breaker opened after {self._failure_count} failures")
    
    async def call(self, func, *args, **kwargs):
        """
        通过熔断器执行函数
        
        Args:
            func: 要执行的函数
            *args, **kwargs: 函数参数
            
        Returns:
            函数返回值
            
        Raises:
            FuzzingError: 熔断器打开时抛出
        """
        if self.is_open:
            raise FuzzingError(
                message="Circuit breaker is open",
                severity=ErrorSeverity.RECOVERABLE,
                context="circuit_breaker"
            )
        
        try:
            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)
            self.record_success()
            return result
        except self.expected_exception as e:
            self.record_failure()
            raise
