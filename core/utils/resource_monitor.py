"""
Resource Monitor
资源监控模块 - 内存/CPU限制与监控

功能：
1. 内存使用监控
2. CPU配额限制
3. 响应大小限制
4. 自动资源调控
"""

import os
import sys
import time
import asyncio
import logging
import resource
from typing import Optional, Callable
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ResourceLimits:
    """资源限制配置"""
    memory_limit_mb: Optional[int] = None
    cpu_quota_percent: Optional[float] = None
    max_response_size: int = 10 * 1024 * 1024
    max_concurrent_requests: int = 300


@dataclass
class ResourceUsage:
    """资源使用情况"""
    memory_mb: float
    memory_percent: float
    cpu_percent: float
    timestamp: float


class ResourceMonitor:
    """
    资源监控器
    
    监控：
    1. 内存使用量
    2. CPU使用率
    3. 响应大小
    4. 并发数
    """

    def __init__(self, limits: Optional[ResourceLimits] = None):
        self.limits = limits or ResourceLimits()
        self._usage_history = []
        self._max_history = 1000
        self._callbacks = []

    def set_memory_limit(self, limit_mb: int):
        """设置内存限制（仅在Linux有效）"""
        try:
            soft, hard = resource.getrlimit(resource.RLIMIT_AS)
            limit_bytes = limit_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (limit_bytes, hard))
            self.limits.memory_limit_mb = limit_mb
            logger.info(f"Memory limit set to {limit_mb}MB")
            return True
        except (ValueError, OSError) as e:
            logger.warning(f"Failed to set memory limit: {e}")
            return False

    def set_cpu_quota(self, quota_percent: float):
        """设置CPU配额（在容器中有效）"""
        self.limits.cpu_quota_percent = quota_percent
        try:
            cgroup_quota_path = '/sys/fs/cgroup/cpu/cpu.cfs_quota_us'
            if os.path.exists(cgroup_quota_path):
                quota_us = int(quota_percent * 1000)
                with open(cgroup_quota_path, 'w') as f:
                    f.write(str(quota_us))
                logger.info(f"CPU quota set to {quota_percent}%")
        except Exception as e:
            logger.debug(f"CPU quota not supported: {e}")

    def get_memory_usage(self) -> ResourceUsage:
        """获取当前内存使用情况"""
        try:
            import psutil
            process = psutil.Process()
            memory_info = process.memory_info()
            memory_mb = memory_info.rss / (1024 * 1024)
            memory_percent = process.memory_percent()

            return ResourceUsage(
                memory_mb=memory_mb,
                memory_percent=memory_percent,
                cpu_percent=process.cpu_percent(interval=0.1),
                timestamp=time.time()
            )
        except ImportError:
            return self._get_simple_memory_usage()

    def _get_simple_memory_usage(self) -> ResourceUsage:
        """使用resource模块获取内存使用"""
        try:
            usage = resource.getrusage(resource.RUSAGE_SELF)
            memory_mb = usage.ru_maxrss / 1024
            return ResourceUsage(
                memory_mb=memory_mb,
                memory_percent=0.0,
                cpu_percent=0.0,
                timestamp=time.time()
            )
        except Exception:
            return ResourceUsage(
                memory_mb=0.0,
                memory_percent=0.0,
                cpu_percent=0.0,
                timestamp=time.time()
            )

    def check_response_size(self, content_length: int) -> bool:
        """
        检查响应大小是否超限
        
        Returns:
            True if within limits, False if too large
        """
        if content_length > self.limits.max_response_size:
            logger.debug(
                f"Response too large: {content_length} > {self.limits.max_response_size}"
            )
            return False
        return True

    def record_usage(self):
        """记录当前资源使用"""
        usage = self.get_memory_usage()
        self._usage_history.append(usage)

        if len(self._usage_history) > self._max_history:
            self._usage_history.pop(0)

        if self.limits.memory_limit_mb:
            if usage.memory_mb > self.limits.memory_limit_mb * 0.9:
                self._trigger_memory_warning(usage)

    def _trigger_memory_warning(self, usage: ResourceUsage):
        """触发内存警告"""
        logger.warning(
            f"Memory usage high: {usage.memory_mb:.1f}MB "
            f"({usage.memory_percent:.1f}%)"
        )
        for callback in self._callbacks:
            try:
                callback(usage)
            except Exception as e:
                logger.debug(f"Warning callback failed: {e}")

    def register_warning_callback(self, callback: Callable[[ResourceUsage], None]):
        """注册资源警告回调"""
        self._callbacks.append(callback)

    def get_average_usage(self, last_n: int = 10) -> ResourceUsage:
        """获取最近N次平均使用量"""
        if not self._usage_history:
            return ResourceUsage(0, 0, 0, time.time())

        recent = self._usage_history[-last_n:]
        avg_memory = sum(u.memory_mb for u in recent) / len(recent)
        avg_percent = sum(u.memory_percent for u in recent) / len(recent)

        return ResourceUsage(
            memory_mb=avg_memory,
            memory_percent=avg_percent,
            cpu_percent=0,
            timestamp=time.time()
        )

    def should_throttle(self) -> bool:
        """判断是否应该限流"""
        if not self.limits.memory_limit_mb:
            return False

        recent = self.get_average_usage(5)
        return recent.memory_percent > 70.0

    def get_statistics(self) -> dict:
        """获取资源统计"""
        if not self._usage_history:
            return {'samples': 0}

        memory_values = [u.memory_mb for u in self._usage_history]
        return {
            'samples': len(self._usage_history),
            'memory_mb_avg': sum(memory_values) / len(memory_values),
            'memory_mb_max': max(memory_values),
            'memory_limit_mb': self.limits.memory_limit_mb,
            'max_response_size': self.limits.max_response_size,
        }


class AdaptiveResourceController:
    """
    自适应资源控制器
    
    根据资源使用情况自动调整扫描参数
    """

    def __init__(self, monitor: ResourceMonitor):
        self.monitor = monitor

    async def adapt_concurrency(self, current_concurrency: int) -> int:
        """
        根据资源使用情况调整并发数
        
        Returns:
            建议的新并发数
        """
        usage = self.monitor.get_memory_usage()

        if usage.memory_percent > 80:
            new_concurrency = int(current_concurrency * 0.7)
            logger.info(
                f"High memory usage, reducing concurrency: {current_concurrency} -> {new_concurrency}"
            )
            return max(new_concurrency, 10)

        elif usage.memory_percent < 50:
            new_concurrency = int(current_concurrency * 1.2)
            return min(new_concurrency, self.monitor.limits.max_concurrent_requests)

        return current_concurrency
