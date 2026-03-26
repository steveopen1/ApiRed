"""
Multi-Level Cache Module - 多级缓存架构

提供三级缓存：
- L1: 进程内内存 (LRU + 访问频率)
- L2: Redis/DB (持久化, TTL)
- L3: SQLite/文件 (归档)

设计参考：
- Redis的LFU策略
- CPU多级缓存的写回策略
"""

import time
import threading
import hashlib
import pickle
from abc import ABC, abstractmethod
from collections import OrderedDict
from typing import Optional, Any, Dict, Generic, TypeVar, Callable
from dataclasses import dataclass, field
import logging

logger = logging.getLogger(__name__)

T = TypeVar('T')


@dataclass
class CacheEntry(Generic[T]):
    """缓存条目"""
    key: str
    value: T
    created_at: float = field(default_factory=time.time)
    last_accessed: float = field(default_factory=time.time)
    access_count: int = 0
    ttl: Optional[int] = None
    
    def is_expired(self) -> bool:
        """检查是否过期"""
        if self.ttl is None:
            return False
        return time.time() - self.created_at > self.ttl
    
    def touch(self):
        """更新访问时间"""
        self.last_accessed = time.time()
        self.access_count += 1


class CacheLevel(ABC):
    """缓存层抽象基类"""
    
    @abstractmethod
    def get(self, key: str) -> Optional[Any]:
        """获取缓存"""
        pass
    
    @abstractmethod
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """设置缓存"""
        pass
    
    @abstractmethod
    def delete(self, key: str) -> bool:
        """删除缓存"""
        pass
    
    @abstractmethod
    def clear(self) -> None:
        """清空缓存"""
        pass
    
    @abstractmethod
    def size(self) -> int:
        """获取缓存大小"""
        pass


class LRUCache(CacheLevel):
    """
    L1: 进程内LRU缓存
    
    特性：
    - 基于访问频率的LRU淘汰
    - 支持TTL过期
    - 线程安全
    """
    
    def __init__(self, max_size: int = 1000, ttl: Optional[int] = None):
        self.max_size = max_size
        self.default_ttl = ttl
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._lock = threading.RLock()
        self._hits = 0
        self._misses = 0
    
    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                self._misses += 1
                return None
            
            if entry.is_expired():
                del self._cache[key]
                self._misses += 1
                return None
            
            self._cache.move_to_end(key)
            entry.touch()
            return entry.value
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        with self._lock:
            if key in self._cache:
                self._cache[key].value = value
                self._cache[key].ttl = ttl
                self._cache[key].touch()
                self._cache.move_to_end(key)
            else:
                if len(self._cache) >= self.max_size:
                    self._evict_lru()
                
                entry = CacheEntry(
                    key=key,
                    value=value,
                    ttl=ttl or self.default_ttl
                )
                self._cache[key] = entry
    
    def _evict_lru(self):
        """淘汰最少使用的条目"""
        if not self._cache:
            return
        
        lru_key = next(iter(self._cache))
        del self._cache[lru_key]
    
    def delete(self, key: str) -> bool:
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                return True
            return False
    
    def clear(self) -> None:
        with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0
    
    def size(self) -> int:
        with self._lock:
            return len(self._cache)
    
    @property
    def stats(self) -> Dict[str, Any]:
        with self._lock:
            total = self._hits + self._misses
            hit_rate = self._hits / total if total > 0 else 0.0
            return {
                'size': len(self._cache),
                'max_size': self.max_size,
                'hits': self._hits,
                'misses': self._misses,
                'hit_rate': hit_rate
            }


class LFUCache(CacheLevel):
    """
    L1: 进程内LFU缓存（访问频率优先）
    
    特性：
    - 最少使用条目优先淘汰
    - 基于Redis的LFU近似算法
    """
    
    def __init__(self, max_size: int = 1000, ttl: Optional[int] = None):
        self.max_size = max_size
        self.default_ttl = ttl
        self._cache: Dict[str, CacheEntry] = {}
        self._access_order: list = []
        self._lock = threading.RLock()
        self._hits = 0
        self._misses = 0
    
    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                self._misses += 1
                return None
            
            if entry.is_expired():
                self._remove_from_cache(key)
                self._misses += 1
                return None
            
            entry.touch()
            self._update_access_order(key)
            return entry.value
    
    def _update_access_order(self, key: str):
        """更新访问顺序"""
        if key in self._access_order:
            self._access_order.remove(key)
        self._access_order.append(key)
    
    def _remove_from_cache(self, key: str):
        """从缓存移除"""
        if key in self._cache:
            del self._cache[key]
        if key in self._access_order:
            self._access_order.remove(key)
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        with self._lock:
            if key in self._cache:
                self._cache[key].value = value
                self._cache[key].ttl = ttl
                self._cache[key].touch()
                self._update_access_order(key)
            else:
                if len(self._cache) >= self.max_size:
                    self._evict_lfu()
                
                entry = CacheEntry(
                    key=key,
                    value=value,
                    ttl=ttl or self.default_ttl
                )
                self._cache[key] = entry
                self._access_order.append(key)
    
    def _evict_lfu(self):
        """淘汰最少使用的条目"""
        if not self._cache:
            return
        
        lfu_key = None
        min_count = float('inf')
        
        for key in self._access_order:
            entry = self._cache.get(key)
            if entry and entry.access_count < min_count:
                min_count = entry.access_count
                lfu_key = key
        
        if lfu_key:
            self._remove_from_cache(lfu_key)
    
    def delete(self, key: str) -> bool:
        with self._lock:
            if key in self._cache:
                self._remove_from_cache(key)
                return True
            return False
    
    def clear(self) -> None:
        with self._lock:
            self._cache.clear()
            self._access_order.clear()
            self._hits = 0
            self._misses = 0
    
    def size(self) -> int:
        with self._lock:
            return len(self._cache)
    
    @property
    def stats(self) -> Dict[str, Any]:
        with self._lock:
            total = self._hits + self._misses
            hit_rate = self._hits / total if total > 0 else 0.0
            return {
                'size': len(self._cache),
                'max_size': self.max_size,
                'hits': self._hits,
                'misses': self._misses,
                'hit_rate': hit_rate
            }


class TwoLevelCache(CacheLevel):
    """
    两级缓存管理器 (L1内存 + L2存储)
    
    策略：
    - L1: LRU/LFU内存缓存
    - L2: 数据库/文件持久化存储
    - 读取时L1优先，写入时双写
    """
    
    def __init__(
        self,
        l1_cache: Optional[CacheLevel] = None,
        l2_store: Optional[Callable[[str], Any]] = None,
        l2_save: Optional[Callable[[str, Any], None]] = None,
        on_l2_hit: Optional[Callable[[str, Any], None]] = None
    ):
        self.l1 = l1_cache or LRUCache(max_size=1000)
        self.l2_store = l2_store
        self.l2_save = l2_save
        self.on_l2_hit = on_l2_hit
    
    def get(self, key: str) -> Optional[Any]:
        value = self.l1.get(key)
        if value is not None:
            return value
        
        if self.l2_store:
            value = self.l2_store(key)
            if value is not None:
                self.l1.set(key, value)
                if self.on_l2_hit:
                    self.on_l2_hit(key, value)
                return value
        
        return None
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        self.l1.set(key, value, ttl)
        if self.l2_save:
            self.l2_save(key, value)
    
    def delete(self, key: str) -> bool:
        deleted = self.l1.delete(key)
        return deleted
    
    def clear(self) -> None:
        self.l1.clear()
    
    def size(self) -> int:
        return self.l1.size()
    
    @property
    def stats(self) -> Dict[str, Any]:
        base_stats = self.l1.stats if hasattr(self.l1, 'stats') else {'size': self.size()}
        base_stats['l1_type'] = type(self.l1).__name__
        return base_stats


class MultiLevelCacheManager:
    """
    多级缓存管理器
    
    支持三级缓存：
    - L1: 进程内内存 (最快)
    - L2: Redis/DB (分布式共享)
    - L3: SQLite/文件 (持久化归档)
    
    读取策略: L1 → L2 → L3
    写入策略: 写穿所有层
    """
    
    def __init__(
        self,
        l1_size: int = 1000,
        l2_enabled: bool = False,
        l3_enabled: bool = False,
        cache_ttl: int = 3600
    ):
        self.l1 = LRUCache(max_size=l1_size, ttl=cache_ttl)
        self.l2_enabled = l2_enabled
        self.l3_enabled = l3_enabled
        self._l2_cache: Optional[Any] = None
        self._l3_cache: Optional[Any] = None
    
    def get(self, key: str) -> Optional[Any]:
        value = self.l1.get(key)
        if value is not None:
            return value
        
        if self.l2_enabled and self._l2_cache:
            value = self._l2_cache.get(key)
            if value is not None:
                self.l1.set(key, value)
                return value
        
        if self.l3_enabled and self._l3_cache:
            value = self._l3_cache.get(key)
            if value is not None:
                self.l1.set(key, value)
                return value
        
        return None
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        self.l1.set(key, value, ttl)
        
        if self.l2_enabled and self._l2_cache:
            self._l2_cache.set(key, value, ttl)
        
        if self.l3_enabled and self._l3_cache:
            self._l3_cache.set(key, value, ttl)
    
    def delete(self, key: str) -> bool:
        deleted = self.l1.delete(key)
        
        if self.l2_enabled and self._l2_cache:
            self._l2_cache.delete(key)
        
        if self.l3_enabled and self._l3_cache:
            self._l3_cache.delete(key)
        
        return deleted
    
    def clear(self) -> None:
        self.l1.clear()
        
        if self.l2_enabled and self._l2_cache:
            self._l2_cache.clear()
        
        if self.l3_enabled and self._l3_cache:
            self._l3_cache.clear()
    
    def set_l2_cache(self, cache: CacheLevel):
        """设置L2缓存"""
        self._l2_cache = cache
        self.l2_enabled = True
    
    def set_l3_cache(self, cache: CacheLevel):
        """设置L3缓存"""
        self._l3_cache = cache
        self.l3_enabled = True
    
    @property
    def stats(self) -> Dict[str, Any]:
        return {
            'l1': self.l1.stats,
            'l2_enabled': self.l2_enabled,
            'l3_enabled': self.l3_enabled
        }


def adaptive_cache_key(*args, **kwargs) -> str:
    """
    生成自适应缓存键
    
    基于参数生成稳定的哈希键
    """
    key_data = pickle.dumps((args, sorted(kwargs.items())))
    return hashlib.sha256(key_data).hexdigest()[:32]
