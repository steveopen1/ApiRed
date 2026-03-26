"""
Cache Module - 多级缓存模块
"""

from .cache_levels import (
    CacheLevel,
    CacheEntry,
    LRUCache,
    LFUCache,
    TwoLevelCache,
    MultiLevelCacheManager,
    adaptive_cache_key
)

__all__ = [
    'CacheLevel',
    'CacheEntry',
    'LRUCache',
    'LFUCache',
    'TwoLevelCache',
    'MultiLevelCacheManager',
    'adaptive_cache_key',
]
