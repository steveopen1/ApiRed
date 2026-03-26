"""
Unit tests for Multi-Level Cache Module
"""

import pytest
import time
from collections import OrderedDict

from core.cache import (
    CacheLevel,
    CacheEntry,
    LRUCache,
    LFUCache,
    TwoLevelCache,
    MultiLevelCacheManager,
    adaptive_cache_key
)


class TestCacheEntry:
    """Test cases for CacheEntry"""
    
    def test_cache_entry_basic(self):
        """Test basic cache entry"""
        entry = CacheEntry(key="test", value="value")
        
        assert entry.key == "test"
        assert entry.value == "value"
        assert entry.access_count == 0
        assert entry.ttl is None
        assert not entry.is_expired()
    
    def test_cache_entry_ttl(self):
        """Test cache entry with TTL"""
        entry = CacheEntry(key="test", value="value", ttl=1)
        
        assert entry.ttl == 1
        assert not entry.is_expired()
        
        time.sleep(1.1)
        assert entry.is_expired()
    
    def test_cache_entry_touch(self):
        """Test cache entry touch"""
        entry = CacheEntry(key="test", value="value")
        
        entry.touch()
        
        assert entry.access_count == 1
        assert entry.last_accessed >= entry.created_at


class TestLRUCache:
    """Test cases for LRUCache"""
    
    def test_initialization(self):
        """Test LRU cache initialization"""
        cache = LRUCache(max_size=100, ttl=60)
        
        assert cache.max_size == 100
        assert cache.default_ttl == 60
        assert cache.size() == 0
    
    def test_basic_set_get(self):
        """Test basic set and get"""
        cache = LRUCache(max_size=10)
        
        cache.set("key1", "value1")
        
        assert cache.get("key1") == "value1"
        assert cache.size() == 1
    
    def test_lru_eviction(self):
        """Test LRU eviction on capacity"""
        cache = LRUCache(max_size=3)
        
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        cache.set("key3", "value3")
        
        assert cache.get("key1") == "value1"
        
        cache.set("key4", "value4")
        
        assert cache.get("key1") == "value1"
        assert cache.get("key4") == "value4"
        assert cache.get("key2") is None
    
    def test_lru_order_update(self):
        """Test LRU order is updated on access"""
        cache = LRUCache(max_size=3)
        
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        cache.set("key3", "value3")
        
        cache.get("key1")
        cache.set("key4", "value4")
        
        assert cache.get("key1") == "value1"
        assert cache.get("key3") is None
    
    def test_ttl_expiration(self):
        """Test TTL expiration"""
        cache = LRUCache(max_size=10, ttl=1)
        
        cache.set("key1", "value1")
        
        assert cache.get("key1") == "value1"
        
        time.sleep(1.1)
        
        assert cache.get("key1") is None
    
    def test_delete(self):
        """Test delete operation"""
        cache = LRUCache(max_size=10)
        
        cache.set("key1", "value1")
        assert cache.get("key1") == "value1"
        
        cache.delete("key1")
        
        assert cache.get("key1") is None
        assert cache.size() == 0
    
    def test_clear(self):
        """Test clear operation"""
        cache = LRUCache(max_size=10)
        
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        
        cache.clear()
        
        assert cache.size() == 0
        assert cache.stats['hits'] == 0
    
    def test_stats(self):
        """Test statistics tracking"""
        cache = LRUCache(max_size=10)
        
        cache.set("key1", "value1")
        cache.get("key1")
        cache.get("nonexistent")
        
        stats = cache.stats
        
        assert stats['hits'] == 1
        assert stats['misses'] == 1
        assert stats['hit_rate'] == 0.5


class TestLFUCache:
    """Test cases for LFUCache"""
    
    def test_initialization(self):
        """Test LFU cache initialization"""
        cache = LFUCache(max_size=100)
        
        assert cache.max_size == 100
        assert cache.size() == 0
    
    def test_lfu_eviction(self):
        """Test LFU eviction based on frequency"""
        cache = LFUCache(max_size=3)
        
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        cache.set("key3", "value3")
        
        cache.get("key1")
        cache.get("key1")
        cache.get("key2")
        
        cache.set("key4", "value4")
        
        assert cache.get("key1") == "value1"
        assert cache.get("key3") is None
    
    def test_lfu_access_count(self):
        """Test LFU access count tracking"""
        cache = LFUCache(max_size=10)
        
        cache.set("key1", "value1")
        cache.get("key1")
        cache.get("key1")
        cache.get("key1")
        
        entry = cache._cache.get("key1")
        assert entry.access_count == 3


class TestTwoLevelCache:
    """Test cases for TwoLevelCache"""
    
    def test_initialization(self):
        """Test two-level cache initialization"""
        l1 = LRUCache(max_size=10)
        cache = TwoLevelCache(l1_cache=l1)
        
        assert cache.l1 is l1
        assert cache.l2_store is None
    
    def test_l1_hit(self):
        """Test L1 cache hit"""
        l1 = LRUCache(max_size=10)
        cache = TwoLevelCache(l1_cache=l1)
        
        cache.set("key1", "value1")
        
        assert cache.get("key1") == "value1"
    
    def test_l2_fallback(self):
        """Test L2 cache fallback on L1 miss"""
        l1 = LRUCache(max_size=10)
        l2_store_called = False
        
        def l2_store(key):
            nonlocal l2_store_called
            l2_store_called = True
            return {"key1": "l2_value"}.get(key)
        
        cache = TwoLevelCache(l1_cache=l1, l2_store=l2_store)
        
        result = cache.get("key1")
        
        assert result == "l2_value"
        assert l2_store_called
        assert cache.l1.get("key1") == "l2_value"


class TestMultiLevelCacheManager:
    """Test cases for MultiLevelCacheManager"""
    
    def test_initialization(self):
        """Test manager initialization"""
        manager = MultiLevelCacheManager(l1_size=100, cache_ttl=3600)
        
        assert manager.l1.size() == 0
        assert not manager.l2_enabled
        assert not manager.l3_enabled
    
    def test_get_from_l1(self):
        """Test get from L1"""
        manager = MultiLevelCacheManager()
        
        manager.set("key1", "value1")
        
        assert manager.get("key1") == "value1"
    
    def test_set_propagates(self):
        """Test that set propagates to all levels"""
        manager = MultiLevelCacheManager()
        
        manager.set("key1", "value1")
        
        assert manager.l1.get("key1") == "value1"


class TestAdaptiveCacheKey:
    """Test cases for adaptive_cache_key"""
    
    def test_basic_key_generation(self):
        """Test basic cache key generation"""
        key1 = adaptive_cache_key("arg1", "arg2")
        key2 = adaptive_cache_key("arg1", "arg2")
        key3 = adaptive_cache_key("arg1", "arg3")
        
        assert key1 == key2
        assert key1 != key3
    
    def test_key_with_kwargs(self):
        """Test cache key with keyword arguments"""
        key1 = adaptive_cache_key("arg1", key="value")
        key2 = adaptive_cache_key("arg1", key="value")
        
        assert key1 == key2


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
