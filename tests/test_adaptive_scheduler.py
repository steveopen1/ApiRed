"""
Unit tests for AdaptiveBatchScheduler and AdaptiveDNSResolver
"""

import pytest
import asyncio
import time
from collections import deque
from unittest.mock import AsyncMock, MagicMock, patch

from core.utils.adaptive_scheduler import (
    AdaptiveBatchScheduler,
    AdaptiveDNSResolver,
    adaptive_batch_process
)


class TestAdaptiveBatchScheduler:
    """Test cases for AdaptiveBatchScheduler"""
    
    def test_initialization(self):
        """Test scheduler initialization"""
        scheduler = AdaptiveBatchScheduler(
            initial_batch_size=50,
            min_batch_size=10,
            max_batch_size=100
        )
        
        assert scheduler.batch_size == 50
        assert scheduler.initial_batch_size == 50
        assert scheduler.min_batch_size == 10
        assert scheduler.max_batch_size == 100
    
    def test_batch_size_increase_on_fast_responses(self):
        """Test batch size increases on fast responses"""
        scheduler = AdaptiveBatchScheduler(
            initial_batch_size=50,
            min_batch_size=10,
            max_batch_size=100,
            fast_threshold=0.5
        )
        
        for _ in range(10):
            scheduler.record_success(0.1)
        
        assert scheduler.batch_size > 50
    
    def test_batch_size_decrease_on_slow_responses(self):
        """Test batch size decreases on slow responses"""
        scheduler = AdaptiveBatchScheduler(
            initial_batch_size=50,
            min_batch_size=10,
            max_batch_size=100,
            slow_threshold=2.0
        )
        
        for _ in range(5):
            scheduler.record_success(3.0)
        
        assert scheduler.batch_size < 50
    
    def test_batch_size_decrease_on_failures(self):
        """Test batch size decreases on failures"""
        scheduler = AdaptiveBatchScheduler(
            initial_batch_size=50,
            min_batch_size=10,
            max_batch_size=100
        )
        
        for _ in range(3):
            scheduler.record_failure()
        
        assert scheduler.batch_size < 50
    
    def test_batch_size_never_exceeds_max(self):
        """Test batch size never exceeds maximum"""
        scheduler = AdaptiveBatchScheduler(
            initial_batch_size=50,
            min_batch_size=10,
            max_batch_size=100,
            fast_threshold=0.5
        )
        
        for _ in range(100):
            scheduler.record_success(0.01)
        
        assert scheduler.batch_size <= 100
    
    def test_batch_size_never_below_min(self):
        """Test batch size never below minimum"""
        scheduler = AdaptiveBatchScheduler(
            initial_batch_size=50,
            min_batch_size=10,
            max_batch_size=100,
            slow_threshold=2.0
        )
        
        for _ in range(100):
            scheduler.record_success(10.0)
        
        assert scheduler.batch_size >= 10
    
    def test_reset(self):
        """Test scheduler reset"""
        scheduler = AdaptiveBatchScheduler(
            initial_batch_size=50,
            min_batch_size=10,
            max_batch_size=100
        )
        
        for _ in range(10):
            scheduler.record_success(0.1)
        
        scheduler.reset()
        
        assert scheduler.batch_size == 50
        assert scheduler.stats['total_requests'] == 0
    
    def test_stats_tracking(self):
        """Test statistics tracking"""
        scheduler = AdaptiveBatchScheduler()
        
        scheduler.record_success(0.5)
        scheduler.record_success(1.0)
        scheduler.record_failure()
        
        stats = scheduler.stats
        assert stats['total_requests'] == 3
        assert stats['success_count'] == 2
        assert stats['fail_count'] == 1


class TestAdaptiveDNSResolver:
    """Test cases for AdaptiveDNSResolver"""
    
    def test_initialization(self):
        """Test resolver initialization"""
        resolver = AdaptiveDNSResolver(
            base_concurrency=50,
            min_concurrency=10,
            max_concurrency=100
        )
        
        assert resolver.concurrency == 50
        assert resolver.base_concurrency == 50
        assert resolver.min_concurrency == 10
        assert resolver.max_concurrency == 100
    
    def test_concurrency_increase_on_fast_responses(self):
        """Test concurrency increases on fast responses"""
        resolver = AdaptiveDNSResolver(
            base_concurrency=50,
            min_concurrency=10,
            max_concurrency=100,
            fast_threshold=0.1
        )
        
        for _ in range(10):
            resolver.record_response_time(0.01)
        
        assert resolver.concurrency > 50
    
    def test_concurrency_decrease_on_slow_responses(self):
        """Test concurrency decreases on slow responses"""
        resolver = AdaptiveDNSResolver(
            base_concurrency=50,
            min_concurrency=10,
            max_concurrency=100,
            slow_threshold=2.0
        )
        
        for _ in range(5):
            resolver.record_response_time(5.0)
        
        assert resolver.concurrency < 50
    
    def test_timeout_tracking(self):
        """Test timeout tracking and adjustment"""
        resolver = AdaptiveDNSResolver(
            base_concurrency=50,
            min_concurrency=10,
            max_concurrency=100
        )
        
        resolver.record_timeout()
        resolver.record_timeout()
        resolver.record_timeout()
        
        assert resolver.concurrency < 50
    
    def test_reset(self):
        """Test resolver reset"""
        resolver = AdaptiveDNSResolver(
            base_concurrency=50,
            min_concurrency=10,
            max_concurrency=100
        )
        
        for _ in range(10):
            resolver.record_response_time(0.01)
        
        resolver.reset()
        
        assert resolver.concurrency == 50
        assert resolver.stats['total_requests'] == 0


class TestAdaptiveBatchProcess:
    """Test cases for adaptive_batch_process"""
    
    @pytest.mark.asyncio
    async def test_adaptive_batch_process_basic(self):
        """Test basic adaptive batch processing"""
        scheduler = AdaptiveBatchScheduler(initial_batch_size=2)
        
        items = [1, 2, 3, 4, 5]
        
        async def processor(item):
            await asyncio.sleep(0.01)
            return (item * 2, True, 0.01)
        
        results = await adaptive_batch_process(scheduler, items, processor)
        
        assert len(results) == 5
        assert results == [2, 4, 6, 8, 10]
    
    @pytest.mark.asyncio
    async def test_adaptive_batch_process_with_failures(self):
        """Test adaptive batch processing with failures"""
        scheduler = AdaptiveBatchScheduler(initial_batch_size=2)
        
        items = [1, 2, 3, 4, 5]
        call_count = 0
        
        async def processor(item):
            nonlocal call_count
            call_count += 1
            await asyncio.sleep(0.01)
            if item == 3:
                return (None, False, 0.0)
            return (item * 2, True, 0.01)
        
        results = await adaptive_batch_process(scheduler, items, processor)
        
        assert len(results) == 4
        assert 3 not in results
    
    @pytest.mark.asyncio
    async def test_break_on_first_success(self):
        """Test break_on_first_success option"""
        scheduler = AdaptiveBatchScheduler(initial_batch_size=2)
        
        items = [1, 2, 3, 4, 5]
        
        async def processor(item):
            await asyncio.sleep(0.01)
            return (item * 2, True, 0.01)
        
        results = await adaptive_batch_process(
            scheduler, items, processor, 
            break_on_first_success=True
        )
        
        assert len(results) == 1


class TestAdaptiveSchedulerIntegration:
    """Integration tests for adaptive schedulers"""
    
    def test_multiple_fast_responses_increase_batch(self):
        """Test that multiple fast responses gradually increase batch size"""
        scheduler = AdaptiveBatchScheduler(
            initial_batch_size=50,
            min_batch_size=10,
            max_batch_size=100,
            fast_threshold=0.5
        )
        
        initial_batch = scheduler.batch_size
        
        for i in range(20):
            scheduler.record_success(0.1 + (i * 0.01))
        
        final_batch = scheduler.batch_size
        
        assert final_batch > initial_batch
    
    def test_multiple_slow_responses_decrease_batch(self):
        """Test that multiple slow responses gradually decrease batch size"""
        scheduler = AdaptiveBatchScheduler(
            initial_batch_size=50,
            min_batch_size=10,
            max_batch_size=100,
            slow_threshold=2.0
        )
        
        initial_batch = scheduler.batch_size
        
        for i in range(10):
            scheduler.record_success(3.0 + (i * 0.1))
        
        final_batch = scheduler.batch_size
        
        assert final_batch < initial_batch
    
    def test_interleaved_responses(self):
        """Test behavior with interleaved fast and slow responses"""
        scheduler = AdaptiveBatchScheduler(
            initial_batch_size=50,
            min_batch_size=10,
            max_batch_size=100,
            fast_threshold=0.5,
            slow_threshold=2.0
        )
        
        responses = [0.1, 0.2, 3.0, 0.3, 0.1, 4.0, 0.2, 0.1]
        
        for resp in responses:
            scheduler.record_success(resp)
        
        assert 10 <= scheduler.batch_size <= 100


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
