import pytest
import asyncio


@pytest.fixture
def event_loop():
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def sample_scan_result():
    from core.models import ScanResult
    return ScanResult(
        target_url="https://example.com",
        start_time="2026-03-21 10:00:00"
    )
