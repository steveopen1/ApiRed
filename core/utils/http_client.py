"""
Async HTTP Client Module
异步并发HTTP客户端
"""

import asyncio
import aiohttp
from typing import List, Dict, Any, Callable, Optional, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse
import ssl
import hashlib
import time


@dataclass
class AsyncTask:
    """异步任务定义"""
    url: str
    method: str = 'GET'
    headers: Dict[str, str] = field(default_factory=dict)
    data: Any = None
    callback: Optional[Callable] = None
    priority: int = 0
    retry_count: int = 3
    timeout: int = 30


@dataclass
class TaskResult:
    """任务结果"""
    url: str
    method: str
    status_code: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    content: str = ''
    content_bytes: bytes = b''
    error: Optional[str] = None
    duration: float = 0.0
    content_hash: str = ''


class AsyncHttpClient:
    """异步HTTP客户端"""
    
    def __init__(
        self,
        max_concurrent: int = 50,
        max_retries: int = 3,
        timeout: int = 30,
        proxy: Optional[str] = None
    ):
        self.max_concurrent = max_concurrent
        self.max_retries = max_retries
        self.default_timeout = aiohttp.ClientTimeout(total=timeout)
        self.proxy = proxy
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.session: Optional[aiohttp.ClientSession] = None
        self._request_count = 0
        self._lock = asyncio.Lock()
    
    async def __aenter__(self):
        await self._ensure_session()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def _ensure_session(self):
        """确保Session存在"""
        if self.session is None or self.session.closed:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            connector = aiohttp.TCPConnector(
                ssl=ssl_context,
                limit=self.max_concurrent,
                limit_per_host=10
            )
            self.session = aiohttp.ClientSession(
                connector=connector,
                timeout=self.default_timeout
            )
    
    async def request(
        self,
        url: str,
        method: str = 'GET',
        headers: Optional[Dict[str, str]] = None,
        data: Any = None,
        retry: int = None,
        timeout: int = None
    ) -> TaskResult:
        """发起异步请求"""
        await self._ensure_session()
        
        retry = retry if retry is not None else self.max_retries
        timeout = timeout if timeout else self.default_timeout.total
        
        result = TaskResult(url=url, method=method)
        start_time = time.time()
        
        for attempt in range(retry):
            async with self.semaphore:
                try:
                    async with self.session.request(
                        method,
                        url,
                        headers=headers,
                        data=data,
                        proxy=self.proxy,
                        timeout=aiohttp.ClientTimeout(total=timeout)
                    ) as response:
                        result.status_code = response.status
                        result.headers = dict(response.headers)
                        
                        result.content_bytes = await response.read()
                        result.content = result.content_bytes.decode('utf-8', errors='ignore')
                        result.content_hash = hashlib.sha256(
                            result.content_bytes
                        ).hexdigest()[:16]
                        result.duration = time.time() - start_time
                        
                        if self._request_count % 100 == 0:
                            async with self._lock:
                                self._request_count += 1
                        else:
                            async with self._lock:
                                self._request_count += 1
                        
                        return result
                        
                except asyncio.TimeoutError:
                    result.error = f'Timeout after {timeout}s'
                except aiohttp.ClientError as e:
                    result.error = f'ClientError: {str(e)}'
                except Exception as e:
                    result.error = f'Error: {str(e)}'
                
                if attempt < retry - 1:
                    await asyncio.sleep(0.5 * (attempt + 1))
        
        result.duration = time.time() - start_time
        return result
    
    async def batch_request(
        self,
        tasks: List[AsyncTask],
        progress_callback: Optional[Callable] = None
    ) -> List[TaskResult]:
        """批量异步请求"""
        await self._ensure_session()
        
        async def execute_task(task: AsyncTask) -> TaskResult:
            result = await self.request(
                task.url,
                task.method,
                task.headers,
                task.data,
                task.retry_count,
                task.timeout
            )
            
            if task.callback:
                return task.callback(result) or result
            return result
        
        results = []
        for i, coro in enumerate(asyncio.as_completed([
            execute_task(t) for t in tasks
        ])):
            result = await coro
            results.append(result)
            
            if progress_callback and (i + 1) % 10 == 0:
                progress_callback(i + 1, len(tasks))
        
        return results
    
    @property
    def request_count(self) -> int:
        """获取请求计数"""
        return self._request_count
    
    def reset_counter(self):
        """重置计数器"""
        self._request_count = 0


class RequestPool:
    """请求池管理器"""
    
    def __init__(self, client: AsyncHttpClient):
        self.client = client
        self.pending_tasks: List[AsyncTask] = []
        self.completed_results: List[TaskResult] = []
    
    def add_task(self, task: AsyncTask):
        """添加任务"""
        self.pending_tasks.append(task)
    
    def add_tasks(self, tasks: List[AsyncTask]):
        """批量添加任务"""
        self.pending_tasks.extend(tasks)
    
    async def execute_all(
        self,
        progress_callback: Optional[Callable] = None
    ) -> List[TaskResult]:
        """执行所有任务"""
        results = await self.client.batch_request(
            self.pending_tasks,
            progress_callback
        )
        self.completed_results.extend(results)
        self.pending_tasks.clear()
        return results
    
    def get_results_by_status(self, status_code: int) -> List[TaskResult]:
        """按状态码筛选结果"""
        return [r for r in self.completed_results if r.status_code == status_code]
    
    def get_results_by_pattern(self, pattern: str) -> List[TaskResult]:
        """按内容模式筛选结果"""
        import re
        return [
            r for r in self.completed_results
            if re.search(pattern, r.content, re.IGNORECASE)
        ]
