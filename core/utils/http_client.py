"""
Async HTTP Client Module
异步并发HTTP客户端
支持同步requests作为aiohttp失败时的备选方案
"""

import asyncio
import aiohttp
import requests
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
    verify_ssl: bool = True


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
        max_concurrent: int = 300,
        max_retries: int = 3,
        timeout: int = 30,
        proxy: Optional[str] = None,
        verify_ssl: bool = True,
        rate_limit: int = 0,
        respect_retry_after: bool = True
    ):
        self.max_concurrent = max_concurrent
        self.max_retries = max_retries
        self.default_timeout = aiohttp.ClientTimeout(total=timeout)
        self.proxy = proxy
        self.verify_ssl = verify_ssl
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.session: Optional[aiohttp.ClientSession] = None
        self._request_count = 0
        self._lock = asyncio.Lock()
        self._ssl_verified: Optional[bool] = None
        self.rate_limit = rate_limit
        self.respect_retry_after = respect_retry_after
        self._rate_limit_enabled = rate_limit > 0
        self._last_request_time = 0.0
        self._min_request_interval = 1.0 / rate_limit if rate_limit > 0 else 0
        self._429_count = 0
        self._429_backoff_until = 0.0
        self._active_requests = 0
        self._close_event = asyncio.Event()
        self._close_event.set()
    
    async def __aenter__(self):
        await self._ensure_session()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self._close_event.clear()
        if self.session and self._active_requests > 0:
            await self._close_event.wait()
        if self.session:
            await self.session.close()
    
    async def _ensure_session(self, verify_ssl: Optional[bool] = None):
        """确保Session存在"""
        if verify_ssl is None:
            verify_ssl = self.verify_ssl
        
        async with self._lock:
            if self._ssl_verified != verify_ssl and self.session is not None and not self.session.closed:
                if self._active_requests > 0:
                    old_session = self.session
                    self.session = None
                    async def close_after_requests():
                        while self._active_requests > 0:
                            await asyncio.sleep(0.1)
                        if not old_session.closed:
                            await old_session.close()
                    asyncio.create_task(close_after_requests())
                else:
                    await self.session.close()
                    self.session = None
            
            if self.session is None or self.session.closed:
                self._ssl_verified = verify_ssl
                if verify_ssl:
                    ssl_context = ssl.create_default_context()
                else:
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
        json_data: Any = None,
        retry: Optional[int] = None,
        timeout: Optional[int] = None,
        verify_ssl: Optional[bool] = None
    ) -> TaskResult:
        """发起异步请求，aiohttp失败时自动降级到同步requests"""
        if verify_ssl is not None:
            self.verify_ssl = verify_ssl
        await self._ensure_session(verify_ssl)
        
        retry = retry if retry is not None else self.max_retries
        timeout_sec = int(timeout) if timeout is not None else int(self.default_timeout.total)
        
        result = TaskResult(url=url, method=method)
        start_time = time.time()
        
        for attempt in range(retry):
            if self._rate_limit_enabled:
                await self._apply_rate_limit()
            
            if self._429_backoff_until > time.time():
                wait_time = self._429_backoff_until - time.time()
                if wait_time > 0:
                    await asyncio.sleep(wait_time)
            
            async with self.semaphore:
                self._active_requests += 1
                if self._active_requests == 1:
                    self._close_event.clear()
                try:
                    async with self.session.request(
                        method,
                        url,
                        headers=headers,
                        data=data,
                        json=json_data,
                        proxy=self.proxy,
                        timeout=aiohttp.ClientTimeout(total=timeout_sec)
                    ) as response:
                        result.status_code = response.status
                        result.headers = dict(response.headers)
                        
                        if response.status == 429 and self.respect_retry_after:
                            retry_after = response.headers.get('Retry-After')
                            if retry_after:
                                try:
                                    wait_seconds = int(retry_after)
                                    self._429_backoff_until = time.time() + wait_seconds
                                    logger.info(f"Rate limited. Respecting Retry-After: {wait_seconds}s")
                                except ValueError:
                                    self._429_backoff_until = time.time() + 60
                            else:
                                self._429_backoff_until = time.time() + 60
                            self._429_count += 1
                        
                        result.content_bytes = await response.read()
                        result.content = result.content_bytes.decode('utf-8', errors='ignore')
                        result.content_hash = hashlib.sha256(
                            result.content_bytes
                        ).hexdigest()[:16]
                        result.duration = time.time() - start_time
                        
                        async with self._lock:
                            self._request_count += 1
                        
                        return result
                except asyncio.TimeoutError:
                    result.error = f'Timeout after {timeout_sec}s'
                except aiohttp.ClientError as e:
                    result.error = f'ClientError: {str(e)}'
                except ssl.SSLError as e:
                    result.error = f'SSLError: {str(e)}'
                except Exception as e:
                    result.error = f'Error: {str(e)}'
                finally:
                    self._active_requests -= 1
                    if self._active_requests == 0:
                        self._close_event.set()
                
                if attempt < retry - 1:
                    import random
                    base_delay = 0.5
                    max_delay = 30.0
                    exponential_delay = min(base_delay * (2 ** attempt), max_delay)
                    jitter = random.uniform(0, 0.3 * exponential_delay)
                    await asyncio.sleep(exponential_delay + jitter)
        
        result.duration = time.time() - start_time
        
        if result.error and ('SSL' in result.error or 'ClientError' in result.error or 'sslv3' in result.error.lower()):
            return await self._fallback_request(url, method, headers, data, timeout_sec, verify_ssl, json_data)
        
        return result
    
    async def _fallback_request(
        self,
        url: str,
        method: str = 'GET',
        headers: Optional[Dict[str, str]] = None,
        data: Any = None,
        timeout: int = 30,
        verify_ssl: Optional[bool] = None,
        json_data: Any = None
    ) -> TaskResult:
        """同步requests降级方案，处理SSL问题"""
        result = TaskResult(url=url, method=method)
        start_time = time.time()
        
        try:
            verify = verify_ssl if verify_ssl is not None else self.verify_ssl
            use_json = json_data is not None and method.upper() in ('POST', 'PUT', 'PATCH')
            
            if method == 'GET':
                resp = requests.get(
                    url,
                    headers=headers,
                    timeout=timeout,
                    verify=verify,
                    proxies={'http': self.proxy, 'https': self.proxy} if self.proxy else None
                )
            elif method == 'POST_DATA' or (method == 'POST' and not use_json):
                resp = requests.post(
                    url,
                    data=data,
                    headers=headers,
                    timeout=timeout,
                    verify=verify,
                    proxies={'http': self.proxy, 'https': self.proxy} if self.proxy else None
                )
            elif method == 'POST_JSON' or use_json:
                resp = requests.post(
                    url,
                    json=json_data,
                    headers=headers,
                    timeout=timeout,
                    verify=verify,
                    proxies={'http': self.proxy, 'https': self.proxy} if self.proxy else None
                )
            else:
                resp = requests.request(
                    method,
                    url,
                    headers=headers,
                    data=data if not use_json else None,
                    json=json_data if use_json else None,
                    timeout=timeout,
                    verify=verify,
                    proxies={'http': self.proxy, 'https': self.proxy} if self.proxy else None
                )
            
            result.status_code = resp.status_code
            result.headers = dict(resp.headers)
            result.content = resp.text
            result.content_bytes = resp.content
            result.content_hash = hashlib.sha256(resp.content).hexdigest()[:16]
            result.duration = time.time() - start_time
            
            self._request_count += 1
            
        except requests.exceptions.SSLError as e:
            result.error = f'SSLError (fallback): {str(e)}'
            result.status_code = 0
        except requests.exceptions.Timeout as e:
            result.error = f'Timeout (fallback): {str(e)}'
            result.status_code = 0
        except requests.exceptions.RequestException as e:
            result.error = f'RequestException (fallback): {str(e)}'
            result.status_code = 0
        except Exception as e:
            result.error = f'Fallback error: {str(e)}'
            result.status_code = 0
        
        result.duration = time.time() - start_time
        return result
    
    async def batch_request(
        self,
        tasks: List[AsyncTask],
        progress_callback: Optional[Callable] = None
    ) -> List[TaskResult]:
        """批量异步请求"""
        async def execute_task(task: AsyncTask) -> TaskResult:
            result = await self.request(
                task.url,
                task.method,
                task.headers,
                task.data,
                task.retry_count,
                task.timeout,
                task.verify_ssl
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
    
    async def _apply_rate_limit(self):
        """应用速率限制"""
        if not self._rate_limit_enabled or self._min_request_interval <= 0:
            return
        
        current_time = time.time()
        time_since_last = current_time - self._last_request_time
        
        if time_since_last < self._min_request_interval:
            wait_time = self._min_request_interval - time_since_last
            await asyncio.sleep(wait_time)
        
        self._last_request_time = time.time()
    
    def set_rate_limit(self, requests_per_second: int):
        """动态设置速率限制"""
        self.rate_limit = requests_per_second
        self._rate_limit_enabled = requests_per_second > 0
        self._min_request_interval = 1.0 / requests_per_second if requests_per_second > 0 else 0
        logger.info(f"Rate limit set to {requests_per_second} req/s")


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
