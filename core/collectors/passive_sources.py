"""
扩展被动源采集模块

支持更多的被动数据源:
1. Wayback Machine
2. CommonCrawl  
3. AlienVault OTX
4. URLScan
5. SecurityTrails
6. crt.sh (证书透明度)
7. Pastebin
8. GitHub Code Search

参考 urlfinder 项目的被动源设计
"""

import asyncio
import hashlib
import json
import logging
import re
import time
from typing import Dict, List, Set, Optional, Any, Tuple, AsyncIterator
from urllib.parse import urlparse, parse_qs
from dataclasses import dataclass, field
from enum import Enum
import asyncio

logger = logging.getLogger(__name__)


class PassiveSource(Enum):
    """被动数据源类型"""
    WAYBACK = "wayback"
    COMMONS = "commoncrawl"
    ALIENVAULT = "alienvault"
    URLSCAN = "urlscan"
    SECURITYTRAILS = "securitytrails"
    CRTSH = "crtsh"
    GITLAB = "gitlab"
    GITHUB = "github"
    BING = "bing"
    BINARYEDGE = "binaryedge"
    SHODAN = "shodan"
    VIRUSTOTAL = "virustotal"


@dataclass
class SourceConfig:
    """数据源配置"""
    name: PassiveSource
    base_url: str
    rate_limit: int
    max_results: int
    requires_api_key: bool
    priority: int
    parallel_requests: int


class PassiveSourceCollector:
    """
    扩展被动源采集器
    
    支持并行从多个数据源采集 URL
    """

    SOURCE_CONFIGS = {
        PassiveSource.WAYBACK: SourceConfig(
            name=PassiveSource.WAYBACK,
            base_url="https://web.archive.org/cdx/search/cdx",
            rate_limit=10,
            max_results=10000,
            requires_api_key=False,
            priority=1,
            parallel_requests=5,
        ),
        PassiveSource.COMMONS: SourceConfig(
            name=PassiveSource.COMMONS,
            base_url="https://index.commoncrawl.org/collinfo.json",
            rate_limit=5,
            max_results=5000,
            requires_api_key=False,
            priority=2,
            parallel_requests=3,
        ),
        PassiveSource.ALIENVAULT: SourceConfig(
            name=PassiveSource.ALIENVAULT,
            base_url="https://otx.alienvault.com/api/v1/indicators/hostname",
            rate_limit=10,
            max_results=1000,
            requires_api_key=False,
            priority=3,
            parallel_requests=3,
        ),
        PassiveSource.URLSCAN: SourceConfig(
            name=PassiveSource.URLSCAN,
            base_url="https://urlscan.io/api/v1/search",
            rate_limit=5,
            max_results=2000,
            requires_api_key=True,
            priority=4,
            parallel_requests=2,
        ),
        PassiveSource.CRTSH: SourceConfig(
            name=PassiveSource.CRTSh,
            base_url="https://crt.sh",
            rate_limit=20,
            max_results=5000,
            requires_api_key=False,
            priority=2,
            parallel_requests=5,
        ),
        PassiveSource.BINARYEDGE: SourceConfig(
            name=PassiveSource.BINARYEDGE,
            base_url="https://api.binaryedge.io/v2/minified",
            rate_limit=10,
            max_results=1000,
            requires_api_key=True,
            priority=5,
            parallel_requests=2,
        ),
        PassiveSource.SHODAN: SourceConfig(
            name=PassiveSource.SHODAN,
            base_url="https://api.shodan.io/shodan",
            rate_limit=10,
            max_results=1000,
            requires_api_key=True,
            priority=5,
            parallel_requests=2,
        ),
    }

    def __init__(self, http_client=None, api_keys: Dict[str, str] = None):
        self.http_client = http_client
        self.api_keys = api_keys or {}
        self.collected_urls: Set[str] = set()
        self.source_stats: Dict[str, int] = {}
        self._rate_limiter = TokenBucket(rate=50, capacity=100)

    async def collect_from_all(self, domain: str) -> Set[str]:
        """
        从所有可用数据源采集 URL
        
        Args:
            domain: 目标域名
            
        Returns:
            采集到的 URL 集合
        """
        tasks = []
        
        for source in PassiveSource:
            if source == PassiveSource.GITHUB or source == PassiveSource.GITLAB:
                continue
            
            config = self.SOURCE_CONFIGS.get(source)
            if not config:
                continue
            
            if config.requires_api_key and not self._has_api_key(source):
                logger.debug(f"Skipping {source.value} - no API key")
                continue
            
            tasks.append(self._collect_from_source(source, domain))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, set):
                self.collected_urls.update(result)
        
        return self.collected_urls

    def _has_api_key(self, source: PassiveSource) -> bool:
        """检查是否有 API Key"""
        key_map = {
            PassiveSource.URLSCAN: 'URLSCAN_API_KEY',
            PassiveSource.BINARYEDGE: 'BINARYEDGE_API_KEY',
            PassiveSource.SHODAN: 'SHODAN_API_KEY',
            PassiveSource.SECURITYTRAILS: 'SECURITYTRAILS_API_KEY',
            PassiveSource.VIRUSTOTAL: 'VIRUSTOTAL_API_KEY',
        }
        env_key = key_map.get(source)
        if env_key:
            return env_key in self.api_keys or self._check_env(env_key)
        return False

    def _check_env(self, key: str) -> bool:
        """检查环境变量"""
        import os
        return os.environ.get(key) is not None

    async def _collect_from_source(self, source: PassiveSource, domain: str) -> Set[str]:
        """从指定数据源采集"""
        config = self.SOURCE_CONFIGS.get(source)
        if not config:
            return set()
        
        try:
            await self._rate_limiter.acquire()
            
            if source == PassiveSource.WAYBACK:
                return await self._collect_wayback(domain, config)
            elif source == PassiveSource.COMMONS:
                return await self._collect_commoncrawl(domain, config)
            elif source == PassiveSource.ALIENVAULT:
                return await self._collect_alienvault(domain, config)
            elif source == PassiveSource.URLSCAN:
                return await self._collect_urlscan(domain, config)
            elif source == PassiveSource.CRTSH:
                return await self._collect_crtsh(domain, config)
            elif source == PassiveSource.BINARYEDGE:
                return await self._collect_binaryedge(domain, config)
            elif source == PassiveSource.SHODAN:
                return await self._collect_shodan(domain, config)
            
            return set()
            
        except Exception as e:
            logger.debug(f"Collection from {source.value} failed: {e}")
            return set()

    async def _collect_wayback(self, domain: str, config: SourceConfig) -> Set[str]:
        """从 Wayback Machine 采集"""
        urls = set()
        
        try:
            params = {
                'url': f'*.{domain}/*',
                'output': 'json',
                'fl': 'original',
                'limit': config.max_results,
                'filter': 'statuscode:200',
                'from': '2000',
                'to': time.strftime('%Y'),
            }
            
            query = '&'.join(f'{k}={v}' for k, v in params.items())
            url = f"{config.base_url}?{query}"
            
            if self.http_client:
                resp = await self.http_client.request(url, timeout=30)
                if resp and resp.status_code == 200:
                    try:
                        data = json.loads(resp.content)
                        if isinstance(data, list) and len(data) > 1:
                            for row in data[1:]:
                                if row and row[0]:
                                    original_url = row[0]
                                    if self._is_valid_url(original_url, domain):
                                        urls.add(original_url)
                                        self.source_stats['wayback'] = self.source_stats.get('wayback', 0) + 1
                    except Exception as e:
                        logger.debug(f"Wayback parsing error: {e}")
                        
        except Exception as e:
            logger.debug(f"Wayback collection error: {e}")
        
        logger.info(f"Wayback collected {len(urls)} URLs for {domain}")
        return urls

    async def _collect_commoncrawl(self, domain: str, config: SourceConfig) -> Set[str]:
        """从 CommonCrawl 采集"""
        urls = set()
        
        try:
            if self.http_client:
                resp = await self.http_client.request(config.base_url, timeout=10)
                if resp and resp.status_code == 200:
                    try:
                        cdx_info = json.loads(resp.content)
                        if cdx_info and len(cdx_info) > 0:
                            latest_cdx = cdx_info[0].get('id', '')
                            
                            cdx_url = f"https://index.commoncrawl.org/{latest_cdx}-index"
                            params = {
                                'url': f'*.{domain}/*',
                                'output': 'json',
                                'limit': config.max_results,
                            }
                            query = '&'.join(f'{k}={v}' for k, v in params.items())
                            cdx_url = f"{cdx_url}?{query}"
                            
                            resp2 = await self.http_client.request(cdx_url, timeout=60)
                            if resp2 and resp2.status_code == 200:
                                for line in resp2.content.decode('utf-8', errors='ignore').split('\n'):
                                    if line.strip():
                                        try:
                                            data = json.loads(line)
                                            if 'url' in data:
                                                original_url = data['url']
                                                if self._is_valid_url(original_url, domain):
                                                    urls.add(original_url)
                                                    self.source_stats['commoncrawl'] = self.source_stats.get('commoncrawl', 0) + 1
                                        except Exception:
                                            continue
                                            
                    except Exception as e:
                        logger.debug(f"CommonCrawl parsing error: {e}")
                        
        except Exception as e:
            logger.debug(f"CommonCrawl collection error: {e}")
        
        logger.info(f"CommonCrawl collected {len(urls)} URLs for {domain}")
        return urls

    async def _collect_alienvault(self, domain: str, config: SourceConfig) -> Set[str]:
        """从 AlienVault OTX 采集"""
        urls = set()
        
        try:
            if self.http_client:
                url = f"{config.base_url}/{domain}/url_list?limit={config.max_results}"
                resp = await self.http_client.request(url, timeout=30)
                if resp and resp.status_code == 200:
                    try:
                        data = json.loads(resp.content)
                        if 'url_list' in data:
                            for item in data['url_list'][:config.max_results]:
                                if 'url' in item:
                                    original_url = item['url']
                                    if self._is_valid_url(original_url, domain):
                                        urls.add(original_url)
                                        self.source_stats['alienvault'] = self.source_stats.get('alienvault', 0) + 1
                    except Exception as e:
                        logger.debug(f"OTX parsing error: {e}")
                        
        except Exception as e:
            logger.debug(f"AlienVault collection error: {e}")
        
        logger.info(f"AlienVault collected {len(urls)} URLs for {domain}")
        return urls

    async def _collect_urlscan(self, domain: str, config: SourceConfig) -> Set[str]:
        """从 URLScan 采集"""
        urls = set()
        api_key = self.api_keys.get('URLSCAN_API_KEY') or self._get_env('URLSCAN_API_KEY')
        
        if not api_key:
            return urls
        
        try:
            if self.http_client:
                headers = {'API-Key': api_key}
                url = f"{config.base_url}/?q=domain:{domain}&size={config.max_results}"
                resp = await self.http_client.request(url, timeout=30, headers=headers)
                if resp and resp.status_code == 200:
                    try:
                        data = json.loads(resp.content)
                        if 'results' in data:
                            for result in data['results'][:config.max_results]:
                                if 'url' in result:
                                    original_url = result['url']
                                    if self._is_valid_url(original_url, domain):
                                        urls.add(original_url)
                                        self.source_stats['urlscan'] = self.source_stats.get('urlscan', 0) + 1
                    except Exception as e:
                        logger.debug(f"URLScan parsing error: {e}")
                        
        except Exception as e:
            logger.debug(f"URLScan collection error: {e}")
        
        logger.info(f"URLScan collected {len(urls)} URLs for {domain}")
        return urls

    async def _collect_crtsh(self, domain: str, config: SourceConfig) -> Set[str]:
        """从 crt.sh 采集 (证书透明度)"""
        urls = set()
        
        try:
            if self.http_client:
                url = f"{config.base_url}/?q=%.{domain}&output=json&limit={config.max_results}"
                resp = await self.http_client.request(url, timeout=30)
                if resp and resp.status_code == 200:
                    try:
                        data = json.loads(resp.content)
                        if isinstance(data, list):
                            for cert in data[:config.max_results]:
                                if 'name_value' in cert:
                                    SANs = cert['name_value'].split('\n')
                                    for san in SANs:
                                        san = san.strip()
                                        if san.startswith('*.'):
                                            san = san[2:]
                                        if domain in san and san.startswith('http'):
                                            if self._is_valid_url(san, domain):
                                                urls.add(san)
                                                self.source_stats['crtsh'] = self.source_stats.get('crtsh', 0) + 1
                    except Exception as e:
                        logger.debug(f"crt.sh parsing error: {e}")
                        
        except Exception as e:
            logger.debug(f"crt.sh collection error: {e}")
        
        logger.info(f"crt.sh collected {len(urls)} URLs for {domain}")
        return urls

    async def _collect_binaryedge(self, domain: str, config: SourceConfig) -> Set[str]:
        """从 BinaryEdge 采集"""
        urls = set()
        api_key = self.api_keys.get('BINARYEDGE_API_KEY') or self._get_env('BINARYEDGE_API_KEY')
        
        if not api_key:
            return urls
        
        try:
            if self.http_client:
                headers = {'X-Key': api_key}
                url = f"{config.base_url}/query/host-search/{domain}?page=1"
                resp = await self.http_client.request(url, timeout=30, headers=headers)
                if resp and resp.status_code == 200:
                    try:
                        data = json.loads(resp.content)
                        if 'events' in data:
                            for event in data['events'][:config.max_results]:
                                if 'uri' in event:
                                    original_url = event['uri']
                                    if self._is_valid_url(original_url, domain):
                                        urls.add(original_url)
                                        self.source_stats['binaryedge'] = self.source_stats.get('binaryedge', 0) + 1
                    except Exception as e:
                        logger.debug(f"BinaryEdge parsing error: {e}")
                        
        except Exception as e:
            logger.debug(f"BinaryEdge collection error: {e}")
        
        logger.info(f"BinaryEdge collected {len(urls)} URLs for {domain}")
        return urls

    async def _collect_shodan(self, domain: str, config: SourceConfig) -> Set[str]:
        """从 Shodan 采集"""
        urls = set()
        api_key = self.api_keys.get('SHODAN_API_KEY') or self._get_env('SHODAN_API_KEY')
        
        if not api_key:
            return urls
        
        try:
            if self.http_client:
                url = f"{config.base_url}/info?key={api_key}"
                resp = await self.http_client.request(url, timeout=10)
                if resp and resp.status_code == 200:
                    search_url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query=hostname:{domain}&limit={config.max_results}"
                    resp2 = await self.http_client.request(search_url, timeout=30)
                    if resp2 and resp2.status_code == 200:
                        try:
                            data = json.loads(resp2.content)
                            if 'matches' in data:
                                for match in data['matches'][:config.max_results]:
                                    if 'uri' in match:
                                        original_url = match['uri']
                                        if self._is_valid_url(original_url, domain):
                                            urls.add(original_url)
                                            self.source_stats['shodan'] = self.source_stats.get('shodan', 0) + 1
                        except Exception as e:
                            logger.debug(f"Shodan parsing error: {e}")
                        
        except Exception as e:
            logger.debug(f"Shodan collection error: {e}")
        
        logger.info(f"Shodan collected {len(urls)} URLs for {domain}")
        return urls

    def _get_env(self, key: str) -> Optional[str]:
        """获取环境变量"""
        import os
        return os.environ.get(key)

    def _is_valid_url(self, url: str, domain: str) -> bool:
        """验证 URL 是否有效且属于目标域名"""
        if not url or len(url) < 10:
            return False
        
        try:
            parsed = urlparse(url)
            
            if parsed.netloc:
                if domain not in parsed.netloc and not parsed.netloc.endswith(f'.{domain}'):
                    return False
            
            if not parsed.scheme in ('http', 'https'):
                return False
            
            blacklist = ['.png', '.jpg', '.jpeg', '.gif', '.css', '.js', '.ico', '.svg', '.woff', '.woff2']
            if any(parsed.path.lower().endswith(ext) for ext in blacklist):
                return False
            
            if len(parsed.path) < 2:
                return False
            
            return True
            
        except Exception:
            return False

    def filter_api_urls(self, urls: Set[str]) -> List[str]:
        """过滤出可能是 API 的 URL"""
        api_indicators = [
            'api', 'v1', 'v2', 'v3', 'rest', 'graphql', 'json',
            'swagger', 'openapi', 'oauth', '/auth', '/user', '/admin',
            'endpoint', 'service',
        ]
        
        filtered = []
        for url in urls:
            url_lower = url.lower()
            if any(indicator in url_lower for indicator in api_indicators):
                filtered.append(url)
        
        return filtered

    def get_stats(self) -> Dict[str, int]:
        """获取采集统计"""
        return {
            'total_urls': len(self.collected_urls),
            'api_urls': len(self.filter_api_urls(self.collected_urls)),
            **self.source_stats
        }


class TokenBucket:
    """令牌桶限流器"""
    
    def __init__(self, rate: float, capacity: int):
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.last_update = time.time()
        self._lock = asyncio.Lock()
    
    async def acquire(self):
        """获取令牌"""
        async with self._lock:
            now = time.time()
            elapsed = now - self.last_update
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            self.last_update = now
            
            if self.tokens < 1:
                sleep_time = (1 - self.tokens) / self.rate
                await asyncio.sleep(sleep_time)
                self.tokens = 0
            else:
                self.tokens -= 1


async def collect_passive(domain: str, http_client=None) -> Set[str]:
    """
    便捷函数: 被动采集 URL
    
    Args:
        domain: 目标域名
        http_client: HTTP 客户端
        
    Returns:
        采集到的 URL 集合
    """
    collector = PassiveSourceCollector(http_client)
    return await collector.collect_from_all(domain)


if __name__ == "__main__":
    print("Extended Passive Source Collector")
    print("Supports: Wayback, CommonCrawl, AlienVault, URLScan, crt.sh, etc.")
