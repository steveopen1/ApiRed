"""
HybridFuzzer - 综合混合Fuzzing算法

融合Akto、urlfinder、FLUX的算法优点:

1. 多源数据采集 (urlfinder启发)
   - 被动源: Wayback, CommonCrawl, AlienVault等
   - 主动源: JS解析, 响应分析, OpenAPI检测

2. 流量模式学习 (Akto启发)
   - 从HTTP响应中学习API模式
   - 分析请求-响应关系
   - 学习参数位置和类型
   - 动态更新词表

3. 智能探测 (FLUX启发)
   - TF-IDF URL分类
   - 自适应批处理
   - 多源组合探测

Author: ApiRed
"""

import asyncio
import hashlib
import re
import time
import logging
from typing import Dict, List, Set, Optional, Tuple, Any, Callable
from dataclasses import dataclass, field
from collections import defaultdict, Counter
from urllib.parse import urlparse, urljoin
from enum import Enum
import threading
import json

logger = logging.getLogger(__name__)


class DataSource(Enum):
    """数据源类型"""
    WAYBACK = "wayback"
    COMMONS = "commoncrawl"
    ALIENVAULT = "alienvault"
    JS_PARSE = "js_parse"
    HTML_PARSE = "html_parse"
    SWAGGER = "swagger"
    RESPONSE_LEARN = "response_learn"
    FUZZ_GEN = "fuzz_gen"


class DynamicWordlist:
    """
    动态词表管理器
    
    特点:
    - 线程安全
    - 自动去重
    - 按置信度排序
    - 支持导出为列表
    """
    
    def __init__(self, max_size: int = 10000):
        self._resources: Set[str] = set()
        self._actions: Set[str] = set()
        self._prefixes: Set[str] = set()
        self._suffixes: Set[str] = set()
        self._full_paths: Set[str] = set()
        self._params: Dict[str, Set[str]] = defaultdict(set)
        self._confidence: Dict[str, float] = {}
        self._lock = threading.Lock()
        self._max_size = max_size
        self._update_count = 0
    
    def add_resource(self, resource: str, confidence: float = 0.5):
        """添加资源词"""
        if not resource or len(resource) < 2:
            return
        with self._lock:
            if resource not in self._resources:
                self._resources.add(resource)
                self._confidence[f"res:{resource}"] = confidence
                self._update_count += 1
    
    def add_action(self, action: str, confidence: float = 0.5):
        """添加动作词"""
        if not action or len(action) < 2:
            return
        with self._lock:
            if action not in self._actions:
                self._actions.add(action)
                self._confidence[f"act:{action}"] = confidence
                self._update_count += 1
    
    def add_prefix(self, prefix: str, confidence: float = 0.5):
        """添加API前缀"""
        if not prefix or len(prefix) < 2:
            return
        with self._lock:
            if prefix not in self._prefixes:
                self._prefixes.add(prefix)
                self._confidence[f"pre:{prefix}"] = confidence
                self._update_count += 1
    
    def add_suffix(self, suffix: str, confidence: float = 0.5):
        """添加后缀"""
        if not suffix or len(suffix) < 2:
            return
        with self._lock:
            if suffix not in self._suffixes:
                self._suffixes.add(suffix)
                self._confidence[f"suf:{suffix}"] = confidence
                self._update_count += 1
    
    def add_full_path(self, path: str, confidence: float = 0.5):
        """添加完整路径"""
        if not path or len(path) < 3:
            return
        with self._lock:
            if path not in self._full_paths:
                self._full_paths.add(path)
                self._confidence[f"path:{path}"] = confidence
                self._update_count += 1
    
    def add_param(self, param_name: str, example_value: str):
        """添加参数"""
        if not param_name or len(param_name) < 2:
            return
        with self._lock:
            self._params[param_name].add(example_value)
    
    def learn_from_pattern(self, pattern: 'APIPattern'):
        """从APIPattern学习"""
        if pattern.resource:
            self.add_resource(pattern.resource, pattern.confidence)
        if pattern.action:
            self.add_action(pattern.action, pattern.confidence)
        if pattern.prefix:
            self.add_prefix(pattern.prefix, pattern.confidence)
        if pattern.suffix:
            self.add_suffix(pattern.suffix, pattern.confidence)
        if pattern.prefix and pattern.resource:
            full = f"/{pattern.prefix}/{pattern.resource}"
            self.add_full_path(full, pattern.confidence)
    
    def get_resources(self, min_confidence: float = 0.0) -> List[Tuple[str, float]]:
        """获取资源词，按置信度排序"""
        with self._lock:
            result = [(r, self._confidence.get(f"res:{r}", 0.5)) 
                     for r in self._resources
                     if self._confidence.get(f"res:{r}", 0) >= min_confidence]
        return sorted(result, key=lambda x: x[1], reverse=True)
    
    def get_actions(self, min_confidence: float = 0.0) -> List[Tuple[str, float]]:
        """获取动作词，按置信度排序"""
        with self._lock:
            result = [(a, self._confidence.get(f"act:{a}", 0.5)) 
                     for a in self._actions
                     if self._confidence.get(f"act:{a}", 0) >= min_confidence]
        return sorted(result, key=lambda x: x[1], reverse=True)
    
    def get_prefixes(self, min_confidence: float = 0.0) -> List[Tuple[str, float]]:
        """获取前缀，按置信度排序"""
        with self._lock:
            result = [(p, self._confidence.get(f"pre:{p}", 0.5)) 
                     for p in self._prefixes
                     if self._confidence.get(f"pre:{p}", 0) >= min_confidence]
        return sorted(result, key=lambda x: x[1], reverse=True)
    
    def get_suffixes(self, min_confidence: float = 0.0) -> List[Tuple[str, float]]:
        """获取后缀，按置信度排序"""
        with self._lock:
            result = [(s, self._confidence.get(f"suf:{s}", 0.5)) 
                     for s in self._suffixes
                     if self._confidence.get(f"suf:{s}", 0) >= min_confidence]
        return sorted(result, key=lambda x: x[1], reverse=True)
    
    def get_full_paths(self, min_confidence: float = 0.0) -> List[Tuple[str, float]]:
        """获取完整路径，按置信度排序"""
        with self._lock:
            result = [(p, self._confidence.get(f"path:{p}", 0.5)) 
                     for p in self._full_paths
                     if self._confidence.get(f"path:{p}", 0) >= min_confidence]
        return sorted(result, key=lambda x: x[1], reverse=True)
    
    def generate_fuzz_paths(self, top_n: int = 50) -> List[str]:
        """生成Fuzzing路径"""
        paths = []
        
        prefixes = [p for p, _ in self.get_prefixes()[:10]]
        resources = [r for r, _ in self.get_resources()[:top_n]]
        actions = [a for a, _ in self.get_actions()[:top_n]]
        suffixes = [s for s, _ in self.get_suffixes()[:top_n]]
        
        full_paths = [p for p, _ in self.get_full_paths()[:top_n]]
        paths.extend(full_paths)
        
        for prefix in prefixes:
            for resource in resources:
                paths.append(f"/{prefix}/{resource}")
                for suffix in suffixes[:10]:
                    paths.append(f"/{prefix}/{resource}/{suffix}")
        
        for resource in resources:
            for action in actions[:20]:
                paths.append(f"/{resource}/{action}")
        
        for suffix in suffixes[:30]:
            paths.append(f"/{suffix}")
        
        return list(set(paths))[:500]
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        with self._lock:
            return {
                'resources': len(self._resources),
                'actions': len(self._actions),
                'prefixes': len(self._prefixes),
                'suffixes': len(self._suffixes),
                'full_paths': len(self._full_paths),
                'params': len(self._params),
                'total_updates': self._update_count
            }
    
    def merge_from(self, other: 'DynamicWordlist'):
        """合并另一个词表"""
        with self._lock:
            for resource, conf in other.get_resources():
                if resource not in self._resources:
                    self._resources.add(resource)
                    self._confidence[f"res:{resource}"] = conf
            for action, conf in other.get_actions():
                if action not in self._actions:
                    self._actions.add(action)
                    self._confidence[f"act:{action}"] = conf
            for prefix, conf in other.get_prefixes():
                if prefix not in self._prefixes:
                    self._prefixes.add(prefix)
                    self._confidence[f"pre:{prefix}"] = conf
            for suffix, conf in other.get_suffixes():
                if suffix not in self._suffixes:
                    self._suffixes.add(suffix)
                    self._confidence[f"suf:{suffix}"] = conf
            for path, conf in other.get_full_paths():
                if path not in self._full_paths:
                    self._full_paths.add(path)
                    self._confidence[f"path:{path}"] = conf


@dataclass
class APIPattern:
    """学习到的API模式"""
    prefix: str
    resource: str
    action: str
    suffix: str
    method: str = "GET"
    params: List[str] = field(default_factory=list)
    source: DataSource = DataSource.FUZZ_GEN
    confidence: float = 0.5
    frequency: int = 1


@dataclass
class DiscoveredEndpoint:
    """发现的端点"""
    path: str
    method: str
    source: DataSource
    confidence: float
    patterns: List[APIPattern] = field(default_factory=list)
    params: List[str] = field(default_factory=list)
    discovered_at: float = field(default_factory=time.time)


class TrafficPatternLearner:
    """
    流量模式学习器 (Akto启发)
    
    从HTTP响应中学习API模式:
    - 分析响应结构推断API资源
    - 学习参数命名模式
    - 发现RESTful路径模式
    """
    
    def __init__(self):
        self.learned_patterns: List[APIPattern] = []
        self.resource_counter: Counter = Counter()
        self.action_counter: Counter = Counter()
        self.param_patterns: Dict[str, Set[str]] = defaultdict(set)
        
    def learn_from_response(self, url: str, response_content: str, status_code: int) -> List[APIPattern]:
        """从HTTP响应学习API模式"""
        patterns = []
        
        if status_code == 200 and response_content:
            patterns.extend(self._learn_from_json(url, response_content))
            patterns.extend(self._learn_from_html(url, response_content))
            
        return patterns
    
    def _learn_from_json(self, url: str, content: str) -> List[APIPattern]:
        """从JSON响应学习"""
        patterns = []
        try:
            if not content.strip().startswith(('{', '[')):
                return patterns
                
            data = json.loads(content)
            
            if isinstance(data, dict):
                self._analyze_dict_keys(url, data, patterns)
            elif isinstance(data, list) and data and isinstance(data[0], dict):
                self._analyze_list_items(url, data, patterns)
                
        except (json.JSONDecodeError, Exception):
            pass
            
        return patterns
    
    def _analyze_dict_keys(self, url: str, data: dict, patterns: List[APIPattern]):
        """分析字典键"""
        parsed = urlparse(url)
        path = parsed.path.strip('/')
        parts = path.split('/') if path else []
        
        resource = parts[-1] if parts else ""
        prefix = '/'.join(parts[:-1]) if len(parts) > 1 else ""
        
        for key in data.keys():
            if self._is_suspicious_key(key):
                continue
                
            if isinstance(data[key], (dict, list)):
                pattern = APIPattern(
                    prefix=prefix,
                    resource=resource,
                    action="",
                    suffix="",
                    source=DataSource.RESPONSE_LEARN,
                    confidence=0.6
                )
                patterns.append(pattern)
                self.resource_counter[key.lower()] += 1
                
    def _analyze_list_items(self, url: str, data: list, patterns: List[APIPattern]):
        """分析列表项"""
        parsed = urlparse(url)
        path = parsed.path.strip('/')
        parts = path.split('/') if path else []
        
        if not data:
            return
            
        item = data[0]
        if not isinstance(item, dict):
            return
            
        resource = parts[-1] if parts else ""
        if resource.endswith('s') and len(resource) > 2:
            resource = resource[:-1]
            
        for key in item.keys():
            if self._is_suspicious_key(key):
                continue
                
            param_patterns = self._infer_param_pattern(key, item[key])
            for pp in param_patterns:
                self.param_patterns[key.lower()].add(pp)
                
    def _is_suspicious_key(self, key: str) -> bool:
        """检查是否是可疑键名"""
        suspicious = {'_', '__', '0', '1', 'id', 'ID', 'Id'}
        return key.strip() in suspicious or key.startswith('_')
    
    def _infer_param_pattern(self, key: str, value: Any) -> List[str]:
        """推断参数模式"""
        patterns = []
        
        if isinstance(value, int):
            if 'id' in key.lower():
                patterns.append(f"{key}={value}")
            elif 'page' in key.lower() or 'num' in key.lower():
                patterns.append(f"{key}=1")
            elif 'size' in key.lower() or 'limit' in key.lower():
                patterns.append(f"{key}=10")
            elif 'count' in key.lower() or 'total' in key.lower():
                patterns.append(f"{key}=0")
                
        elif isinstance(value, str):
            if 'name' in key.lower():
                patterns.append(f"{key}=test")
            elif 'email' in key.lower():
                patterns.append(f"{key}=test@example.com")
            elif 'status' in key.lower():
                patterns.append(f"{key}=active")
                
        return patterns
    
    def _learn_from_html(self, url: str, content: str) -> List[APIPattern]:
        """从HTML响应学习"""
        patterns = []
        
        api_paths = re.findall(r'["\']/(api|v[0-9]|rest|graphql)[\w/\-]*["\']', content)
        for path in api_paths[:20]:
            path_clean = path.strip('"\'')
            if path_clean and len(path_clean) > 2:
                patterns.append(APIPattern(
                    prefix="",
                    resource=path_clean.split('/')[-1] if '/' in path_clean else path_clean,
                    action="",
                    suffix="",
                    source=DataSource.HTML_PARSE,
                    confidence=0.5
                ))
                
        return patterns
    
    def get_learned_patterns(self) -> List[APIPattern]:
        """获取学习到的模式"""
        return self.learned_patterns
    
    def get_top_resources(self, n: int = 20) -> List[str]:
        """获取高频资源"""
        return [k for k, v in self.resource_counter.most_common(n)]
    
    def get_param_pattern(self, param_name: str) -> Set[str]:
        """获取参数模式"""
        return self.param_patterns.get(param_name.lower(), set())


class PassiveSourceCollector:
    """
    被动数据源采集器 (urlfinder启发)
    
    支持的被动源:
    - Wayback Machine
    - Common Crawl
    - AlienVault OTX
    """
    
    def __init__(self, http_client=None):
        self.http_client = http_client
        self.cached_urls: Set[str] = set()
        
    async def collect_from_wayback(self, domain: str) -> Set[str]:
        """从Wayback Machine采集URL"""
        urls = set()
        
        try:
            url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&limit=1000"
            
            if self.http_client:
                response = await self.http_client.request(url, timeout=30)
                if response and response.status_code == 200:
                    try:
                        data = json.loads(response.content)
                        if isinstance(data, list) and len(data) > 1:
                            for row in data[1:]:
                                if row and row[0]:
                                    original_url = row[0]
                                    if self._is_api_url(original_url):
                                        urls.add(original_url)
                    except Exception as e:
                        logger.debug(f"Wayback parsing error: {e}")
                        
        except Exception as e:
            logger.debug(f"Wayback collection error: {e}")
            
        self.cached_urls.update(urls)
        logger.info(f"Wayback collected {len(urls)} URLs for {domain}")
        return urls
    
    async def collect_from_alienvault(self, domain: str) -> Set[str]:
        """从AlienVault OTX采集URL"""
        urls = set()
        
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/hostname/{domain}/url_list?limit=100"
            
            if self.http_client:
                response = await self.http_client.request(url, timeout=30)
                if response and response.status_code == 200:
                    try:
                        data = json.loads(response.content)
                        if 'url_list' in data:
                            for item in data['url_list'][:500]:
                                if 'url' in item:
                                    original_url = item['url']
                                    if self._is_api_url(original_url):
                                        urls.add(original_url)
                    except Exception as e:
                        logger.debug(f"OTX parsing error: {e}")
                        
        except Exception as e:
            logger.debug(f"OTX collection error: {e}")
            
        self.cached_urls.update(urls)
        logger.info(f"OTX collected {len(urls)} URLs for {domain}")
        return urls
    
    def _is_api_url(self, url: str) -> bool:
        """判断是否是API URL"""
        if not url:
            return False
            
        api_indicators = [
            'api', 'v1', 'v2', 'v3', 'v4', 'rest', 'graphql',
            'json', 'xml', 'swagger', 'openapi', 'oauth',
            '/auth', '/user', '/admin', '/api/'
        ]
        
        url_lower = url.lower()
        return any(indicator in url_lower for indicator in api_indicators)
    
    async def collect_all(self, domain: str) -> Set[str]:
        """从所有被动源采集"""
        tasks = [
            self.collect_from_wayback(domain),
            self.collect_from_alienvault(domain)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        all_urls = set()
        for result in results:
            if isinstance(result, set):
                all_urls.update(result)
                
        return all_urls


class SmartRateLimiter:
    """
    智能速率限制器 (类似urlfinder的per-provider限制)
    
    特点:
    - per-target速率限制
    - 自适应调整
    - 防止封禁
    """
    
    def __init__(self, default_rate: int = 30):
        self.default_rate = default_rate
        self.target_rates: Dict[str, int] = {}
        self.target_last_request: Dict[str, float] = {}
        self.failed_requests: Dict[str, int] = defaultdict(int)
        
    def get_rate(self, target: str) -> int:
        """获取目标速率限制"""
        return self.target_rates.get(target, self.default_rate)
    
    def adjust_rate(self, target: str, success: bool):
        """根据成功率调整速率"""
        current_rate = self.get_rate(target)
        
        if success:
            if self.failed_requests[target] > 0:
                self.failed_requests[target] = max(0, self.failed_requests[target] - 1)
            new_rate = min(int(current_rate * 1.1), 100)
        else:
            self.failed_requests[target] += 1
            new_rate = max(int(current_rate * 0.5), 5)
            
        self.target_rates[target] = new_rate
        
    async def acquire(self, target: str):
        """获取许可"""
        rate = self.get_rate(target)
        min_interval = 1.0 / rate
        
        last = self.target_last_request.get(target, 0)
        elapsed = time.time() - last
        
        if elapsed < min_interval:
            await asyncio.sleep(min_interval - elapsed)
            
        self.target_last_request[target] = time.time()


class TFIDFClassifier:
    """
    TF-IDF URL分类器 (FLUX启发)
    
    使用TF-IDF算法识别API前缀和资源路径
    """
    
    def __init__(self):
        self.segment_freq: Counter = Counter()
        self.doc_freq: Counter = Counter()
        self.total_docs = 0
        self.segment_positions: Dict[str, Set[int]] = defaultdict(set)
        
    def fit(self, urls: List[str]):
        """从URL列表学习"""
        for url in urls:
            parsed = urlparse(url)
            path = parsed.path
            
            if not path or path == '/':
                continue
                
            segments = [s for s in path.split('/') if s]
            
            self.total_docs += 1
            
            for seg in set(segments):
                self.doc_freq[seg] += 1
                
            for i, seg in enumerate(segments):
                self.segment_freq[seg] += 1
                self.segment_positions[seg].add(i)
    
    def score_segment(self, segment: str) -> float:
        """计算段的TF-IDF分数"""
        if self.total_docs == 0 or segment not in self.segment_freq:
            return 0.0
            
        tf = self.segment_freq[segment] / self.total_docs
        docs_with_seg = self.doc_freq.get(segment, 1)
        idf = 1.0 / (docs_with_seg / self.total_docs + 0.01)
        
        positions = self.segment_positions.get(segment, {0})
        avg_pos = sum(positions) / len(positions) if positions else 0
        pos_weight = 1.0 / (avg_pos + 1)
        
        return tf * idf * pos_weight
    
    def classify_prefixes(self, threshold: float = 0.1) -> Set[str]:
        """分类API前缀"""
        prefixes = set()
        
        for seg in self.segment_freq:
            score = self.score_segment(seg)
            if score > threshold:
                prefixes.add(seg)
                
        return prefixes


class HybridFuzzer:
    """
    综合混合Fuzzer
    
    融合三个项目的优点:
    1. Akto: 流量模式学习 + 动态词表更新
    2. urlfinder: 被动数据源
    3. FLUX: TF-IDF分类 + 自适应批处理
    """
    
    def __init__(self, http_client=None):
        self.http_client = http_client
        self.traffic_learner = TrafficPatternLearner()
        self.passive_collector = PassiveSourceCollector(http_client)
        self.rate_limiter = SmartRateLimiter(default_rate=30)
        self.tfidf_classifier = TFIDFClassifier()
        
        self._wordlist = DynamicWordlist()
        
        self.discovered_endpoints: List[DiscoveredEndpoint] = []
        self.all_urls: Set[str] = set()
    
    @property
    def dynamic_wordlist(self) -> DynamicWordlist:
        """获取动态词表"""
        return self._wordlist
    
    def learn_and_update_wordlist(self, patterns: List[APIPattern]):
        """
        学习模式并更新动态词表
        
        这是Akto算法的核心：不断从流量中学习，更新词表
        """
        for pattern in patterns:
            self._wordlist.learn_from_pattern(pattern)
        
        logger.debug(f"Wordlist updated: {self._wordlist.get_stats()}")
    
    def get_dynamic_fuzz_paths(self) -> List[str]:
        """获取动态生成的Fuzzing路径"""
        return self._wordlist.generate_fuzz_paths()
    
    async def discover(self, base_url: str, domain: str) -> List[DiscoveredEndpoint]:
        """综合发现入口"""
        logger.info(f"Starting hybrid discovery for {domain}")
        
        parsed = urlparse(base_url)
        target = f"{parsed.scheme}://{parsed.netloc}"
        
        discovery_tasks = [
            self._discover_from_passive_sources(domain),
            self._discover_from_active_crawl(base_url),
            self._discover_from_fuzzing(target)
        ]
        
        await asyncio.gather(*discovery_tasks, return_exceptions=True)
        
        self._update_wordlist_from_discoveries()
        
        logger.info(f"Hybrid discovery complete: {len(self.discovered_endpoints)} endpoints")
        return self.discovered_endpoints
    
    def _update_wordlist_from_discoveries(self):
        """从发现结果更新词表"""
        for endpoint in self.discovered_endpoints:
            path = endpoint.path.strip('/')
            parts = path.split('/')
            
            for part in parts:
                if self._is_api_prefix(part):
                    self._wordlist.add_prefix(part, endpoint.confidence)
                else:
                    self._wordlist.add_resource(part, endpoint.confidence)
            
            self._wordlist.add_full_path(path, endpoint.confidence)
    
    async def _discover_from_passive_sources(self, domain: str):
        """从被动源发现"""
        try:
            passive_urls = await self.passive_collector.collect_all(domain)
            
            for url in passive_urls:
                if url not in self.all_urls:
                    self.all_urls.add(url)
                    
                    endpoint = DiscoveredEndpoint(
                        path=urlparse(url).path,
                        method="GET",
                        source=DataSource.WAYBACK,
                        confidence=0.7
                    )
                    self.discovered_endpoints.append(endpoint)
                    
        except Exception as e:
            logger.debug(f"Passive discovery error: {e}")
    
    async def _discover_from_active_crawl(self, base_url: str):
        """从主动爬取发现"""
        try:
            if not self.http_client:
                return
                
            response = await self.http_client.request(base_url)
            if not response:
                return
                
            content = response.content if hasattr(response, 'content') else ""
            
            patterns = self.traffic_learner.learn_from_response(
                base_url, content, response.status_code
            )
            
            for pattern in patterns:
                path = f"/{pattern.prefix}/{pattern.resource}".strip('/') if pattern.prefix else f"/{pattern.resource}"
                
                endpoint = DiscoveredEndpoint(
                    path=path,
                    method="GET",
                    source=DataSource.RESPONSE_LEARN,
                    confidence=0.6,
                    patterns=[pattern]
                )
                self.discovered_endpoints.append(endpoint)
                self.all_urls.add(path)
                
            urls_in_page = re.findall(r'href=["\'](/[^"\']+)["\']', content)
            for url in urls_in_page[:100]:
                if url.startswith('/') and self._is_api_path(url):
                    full_url = urljoin(base_url, url)
                    if full_url not in self.all_urls:
                        self.all_urls.add(full_url)
                        
                        endpoint = DiscoveredEndpoint(
                            path=url,
                            method="GET",
                            source=DataSource.HTML_PARSE,
                            confidence=0.5
                        )
                        self.discovered_endpoints.append(endpoint)
                        
        except Exception as e:
            logger.debug(f"Active crawl error: {e}")
    
    async def _discover_from_fuzzing(self, target: str):
        """从Fuzzing发现"""
        fuzz_targets = self._generate_fuzz_targets()
        
        for fuzz_path in fuzz_targets[:500]:
            await self.rate_limiter.acquire(target)
            
            url = f"{target}{fuzz_path}"
            
            try:
                if self.http_client:
                    response = await self.http_client.request(url, method='HEAD', timeout=5)
                    status = response.status_code if response else 0
                else:
                    status = 0
                    
                if status and 200 <= status < 400:
                    endpoint = DiscoveredEndpoint(
                        path=fuzz_path,
                        method="GET",
                        source=DataSource.FUZZ_GEN,
                        confidence=0.4
                    )
                    self.discovered_endpoints.append(endpoint)
                    self.all_urls.add(fuzz_path)
                    
                self.rate_limiter.adjust_rate(target, 200 <= status < 400)
                
            except Exception:
                self.rate_limiter.adjust_rate(target, False)
    
    def _generate_fuzz_targets(self) -> List[str]:
        """生成Fuzz目标"""
        targets = []
        
        resources = self.traffic_learner.get_top_resources(30)
        
        common_suffixes = [
            '', '/list', '/detail', '/add', '/create', '/edit', '/update', '/delete',
            '/search', '/query', '/filter', '/export', '/import',
            '/info', '/page', '/all', '/count', '/stats'
        ]
        
        api_prefixes = ['api', 'v1', 'v2', 'v3', 'rest', 'graphql']
        
        for resource in resources:
            for prefix in api_prefixes:
                for suffix in common_suffixes:
                    path = f"/{prefix}/{resource}{suffix}"
                    if path not in targets:
                        targets.append(path)
        
        for resource in ['user', 'users', 'order', 'orders', 'product', 'products', 
                         'admin', 'login', 'auth', 'token', 'account', 'session']:
            for prefix in api_prefixes:
                for suffix in common_suffixes:
                    path = f"/{prefix}/{resource}{suffix}"
                    if path not in targets:
                        targets.append(path)
                        
        return targets[:1000]
    
    def _is_api_path(self, path: str) -> bool:
        """判断是否是API路径"""
        api_indicators = ['api', 'v1', 'v2', 'rest', 'graphql', 'json']
        path_lower = path.lower()
        return any(ind in path_lower for ind in api_indicators) or '/' in path
    
    def _is_api_prefix(self, segment: str) -> bool:
        """判断是否是API前缀"""
        prefixes = {'api', 'v1', 'v2', 'v3', 'v4', 'v5', 'rest', 'graphql', 'soap', 'rpc', 'gateway', 'openapi', 'swagger'}
        return segment.lower() in prefixes
    
    def get_endpoints(self) -> List[DiscoveredEndpoint]:
        """获取所有发现的端点"""
        return self.discovered_endpoints
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        source_counts = Counter(e.source.value for e in self.discovered_endpoints)
        
        return {
            'total_endpoints': len(self.discovered_endpoints),
            'by_source': dict(source_counts),
            'learned_resources': len(self.traffic_learner.resource_counter),
            'learned_params': len(self.traffic_learner.param_patterns),
            'passive_urls': len(self.all_urls),
            'dynamic_wordlist': self._wordlist.get_stats()
        }
    
    def get_fuzz_paths_preview(self, top_n: int = 20) -> List[str]:
        """获取动态生成的Fuzzing路径预览"""
        paths = self._wordlist.generate_fuzz_paths(top_n)
        return paths[:top_n]


async def hybrid_fuzz(base_url: str, http_client=None) -> Tuple[List[DiscoveredEndpoint], Dict[str, Any]]:
    """
    便捷函数: 执行综合混合Fuzzing
    
    Returns:
        (发现的端点列表, 统计信息)
    """
    parsed = urlparse(base_url)
    domain = parsed.netloc
    
    fuzzer = HybridFuzzer(http_client)
    endpoints = await fuzzer.discover(base_url, domain)
    stats = fuzzer.get_stats()
    
    return endpoints, stats


if __name__ == "__main__":
    print("HybridFuzzer - 综合混合Fuzzing算法")
    print("融合: Akto + urlfinder + FLUX")
