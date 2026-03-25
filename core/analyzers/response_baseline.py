"""
Response Baseline Learning Module
响应基线学习 - 解决非标准响应行为问题
"""

import hashlib
import re
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass
from collections import Counter


@dataclass
class ResponseBaseline:
    """响应基线"""
    content_hash: str
    content_preview: str
    status_codes: List[int]
    content_length_stats: Dict[str, float]
    common_strings: List[str]
    is_api: bool
    is_default_page: bool


@dataclass
class APIResponseSignature:
    """API 响应签名"""
    url: str
    status_code: int
    content_preview: str
    is_api: bool


class ResponseDifferentiator:
    """
    响应差异化分析器
    参考 0x727/ChkApi 的 content_hash 差异化功能

    功能：
    1. 计算响应内容哈希
    2. 统计相同哈希出现次数
    3. 识别响应差异化（过滤重复的"缺少凭证"响应）
    """

    def __init__(self):
        self.content_hashes: Dict[str, int] = {}
        self.hash_to_responses: Dict[str, List[Dict]] = {}

    def add_response(self, url: str, method: str, status_code: int,
                    content: str, content_length: int) -> str:
        """
        添加响应并计算哈希

        Returns:
            content_hash
        """
        content_hash = hashlib.md5(content[:1000].encode()).hexdigest()

        self.content_hashes[content_hash] = self.content_hashes.get(content_hash, 0) + 1

        if content_hash not in self.hash_to_responses:
            self.hash_to_responses[content_hash] = []

        self.hash_to_responses[content_hash].append({
            'url': url,
            'method': method,
            'status_code': status_code,
            'length': content_length,
            'hash_count': self.content_hashes[content_hash]
        })

        return content_hash

    def get_hash_count(self, content_hash: str) -> int:
        """获取相同哈希出现次数"""
        return self.content_hashes.get(content_hash, 0)

    def is_duplicate_response(self, content_hash: str, threshold: int = 5) -> bool:
        """
        判断是否为重复响应
        如果相同哈希出现次数超过阈值，认为是重复响应
        """
        return self.content_hashes.get(content_hash, 0) > threshold

    def get_rare_responses(self, min_count: int = 1, max_count: int = 3) -> List[str]:
        """
        获取稀有响应（出现次数较少的哈希）
        这些响应更可能是有效的 API 响应
        """
        return [
            h for h, count in self.content_hashes.items()
            if min_count <= count <= max_count
        ]

    def get_duplicate_groups(self) -> Dict[str, List[Dict]]:
        """
        获取重复响应组
        用于过滤大量相同的"缺少凭证"等默认响应
        """
        return {
            h: responses for h, responses in self.hash_to_responses.items()
            if len(responses) > 3
        }

    def analyze_response_diversity(self) -> Dict[str, Any]:
        """
        分析响应多样性

        返回：
        - unique_count: 唯一响应数
        - duplicate_count: 重复响应数
        - total_count: 总响应数
        - diversity_rate: 多样性比率
        """
        total = sum(self.content_hashes.values())
        unique = len(self.content_hashes)
        duplicates = sum(c - 1 for c in self.content_hashes.values())

        return {
            'unique_count': unique,
            'duplicate_count': duplicates,
            'total_count': total,
            'diversity_rate': unique / total if total > 0 else 0,
            'hash_distribution': dict(sorted(
                self.content_hashes.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10])
        }


class ResponseBaselineLearner:
    """
    响应基线学习器
    
    解决的问题：
    1. "全部 200" - 所有路径返回 200，无法用状态码判断
    2. 默认页面检测 - 大量响应是默认页面，需要过滤
    3. API 有效性判断 - 状态码相同但内容不同
    
    工作原理：
    1. 从初始探测响应中学习基线
    2. 识别默认页面特征
    3. 通过内容特征判断是否为有效 API 响应
    """
    
    def __init__(self):
        self.baselines: Dict[str, ResponseBaseline] = {}
        self.default_page_hashes: Set[str] = set()
        self.api_content_signatures: List[str] = [
            '"',                    # JSON starts with quote
            'application/json',
            '"code":',
            '"data":',
            '"success":',
            '"status":',
            '"total":',
            '"rows":',
            '"token"',
            '"session"',
            '[' ,                   # JSON array
        ]
        self.non_api_signatures: List[str] = [
            '<html',
            '<!DOCTYPE',
            '<title>',
            '.html',
            '.jsp',
            '.asp',
            '智慧小区',
            'VC Framework',
            'page not found',
            '404',
            'error',
            'Internal Server Error',
        ]
        self._learned = False
    
    def learn(self, responses: List['TaskResult']) -> Dict[str, ResponseBaseline]:
        """
        从响应列表中学习基线
        
        Args:
            responses: HTTP 响应列表
        
        Returns:
            学习到的基线字典
        """
        self._learn_default_pages(responses)
        self._learn_baselines(responses)
        self._learned = True
        return self.baselines
    
    def _learn_default_pages(self, responses: List['TaskResult']):
        """学习默认页面特征"""
        content_counts: Dict[str, int] = {}
        
        for r in responses:
            content_preview = self._get_content_preview(r)
            if content_preview:
                content_counts[content_preview] = content_counts.get(content_preview, 0) + 1
        
        most_common_threshold = len(responses) * 0.1
        for content_preview, count in content_counts.items():
            if count >= most_common_threshold:
                self.default_page_hashes.add(hashlib.md5(content_preview.encode()).hexdigest())
    
    def _learn_baselines(self, responses: List['TaskResult']):
        """学习响应基线"""
        clusters: Dict[str, List['TaskResult']] = {}
        
        for r in responses:
            content_preview = self._get_content_preview(r)
            if not content_preview:
                continue
            
            content_hash = hashlib.md5(content_preview.encode()).hexdigest()
            
            if content_hash not in clusters:
                clusters[content_hash] = []
            clusters[content_hash].append(r)
        
        for content_hash, cluster_responses in clusters.items():
            status_codes = [r.status_code for r in cluster_responses]
            content_lengths = [len(r.content) if r.content else 0 for r in cluster_responses]
            
            is_api = self._is_likely_api(cluster_responses[0])
            is_default = self._is_default_page(cluster_responses[0])
            
            self.baselines[content_hash] = ResponseBaseline(
                content_hash=content_hash,
                content_preview=self._get_content_preview(cluster_responses[0]),
                status_codes=status_codes,
                content_length_stats=self._calc_length_stats(content_lengths),
                common_strings=self._extract_common_strings(cluster_responses),
                is_api=is_api,
                is_default_page=is_default
            )
    
    def _get_content_preview(self, response: 'TaskResult') -> str:
        """获取内容预览（前 500 字符）"""
        if hasattr(response, 'content') and response.content:
            content = response.content
            if isinstance(content, bytes):
                content = content.decode('utf-8', errors='ignore')
            return content[:500]
        return ""
    
    def _is_likely_api(self, response: 'TaskResult') -> bool:
        """判断是否为可能的 API 响应"""
        content = self._get_content_preview(response)
        content_lower = content.lower()
        
        api_score = sum(1 for sig in self.api_content_signatures if sig in content_lower)
        non_api_score = sum(1 for sig in self.non_api_signatures if sig in content_lower)
        
        return api_score > non_api_score and api_score >= 2
    
    def _is_default_page(self, response: 'TaskResult') -> bool:
        """判断是否为默认页面"""
        content = self._get_content_preview(response)
        content_hash = hashlib.md5(content.encode()).hexdigest()
        
        if content_hash in self.default_page_hashes:
            return True
        
        content_lower = content.lower()
        default_indicators = [
            '智慧小区', 'vc framework', 'vc-framework',
            'page not found', '404 not found',
            '<title>404', '<title>500'
        ]
        
        return any(ind in content_lower for ind in default_indicators)
    
    def _calc_length_stats(self, lengths: List[int]) -> Dict[str, float]:
        """计算长度统计"""
        if not lengths:
            return {'mean': 0, 'std': 0, 'min': 0, 'max': 0}
        
        mean = sum(lengths) / len(lengths)
        variance = sum((x - mean) ** 2 for x in lengths) / len(lengths)
        std = variance ** 0.5
        
        return {
            'mean': mean,
            'std': std,
            'min': min(lengths),
            'max': max(lengths)
        }
    
    def _extract_common_strings(self, responses: List['TaskResult']) -> List[str]:
        """提取共同字符串"""
        if not responses:
            return []
        
        first_content = self._get_content_preview(responses[0])
        
        common = []
        for i in range(min(10, len(first_content))):
            prefix = first_content[:i+1]
            count = sum(1 for r in responses if self._get_content_preview(r).startswith(prefix))
            if count == len(responses):
                common.append(prefix)
            else:
                break
        
        return common[:10]
    
    def is_api_response(self, response: 'TaskResult') -> bool:
        """判断是否为 API 响应"""
        if self._learned:
            content_preview = self._get_content_preview(response)
            content_hash = hashlib.md5(content_preview.encode()).hexdigest()
            
            if content_hash in self.baselines:
                return self.baselines[content_hash].is_api
        
        return self._is_likely_api(response)
    
    def is_default_page(self, response: 'TaskResult') -> bool:
        """判断是否为默认页面"""
        if self._learned:
            content_preview = self._get_content_preview(response)
            content_hash = hashlib.md5(content_preview.encode()).hexdigest()
            
            if content_hash in self.baselines:
                return self.baselines[content_hash].is_default_page
        
        return self._is_default_page(response)
    
    def is_valid_api(self, response: 'TaskResult') -> bool:
        """
        综合判断是否为有效的 API 响应
        
        排除：
        1. 默认页面
        2. HTML 错误页面
        3. 空响应
        
        保留：
        1. JSON 响应
        2. 包含 API 特征（token, code, data 等）
        """
        if self.is_default_page(response):
            return False
        
        content = self._get_content_preview(response)
        if not content or len(content) < 10:
            return False
        
        if self.is_api_response(response):
            return True
        
        content_lower = content.lower()
        
        negative_patterns = [
            '<html', '<!doctype', '<title>',
            'page not found', '404', '500 error',
            'internal server error', 'forbidden',
            'access denied', 'unauthorized',
            '安全卫士', '应用防护平台', 'waf', '云防护',
            '您的请求带有不法参数', '已被安全卫士拦截',
            '请求拦截', '访问拦截', 'attackType',
            'xss', 'sql injection', 'webshell',
            'protected', 'defense', 'guard'
        ]
        
        positive_patterns = [
            '"', 'application/json', 'application/xml',
            '"code"', '"data"', '"success"',
            '"token"', '"session"', '"user"',
            '"id"', '"name"'
        ]
        
        neg_score = sum(1 for p in negative_patterns if p in content_lower)
        pos_score = sum(1 for p in positive_patterns if p in content_lower)
        
        return pos_score > neg_score
    
    def get_baseline_count(self) -> int:
        """获取学习的基线数量"""
        return len(self.baselines)
    
    def get_default_page_count(self) -> int:
        """获取识别的默认页面数量"""
        return len(self.default_page_hashes)


def create_baseline_learner() -> ResponseBaselineLearner:
    """创建响应基线学习器"""
    return ResponseBaselineLearner()
