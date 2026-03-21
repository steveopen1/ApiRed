"""
Response Cluster Module
响应指纹聚类模块 - 404基线过滤
"""

import hashlib
import re
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from collections import defaultdict
import json


@dataclass
class ResponseFingerprint:
    """响应指纹"""
    status_code: int
    length_bucket: str
    template_hash: str
    raw_hash: str
    content_preview: str
    url: str


class ResponseCluster:
    """响应指纹聚类"""
    
    LENGTH_BUCKETS = [
        (0, "empty"),
        (100, "tiny"),
        (1000, "small"),
        (10000, "medium"),
        (100000, "large"),
        (float('inf'), "huge")
    ]
    
    TEMPLATE_PATTERNS = [
        (r'<!DOCTYPE\s+html', 'html'),
        (r'<html', 'html'),
        (r'^\s*\{', 'json'),
        (r'^\s*\[', 'json'),
        (r'^\s*<', 'xml'),
    ]
    
    def __init__(self, similarity_threshold: float = 0.8):
        self.similarity_threshold = similarity_threshold
        self._clusters: Dict[str, List[ResponseFingerprint]] = defaultdict(list)
        self._cluster_stats: Dict[str, Dict] = {}
    
    def compute_fingerprint(self, url: str, status_code: int, content: str) -> ResponseFingerprint:
        """计算响应指纹"""
        length_bucket = self._get_length_bucket(len(content))
        template_hash = self._extract_template_hash(content)
        raw_hash = hashlib.md5(content[:5000].encode()).hexdigest()[:16]
        content_preview = self._extract_preview(content)
        
        return ResponseFingerprint(
            status_code=status_code,
            length_bucket=length_bucket,
            template_hash=template_hash,
            raw_hash=raw_hash,
            content_preview=content_preview,
            url=url
        )
    
    def _get_length_bucket(self, length: int) -> str:
        """获取长度分桶"""
        for max_len, bucket in self.LENGTH_BUCKETS:
            if length < max_len:
                return bucket
        return "huge"
    
    def _extract_template_hash(self, content: str) -> str:
        """提取模板哈希"""
        cleaned = self._remove_dynamic_content(content[:2000])
        
        template_type = 'unknown'
        for pattern, ptype in self.TEMPLATE_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                template_type = ptype
                break
        
        template_content = cleaned[:500]
        return hashlib.md5(f"{template_type}:{template_content}".encode()).hexdigest()[:8]
    
    def _remove_dynamic_content(self, content: str) -> str:
        """移除动态内容"""
        cleaned = re.sub(r'\d+', 'N', content)
        cleaned = re.sub(r'[a-f0-9]{32,}', 'HASH', cleaned)
        cleaned = re.sub(r'[a-f0-9]{16,31}', 'HASH16', cleaned)
        cleaned = re.sub(r'["\'][\w+-]+["\']\s*:\s*["\'][^"\']{50,}["\']', 'LONG_STR', cleaned)
        
        return cleaned
    
    def _extract_preview(self, content: str, max_len: int = 100) -> str:
        """提取预览"""
        if not content:
            return ""
        
        lines = content.split('\n')
        preview_lines = []
        
        for line in lines[:5]:
            cleaned = re.sub(r'\s+', ' ', line).strip()
            if cleaned:
                preview_lines.append(cleaned[:100])
        
        return ' | '.join(preview_lines)
    
    def add_response(self, fingerprint: ResponseFingerprint):
        """添加响应到聚类"""
        key = self._get_cluster_key(fingerprint)
        self._clusters[key].append(fingerprint)
    
    def _get_cluster_key(self, fp: ResponseFingerprint) -> str:
        """获取聚类键"""
        return f"{fp.status_code}_{fp.length_bucket}_{fp.template_hash}"
    
    def analyze_clusters(self) -> Dict[str, Any]:
        """分析聚类"""
        results = {
            'total_responses': 0,
            'clusters': {},
            '404_family': [],
            'error_family': [],
            'success_family': [],
            'suspicious_apis': []
        }
        
        for cluster_key, fingerprints in self._clusters.items():
            count = len(fingerprints)
            results['total_responses'] += count
            
            status = fingerprints[0].status_code
            sample_url = fingerprints[0].url
            
            cluster_info = {
                'count': count,
                'status': status,
                'length_bucket': fingerprints[0].length_bucket,
                'template_hash': fingerprints[0].template_hash,
                'sample_url': sample_url
            }
            
            results['clusters'][cluster_key] = cluster_info
            
            if status == 404:
                results['404_family'].append(cluster_key)
            elif status >= 400:
                results['error_family'].append(cluster_key)
            elif 200 <= status < 300:
                results['success_family'].append(cluster_key)
        
        results['404_ratio'] = (
            len(results['404_family']) / len(results['clusters'])
            if results['clusters'] else 0
        )
        
        return results
    
    def get_suspicious_apis(self) -> List[str]:
        """获取可疑API列表"""
        suspicious = []
        
        for cluster_key, fps in self._clusters.items():
            if fps[0].status_code == 404 and len(fps) > 10:
                suspicious.extend([fp.url for fp in fps[:5]])
        
        return suspicious
    
    def is_404_family(self, fingerprint: ResponseFingerprint) -> bool:
        """判断是否属于404家族"""
        return self._get_cluster_key(fingerprint) in self._404_family_clusters
    
    def should_skip_ai_analysis(self, fingerprint: ResponseFingerprint) -> Tuple[bool, str]:
        """判断是否应跳过AI分析"""
        if fingerprint.status_code == 404:
            return True, "404 response"
        
        cluster_key = self._get_cluster_key(fingerprint)
        
        if cluster_key in self._clusters:
            count = len(self._clusters[cluster_key])
            if count > 50 and fingerprint.status_code >= 400:
                return True, f"Large error cluster ({count})"
        
        if fingerprint.length_bucket == "empty":
            return True, "Empty response"
        
        return False, ""


class BypassTester:
    """Bypass测试器"""
    
    BYPASS_TECHNIQUES = {
        'header_injection': [
            {'X-Forwarded-Host': 'localhost'},
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Original-URL': None},
            {'X-Rewrite-URL': None}
        ],
        'method_tampering': [
            {'_method': 'PUT'},
            {'_method': 'DELETE'},
            {'X-HTTP-Method': 'PUT'},
            {'X-HTTP-Method-Override': 'DELETE'}
        ],
        'path_traversal': [
            {'../': ''},
            {'..;/': ''},
            {'....;//': ''},
            {'%2e%2e%2f': ''}
        ],
        'encoding_bypass': [
            {'%': '%25'},
            {'.': '%2e'},
            {'/': '%2f'},
            {'\\': '%5c'}
        ]
    }
    
    @classmethod
    def get_techniques(cls, technique_names: List[str] = None) -> Dict[str, List[Dict]]:
        """获取Bypass技术"""
        if technique_names:
            return {
                k: v for k, v in cls.BYPASS_TECHNIQUES.items()
                if k in technique_names
            }
        return cls.BYPASS_TECHNIQUES
    
    @classmethod
    def generate_bypass_urls(cls, original_url: str, techniques: List[str] = None) -> List[Tuple[str, str]]:
        """生成Bypass URL列表"""
        bypass_urls = []
        techniques = techniques or list(cls.BYPASS_TECHNIQUES.keys())
        
        for tech_name in techniques:
            if tech_name not in cls.BYPASS_TECHNIQUES:
                continue
            
            for headers in cls.BYPASS_TECHNIQUES[tech_name]:
                bypass_urls.append((original_url, tech_name))
        
        return bypass_urls
