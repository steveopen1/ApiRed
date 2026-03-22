"""
Response Difference Analyzer
响应差异分析器 - 判断真假绕过，避免假阳性
参考 HackerOne/Bugcrowd 众测实战技巧
"""

import hashlib
import json
import re
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass
from difflib import SequenceMatcher


@dataclass
class ResponseDiff:
    """响应差异"""
    diff_type: str  # status_code, header, content_length, content_body, structure
    original_value: Any
    modified_value: Any
    significance: float  # 0.0 - 1.0, 越高表示越重要
    is_positive: bool  # True = 真正的绕过, False = 假阳性


class ResponseAnalyzer:
    """
    响应差异分析器
    
    功能:
    1. 状态码差异分析
    2. 响应头差异分析
    3. 内容长度差异分析
    4. JSON 结构差异分析
    5. 假阳性识别
    """
    
    FALSE_POSITIVE_PATTERNS = {
        'redirect': [
            r'<script>window\.location',
            r'<meta http-equiv="refresh"',
            r'href="login',
            r'Redirecting to',
        ],
        'error': [
            r'error occurred',
            r'something went wrong',
            r'please try again',
            r'system error',
        ],
        'captcha': [
            r'captcha',
            r'verification required',
            r'are you a robot',
        ],
        'blocked': [
            r'access blocked',
            r'request blocked',
            r'too many requests',
        ]
    }
    
    POSITIVE_BYPASS_PATTERNS = {
        'data_leak': [
            r'"email"\s*:',
            r'"phone"\s*:',
            r'"address"\s*:',
            r'"password"\s*:',
            r'"ssn"\s*:',
            r'"credit_card"\s*:',
            r'"api_key"\s*:',
        ],
        'sensitive_access': [
            r'"admin"\s*:',
            r'"role"\s*:\s*"admin"',
            r'"privileges"\s*:',
            r'"is_superuser"\s*:',
        ],
        'auth_bypass': [
            r'"token"\s*:',
            r'"session"\s*:',
            r'"auth"\s*:',
        ]
    }
    
    def __init__(self, similarity_threshold: float = 0.85):
        self.similarity_threshold = similarity_threshold
        self._response_cache: Dict[str, str] = {}
    
    def analyze(
        self,
        original_response: Dict[str, Any],
        modified_response: Dict[str, Any]
    ) -> Tuple[bool, List[ResponseDiff]]:
        """
        分析响应差异
        
        Returns:
            (是否为真正的绕过, 差异列表)
        """
        diffs = []
        
        status_diff = self._analyze_status_code(original_response, modified_response)
        if status_diff:
            diffs.append(status_diff)
        
        header_diffs = self._analyze_headers(original_response, modified_response)
        diffs.extend(header_diffs)
        
        content_diff = self._analyze_content(original_response, modified_response)
        if content_diff:
            diffs.append(content_diff)
        
        structure_diff = self._analyze_json_structure(original_response, modified_response)
        if structure_diff:
            diffs.append(structure_diff)
        
        is_true_bypass = self._is_true_bypass(diffs, modified_response)
        
        return is_true_bypass, diffs
    
    def _analyze_status_code(
        self,
        original: Dict[str, Any],
        modified: Dict[str, Any]
    ) -> Optional[ResponseDiff]:
        """分析状态码差异"""
        orig_status = original.get('status_code', 0)
        mod_status = modified.get('status_code', 0)
        
        if orig_status == mod_status:
            return None
        
        significance = 0.0
        diff_type = 'status_code'
        original_value = orig_status
        modified_value = mod_status
        
        if orig_status in [401, 403] and mod_status == 200:
            significance = 1.0
        elif orig_status in [401, 403] and mod_status in [302, 301]:
            significance = 0.3
        elif orig_status == 404 and mod_status == 200:
            significance = 0.9
        elif mod_status in [500, 502, 503]:
            significance = 0.2
        else:
            significance = 0.5
        
        return ResponseDiff(
            diff_type=diff_type,
            original_value=original_value,
            modified_value=modified_value,
            significance=significance,
            is_positive=significance >= 0.5
        )
    
    def _analyze_headers(
        self,
        original: Dict[str, Any],
        modified: Dict[str, Any]
    ) -> List[ResponseDiff]:
        """分析响应头差异"""
        diffs = []
        
        orig_headers = original.get('headers', {})
        mod_headers = modified.get('headers', {})
        
        if not isinstance(orig_headers, dict):
            orig_headers = {}
        if not isinstance(mod_headers, dict):
            mod_headers = {}
        
        all_keys = set(orig_headers.keys()) | set(mod_headers.keys())
        
        for key in all_keys:
            if key.lower() in ['content-length', 'content-encoding', 'date', 'server']:
                continue
            
            orig_val = str(orig_headers.get(key, ''))
            mod_val = str(mod_headers.get(key, ''))
            
            if orig_val != mod_val:
                significance = 0.3 if 'set-cookie' in key.lower() else 0.2
                
                diffs.append(ResponseDiff(
                    diff_type=f'header_{key}',
                    original_value=orig_val,
                    modified_value=mod_val,
                    significance=significance,
                    is_positive=False
                ))
        
        return diffs
    
    def _analyze_content(
        self,
        original: Dict[str, Any],
        modified: Dict[str, Any]
    ) -> Optional[ResponseDiff]:
        """分析响应内容差异"""
        orig_content = original.get('content', '')
        mod_content = modified.get('content', '')
        
        if not orig_content or not mod_content:
            if orig_content != mod_content:
                return ResponseDiff(
                    diff_type='content_length',
                    original_value=len(orig_content) if orig_content else 0,
                    modified_value=len(mod_content) if mod_content else 0,
                    significance=0.4,
                    is_positive=False
                )
            return None
        
        orig_len = len(orig_content)
        mod_len = len(mod_content)
        length_ratio = min(orig_len, mod_len) / max(orig_len, mod_len) if max(orig_len, mod_len) > 0 else 1.0
        
        if length_ratio < 0.5:
            return ResponseDiff(
                diff_type='content_length',
                original_value=orig_len,
                modified_value=mod_len,
                significance=0.6,
                is_positive=True
            )
        
        similarity = SequenceMatcher(None, orig_content, mod_content).ratio()
        
        if similarity < 0.7:
            return ResponseDiff(
                diff_type='content_body',
                original_value=f"{orig_len} chars",
                modified_value=f"{mod_len} chars",
                significance=0.7,
                is_positive=True
            )
        
        return None
    
    def _analyze_json_structure(
        self,
        original: Dict[str, Any],
        modified: Dict[str, Any]
    ) -> Optional[ResponseDiff]:
        """分析 JSON 结构差异"""
        orig_content = original.get('content', '')
        mod_content = modified.get('content', '')
        
        try:
            if not (orig_content.strip().startswith('{') and mod_content.strip().startswith('{')):
                return None
            
            orig_json = json.loads(orig_content)
            mod_json = json.loads(mod_content)
            
            if not isinstance(orig_json, dict) or not isinstance(mod_json, dict):
                return None
            
            orig_keys = set(orig_json.keys())
            mod_keys = set(mod_json.keys())
            
            added_keys = mod_keys - orig_keys
            removed_keys = orig_keys - mod_keys
            
            if added_keys:
                sensitive_added = added_keys & {'email', 'phone', 'address', 'password', 'ssn', 
                                                  'credit_card', 'admin', 'role', 'token', 'api_key'}
                if sensitive_added:
                    return ResponseDiff(
                        diff_type='json_structure',
                        original_value=f"Keys: {orig_keys}",
                        modified_value=f"Added keys: {sensitive_added}",
                        significance=0.9,
                        is_positive=True
                    )
            
            if removed_keys:
                return ResponseDiff(
                    diff_type='json_structure',
                    original_value=f"Keys: {orig_keys}",
                    modified_value=f"Removed keys: {removed_keys}",
                    significance=0.5,
                    is_positive=False
                )
                
        except (json.JSONDecodeError, TypeError):
            pass
        
        return None
    
    def _is_true_bypass(
        self,
        diffs: List[ResponseDiff],
        modified_response: Dict[str, Any]
    ) -> bool:
        """判断是否为真正的绕过"""
        if not diffs:
            return False
        
        content = modified_response.get('content', '')
        
        if not content:
            return False
        
        content_lower = content.lower()
        
        for pattern_list in self.FALSE_POSITIVE_PATTERNS.values():
            for pattern in pattern_list:
                if re.search(pattern, content_lower, re.IGNORECASE):
                    return False
        
        for pattern_list in self.POSITIVE_BYPASS_PATTERNS.values():
            for pattern in pattern_list:
                if re.search(pattern, content_lower, re.IGNORECASE):
                    return True
        
        high_significance_diffs = [d for d in diffs if d.significance >= 0.7]
        if high_significance_diffs:
            return any(d.is_positive for d in high_significance_diffs)
        
        status_diff = next((d for d in diffs if d.diff_type == 'status_code'), None)
        if status_diff and status_diff.original_value in [401, 403] and status_diff.modified_value == 200:
            return True
        
        return False
    
    def compute_response_hash(
        self,
        response: Dict[str, Any]
    ) -> str:
        """计算响应哈希"""
        content = response.get('content', '')
        status = response.get('status_code', 0)
        key = f"{status}:{content[:500]}"
        return hashlib.md5(key.encode()).hexdigest()[:16]
    
    def is_duplicate_response(
        self,
        response: Dict[str, Any]
    ) -> bool:
        """检查是否为重复响应"""
        resp_hash = self.compute_response_hash(response)
        if resp_hash in self._response_cache:
            return True
        self._response_cache[resp_hash] = ''
        return False
    
    def reset_cache(self):
        """重置缓存"""
        self._response_cache.clear()


def analyze_response_pair(
    original: Dict[str, Any],
    modified: Dict[str, Any]
) -> Tuple[bool, str]:
    """
    快速分析响应差异
    
    Returns:
        (是否为真绕过, 分析说明)
    """
    analyzer = ResponseAnalyzer()
    is_bypass, diffs = analyzer.analyze(original, modified)
    
    if is_bypass:
        reason = "检测到敏感数据泄露或认证绕过"
    else:
        reason = "未发现明显的漏洞迹象或为假阳性"
    
    return is_bypass, reason
