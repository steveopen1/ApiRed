"""
Vulnerability Verification Framework
漏洞多维验证框架 - 降低误报率

核心思路：
1. 多维度验证：响应内容+状态码+时间+上下文
2. 证据链：每一步验证都记录证据
3. 可信度评分：综合评分而非二元判定
4. 验证历史：记录历史验证结果用于学习
"""

import asyncio
import time
import logging
from typing import Dict, List, Optional, Any, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
from difflib import SequenceMatcher

logger = logging.getLogger(__name__)


class VerificationConfidence(Enum):
    """验证置信度"""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    FALSE_POSITIVE = "false_positive"


@dataclass
class VerificationEvidence:
    """验证证据"""
    check_name: str
    passed: bool
    details: str
    baseline_value: Optional[str] = None
    test_value: Optional[str] = None


@dataclass
class MultiDimensionalVerification:
    """多维度验证结果"""
    vuln_type: str
    url: str
    param: str
    confidence: VerificationConfidence
    evidence_chain: List[VerificationEvidence]
    overall_score: float
    is_verified: bool
    recommendation: str
    verification_details: str = ""


class ResponseBaseline:
    """响应基线"""

    def __init__(self):
        self.baselines: Dict[str, Dict] = {}

    def record_baseline(
        self,
        url: str,
        method: str,
        response_data: Dict
    ):
        key = f"{method}:{url}"
        self.baselines[key] = {
            'status_code': response_data.get('status_code'),
            'content_hash': response_data.get('content_hash'),
            'content_length': len(response_data.get('content', '')),
            'response_time': response_data.get('response_time', 0),
            'headers': response_data.get('headers', {}),
            'timestamp': time.time()
        }

    def get_baseline(self, url: str, method: str) -> Optional[Dict]:
        key = f"{method}:{url}"
        return self.baselines.get(key)

    def clear_old_baselines(self, max_age: int = 3600):
        """清除过期的基线数据"""
        current_time = time.time()
        expired_keys = [
            k for k, v in self.baselines.items()
            if current_time - v.get('timestamp', 0) > max_age
        ]
        for k in expired_keys:
            del self.baselines[k]


class MultiDimensionalVerifier:
    """
    多维度漏洞验证器
    
    验证维度：
    1. 内容维度：响应内容差异
    2. 状态码维度：HTTP状态码变化
    3. 时间维度：响应时间异常
    4. 上下文维度：错误上下文匹配
    """

    SQLI_ERROR_KEYWORDS = [
        'sql', 'mysql', 'oracle', 'postgresql', 'sqlite', 'mariadb',
        'syntax error', 'mysql_', 'mysqli_', 'ora-', 'sqlstate',
        'microsoft sql', 'odbc', 'sqlite_', 'psycopg2', 'pq_connect',
        'warning: mysql', 'fatal:', 'unterminated', 'quoted string',
        'sql syntax', 'invalid query', 'query failed',
    ]

    XSS_REFLECTION_KEYWORDS = [
        '<script', 'javascript:', 'onerror=', 'onload=',
        'onclick=', 'onmouseover=', 'onfocus=',
        'alert(', 'prompt(', 'confirm(',
    ]

    def __init__(self):
        self.baseline = ResponseBaseline()

    async def verify_sql_injection(
        self,
        url: str,
        method: str,
        baseline_response: Dict,
        test_response: Dict,
        payload: str
    ) -> MultiDimensionalVerification:
        """多维度SQL注入验证"""
        evidence_chain = []

        content_check = self._check_content_difference(
            baseline_response.get('content', ''),
            test_response.get('content', ''),
            payload
        )
        evidence_chain.append(content_check)

        status_check = self._check_status_change(
            baseline_response.get('status_code'),
            test_response.get('status_code')
        )
        evidence_chain.append(status_check)

        time_check = self._check_response_time(test_response, payload)
        evidence_chain.append(time_check)

        error_keyword_check = self._check_error_keywords(
            test_response.get('content', ''),
            baseline_response.get('content', ''),
            payload
        )
        evidence_chain.append(error_keyword_check)

        score = self._calculate_score(evidence_chain)
        confidence = self._score_to_confidence(score)

        is_verified = confidence in [VerificationConfidence.HIGH, VerificationConfidence.MEDIUM]

        return MultiDimensionalVerification(
            vuln_type='sql_injection',
            url=url,
            param=payload,
            confidence=confidence,
            evidence_chain=evidence_chain,
            overall_score=score,
            is_verified=is_verified,
            recommendation=self._get_recommendation(confidence, 'sql_injection')
        )

    def _check_content_difference(
        self,
        baseline_content: str,
        test_content: str,
        payload: str
    ) -> VerificationEvidence:
        """内容维度检查"""
        if not baseline_content or not test_content:
            return VerificationEvidence(
                check_name='content_diff',
                passed=False,
                details='Empty content'
            )

        baseline_lower = baseline_content.lower()
        test_lower = test_content.lower()

        if payload.lower() in test_lower and payload.lower() not in baseline_lower:
            return VerificationEvidence(
                check_name='content_diff',
                passed=True,
                details='Payload reflected in response',
                baseline_value=baseline_content[:200],
                test_value=test_content[:200]
            )

        matcher = SequenceMatcher(None, baseline_lower, test_lower)
        similarity = matcher.ratio()
        diff_ratio = 1 - similarity

        if diff_ratio > 0.3:
            return VerificationEvidence(
                check_name='content_diff',
                passed=True,
                details=f'Content difference ratio: {diff_ratio:.2f}',
                baseline_value=baseline_content[:100],
                test_value=test_content[:100]
            )

        return VerificationEvidence(
            check_name='content_diff',
            passed=False,
            details=f'Content similarity: {similarity:.2f}'
        )

    def _check_status_change(
        self,
        baseline_status: int,
        test_status: int
    ) -> VerificationEvidence:
        """状态码维度检查"""
        if test_status != baseline_status:
            return VerificationEvidence(
                check_name='status_change',
                passed=True,
                details=f'Status changed: {baseline_status} -> {test_status}',
                baseline_value=str(baseline_status),
                test_value=str(test_status)
            )

        return VerificationEvidence(
            check_name='status_change',
            passed=False,
            details=f'Status unchanged: {baseline_status}'
        )

    def _check_response_time(
        self,
        response: Dict,
        payload: str
    ) -> VerificationEvidence:
        """时间维度检查（用于盲注）"""
        response_time = response.get('response_time', 0)

        if response_time > 5.0:
            return VerificationEvidence(
                check_name='response_time',
                passed=True,
                details=f'Slow response: {response_time:.2f}s',
                test_value=str(response_time)
            )

        return VerificationEvidence(
            check_name='response_time',
            passed=False,
            details=f'Reasonable response time: {response_time:.2f}s'
        )

    def _check_error_keywords(
        self,
        test_content: str,
        baseline_content: str,
        payload: str
    ) -> VerificationEvidence:
        """错误关键字维度检查"""
        baseline_lower = baseline_content.lower()
        test_lower = test_content.lower()

        matched_errors = []
        for keyword in self.SQLI_ERROR_KEYWORDS:
            if keyword in test_lower and keyword not in baseline_lower:
                matched_errors.append(keyword)

        if matched_errors:
            return VerificationEvidence(
                check_name='error_keywords',
                passed=True,
                details=f'Matched error keywords: {matched_errors[:3]}',
                test_value=', '.join(matched_errors[:3])
            )

        return VerificationEvidence(
            check_name='error_keywords',
            passed=False,
            details='No SQL error keywords found'
        )

    def _calculate_score(self, evidence_chain: List[VerificationEvidence]) -> float:
        """计算综合评分"""
        if not evidence_chain:
            return 0.0

        weights = {
            'content_diff': 0.3,
            'status_change': 0.2,
            'response_time': 0.2,
            'error_keywords': 0.3
        }

        total_score = 0.0
        total_weight = 0.0

        for evidence in evidence_chain:
            weight = weights.get(evidence.check_name, 0.25)
            if evidence.passed:
                total_score += weight
            total_weight += weight

        return total_score / total_weight if total_weight > 0 else 0.0

    def _score_to_confidence(self, score: float) -> VerificationConfidence:
        """评分转置信度"""
        if score >= 0.7:
            return VerificationConfidence.HIGH
        elif score >= 0.4:
            return VerificationConfidence.MEDIUM
        elif score >= 0.2:
            return VerificationConfidence.LOW
        else:
            return VerificationConfidence.FALSE_POSITIVE

    def _get_recommendation(self, confidence: VerificationConfidence, vuln_type: str) -> str:
        """获取建议"""
        if confidence == VerificationConfidence.HIGH:
            return f"{vuln_type} confirmed with high confidence"
        elif confidence == VerificationConfidence.MEDIUM:
            return f"{vuln_type} detected with medium confidence - manual verification recommended"
        elif confidence == VerificationConfidence.LOW:
            return f"Weak indicators of {vuln_type} - likely false positive"
        else:
            return f"Analysis inconclusive - treat as potential false positive"


class VerificationCache:
    """验证结果缓存"""

    def __init__(self):
        self._cache: Dict[str, MultiDimensionalVerification] = {}

    def get(self, key: str) -> Optional[MultiDimensionalVerification]:
        return self._cache.get(key)

    def set(self, key: str, result: MultiDimensionalVerification):
        self._cache[key] = result

    def clear(self):
        self._cache.clear()

    def get_statistics(self) -> Dict:
        confirmed = sum(
            1 for v in self._cache.values()
            if v.is_verified
        )
        return {
            'total': len(self._cache),
            'verified': confirmed,
            'false_positives': len(self._cache) - confirmed
        }
