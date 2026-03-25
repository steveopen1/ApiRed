#!/usr/bin/env python3
"""
差分测试机制 - 基于 FLUX v5.2.1
通过对比基准响应和Payload响应的差异来降低误报率
"""

import hashlib
import logging
import re
from typing import Dict, List, Optional, Tuple, Callable
from dataclasses import dataclass
from urllib.parse import urlparse, parse_qs, urlencode

logger = logging.getLogger(__name__)


@dataclass
class BaselineResponse:
    """基准响应"""
    url: str
    method: str
    status_code: int
    content_length: int
    content_hash: str
    content_type: str
    response_time: float
    headers: Dict[str, str]
    body_snippet: str = ""
    forms: List[Dict] = None

    def __post_init__(self):
        if self.forms is None:
            self.forms = []


@dataclass
class DifferentialResult:
    """差分测试结果"""
    url: str
    method: str
    param: str
    payload: str
    baseline: BaselineResponse
    payload_response: 'Response'
    diff_score: float
    is_vulnerable: bool
    evidence: str
    confidence: float
    details: Dict = None

    def __post_init__(self):
        if self.details is None:
            self.details = {}


class DifferentialTester:
    """差分测试器"""

    DIFF_THRESHOLDS = {
        'sql_injection': 0.4,
        'xss': 0.3,
        'lfi': 0.5,
        'rce': 0.6,
        'ssrf': 0.5,
        'idor': 0.35,
    }

    ERROR_INDICATORS = {
        'sql': [
            r'mysql', r'syntax error', r'ORA-', r'postgresql',
            r'microsoft sql', r'sqlsrv', r'odbc', r'sqlite',
            r'warning.*mysql', r' mariadb', r'sql syntax',
            r'unclosed quotation', r'missing operator',
        ],
        'xss': [
            r'<script', r'alert(', r'javascript:', r'onerror=',
            r'onload=', r'eval(', r'document\.cookie',
        ],
        'lfi': [
            r'root:', r'bin/bash', r'/etc/passwd',
            r'thumbnail', r'layout:', r'base64',
        ],
        'rce': [
            r'uid=', r'gid=', r'user=', r'groups=',
            r'root:x', r'windows',
        ],
        'ssrf': [
            r'ami-', r'instance-id', r'aws-access',
            r'metadata\.aliyun', r'169.254',
        ],
    }

    def __init__(self, session=None, threshold: float = 0.4):
        self.session = session
        self.baselines: Dict[str, BaselineResponse] = {}
        self.threshold = threshold
        self.baseline_cache: Dict[str, Dict] = {}

    def establish_baseline(self, url: str, method: str = "GET",
                         params: Dict = None, headers: Dict = None) -> Optional[BaselineResponse]:
        if params is None:
            params = {}
        if headers is None:
            headers = {}

        cache_key = f"{method}:{url}:{str(params)}"

        if cache_key in self.baselines:
            return self.baselines[cache_key]

        try:
            if method.upper() == "GET":
                response = self.session.get(url, params=params, headers=headers, timeout=10, verify=False)
            else:
                response = self.session.request(method, url, data=params, headers=headers, timeout=10, verify=False)

            baseline = self._create_baseline(url, method, response, params)
            self.baselines[cache_key] = baseline
            return baseline

        except Exception as e:
            logger.debug(f"建立基准响应失败: {e}")
            return None

    def test_payload(self, url: str, method: str, param: str,
                    original_value: str, payload: str,
                    baseline: BaselineResponse,
                    vuln_type: str = 'sql') -> DifferentialResult:
        try:
            params = {param: original_value}
            test_params = {param: payload}

            if method.upper() == "GET":
                response = self.session.get(url, params=test_params, timeout=10, verify=False)
            else:
                response = self.session.post(url, data=test_params, timeout=10, verify=False)

            diff_score = self._calculate_diff(baseline, response)

            threshold = self.DIFF_THRESHOLDS.get(vuln_type, self.threshold)
            is_vulnerable = diff_score >= threshold

            error_indicators = self.ERROR_INDICATORS.get(vuln_type, [])
            evidence = self._find_evidence(response, error_indicators)

            confidence = self._calculate_confidence(diff_score, is_vulnerable, evidence)

            return DifferentialResult(
                url=url,
                method=method,
                param=param,
                payload=payload,
                baseline=baseline,
                payload_response=response,
                diff_score=diff_score,
                is_vulnerable=is_vulnerable,
                evidence=evidence,
                confidence=confidence,
                details={
                    'baseline_status': baseline.status_code,
                    'payload_status': response.status_code,
                    'baseline_length': baseline.content_length,
                    'payload_length': len(response.content) if response.content else 0,
                }
            )

        except Exception as e:
            logger.debug(f"Payload测试失败: {e}")
            return DifferentialResult(
                url=url,
                method=method,
                param=param,
                payload=payload,
                baseline=baseline,
                payload_response=None,
                diff_score=0.0,
                is_vulnerable=False,
                evidence="",
                confidence=0.0,
                details={'error': str(e)}
            )

    def _create_baseline(self, url: str, method: str, response, params: Dict) -> BaselineResponse:
        content = response.content if response.content else b''
        content_hash = hashlib.md5(content).hexdigest()

        try:
            body_text = response.text[:500]
        except:
            body_text = str(content[:500])

        baseline = BaselineResponse(
            url=url,
            method=method,
            status_code=response.status_code,
            content_length=len(content),
            content_hash=content_hash,
            content_type=response.headers.get('Content-Type', ''),
            response_time=response.elapsed.total_seconds() if hasattr(response, 'elapsed') else 0,
            headers=dict(response.headers),
            body_snippet=body_text,
            forms=self._extract_forms(response.text if hasattr(response, 'text') else '')
        )

        self.baseline_cache[f"{method}:{url}"] = {
            'status_code': baseline.status_code,
            'content_length': baseline.content_length,
            'content_hash': baseline.content_hash,
        }

        return baseline

    def _calculate_diff(self, baseline: BaselineResponse, payload_response) -> float:
        if payload_response is None:
            return 0.0

        diff_score = 0.0

        if baseline.status_code != payload_response.status_code:
            diff_score += 0.3

        baseline_len = baseline.content_length
        payload_len = len(payload_response.content) if payload_response.content else 0

        if baseline_len > 0:
            length_ratio = abs(payload_len - baseline_len) / baseline_len
            if length_ratio > 0.5:
                diff_score += 0.2

        payload_hash = hashlib.md5(payload_response.content).hexdigest()
        if baseline.content_hash != payload_hash:
            diff_score += 0.4

        payload_content_type = payload_response.headers.get('Content-Type', '')
        if baseline.content_type != payload_content_type:
            diff_score += 0.1

        return min(diff_score, 1.0)

    def _find_evidence(self, response, error_indicators: List[str]) -> str:
        if response is None:
            return ""

        try:
            body = response.text.lower()
        except:
            body = str(response.content).lower()

        for pattern in error_indicators:
            if re.search(pattern, body, re.IGNORECASE):
                match = re.search(r'.{0,50}' + pattern + r'.{0,50}', body, re.IGNORECASE)
                if match:
                    return match.group(0)[:100]

        return ""

    def _calculate_confidence(self, diff_score: float, is_vulnerable: bool, evidence: str) -> float:
        confidence = 0.5

        if is_vulnerable:
            confidence += 0.2

        if diff_score > 0.5:
            confidence += 0.15

        if evidence:
            confidence += 0.15

        if diff_score > 0.7:
            confidence += 0.1

        return min(confidence, 1.0)

    def _extract_forms(self, html: str) -> List[Dict]:
        forms = []
        try:
            form_pattern = r'<form[^>]*>(.*?)</form>'
            for form_match in re.finditer(form_pattern, html, re.DOTALL | re.IGNORECASE):
                form_content = form_match.group(0)
                action_match = re.search(r'action=["\']([^"\']*)["\']', form_content, re.IGNORECASE)
                method_match = re.search(r'method=["\']([^"\']*)["\']', form_content, re.IGNORECASE)
                forms.append({
                    'action': action_match.group(1) if action_match else '',
                    'method': method_match.group(1) if method_match else 'get',
                })
        except Exception:
            pass
        return forms

    def batch_test(self, url: str, method: str, param: str,
                  original_value: str, payloads: List[str],
                  vuln_type: str = 'sql') -> List[DifferentialResult]:
        baseline = self.establish_baseline(url, method, {param: original_value})
        if not baseline:
            return []

        results = []
        for payload in payloads:
            result = self.test_payload(url, method, param, original_value, payload, baseline, vuln_type)
            results.append(result)

        return results

    def get_baseline(self, url: str, method: str = "GET") -> Optional[BaselineResponse]:
        for key, baseline in self.baselines.items():
            if key.startswith(f"{method}:{url}"):
                return baseline
        return None

    def clear_baselines(self):
        self.baselines.clear()
        self.baseline_cache.clear()


__all__ = ['DifferentialTester', 'DifferentialResult', 'BaselineResponse']
