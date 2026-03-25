#!/usr/bin/env python3
"""
云安全检测模块 - 基于 FLUX v5.2.1
检测云存储桶、密钥泄露、云服务配置等
"""

import re
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


@dataclass
class CloudVulnResult:
    """云安全漏洞结果"""
    vuln_type: str
    severity: str
    url: str
    param: str = ""
    payload: str = ""
    detail: str = ""
    evidence: str = ""
    remediation: str = ""


class CloudBucketTester:
    """云存储桶安全测试器"""

    BUCKET_CONFIGS = {
        "阿里云OSS": {
            "domains": [".oss-cn", ".oss-ap", ".oss-us", ".aliyuncs.com"],
            "list_indicator": "<ListBucketResult",
            "severity": "High"
        },
        "腾讯云COS": {
            "domains": [".cos.ap", ".cos.na", ".myqcloud.com"],
            "list_indicator": "<ListBucketResult",
            "severity": "High"
        },
        "AWS S3": {
            "domains": [".s3.amazonaws.com", ".s3-", ".amazonaws.com"],
            "list_indicator": "<ListBucketResult",
            "severity": "High"
        },
        "华为云OBS": {
            "domains": [".obs.cn", ".obs.ap", ".myhuaweicloud.com"],
            "list_indicator": "<ListBucketResult",
            "severity": "High"
        },
    }

    def __init__(self, session=None, timeout: int = 10):
        self.session = session
        self.timeout = timeout
        self.findings: List[CloudVulnResult] = []

    def detect_bucket_provider(self, url: str) -> Optional[Tuple[str, Dict]]:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        for provider, config in self.BUCKET_CONFIGS.items():
            for domain in config.get("domains", []):
                if domain in hostname:
                    return provider, config
        return None

    def test_bucket_access(self, url: str) -> List[CloudVulnResult]:
        findings = []
        provider_info = self.detect_bucket_provider(url)

        if not provider_info:
            return findings

        provider, config = provider_info
        list_url = f"{url.rstrip('/')}/?list-type=2"

        try:
            response = self.session.get(list_url, timeout=self.timeout, verify=False)
            content = response.text

            if config.get("list_indicator") in content:
                logger.info(f"[+] 发现可遍历存储桶: {provider} at {url}")
                findings.append(CloudVulnResult(
                    vuln_type="存储桶可遍历",
                    severity=config.get("severity", "High"),
                    url=url,
                    detail=f"{provider} 存储桶允许未授权列举"
                ))
        except:
            pass

        return findings

    def test_bucket_acl(self, url: str) -> List[CloudVulnResult]:
        findings = []
        provider_info = self.detect_bucket_provider(url)

        if not provider_info:
            return findings

        provider, config = provider_info
        acl_url = f"{url.rstrip('/')}/?acl"

        try:
            response = self.session.get(acl_url, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                findings.append(CloudVulnResult(
                    vuln_type="存储桶ACL可读",
                    severity="Medium",
                    url=acl_url,
                    detail=f"{provider} 存储桶ACL策略可读"
                ))
        except:
            pass

        return findings


class CloudSecretScanner:
    """云密钥泄露检测"""

    CLOUD_KEY_PATTERNS = {
        "AWS Access Key": {
            "pattern": r'AKIA[0-9A-Z]{16}',
            "provider": "AWS",
            "severity": "Critical"
        },
        "阿里云 AccessKey": {
            "pattern": r'LTAI[a-zA-Z0-9]{12,20}',
            "provider": "阿里云",
            "severity": "Critical"
        },
        "腾讯云 SecretId": {
            "pattern": r'AKID[a-zA-Z0-9]{32,40}',
            "provider": "腾讯云",
            "severity": "Critical"
        },
        "华为云 Key": {
            "pattern": r'HW[a-zA-Z0-9]{24,32}',
            "provider": "华为云",
            "severity": "Critical"
        },
    }

    def __init__(self):
        self.findings: List[CloudVulnResult] = []

    def scan_for_cloud_keys(self, content: str, source: str = "") -> List[CloudVulnResult]:
        findings = []

        for key_name, key_info in self.CLOUD_KEY_PATTERNS.items():
            pattern = key_info["pattern"]
            matches = re.findall(pattern, content)
            
            for match in matches[:5]:
                logger.info(f"[+] 发现云密钥: {key_name} in {source}")
                findings.append(CloudVulnResult(
                    vuln_type="云密钥泄露",
                    severity=key_info["severity"],
                    url=source,
                    detail=f"发现{key_info['provider']} {key_name}",
                    evidence=f"密钥前8位: {match[:8]}***"
                ))

        return findings


__all__ = ['CloudBucketTester', 'CloudSecretScanner', 'CloudVulnResult']
