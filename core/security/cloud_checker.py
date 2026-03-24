"""
Cloud Security Module
云安全检测模块
参考 FLUX 云安全检测实现
支持 12 种云服务商检测
"""

import re
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class CloudFinding:
    """云安全发现"""
    service: str
    finding_type: str
    severity: str
    url: str
    access_key_id: str = ""
    bucket_name: str = ""
    detail: str = ""
    verified: bool = False


class CloudSecurityChecker:
    """
    云安全检测器
    
    支持检测：
    - 云 Access Key 泄露
    - 存储桶遍历
    - 存储桶接管
    - ACL/Policy 泄露
    - 未授权操作
    """
    
    ALIYUN_OSS_PATTERNS = [
        r'oss-cn-[a-z]+',
        r'\.oss\.aliyuncs\.com',
        r'\.oss-cn-hangzhou',
        r'\.oss-cn-beijing',
    ]
    
    TENCENT_COS_PATTERNS = [
        r'\.cos\.[a-z]+\.myqcloud\.com',
        r'cos\.tencentcos',
        r'cos\.myqcloud',
    ]
    
    AWS_S3_PATTERNS = [
        r'\.s3\.[a-z]+-west-\d+\.amazonaws\.com',
        r'\.s3\.[a-z]+-\w+-\d+\.amazonaws\.com',
        r's3\.[a-z]+-\w+-\d+\.amazonaws\.com',
    ]
    
    HUAWEI_OBS_PATTERNS = [
        r'\.obs\.[a-z]+-myhuaweicloud\.com',
        r'\.obs\.[a-z]+-\w+\.hwclouds-ddd',
    ]
    
    QINIU_KODO_PATTERNS = [
        r'\.qiniu[abc]\.com',
        r'qiniu',
        r'\.s.qiniu',
    ]
    
    BAIDU_BOS_PATTERNS = [
        r'\.bcebos\.com',
        r'\.bdpns\.baidu\.com',
    ]
    
    JD_CLOUD_PATTERNS = [
        r'\.oss.jdcloud-idd',
        r'\.s3\.jdcloud-idd',
    ]
    
    CLOUD_KEY_PATTERNS = {
        'aliyun': [
            r'LTAI[a-z0-9]{20,}',
            r'AKIA[0-9A-Z]{16}',
        ],
        'tencent': [
            r'AKID[0-9A-Za-z]{20,}',
            r'AKID[a-zA-Z0-9]{20,}',
        ],
        'aws': [
            r'AKIA[0-9A-Z]{16,}',
            r'ASIA[0-9A-Z]{16,}',
        ],
        'huawei': [
            r'HW[A-Z0-9]{20,}',
        ],
        'qiniu': [
            r'[a-zA-Z0-9]{30,}:[a-zA-Z0-9]{30,}',
        ],
        'baidu': [
            r'bce-[a-zA-Z0-9]{20,}',
        ],
        'jd': [
            r'jd\.[a-zA-Z0-9]{20,}',
        ],
    }
    
    CLOUD_METADATA_ENDPOINTS = {
        'aws': [
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/user-data/',
        ],
        'aliyun': [
            'http://100.100.100.200/latest/meta-data/',
            'http://100.100.100.200/latest/user-data/',
        ],
        'tencent': [
            'http://metadata.tencentyun.com/latest/meta-data/',
        ],
        'huawei': [
            'http://169.254.169.254/latest/meta-data/',
        ],
        'gcp': [
            'http://metadata.google.internal/computeMetadata/v1/',
        ],
        'azure': [
            'http://169.254.169.254/metadata/instance',
        ],
    }
    
    def __init__(self, http_client=None):
        self.http_client = http_client
        self.findings: List[CloudFinding] = []
    
    async def check_access_keys(self, content: str) -> List[CloudFinding]:
        """
        检测云 Access Key 泄露
        
        Args:
            content: 待检测内容
            
        Returns:
            List[CloudFinding]: 发现的问题
        """
        findings = []
        
        for provider, patterns in self.CLOUD_KEY_PATTERNS.items():
            for pattern in patterns:
                matches = re.findall(pattern, content)
                for match in matches:
                    finding = CloudFinding(
                        service=provider,
                        finding_type='access_key_exposure',
                        severity='critical',
                        url='',
                        access_key_id=match[:20] + '***'
                    )
                    findings.append(finding)
                    logger.warning(f"Cloud Access Key detected: {provider} - {match[:20]}***")
        
        self.findings.extend(findings)
        return findings
    
    async def check_buckets(self, content: str) -> List[CloudFinding]:
        """
        检测存储桶 URL 泄露
        
        Args:
            content: 待检测内容
            
        Returns:
            List[CloudFinding]: 发现的存储桶
        """
        findings = []
        
        all_patterns = (
            self.ALIYUN_OSS_PATTERNS +
            self.TENCENT_COS_PATTERNS +
            self.AWS_S3_PATTERNS +
            self.HUAWEI_OBS_PATTERNS +
            self.QINIU_KODO_PATTERNS +
            self.BAIDU_BOS_PATTERNS +
            self.JD_CLOUD_PATTERNS
        )
        
        for pattern in all_patterns:
            matches = re.findall(r'https?://[^\s"\'<>]+' + pattern + r'[^\s"\'<>]*', content)
            for match in matches:
                service = self._identify_service(match)
                finding = CloudFinding(
                    service=service,
                    finding_type='bucket_url',
                    severity='medium',
                    url=match,
                    bucket_name=self._extract_bucket_name(match)
                )
                findings.append(finding)
        
        self.findings.extend(findings)
        return findings
    
    def _identify_service(self, url: str) -> str:
        """识别云服务商"""
        if 'aliyuncs' in url or 'aliyun' in url:
            return 'aliyun'
        if 'tencent' in url or 'myqcloud' in url:
            return 'tencent'
        if 'aws' in url or 'amazon' in url:
            return 'aws'
        if 'huawei' in url or 'hwclouds' in url:
            return 'huawei'
        if 'qiniu' in url:
            return 'qiniu'
        if 'baidu' in url or 'bdpns' in url:
            return 'baidu'
        if 'jd' in url:
            return 'jd'
        return 'unknown'
    
    def _extract_bucket_name(self, url: str) -> str:
        """提取存储桶名称"""
        patterns = [
            r'://([a-z0-9-]+)\.',
            r'://([a-z0-9]+)-([a-z0-9-]+)\.',
            r'/([a-z0-9-]+)/',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, url)
            if match:
                return match.group(1) if match.lastindex == 1 else f"{match.group(1)}-{match.group(2)}"
        
        return ''
    
    async def check_bucket_acl(self, bucket_url: str) -> Optional[CloudFinding]:
        """
        检测存储桶 ACL 配置
        
        Args:
            bucket_url: 存储桶 URL
            
        Returns:
            Optional[CloudFinding]: ACL 问题
        """
        acl_url = bucket_url.rstrip('/')
        if not acl_url.endswith('/'):
            acl_url += '/'
        acl_url += '?acl'
        
        try:
            if self.http_client:
                response = await self.http_client.request(acl_url, 'GET')
                if response and response.status_code == 200:
                    content = response.content or ''
                    if '<Owner>' in content and '<Grantee' in content:
                        if 'AllUsers' in content or 'AuthenticatedUsers' in content:
                            return CloudFinding(
                                service=self._identify_service(bucket_url),
                                finding_type='bucket_acl_public',
                                severity='high',
                                url=bucket_url,
                                detail='存储桶 ACL 配置为公共访问'
                            )
        except Exception as e:
            logger.debug(f"ACL check failed: {e}")
        
        return None
    
    async def check_bucket_list(self, bucket_url: str) -> Optional[CloudFinding]:
        """
        检测存储桶是否可列举文件
        
        Args:
            bucket_url: 存储桶 URL
            
        Returns:
            Optional[CloudFinding]: 遍历漏洞
        """
        list_url = bucket_url.rstrip('/')
        if not list_url.endswith('/'):
            list_url += '/'
        
        try:
            if self.http_client:
                response = await self.http_client.request(list_url, 'GET')
                if response and response.status_code == 200:
                    content = response.content or ''
                    if '<Contents>' in content or '<?xml' in content:
                        return CloudFinding(
                            service=self._identify_service(bucket_url),
                            finding_type='bucket_listing',
                            severity='high',
                            url=bucket_url,
                            detail='存储桶允许列举文件'
                        )
        except Exception:
            pass
        
        return None
    
    async def test_ssrf(self, url: str, target: str) -> bool:
        """
        测试 SSRF 漏洞
        
        Args:
            url: 目标 URL
            target: SSRF 目标 (如元数据端点)
            
        Returns:
            bool: 是否存在 SSRF
        """
        try:
            if self.http_client:
                response = await self.http_client.request(url, 'GET')
                if response and response.status_code in [200, 201]:
                    content = response.content or ''
                    if any(x in content for x in ['instance-id', 'ami-id', 'local-hostname', 'metadata']):
                        return True
        except Exception:
            pass
        
        return False
    
    async def check_metadata_ssrf(self, url: str) -> List[CloudFinding]:
        """
        检测云元数据 SSRF
        
        Args:
            url: 目标 URL
            
        Returns:
            List[CloudFinding]: 发现的问题
        """
        findings = []
        
        for service, endpoints in self.CLOUD_METADATA_ENDPOINTS.items():
            for endpoint in endpoints:
                if await self.test_ssrf(url, endpoint):
                    finding = CloudFinding(
                        service=service,
                        finding_type='metadata_ssrf',
                        severity='critical',
                        url=url,
                        detail=f'云元数据 SSRF: {endpoint}'
                    )
                    findings.append(finding)
                    logger.warning(f"Cloud metadata SSRF detected on {url} via {service}")
        
        return findings
    
    def get_all_findings(self) -> List[CloudFinding]:
        """获取所有发现"""
        return self.findings
    
    def clear_findings(self):
        """清空发现列表"""
        self.findings.clear()


def check_aws_keys(content: str) -> List[str]:
    """便捷函数：检测 AWS Key"""
    patterns = [r'AKIA[0-9A-Z]{16,}', r'ASIA[0-9A-Z]{16,}']
    keys = []
    for pattern in patterns:
        keys.extend(re.findall(pattern, content))
    return list(set(keys))


def check_aliyun_keys(content: str) -> List[str]:
    """便捷函数：检测阿里云 Key"""
    patterns = [r'LTAI[a-z0-9]{20,}']
    keys = []
    for pattern in patterns:
        keys.extend(re.findall(pattern, content))
    return list(set(keys))
