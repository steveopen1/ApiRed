"""
Cloud Service Detector Module
国内云服务检测模块 - 检测国内主流云服务的未授权访问风险

支持:
- 阿里云: OSS/OTS/STS/SMS/Functions/API网关
- 腾讯云: COS/STS/SMS/CVM/CLS
- 华为云: OBS/SMS/FunctionGraph/APIGateway
- 百度智能云: BOS/SMS/FC
- 火山引擎: TOS/SMS/FC/APIGateway
- 京东云: OSS/SMS
- 七牛云: Kodo/SMS/Live
- 又拍云: USS
- 青云: QS
"""

import re
import asyncio
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum

from core.models import APIEndpoint, Vulnerability, Severity


class CloudProvider(Enum):
    """云服务商枚举"""
    ALIYUN = "aliyun"
    TENCENT = "tencent"
    HUAWEI = "huawei"
    BAIDU = "baidu"
    VOLCENGINE = "volcengine"
    JDCLOUD = "jdcloud"
    QINIU = "qiniu"
    UPYUN = "upyun"
    QINGCLOUD = "qingcloud"
    UNKNOWN = "unknown"


class CloudServiceType(Enum):
    """云服务类型枚举"""
    OSS = "oss"
    OTS = "ots"
    STS = "sts"
    SMS = "sms"
    FC = "fc"
    API_GATEWAY = "api_gateway"
    COS = "cos"
    CVM = "cvm"
    CLS = "cls"
    OBS = "obs"
    BOS = "bos"
    TOS = "tos"
    LIVE = "live"
    USS = "uss"
    QS = "qs"
    UNKNOWN = "unknown"


@dataclass
class CloudDetectionResult:
    """云服务检测结果"""
    api_id: str
    provider: CloudProvider
    service_type: CloudServiceType
    endpoint_url: str
    confidence: float
    indicators: List[str] = field(default_factory=list)
    region: Optional[str] = None
    bucket_name: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CloudUnauthorizedTestResult:
    """云服务未授权访问测试结果"""
    api_id: str
    provider: CloudProvider
    service_type: CloudServiceType
    test_name: str
    is_vulnerable: bool
    severity: Severity = Severity.HIGH
    evidence: str = ""
    remediation: str = ""


@dataclass
class CloudService:
    """云服务信息"""
    provider: CloudProvider
    service_type: CloudServiceType
    endpoint: str
    region: Optional[str] = None
    bucket_name: Optional[str] = None
    access_control: str = "unknown"


class CloudServiceDetector:
    """
    国内云服务检测器
    检测阿里云/腾讯云/华为云等国内云服务的未授权访问
    """
    
    CLOUD_DOMAIN_PATTERNS = {
        CloudProvider.ALIYUN: {
            CloudServiceType.OSS: [
                r'oss-[a-z0-9-]+\.aliyuncs\.com',
                r'[a-z0-9-]+\.oss-cn-[a-z0-9-]+\.aliyuncs\.com',
            ],
            CloudServiceType.OTS: [
                r'[a-z0-9-]+\.ots\.aliyuncs\.com',
            ],
            CloudServiceType.STS: [
                r'sts\.aliyuncs\.com',
            ],
            CloudServiceType.SMS: [
                r'dysms\.aliyuncs\.com',
            ],
            CloudServiceType.FC: [
                r'[a-z0-9-]+\.fc\.aliyuncs\.com',
                r'[a-z0-9-]+\.function.aliyuncs\.com',
            ],
            CloudServiceType.API_GATEWAY: [
                r'[a-z0-9-]+\.apigateway\.aliyuncs\.com',
            ],
        },
        CloudProvider.TENCENT: {
            CloudServiceType.COS: [
                r'[a-z0-9-]+-\d+\.cos\.[a-z0-9-]+\.myqcloud\.com',
                r'[a-z0-9-]+\.cos\.tencentcloudapi\.com',
            ],
            CloudServiceType.STS: [
                r'sts\.tencentcloudapi\.com',
            ],
            CloudServiceType.SMS: [
                r'sms\.tencentcloudapi\.com',
            ],
            CloudServiceType.CVM: [
                r'cvm\.tencentcloudapi\.com',
            ],
            CloudServiceType.CLS: [
                r'cls\.tencentcloudapi\.com',
            ],
        },
        CloudProvider.HUAWEI: {
            CloudServiceType.OBS: [
                r'[a-z0-9-]+\.obs\.hwclouds\.com',
                r'[a-z0-9-]+\.obs\.huaweicloud\.com',
            ],
            CloudServiceType.SMS: [
                r'sms\.hwclouds\.com',
            ],
            CloudServiceType.FC: [
                r'[a-z0-9-]+\.functiongraph\.hwclouds\.com',
            ],
            CloudServiceType.API_GATEWAY: [
                r'[a-z0-9-]+\.apigateway\.hwclouds\.com',
            ],
        },
        CloudProvider.BAIDU: {
            CloudServiceType.BOS: [
                r'[a-z0-9-]+\.bj\.bos\.baidubce\.com',
                r'[a-z0-9-]+\.gz\.bos\.baidubce\.com',
            ],
            CloudServiceType.SMS: [
                r'sms\.baidubce\.com',
            ],
            CloudServiceType.FC: [
                r'fcp\.baidubce\.com',
            ],
        },
        CloudProvider.VOLCENGINE: {
            CloudServiceType.TOS: [
                r'[a-z0-9-]+\.tos\.[a-z0-9-]+\.volcengineapi\.com',
            ],
            CloudServiceType.SMS: [
                r'sms\.volcengineapi\.com',
            ],
            CloudServiceType.FC: [
                r'[a-z0-9-]+\.live\.volcengineapi\.com',
            ],
            CloudServiceType.API_GATEWAY: [
                r'[a-z0-9-]+\.apigateway\.volcengineapi\.com',
            ],
        },
        CloudProvider.JDCLOUD: {
            CloudServiceType.OSS: [
                r'[a-z0-9-]+\.oss-cn-[a-z0-9-]+\.jdcloud-api\.com',
            ],
            CloudServiceType.SMS: [
                r'sms\.jdcloud-api\.com',
            ],
        },
        CloudProvider.QINIU: {
            CloudServiceType.OSS: [
                r'[a-z0-9-]+\.qiniu\.com',
                r'[a-z0-9-]+\.qiniucdn\.com',
            ],
            CloudServiceType.SMS: [
                r'sms\.qns\.ai',
            ],
            CloudServiceType.LIVE: [
                r'live\.qiniu\.com',
            ],
        },
        CloudProvider.UPYUN: {
            CloudServiceType.USS: [
                r'[a-z0-9-]+\.upcdn\.net',
                r'[a-z0-9-]+\.upai\.com',
            ],
        },
        CloudProvider.QINGCLOUD: {
            CloudServiceType.QS: [
                r'[a-z0-9-]+\.qingstor\.com',
            ],
        },
    }
    
    def __init__(self, http_client: Any = None):
        """
        初始化云服务检测器
        
        Args:
            http_client: HTTP客户端
        """
        self.http_client = http_client
    
    async def detect_cloud_services(self, endpoints: List[APIEndpoint]) -> List[CloudDetectionResult]:
        """
        检测端点中的云服务调用
        
        Args:
            endpoints: API端点列表
            
        Returns:
            List[CloudDetectionResult]: 检测结果列表
        """
        results = []
        
        for endpoint in endpoints:
            result = await self._detect_from_endpoint(endpoint)
            if result:
                results.extend(result)
        
        return results
    
    async def _detect_from_endpoint(self, endpoint: APIEndpoint) -> List[CloudDetectionResult]:
        """从端点检测云服务"""
        results = []
        url_lower = endpoint.full_url.lower()
        
        for provider, services in self.CLOUD_DOMAIN_PATTERNS.items():
            for service_type, patterns in services.items():
                for pattern in patterns:
                    if re.search(pattern, url_lower, re.IGNORECASE):
                        region = self._extract_region(url_lower, provider)
                        bucket = self._extract_bucket(url_lower, service_type)
                        
                        results.append(CloudDetectionResult(
                            api_id=endpoint.api_id,
                            provider=provider,
                            service_type=service_type,
                            endpoint_url=endpoint.full_url,
                            confidence=0.9,
                            indicators=[f'pattern_match:{pattern}'],
                            region=region,
                            bucket_name=bucket,
                            details={'pattern': pattern}
                        ))
        
        return results
    
    def _extract_region(self, url: str, provider: CloudProvider) -> Optional[str]:
        """提取区域信息"""
        region_patterns = {
            CloudProvider.ALIYUN: r'oss-cn-([a-z0-9-]+)',
            CloudProvider.TENCENT: r'cos\.([a-z0-9-]+)\.',
            CloudProvider.HUAWEI: r'obs\.([a-z0-9-]+)\.',
            CloudProvider.BAIDU: r'\.([a-z0-9]+)\.bos\.',
            CloudProvider.VOLCENGINE: r'tos\.([a-z0-9-]+)\.',
        }
        
        pattern = region_patterns.get(provider)
        if pattern:
            match = re.search(pattern, url)
            if match:
                return match.group(1) if match.lastindex else None
        
        return None
    
    def _extract_bucket(self, url: str, service_type: CloudServiceType) -> Optional[str]:
        """提取存储桶名称"""
        if service_type in [CloudServiceType.OSS, CloudServiceType.COS, 
                           CloudServiceType.OBS, CloudServiceType.BOS,
                           CloudServiceType.TOS, CloudServiceType.QS]:
            patterns = [
                r'([a-z0-9-]+)\.oss-',
                r'([a-z0-9-]+)-\d+\.cos',
                r'([a-z0-9-]+)\.obs\.',
                r'([a-z0-9-]+)\.bos\.',
                r'([a-z0-9-]+)\.tos\.',
                r'([a-z0-9-]+)\.qingstor\.',
            ]
            for pattern in patterns:
                match = re.search(pattern, url)
                if match:
                    return match.group(1)
        
        return None
    
    async def detect_from_responses(self, responses: List[Dict]) -> List[CloudDetectionResult]:
        """
        从HTTP响应中检测云服务信息
        
        Args:
            responses: HTTP响应列表
            
        Returns:
            List[CloudDetectionResult]: 检测结果列表
        """
        results = []
        
        cloud_header_patterns = {
            CloudProvider.ALIYUN: [
                (r'x-oss-', CloudServiceType.OSS),
                (r'aliyun-', CloudServiceType.OSS),
            ],
            CloudProvider.TENCENT: [
                (r'x-cos-', CloudServiceType.COS),
                (r'tencent-', CloudServiceType.COS),
            ],
            CloudProvider.HUAWEI: [
                (r'hw-', CloudServiceType.OBS),
                (r'hwclouds-', CloudServiceType.OBS),
            ],
        }
        
        for resp in responses:
            headers = resp.get('headers', {})
            content = resp.get('content', '')
            
            for provider, patterns in cloud_header_patterns.items():
                for header_pattern, service_type in patterns:
                    if any(header_pattern in k.lower() for k in headers.keys()):
                        results.append(CloudDetectionResult(
                            api_id=resp.get('api_id', ''),
                            provider=provider,
                            service_type=service_type,
                            endpoint_url=resp.get('url', ''),
                            confidence=0.8,
                            indicators=[f'header_match:{header_pattern}']
                        ))
            
            content_lower = content.lower() if isinstance(content, str) else str(content)
            if 'aliyun' in content_lower or 'aliyuncs' in content_lower:
                results.append(CloudDetectionResult(
                    api_id=resp.get('api_id', ''),
                    provider=CloudProvider.ALIYUN,
                    service_type=CloudServiceType.OSS,
                    endpoint_url=resp.get('url', ''),
                    confidence=0.6,
                    indicators=['content_keyword:aliyun']
                ))
        
        return results
    
    async def test_unauthorized_access(self, service: CloudService) -> List[CloudUnauthorizedTestResult]:
        """
        测试云服务未授权访问
        
        Args:
            service: 云服务实例
            
        Returns:
            List[CloudUnauthorizedTestResult]: 测试结果列表
        """
        results = []
        
        if service.service_type in [CloudServiceType.OSS, CloudServiceType.COS, 
                                   CloudServiceType.OBS, CloudServiceType.BOS,
                                   CloudServiceType.TOS, CloudServiceType.QS]:
            results.append(await self._test_object_storage_public(service))
        
        if service.service_type == CloudServiceType.SMS:
            results.append(await self._test_sms_overflow(service))
        
        return results
    
    async def _test_object_storage_public(self, service: CloudService) -> CloudUnauthorizedTestResult:
        """测试对象存储公开访问"""
        if not self.http_client:
            return CloudUnauthorizedTestResult(
                api_id='',
                provider=service.provider,
                service_type=service.service_type,
                test_name='Object Storage Public Access',
                is_vulnerable=False,
                severity=Severity.MEDIUM
            )
        
        test_urls = [
            f"https://{service.bucket_name or 'test'}.oss-xxx.aliyuncs.com",
            f"https://{service.bucket_name or 'test'}.cos.xxx.myqcloud.com",
        ]
        
        for test_url in test_urls:
            try:
                response = await self.http_client.request(test_url, method='GET')
                if response.status_code == 200:
                    content_sample = response.content[:500] if response.content else ''
                    return CloudUnauthorizedTestResult(
                        api_id='',
                        provider=service.provider,
                        service_type=service.service_type,
                        test_name='Object Storage Public Access',
                        is_vulnerable=True,
                        severity=Severity.CRITICAL,
                        evidence=f'Status: {response.status_code}, Content: {content_sample[:100]}',
                        remediation='设置对象存储访问权限,启用Bucket Policy'
                    )
            except Exception:
                pass
        
        return CloudUnauthorizedTestResult(
            api_id='',
            provider=service.provider,
            service_type=service.service_type,
            test_name='Object Storage Public Access',
            is_vulnerable=False,
            severity=Severity.MEDIUM
        )
    
    async def _test_sms_overflow(self, service: CloudService) -> CloudUnauthorizedTestResult:
        """测试短信服务溢出"""
        return CloudUnauthorizedTestResult(
            api_id='',
            provider=service.provider,
            service_type=CloudServiceType.SMS,
            test_name='SMS Service Overflow',
            is_vulnerable=False,
            severity=Severity.MEDIUM
        )
    
    def get_provider_name(self, provider: CloudProvider) -> str:
        """获取云服务商名称"""
        names = {
            CloudProvider.ALIYUN: '阿里云',
            CloudProvider.TENCENT: '腾讯云',
            CloudProvider.HUAWEI: '华为云',
            CloudProvider.BAIDU: '百度智能云',
            CloudProvider.VOLCENGINE: '火山引擎',
            CloudProvider.JDCLOUD: '京东云',
            CloudProvider.QINIU: '七牛云',
            CloudProvider.UPYUN: '又拍云',
            CloudProvider.QINGCLOUD: '青云',
            CloudProvider.UNKNOWN: '未知',
        }
        return names.get(provider, '未知')
    
    def get_service_name(self, service_type: CloudServiceType) -> str:
        """获取服务类型名称"""
        names = {
            CloudServiceType.OSS: '对象存储',
            CloudServiceType.OTS: '表格存储',
            CloudServiceType.STS: '安全令牌服务',
            CloudServiceType.SMS: '短信服务',
            CloudServiceType.FC: '函数计算',
            CloudServiceType.API_GATEWAY: 'API网关',
            CloudServiceType.COS: '对象存储',
            CloudServiceType.CVM: '云服务器',
            CloudServiceType.CLS: '日志服务',
            CloudServiceType.OBS: '对象存储',
            CloudServiceType.BOS: '对象存储',
            CloudServiceType.TOS: '对象存储',
            CloudServiceType.LIVE: '直播服务',
            CloudServiceType.USS: '融合CDN',
            CloudServiceType.QS: '对象存储',
            CloudServiceType.UNKNOWN: '未知',
        }
        return names.get(service_type, '未知')
