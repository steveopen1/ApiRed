"""
OSS Collector Module
全链路 OSS 存储桶采集器
在扫描的各个阶段自动发现和收集 OSS URL
"""

import re
import logging
from typing import List, Dict, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class CloudProvider(Enum):
    """云服务商"""
    ALIYUN = "aliyun"
    TENCENT = "tencent"
    HUAWEI = "huawei"
    AWS = "aws"
    UNKNOWN = "unknown"


@dataclass
class OSSEndpoint:
    """OSS 存储桶端点"""
    url: str
    bucket: str
    region: str
    provider: CloudProvider
    full_url: str
    source: str = ""
    confidence: float = 0.8

    def __str__(self):
        return f"[{self.provider.value}] {self.bucket} ({self.region}) - {self.full_url}"


@dataclass
class OSSCollectorResults:
    """OSS 采集结果"""
    oss_urls: List[OSSEndpoint] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)

    def add(self, endpoint: OSSEndpoint, source: str, method: str = ""):
        """添加一个 OSS 发现"""
        self.oss_urls.append(endpoint)
        self.findings.append({
            "endpoint": endpoint,
            "source": source,
            "method": method,
            "timestamp": None
        })

    def get_unique_buckets(self) -> Set[str]:
        """获取去重后的 bucket 列表"""
        return set(ep.bucket for ep in self.oss_urls)

    def get_by_provider(self, provider: CloudProvider) -> List[OSSEndpoint]:
        """按云服务商筛选"""
        return [ep for ep in self.oss_urls if ep.provider == provider]


class OSSCollector:
    """
    全链路 OSS 采集器

    在扫描的各个阶段被触发，自动从各种来源发现 OSS 存储桶 URL：
    - JS 文件内容
    - HTML 内容
    - API 响应
    - 错误信息
    - 配置信息
    - 环境变量
    """

    ALIYUN_PATTERNS = [
        re.compile(r'(https?://)?([a-zA-Z0-9\-\_]+)\.oss\-([a-zA-Z0-9\-]+)\.aliyuncs\.com', re.I),
        re.compile(r'(https?://)?([a-zA-Z0-9\-\_]+)\.oss\.aliyuncs\.com', re.I),
        re.compile(r'oss://([a-zA-Z0-9\-\_]+)/?', re.I),
    ]

    TENCENT_PATTERNS = [
        re.compile(r'(https?://)?([a-zA-Z0-9\-\_]+)\.cos\.([a-zA-Z0-9\-]+)\.myqcloud\.com', re.I),
        re.compile(r'(https?://)?([a-zA-Z0-9\-\_]+)\.cos\.myqcloud\.com', re.I),
        re.compile(r'cos://([a-zA-Z0-9\-\_]+)/?', re.I),
    ]

    HUAWEI_PATTERNS = [
        re.compile(r'(https?://)?([a-zA-Z0-9\-\_]+)\.obs\-([a-zA-Z0-9\-]+)\.myhuaweicloud\.com', re.I),
        re.compile(r'(https?://)?([a-zA-Z0-9\-\_]+)\.obs\.myhuaweicloud\.com', re.I),
        re.compile(r'obs://([a-zA-Z0-9\-\_]+)/?', re.I),
    ]

    AWS_PATTERNS = [
        re.compile(r'(https?://)?([a-zA-Z0-9\-\_]+)\.s3\-([a-zA-Z0-9\-]+)\.amazonaws\.com', re.I),
        re.compile(r'(https?://)?([a-zA-Z0-9\-\_]+)\.s3\.amazonaws\.com', re.I),
        re.compile(r'(https?://)?s3\-([a-zA-Z0-9\-]+)\.amazonaws\.com/([a-zA-Z0-9\-\_]+)', re.I),
        re.compile(r's3://([a-zA-Z0-9\-\_]+)/?', re.I),
    ]

    SENSITIVE_PATTERNS = [
        r'aliyun.*secret',
        r'access.?key',
        r'oss.*password',
        r'bucket.*key',
        r'cos.*secret',
        r'cos.*password',
        r's3.*secret',
        r's3.*key',
        r'obs.*secret',
        r'obs.*password',
    ]

    def __init__(self):
        self.results = OSSCollectorResults()
        self._processed_urls: Set[str] = set()

    def reset(self):
        """重置采集器状态"""
        self.results = OSSCollectorResults()
        self._processed_urls.clear()

    def collect(self, source: str, content: Any, method: str = "") -> List[OSSEndpoint]:
        """
        从任意来源收集 OSS URL

        Args:
            source: 来源标识 (js, html, response, config, env, etc.)
            content: 内容 (str, dict, Response object, etc.)
            method: 相关方法 (GET, POST, etc.)

        Returns:
            新发现的 OSS 端点列表
        """
        new_endpoints = []

        if isinstance(content, str):
            endpoints = self._extract_from_text(content)
        elif isinstance(content, dict):
            endpoints = self._extract_from_dict(content)
        elif hasattr(content, 'text'):
            endpoints = self._extract_from_text(getattr(content, 'text', ''))
            if hasattr(content, 'url'):
                endpoints.extend(self._extract_from_text(getattr(content, 'url', '')))
        elif isinstance(content, (list, tuple)):
            endpoints = []
            for item in content:
                endpoints.extend(self.collect(source, item, method))
            return endpoints
        else:
            endpoints = []

        for endpoint in endpoints:
            if self._is_new_endpoint(endpoint):
                self.results.add(endpoint, source, method)
                new_endpoints.append(endpoint)
                logger.debug(f"[OSS] Found {endpoint.provider.value} bucket: {endpoint.bucket} from {source}")

        return new_endpoints

    def _is_new_endpoint(self, endpoint: OSSEndpoint) -> bool:
        """检查是否是新的端点"""
        key = f"{endpoint.provider.value}:{endpoint.bucket}:{endpoint.region}"
        if key in self._processed_urls:
            return False
        self._processed_urls.add(key)
        return True

    def _extract_from_text(self, text: str) -> List[OSSEndpoint]:
        """从文本内容提取 OSS URL"""
        if not text:
            return []

        endpoints = []

        endpoints.extend(self._extract_aliyun(text))
        endpoints.extend(self._extract_tencent(text))
        endpoints.extend(self._extract_huawei(text))
        endpoints.extend(self._extract_aws(text))

        return endpoints

    def _extract_from_dict(self, data: Dict) -> List[OSSEndpoint]:
        """从字典内容提取 OSS URL"""
        if not data:
            return []

        endpoints = []
        text_content = self._dict_to_text(data)
        endpoints.extend(self._extract_from_text(text_content))

        for key, value in data.items():
            if isinstance(value, str):
                key_lower = key.lower()
                if any(p in key_lower for p in ['url', 'endpoint', 'host', 'bucket', 'oss', 'cos', 's3', 'obs']):
                    found = self._extract_from_text(value)
                    for ep in found:
                        ep.source = f"dict.{key}"
                    endpoints.extend(found)
            elif isinstance(value, dict):
                endpoints.extend(self._extract_from_dict(value))
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        endpoints.extend(self._extract_from_dict(item))
                    elif isinstance(item, str):
                        endpoints.extend(self._extract_from_text(item))

        return endpoints

    def _dict_to_text(self, data: Dict) -> str:
        """将字典转换为文本用于正则匹配"""
        parts = []

        def flatten(obj, prefix=""):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    flatten(v, f"{prefix}.{k}" if prefix else k)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    flatten(item, f"{prefix}[{i}]")
            else:
                parts.append(str(obj))

        flatten(data)
        return " ".join(parts)

    def _extract_aliyun(self, text: str) -> List[OSSEndpoint]:
        """提取阿里云 OSS URL"""
        endpoints = []

        for pattern in self.ALIYUN_PATTERNS:
            for match in pattern.finditer(text):
                if match.lastindex and match.lastindex >= 2:
                    bucket = match.group(2)
                    region = match.group(3) if match.lastindex >= 3 else "oss-public"
                    full_url = f"https://{bucket}.oss-{region}.aliyuncs.com"

                    endpoint = OSSEndpoint(
                        url=f"oss://{bucket}",
                        bucket=bucket,
                        region=region,
                        provider=CloudProvider.ALIYUN,
                        full_url=full_url,
                        source="text",
                        confidence=0.9
                    )
                    endpoints.append(endpoint)

        return endpoints

    def _extract_tencent(self, text: str) -> List[OSSEndpoint]:
        """提取腾讯云 COS URL"""
        endpoints = []

        for pattern in self.TENCENT_PATTERNS:
            for match in pattern.finditer(text):
                if match.lastindex and match.lastindex >= 2:
                    bucket = match.group(2)
                    region = match.group(3) if match.lastindex >= 3 else "cos-public"
                    full_url = f"https://{bucket}.cos.{region}.myqcloud.com"

                    endpoint = OSSEndpoint(
                        url=f"cos://{bucket}",
                        bucket=bucket,
                        region=region,
                        provider=CloudProvider.TENCENT,
                        full_url=full_url,
                        source="text",
                        confidence=0.9
                    )
                    endpoints.append(endpoint)

        return endpoints

    def _extract_huawei(self, text: str) -> List[OSSEndpoint]:
        """提取华为云 OBS URL"""
        endpoints = []

        for pattern in self.HUAWEI_PATTERNS:
            for match in pattern.finditer(text):
                if match.lastindex and match.lastindex >= 2:
                    bucket = match.group(2)
                    region = match.group(3) if match.lastindex >= 3 else "obs-public"
                    full_url = f"https://{bucket}.obs-{region}.myhuaweicloud.com"

                    endpoint = OSSEndpoint(
                        url=f"obs://{bucket}",
                        bucket=bucket,
                        region=region,
                        provider=CloudProvider.HUAWEI,
                        full_url=full_url,
                        source="text",
                        confidence=0.9
                    )
                    endpoints.append(endpoint)

        return endpoints

    def _extract_aws(self, text: str) -> List[OSSEndpoint]:
        """提取 AWS S3 URL"""
        endpoints = []

        for pattern in self.AWS_PATTERNS:
            for match in pattern.finditer(text):
                if match.lastindex and match.lastindex >= 2:
                    bucket = match.group(2)
                    region = match.group(3) if match.lastindex >= 3 else "us-east-1"
                    full_url = f"https://{bucket}.s3-{region}.amazonaws.com"

                    endpoint = OSSEndpoint(
                        url=f"s3://{bucket}",
                        bucket=bucket,
                        region=region,
                        provider=CloudProvider.AWS,
                        full_url=full_url,
                        source="text",
                        confidence=0.9
                    )
                    endpoints.append(endpoint)

        return endpoints

    def on_js_collected(self, js_content: str) -> List[OSSEndpoint]:
        """JS 采集完成回调"""
        return self.collect("js", js_content)

    def on_ast_analyzed(self, ast_result: Any) -> List[OSSEndpoint]:
        """AST 分析完成回调"""
        if isinstance(ast_result, dict):
            return self.collect("ast", ast_result)
        return []

    def on_path_extracted(self, paths: List[str]) -> List[OSSEndpoint]:
        """路径提取完成回调"""
        text = " ".join(paths) if paths else ""
        return self.collect("paths", text)

    def on_fuzz_completed(self, fuzz_result: Any) -> List[OSSEndpoint]:
        """Fuzzing 完成回调"""
        return self.collect("fuzz", fuzz_result)

    def on_http_response(self, response: Any) -> List[OSSEndpoint]:
        """HTTP 响应回调"""
        return self.collect("response", response)

    def on_sensitive_detected(self, sensitive_data: Any) -> List[OSSEndpoint]:
        """敏感信息检测回调"""
        return self.collect("sensitive", sensitive_data)

    def on_env_config(self, env_config: Dict) -> List[OSSEndpoint]:
        """环境配置回调"""
        return self.collect("env", env_config)

    def on_swagger_parsed(self, swagger_data: Dict) -> List[OSSEndpoint]:
        """Swagger 解析完成回调"""
        return self.collect("swagger", swagger_data)

    def get_all_endpoints(self) -> List[OSSEndpoint]:
        """获取所有发现的 OSS 端点"""
        return self.results.oss_urls

    def get_summary(self) -> Dict[str, Any]:
        """获取采集摘要"""
        summary = {
            "total_count": len(self.results.oss_urls),
            "by_provider": {},
            "unique_buckets": list(self.results.get_unique_buckets())
        }

        for provider in CloudProvider:
            count = len(self.results.get_by_provider(provider))
            if count > 0:
                summary["by_provider"][provider.value] = count

        return summary


_global_oss_collector = None


def get_oss_collector() -> OSSCollector:
    """获取全局 OSS 采集器实例"""
    global _global_oss_collector
    if _global_oss_collector is None:
        _global_oss_collector = OSSCollector()
    return _global_oss_collector


def reset_oss_collector():
    """重置全局 OSS 采集器"""
    global _global_oss_collector
    if _global_oss_collector:
        _global_oss_collector.reset()
    else:
        _global_oss_collector = OSSCollector()
