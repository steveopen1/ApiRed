"""
OSS Vulnerability Tester Module
OSS 存储桶漏洞测试模块
支持阿里云 OSS、腾讯云 COS、华为云 OBS、AWS S3
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import hashlib

logger = logging.getLogger(__name__)


class OSSVulnType(Enum):
    """OSS 漏洞类型"""
    SENSITIVE_FILE_LEAK = "oss_sensitive_file_leak"
    ANONYMOUS_UPLOAD = "oss_anonymous_upload"
    ANONYMOUS_DELETE = "oss_anonymous_delete"
    ANONYMOUS_POST = "oss_anonymous_post"
    CORS_MISCONFIG = "oss_cors_misconfig"
    DIRECTORY_TRAVERSAL = "oss_directory_traversal"
    LOG_DISCLOSURE = "oss_log_disclosure"
    PUBLIC_LISTING = "oss_public_listing"
    VERSION_LEAK = "oss_version_leak"
    BUCKET_POLICY_OPEN = "oss_bucket_policy_open"
    CONFIG_LEAK = "oss_config_leak"


class RiskLevel(Enum):
    """风险等级"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class OSSVulnResult:
    """OSS 漏洞测试结果"""
    vuln_type: OSSVulnType
    bucket: str
    region: str
    provider: str
    url: str
    risk_level: RiskLevel
    verified: bool
    payload: str = ""
    description: str = ""
    poc: str = ""
    remediation: str = ""


@dataclass
class OSSScanConfig:
    """OSS 扫描配置"""
    timeout: int = 10
    retry: int = 2
    scan_sensitive_file: bool = True
    scan_anonymous_upload: bool = True
    scan_anonymous_delete: bool = True
    scan_cors: bool = True
    scan_directory_traversal: bool = True
    scan_logs: bool = True
    scan_public_listing: bool = True
    scan_version_leak: bool = True
    scan_bucket_policy: bool = True
    test_file_content: str = "OSS_TEST_FILE_CONTENT"
    sensitive_paths: List[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.sensitive_paths:
            self.sensitive_paths = [
                ".env",
                ".git/config",
                ".git/credentials",
                "id_rsa",
                "id_rsa.pub",
                "aws_access_key.json",
                "credentials.json",
                "config.json",
                "wp-config.php",
                "database.sql",
                "backup.sql",
                "dump.sql",
                ".htaccess",
                ".htpasswd",
                "package.json",
                "package-lock.json",
                "yarn.lock",
                "composer.json",
                ".npmrc",
                ".bashrc",
                ".bash_history",
                "server.key",
                "private.pem",
                "access_key.txt",
            ]


class OSSVulnTester:
    """
    OSS 漏洞测试器

    支持的云服务商：
    - 阿里云 OSS
    - 腾讯云 COS
    - 华为云 OBS
    - AWS S3
    """

    def __init__(self, http_client=None, config: OSSScanConfig = None):
        self.http_client = http_client
        self.config = config or OSSScanConfig()

    async def test_bucket(self, bucket_url: str, bucket_name: str, region: str,
                         provider: str) -> List[OSSVulnResult]:
        """
        测试单个存储桶

        Args:
            bucket_url: 存储桶完整 URL
            bucket_name: 存储桶名称
            region: 区域
            provider: 云服务商

        Returns:
            发现的漏洞列表
        """
        results = []

        if self.config.scan_public_listing:
            result = await self._check_public_listing(bucket_url, bucket_name, region, provider)
            if result:
                results.append(result)

        if self.config.scan_sensitive_file:
            sensitive_results = await self._check_sensitive_files(bucket_url, bucket_name, region, provider)
            results.extend(sensitive_results)

        if self.config.scan_anonymous_upload:
            result = await self._check_anonymous_upload(bucket_url, bucket_name, region, provider)
            if result:
                results.append(result)

        if self.config.scan_anonymous_delete:
            result = await self._check_anonymous_delete(bucket_url, bucket_name, region, provider)
            if result:
                results.append(result)

        if self.config.scan_cors:
            result = await self._check_cors_misconfig(bucket_url, bucket_name, region, provider)
            if result:
                results.append(result)

        if self.config.scan_directory_traversal:
            result = await self._check_directory_traversal(bucket_url, bucket_name, region, provider)
            if result:
                results.append(result)

        if self.config.scan_logs:
            result = await self._check_log_disclosure(bucket_url, bucket_name, region, provider)
            if result:
                results.append(result)

        if self.config.scan_bucket_policy:
            result = await self._check_bucket_policy(bucket_url, bucket_name, region, provider)
            if result:
                results.append(result)

        return results

    async def _check_public_listing(self, bucket_url: str, bucket_name: str,
                                    region: str, provider: str) -> Optional[OSSVulnResult]:
        """检查是否可公开列举目录"""
        try:
            if not self.http_client:
                return None

            resp = await self.http_client.request(bucket_url, 'GET')

            if resp.status_code == 200:
                content = resp.content if hasattr(resp, 'content') else ''
                if isinstance(content, bytes):
                    content = content.decode('utf-8', errors='ignore')

                if '<ListBucketResult' in content or 'ListAllMyBucketsResult' in content:
                    return OSSVulnResult(
                        vuln_type=OSSVulnType.PUBLIC_LISTING,
                        bucket=bucket_name,
                        region=region,
                        provider=provider,
                        url=bucket_url,
                        risk_level=RiskLevel.HIGH,
                        verified=True,
                        description="存储桶可以公开列举目录，可遍历所有文件",
                        poc=f"GET {bucket_url}",
                        remediation="设置存储桶访问策略，禁止公开列举"
                    )

            if resp.status_code == 403:
                return None

            if resp.status_code == 200 and 'AccessDenied' not in (resp.content if hasattr(resp, 'content') else ''):
                pass

        except Exception as e:
            logger.debug(f"Public listing check failed for {bucket_url}: {e}")

        return None

    async def _check_sensitive_files(self, bucket_url: str, bucket_name: str,
                                     region: str, provider: str) -> List[OSSVulnResult]:
        """检查敏感文件泄露"""
        results = []

        for sensitive_path in self.config.sensitive_paths[:20]:
            try:
                if not self.http_client:
                    break

                test_url = f"{bucket_url}/{sensitive_path}" if not bucket_url.endswith('/') else f"{bucket_url}{sensitive_path}"

                resp = await self.http_client.request(test_url, 'GET', timeout=self.config.timeout)

                if resp.status_code == 200:
                    content = resp.content if hasattr(resp, 'content') else ''
                    content_str = content.decode('utf-8', errors='ignore') if isinstance(content, bytes) else str(content)

                    if len(content_str) > 0 and len(content_str) < 1024 * 1024:
                        file_type = self._classify_sensitive_file(sensitive_path, content_str)

                        if file_type == "critical":
                            results.append(OSSVulnResult(
                                vuln_type=OSSVulnType.SENSITIVE_FILE_LEAK,
                                bucket=bucket_name,
                                region=region,
                                provider=provider,
                                url=test_url,
                                risk_level=RiskLevel.CRITICAL,
                                verified=True,
                                payload=sensitive_path,
                                description=f"敏感文件泄露: {sensitive_path}",
                                poc=f"GET {test_url}",
                                remediation="立即删除泄露的敏感文件，配置存储桶策略禁止未授权访问"
                            ))
                        elif file_type == "high":
                            results.append(OSSVulnResult(
                                vuln_type=OSSVulnType.SENSITIVE_FILE_LEAK,
                                bucket=bucket_name,
                                region=region,
                                provider=provider,
                                url=test_url,
                                risk_level=RiskLevel.HIGH,
                                verified=True,
                                payload=sensitive_path,
                                description=f"敏感配置泄露: {sensitive_path}",
                                poc=f"GET {test_url}",
                                remediation="移除或保护敏感配置文件"
                            ))

            except Exception as e:
                logger.debug(f"Sensitive file check failed for {test_url}: {e}")

        return results

    def _classify_sensitive_file(self, path: str, content: str) -> str:
        """分类敏感文件风险等级"""
        path_lower = path.lower()

        critical_patterns = ['.env', 'id_rsa', 'credentials', 'access_key', 'secret']
        high_patterns = ['.git/', 'wp-config', 'database', 'backup', 'dump', '.sql']

        if any(p in path_lower for p in critical_patterns):
            if 'password' in content.lower() or 'secret' in content.lower() or 'key' in content.lower():
                return "critical"

        if any(p in path_lower for p in high_patterns):
            return "high"

        return "medium"

    async def _check_anonymous_upload(self, bucket_url: str, bucket_name: str,
                                     region: str, provider: str) -> Optional[OSSVulnResult]:
        """检查是否支持匿名上传"""
        test_file_name = f"test_{hashlib.md5(str(hash(bucket_url)).encode()).hexdigest()[:8]}.txt"
        test_content = self.config.test_file_content

        try:
            if not self.http_client:
                return None

            if provider == "aliyun":
                upload_url = f"{bucket_url}/{test_file_name}"
            elif provider == "tencent":
                upload_url = f"{bucket_url}/{test_file_name}"
            elif provider == "huawei":
                upload_url = f"{bucket_url}/{test_file_name}"
            elif provider == "aws":
                upload_url = f"{bucket_url}/{test_file_name}"
            else:
                upload_url = f"{bucket_url}/{test_file_name}"

            resp = await self.http_client.request(
                upload_url,
                'PUT',
                data=test_content.encode('utf-8'),
                headers={'Content-Type': 'text/plain'},
                timeout=self.config.timeout
            )

            if resp.status_code in [200, 201, 204]:
                await self._cleanup_test_file(upload_url, provider)

                return OSSVulnResult(
                    vuln_type=OSSVulnType.ANONYMOUS_UPLOAD,
                    bucket=bucket_name,
                    region=region,
                    provider=provider,
                    url=bucket_url,
                    risk_level=RiskLevel.CRITICAL,
                    verified=True,
                    payload=f"PUT {upload_url}",
                    description="存储桶允许匿名上传文件，可导致恶意文件部署",
                    poc=f"PUT {upload_url}\nContent: {test_content}",
                    remediation="立即禁用匿名上传，配置存储桶策略要求认证"
                )

        except Exception as e:
            logger.debug(f"Anonymous upload check failed for {bucket_url}: {e}")

        return None

    async def _check_anonymous_delete(self, bucket_url: str, bucket_name: str,
                                     region: str, provider: str) -> Optional[OSSVulnResult]:
        """检查是否支持匿名删除"""
        test_file_name = f"delete_test_{hashlib.md5(str(hash(bucket_url)).encode()).hexdigest()[:8]}.txt"
        test_content = self.config.test_file_content

        try:
            if not self.http_client:
                return None

            upload_url = f"{bucket_url}/{test_file_name}" if not bucket_url.endswith('/') else f"{bucket_url}{test_file_name}"

            put_resp = await self.http_client.request(
                upload_url,
                'PUT',
                data=test_content.encode('utf-8'),
                headers={'Content-Type': 'text/plain'},
                timeout=self.config.timeout
            )

            if put_resp.status_code not in [200, 201, 204]:
                return None

            del_resp = await self.http_client.request(
                upload_url,
                'DELETE',
                timeout=self.config.timeout
            )

            if del_resp.status_code in [200, 204]:
                return OSSVulnResult(
                    vuln_type=OSSVulnType.ANONYMOUS_DELETE,
                    bucket=bucket_name,
                    region=region,
                    provider=provider,
                    url=bucket_url,
                    risk_level=RiskLevel.CRITICAL,
                    verified=True,
                    payload=f"DELETE {upload_url}",
                    description="存储桶允许匿名删除文件，可导致数据被非法删除",
                    poc=f"DELETE {upload_url}",
                    remediation="立即禁用匿名删除，配置存储桶策略禁止未授权删除"
                )

        except Exception as e:
            logger.debug(f"Anonymous delete check failed for {bucket_url}: {e}")

        return None

    async def _check_cors_misconfig(self, bucket_url: str, bucket_name: str,
                                    region: str, provider: str) -> Optional[OSSVulnResult]:
        """检查 CORS 配置是否过宽"""
        try:
            if not self.http_client:
                return None

            resp = await self.http_client.request(
                bucket_url,
                'OPTIONS',
                headers={
                    'Origin': 'https://evil.com',
                    'Access-Control-Request-Method': 'PUT'
                },
                timeout=self.config.timeout
            )

            if resp.status_code == 200:
                cors_header = None
                if hasattr(resp, 'headers'):
                    cors_header = resp.headers.get('Access-Control-Allow-Origin', '')

                if cors_header == '*' or cors_header == 'https://evil.com':
                    return OSSVulnResult(
                        vuln_type=OSSVulnType.CORS_MISCONFIG,
                        bucket=bucket_name,
                        region=region,
                        provider=provider,
                        url=bucket_url,
                        risk_level=RiskLevel.MEDIUM,
                        verified=True,
                        payload=f"OPTIONS with Origin: https://evil.com",
                        description=f"CORS 配置过宽，允许任意来源跨域访问: {cors_header}",
                        poc=f"OPTIONS {bucket_url}\nOrigin: https://evil.com",
                        remediation="修改 CORS 配置，限制允许的来源域名"
                    )

        except Exception as e:
            logger.debug(f"CORS check failed for {bucket_url}: {e}")

        return None

    async def _check_directory_traversal(self, bucket_url: str, bucket_name: str,
                                        region: str, provider: str) -> Optional[OSSVulnResult]:
        """检查目录遍历漏洞"""
        traversal_paths = [
            '../../../etc/passwd',
            '..%2F..%2F..%2Fetc%2Fpasswd',
            '....//....//....//etc/passwd',
        ]

        try:
            if not self.http_client:
                return None

            for path in traversal_paths[:3]:
                test_url = f"{bucket_url}/{path}" if not bucket_url.endswith('/') else f"{bucket_url}{path}"

                resp = await self.http_client.request(test_url, 'GET', timeout=self.config.timeout)

                if resp.status_code == 200:
                    content = resp.content if hasattr(resp, 'content') else ''
                    content_str = content.decode('utf-8', errors='ignore') if isinstance(content, bytes) else str(content)

                    if 'root:' in content_str and '/bin/' in content_str:
                        return OSSVulnResult(
                            vuln_type=OSSVulnType.DIRECTORY_TRAVERSAL,
                            bucket=bucket_name,
                            region=region,
                            provider=provider,
                            url=test_url,
                            risk_level=RiskLevel.MEDIUM,
                            verified=True,
                            payload=path,
                            description="存储桶存在目录遍历漏洞，可读取系统敏感文件",
                            poc=f"GET {test_url}",
                            remediation="修复路径解析逻辑，禁止使用用户输入的路径进行文件读取"
                        )

        except Exception as e:
            logger.debug(f"Directory traversal check failed for {bucket_url}: {e}")

        return None

    async def _check_log_disclosure(self, bucket_url: str, bucket_name: str,
                                    region: str, provider: str) -> Optional[OSSVulnResult]:
        """检查日志文件泄露"""
        log_paths = ['logs/', 'accesslog/', 'log/', '.logs/', 'access_log/']

        for log_path in log_paths[:3]:
            try:
                if not self.http_client:
                    break

                test_url = f"{bucket_url}/{log_path}" if not bucket_url.endswith('/') else f"{bucket_url}{log_path}"

                resp = await self.http_client.request(test_url, 'GET', timeout=self.config.timeout)

                if resp.status_code == 200:
                    content = resp.content if hasattr(resp, 'content') else ''
                    content_str = content.decode('utf-8', errors='ignore') if isinstance(content, bytes) else str(content)

                    if 'GET /' in content_str or 'POST /' in content_str or 'HTTP/' in content_str:
                        return OSSVulnResult(
                            vuln_type=OSSVulnType.LOG_DISCLOSURE,
                            bucket=bucket_name,
                            region=region,
                            provider=provider,
                            url=test_url,
                            risk_level=RiskLevel.HIGH,
                            verified=True,
                            payload=log_path,
                            description="存储桶存在日志文件泄露，可获取访问记录",
                            poc=f"GET {test_url}",
                            remediation="删除日志文件或限制存储桶访问"
                        )

            except Exception as e:
                logger.debug(f"Log disclosure check failed for {test_url}: {e}")

        return None

    async def _check_bucket_policy(self, bucket_url: str, bucket_name: str,
                                  region: str, provider: str) -> Optional[OSSVulnResult]:
        """检查存储桶策略是否开放"""
        policy_paths = ['?policy', '?acl', 'policy', 'acl']

        for policy_path in policy_paths[:2]:
            try:
                if not self.http_client:
                    break

                test_url = f"{bucket_url}/{policy_path}" if not bucket_url.endswith('/') else f"{bucket_url}{policy_path}"

                resp = await self.http_client.request(test_url, 'GET', timeout=self.config.timeout)

                if resp.status_code == 200:
                    content = resp.content if hasattr(resp, 'content') else ''
                    content_str = content.decode('utf-8', errors='ignore') if isinstance(content, bytes) else str(content)

                    if '"Effect":"Allow"' in content_str or '"Principal":"*"' in content_str:
                        return OSSVulnResult(
                            vuln_type=OSSVulnType.BUCKET_POLICY_OPEN,
                            bucket=bucket_name,
                            region=region,
                            provider=provider,
                            url=test_url,
                            risk_level=RiskLevel.HIGH,
                            verified=True,
                            payload=policy_path,
                            description="存储桶策略配置为公开允许访问",
                            poc=f"GET {test_url}",
                            remediation="修改存储桶策略，限制为仅授权用户访问"
                        )

            except Exception as e:
                logger.debug(f"Bucket policy check failed for {test_url}: {e}")

        return None

    async def _cleanup_test_file(self, url: str, provider: str):
        """清理测试文件"""
        try:
            if self.http_client:
                await self.http_client.request(url, 'DELETE', timeout=5)
        except Exception as e:
            logger.debug(f"Cleanup failed for {url}: {e}")


def get_oss_vuln_type_name(vuln_type: OSSVulnType) -> str:
    """获取漏洞类型显示名称"""
    names = {
        OSSVulnType.SENSITIVE_FILE_LEAK: "敏感文件泄露",
        OSSVulnType.ANONYMOUS_UPLOAD: "匿名文件上传",
        OSSVulnType.ANONYMOUS_DELETE: "匿名文件删除",
        OSSVulnType.ANONYMOUS_POST: "匿名表单上传",
        OSSVulnType.CORS_MISCONFIG: "CORS配置过宽",
        OSSVulnType.DIRECTORY_TRAVERSAL: "目录遍历",
        OSSVulnType.LOG_DISCLOSURE: "日志文件泄露",
        OSSVulnType.PUBLIC_LISTING: "公开目录列举",
        OSSVulnType.VERSION_LEAK: "版本信息泄露",
        OSSVulnType.BUCKET_POLICY_OPEN: "存储桶策略开放",
        OSSVulnType.CONFIG_LEAK: "配置文件泄露",
    }
    return names.get(vuln_type, vuln_type.value)


def get_risk_level_name(risk_level: RiskLevel) -> str:
    """获取风险等级显示名称"""
    names = {
        RiskLevel.CRITICAL: "严重",
        RiskLevel.HIGH: "高危",
        RiskLevel.MEDIUM: "中危",
        RiskLevel.LOW: "低危",
        RiskLevel.INFO: "信息",
    }
    return names.get(risk_level, risk_level.value)
