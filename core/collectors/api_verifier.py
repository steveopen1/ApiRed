"""
API Verifier Module
API验证器 - 验证发现的API是否返回有效JSON响应，并检查响应内容唯一性
"""

import json
import hashlib
import asyncio
import logging
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
from urllib.parse import urljoin

logger = logging.getLogger(__name__)


@dataclass
class VerifiedAPI:
    """验证通过的API"""
    path: str
    method: str = "GET"
    status_code: int = 0
    content_type: str = ""
    content_length: int = 0
    content_hash: str = ""
    is_valid_json: bool = False
    is_unique_content: bool = False
    is_sensitive_response: bool = False
    response_preview: str = ""
    extracted_urls: List[str] = field(default_factory=list)
    error: str = ""


@dataclass
class VerificationResult:
    """验证结果"""
    total_apis: int = 0
    valid_json_apis: List[VerifiedAPI] = field(default_factory=list)
    unique_content_apis: List[VerifiedAPI] = field(default_factory=list)
    sensitive_apis: List[VerifiedAPI] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'total_apis': self.total_apis,
            'valid_json_count': len(self.valid_json_apis),
            'unique_content_count': len(self.unique_content_apis),
            'sensitive_count': len(self.sensitive_apis),
            'valid_json_apis': [self._api_to_dict(a) for a in self.valid_json_apis],
            'unique_content_apis': [self._api_to_dict(a) for a in self.unique_content_apis],
            'sensitive_apis': [self._api_to_dict(a) for a in self.sensitive_apis],
        }
    
    def _api_to_dict(self, api: VerifiedAPI) -> Dict[str, Any]:
        return {
            'path': api.path,
            'method': api.method,
            'status_code': api.status_code,
            'content_length': api.content_length,
            'content_hash': api.content_hash,
            'is_valid_json': api.is_valid_json,
            'is_sensitive': api.is_sensitive_response,
            'extracted_urls': api.extracted_urls,
            'response_preview': api.response_preview[:100] if api.response_preview else "",
            'error': api.error,
        }


class APIVerifier:
    """
    API验证器
    
    功能：
    1. 验证API是否返回有效JSON响应
    2. 检查响应内容是否唯一（去重）
    3. 分类显示验证结果
    """
    
    def __init__(
        self,
        http_client,
        base_url: str,
        timeout: float = 10.0,
        max_concurrent: int = 50,
        cookies: str = ""
    ):
        self.http_client = http_client
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.cookies = cookies
        self._content_hashes: Dict[str, List[str]] = {}
    
    async def verify_apis(self, api_paths: List[str], methods: Optional[List[str]] = None) -> VerificationResult:
        """
        验证API列表
        
        Args:
            api_paths: API路径列表
            methods: 可选的HTTP方法列表，默认GET和POST
        
        Returns:
            VerificationResult: 验证结果
        """
        if methods is None:
            methods = ["GET", "POST"]
        
        result = VerificationResult()
        result.total_apis = len(api_paths)
        
        verified_apis: List[VerifiedAPI] = []
        content_hashes: Set[str] = set()
        
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def verify_single(api_path: str) -> Optional[VerifiedAPI]:
            async with semaphore:
                return await self._verify_single_api(api_path, methods)
        
        tasks = [verify_single(path) for path in api_paths]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for r in results:
            if isinstance(r, VerifiedAPI):
                verified_apis.append(r)
                if r.is_valid_json:
                    result.valid_json_apis.append(r)
                    if r.content_hash:
                        content_hashes.add(r.content_hash)
                elif r.is_sensitive_response:
                    result.sensitive_apis.append(r)
        
        seen_hashes: Set[str] = set()
        for api in result.valid_json_apis:
            if api.content_hash and api.content_hash not in seen_hashes:
                seen_hashes.add(api.content_hash)
                api.is_unique_content = True
                result.unique_content_apis.append(api)
        
        logger.info(
            f"[API Verifier] 验证完成: 总API={result.total_apis}, "
            f"有效JSON={len(result.valid_json_apis)}, "
            f"敏感响应(403)={len(result.sensitive_apis)}, "
            f"唯一内容={len(result.unique_content_apis)}"
        )
        
        return result
    
    async def _verify_single_api(self, api_path: str, methods: List[str]) -> Optional[VerifiedAPI]:
        """验证单个API"""
        verified = VerifiedAPI(path=api_path)
        
        headers = {}
        if self.cookies:
            headers['Cookie'] = self.cookies
        
        for method in methods:
            try:
                base = self.base_url.rstrip('/')
                path = api_path.lstrip('/')
                full_url = f"{base}/{path}"
                
                response = await self.http_client.request(
                    full_url,
                    method=method,
                    headers=headers,
                    timeout=self.timeout
                )
                
                if response.error:
                    verified.error = response.error
                    continue
                
                verified.status_code = response.status_code
                verified.method = method
                
                if 200 <= response.status_code < 400:
                    verified.content_type = response.headers.get('Content-Type', '').lower()
                    verified.content_length = len(response.content_bytes)
                    verified.content_hash = hashlib.md5(response.content_bytes).hexdigest()
                    
                    verified.is_valid_json = self._is_valid_json(
                        response.content_bytes,
                        verified.content_type
                    )
                    
                    if verified.is_valid_json:
                        try:
                            verified.response_preview = response.content_bytes[:200].decode('utf-8', errors='ignore')
                        except:
                            verified.response_preview = str(response.content_bytes[:200])
                        break
                    else:
                        verified.response_preview = response.content_bytes[:200].decode('utf-8', errors='ignore').strip()
                        verified.is_sensitive_response = True
                        verified.extracted_urls = self._extract_urls_from_response(response.content_bytes)
                        break
                
                elif response.status_code == 403:
                    verified.is_sensitive_response = True
                    verified.error = f"HTTP 403 Forbidden - Access Denied"
                    verified.content_type = response.headers.get('Content-Type', '').lower()
                    verified.content_length = len(response.content_bytes)
                    verified.response_preview = response.content_bytes[:200].decode('utf-8', errors='ignore').strip()
                    verified.extracted_urls = self._extract_urls_from_response(response.content_bytes)
                    break
                
                elif response.status_code == 401:
                    verified.is_sensitive_response = True
                    verified.error = f"HTTP 401 Unauthorized - Authentication Required"
                    verified.content_type = response.headers.get('Content-Type', '').lower()
                    verified.content_length = len(response.content_bytes)
                    verified.response_preview = response.content_bytes[:200].decode('utf-8', errors='ignore').strip()
                    verified.extracted_urls = self._extract_urls_from_response(response.content_bytes)
                    break
                
                else:
                    verified.error = f"HTTP {response.status_code}"
                    
            except asyncio.TimeoutError:
                verified.error = "Timeout"
            except Exception as e:
                verified.error = str(e)
                continue
        
        return verified
    
    def _extract_urls_from_response(self, content: bytes) -> List[str]:
        """从响应内容中提取API链接"""
        import re
        from urllib.parse import urlparse
        
        extracted = []
        try:
            text = content.decode('utf-8', errors='ignore')
        except:
            return extracted
        
        url_patterns = [
            r'''["\'](/api/[^"\']+)["\']''',
            r'''["\'](/[a-zA-Z0-9_/-]+\.json)["\']''',
            r'''href=["\'](/[^"\']+)["\']''',
            r'''url:\s*["\']([^"\']+)["\']''',
            r'''src=["\'](/[^"\']+)["\']''',
        ]
        
        for pattern in url_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                if match and len(match) > 1:
                    path = match.strip()
                    if path.startswith('/') and not path.startswith('//'):
                        if path not in extracted:
                            extracted.append(path)
        
        return extracted
    
    def _is_valid_json(self, content: bytes, content_type: str) -> bool:
        """检查响应是否为有效JSON"""
        if 'application/json' in content_type:
            return True
        
        try:
            text = content.decode('utf-8', errors='ignore').strip()
            if text.startswith('{') or text.startswith('['):
                json.loads(text)
                return True
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
            pass
        
        return False
    
    def print_categorized_results(self, result: VerificationResult) -> None:
        """打印分类结果"""
        print("\n" + "=" * 60)
        print("API 验证结果")
        print("=" * 60)
        
        print(f"\n总 API 数量: {result.total_apis}")
        print(f"有效 JSON 响应: {len(result.valid_json_apis)}")
        print(f"唯一内容: {len(result.unique_content_apis)}")
        print(f"敏感响应(403/401): {len(result.sensitive_apis)}")
        
        print("\n" + "-" * 60)
        print("有效 JSON 响应")
        print("-" * 60)
        if result.valid_json_apis:
            for api in result.valid_json_apis:
                preview = api.response_preview[:50].replace('\n', ' ').replace('\r', '') if api.response_preview else ""
                print(f"  [{api.method}] {api.path} - {api.content_length} bytes - {preview}...")
        else:
            print("  无")
        
        print("\n" + "-" * 60)
        print("敏感响应 (403/401 - 可能需要认证)")
        print("-" * 60)
        if result.sensitive_apis:
            for api in result.sensitive_apis:
                preview = api.response_preview[:50].replace('\n', ' ').replace('\r', '') if api.response_preview else ""
                print(f"  [{api.method}] {api.path} - {api.status_code} - {preview}...")
                if api.extracted_urls:
                    for url in api.extracted_urls[:5]:
                        print(f"      -> 发现链接: {url}")
        else:
            print("  无")
        
        print("\n" + "-" * 60)
        print("有效 JSON 响应 + 唯一内容")
        print("-" * 60)
        if result.unique_content_apis:
            for api in result.unique_content_apis:
                preview = api.response_preview[:50].replace('\n', ' ').replace('\r', '') if api.response_preview else ""
                print(f"  [{api.method}] {api.path} - {api.content_length} bytes - {preview}...")
        else:
            print("  无")
        
        print("\n" + "=" * 60)
    
    def save_results(self, result: VerificationResult, output_dir: str) -> None:
        """保存验证结果到文件"""
        import os
        
        os.makedirs(output_dir, exist_ok=True)
        
        valid_json_file = os.path.join(output_dir, "verified_valid_json.txt")
        unique_content_file = os.path.join(output_dir, "verified_unique_content.txt")
        
        with open(valid_json_file, 'w', encoding='utf-8') as f:
            for api in result.valid_json_apis:
                f.write(f"{api.method} {api.path}\n")
        
        with open(unique_content_file, 'w', encoding='utf-8') as f:
            for api in result.unique_content_apis:
                f.write(f"{api.method} {api.path}\n")
        
        logger.info(f"[API Verifier] 结果已保存: {valid_json_file}, {unique_content_file}")


async def verify_endpoints(
    http_client,
    base_url: str,
    endpoints: List[str],
    timeout: float = 10.0,
    cookies: str = ""
) -> VerificationResult:
    """
    便捷函数：验证端点列表
    
    Args:
        http_client: HTTP客户端
        base_url: 基础URL
        endpoints: 端点列表
        timeout: 超时时间
        cookies: Cookie字符串
    
    Returns:
        VerificationResult: 验证结果
    """
    verifier = APIVerifier(
        http_client=http_client,
        base_url=base_url,
        timeout=timeout,
        cookies=cookies
    )
    return await verifier.verify_apis(endpoints)