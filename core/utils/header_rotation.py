"""
HTTP Header Rotation and Fingerprint Module
HTTP Header 轮换和指纹伪装模块
参考 FLUX v3.0 智能防护规避实现
支持 4 种真实浏览器指纹轮换
"""

import random
import hashlib
from typing import Dict, List, Optional
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class BrowserFingerprint:
    """浏览器指纹"""
    user_agent: str
    sec_ch_ua: str
    sec_ch_ua_mobile: str
    sec_ch_ua_platform: str
    accept: str
    accept_language: str
    accept_encoding: str
    referer: str


class HeaderRotator:
    """
    Header 轮换器
    
    支持 4 种真实浏览器指纹：
    - Chrome on Windows
    - Chrome on macOS
    - Firefox on Windows
    - Safari on macOS
    """
    
    FINGERPRINTS = [
        BrowserFingerprint(
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            sec_ch_ua='"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            sec_ch_ua_mobile='?0',
            sec_ch_ua_platform='"Windows"',
            accept='text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            accept_language='en-US,en;q=0.9',
            accept_encoding='gzip, deflate, br',
            referer='https://www.google.com',
        ),
        BrowserFingerprint(
            user_agent='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
            sec_ch_ua='"Chromium";v="120", "Safari";v="120"',
            sec_ch_ua_mobile='?0',
            sec_ch_ua_platform='"macOS"',
            accept='text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            accept_language='en-US,en;q=0.9',
            accept_encoding='gzip, deflate, br',
            referer='https://www.google.com',
        ),
        BrowserFingerprint(
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            sec_ch_ua='"Chromium";v="120", "Firefox";v="121"',
            sec_ch_ua_mobile='?0',
            sec_ch_ua_platform='"Windows"',
            accept='text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            accept_language='en-US,en;q=0.9',
            accept_encoding='gzip, deflate, br',
            referer='https://www.google.com',
        ),
        BrowserFingerprint(
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
            sec_ch_ua='"Chromium";v="120", "Microsoft Edge";v="120", "Not=A_Brand";v="99"',
            sec_ch_ua_mobile='?0',
            sec_ch_ua_platform='"Windows"',
            accept='text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            accept_language='en-US,en;q=0.9',
            accept_encoding='gzip, deflate, br',
            referer='https://www.bing.com',
        ),
    ]
    
    def __init__(self):
        self.current_index = 0
        self.fingerprints = self.FINGERPRINTS
    
    def get_random(self) -> BrowserFingerprint:
        """获取随机指纹"""
        return random.choice(self.fingerprints)
    
    def get_next(self) -> BrowserFingerprint:
        """获取下一个指纹（轮换）"""
        fp = self.fingerprints[self.current_index]
        self.current_index = (self.current_index + 1) % len(self.fingerprints)
        return fp
    
    def get_headers(self, base_headers: Dict = None) -> Dict[str, str]:
        """
        获取轮换后的请求头
        
        Args:
            base_headers: 基础请求头
            
        Returns:
            Dict[str, str]: 完整的请求头
        """
        fp = self.get_random()
        
        headers = base_headers.copy() if base_headers else {}
        
        headers['User-Agent'] = fp.user_agent
        headers['Sec-Ch-Ua'] = fp.sec_ch_ua
        headers['Sec-Ch-Ua-Mobile'] = fp.sec_ch_ua_mobile
        headers['Sec-Ch-Ua-Platform'] = fp.sec_ch_ua_platform
        headers['Accept'] = fp.accept
        headers['Accept-Language'] = fp.accept_language
        headers['Accept-Encoding'] = fp.accept_encoding
        headers['Referer'] = fp.referer
        headers['Sec-Fetch-Dest'] = 'document'
        headers['Sec-Fetch-Mode'] = 'navigate'
        headers['Sec-Fetch-Site'] = 'none'
        headers['Sec-Fetch-User'] = '?1'
        headers['Upgrade-Insecure-Requests'] = '1'
        headers['Cache-Control'] = 'max-age=0'
        
        return headers


class AdaptiveRateLimiter:
    """
    自适应速率限制器
    
    根据服务器响应动态调整请求频率
    """
    
    def __init__(self, initial_delay: float = 1.0, max_delay: float = 60.0):
        self.delay = initial_delay
        self.max_delay = max_delay
        self.success_count = 0
        self.error_count = 0
        self.last_error_time = 0
    
    def record_success(self):
        """记录成功响应"""
        self.success_count += 1
        self.error_count = 0
        if self.delay > 1.0:
            self.delay = max(1.0, self.delay * 0.9)
    
    def record_error(self, is_rate_limit: bool = False):
        """记录错误响应"""
        self.error_count += 1
        if is_rate_limit or self.error_count > 3:
            self.delay = min(self.max_delay, self.delay * 2)
            logger.warning(f"Rate limit triggered, increasing delay to {self.delay}s")
    
    def get_delay(self) -> float:
        """获取当前延迟"""
        return self.delay
    
    def should_retry(self) -> bool:
        """判断是否应该重试"""
        return self.delay < self.max_delay


class CSRFExtractor:
    """
    CSRF Token 自动提取器
    
    支持 6 种常见 Token 格式
    """
    
    CSRF_PATTERNS = [
        r'<input[^>]+name=["\']csrf[^"\']+value=["\']([^"\']+)["\']',
        r'<input[^>]+name=["\']_csrf["\']+value=["\']([^"\']+)["\']',
        r'<meta[^>]+name=["\']csrf-token["\']+content=["\']([^"\']+)["\']',
        r'csrf[_-]?token["\s]*[:=]["\s]*["\']([^"\']+)["\']',
        r'csrf["\s]*[:=]["\s]*["\']([^"\']{20,})["\']',
        r'["\']csrf["\']\s*:\s*["\']([^"\']+)["\']',
    ]
    
    @classmethod
    def extract(cls, content: str) -> Dict[str, str]:
        """
        从 HTML/JS 中提取 CSRF Token
        
        Returns:
            Dict[str, str]: {token_name: token_value}
        """
        tokens = {}
        
        for pattern in cls.CSRF_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if len(match) >= 2:
                    name, value = match[0], match[1]
                    name = name.lower().strip()
                    if 'csrf' in name:
                        tokens[name] = value
                elif len(match) == 1 and len(match[0]) > 20:
                    tokens['csrf_token'] = match[0]
        
        return tokens
    
    @classmethod
    def extract_from_response(cls, response_text: str) -> Optional[str]:
        """
        从响应中提取 CSRF Token 值
        
        Returns:
            Optional[str]: Token 值
        """
        tokens = cls.extract(response_text)
        if tokens:
            return list(tokens.values())[0]
        return None


import re
