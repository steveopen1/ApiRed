"""
Realtime Output Module
实时输出模块 - 终端日志和文件输出
"""

import os
import re
import logging
import threading
from typing import Set, List, Optional
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


STATIC_EXTENSIONS = {'.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot', '.map', '.html', '.htm', '.xml', '.txt', '.md', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.zip', '.tar', '.gz'}
STATIC_PATH_PREFIXES = ['/static/', '/assets/', '/images/', '/css/', '/js/', '/lib/', '/font/', '/fonts/', '/media/', '/img/', '/pic/', '/style/', '/styles/']

class RealtimeOutput:
    """
    实时输出器
    
    功能：
    1. 终端实时显示日志
    2. 文件实时输出
       - URLs
       - 子域名
       - 根域名
       - APIs
       - IPs / IP:port
       - 敏感信息
       - 漏洞
       - JS URLs
    """
    
    def __init__(self, output_dir: str = "./output"):
        self.output_dir = output_dir
        self._lock = threading.Lock()
        
        self.urls_file = None
        self.subdomains_file = None
        self.rootdomains_file = None
        self.apis_file = None
        self.ips_file = None
        self.sensitive_file = None
        self.vulns_file = None
        self.js_file = None
        
        self._timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._init_files()
    
    def _init_files(self):
        """初始化输出文件"""
        os.makedirs(self.output_dir, exist_ok=True)
        
        self.urls_file = os.path.join(self.output_dir, f"realtime_urls_{self._timestamp}.txt")
        self.subdomains_file = os.path.join(self.output_dir, f"realtime_subdomains_{self._timestamp}.txt")
        self.rootdomains_file = os.path.join(self.output_dir, f"realtime_rootdomains_{self._timestamp}.txt")
        self.apis_file = os.path.join(self.output_dir, f"realtime_apis_{self._timestamp}.txt")
        self.ips_file = os.path.join(self.output_dir, f"realtime_ips_{self._timestamp}.txt")
        self.sensitive_file = os.path.join(self.output_dir, f"realtime_sensitive_{self._timestamp}.txt")
        self.vulns_file = os.path.join(self.output_dir, f"realtime_vulns_{self._timestamp}.txt")
        self.js_file = os.path.join(self.output_dir, f"realtime_js_{self._timestamp}.txt")
        
        for f in [self.urls_file, self.subdomains_file, self.rootdomains_file, 
                  self.apis_file, self.ips_file, self.sensitive_file, 
                  self.vulns_file, self.js_file]:
            if f:
                Path(f).touch()
    
    def output_url(self, url: str, source: str = ""):
        """输出 URL"""
        if not url:
            return
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_msg = f"[{timestamp}] [URL] {url}"
        if source:
            log_msg += f" (from {source})"
        
        logger.info(log_msg)
        
        with self._lock:
            with open(self.urls_file, 'a', encoding='utf-8') as f:
                f.write(url + '\n')
    
    def output_subdomain(self, subdomain: str, source: str = ""):
        """输出子域名"""
        if not subdomain:
            return
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_msg = f"[{timestamp}] [SUBDOMAIN] {subdomain}"
        if source:
            log_msg += f" (from {source})"
        
        logger.info(log_msg)
        
        with self._lock:
            with open(self.subdomains_file, 'a', encoding='utf-8') as f:
                f.write(subdomain + '\n')
    
    def output_rootdomain(self, rootdomain: str, source: str = ""):
        """输出根域名"""
        if not rootdomain:
            return
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_msg = f"[{timestamp}] [ROOTDOMAIN] {rootdomain}"
        if source:
            log_msg += f" (from {source})"
        
        logger.info(log_msg)
        
        with self._lock:
            with open(self.rootdomains_file, 'a', encoding='utf-8') as f:
                f.write(rootdomain + '\n')
    
    def _is_static_resource(self, path: str) -> bool:
        """判断是否为静态资源路径"""
        path_lower = path.lower()
        if '?' in path:
            path_lower = path_lower.split('?')[0]
        path_lower = path_lower.strip()
        
        for ext in STATIC_EXTENSIONS:
            if path_lower.endswith(ext):
                return True
        
        for prefix in STATIC_PATH_PREFIXES:
            if path_lower.startswith(prefix):
                return True
        
        return False
    
    def output_api(self, api_path: str, method: str = "GET", source: str = ""):
        """输出 API 路径"""
        if not api_path:
            return
        
        if self._is_static_resource(api_path):
            return
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_msg = f"[{timestamp}] [API] {method} {api_path}"
        if source:
            log_msg += f" (from {source})"
        
        logger.info(log_msg)
        
        with self._lock:
            with open(self.apis_file, 'a', encoding='utf-8') as f:
                f.write(f"{method} {api_path}\n")
    
    def output_ip(self, ip: str, port: str = "", source: str = ""):
        """输出 IP / IP:port"""
        if not ip:
            return
        
        ip_port = f"{ip}:{port}" if port else ip
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_msg = f"[{timestamp}] [IP] {ip_port}"
        if source:
            log_msg += f" (from {source})"
        
        logger.info(log_msg)
        
        with self._lock:
            with open(self.ips_file, 'a', encoding='utf-8') as f:
                f.write(f"{ip_port}\n")
    
    def output_sensitive(self, sensitive_type: str, content: str, source: str = ""):
        """输出敏感信息"""
        if not sensitive_type or not content:
            return
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_msg = f"[{timestamp}] [SENSITIVE:{sensitive_type}] {content[:50]}..."
        if source:
            log_msg += f" (from {source})"
        
        logger.warning(log_msg)
        
        with self._lock:
            with open(self.sensitive_file, 'a', encoding='utf-8') as f:
                f.write(f"[{sensitive_type}] {content}\n")
    
    def output_js(self, js_url: str, size: int = 0, source: str = ""):
        """输出 JS URL"""
        if not js_url:
            return
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        size_str = f"({size} bytes)" if size else ""
        log_msg = f"[{timestamp}] [JS] {js_url} {size_str}"
        if source:
            log_msg += f" (from {source})"
        
        logger.info(log_msg)
        
        with self._lock:
            with open(self.js_file, 'a', encoding='utf-8') as f:
                f.write(f"{js_url}\n")
    
    def output_vulnerability(self, vuln_type: str, endpoint: str, severity: str = "medium", 
                              details: str = "", payload: str = ""):
        """输出漏洞"""
        if not vuln_type or not endpoint:
            return
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_msg = f"[{timestamp}] [VULN:{severity.upper()}] {vuln_type} @ {endpoint}"
        if payload:
            log_msg += f" | payload: {payload[:50]}..."
        
        logger.warning(log_msg)
        
        with self._lock:
            with open(self.vulns_file, 'a', encoding='utf-8') as f:
                line = f"[{severity.upper()}] {vuln_type} | {endpoint}"
                if payload:
                    line += f" | payload: {payload}"
                if details:
                    line += f" | details: {details}"
                f.write(line + '\n')
    
    def get_output_files(self) -> dict:
        """获取所有输出文件路径"""
        return {
            'urls': self.urls_file,
            'subdomains': self.subdomains_file,
            'rootdomains': self.rootdomains_file,
            'apis': self.apis_file,
            'ips': self.ips_file,
            'sensitive': self.sensitive_file,
            'vulns': self.vulns_file,
            'js': self.js_file
        }
    
    def close(self):
        """关闭并刷新所有文件"""
        logger.info(f"Realtime output files saved to: {self.output_dir}/")


_realtime_output_instance: Optional[RealtimeOutput] = None


def get_realtime_output(output_dir: str = "./output") -> RealtimeOutput:
    """获取全局实时输出实例"""
    global _realtime_output_instance
    if _realtime_output_instance is None:
        _realtime_output_instance = RealtimeOutput(output_dir)
    return _realtime_output_instance
