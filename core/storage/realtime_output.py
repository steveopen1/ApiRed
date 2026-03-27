"""
Realtime Output Module
实时输出模块 - 终端日志和文件输出
"""

import os
import logging
import threading
from typing import Set, List, Optional
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class RealtimeOutput:
    """
    实时输出器
    
    功能：
    1. 终端实时显示日志
    2. 文件实时输出
       - URLs
       - 域名
       - APIs
       - IPs / IP:port
       - 敏感信息
    """
    
    def __init__(self, output_dir: str = "./output"):
        self.output_dir = output_dir
        self._lock = threading.Lock()
        
        self.urls_file = None
        self.domains_file = None
        self.apis_file = None
        self.ips_file = None
        self.sensitive_file = None
        
        self._init_files()
    
    def _init_files(self):
        """初始化输出文件"""
        os.makedirs(self.output_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        self.urls_file = os.path.join(self.output_dir, f"realtime_urls_{timestamp}.txt")
        self.domains_file = os.path.join(self.output_dir, f"realtime_domains_{timestamp}.txt")
        self.apis_file = os.path.join(self.output_dir, f"realtime_apis_{timestamp}.txt")
        self.ips_file = os.path.join(self.output_dir, f"realtime_ips_{timestamp}.txt")
        self.sensitive_file = os.path.join(self.output_dir, f"realtime_sensitive_{timestamp}.txt")
        
        for f in [self.urls_file, self.domains_file, self.apis_file, self.ips_file, self.sensitive_file]:
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
    
    def output_domain(self, domain: str, domain_type: str = "subdomain"):
        """输出域名"""
        if not domain:
            return
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_msg = f"[{timestamp}] [{domain_type.upper()}] {domain}"
        
        logger.info(log_msg)
        
        with self._lock:
            with open(self.domains_file, 'a', encoding='utf-8') as f:
                f.write(f"{domain}\n")
    
    def output_api(self, api_path: str, method: str = "GET", source: str = ""):
        """输出 API 路径"""
        if not api_path:
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
    
    def output_js(self, js_url: str, size: int = 0):
        """输出 JS URL"""
        if not js_url:
            return
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        size_str = f"({size} bytes)" if size else ""
        log_msg = f"[{timestamp}] [JS] {js_url} {size_str}"
        
        logger.info(log_msg)
    
    def output_vulnerability(self, vuln_type: str, endpoint: str, severity: str = "medium"):
        """输出漏洞"""
        if not vuln_type or not endpoint:
            return
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_msg = f"[{timestamp}] [VULN:{severity.upper()}] {vuln_type} @ {endpoint}"
        
        logger.warning(log_msg)
    
    def get_output_files(self) -> dict:
        """获取所有输出文件路径"""
        return {
            'urls': self.urls_file,
            'domains': self.domains_file,
            'apis': self.apis_file,
            'ips': self.ips_file,
            'sensitive': self.sensitive_file
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
