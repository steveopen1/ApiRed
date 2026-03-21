"""
Selenium CDP Collector
基于 Selenium 的 Chrome DevTools Protocol 采集器
支持获取 performance logs、network logs
"""

import json
import time
import warnings
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass
from urllib.parse import urlparse


warnings.filterwarnings("ignore")


@dataclass
class CDPResource:
    """CDP 采集的资源"""
    url: str
    resource_type: str
    referer: str
    method: str
    post_data: str = ""


class SeleniumCDPCollector:
    """
    Selenium CDP 采集器
    
    功能：
    1. 获取 Chrome performance logs
    2. 获取 Network logs
    3. 获取 JS 文件列表
    4. 获取 API 请求
    """
    
    def __init__(self):
        self.driver = None
        self.api_endpoints: Set[str] = set()
        self.js_files: Set[str] = set()
        self.cdp_resources: List[CDPResource] = []
    
    def create_driver(self, chromedriver_path: str = "/usr/bin/chromedriver") -> bool:
        """创建 Selenium WebDriver"""
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.service import Service
            from selenium.webdriver.chrome.options import Options
            from selenium.webdriver.support.ui import WebDriverWait
            
            options = Options()
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--headless')
            options.add_argument('--disable-gpu')
            options.add_argument('--window-size=1920x1080')
            options.add_argument('--ignore-certificate-errors')
            options.add_argument('--ignore-ssl-errors')
            options.set_capability('goog:loggingPrefs', {'performance': 'ALL'})
            
            service = Service(executable_path=chromedriver_path)
            self.driver = webdriver.Chrome(service=service, options=options)
            
            self.driver.execute_cdp_cmd(
                'Network.setExtraHTTPHeaders',
                {"headers": {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"}}
            )
            
            return True
        except Exception as e:
            print(f"Failed to create driver: {e}")
            return False
    
    def navigate(self, url: str, wait: int = 20) -> str:
        """导航到 URL 并等待"""
        if not self.driver:
            return ""
        
        try:
            self.driver.get(url)
            WebDriverWait(self.driver, wait).until(
                lambda d: d.execute_script("return document.readyState") == "complete"
            )
            time.sleep(2)
            return self.driver.current_url
        except Exception as e:
            print(f"Navigation failed: {e}")
            return ""
    
    def get_performance_logs(self) -> List[Dict]:
        """获取 performance logs"""
        if not self.driver:
            return []
        
        try:
            logs = self.driver.get_log('performance')
            return [json.loads(log['message']) for log in logs]
        except Exception:
            return []
    
    def process_network_events(self, logs: List[Dict]) -> List[CDPResource]:
        """处理网络事件"""
        resources = []
        
        for log in logs:
            try:
                message = log.get('message', {})
                method = message.get('method', '')
                
                if 'Network.requestWillBeSent' in method:
                    params = message.get('params', {})
                    request = params.get('request', {})
                    resource = CDPResource(
                        url=request.get('url', ''),
                        resource_type=self._check_url_type(request.get('url', ''),
                        referer=request.get('headers', {}).get('Referer', ''),
                        method=request.get('method', 'GET'),
                        post_data=request.get('postData', '')
                    )
                    
                    if resource.url:
                        resources.append(resource)
                        
                        if resource.url.endswith('.js'):
                            self.js_files.add(resource.url)
                        
                        if self._is_api_url(resource.url):
                            self.api_endpoints.add(resource.url)
                
                self.cdp_resources = resources
            except Exception:
                pass
        
        return resources
    
    def _check_url_type(self, url: str) -> str:
        """检查 URL 类型"""
        if not url or url.count('?') > 1 or not url.startswith('http'):
            return ''
        
        url_parse = urlparse(url)
        path = url_parse.path
        
        if path.lower().endswith('.js'):
            return 'js'
        
        if '.' not in path.lower().rsplit('/')[-1]:
            return 'no_js'
        
        return ''
    
    def _is_api_url(self, url: str) -> bool:
        """判断是否为 API URL"""
        api_patterns = [
            '/api/', '/rest/', '/v1/', '/v2/',
            '/callComponent/', '/rpc/', '/graphql'
        ]
        return any(p in url for p in api_patterns)
    
    def collect_all(self, url: str) -> Dict[str, List]:
        """采集所有资源"""
        if not self.create_driver():
            return {'js_files': [], 'api_endpoints': [], 'resources': []}
        
        self.navigate(url)
        logs = self.get_performance_logs()
        resources = self.process_network_events(logs)
        
        return {
            'js_files': list(self.js_files),
            'api_endpoints': list(self.api_endpoints),
            'resources': [r.__dict__ for r in resources]
        }
    
    def quit(self):
        """关闭 driver"""
        if self.driver:
            try:
                self.driver.quit()
            except Exception:
                pass


def create_cdp_collector() -> Optional[SeleniumCDPCollector]:
    """创建 CDP 采集器"""
    collector = SeleniumCDPCollector()
    if collector.create_driver():
        return collector
    return None
