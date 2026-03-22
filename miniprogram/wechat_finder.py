"""
WeChat Mini Program Finder
微信小程序API发现器
"""

import re
import json
import zipfile
import tempfile
import os
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from urllib.parse import urlparse

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False


@dataclass
class MiniProgramInfo:
    """小程序信息"""
    appid: str
    name: str
    version: str
    package_path: Optional[str] = None
    api_domains: List[str] = None
    auth_domains: List[str] = None
    cloud_api_endpoints: List[str] = None
    
    def __post_init__(self):
        if self.api_domains is None:
            self.api_domains = []
        if self.auth_domains is None:
            self.auth_domains = []
        if self.cloud_api_endpoints is None:
            self.cloud_api_endpoints = []


class WeChatMiniProgramFinder:
    """
    微信小程序API发现器
    支持从URL、AppID或包文件发现小程序的API端点
    """
    
    WX_API_PATTERNS = [
        r'https?://api\.weixin\.qq\.com/',
        r'https?://.*\.servicewechat\.com/',
        r'https?://.*\.wxsession\.com/',
        r'https?://.*\.weapp-.*\.tencentcs\.com/',
        r'https?://.*\.qcloud\.com/',
        r'https?://.*\.myqcloud\.com/',
    ]
    
    WX_AUTH_PATTERNS = [
        r'https?://open\.weixin\.qq\.com/',
        r'https?://api\.weixin\.qq\.com/auth/',
    ]
    
    WX_CLOUD_PATTERNS = [
        r'https?://api\.tcb\.qq\.com/',
        r'https?://api\.cloud\.qq\.com/',
        r'https?://tcb-api\.tencentyun\.com/',
    ]
    
    def __init__(self):
        self.discovered_apis: List[str] = []
        self.discovered_auth: List[str] = []
        self.discovered_cloud: List[str] = []
    
    async def find_from_url(self, url: str) -> MiniProgramInfo:
        """
        从URL发现小程序
        
        Args:
            url: 小程序URL或AppID
            
        Returns:
            MiniProgramInfo: 小程序信息
        """
        appid = self._extract_appid_from_url(url)
        
        if not appid:
            appid = url if self._looks_like_appid(url) else ""
        
        return MiniProgramInfo(
            appid=appid,
            name="Discovered App",
            version="1.0.0",
            package_path=None
        )
    
    async def find_from_appid(self, appid: str) -> MiniProgramInfo:
        """
        从AppID发现小程序
        
        Args:
            appid: 微信AppID
            
        Returns:
            MiniProgramInfo: 小程序信息
        """
        return MiniProgramInfo(
            appid=appid,
            name=f"Mini Program {appid[:8]}",
            version="1.0.0"
        )
    
    def analyze_package(self, apk_path: str) -> MiniProgramInfo:
        """
        分析小程序包文件
        
        Args:
            apk_path: 小程序包路径 (.wxapkg)
            
        Returns:
            MiniProgramInfo: 小程序信息
        """
        if not os.path.exists(apk_path):
            raise FileNotFoundError(f"Package not found: {apk_path}")
        
        appid = ""
        name = "Unknown"
        version = "1.0.0"
        api_domains = []
        auth_domains = []
        
        try:
            if apk_path.endswith('.wxapkg'):
                appid, name, version, api_domains, auth_domains = self._parse_wxapkg(apk_path)
            elif apk_path.endswith('.apkg'):
                appid, name, version, api_domains, auth_domains = self._parse_wxapkg(apk_path)
            else:
                with zipfile.ZipFile(apk_path, 'r') as zf:
                    config = self._parse_mini_config(zf)
                    if config:
                        appid = config.get('appid', appid)
                        name = config.get('name', name)
                        version = config.get('version', version)
                        api_domains = config.get('apiDomains', [])
                        auth_domains = config.get('authDomains', [])
        except Exception as e:
            print(f"Failed to analyze package: {e}")
        
        return MiniProgramInfo(
            appid=appid,
            name=name,
            version=version,
            package_path=apk_path,
            api_domains=api_domains,
            auth_domains=auth_domains
        )
    
    def _parse_wxapkg(self, wxapkg_path: str) -> tuple:
        """解析微信小程序包"""
        appid = ""
        name = "Unknown"
        version = "1.0.0"
        api_domains = []
        auth_domains = []
        
        try:
            with open(wxapkg_path, 'rb') as f:
                content = f.read()
            
                try:
                    text_content = content.decode('utf-8', errors='ignore')
                    
                    appid_match = re.search(r'"appid"\s*:\s*"([^"]+)"', text_content)
                    if appid_match:
                        appid = appid_match.group(1)
                    
                    name_match = re.search(r'"appname"\s*:\s*"([^"]+)"', text_content)
                    if name_match:
                        name = name_match.group(1)
                    
                    for pattern in self.WX_API_PATTERNS:
                        matches = re.findall(pattern, text_content)
                        api_domains.extend(matches)
                    
                    for pattern in self.WX_AUTH_PATTERNS:
                        matches = re.findall(pattern, text_content)
                        auth_domains.extend(matches)
                    
                    for pattern in self.WX_CLOUD_PATTERNS:
                        matches = re.findall(pattern, text_content)
                        self.discovered_cloud.extend(matches)
                
                except Exception as e:
                    print(f"Failed to parse wxapkg content: {e}")
        
        except Exception as e:
            print(f"Failed to read wxapkg: {e}")
        
        return appid, name, version, list(set(api_domains)), list(set(auth_domains))
    
    def _parse_mini_config(self, zip_file: zipfile.ZipFile) -> Optional[dict]:
        """解析小程序配置文件"""
        config_files = ['app.json', 'project.config.json', 'config.json']
        
        for config_file in config_files:
            try:
                content = zip_file.read(config_file).decode('utf-8')
                return json.loads(content)
            except Exception:
                continue
        
        return None
    
    async def discover_apis(self, mini_program: MiniProgramInfo) -> List[Dict[str, Any]]:
        """
        发现小程序API端点
        
        Args:
            mini_program: 小程序信息
            
        Returns:
            List[Dict]: API端点列表
        """
        apis = []
        
        for domain in mini_program.api_domains:
            apis.append({
                "url": domain,
                "method": "GET",
                "type": "api_domain",
                "auth": "unknown"
            })
        
        for domain in mini_program.auth_domains:
            apis.append({
                "url": domain,
                "method": "GET",
                "type": "auth_domain",
                "auth": "wechat_oauth"
            })
        
        for endpoint in self.discovered_cloud:
            apis.append({
                "url": endpoint,
                "method": "POST",
                "type": "cloud_api",
                "auth": "cloud_tencent"
            })
        
        return apis
    
    def _extract_appid_from_url(self, url: str) -> str:
        """从URL提取AppID"""
        if 'appid=' in url:
            match = re.search(r'appid=([^&\s]+)', url)
            if match:
                return match.group(1)
        
        if 'id=' in url and 'wechat' in url.lower():
            match = re.search(r'id=([^&\s]+)', url)
            if match:
                return match.group(1)
        
        return ""
    
    def _looks_like_appid(self, text: str) -> bool:
        """判断是否像AppID"""
        return bool(re.match(r'^wx[0-9a-f]{16}$', text, re.I))


async def main():
    """命令行入口"""
    import argparse
    
    parser = argparse.ArgumentParser(description='WeChat Mini Program API Finder')
    parser.add_argument('--url', help='Mini Program URL or AppID')
    parser.add_argument('--appid', help='Mini Program AppID')
    parser.add_argument('--package', help='Mini Program package file (.wxapkg)')
    parser.add_argument('--output', '-o', help='Output file')
    
    args = parser.parse_args()
    
    finder = WeChatMiniProgramFinder()
    
    if args.package:
        info = finder.analyze_package(args.package)
    elif args.appid:
        info = await finder.find_from_appid(args.appid)
    elif args.url:
        info = await finder.find_from_url(args.url)
    else:
        parser.print_help()
        return
    
    print(f"AppID: {info.appid}")
    print(f"Name: {info.name}")
    print(f"Version: {info.version}")
    print(f"API Domains: {len(info.api_domains)}")
    print(f"Auth Domains: {len(info.auth_domains)}")
    
    apis = await finder.discover_apis(info)
    print(f"Total APIs: {len(apis)}")
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump({
                'info': {
                    'appid': info.appid,
                    'name': info.name,
                    'version': info.version
                },
                'apis': apis
            }, f, indent=2)
        print(f"Results saved to {args.output}")


if __name__ == '__main__':
    import asyncio
    asyncio.run(main())
