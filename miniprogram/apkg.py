"""
APKG Package Analyzer
微信小程序包分析工具
"""

import zipfile
import json
import re
from typing import Dict, List, Optional, Tuple

class PackageAnalyzer:
    """微信小程序包分析器"""
    
    def __init__(self, package_path: str):
        self.package_path = package_path
        self.config: Dict = {}
        self.api_domains: List[str] = []
        self.auth_domains: List[str] = []
        self.cloud_domains: List[str] = []
        self.subpackages: List[str] = []
        
    def analyze(self) -> Dict:
        """分析小程序包"""
        try:
            with zipfile.ZipFile(self.package_path, 'r') as zf:
                self._extract_config(zf)
                self._extract_domains(zf)
                self._extract_subpackages(zf)
        except Exception as e:
            return {"error": str(e)}
        
        return {
            "config": self.config,
            "api_domains": self.api_domains,
            "auth_domains": self.auth_domains,
            "cloud_domains": self.cloud_domains,
            "subpackages": self.subpackages
        }
    
    def _extract_config(self, zf: zipfile.ZipFile):
        """提取配置信息"""
        for filename in zf.namelist():
            if 'app.json' in filename or 'project.config.json' in filename:
                try:
                    content = zf.read(filename).decode('utf-8')
                    self.config = json.loads(content)
                except Exception:
                    pass
    
    def _extract_domains(self, zf: zipfile.ZipFile):
        """提取域名配置"""
        domain_patterns = [
            r'https?://[a-zA-Z0-9.-]+\.weixin\.qq\.com',
            r'https?://[a-zA-Z0-9.-]+\.servicewechat\.com',
            r'https?://[a-zA-Z0-9.-]+\.qcloud\.com',
            r'https?://[a-zA-Z0-9.-]+\.myqcloud\.com',
            r'https?://[a-zA-Z0-9.-]+\.tcb\.qq\.com',
        ]
        
        for filename in zf.namelist():
            if filename.endswith(('.js', '.json', '.wxml'):
                try:
                    content = zf.read(filename).decode('utf-8', errors='ignore')
                    for pattern in domain_patterns:
                        matches = re.findall(pattern, content)
                        for match in matches:
                            if 'api' in match:
                                self.api_domains.append(match)
                            elif 'auth' in match or 'open' in match:
                                self.auth_domains.append(match)
                            elif 'cloud' in match or 'tcb' in match:
                                self.cloud_domains.append(match)
                except Exception:
                    pass
    
    def _extract_subpackages(self, zf: zipfile.ZipFile):
        """提取分包配置"""
        if 'app.json' in zf.namelist():
            try:
                content = zf.read('app.json').decode('utf-8')
                app_config = json.loads(content)
                subpackages = app_config.get('subPackages', [])
                self.subpackages = [pkg.get('root', '') for pkg in subpackages]
            except Exception:
                pass


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print('Usage: python apkg.py <package_path>')
        sys.exit(1)
    
    analyzer = PackageAnalyzer(sys.argv[1])
    result = analyzer.analyze()
    print(json.dumps(result, indent=2, ensure_ascii=False))
