"""
Sensitive Path Fuzzing Module
敏感路径 Fuzzing 模块
参考 FLUX 敏感路径 fuzzing 功能
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional, Set
from urllib.parse import urljoin
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class PathFuzzFinding:
    """路径 fuzzing 发现"""
    path: str
    status_code: int
    content_length: int
    is_sensitive: bool
    severity: str


class SensitivePathFuzzer:
    """
    敏感路径 Fuzzer
    
    发现敏感路径和配置文件的 fuzzing
    """
    
    SENSITIVE_PATHS = [
        '.env',
        '.env.local',
        '.env.production',
        '.git/config',
        '.git/HEAD',
        '.git/index',
        '.git/logs/HEAD',
        '.svn/entries',
        '.hg/requires',
        '.DS_Store',
        'Thumbs.db',
        'desktop.ini',
        'config.yml',
        'config.yaml',
        'settings.py',
        'settings.json',
        'wp-config.php',
        'configuration.php',
        'settings.php',
        'database.yml',
        'database.yaml',
        'credentials.json',
        'secrets.json',
        '.htpasswd',
        '.htaccess',
        'web.config',
        'app.config',
        '.npmrc',
        '.yarnrc',
        'package.json',
        'package-lock.json',
        'yarn.lock',
        'composer.lock',
        'Gemfile.lock',
        'requirements.txt',
        'Pipfile.lock',
        'debug.log',
        'error.log',
        'access.log',
        'application.log',
        'server.log',
        'test.log',
        '.bash_history',
        '.zsh_history',
        '.bashrc',
        '.profile',
        '.ssh/authorized_keys',
        '.ssh/id_rsa',
        '.ssh/id_rsa.pub',
        'id_rsa',
        'id_dsa',
        'private_key.pem',
        'public_key.pem',
        'README.md',
        'CHANGELOG.md',
        'LICENSE.md',
        'version.txt',
        'build.txt',
        'release.txt',
    ]
    
    ADMIN_PATHS = [
        'admin/',
        'admin/index.php',
        'admin/login',
        'admin/dashboard',
        'admin/config',
        'admin/settings',
        'administrator/',
        'administrator/index.php',
        'manage/',
        'management/',
        'cpanel/',
        'webmail/',
        'phpmyadmin/',
        'phpMyAdmin/',
        'mysql-admin/',
        'w00tw00t.at.blackukrpc.net',
        '.git',
        '.git/config',
        '.git/HEAD',
        '.env',
        '.htaccess',
        '.htpasswd',
        'wp-admin',
        'wp-login.php',
        'wordpress/wp-admin',
        'administrator',
        'admin.php',
        'login.php',
        'dashboard',
        'webconsole',
        'console',
        'backend',
        'console/login',
        '管理中心',
        '管理员',
        '登录',
        '后台',
        'wp-admin',
        'admin',
    ]
    
    BACKUP_PATHS = [
        '.bak',
        '.backup',
        '.backup.sql',
        '.sql.bak',
        '.tar.gz',
        '.zip',
        '.rar',
        '.7z',
        '.old',
        '.orig',
        '.save',
        '.copy',
        '.tmp',
        '.swp',
        '~',
        '.git/backup',
        'backup/',
        'backups/',
        'dump.sql',
        'database.sql',
        'db.sql',
        'data.sql',
    ]
    
    CONFIG_PATHS = [
        '/nginx.conf',
        '/apache.conf',
        '/httpd.conf',
        '/tomcat-users.xml',
        '/server.xml',
        '/context.xml',
        '/web.xml',
        '/application.properties',
        '/application.yml',
        '/application.yaml',
        '/bootstrap.yml',
        '/bootstrap.properties',
        '/log4j.properties',
        '/log4j.xml',
        '/logback.xml',
        '/logback-spring.xml',
        '/jetty.xml',
        'config/application.properties',
        'config/application.yml',
    ]
    
    API_CONFIGS = [
        'api/config',
        'api/keys',
        'api/v1/config',
        'api/v2/config',
        'api/v3/config',
        'config/api_keys.json',
        'config/credentials.json',
    ]
    
    def __init__(self, http_client=None):
        self.http_client = http_client
        self.findings: List[PathFuzzFinding] = []
    
    async def fuzz(
        self,
        base_url: str,
        paths: List[str] = None,
        severity_filter: str = 'all'
    ) -> List[PathFuzzFinding]:
        """
        Fuzz 敏感路径
        
        Args:
            base_url: 目标 URL
            paths: 自定义路径列表，None 则使用默认列表
            severity_filter: 严重程度过滤 (all/high/medium/low)
            
        Returns:
            List[PathFuzzFinding]: 发现的问题
        """
        if paths is None:
            paths = (
                self.SENSITIVE_PATHS +
                self.ADMIN_PATHS +
                self.BACKUP_PATHS +
                self.CONFIG_PATHS +
                self.API_CONFIGS
            )
        
        if self.http_client is None:
            return self.findings
        
        async def check_path(path: str) -> Optional[PathFuzzFinding]:
            url = urljoin(base_url.rstrip('/') + '/', path.lstrip('/'))
            try:
                response = await self.http_client.request(url, 'GET', timeout=5)
                if response and response.status_code == 200:
                    is_sensitive = self._is_sensitive(path)
                    severity = self._get_severity(path, is_sensitive)
                    
                    if severity_filter != 'all' and severity != severity_filter:
                        return None
                    
                    finding = PathFuzzFinding(
                        path=path,
                        status_code=response.status_code,
                        content_length=len(response.content) if response.content else 0,
                        is_sensitive=is_sensitive,
                        severity=severity
                    )
                    self.findings.append(finding)
                    return finding
                    
            except Exception as e:
                logger.debug(f"Path fuzz error for {path}: {e}")
            
            return None
        
        tasks = [check_path(p) for p in paths]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        return self.findings
    
    def _is_sensitive(self, path: str) -> bool:
        """判断路径是否敏感"""
        path_lower = path.lower()
        
        sensitive_indicators = [
            '.env', '.git', '.svn', '.htaccess', 'config',
            'backup', '.bak', '.sql', '.log', '.key', '.pem',
            'secrets', 'credentials', 'password', 'admin', 'login',
            '.bash_history', '.ssh', 'wp-admin', 'phpmyadmin'
        ]
        
        return any(ind in path_lower for ind in sensitive_indicators)
    
    def _get_severity(self, path: str, is_sensitive: bool) -> str:
        """获取严重程度"""
        if not is_sensitive:
            return 'low'
        
        critical = ['.env', '.git/', '.htaccess', 'wp-config', 'secrets', 'credentials']
        high = ['admin', 'login', 'dashboard', 'backup', '.sql', '.log', '.ssh']
        medium = ['config', '.bak', '.old', '.cache']
        
        path_lower = path.lower()
        
        if any(c in path_lower for c in critical):
            return 'critical'
        if any(c in path_lower for c in high):
            return 'high'
        if any(c in path_lower for c in medium):
            return 'medium'
        
        return 'medium'
    
    def get_all_findings(self) -> List[PathFuzzFinding]:
        """获取所有发现"""
        return self.findings


async def fuzz_sensitive_paths(base_url: str, http_client=None) -> List[PathFuzzFinding]:
    """
    便捷函数：Fuzz 敏感路径
    """
    fuzzer = SensitivePathFuzzer(http_client)
    return await fuzzer.fuzz(base_url)
