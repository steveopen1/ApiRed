"""
Vulnerability Verification and PoC Generation Module
漏洞验证和 PoC 生成模块
参考 FLUX v4.1 漏洞验证模块
自动生成漏洞利用证明和影响评估
"""

import re
import json
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from urllib.parse import urlencode, urlparse

logger = logging.getLogger(__name__)


@dataclass
class VulnVerification:
    """漏洞验证结果"""
    vuln_type: str
    url: str
    payload: str
    verified: bool
    poc: str
    impact: str
    remediation: str


class VulnVerifier:
    """
    漏洞验证器
    
    支持验证：
    - SQL 注入
    - RCE
    - LFI
    - SSRF
    - 云元数据
    - 未授权访问
    """
    
    def __init__(self, http_client=None):
        self.http_client = http_client
    
    async def verify_sql_injection(self, url: str, params: Dict, method: str = 'POST') -> Optional[VulnVerification]:
        """
        验证 SQL 注入
        
        Returns:
            VulnVerification: 验证结果
        """
        if not self.http_client:
            return None
        
        try:
            baseline_resp = await self.http_client.request(
                url, method, data=params
            )
            baseline_content = baseline_resp.content.lower() if baseline_resp.content else ''
            
            test_params = params.copy()
            test_params[list(params.keys())[0]] = "' OR '1'='1"
            
            test_resp = await self.http_client.request(
                url, method, data=test_params
            )
            test_content = test_resp.content.lower() if test_resp.content else ''
            
            sql_errors = [
                'sql', 'mysql', 'oracle', 'postgresql', 'sqlite', 'mariadb',
                'syntax error', 'mysql_', 'mysqli_', 'ora-', 'sqlstate',
                'microsoft sql', 'odbc', 'sqlite_', 'psycopg2', 'pq_connect',
                'warning: mysql', 'fatal:', 'unterminated', 'quoted string',
            ]
            
            matched_errors = [e for e in sql_errors if e in test_content and e not in baseline_content]
            
            if matched_errors:
                poc = self._generate_sql_injection_poc(url, params, method)
                return VulnVerification(
                    vuln_type='SQL_INJECTION',
                    url=url,
                    payload=test_params[list(params.keys())[0]],
                    verified=True,
                    poc=poc,
                    impact='可导致数据泄露或数据库被控制',
                    remediation='使用参数化查询，避免 SQL 拼接'
                )
            
        except Exception as e:
            logger.debug(f"SQL injection verification failed: {e}")
        
        return None
    
    def _generate_sql_injection_poc(self, url: str, params: Dict, method: str) -> str:
        """生成 SQL 注入 PoC"""
        poc = f"""== SQL Injection PoC ==

请求信息:
URL: {url}
方法: {method}
参数: {json.dumps(params, ensure_ascii=False)}

漏洞验证:
1. 正常请求参数: {json.dumps(params, ensure_ascii=False)}
2. 测试 Payload: ' OR '1'='1
3. 如果响应包含数据库错误信息，则确认存在 SQL 注入

影响:
- 敏感数据泄露
- 数据篡改
- 数据库被控制

修复建议:
- 使用参数化查询
- 输入验证和过滤
- 最小权限原则配置数据库用户"""
        return poc
    
    async def verify_rce(self, url: str, params: Dict, method: str = 'POST') -> Optional[VulnVerification]:
        """
        验证 RCE
        
        Returns:
            VulnVerification: 验证结果
        """
        if not self.http_client:
            return None
        
        try:
            test_commands = ['echo apired_test', 'whoami', 'id']
            
            for cmd in test_commands:
                test_params = params.copy()
                test_params['cmd'] = cmd
                
                resp = await self.http_client.request(url, method, data=test_params)
                content = resp.content if resp.content else ''
                
                if 'apired_test' in content or 'uid=' in content or 'root' in content:
                    poc = self._generate_rce_poc(url, params, method, cmd)
                    return VulnVerification(
                        vuln_type='RCE',
                        url=url,
                        payload=cmd,
                        verified=True,
                        poc=poc,
                        impact='可执行任意系统命令',
                        remediation='避免命令拼接，使用安全的 API'
                    )
        
        except Exception as e:
            logger.debug(f"RCE verification failed: {e}")
        
        return None
    
    def _generate_rce_poc(self, url: str, params: Dict, method: str, cmd: str) -> str:
        """生成 RCE PoC"""
        return f"""== RCE PoC ==

请求信息:
URL: {url}
方法: {method}
参数: {json.dumps(params, ensure_ascii=False)}

漏洞验证:
测试命令: {cmd}
如果在响应中看到命令输出，则确认存在 RCE

影响:
- 服务器被完全控制
- 敏感数据泄露
- 横向移动

修复建议:
- 避免使用 system()/exec()/shell_exec() 等命令执行函数
- 使用安全的 API 替代系统命令
- 输入验证和过滤"""
    
    async def verify_ssrf(self, url: str, params: Dict, metadata_endpoint: str = 'http://169.254.169.254/') -> Optional[VulnVerification]:
        """
        验证 SSRF
        
        Returns:
            VulnVerification: 验证结果
        """
        if not self.http_client:
            return None
        
        try:
            test_params = params.copy()
            test_params['url'] = metadata_endpoint
            
            resp = await self.http_client.request(url, 'POST', data=test_params)
            content = resp.content if resp.content else ''
            
            ssrf_indicators = [
                'instance-id', 'ami-id', 'local-hostname', 'local-ipv4',
                'security-credentials', 'iam', 'access-key', '/meta-data/'
            ]
            
            matched = [ind for ind in ssrf_indicators if ind in content.lower()]
            
            if matched:
                return VulnVerification(
                    vuln_type='SSRF',
                    url=url,
                    payload=test_params.get('url', ''),
                    verified=True,
                    poc=self._generate_ssrf_poc(url, params),
                    impact='访问云元数据服务，泄露云凭据',
                    remediation='过滤用户输入的 URL，使用 safeurljoin 或白名单验证'
                )
        
        except Exception as e:
            logger.debug(f"SSRF verification failed: {e}")
        
        return None
    
    def _generate_ssrf_poc(self, url: str, params: Dict) -> str:
        """生成 SSRF PoC"""
        return f"""== SSRF PoC ==

请求信息:
URL: {url}
参数: {json.dumps(params, ensure_ascii=False)}

测试 Payload:
http://169.254.169.254/latest/meta-data/

验证方法:
1. 检查响应是否包含云元数据 (instance-id, ami-id 等)
2. 如果是 AWS 元数据端点，可能获取 IAM 凭据

影响:
- 云账号凭据泄露
- 云资源被控制
- 横向移动

修复建议:
- 验证用户输入的 URL 是否在白名单内
- 使用 urllib.parse 获取 URL 后验证 host
- 禁止访问内网 IP 或云元数据端点"""
    
    async def verify_lfi(self, url: str, params: Dict) -> Optional[VulnVerification]:
        """
        验证 LFI
        
        Returns:
            VulnVerification: 验证结果
        """
        if not self.http_client:
            return None
        
        try:
            test_paths = ['/etc/passwd', '../../../../etc/passwd', 'C:\\Windows\\win.ini']
            
            for path in test_paths:
                test_params = params.copy()
                test_params['file'] = path
                
                resp = await self.http_client.request(url, 'GET', params=test_params)
                
                if resp.status_code == 200:
                    content = resp.content if resp.content else ''
                    
                    if 'root:' in content or '[extensions]' in content:
                        return VulnVerification(
                            vuln_type='LFI',
                            url=url,
                            payload=path,
                            verified=True,
                            poc=self._generate_lfi_poc(url, params),
                            impact='读取服务器敏感文件',
                            remediation='避免路径拼接，使用白名单文件访问'
                        )
        
        except Exception as e:
            logger.debug(f"LFI verification failed: {e}")
        
        return None
    
    def _generate_lfi_poc(self, url: str, params: Dict) -> str:
        """生成 LFI PoC"""
        return f"""== LFI PoC ==

请求信息:
URL: {url}
参数: {json.dumps(params, ensure_ascii=False)}

测试 Payload:
/etc/passwd (Linux)
C:\\Windows\\win.ini (Windows)

验证方法:
1. 发送请求
2. 检查响应是否包含系统文件内容

影响:
- 敏感文件泄露
- 配置文件泄露
- SSH 密钥泄露

修复建议:
- 避免路径拼接
- 使用 realpath() 验证路径
- 白名单文件访问"""


def verify_vulnerability(vuln_type: str, url: str, params: Dict = None) -> Optional[str]:
    """
    便捷函数：生成漏洞 PoC
    
    Returns:
        str: PoC 文本
    """
    if vuln_type == 'sql_injection':
        return f"SQL Injection PoC:\nURL: {url}\nParams: {params}"
    elif vuln_type == 'rce':
        return f"RCE PoC:\nURL: {url}\nParams: {params}"
    elif vuln_type == 'ssrf':
        return f"SSRF PoC:\nURL: {url}\nParams: {params}"
    elif vuln_type == 'lfi':
        return f"LFI PoC:\nURL: {url}\nParams: {params}"
    else:
        return f"Vulnerability PoC for {vuln_type}"
