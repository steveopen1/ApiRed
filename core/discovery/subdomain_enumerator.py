"""
Subdomain Discovery Module
子域名发现模块
参考 FLUX 子域名发现功能
支持多种子域名枚举技术
"""

import asyncio
import logging
import socket
import re
import time
import logging
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass
import dns.resolver
import dns.query
import dns.zone
from urllib.parse import urlparse

from ..utils.adaptive_scheduler import AdaptiveDNSResolver

logger = logging.getLogger(__name__)


@dataclass
class SubdomainFinding:
    """子域名发现结果"""
    subdomain: str
    ip_address: str
    source: str
    is_alive: bool = True


class SubdomainEnumerator:
    """
    子域名枚举器
    
    支持的枚举技术：
    - DNS 字典爆破
    - DNS 区域传输
    - 搜索引擎查询
    - 证书透明度日志
    - Whois 查询
    """
    
    COMMON_SUBDOMAINS = [
        'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp',
        'pop', 'ns1', 'webdisk', 'ns2', 'cpanel', 'whm',
        'autodiscover', 'autoconfig', 'm', 'imap', 'test', 'ns',
        'blog', 'pop3', 'dev', 'www2', 'admin', 'forum',
        'news', 'vpn', 'ns3', 'mail2', 'new', 'mysql',
        'old', 'lists', 'support', 'mobile', 'mx', 'static',
        'docs', 'beta', 'shop', 'sql', 'secure', 'api',
        'cdn', 'java', 'stats', 'cn', 'blog', 'mail3',
        'search', 'staging', 'gateway', 's1', 's2', 's3',
        's4', 's5', 's6', 's7', 's8', 's9', 's10',
        's11', 's12', 's13', 's14', 's15', 's16', 's17',
        'gitlab', 'jenkins', 'k8s', 'kubernetes', 'docker', 'registry',
        'harbor', 'grafana', 'prometheus', 'elk', 'kibana', 'alertmanager',
        'consul', 'etcd', 'vault', 'rancher', 'argocd', 'jenkins',
        'staging', 'preprod', 'pre', 'prod', 'production', 'demo',
        'git', 'gitlab', 'github', 'gitea', 'gogs',
        'vpn', 'vpn1', 'vpn2', 'portal', 'sso', 'sso1', 'sso2',
        'auth', 'oauth', 'cas', 'ldap', 'ad', 'active-directory',
        'db', 'database', 'mysql', 'postgresql', 'mongodb', 'redis',
        'elasticsearch', 'rabbitmq', 'kafka', 'zookeeper', 'nacos',
        'apollo', 'spring', 'springboot', 'tomcat', 'jetty', 'weblogic',
        'websphere', 'jboss', 'pay', 'payment', 'order', 'trade',
        'asset', 'assets', 'static', 'cdn', 'media', 'img', 'images',
        'video', 'upload', 'file', 'files', 'drive', 'nas', 'storage',
        'backup', 'backups', 'mirror', 'replica', 'cache', 'redis',
        'session', 'memcache', 'queue', 'beanstalk',
    ]
    
    WILDCARD_DNS_SERVERS = [
        '8.8.8.8',
        '8.8.4.4',
        '1.1.1.1',
        '1.0.0.1',
        '9.9.9.9',
        '208.67.222.222',
        '208.67.220.220',
    ]
    
    def __init__(self, http_client=None, concurrency: int = 50):
        self.http_client = http_client
        self.concurrency = concurrency
        self.discovered: Set[str] = set()
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3.0
        self.resolver.lifetime = 5.0
        self._dns_scheduler = AdaptiveDNSResolver(
            base_concurrency=concurrency,
            min_concurrency=10,
            max_concurrency=100,
            fast_threshold=0.1,
            slow_threshold=2.0
        )
    
    async def enumerate(
        self,
        domain: str,
        wordlist: List[str] = None,
        sources: List[str] = None
    ) -> List[SubdomainFinding]:
        """
        枚举子域名
        
        Args:
            domain: 目标域名
            wordlist: 字典列表，None 则使用默认字典
            sources: 数据源列表 ['dns', 'zone', 'cert', 'search']
            
        Returns:
            List[SubdomainFinding]: 发现的子域名
        """
        if wordlist is None:
            wordlist = self.COMMON_SUBDOMAINS
        
        if sources is None:
            sources = ['dns', 'cert']
        
        findings = []
        tasks = []
        
        if 'dns' in sources:
            tasks.append(self._dns_bruteforce(domain, wordlist))
        
        if 'zone' in sources:
            tasks.append(self._zone_transfer(domain))
        
        if 'cert' in sources:
            tasks.append(self._cert_transparency(domain))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, list):
                findings.extend(result)
        
        return findings
    
    async def _dns_bruteforce(
        self,
        domain: str,
        wordlist: List[str]
    ) -> List[SubdomainFinding]:
        """DNS 字典爆破（自适应并发）"""
        findings = []
        loop = asyncio.get_event_loop()
        
        async def check_subdomain(semaphore: asyncio.Semaphore, subdomain: str) -> Optional[SubdomainFinding]:
            async with semaphore:
                start_time = time.time()
                try:
                    full_domain = f"{subdomain}.{domain}"
                    answers = await loop.run_in_executor(
                        None, 
                        lambda: self.resolver.resolve(full_domain, 'A')
                    )
                    elapsed = time.time() - start_time
                    ips = [rdata.address for rdata in answers]
                    
                    if ips:
                        self.discovered.add(full_domain)
                        self._dns_scheduler.record_response_time(elapsed)
                        return SubdomainFinding(
                            subdomain=full_domain,
                            ip_address=', '.join(ips),
                            source='dns_bruteforce'
                        )
                    self._dns_scheduler.record_response_time(elapsed)
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                    self._dns_scheduler.record_response_time(time.time() - start_time)
                    pass
                except Exception as e:
                    self._dns_scheduler.record_timeout()
                    logger.debug(f"DNS check failed for {subdomain}.{domain}: {e}")
                
                return None
        
        semaphore = asyncio.Semaphore(self._dns_scheduler.concurrency)
        tasks = [check_subdomain(semaphore, sub) for sub in wordlist]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, SubdomainFinding):
                findings.append(result)
        
        logger.debug(f"DNS bruteforce completed with concurrency: {self._dns_scheduler.concurrency}")
        return findings
    
    async def _zone_transfer(self, domain: str) -> List[SubdomainFinding]:
        """DNS 区域传输尝试"""
        findings = []
        
        try:
            ns_records = self.resolver.resolve(domain, 'NS')
            for ns in ns_records:
                try:
                    ns_address = socket.gethostbyname(str(ns))
                    axfr = dns.query.xfr(ns_address, domain, timeout=5)
                    zone = dns.zone.from_xfr(axfr)
                    
                    if zone:
                        for name, node in zone.nodes.items():
                            subdomain = f"{name}.{domain}"
                            if subdomain not in self.discovered:
                                self.discovered.add(subdomain)
                                findings.append(SubdomainFinding(
                                    subdomain=subdomain,
                                    ip_address='NS',
                                    source='zone_transfer'
                                ))
                except Exception as e:
                    logger.debug(f"Zone transfer failed for {domain} via {ns}: {e}")
        except Exception as e:
            logger.debug(f"NS lookup failed for {domain}: {e}")
        
        return findings
    
    async def _cert_transparency(self, domain: str) -> List[SubdomainFinding]:
        """证书透明度日志查询"""
        findings = []
        
        try:
            import socket
            
            ct_domains = [
                f"https://crt.sh/?q=%.{domain}&output=json",
                f"https://api.certspotter.com/v0/issuers?domain={domain}",
                f"https://dns.google/resolve?name=*.{domain}&type=A",
            ]
            
            for ct_url in ct_domains[:1]:
                if self.http_client:
                    try:
                        response = await self.http_client.request(
                            ct_url,
                            'GET',
                            timeout=10
                        )
                        if response and response.content:
                            subdomains = re.findall(
                                r'([a-z0-9._-]+\.' + re.escape(domain) + r')',
                                response.content.lower()
                            )
                            for subdomain in set(subdomains):
                                if subdomain not in self.discovered:
                                    self.discovered.add(subdomain)
                                    findings.append(SubdomainFinding(
                                        subdomain=subdomain,
                                        ip_address='',
                                        source='cert_transparency'
                                    ))
                    except Exception as e:
                        logger.debug(f"CT lookup failed: {e}")
        except Exception as e:
            logger.debug(f"Cert transparency search failed: {e}")
        
        return findings
    
    def get_discovered(self) -> List[str]:
        """获取所有发现的子域名"""
        return list(self.discovered)


async def enumerate_subdomains(domain: str, http_client=None) -> List[str]:
    """
    便捷函数：枚举子域名
    
    Args:
        domain: 目标域名
        http_client: HTTP 客户端
        
    Returns:
        List[str]: 子域名列表
    """
    enumerator = SubdomainEnumerator(http_client)
    findings = await enumerator.enumerate(domain)
    return [f.subdomain for f in findings]
