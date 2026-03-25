#!/usr/bin/env python3
"""
容器安全检测模块 - 基于 FLUX v5.2.1
检测 Docker/Containerd 配置安全和容器逃逸风险
"""

import logging
from typing import Dict, List, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ContainerVulnResult:
    """容器安全漏洞结果"""
    vuln_type: str
    severity: str
    url: str
    runtime: str
    detail: str = ""
    evidence: str = ""
    cve_id: str = ""
    remediation: str = ""


class ContainerSecurityTester:
    """容器安全测试器"""

    RUNTIME_ENDPOINTS = {
        "Docker": {
            "ports": [2375, 2376],
            "endpoints": ["/containers/json", "/images/json", "/info"],
            "indicators": ["docker", "containers"],
            "severity": "Critical"
        },
        "Containerd": {
            "ports": [1338],
            "endpoints": ["/v1/containers", "/v1/images"],
            "indicators": ["containerd", "cri"],
            "severity": "Critical"
        },
    }

    CONTAINER_CVE_DATABASE = {
        "CVE-2019-5736": {
            "description": "runc容器逃逸漏洞",
            "severity": "Critical",
            "cvss": 8.6
        },
        "CVE-2020-15257": {
            "description": "containerd-shim ASLR绕过",
            "severity": "High",
            "cvss": 5.2
        },
        "CVE-2021-30465": {
            "description": "runc挂载传播逃逸漏洞",
            "severity": "High",
            "cvss": 7.6
        },
    }

    ESCAPE_RISK_CONFIGS = {
        "privileged": {
            "pattern": r'"Privileged"\s*:\s*true',
            "severity": "Critical",
            "description": "特权容器可直接逃逸"
        },
        "docker_sock": {
            "pattern": r'/var/run/docker\.sock',
            "severity": "Critical",
            "description": "挂载Docker Socket可在容器内控制主机"
        },
    }

    def __init__(self, session=None, timeout: int = 15):
        self.session = session
        self.timeout = timeout
        self.findings: List[ContainerVulnResult] = []

    def scan_container_runtimes(self, host: str) -> List[ContainerVulnResult]:
        findings = []

        for runtime_name, runtime_info in self.RUNTIME_ENDPOINTS.items():
            for port in runtime_info.get("ports", []):
                for endpoint in runtime_info.get("endpoints", [])[:1]:
                    url = f"http://{host}:{port}{endpoint}"
                    try:
                        response = self.session.get(url, timeout=5, verify=False)
                        if response.status_code in [200, 201]:
                            logger.info(f"[+] 发现容器运行时: {runtime_name} at {url}")
                            findings.append(ContainerVulnResult(
                                vuln_type="未授权API访问",
                                severity=runtime_info.get("severity", "High"),
                                url=url,
                                runtime=runtime_name,
                                detail=f"{runtime_name} API允许未授权访问"
                            ))
                    except:
                        pass

        return findings

    def check_container_config(self, config_text: str) -> List[ContainerVulnResult]:
        findings = []

        for risk_name, risk_info in self.ESCAPE_RISK_CONFIGS.items():
            import re
            if re.search(risk_info["pattern"], config_text):
                findings.append(ContainerVulnResult(
                    vuln_type="容器逃逸风险",
                    severity=risk_info["severity"],
                    url="",
                    runtime="Docker",
                    detail=risk_info["description"],
                    evidence=f"配置项: {risk_name}"
                ))

        return findings


__all__ = ['ContainerSecurityTester', 'ContainerVulnResult']
