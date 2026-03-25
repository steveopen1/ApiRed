#!/usr/bin/env python3
"""
CI/CD配置安全检测模块 - 基于 FLUX v5.2.1
检测 GitLab CI/Jenkins/GitHub Actions 等配置泄露
"""

import re
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class CICDVulnResult:
    """CI/CD安全漏洞结果"""
    vuln_type: str
    severity: str
    url: str
    component: str
    detail: str = ""
    evidence: str = ""
    remediation: str = ""


class CICDScanner:
    """CI/CD配置泄露检测器"""

    CICD_CONFIG_FILES = {
        "GitLab CI": [
            ".gitlab-ci.yml",
            ".gitlab-ci.yaml",
        ],
        "Jenkins": [
            "Jenkinsfile",
            "jenkins/config.xml",
        ],
        "GitHub Actions": [
            ".github/workflows/",
        ],
        "Docker": [
            "Dockerfile",
            "docker-compose.yml",
        ],
        "Kubernetes": [
            "deployment.yaml",
            "configmap.yaml",
            "secret.yaml",
        ],
    }

    CICD_SECRET_PATTERNS = {
        "GitLab Token": {
            "pattern": r'glpat-[0-9a-zA-Z\-_]{20}',
            "severity": "Critical"
        },
        "Jenkins API Token": {
            "pattern": r'[0-9a-f]{32}',
            "severity": "High"
        },
        "Travis CI Token": {
            "pattern": r'travisci_[0-9a-zA-Z]{20,}',
            "severity": "Critical"
        },
        "CircleCI Token": {
            "pattern": r'circleci_[0-9a-f]{40}',
            "severity": "Critical"
        },
        "Docker Hub Token": {
            "pattern": r'dckr_pat_[0-9a-zA-Z_-]{27,}',
            "severity": "Critical"
        },
        "npm Token": {
            "pattern": r'npm_[A-Za-z0-9]{36}',
            "severity": "High"
        },
        "Slack Webhook": {
            "pattern": r'https://hooks\.slack\.com/services/[A-Za-z0-9+/]+',
            "severity": "Medium"
        },
    }

    def __init__(self, session=None, timeout: int = 15):
        self.session = session
        self.timeout = timeout
        self.findings: List[CICDVulnResult] = []

    def scan_cicd_configs(self, base_url: str) -> List[CICDVulnResult]:
        findings = []
        parsed_url = base_url.rstrip('/')

        for cicd_type, paths in self.CICD_CONFIG_FILES.items():
            for path in paths:
                url = f"{parsed_url}/{path}"
                try:
                    response = self.session.get(url, timeout=self.timeout, verify=False)
                    if response.status_code == 200:
                        logger.info(f"[+] 发现CI/CD配置: {cicd_type} at {url}")

                        secrets = self._scan_for_secrets(response.text)
                        for secret_type, secret_info in secrets.items():
                            findings.append(CICDVulnResult(
                                vuln_type="敏感信息泄露",
                                severity=secret_info["severity"],
                                url=url,
                                component=cicd_type,
                                detail=f"发现{secret_type}",
                                evidence=secret_info["evidence"]
                            ))
                except:
                    pass

        return findings

    def _scan_for_secrets(self, content: str) -> Dict:
        found_secrets = {}

        for secret_name, secret_info in self.CICD_SECRET_PATTERNS.items():
            pattern = secret_info["pattern"]
            matches = re.findall(pattern, content)
            if matches:
                found_secrets[secret_name] = {
                    "severity": secret_info["severity"],
                    "evidence": f"匹配到 {len(matches)} 处"
                }

        return found_secrets


__all__ = ['CICDScanner', 'CICDVulnResult']
