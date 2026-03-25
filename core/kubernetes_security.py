#!/usr/bin/env python3
"""
Kubernetes安全检测模块 - 基于 FLUX v5.2.1
检测 K8s API Server/Dashboard/etcd/kubelet 等组件
"""

import logging
from typing import Dict, List, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class K8sVulnResult:
    """K8s安全漏洞结果"""
    vuln_type: str
    severity: str
    url: str
    component: str
    detail: str = ""
    evidence: str = ""
    cve_id: str = ""
    remediation: str = ""


class K8sSecurityTester:
    """Kubernetes安全测试器"""

    K8S_COMPONENTS = {
        "API Server": {
            "ports": [6443, 8080, 443],
            "paths": ["/api", "/apis", "/version", "/healthz"],
            "indicators": ["kubernetes", "k8s", "apiVersion"],
            "severity": "Critical"
        },
        "Dashboard": {
            "ports": [443, 8443, 9090],
            "paths": ["/", "/api/v1/login", "/api/v1/csrftoken/login"],
            "indicators": ["kubernetes-dashboard", "Dashboard", "k8s-dashboard"],
            "severity": "Critical"
        },
        "etcd": {
            "ports": [2379, 2380],
            "paths": ["/v2/keys", "/v3/cluster/member/list", "/version"],
            "indicators": ["etcdserver", "etcdcluster"],
            "severity": "Critical"
        },
        "kubelet": {
            "ports": [10250, 10255, 10248],
            "paths": ["/pods", "/runningpods", "/metrics", "/healthz"],
            "indicators": ["kubelet", "pod", "container"],
            "severity": "Critical"
        },
        "kube-proxy": {
            "ports": [10249, 10256],
            "paths": ["/metrics", "/healthz"],
            "indicators": ["kubeproxy", "kube-proxy"],
            "severity": "High"
        }
    }

    K8S_CVE_DATABASE = {
        "CVE-2018-1002102": {
            "component": "API Server",
            "description": "kube-apiserver权限提升漏洞",
            "severity": "High",
            "check_path": "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"
        },
        "CVE-2019-11247": {
            "component": "API Server",
            "description": "API Server访问自定义资源子范围漏洞",
            "severity": "High",
            "check_path": "/apis/apiextensions.k8s.io/v1beta1/customresourcedefinitions"
        },
        "CVE-2020-8554": {
            "component": "API Server",
            "description": "Kubernetes中间人攻击漏洞",
            "severity": "Medium",
            "check_path": "/api/v1/services"
        },
    }

    def __init__(self, session=None, timeout: int = 15):
        self.session = session
        self.timeout = timeout
        self.findings: List[K8sVulnResult] = []

    def scan_k8s_components(self, base_url: str) -> List[K8sVulnResult]:
        findings = []
        import requests
        parsed = requests.utils.urlparse(base_url)
        host = parsed.hostname

        if not host:
            return findings

        logger.info(f"[*] 开始K8s组件扫描: {host}")

        for component_name, component_info in self.K8S_COMPONENTS.items():
            for port in component_info.get("ports", []):
                for path in component_info.get("paths", [])[:2]:
                    url = f"http://{host}:{port}{path}"
                    try:
                        response = self.session.get(url, timeout=5, verify=False)
                        content = response.text.lower()

                        for indicator in component_info.get("indicators", []):
                            if indicator.lower() in content:
                                logger.info(f"[+] 发现K8s组件: {component_name} at {url}")

                                finding = self._test_unauthorized_access(url, component_name, component_info)
                                if finding:
                                    findings.append(finding)
                                break
                    except:
                        pass

        return findings

    def _test_unauthorized_access(self, url: str, component: str, info: Dict) -> Optional[K8sVulnResult]:
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                return K8sVulnResult(
                    vuln_type="未授权访问",
                    severity=info.get("severity", "High"),
                    url=url,
                    component=component,
                    detail=f"{component} 允许未授权访问",
                    evidence=f"状态码: {response.status_code}"
                )
        except:
            pass
        return None


__all__ = ['K8sSecurityTester', 'K8sVulnResult']
