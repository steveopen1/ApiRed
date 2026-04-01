"""
Enhanced Report Generator Module
增强报告生成器 - 分层报告、POC生成
"""

import json
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class Severity(Enum):
    """漏洞严重等级"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class VulnCategory(Enum):
    """漏洞类别"""
    INJECTION = "injection"
    AUTH = "authentication"
    SENSITIVE_DATA = "sensitive_data"
    CONFIG = "configuration"
    NETWORK = "network"
    ENUMERATION = "enumeration"
    ACCESS_CONTROL = "access_control"
    OTHER = "other"


@dataclass
class POC:
    """漏洞验证代码"""
    request: str = ""  # HTTP 请求
    response: str = ""  # 响应示例
    command: str = ""  # 命令行 POC
    curl: str = ""  # curl 命令


@dataclass
class Remediation:
    """修复建议"""
    immediate: str = ""  # 立即修复
    short_term: str = ""  # 短期修复
    long_term: str = ""  # 长期修复


@dataclass
class Vulnerability:
    """漏洞"""
    name: str
    severity: Severity
    category: VulnCategory
    description: str
    url: str
    method: str = "GET"
    payload: str = ""
    poc: POC = field(default_factory=POC)
    remediation: Remediation = field(default_factory=Remediation)
    evidence: str = ""
    references: List[str] = field(default_factory=list)
    cwe: str = ""
    cvss: str = ""


@dataclass
class SensitiveFinding:
    """敏感信息发现"""
    info_type: str  # internal_ip, email, phone, credential
    value: str
    source: str  # js, response, header
    location: str  # 文件/URL
    severity: Severity
    description: str


@dataclass
class EnhancedReport:
    """增强扫描报告"""
    target: str
    scan_time: str
    total_apis: int = 0
    tested_apis: int = 0
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    sensitive_findings: List[SensitiveFinding] = field(default_factory=list)
    waf_detected: List[str] = field(default_factory=list)
    server_info: Dict[str, str] = field(default_factory=dict)
    api_prefixes: List[str] = field(default_factory=list)
    statistics: Dict[str, int] = field(default_factory=dict)
    
    def get_by_severity(self, severity: Severity) -> List[Vulnerability]:
        return [v for v in self.vulnerabilities if v.severity == severity]
    
    def get_summary(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "scan_time": self.scan_time,
            "total_vulnerabilities": len(self.vulnerabilities),
            "by_severity": {
                "critical": len(self.get_by_severity(Severity.CRITICAL)),
                "high": len(self.get_by_severity(Severity.HIGH)),
                "medium": len(self.get_by_severity(Severity.MEDIUM)),
                "low": len(self.get_by_severity(Severity.LOW)),
                "info": len(self.get_by_severity(Severity.INFO)),
            },
            "total_sensitive_findings": len(self.sensitive_findings),
            "sensitive_by_type": self._count_sensitive_by_type(),
            "waf_detected": self.waf_detected,
            "api_prefixes": self.api_prefixes,
        }
    
    def _count_sensitive_by_type(self) -> Dict[str, int]:
        counts = {}
        for finding in self.sensitive_findings:
            if finding.info_type not in counts:
                counts[finding.info_type] = 0
            counts[finding.info_type] += 1
        return counts
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "scan_time": self.scan_time,
            "summary": self.get_summary(),
            "vulnerabilities": [
                {
                    "name": v.name,
                    "severity": v.severity.value,
                    "category": v.category.value,
                    "description": v.description,
                    "url": v.url,
                    "method": v.method,
                    "payload": v.payload,
                    "poc": {
                        "request": v.poc.request,
                        "response": v.poc.response,
                        "curl": v.poc.curl,
                    },
                    "remediation": {
                        "immediate": v.remediation.immediate,
                        "short_term": v.remediation.short_term,
                        "long_term": v.remediation.long_term,
                    },
                    "evidence": v.evidence,
                    "references": v.references,
                    "cwe": v.cwe,
                    "cvss": v.cvss,
                }
                for v in self.vulnerabilities
            ],
            "sensitive_findings": [
                {
                    "info_type": f.info_type,
                    "value": f.value,
                    "source": f.source,
                    "location": f.location,
                    "severity": f.severity.value,
                    "description": f.description,
                }
                for f in self.sensitive_findings
            ],
            "waf_detected": self.waf_detected,
            "server_info": self.server_info,
            "api_prefixes": self.api_prefixes,
        }


class ReportGenerator:
    """报告生成器"""
    
    def __init__(self, target: str):
        self.target = target
        self.report = EnhancedReport(
            target=target,
            scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
    
    def add_vulnerability(self, vuln: Vulnerability):
        """添加漏洞"""
        self.report.vulnerabilities.append(vuln)
    
    def add_sensitive_finding(self, finding: SensitiveFinding):
        """添加敏感信息发现"""
        self.report.sensitive_findings.append(finding)
    
    def add_waf(self, waf_name: str):
        """添加检测到的 WAF"""
        if waf_name not in self.report.waf_detected:
            self.report.waf_detected.append(waf_name)
    
    def set_server_info(self, server_info: Dict[str, str]):
        """设置服务器信息"""
        self.report.server_info = server_info
    
    def add_api_prefix(self, prefix: str):
        """添加 API 前缀"""
        if prefix not in self.report.api_prefixes:
            self.report.api_prefixes.append(prefix)
    
    def set_statistics(self, stats: Dict[str, int]):
        """设置统计信息"""
        self.report.statistics = stats
    
    def generate_json(self, indent: int = 2) -> str:
        """生成 JSON 报告"""
        return json.dumps(self.report.to_dict(), indent=indent, ensure_ascii=False)
    
    def generate_html(self) -> str:
        """生成 HTML 报告"""
        summary = self.report.get_summary()
        
        html = f"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>安全扫描报告 - {self.target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: #333; color: white; padding: 20px; border-radius: 5px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
        .summary-card {{ background: white; padding: 15px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .critical {{ border-left: 4px solid #d32f2f; }}
        .high {{ border-left: 4px solid #f57c00; }}
        .medium {{ border-left: 4px solid #fbc02d; }}
        .low {{ border-left: 4px solid #388e3c; }}
        .info {{ border-left: 4px solid #1976d2; }}
        .vuln-list {{ background: white; padding: 20px; border-radius: 5px; margin: 20px 0; }}
        .vuln-item {{ border-left: 4px solid #ccc; padding: 15px; margin: 10px 0; background: #f9f9f9; }}
        .poc {{ background: #2d2d2d; color: #fff; padding: 10px; border-radius: 3px; font-family: monospace; overflow-x: auto; }}
        .section {{ background: white; padding: 20px; border-radius: 5px; margin: 20px 0; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>安全扫描报告</h1>
        <p><strong>目标:</strong> {self.target}</p>
        <p><strong>扫描时间:</strong> {self.report.scan_time}</p>
    </div>
    
    <div class="summary">
        <div class="summary-card critical">
            <h3>严重漏洞</h3>
            <p style="font-size: 2em; margin: 0;">{summary['by_severity']['critical']}</p>
        </div>
        <div class="summary-card high">
            <h3>高危漏洞</h3>
            <p style="font-size: 2em; margin: 0;">{summary['by_severity']['high']}</p>
        </div>
        <div class="summary-card medium">
            <h3>中危漏洞</h3>
            <p style="font-size: 2em; margin: 0;">{summary['by_severity']['medium']}</p>
        </div>
        <div class="summary-card low">
            <h3>低危漏洞</h3>
            <p style="font-size: 2em; margin: 0;">{summary['by_severity']['low']}</p>
        </div>
        <div class="summary-card info">
            <h3>敏感信息</h3>
            <p style="font-size: 2em; margin: 0;">{summary['total_sensitive_findings']}</p>
        </div>
    </div>
    
    <div class="section">
        <h2>API 前缀</h2>
        <ul>
            {"".join(f"<li>{p}</li>" for p in self.report.api_prefixes)}
        </ul>
    </div>
    
    <div class="section">
        <h2>检测到的安全产品</h2>
        <ul>
            {"".join(f"<li>{w}</li>" for w in self.report.waf_detected)}
        </ul>
    </div>
    
    <div class="vuln-list">
        <h2>漏洞详情</h2>
"""
        
        for vuln in self.report.vulnerabilities:
            html += f"""
        <div class="vuln-item {vuln.severity.value}">
            <h3>[{vuln.severity.value.upper()}] {vuln.name}</h3>
            <p><strong>URL:</strong> {vuln.method} {vuln.url}</p>
            <p><strong>描述:</strong> {vuln.description}</p>
"""
            if vuln.payload:
                html += f'<p><strong>Payload:</strong> <code>{vuln.payload}</code></p>'
            if vuln.poc.curl:
                html += f'<div class="poc"><pre>{vuln.poc.curl}</pre></div>'
            html += """
        </div>
"""
        
        html += """
    </div>
    
    <div class="section">
        <h2>敏感信息发现</h2>
"""
        
        for finding in self.report.sensitive_findings:
            html += f"""
        <div class="vuln-item">
            <h3>[{finding.severity.value.upper()}] {finding.info_type}</h3>
            <p><strong>值:</strong> {finding.value}</p>
            <p><strong>来源:</strong> {finding.source} ({finding.location})</p>
            <p><strong>描述:</strong> {finding.description}</p>
        </div>
"""
        
        html += """
    </div>
</body>
</html>
"""
        return html
    
    def get_report(self) -> EnhancedReport:
        """获取报告对象"""
        return self.report


class POCGenerator:
    """POC 生成器"""
    
    @staticmethod
    def generate_curl(method: str, url: str, headers: Dict = None, data: str = None, json_data: Dict = None) -> str:
        """生成 curl 命令"""
        parts = [f"curl -X {method.upper()}"]
        
        if headers:
            for key, value in headers.items():
                parts.append(f"-H '{key}: {value}'")
        
        if data:
            if json_data:
                parts.append(f"-d '{json.dumps(json_data)}'")
            else:
                parts.append(f"-d '{data}'")
        
        parts.append(f"'{url}'")
        
        return " \\\\\n  ".join(parts)
    
    @staticmethod
    def generate_http_request(method: str, url: str, headers: Dict = None, body: str = None) -> str:
        """生成 HTTP 请求"""
        lines = [f"{method.upper()} {url} HTTP/1.1"]
        
        if headers:
            for key, value in headers.items():
                lines.append(f"{key}: {value}")
        
        lines.append("")
        
        if body:
            lines.append(body)
        
        return "\n".join(lines)
    
    @staticmethod
    def generate_sqli_poc(url: str, param: str, payload: str) -> POC:
        """生成 SQL 注入 POC"""
        poc = POC()
        poc.curl = POCGenerator.generate_curl("GET", f"{url}?{param}={payload}")
        poc.request = POCGenerator.generate_http_request("GET", f"{url}?{param}={payload}")
        return poc
    
    @staticmethod
    def generate_xss_poc(url: str, param: str, payload: str) -> POC:
        """生成 XSS POC"""
        poc = POC()
        poc.curl = POCGenerator.generate_curl("GET", f"{url}?{param}={payload}")
        poc.request = POCGenerator.generate_http_request("GET", f"{url}?{param}={payload}")
        return poc
    
    @staticmethod
    def generate_upload_poc(url: str, filename: str, content: str) -> POC:
        """生成文件上传 POC"""
        poc = POC()
        poc.curl = POCGenerator.generate_curl("POST", url, 
                                             headers={"Content-Type": "multipart/form-data"},
                                             data=f"--boundary\\nContent-Disposition: form-data; name='file'; filename='{filename}'\\n\\n{content}\\n--boundary--")
        poc.request = POCGenerator.generate_http_request("POST", url,
                                                       headers={"Content-Type": "multipart/form-data"},
                                                       body=f"--boundary\\nContent-Disposition: form-data; name='file'; filename='{filename}'\\n\\n{content}\\n--boundary--")
        return poc


class RemediationGenerator:
    """修复建议生成器"""
    
    REMEDIATIONS = {
        "sql_injection": Remediation(
            immediate="使用参数化查询替代字符串拼接",
            short_term="对所有用户输入进行严格的输入验证",
            long_term="定期进行代码审计，使用 Web 应用防火墙"
        ),
        "xss": Remediation(
            immediate="对所有输出进行 HTML 转义",
            short_term="实施 Content Security Policy (CSP)",
            long_term="定期进行 XSS 漏洞扫描"
        ),
        "sensitive_data_exposure": Remediation(
            immediate="移除代码中的硬编码凭据",
            short_term="实施加密存储敏感信息",
            long_term="定期审计敏感信息泄露风险"
        ),
        "authentication_bypass": Remediation(
            immediate="检查认证逻辑，修复越权漏洞",
            short_term="实施强制的访问控制检查",
            long_term="定期进行渗透测试"
        ),
        "idor": Remediation(
            immediate="在所有 API 端点实施对象级访问控制",
            short_term="使用间接引用映射隐藏真实 ID",
            long_term="定期审计访问控制策略"
        ),
        "ssrf": Remediation(
            immediate="对用户输入的 URL 进行严格验证",
            short_term="禁用不必要的 URL 跳转",
            long_term="使用白名单限制可访问的地址"
        ),
    }
    
    @classmethod
    def get_remediation(cls, vuln_type: str) -> Remediation:
        """获取漏洞类型的修复建议"""
        vuln_type_lower = vuln_type.lower()
        
        for key, remediation in cls.REMEDIATIONS.items():
            if key in vuln_type_lower:
                return remediation
        
        return Remediation(
            immediate="实施安全编码实践",
            short_term="进行安全代码审查",
            long_term="定期安全测试"
        )
