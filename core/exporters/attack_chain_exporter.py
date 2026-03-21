"""
Attack Chain Exporter
攻击链可视化 - 生成 Mermaid 图表和交互式 HTML 报告
"""

from typing import Dict, List, Any
from dataclasses import dataclass
import json
import re


@dataclass
class AttackChainNode:
    """攻击链节点"""
    node_id: str
    node_type: str
    label: str
    details: Dict


@dataclass
class AttackChainEdge:
    """攻击链边"""
    from_node: str
    to_node: str
    edge_type: str
    label: str


class AttackChainExporter:
    """攻击链导出器"""

    def _sanitize_node_id(self, node_id: str) -> str:
        """将节点 ID 转换为 Mermaid 合法的标识符（只允许字母数字）"""
        return re.sub(r'[^a-zA-Z0-9]', '_', node_id)

    def generate_mermaid(self, scan_result) -> str:
        """生成 Mermaid 格式的攻击链图"""
        mermaid_lines = ['graph LR']
        mermaid_lines.append('    subgraph "Attack Chain"')

        nodes = set()
        edges = []

        for vuln in scan_result.vulnerabilities:
            vuln_node_id = self._sanitize_node_id(f"V_{vuln.vuln_id}")
            vuln_label = f"{vuln.vuln_type}: {vuln.api_id}"
            mermaid_lines.append(f'    {vuln_node_id}["{vuln_label}"]')
            nodes.add(vuln_node_id)

        for endpoint in scan_result.api_endpoints:
            endpoint_node_id = self._sanitize_node_id(endpoint.api_id)
            if endpoint.status.value if hasattr(endpoint.status, 'value') else endpoint.status == "alive":
                endpoint_label = f"{endpoint.method} {endpoint.path}"
                mermaid_lines.append(f'    {endpoint_node_id}["{endpoint_label}"]')
                nodes.add(endpoint_node_id)

                if hasattr(endpoint, 'vulnerabilities'):
                    for vuln_id in endpoint.vulnerabilities:
                        vuln_node_id = self._sanitize_node_id(f"V_{vuln_id}")
                        edges.append((endpoint_node_id, vuln_node_id, "-->"))

        for edge_from, edge_to, edge_conn in edges:
            mermaid_lines.append(f'    {edge_from} {edge_conn} {edge_to}')

        mermaid_lines.append('    end')

        return '\n'.join(mermaid_lines)

    def generate_html_report(self, scan_result, output_path: str):
        """生成交互式 HTML 攻击链报告"""
        mermaid_content = self.generate_mermaid(scan_result)

        vuln_count = len(scan_result.vulnerabilities)
        api_count = sum(1 for e in scan_result.api_endpoints
                        if (e.status.value if hasattr(e.status, 'value') else e.status) == "alive")

        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Attack Chain - {scan_result.target_url}</title>
    <script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 20px;
            background: #1a1a2e;
            color: #eee;
        }}
        h1 {{
            color: #00d4ff;
            border-bottom: 2px solid #00d4ff;
            padding-bottom: 10px;
        }}
        .summary {{
            display: flex;
            gap: 20px;
            margin: 20px 0;
        }}
        .stat-card {{
            background: #16213e;
            padding: 15px 25px;
            border-radius: 8px;
            border-left: 4px solid #00d4ff;
        }}
        .stat-card .value {{
            font-size: 2em;
            font-weight: bold;
            color: #00d4ff;
        }}
        .stat-card .label {{
            color: #888;
            font-size: 0.9em;
        }}
        .mermaid {{
            background: #16213e;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
        }}
        .footer {{
            margin-top: 30px;
            color: #666;
            font-size: 0.8em;
        }}
    </style>
</head>
<body>
    <h1>Attack Chain Report</h1>
    <p>Target: <strong>{scan_result.target_url}</strong></p>

    <div class="summary">
        <div class="stat-card">
            <div class="value">{api_count}</div>
            <div class="label">Alive APIs</div>
        </div>
        <div class="stat-card">
            <div class="value">{vuln_count}</div>
            <div class="label">Vulnerabilities</div>
        </div>
    </div>

    <h2>Attack Chain Graph</h2>
    <pre class="mermaid">
{mermaid_content}
    </pre>

    <h2>Vulnerability Details</h2>
    <table style="width:100%; border-collapse: collapse; background: #16213e;">
        <tr style="background: #0f3460;">
            <th style="padding: 10px; text-align: left;">ID</th>
            <th style="padding: 10px; text-align: left;">Type</th>
            <th style="padding: 10px; text-align: left;">API</th>
            <th style="padding: 10px; text-align: left;">Severity</th>
        </tr>
"""

        for vuln in scan_result.vulnerabilities:
            severity_color = {
                "critical": "#ff4444",
                "high": "#ff8800",
                "medium": "#ffcc00",
                "low": "#44ff44"
            }.get(vuln.severity.value if hasattr(vuln.severity, 'value') else vuln.severity, "#888")
            html_content += f"""
        <tr style="border-bottom: 1px solid #333;">
            <td style="padding: 10px;">{vuln.vuln_id}</td>
            <td style="padding: 10px;">{vuln.vuln_type}</td>
            <td style="padding: 10px;">{vuln.api_id}</td>
            <td style="padding: 10px; color: {severity_color};">{vuln.severity.value if hasattr(vuln.severity, 'value') else vuln.severity}</td>
        </tr>
"""

        html_content += """
    </table>

    <script>mermaid.initialize({ startOnLoad: true, theme: 'dark' });</script>
    <div class="footer">
        Generated by Attack Chain Exporter
    </div>
</body>
</html>
"""
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

    def generate_json(self, scan_result) -> str:
        """生成攻击链 JSON 格式"""
        chains = []

        for endpoint in scan_result.api_endpoints:
            if hasattr(endpoint, 'vulnerabilities') and endpoint.vulnerabilities:
                for vuln_id in endpoint.vulnerabilities:
                    chain = {
                        "chain_id": f"chain_{endpoint.api_id}_{vuln_id}",
                        "entry_point": endpoint.api_id,
                        "api_path": [endpoint.api_id],
                        "vulnerability": vuln_id,
                        "severity": "unknown",
                        "remediation": ""
                    }
                    for vuln in scan_result.vulnerabilities:
                        if vuln.vuln_id == vuln_id:
                            chain["severity"] = vuln.severity.value if hasattr(vuln.severity, 'value') else vuln.severity
                            chain["remediation"] = vuln.remediation
                            break
                    chains.append(chain)

        return json.dumps({"chains": chains}, indent=2, ensure_ascii=False)