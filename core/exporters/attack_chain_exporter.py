"""
Attack Chain Generator
攻击链分析器 - 真实的漏洞链路分析
从入口点到漏洞的完整攻击路径分析
"""

from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
import json
import re


class AttackVector(Enum):
    """攻击向量类型"""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    SSRF = "ssrf"
    IDOR = "idor"
    AUTH_BYPASS = "auth_bypass"
    INFORMATION_DISCLOSURE = "information_disclosure"
    UNKNOWN = "unknown"


class AttackSeverity(Enum):
    """攻击严重程度"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class AttackStep:
    """攻击步骤"""
    step_id: str
    step_type: str
    api_endpoint: str
    method: str
    description: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    conditions: List[str] = field(default_factory=list)


@dataclass
class AttackChain:
    """完整攻击链"""
    chain_id: str
    attack_vector: AttackVector
    severity: AttackSeverity
    entry_point: str
    vulnerable_endpoint: str
    steps: List[AttackStep] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)
    impact: str = ""
    remediation: str = ""


class AttackChainAnalyzer:
    """
    攻击链分析器
    
    分析攻击路径：
    1. 入口点识别（登录、认证、公开接口）
    2. 敏感操作识别（CRUD、权限操作）
    3. 漏洞利用路径
    4. 风险评分
    """

    ENTRY_PATTERNS = {
        'login', 'signin', 'auth', 'token', 'captcha',
        'public', 'anonymous', 'guest', 'auth'
    }

    SENSITIVE_PATTERNS = {
        'admin', 'manage', 'user', 'role', 'permission', 'config', 'setting',
        'order', 'product', 'money', 'pay', 'account', 'password', 'credit',
        'export', 'import', 'delete', 'remove', 'update', 'edit', 'create', 'add'
    }

    def __init__(self):
        self.chains: List[AttackChain] = []
        self.entry_points: List[str] = []
        self.sensitive_operations: List[str] = []

    def analyze(self, endpoints: List[Dict], vulnerabilities: List[Dict]) -> List[Dict]:
        """
        分析攻击链
        
        Args:
            endpoints: API端点列表
            vulnerabilities: 发现的漏洞列表
            
        Returns:
            攻击链列表
        """
        if not endpoints or not vulnerabilities:
            return []

        self._identify_entry_points(endpoints)
        self._identify_sensitive_operations(endpoints)
        
        chains = []
        for vuln in vulnerabilities:
            chain = self._analyze_single_vulnerability(vuln)
            if chain:
                chains.append(chain)
                
        return chains

    def _identify_entry_points(self, endpoints: List[Dict]) -> None:
        """识别入口点（登录、认证、公开接口）"""
        self.entry_points = []
        for ep in endpoints:
            path = ep.get('path', '')
            path_lower = path.lower()
            
            if any(pattern in path_lower for pattern in ['login', 'signin', 'auth', 'captcha', 'public', 'anonymous', 'guest']):
                self.entry_points.append(path)
                
    def _identify_sensitive_operations(self, endpoints: List[Dict]) -> None:
        """识别敏感操作"""
        self.sensitive_operations = []
        for ep in endpoints:
            path = ep.get('path', '')
            path_lower = path.lower()
            
            if any(pattern in path_lower for pattern in ['admin', 'manage', 'config', 'setting', 'user', 'role', 'permission']):
                self.sensitive_operations.append(path)

    def _classify_attack_vector(self, vuln_type: str) -> AttackVector:
        """分类攻击向量"""
        vuln_lower = vuln_type.lower()
        
        if any(p in vuln_lower for p in ['sql', 'sql', '注入', 'sqli', 'nosql', 'mongodb', 'redis']):
            return AttackVector.SQL_INJECTION
        if any(p in vuln_lower for p in ['xss', 'script', 'scripting']):
            return AttackVector.XSS
        if any(p in vuln_lower for p in ['ssrf', 'url', 'fetch', 'load']):
            return AttackVector.SSRF
        if any(p in vuln_lower for p in ['idor', 'broken', 'authorization']):
            return AttackVector.IDOR
        if any(p in vuln_lower for p in ['auth', 'bypass', '401', '403', 'unauthorized', 'forbidden']):
            return AttackVector.AUTH_BYPASS
        if any(p in vuln_lower for p in ['info', 'disclosure', 'sensitive', 'debug', 'stack', 'trace']):
            return AttackVector.INFORMATION_DISCLOSURE
        return AttackVector.UNKNOWN

    def _assess_severity(self, chain_data: Dict) -> AttackSeverity:
        """评估攻击链严重程度"""
        path_lower = chain_data.get('vulnerable_endpoint', '').lower()
        
        critical_keywords = ['admin', 'password', 'pay', 'money', 'bank', 'credit', 'auth', 'login']
        high_keywords = ['user', 'order', 'account', 'data', 'config', 'secret']
        medium_keywords = ['read', 'list', 'get', 'search', 'query']
        
        if any(k in path_lower for k in critical_keywords):
            return AttackSeverity.CRITICAL
        if any(k in path_lower for k in high_keywords):
            return AttackSeverity.HIGH
        if any(k in path_lower for k in medium_keywords):
            return AttackSeverity.MEDIUM
        return AttackSeverity.LOW

    def _analyze_single_vulnerability(self, vuln: Dict) -> Optional[Dict]:
        """分析单个漏洞的攻击链"""
        vuln_path = vuln.get('path', '')
        vuln_type = vuln.get('type', 'unknown')
        
        attack_vector = self._classify_attack_vector(vuln_type)
        severity = self._assess_severity({
            'vulnerable_endpoint': vuln_path,
            'type': vuln_type
        })
        
        entry_point = ''
        if self.entry_points:
            entry_point = self.entry_points[0]
        elif vuln_path in self.sensitive_operations:
            entry_point = vuln_path
            
        steps = []
        if entry_point:
            steps.append({
                'id': f"step_{len(steps) + 1}",
                'type': 'entry_point',
                'endpoint': entry_point,
                'method': 'GET',
                'description': f"入口点: {entry_point}"
            })
        
        steps.append({
            'id': f"step_{len(steps) + 1}",
            'type': 'sensitive_operation',
            'endpoint': vuln_path,
            'method': vuln.get('method', 'GET'),
            'description': f"敏感操作: {vuln_path}"
        })
        
        impact_map = {
            AttackVector.SQL_INJECTION: "可导致数据库泄露或服务器沦陷",
            AttackVector.XSS: "可窃取用户Cookie或执行恶意脚本",
            AttackVector.SSRF: "可探测内网服务",
            AttackVector.IDOR: "可越权访问其他用户数据",
            AttackVector.AUTH_BYPASS: "可绕过认证访问敏感接口",
            AttackVector.INFORMATION_DISCLOSURE: "可获取系统敏感信息",
            AttackVector.UNKNOWN: "存在安全风险"
        }
        
        remediation_map = {
            AttackVector.SQL_INJECTION: "使用参数化查询，避免SQL拼接",
            AttackVector.XSS: "对输出进行HTML转义",
            AttackVector.SSRF: "严格校验用户输入的URL，禁止内网访问",
            AttackVector.IDOR: "实施对象级权限检查",
            AttackVector.AUTH_BYPASS: "实施完整的认证和授权检查",
            AttackVector.INFORMATION_DISCLOSURE: "限制错误信息详细程度",
            AttackVector.UNKNOWN: "实施安全编码实践"
        }
        
        return {
            'chain_id': f"chain_{hash(vuln_path) % 10000}",
            'attack_vector': attack_vector.value,
            'severity': severity.value,
            'entry_point': entry_point,
            'vulnerable_endpoint': vuln_path,
            'steps': steps,
            'prerequisites': self._analyze_prerequisites(vuln),
            'impact': impact_map.get(attack_vector, "存在安全风险"),
            'remediation': remediation_map.get(attack_vector, "实施安全编码实践"),
            'vulnerability': vuln
        }

    def _analyze_prerequisites(self, vuln: Dict) -> List[str]:
        """分析攻击前提条件"""
        prereqs = []
        vuln_str = str(vuln).lower()
        
        if 'cookie' in vuln_str or 'session' in vuln_str:
            prereqs.append("需要有效会话Cookie")
        if 'token' in vuln_str or 'jwt' in vuln_str or 'bearer' in vuln_str:
            prereqs.append("需要有效Token")
        if 'auth' in vuln_str or 'login' in vuln_str:
            prereqs.append("需要认证")
            
        if not prereqs:
            prereqs.append("无需认证即可利用")
            
        return prereqs


class AttackChainExporter:
    """攻击链导出器"""

    def __init__(self):
        self.analyzer = AttackChainAnalyzer()

    def generate_chains(self, endpoints: List[Dict], vulnerabilities: List[Dict]) -> List[Dict]:
        """生成攻击链"""
        return self.analyzer.analyze(endpoints, vulnerabilities)

    def generate_mermaid(self, chains: List[Dict]) -> str:
        """生成Mermaid格式的攻击链图"""
        lines = ['graph TD']
        lines.append('    subgraph Attack_Chain')
        
        for chain in chains:
            chain_node = f"C{hash(chain.get("chain_id", "unknown") % 10000}"
            vuln_node = f"V{hash(chain.get("vulnerable_endpoint", "unknown") % 10000}"
            severity = chain.get('severity', 'low')
            severity_icons = {
                'critical': '🔴',
                'high': '🟠', 
                'medium': '🟡',
                'low': '🟢'
            }
            icon = severity_icons.get(severity, '⚪️)
            
            lines.append(f'    {chain_node}{icon}["{chain.get("attack_vector", "unknown"): {chain.get("entry_point", "N/A"}]')
            
            for step in chain.get('steps', []):
                step_node = f"S{hash(step.get("id", "unknown") % 10000}"
                lines.append(f'    {step_node}["{step.get("type", "step")}: {step.get("endpoint", "N/A"}"]')
                lines.append(f'    {chain_node} --> {step_node}')
                
            lines.append(f'    {chain_node} --> {vuln_node}')
            
        lines.append('    end')
        return '\n'.join(lines)

    def generate_json(self, chains: List[Dict]) -> str:
        """生成JSON格式"""
        return json.dumps(chains, indent=2, ensure_ascii=False)

    def generate_html(self, chains: List[Dict], target: str = "") -> str:
        """生成HTML报告"""
        json_data = self.generate_json(chains)
        mermaid_graph = self.generate_mermaid(chains)
        
        severity_colors = {
            'critical': '#ff4444',
            'high': '#ff8800',
            'medium': '#ffcc00',
            'low': '#44ff44'
        }
        
        html_template = f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Attack Chain Report - {target}</title>
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
        .chain-card {{
            background: #16213e;
            padding: 15px;
            margin: 10px 0;
            border-radius: 8px;
            border-left: 4px solid #00d4ff;
        }}
        .chain-card.critical {{ border-left-color: #ff4444; }}
        .chain-card.high {{ border-left-color: #ff8800; }}
        .chain-card.medium {{ border-left-color: #ffcc00; }}
        .chain-card.low {{ border-left-color: #44ff44; }}
        .severity {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            margin-left: 10px;
        }}
        .severity.critical {{ background: #ff4444; }}
        .severity.high {{ background: #ff8800; }}
        .severity.medium {{ background: #ffcc00; color: #000; }}
        .severity.low {{ background: #44ff44; }}
        .steps {{
            margin-left: 20px;
            padding-left: 15px;
            border-left: 2px solid #00d4ff;
        }}
        .step {{
            padding: 5px 0;
        }}
        .step-type {{
            color: #888;
            font-size: 0.9em;
        }}
        .prerequisites, .remediation {{
            background: #0f3460;
            padding: 10px;
            border-radius: 4px;
            margin-top: 10px;
        }}
        .prerequisites h4, .remediation h4 {{
            margin: 0 0 5px 0;
            color: #00d4ff;
        }}
        .footer {{
            margin-top: 30px;
            color: #666;
            font-size: 0.8em;
        }}
    </style>
</head>
<body>
    <h1>🔗 Attack Chain Report</h1>
    <p>Target: <strong>{target}</strong></p>
    
    <div class="summary">
        <div class="stat-card">
            <div class="value">{len(chains)}</div>
            <div class="label">Attack Chains</div>
        </div>
    </div>
    
    <h2>📊 Attack Chains</h2>
    <pre class="mermaid">
{mermaid_graph}
    </pre>
    <script>
        mermaid.initialize({{ startOnLoad: true, theme: 'dark' }});
    </script>
    
    <h2>📋 Chain Details</h2>
'''
        
        for chain in chains:
            severity = chain.get('severity', 'low')
            html_template += f'''
    <div class="chain-card {severity}">
        <h3>{chain.get('attack_vector', 'unknown')}<span class="severity {severity}">{severity.upper()}</span></h3>
        <p><strong>Entry Point:</strong> {chain.get('entry_point', 'N/A')}</p>
        <p><strong>Vulnerable Endpoint:</strong> {chain.get('vulnerable_endpoint', 'N/A')}</p>
        
        <div class="steps">
            <h4>Attack Steps:</h4>
'''
            for step in chain.get('steps', []):
                html_template += f'''
            <div class="step">
                <span class="step-type">[{step.get('method', 'GET'}]</span> {step.get('endpoint', 'N/A')}
                <br><small>{step.get('description', '')}</small>
            </div>
'''
            
            html_template += f'''
        </div>
        
        <div class="prerequisites">
            <h4>⚠️ Prerequisites:</h4>
            <ul>
'''
            for prereq in chain.get('prerequisites', []):
                html_template += f'''
                <li>{prereq}</li>
'''
            
            html_template += f'''
            </ul>
        </div>
        
        <div class="remediation">
            <h4>🛡️ Remediation:</h4>
            <p>{chain.get('remediation', 'N/A')}</p>
        </div>
    </div>
'''
        
        html_template += f'''
    
    <div class="footer">
        <p>Generated by ApiRed Attack Chain Analyzer</p>
    </div>
    
    <script>
        mermaid.initialize({{ theme: 'dark' }});
    </script>
</body>
</html>
'''
        
        return html_template

    def export_chains(self, endpoints: List[Dict], vulnerabilities: List[Dict], output_path: str, target: str = "") -> None:
        """导出攻击链报告"""
        chains = self.generate_chains(endpoints, vulnerabilities)
        html_content = self.generate_html(chains, target)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
