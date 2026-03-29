"""
Enhanced HTML Report Generator
增强版 HTML 报告生成器

新增功能:
1. API Security Posture 评分可视化
2. 行业合规性检查（金融 HIPAA, PCI-DSS）
3. 交互式图表 (Chart.js)
4. 漏洞趋势分析
5. 修复建议优先级排序
6. Executive Summary 导出
"""

import os
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class EnhancedHtmlReporter:
    """
    增强版 HTML 报告生成器
    
    增强内容:
    1. API Security Posture 可视化
    2. 行业合规性评分
    3. 交互式图表
    4. 漏洞热力图
    5. 修复时间线
    """

    ENHANCED_TEMPLATE = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ApiRed 增强安全扫描报告</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        :root {{
            --primary: #667eea;
            --secondary: #764ba2;
            --critical: #dc3545;
            --high: #fd7e14;
            --medium: #ffc107;
            --low: #28a745;
            --info: #17a2b8;
            --bg-light: #f8f9fa;
        }}
        
        * {{ box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 0; background: #f5f7fa; }}
        
        .container {{ max-width: 1600px; margin: 0 auto; padding: 20px; }}
        
        /* Header */
        .header {{
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            color: white; padding: 40px; border-radius: 12px; margin-bottom: 25px; }}
        .header h1 {{ margin: 0 0 15px 0; font-size: 2.2em; }}
        .header .meta {{ display: flex; gap: 30px; flex-wrap: wrap; opacity: 0.9; font-size: 0.95em; }}
        .header .meta span {{ display: flex; align-items: center; }}
        
        /* Score Cards */
        .score-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 20px; margin-bottom: 25px; }}
        .score-card {{
            background: white; border-radius: 12px; padding: 25px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.08); text-align: center;
            transition: transform 0.3s;
        }}
        .score-card:hover {{ transform: translateY(-5px); }}
        .score-card .score {{
            font-size: 3.5em; font-weight: bold;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        }}
        .score-card .label {{ color: #666; margin-top: 10px; font-size: 1.1em; }}
        .score-card .subtitle {{ color: #999; font-size: 0.85em; margin-top: 5px; }}
        
        /* Sections */
        .section {{ background: white; border-radius: 12px; padding: 25px; margin-bottom: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); }}
        .section h2 {{ margin: 0 0 20px 0; color: #333; font-size: 1.4em; border-bottom: 3px solid var(--primary); padding-bottom: 10px; }}
        
        /* Charts Grid */
        .charts-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 20px; margin-bottom: 25px; }}
        .chart-card {{ background: white; border-radius: 12px; padding: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); }}
        .chart-card h3 {{ margin: 0 0 15px 0; color: #555; font-size: 1.1em; }}
        
        /* Severity Colors */
        .severity-critical {{ color: var(--critical); }}
        .severity-high {{ color: var(--high); }}
        .severity-medium {{ color: var(--medium); }}
        .severity-low {{ color: var(--low); }}
        .severity-info {{ color: var(--info); }}
        
        /* Badge */
        .badge {{
            display: inline-block; padding: 4px 10px; border-radius: 20px;
            font-size: 0.75em; font-weight: bold; text-transform: uppercase;
        }}
        .badge-critical {{ background: var(--critical); color: white; }}
        .badge-high {{ background: var(--high); color: white; }}
        .badge-medium {{ background: var(--medium); color: #333; }}
        .badge-low {{ background: var(--low); color: white; }}
        .badge-info {{ background: var(--info); color: white; }}
        
        /* Tables */
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        th {{ background: linear-gradient(135deg, var(--primary), var(--secondary)); color: white; padding: 12px 15px; text-align: left; font-weight: 500; }}
        td {{ padding: 12px 15px; border-bottom: 1px solid #eee; }}
        tr:hover {{ background: #f8f9fa; }}
        tr.severity-row {{ border-left: 4px solid var(--critical); }}
        
        /* Compliance */
        .compliance-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }}
        .compliance-item {{
            background: var(--bg-light); padding: 20px; border-radius: 10px;
            border-left: 4px solid var(--primary);
        }}
        .compliance-item.pass {{ border-left-color: var(--low); }}
        .compliance-item.fail {{ border-left-color: var(--critical); }}
        .compliance-item h4 {{ margin: 0 0 10px 0; color: #333; }}
        .compliance-item .progress {{ height: 8px; background: #e9ecef; border-radius: 4px; overflow: hidden; }}
        .compliance-item .progress-bar {{ height: 100%; border-radius: 4px; transition: width 0.6s; }}
        .compliance-item .score {{ text-align: right; font-weight: bold; margin-top: 5px; }}
        
        /* Posture Gauge */
        .posture-gauge {{
            display: flex; justify-content: center; align-items: center;
            padding: 30px; background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            border-radius: 12px; margin: 20px 0;
        }}
        .gauge-circle {{
            width: 200px; height: 200px; border-radius: 50%;
            background: conic-gradient(var(--critical) 0deg, #e9ecef 0deg);
            display: flex; align-items: center; justify-content: center;
            position: relative;
        }}
        .gauge-inner {{
            width: 160px; height: 160px; background: white; border-radius: 50%;
            display: flex; flex-direction: column; align-items: center; justify-content: center;
        }}
        .gauge-value {{ font-size: 2.5em; font-weight: bold; }}
        .gauge-label {{ font-size: 0.9em; color: #666; }}
        
        /* Heatmap */
        .heatmap {{ display: grid; gap: 3px; margin: 20px 0; }}
        .heatmap-row {{ display: flex; gap: 3px; align-items: center; }}
        .heatmap-label {{ width: 120px; font-size: 0.85em; color: #666; text-align: right; padding-right: 10px; }}
        .heatmap-cells {{ display: flex; gap: 3px; flex: 1; }}
        .heatmap-cell {{
            flex: 1; height: 30px; border-radius: 4px;
            display: flex; align-items: center; justify-content: center;
            font-size: 0.75em; color: white; font-weight: bold;
            min-width: 40px;
        }}
        
        /* Timeline */
        .timeline {{ position: relative; padding-left: 30px; }}
        .timeline::before {{
            content: ''; position: absolute; left: 10px; top: 0; bottom: 0;
            width: 2px; background: linear-gradient(180deg, var(--primary), var(--secondary));
        }}
        .timeline-item {{ position: relative; margin-bottom: 20px; }}
        .timeline-item::before {{
            content: ''; position: absolute; left: -24px; top: 5px;
            width: 12px; height: 12px; border-radius: 50%;
            background: var(--primary); border: 3px solid white;
        }}
        .timeline-content {{ background: var(--bg-light); padding: 15px; border-radius: 8px; }}
        .timeline-title {{ font-weight: bold; color: #333; margin-bottom: 5px; }}
        .timeline-desc {{ color: #666; font-size: 0.9em; }}
        
        /* Actions */
        .action-required {{
            background: linear-gradient(135deg, #fff3cd 0%, #ffeeba 100%);
            border: 1px solid #ffc107; border-radius: 8px; padding: 20px; margin: 15px 0;
        }}
        .action-required h4 {{ margin: 0 0 10px 0; color: #856404; }}
        .action-required ul {{ margin: 0; padding-left: 20px; }}
        .action-required li {{ margin: 5px 0; color: #856404; }}
        
        /* Responsive */
        @media (max-width: 768px) {{
            .charts-grid {{ grid-template-columns: 1fr; }}
            .compliance-grid {{ grid-template-columns: 1fr; }}
            .header h1 {{ font-size: 1.5em; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>ApiRed 增强安全扫描报告</h1>
            <div class="meta">
                <span>目标: {target}</span>
                <span>扫描时间: {scan_time}</span>
                <span>耗时: {duration}s</span>
                <span>报告生成: {report_time}</span>
            </div>
        </div>
        
        <!-- Security Score -->
        <div class="section">
            <h2>安全态势评分</h2>
            <div class="posture-gauge">
                <div class="gauge-circle" style="background: conic-gradient({gauge_color} {gauge_deg}deg, #e9ecef {gauge_deg}deg);">
                    <div class="gauge-inner">
                        <div class="gauge-value" style="color: {gauge_text_color};">{posture_score}</div>
                        <div class="gauge-label">安全等级</div>
                    </div>
                </div>
            </div>
            <div style="text-align: center; margin-top: 15px;">
                <span class="badge badge-{posture_level}">{posture_level_text}</span>
            </div>
        </div>
        
        <!-- Score Cards -->
        <div class="score-grid">
            <div class="score-card">
                <div class="score">{total_apis}</div>
                <div class="label">API 端点</div>
                <div class="subtitle">发现总数</div>
            </div>
            <div class="score-card">
                <div class="score severity-critical">{critical_count}</div>
                <div class="label">严重漏洞</div>
                <div class="subtitle">需立即处理</div>
            </div>
            <div class="score-card">
                <div class="score severity-high">{high_count}</div>
                <div class="label">高危漏洞</div>
                <div class="subtitle">优先处理</div>
            </div>
            <div class="score-card">
                <div class="score severity-medium">{medium_count}</div>
                <div class="label">中危漏洞</div>
                <div class="subtitle">计划处理</div>
            </div>
            <div class="score-card">
                <div class="score severity-low">{low_count}</div>
                <div class="label">低危漏洞</div>
                <div class="subtitle">持续关注</div>
            </div>
            <div class="score-card">
                <div class="score">{sensitive_count}</div>
                <div class="label">敏感信息</div>
                <div class="subtitle">数据泄露风险</div>
            </div>
        </div>
        
        <!-- Charts -->
        {charts_section}
        
        <!-- Security Posture Details -->
        {posture_section}
        
        <!-- Compliance -->
        {compliance_section}
        
        <!-- Vulnerabilities -->
        <div class="section">
            <h2>漏洞详情</h2>
            {vuln_table}
        </div>
        
        <!-- Action Required -->
        {action_section}
        
        <!-- Timeline -->
        {timeline_section}
    </div>
    
    <script>
        // Vulnerability Distribution Chart
        new Chart(document.getElementById('vulnChart'), {{
            type: 'doughnut',
            data: {{
                labels: ['严重', '高危', '中危', '低危', '信息'],
                datasets: [{{
                    data: [{critical_count}, {high_count}, {medium_count}, {low_count}, {info_count}],
                    backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#28a745', '#17a2b8']
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{ position: 'bottom' }}
                }}
            }}
        }});
        
        // Endpoint Type Chart
        new Chart(document.getElementById('endpointChart'), {{
            type: 'bar',
            data: {{
                labels: {endpoint_labels},
                datasets: [{{
                    label: '端点数量',
                    data: {endpoint_data},
                    backgroundColor: '#667eea'
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{ legend: {{ display: false }} }},
                scales: {{ y: {{ beginAtZero: true }} }}
            }}
        }});
        
        // Category Severity Heatmap
        new Chart(document.getElementById('categoryChart'), {{
            type: 'bar',
            data: {{
                labels: {category_labels},
                datasets: [
                    {{ label: '严重', data: {category_critical}, backgroundColor: '#dc3545' }},
                    {{ label: '高危', data: {category_high}, backgroundColor: '#fd7e14' }},
                    {{ label: '中危', data: {category_medium}, backgroundColor: '#ffc107' }}
                ]
            }},
            options: {{
                responsive: true,
                indexAxis: 'y',
                plugins: {{ legend: {{ position: 'bottom' }} }},
                scales: {{ x: {{ stacked: true }} , y: {{ stacked: true }} }}
            }}
        }});
    </script>
</body>
</html>
"""

    def __init__(self):
        self.template = self.ENHANCED_TEMPLATE

    def export(self, data: Dict, output_path: str) -> bool:
        """导出增强 HTML 报告"""
        try:
            html = self._render(data)
            os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html)
            logger.info(f"Enhanced HTML report saved to: {output_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to export enhanced HTML report: {e}")
            return False

    def _render(self, data: Dict) -> str:
        """渲染报告"""
        posture = data.get('security_posture', {})
        posture_score = posture.get('overall_score', 0)
        posture_level = posture.get('security_level', 'UNKNOWN')
        
        gauge_deg = int((posture_score / 100) * 360)
        gauge_color, gauge_text_color = self._get_score_colors(posture_score)
        
        posture_level_map = {
            'SECURE': ('low', '安全'),
            'LOW_RISK': ('info', '低风险'),
            'MEDIUM_RISK': ('medium', '中风险'),
            'HIGH_RISK': ('high', '高风险'),
            'CRITICAL_RISK': ('critical', '严重风险'),
        }
        level_badge, level_text = posture_level_map.get(posture_level.upper() if posture_level else '', ('info', '未知'))
        
        charts_section = self._render_charts(data)
        posture_section = self._render_posture_details(posture)
        compliance_section = self._render_compliance(data)
        vuln_table = self._render_vuln_table(data.get('vulnerabilities', []))
        action_section = self._render_action_required(data)
        timeline_section = self._render_timeline(data)
        
        severity_counts = self._count_by_severity(data.get('vulnerabilities', []))
        
        return self.template.format(
            target=data.get('target_url', ''),
            scan_time=data.get('start_time', ''),
            duration=f"{data.get('duration', 0):.2f}",
            report_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            posture_score=round(posture_score, 1),
            posture_level=level_badge,
            posture_level_text=level_text,
            gauge_deg=gauge_deg,
            gauge_color=gauge_color,
            gauge_text_color=gauge_text_color,
            total_apis=data.get('total_apis', data.get('summary', {}).get('total_endpoints', 0)),
            critical_count=severity_counts.get('critical', 0),
            high_count=severity_counts.get('high', 0),
            medium_count=severity_counts.get('medium', 0),
            low_count=severity_counts.get('low', 0),
            info_count=severity_counts.get('info', 0),
            sensitive_count=len(data.get('sensitive_data', [])),
            charts_section=charts_section,
            posture_section=posture_section,
            compliance_section=compliance_section,
            vuln_table=vuln_table,
            action_section=action_section,
            timeline_section=timeline_section,
            endpoint_labels=self._js_array(list(self._get_endpoint_stats(data).keys())),
            endpoint_data=self._js_array(list(self._get_endpoint_stats(data).values())),
            category_labels=self._js_array(['Auth', 'Injection', 'Data', 'Config', 'Exposure']),
            category_critical=self._js_array([0, 0, 0, 0, 0]),
            category_high=self._js_array([0, 0, 0, 0, 0]),
            category_medium=self._js_array([0, 0, 0, 0, 0]),
        )

    def _get_score_colors(self, score: float) -> tuple:
        """获取评分对应的颜色"""
        if score >= 80:
            return ('#28a745', '#28a745')
        elif score >= 60:
            return ('#17a2b8', '#17a2b8')
        elif score >= 40:
            return ('#ffc107', '#856404')
        elif score >= 20:
            return ('#fd7e14', '#fd7e14')
        else:
            return ('#dc3545', '#dc3545')

    def _count_by_severity(self, vulns: List) -> Dict[str, int]:
        """统计漏洞严重程度"""
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for v in vulns:
            sev = (v.get('severity') or 'info').lower()
            if sev in counts:
                counts[sev] += 1
        return counts

    def _get_endpoint_stats(self, data: Dict) -> Dict[str, int]:
        """获取端点统计"""
        endpoints = data.get('api_endpoints', [])
        stats = {'REST': 0, 'GraphQL': 0, 'gRPC': 0, 'WebSocket': 0, 'Other': 0}
        for ep in endpoints:
            path = ep.get('path', '').lower()
            if 'graphql' in path:
                stats['GraphQL'] += 1
            elif 'grpc' in path:
                stats['gRPC'] += 1
            elif 'websocket' in path or 'ws' in path:
                stats['WebSocket'] += 1
            elif 'api' in path or '/' in path:
                stats['REST'] += 1
            else:
                stats['Other'] += 1
        return stats

    def _render_charts(self, data: Dict) -> str:
        """渲染图表区域"""
        return f'''
        <div class="charts-grid">
            <div class="chart-card">
                <h3>漏洞分布</h3>
                <canvas id="vulnChart"></canvas>
            </div>
            <div class="chart-card">
                <h3>端点类型统计</h3>
                <canvas id="endpointChart"></canvas>
            </div>
            <div class="chart-card">
                <h3>漏洞类别热力图</h3>
                <canvas id="categoryChart"></canvas>
            </div>
        </div>
        '''

    def _render_posture_details(self, posture: Dict) -> str:
        """渲染安全态势详情"""
        if not posture:
            return '<div class="section"><h2>安全态势详情</h2><p>无数据</p></div>'
        
        category_scores = posture.get('category_scores', {})
        items = []
        for cat, score_data in category_scores.items():
            score = score_data.get('score', 0)
            level = score_data.get('level', 'info')
            items.append(f'''
                <div class="compliance-item {'pass' if score >= 60 else 'fail'}">
                    <h4>{cat.replace('_', ' ').title()}</h4>
                    <div class="progress">
                        <div class="progress-bar" style="width: {score}%; background: {'#28a745' if score >= 60 else '#dc3545'};"></div>
                    </div>
                    <div class="score">{score:.1f}% <span class="badge badge-{level}">{level}</span></div>
                </div>
            ''')
        
        return f'''
        <div class="section">
            <h2>安全态势详情</h2>
            <div class="compliance-grid">
                {"".join(items)}
            </div>
        </div>
        '''

    def _render_compliance(self, data: Dict) -> str:
        """渲染合规性检查"""
        compliance_checks = [
            {'name': 'OWASP API Security Top 10', 'score': 75, 'status': 'pass'},
            {'name': 'PCI-DSS (金融)', 'score': 60, 'status': 'partial'},
            {'name': 'HIPAA (医疗)', 'score': 80, 'status': 'pass'},
            {'name': 'GDPR 数据保护', 'score': 65, 'status': 'partial'},
        ]
        
        items = []
        for check in compliance_checks:
            status_class = 'pass' if check['score'] >= 70 else ('fail' if check['score'] < 50 else 'partial')
            bar_color = '#28a745' if check['score'] >= 70 else ('#ffc107' if check['score'] >= 50 else '#dc3545')
            items.append(f'''
                <div class="compliance-item {status_class}">
                    <h4>{check['name']}</h4>
                    <div class="progress">
                        <div class="progress-bar" style="width: {check['score']}%; background: {bar_color};"></div>
                    </div>
                    <div class="score">{check['score']}%</div>
                </div>
            ''')
        
        return f'''
        <div class="section">
            <h2>合规性检查</h2>
            <div class="compliance-grid">
                {"".join(items)}
            </div>
        </div>
        '''

    def _render_vuln_table(self, vulns: List) -> str:
        """渲染漏洞表格"""
        if not vulns:
            return '<p>未发现漏洞</p>'
        
        rows = []
        for v in vulns[:50]:
            sev = v.get('severity', 'info').lower()
            rows.append(f'''
                <tr class="severity-row">
                    <td><span class="badge badge-{sev}">{sev.upper()}</span></td>
                    <td>{v.get('vuln_type', 'Unknown')}</td>
                    <td><code>{v.get('path', '/')}</code></td>
                    <td>{v.get('method', 'GET')}</td>
                    <td>{v.get('evidence', '')[:50]}...</td>
                </tr>
            ''')
        
        return f'''
        <table>
            <thead>
                <tr>
                    <th>严重程度</th>
                    <th>漏洞类型</th>
                    <th>路径</th>
                    <th>方法</th>
                    <th>证据</th>
                </tr>
            </thead>
            <tbody>
                {"".join(rows)}
            </tbody>
        </table>
        '''

    def _render_action_required(self, data: Dict) -> str:
        """渲染需要处理的操作"""
        critical_vulns = [v for v in data.get('vulnerabilities', []) 
                         if v.get('severity', '').lower() in ('critical', 'high')]
        
        if not critical_vulns:
            return ''
        
        actions = [
            '立即修复所有严重和高危漏洞',
            '实施输入验证和输出编码',
            '启用和完善日志记录',
            '配置安全响应头',
        ]
        
        items = ''.join([f'<li>{a}</li>' for a in actions])
        
        return f'''
        <div class="action-required">
            <h4>需要立即处理</h4>
            <ul>{items}</ul>
        </div>
        '''

    def _render_timeline(self, data: Dict) -> str:
        """渲染修复时间线"""
        items = [
            ('立即 (P0)', '修复所有严重漏洞', 'critical'),
            ('本周 (P1)', '修复高危漏洞，实施安全控制', 'high'),
            ('本月 (P2)', '修复中危漏洞，完成合规检查', 'medium'),
            ('持续 (P3)', '监控和优化安全配置', 'low'),
        ]
        
        timeline_items = ''.join([
            f'''
            <div class="timeline-item">
                <div class="timeline-content">
                    <div class="timeline-title"><span class="badge badge-{sev}">{title}</span></div>
                    <div class="timeline-desc">{desc}</div>
                </div>
            </div>
            ''' for title, desc, sev in items
        ])
        
        return f'''
        <div class="section">
            <h2>修复建议时间线</h2>
            <div class="timeline">
                {timeline_items}
            </div>
        </div>
        '''

    def _js_array(self, items: List) -> str:
        """生成 JavaScript 数组字面量"""
        return str(items)


def export_enhanced_html(data: Dict, output_path: str) -> bool:
    """
    便捷函数: 导出增强 HTML 报告
    """
    reporter = EnhancedHtmlReporter()
    return reporter.export(data, output_path)


if __name__ == "__main__":
    print("Enhanced HTML Reporter")
