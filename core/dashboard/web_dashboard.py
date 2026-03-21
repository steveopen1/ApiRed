"""
Web Dashboard Module
Web 可视化仪表板
"""

import json
import os
from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading


@dataclass
class DashboardConfig:
    """仪表板配置"""
    host: str = "0.0.0.0"
    port: int = 8080
    static_dir: str = "./static"
    data_dir: str = "./results"


class DashboardHandler(BaseHTTPRequestHandler):
    """仪表板请求处理器"""
    
    static_dir = "./static"
    results_dir = "./results"
    
    def do_GET(self):
        """处理 GET 请求"""
        if self.path == "/" or self.path == "/index.html":
            self.send_html()
        elif self.path == "/api/results":
            self.send_results()
        elif self.path == "/api/stats":
            self.send_stats()
        elif self.path.startswith("/static/"):
            self.send_static()
        else:
            self.send_error(404)
    
    def send_html(self):
        """发送 HTML 页面"""
        html = self._get_dashboard_html()
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode())
    
    def send_results(self):
        """发送扫描结果"""
        results = self._load_results()
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(results, ensure_ascii=False).encode())
    
    def send_stats(self):
        """发送统计信息"""
        stats = self._load_stats()
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(stats, ensure_ascii=False).encode())
    
    def send_static(self):
        """发送静态文件"""
        pass
    
    def _load_results(self) -> List[Dict]:
        """加载结果"""
        results = []
        if os.path.exists(self.results_dir):
            for target_folder in os.listdir(self.results_dir):
                result_file = os.path.join(
                    self.results_dir, target_folder, "scan_result.json"
                )
                if os.path.exists(result_file):
                    try:
                        with open(result_file, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                            results.append(data)
                    except Exception:
                        pass
        return results
    
    def _load_stats(self) -> Dict:
        """加载统计"""
        return {
            "total_scans": 0,
            "total_apis": 0,
            "total_vulns": 0,
            "last_scan": None
        }
    
    def _get_dashboard_html(self) -> str:
        """获取仪表板 HTML"""
        return """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ApiRed Dashboard</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f0f23; color: #fff; min-height: 100vh; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px 40px; display: flex; justify-content: space-between; align-items: center; }
        .header h1 { font-size: 1.5em; }
        .header .version { opacity: 0.8; font-size: 0.9em; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px 40px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: #1a1a3e; border-radius: 12px; padding: 25px; border: 1px solid #333; }
        .stat-card .value { font-size: 2.5em; font-weight: bold; background: linear-gradient(135deg, #667eea, #764ba2); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .stat-card .label { color: #888; margin-top: 5px; font-size: 0.9em; }
        .section { background: #1a1a3e; border-radius: 12px; padding: 25px; margin-bottom: 20px; border: 1px solid #333; }
        .section h2 { margin-bottom: 20px; color: #667eea; border-bottom: 2px solid #333; padding-bottom: 10px; }
        table { width: 100%; border-collapse: collapse; }
        th { text-align: left; padding: 12px; background: #252550; color: #888; font-weight: 500; }
        td { padding: 12px; border-bottom: 1px solid #333; }
        tr:hover { background: #252550; }
        .badge { display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: bold; }
        .badge-critical { background: #dc3545; }
        .badge-high { background: #fd7e14; }
        .badge-medium { background: #ffc107; color: #000; }
        .badge-low { background: #28a745; }
        .method { font-weight: bold; padding: 2px 8px; border-radius: 3px; font-size: 11px; }
        .method-get { background: #61affe; }
        .method-post { background: #49cc90; }
        .method-put { background: #fca130; }
        .method-delete { background: #f93e3e; }
        .target-link { color: #667eea; text-decoration: none; }
        .target-link:hover { text-decoration: underline; }
        .empty-state { text-align: center; padding: 60px; color: #666; }
        .empty-state .icon { font-size: 48px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>ApiRed Dashboard</h1>
            <div class="version">Red Team API Security Scanner v2.0</div>
        </div>
    </div>
    
    <div class="container">
        <div class="stats-grid">
            <div class="stat-card">
                <div class="value" id="total-scans">0</div>
                <div class="label">Total Scans</div>
            </div>
            <div class="stat-card">
                <div class="value" id="total-apis">0</div>
                <div class="label">Total APIs Discovered</div>
            </div>
            <div class="stat-card">
                <div class="value" id="total-vulns">0</div>
                <div class="label">Vulnerabilities Found</div>
            </div>
            <div class="stat-card">
                <div class="value" id="last-scan">-</div>
                <div class="label">Last Scan</div>
            </div>
        </div>
        
        <div class="section">
            <h2>Recent Scans</h2>
            <div id="scans-table">
                <div class="empty-state">
                    <div class="icon">[=]</div>
                    <div>No scan results yet</div>
                    <div style="margin-top: 10px; font-size: 0.9em;">Run: python3 apired.py -u https://target.com</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>High Risk Vulnerabilities</h2>
            <div id="vulns-table">
                <div class="empty-state">
                    <div class="icon">[!]</div>
                    <div>No vulnerabilities detected</div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        async function loadData() {
            try {
                const resp = await fetch('/api/results');
                const data = await resp.json();
                updateDashboard(data);
            } catch (e) {
                console.log('No data available');
            }
        }
        
        function updateDashboard(results) {
            const totalApis = results.reduce((sum, r) => sum + (r.total_apis || 0), 0);
            const totalVulns = results.reduce((sum, r) => sum + (r.vulnerabilities?.length || 0), 0);
            const lastScan = results.length > 0 ? results[results.length - 1].start_time : null;
            
            document.getElementById('total-scans').textContent = results.length;
            document.getElementById('total-apis').textContent = totalApis;
            document.getElementById('total-vulns').textContent = totalVulns;
            document.getElementById('last-scan').textContent = lastScan || '-';
            
            if (results.length > 0) {
                const tbody = results.map(r => {
                    const vulnCount = r.vulnerabilities?.length || 0;
                    const highVulns = r.vulnerabilities?.filter(v => v.severity === 'high' || v.severity === 'critical').length || 0;
                    return `<tr>
                        <td><a href="#" class="target-link">${r.target_url}</a></td>
                        <td>${r.total_apis || 0}</td>
                        <td>${r.alive_apis || 0}</td>
                        <td><span class="badge badge-high">${highVulns}</span></td>
                        <td>${vulnCount}</td>
                        <td>${r.start_time || '-'}</td>
                    </tr>`;
                }).join('');
                
                document.getElementById('scans-table').innerHTML = `
                    <table>
                        <thead><tr><th>Target</th><th>Total APIs</th><th>Alive</th><th>High Risk</th><th>Total Vulns</th><th>Time</th></tr></thead>
                        <tbody>${tbody}</tbody>
                    </table>`;
            }
        }
        
        loadData();
        setInterval(loadData, 30000);
    </script>
</body>
</html>"""
    
    def log_message(self, format, *args):
        """自定义日志"""
        print(f"[Dashboard] {args[0]}")


class WebDashboard:
    """Web 仪表板服务"""
    
    def __init__(self, config: Optional[DashboardConfig] = None):
        self.config = config or DashboardConfig()
        self.server: Optional[HTTPServer] = None
        self.thread: Optional[threading.Thread] = None
    
    def start(self, blocking: bool = True):
        """启动仪表板"""
        DashboardHandler.static_dir = self.config.static_dir
        DashboardHandler.results_dir = self.config.data_dir
        
        self.server = HTTPServer((self.config.host, self.config.port), DashboardHandler)
        
        if blocking:
            print(f"[*] Dashboard running at http://{self.config.host}:{self.config.port}")
            print(f"[*] Results directory: {self.config.data_dir}")
            self.server.serve_forever()
        else:
            self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.thread.start()
            print(f"[*] Dashboard starting at http://{self.config.host}:{self.config.port}")
    
    def stop(self):
        """停止仪表板"""
        if self.server:
            self.server.shutdown()
            self.server = None
    
    @staticmethod
    def get_dashboard_url(port: int = 8080) -> str:
        """获取仪表板 URL"""
        return f"http://localhost:{port}"
