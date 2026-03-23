"""
Web Dashboard Module
Web 控制面板 - 真正的扫描控制器
"""

import json
import os
import time
import threading
import subprocess
import signal
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse
import secrets
import logging

logger = logging.getLogger(__name__)


@dataclass
class ScanTask:
    """扫描任务"""
    task_id: str
    target: str
    status: str = "pending"
    progress: int = 0
    start_time: str = ""
    end_time: str = ""
    pid: int = 0
    output_path: str = ""
    error: str = ""
    config: Dict[str, Any] = field(default_factory=dict)


class TaskManager:
    """任务管理器"""
    
    def __init__(self):
        self.tasks: Dict[str, ScanTask] = {}
        self._lock = threading.Lock()
    
    def create_task(self, target: str, config: Optional[Dict] = None) -> ScanTask:
        """创建扫描任务"""
        task_id = secrets.token_hex(8)
        task = ScanTask(
            task_id=task_id,
            target=target,
            config=config or {},
            start_time=datetime.now().isoformat()
        )
        with self._lock:
            self.tasks[task_id] = task
        return task
    
    def get_task(self, task_id: str) -> Optional[ScanTask]:
        """获取任务"""
        with self._lock:
            return self.tasks.get(task_id)
    
    def update_task(self, task_id: str, **kwargs):
        """更新任务"""
        with self._lock:
            if task_id in self.tasks:
                for key, value in kwargs.items():
                    if hasattr(self.tasks[task_id], key):
                        setattr(self.tasks[task_id], key, value)
    
    def list_tasks(self) -> List[Dict]:
        """列出所有任务"""
        with self._lock:
            return [asdict(t) for t in self.tasks.values()]
    
    def delete_task(self, task_id: str) -> bool:
        """删除任务"""
        with self._lock:
            if task_id in self.tasks:
                task = self.tasks[task_id]
                if task.pid > 0:
                    try:
                        os.kill(task.pid, signal.SIGTERM)
                    except:
                        pass
                del self.tasks[task_id]
                return True
            return False


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ApiRed Controller</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f0f23; color: #fff; min-height: 100vh; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px 40px; display: flex; justify-content: space-between; align-items: center; }
        .header h1 { font-size: 1.5em; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px 40px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: #1a1a3e; border-radius: 12px; padding: 20px; border: 1px solid #333; }
        .stat-card .value { font-size: 2em; font-weight: bold; background: linear-gradient(135deg, #667eea, #764ba2); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .stat-card .label { color: #888; margin-top: 5px; font-size: 0.9em; }
        .section { background: #1a1a3e; border-radius: 12px; padding: 20px; margin-bottom: 20px; border: 1px solid #333; }
        .section h2 { margin-bottom: 15px; color: #667eea; border-bottom: 2px solid #333; padding-bottom: 10px; }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; color: #888; }
        .form-group input { width: 100%; padding: 10px; background: #0f0f23; border: 1px solid #333; border-radius: 6px; color: #fff; }
        .form-group input:focus { outline: none; border-color: #667eea; }
        .btn { padding: 10px 20px; border: none; border-radius: 6px; cursor: pointer; font-weight: bold; transition: opacity 0.2s; }
        .btn:hover { opacity: 0.8; }
        .btn-primary { background: linear-gradient(135deg, #667eea, #764ba2); color: #fff; }
        .btn-danger { background: #dc3545; color: #fff; }
        .btn-success { background: #28a745; color: #fff; }
        .btn-warning { background: #ffc107; color: #000; }
        table { width: 100%; border-collapse: collapse; }
        th { text-align: left; padding: 12px; background: #252550; color: #888; font-weight: 500; }
        td { padding: 12px; border-bottom: 1px solid #333; }
        tr:hover { background: #252550; }
        .badge { display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: bold; }
        .badge-pending { background: #6c757d; }
        .badge-running { background: #17a2b8; }
        .badge-completed { background: #28a745; }
        .badge-failed { background: #dc3545; }
        .progress-bar { width: 100%; height: 8px; background: #333; border-radius: 4px; overflow: hidden; }
        .progress-fill { height: 100%; background: linear-gradient(90deg, #667eea, #764ba2); transition: width 0.3s; }
        .empty-state { text-align: center; padding: 40px; color: #666; }
        .task-card { background: #252550; padding: 15px; border-radius: 8px; margin-bottom: 10px; }
        .task-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
        .task-target { font-weight: bold; color: #667eea; }
        .task-actions { display: flex; gap: 10px; }
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>ApiRed Controller</h1>
            <div style="opacity: 0.8; font-size: 0.9em;">Red Team API Security Scanner</div>
        </div>
    </div>
    
    <div class="container">
        <div class="stats-grid">
            <div class="stat-card">
                <div class="value" id="total-scans">0</div>
                <div class="label">Total Scans</div>
            </div>
            <div class="stat-card">
                <div class="value" id="running-tasks">0</div>
                <div class="label">Running Tasks</div>
            </div>
            <div class="stat-card">
                <div class="value" id="total-apis">0</div>
                <div class="label">Total APIs</div>
            </div>
            <div class="stat-card">
                <div class="value" id="total-vulns">0</div>
                <div class="label">Vulnerabilities</div>
            </div>
        </div>
        
        <div class="section">
            <h2>Start New Scan</h2>
            <div class="form-group">
                <label>Target URL</label>
                <input type="text" id="target-input" placeholder="https://example.com">
            </div>
            <div class="form-group">
                <label>Cookies (optional)</label>
                <input type="text" id="cookies-input" placeholder="session=xxx">
            </div>
            <div style="display: flex; gap: 10px;">
                <button class="btn btn-primary" onclick="startScan()">Start Scan</button>
            </div>
        </div>
        
        <div class="section">
            <h2>Active Tasks</h2>
            <div id="tasks-list">
                <div class="empty-state">No active tasks</div>
            </div>
        </div>
        
        <div class="section">
            <h2>Recent Results</h2>
            <div id="results-list">
                <div class="empty-state">No scan results yet</div>
            </div>
        </div>
    </div>
    
    <script>
        async function loadData() {
            await Promise.all([loadStats(), loadTasks(), loadResults()]);
        }
        
        async function loadStats() {
            try {
                const resp = await fetch('/api/stats');
                const data = await resp.json();
                document.getElementById('total-scans').textContent = data.total_scans || 0;
                document.getElementById('running-tasks').textContent = data.running_tasks || 0;
                document.getElementById('total-apis').textContent = data.total_apis || 0;
                document.getElementById('total-vulns').textContent = data.total_vulns || 0;
            } catch (e) {
                console.error('Failed to load stats:', e);
            }
        }
        
        async function loadTasks() {
            try {
                const resp = await fetch('/api/tasks');
                const data = await resp.json();
                const tasks = data.tasks || [];
                
                if (tasks.length === 0) {
                    document.getElementById('tasks-list').innerHTML = '<div class="empty-state">No active tasks</div>';
                    return;
                }
                
                const html = tasks.map(t => `
                    <div class="task-card">
                        <div class="task-header">
                            <span class="task-target">${t.target}</span>
                            <span class="badge badge-${t.status}">${t.status}</span>
                        </div>
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: ${t.progress}%"></div>
                        </div>
                        <div style="display: flex; justify-content: space-between; margin-top: 10px; font-size: 0.9em; color: #888;">
                            <span>Progress: ${t.progress}%</span>
                            <span>${t.start_time || ''}</span>
                        </div>
                        <div class="task-actions" style="margin-top: 10px;">
                            ${t.status === 'running' ? '<button class="btn btn-danger" onclick="stopTask(\'' + t.task_id + '\')">Stop</button>' : ''}
                            <button class="btn btn-warning" onclick="deleteTask(\'' + t.task_id + '\')">Delete</button>
                        </div>
                    </div>
                `).join('');
                
                document.getElementById('tasks-list').innerHTML = html;
            } catch (e) {
                console.error('Failed to load tasks:', e);
            }
        }
        
        async function loadResults() {
            try {
                const resp = await fetch('/api/results');
                const data = await resp.json();
                const results = data.results || [];
                
                if (results.length === 0) {
                    document.getElementById('results-list').innerHTML = '<div class="empty-state">No scan results</div>';
                    return;
                }
                
                const html = `<table>
                    <thead><tr><th>Target</th><th>APIs</th><th>Vulns</th><th>Time</th></tr></thead>
                    <tbody>
                        ${results.slice(-10).reverse().map(r => `
                            <tr>
                                <td>${r.target_url || r.target || 'Unknown'}</td>
                                <td>${r.total_apis || 0}</td>
                                <td>${(r.vulnerabilities || []).length}</td>
                                <td>${r.start_time || '-'}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>`;
                
                document.getElementById('results-list').innerHTML = html;
            } catch (e) {
                console.error('Failed to load results:', e);
            }
        }
        
        async function startScan() {
            const target = document.getElementById('target-input').value.trim();
            const cookies = document.getElementById('cookies-input').value.trim();
            
            if (!target) {
                alert('Please enter target URL');
                return;
            }
            
            const data = { target, config: {} };
            if (cookies) {
                data.config.cookies = cookies;
            }
            
            try {
                const resp = await fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });
                
                const result = await resp.json();
                
                if (result.error) {
                    alert('Error: ' + result.error);
                } else {
                    document.getElementById('target-input').value = '';
                    document.getElementById('cookies-input').value = '';
                    loadTasks();
                }
            } catch (e) {
                alert('Failed to start scan: ' + e.message);
            }
        }
        
        async function stopTask(taskId) {
            try {
                await fetch('/api/task/stop', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ task_id: taskId })
                });
                loadTasks();
            } catch (e) {
                console.error('Failed to stop task:', e);
            }
        }
        
        async function deleteTask(taskId) {
            try {
                await fetch('/api/task/delete', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ task_id: taskId })
                });
                loadTasks();
                loadStats();
            } catch (e) {
                console.error('Failed to delete task:', e);
            }
        }
        
        loadData();
        setInterval(loadData, 5000);
    </script>
</body>
</html>"""


class DashboardHandler(BaseHTTPRequestHandler):
    """仪表板请求处理器"""
    
    task_manager: TaskManager = TaskManager()
    
    def do_GET(self):
        """处理 GET 请求"""
        parsed = urlparse(self.path)
        path = parsed.path
        
        if path == "/" or path == "/index.html":
            self._send_html()
        elif path == "/api/tasks":
            self._send_tasks()
        elif path == "/api/results":
            self._send_results()
        elif path == "/api/stats":
            self._send_stats()
        elif path.startswith("/api/task/"):
            task_id = path.split("/")[-1]
            self._send_task(task_id)
        else:
            self.send_error(404)
    
    def do_POST(self):
        """处理 POST 请求 - 控制扫描"""
        parsed = urlparse(self.path)
        path = parsed.path
        
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else ""
        
        try:
            data = json.loads(body) if body else {}
        except:
            data = {}
        
        if path == "/api/scan":
            self._handle_start_scan(data)
        elif path == "/api/task/stop":
            task_id = data.get('task_id', '')
            self._handle_stop_scan(task_id)
        elif path == "/api/task/delete":
            task_id = data.get('task_id', '')
            self._handle_delete_task(task_id)
        else:
            self.send_error(404)
    
    def _send_html(self):
        """发送 HTML 页面"""
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(DASHBOARD_HTML.encode())
    
    def _handle_start_scan(self, data: Dict):
        """启动扫描"""
        target = data.get('target')
        if not target:
            self._send_json({"error": "target is required"}, status=400)
            return
        
        config = data.get('config', {})
        
        task = self.task_manager.create_task(target, config)
        
        threading.Thread(
            target=self._run_scan,
            args=(task.task_id, target, config),
            daemon=True
        ).start()
        
        self._send_json({"task_id": task.task_id, "status": "started"})
    
    def _run_scan(self, task_id: str, target: str, config: Dict):
        """运行扫描"""
        self.task_manager.update_task(task_id, status="running", progress=0)
        
        try:
            cmd = ["python3", "apired.py", "-u", target]
            
            if config.get('cookies'):
                cmd.extend(["-c", config['cookies']])
            if config.get('concurrency'):
                cmd.extend(["--concurrency", str(config['concurrency'])])
            if config.get('no_api'):
                cmd.append("--na")
                cmd.append("1")
            if config.get('attack_type') == 'collect':
                cmd.append("--at")
                cmd.append("1")
            
            output_path = f"./results/{target.replace('://', '_').replace('/', '_').replace('.', '_')}"
            os.makedirs(output_path, exist_ok=True)
            
            self.task_manager.update_task(task_id, progress=10, output_path=output_path)
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=os.getcwd()
            )
            
            self.task_manager.update_task(task_id, pid=process.pid)
            
            for progress in range(20, 100, 10):
                time.sleep(2)
                if process.poll() is not None:
                    break
                self.task_manager.update_task(task_id, progress=progress)
            
            stdout, stderr = process.communicate()
            
            self.task_manager.update_task(
                task_id,
                status="completed" if process.returncode == 0 else "failed",
                progress=100,
                end_time=datetime.now().isoformat(),
                error=stderr.decode('utf-8', errors='ignore')[:500] if stderr else ""
            )
            
        except Exception as e:
            self.task_manager.update_task(
                task_id,
                status="failed",
                error=str(e)
            )
    
    def _handle_stop_scan(self, task_id: str):
        """停止扫描"""
        if not task_id:
            self._send_json({"error": "task_id is required"}, status=400)
            return
        
        task = self.task_manager.get_task(task_id)
        if not task:
            self._send_json({"error": "task not found"}, status=404)
            return
        
        if task.pid > 0:
            try:
                os.kill(task.pid, signal.SIGTERM)
                self.task_manager.update_task(
                    task_id,
                    status="stopped",
                    end_time=datetime.now().isoformat()
                )
                self._send_json({"task_id": task_id, "status": "stopped"})
            except Exception as e:
                self._send_json({"error": str(e)}, status=500)
        else:
            self._send_json({"error": "task not running"}, status=400)
    
    def _handle_delete_task(self, task_id: str):
        """删除任务"""
        if not task_id:
            self._send_json({"error": "task_id is required"}, status=400)
            return
        
        success = self.task_manager.delete_task(task_id)
        if success:
            self._send_json({"task_id": task_id, "status": "deleted"})
        else:
            self._send_json({"error": "task not found"}, status=404)
    
    def _send_json(self, data: Dict, status: int = 200):
        """发送JSON响应"""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False).encode())
    
    def _send_tasks(self):
        """发送任务列表"""
        tasks = self.task_manager.list_tasks()
        self._send_json({"tasks": tasks})
    
    def _send_task(self, task_id: str):
        """发送单个任务"""
        task = self.task_manager.get_task(task_id)
        if task:
            self._send_json(asdict(task))
        else:
            self._send_json({"error": "task not found"}, status=404)
    
    def _send_results(self):
        """发送扫描结果"""
        results = self._load_results()
        self._send_json({"results": results})
    
    def _send_stats(self):
        """发送统计信息"""
        tasks = self.task_manager.list_tasks()
        results = self._load_results()
        
        total_apis = sum(r.get('total_apis', 0) for r in results)
        total_vulns = sum(len(r.get('vulnerabilities', [])) for r in results)
        running_count = sum(1 for t in tasks if t['status'] == 'running')
        
        self._send_json({
            "total_scans": len(results),
            "total_tasks": len(tasks),
            "running_tasks": running_count,
            "total_apis": total_apis,
            "total_vulns": total_vulns,
            "last_scan": results[-1].get('start_time') if results else None
        })
    
    def _load_results(self) -> List[Dict]:
        """加载结果"""
        results = []
        results_dir = "./results"
        
        if os.path.exists(results_dir):
            for target_folder in os.listdir(results_dir):
                result_file = os.path.join(
                    results_dir, target_folder, "scan_result.json"
                )
                if os.path.exists(result_file):
                    try:
                        with open(result_file, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                            results.append(data)
                    except Exception as e:
                        logger.warning(f"Failed to load scan result: {e}")
        
        return results
    
    def log_message(self, format, *args):
        """自定义日志"""
        print(f"[Dashboard] {args[0]}")


class WebDashboard:
    """Web 控制面板"""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 8080):
        self.host = host
        self.port = port
        self.server: Optional[HTTPServer] = None
        self.task_manager = TaskManager()
    
    def start(self, blocking: bool = True):
        """启动控制面板"""
        DashboardHandler.task_manager = self.task_manager
        
        self.server = HTTPServer((self.host, self.port), DashboardHandler)
        
        print(f"[*] ApiRed Controller running at http://{self.host}:{self.port}")
        print(f"[*] API Endpoints:")
        print(f"    GET  /                    - Dashboard UI")
        print(f"    GET  /api/tasks          - List tasks")
        print(f"    GET  /api/task/<id>      - Get task details")
        print(f"    GET  /api/results       - List results")
        print(f"    GET  /api/stats         - Statistics")
        print(f"    POST /api/scan         - Start scan")
        print(f"    POST /api/task/stop    - Stop task")
        print(f"    POST /api/task/delete  - Delete task")
        
        if blocking:
            self.server.serve_forever()
        else:
            thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            thread.start()
            print(f"[*] Dashboard started in background")
    
    def stop(self):
        """停止控制面板"""
        if self.server:
            self.server.shutdown()
            self.server = None
    
    @staticmethod
    def get_url(host: str = "localhost", port: int = 8080) -> str:
        """获取控制面板 URL"""
        return f"http://{host}:{port}"


def run_dashboard(host: str = "0.0.0.0", port: int = 8080):
    """运行控制面板"""
    dashboard = WebDashboard(host, port)
    dashboard.start()


if __name__ == "__main__":
    run_dashboard()
