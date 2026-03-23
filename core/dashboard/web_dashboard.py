"""
Web Dashboard Module
专业 Web 控制面板 - 支持 Agent 模式和纯规则模式
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
from urllib.parse import urlparse, parse_qs
import secrets
import logging
import hashlib

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
    scan_mode: str = "rule"  # rule | agent
    config: Dict[str, Any] = field(default_factory=dict)


class ConfigManager:
    """配置管理器 - 统一使用 config.yaml"""
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        from ..utils.config import Config
        self._config = Config()
        self._ai_config: Dict[str, Any] = {}
        self._load_ai_config()
    
    def _load_ai_config(self):
        """加载 AI 配置"""
        self._ai_config = self._config.get_ai_config()
    
    def get(self, key: str, default: Any = None) -> Any:
        """获取配置"""
        if key == 'api_keys':
            return self._config.get('ai.api_keys', {})
        if key == 'ai_provider':
            return self._ai_config.get('provider', 'deepseek')
        if key == 'model_preferences':
            return self._ai_config.get('model_preferences', {})
        return self._config.get(key, default)
    
    def set(self, key: str, value: Any):
        """设置配置"""
        self._config.set(key, value)
        self._config.save()
        if key.startswith('ai.'):
            self._load_ai_config()
    
    def get_all(self) -> Dict[str, Any]:
        """获取所有配置"""
        config = self._config.to_dict()
        ai_config = config.get('ai', {})
        if 'api_keys' in ai_config:
            masked_keys = {}
            for provider, key in ai_config['api_keys'].items():
                if key:
                    masked_keys[provider] = mask_api_key(key)
                else:
                    masked_keys[provider] = ""
            ai_config['api_keys'] = masked_keys
        return {
            "scan_mode": "rule",
            "ai_provider": self._ai_config.get('provider', 'deepseek'),
            "api_keys": ai_config.get('api_keys', {}),
            "model_preferences": ai_config.get('model_preferences', {}),
            "scan_defaults": {
                "concurrency": 50,
                "js_depth": 3,
                "verify_ssl": True,
                "attack_mode": "all"
            },
            "theme": "dark"
        }
    
    def update(self, updates: Dict[str, Any]):
        """批量更新配置"""
        for key, value in updates.items():
            if key == 'api_keys':
                for provider, api_key in value.items():
                    if api_key and not api_key.startswith('***'):
                        self._config.set_api_key(provider, api_key)
            elif key == 'ai_provider':
                self._config.set('ai.provider', value)
            elif key == 'model_preferences':
                for model, model_name in value.items():
                    self._config.set(f'ai.model_preferences.{model}', model_name)
            else:
                self._config.set(key, value)
        self._config.save()
        self._load_ai_config()
    
    def get_api_key(self, provider: str) -> Optional[str]:
        """获取 API key"""
        return self._config.get_api_key(provider)
    
    def set_api_key(self, provider: str, api_key: str):
        """设置 API key"""
        self._config.set_api_key(provider, api_key)
        self._config.save()
        self._load_ai_config()


def mask_api_key(key: str) -> str:
    """掩码 API Key"""
    if not key or len(key) < 8:
        return "***"
    return key[:4] + "***" + key[-4:]


class TaskManager:
    """任务管理器"""
    
    MAX_TASKS = 100
    
    def __init__(self):
        self.tasks: Dict[str, ScanTask] = {}
        self._lock = threading.Lock()
    
    def create_task(self, target: str, config: Optional[Dict] = None, scan_mode: str = "rule") -> ScanTask:
        """创建扫描任务"""
        task_id = secrets.token_hex(8)
        task = ScanTask(
            task_id=task_id,
            target=target,
            config=config or {},
            scan_mode=scan_mode,
            start_time=datetime.now().isoformat()
        )
        with self._lock:
            self._cleanup_old_tasks()
            self.tasks[task_id] = task
        return task
    
    def _cleanup_old_tasks(self):
        """清理旧任务，保持任务数量在限制内"""
        if len(self.tasks) >= self.MAX_TASKS:
            completed = [tid for tid, t in self.tasks.items() 
                        if t.status in ('completed', 'failed', 'stopped')]
            completed.sort(key=lambda x: self.tasks[x].end_time or '')
            for tid in completed[:len(completed) // 2]:
                del self.tasks[tid]
    
    def get_task(self, task_id: str) -> Optional[ScanTask]:
        with self._lock:
            return self.tasks.get(task_id)
    
    def update_task(self, task_id: str, **kwargs):
        with self._lock:
            if task_id in self.tasks:
                for key, value in kwargs.items():
                    if hasattr(self.tasks[task_id], key):
                        setattr(self.tasks[task_id], key, value)
    
    def list_tasks(self) -> List[Dict]:
        with self._lock:
            return [asdict(t) for t in self.tasks.values()]
    
    def delete_task(self, task_id: str) -> bool:
        with self._lock:
            if task_id in self.tasks:
                task = self.tasks[task_id]
                if task.pid > 0:
                    try:
                        os.kill(task.pid, signal.SIGTERM)
                        time.sleep(0.5)
                        try:
                            os.kill(task.pid, 0)
                        except ProcessLookupError:
                            pass
                        else:
                            os.kill(task.pid, signal.SIGKILL)
                    except (ProcessLookupError, PermissionError):
                        pass
                del self.tasks[task_id]
                return True
            return False
    
    def clear_completed(self):
        """清除已完成任务"""
        with self._lock:
            completed = [tid for tid, t in self.tasks.items() if t.status in ('completed', 'failed', 'stopped')]
            for tid in completed:
                del self.tasks[tid]


class DashboardHandler(BaseHTTPRequestHandler):
    """Dashboard 请求处理器"""
    task_manager: TaskManager = None
    
    def do_GET(self):
        parsed = urlparse(self.path)
        
        if parsed.path == '/':
            self._send_html()
        elif parsed.path == '/api/tasks':
            self._send_tasks()
        elif parsed.path == '/api/results':
            self._send_results()
        elif parsed.path == '/api/stats':
            self._send_stats()
        elif parsed.path == '/api/config':
            self._send_config()
        elif parsed.path.startswith('/api/task/'):
            task_id = parsed.path.split('/')[-1]
            if parsed.path.endswith('/stop'):
                self._handle_stop_task(task_id.rsplit('/')[0])
            elif parsed.path.endswith('/delete'):
                self._handle_delete_task(task_id.rsplit('/')[0])
            else:
                self._send_task(task_id)
        else:
            self._send_json({"error": "Not found"}, 404)
    
    def do_POST(self):
        parsed = urlparse(self.path)
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8') if content_length else '{}'
        
        try:
            data = json.loads(body) if body else {}
        except:
            data = {}
        
        if parsed.path == '/api/scan':
            self._handle_start_scan(data)
        elif parsed.path == '/api/task/stop':
            self._handle_stop_task(data.get('task_id'))
        elif parsed.path == '/api/task/delete':
            self._handle_delete_task(data.get('task_id'))
        elif parsed.path == '/api/tasks/clear':
            self._handle_clear_tasks()
        elif parsed.path == '/api/config':
            self._handle_update_config(data)
        else:
            self._send_json({"error": "Not found"}, 404)
    
    def do_PUT(self):
        parsed = urlparse(self.path)
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8') if content_length else '{}'
        
        try:
            data = json.loads(body) if body else {}
        except:
            data = {}
        
        if parsed.path == '/api/config':
            self._handle_update_config(data)
        else:
            self._send_json({"error": "Not found"}, 404)
    
    def _handle_start_scan(self, data: Dict):
        """启动扫描"""
        target = data.get('target')
        if not target:
            self._send_json({"error": "target is required"}, 400)
            return
        
        if not self._validate_target(target):
            self._send_json({"error": "Invalid target URL format"}, 400)
            return
        
        config = data.get('config', {})
        scan_mode = data.get('scan_mode', 'rule')
        
        task = self.task_manager.create_task(target, config, scan_mode)
        
        threading.Thread(
            target=self._run_scan,
            args=(task.task_id, target, config, scan_mode),
            daemon=True
        ).start()
        
        self._send_json({"task_id": task.task_id, "status": "started"})
    
    def _validate_target(self, target: str) -> bool:
        """验证 target URL 格式并防止路径遍历"""
        if not target or len(target) > 2048:
            return False
        if '..' in target or target.startswith('/'):
            return False
        try:
            from urllib.parse import urlparse
            parsed = urlparse(target)
            if parsed.scheme not in ('http', 'https'):
                return False
            if not parsed.netloc:
                return False
            if parsed.scheme in ('javascript', 'data', 'vbscript'):
                return False
            return True
        except Exception:
            return False
    
    def _sanitize_error(self, error: str) -> str:
        """对错误信息进行脱敏处理，移除敏感内容"""
        import re
        if not error:
            return ""
        patterns = [
            (r'(api[_-]?key["\']?\s*[:=]\s*)["\']?[a-zA-Z0-9_\-]{10,}["\']?', r'\1***'),
            (r'(token["\']?\s*[:=]\s*)["\']?[a-zA-Z0-9_\-\.]{10,}["\']?', r'\1***'),
            (r'(password["\']?\s*[:=]\s*)["\']?[^\s"\']{4,}["\']?', r'\1***'),
            (r'(sk[-_][a-zA-Z0-9]{20,})', r'***'),
            (r'(ghp_[a-zA-Z0-9]{36})', r'***'),
            (r'(xox[baprs]-[a-zA-Z0-9\-]{10,})', r'***'),
        ]
        sanitized = error
        for pattern, replacement in patterns:
            sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)
        return sanitized[:500]
    
    def _run_scan(self, task_id: str, target: str, config: Dict, scan_mode: str):
        """运行扫描"""
        self.task_manager.update_task(task_id, status="running", progress=0)
        
        try:
            cmd = ["python3", "main.py", "scan", "-u", target]
            
            if scan_mode == 'agent':
                cmd.append("--ai")
            
            if config.get('cookies'):
                cmd.extend(["-c", config['cookies']])
            if config.get('concurrency'):
                cmd.extend(["--concurrency", str(config['concurrency'])])
            if config.get('attack_mode'):
                mode_map = {'all': '0', 'collect': '1', 'scan': '2'}
                cmd.extend(["--at", mode_map.get(config['attack_mode'], '0')])
            if config.get('js_depth'):
                cmd.extend(["--js-depth", str(config['js_depth'])])
            if config.get('format'):
                cmd.extend(["--format", config['format']])
            
            try:
                from urllib.parse import urlparse
                parsed = urlparse(target)
                safe_name = f"{parsed.scheme}_{parsed.netloc.replace(':', '_').replace('.', '_')}"
                output_path = f"./results/{safe_name}"
            except Exception:
                import hashlib
                safe_name = hashlib.md5(target.encode()).hexdigest()[:12]
                output_path = f"./results/scan_{safe_name}"
            os.makedirs(output_path, exist_ok=True)
            
            self.task_manager.update_task(task_id, progress=10, output_path=output_path)
            
            env = os.environ.copy()
            config_mgr = ConfigManager()
            for provider in ['anthropic', 'openai', 'gemini', 'deepseek', 'mistral', 'ollama', 'custom']:
                api_key = config_mgr.get_api_key(provider)
                if api_key:
                    env[f"{provider.upper()}_API_KEY"] = api_key
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=os.getcwd(),
                env=env
            )
            
            self.task_manager.update_task(task_id, pid=process.pid)
            
            indeterminate_steps = [15, 20, 30, 40, 50, 60, 70, 80]
            step_index = 0
            
            while process.poll() is None:
                time.sleep(3)
                if step_index < len(indeterminate_steps):
                    self.task_manager.update_task(task_id, progress=indeterminate_steps[step_index])
                    step_index += 1
                if step_index >= len(indeterminate_steps):
                    break
            
            stdout, stderr = process.communicate()
            
            self.task_manager.update_task(
                task_id,
                status="completed" if process.returncode == 0 else "failed",
                progress=100,
                end_time=datetime.now().isoformat(),
                error=self._sanitize_error(stderr.decode('utf-8', errors='ignore')) if stderr else ""
            )
            
        except Exception as e:
            self.task_manager.update_task(
                task_id,
                status="failed",
                error=str(e)
            )
    
    def _handle_stop_task(self, task_id: str):
        """停止任务"""
        if not task_id:
            self._send_json({"error": "task_id is required"}, 400)
            return
        
        task = self.task_manager.get_task(task_id)
        if not task:
            self._send_json({"error": "task not found"}, 404)
            return
        
        if task.pid > 0:
            try:
                os.kill(task.pid, signal.SIGTERM)
                time.sleep(0.5)
                try:
                    os.kill(task.pid, 0)
                except ProcessLookupError:
                    pass
                else:
                    os.kill(task.pid, signal.SIGKILL)
                self.task_manager.update_task(
                    task_id,
                    status="stopped",
                    end_time=datetime.now().isoformat()
                )
                self._send_json({"task_id": task_id, "status": "stopped"})
            except (ProcessLookupError, PermissionError) as e:
                self.task_manager.update_task(
                    task_id,
                    status="stopped",
                    end_time=datetime.now().isoformat()
                )
                self._send_json({"task_id": task_id, "status": "stopped"})
            except Exception as e:
                self._send_json({"error": "Failed to stop task"}, 500)
        else:
            self._send_json({"error": "task not running"}, 400)
    
    def _handle_delete_task(self, task_id: str):
        """删除任务"""
        if not task_id:
            self._send_json({"error": "task_id is required"}, 400)
            return
        
        success = self.task_manager.delete_task(task_id)
        if success:
            self._send_json({"task_id": task_id, "status": "deleted"})
        else:
            self._send_json({"error": "task not found"}, 404)
    
    def _handle_clear_tasks(self):
        """清除已完成任务"""
        self.task_manager.clear_completed()
        self._send_json({"status": "cleared"})
    
    def _handle_update_config(self, data: Dict):
        """更新配置"""
        config_mgr = ConfigManager()
        config_mgr.update(data)
        self._send_json({"status": "saved"})
    
    def _send_html(self):
        html_path = os.path.join(os.path.dirname(__file__), 'static', 'index.html')
        try:
            with open(html_path, 'r', encoding='utf-8') as f:
                html = f.read()
        except Exception:
            html = '<html><body><h1>Error loading page</h1></body></html>'
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode())
    
    def _send_json(self, data: Dict, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        origin = self.headers.get('Origin', '')
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        else:
            self.send_header("Access-Control-Allow-Origin", self.headers.get('Host', '*'))
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False).encode())
    
    def _send_tasks(self):
        tasks = self.task_manager.list_tasks()
        self._send_json({"tasks": tasks})
    
    def _send_task(self, task_id: str):
        task = self.task_manager.get_task(task_id)
        if task:
            self._send_json(asdict(task))
        else:
            self._send_json({"error": "task not found"}, 404)
    
    def _send_results(self):
        results = self._load_results()
        self._send_json({"results": results})
    
    def _send_stats(self):
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
    
    def _send_config(self):
        config_mgr = ConfigManager()
        self._send_json(config_mgr.get_all())
    
    def _load_results(self) -> List[Dict]:
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
        print(f"[Dashboard] {args[0]}")


class WebDashboard:
    """Web 控制面板"""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 8080):
        self.host = host
        self.port = port
        self.server: Optional[HTTPServer] = None
        self.task_manager = TaskManager()
    
    def start(self, blocking: bool = True):
        DashboardHandler.task_manager = self.task_manager
        
        self.server = HTTPServer((self.host, self.port), DashboardHandler)
        
        print(f"[*] ApiRed Professional Dashboard running at http://{self.host}:{self.port}")
        print(f"[*] UI Pages:")
        print(f"    Dashboard: http://{self.host}:{self.port}/")
        print(f"[*] API Endpoints:")
        print(f"    GET  /api/tasks          - List tasks")
        print(f"    GET  /api/task/<id>      - Get task details")
        print(f"    GET  /api/results        - List results")
        print(f"    GET  /api/stats          - Statistics")
        print(f"    GET  /api/config         - Get configuration")
        print(f"    PUT  /api/config         - Update configuration")
        print(f"    POST /api/scan           - Start scan")
        print(f"    POST /api/task/stop      - Stop task")
        print(f"    POST /api/task/delete    - Delete task")
        print(f"    POST /api/tasks/clear    - Clear completed tasks")
        
        if blocking:
            self.server.serve_forever()
        else:
            thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            thread.start()
            print(f"[*] Dashboard started in background")
    
    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server = None


def run_dashboard(host: str = "0.0.0.0", port: int = 8080):
    dashboard = WebDashboard(host, port)
    dashboard.start()


if __name__ == "__main__":
    run_dashboard()
