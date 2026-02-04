"""
ChkApi 独立后端API服务器
为Web管理界面提供RESTful API接口
"""
import os
import json
import time
import sqlite3
import threading
import traceback
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

try:
    from plugins.nodeCommon import GlobalRequestCounter
    from plugins.async_analysis import AsyncAnalysisManager
except Exception:
    try:
        from nodeCommon import GlobalRequestCounter
        from async_analysis import AsyncAnalysisManager
    except Exception:
        GlobalRequestCounter = None
        AsyncAnalysisManager = None


# 全局变量
_RESULTS_ROOT = os.path.join(os.getcwd(), "results")
_ACTIVE_SCANS = {}  # 存储正在运行的扫描任务
_SCAN_LOCK = threading.Lock()


class APIRequestHandler(BaseHTTPRequestHandler):
    """API请求处理器"""

    def log_message(self, format, *args):
        """禁用默认日志"""
        pass

    def _send_json(self, data, status=200):
        """发送JSON响应"""
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        if isinstance(data, (dict, list)):
            data = json.dumps(data, ensure_ascii=False)
        self.wfile.write(data.encode("utf-8"))

    def _send_error(self, message, status=400):
        """发送错误响应"""
        self._send_json({"error": message, "success": False}, status)

    def _get_db_path(self, target_id):
        """根据target_id获取数据库路径"""
        if not target_id:
            return None
        target_dir = os.path.join(_RESULTS_ROOT, target_id)
        db_path = os.path.join(target_dir, "results.db")
        if os.path.exists(db_path):
            return db_path
        return None

    def _execute_query(self, db_path, query, params=(), fetch_one=False):
        """执行SQL查询"""
        if not db_path or not os.path.exists(db_path):
            return None if fetch_one else []
        try:
            conn = sqlite3.connect(db_path, timeout=10)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute(query, params)
            if fetch_one:
                result = cur.fetchone()
                conn.close()
                return dict(result) if result else None
            results = [dict(row) for row in cur.fetchall()]
            conn.close()
            return results
        except Exception as e:
            return None if fetch_one else []

    def do_OPTIONS(self):
        """处理CORS预检请求"""
        self._send_json({"status": "ok"})

    def do_GET(self):
        """处理GET请求"""
        try:
            parsed = urlparse(self.path)
            path = parsed.path

            # 路由分发
            if path == "/api/stats":
                self._get_stats()
            elif path == "/api/targets":
                self._get_targets()
            elif path.startswith("/api/target/"):
                target_id = path.split("/")[-1]
                self._get_target_detail(target_id)
            elif path == "/api/apis":
                qs = parse_qs(parsed.query)
                target_id = qs.get("target_id", [""])[0]
                self._get_apis(target_id)
            elif path == "/api/sensitive":
                qs = parse_qs(parsed.query)
                target_id = qs.get("target_id", [""])[0]
                self._get_sensitive(target_id)
            elif path == "/api/response":
                qs = parse_qs(parsed.query)
                target_id = qs.get("target_id", [""])[0]
                response_id = qs.get("id", [""])[0]
                self._get_response(target_id, response_id)
            elif path == "/api/request-log":
                qs = parse_qs(parsed.query)
                target_id = qs.get("target_id", [""])[0]
                self._get_request_log(target_id)
            elif path == "/api/diff":
                qs = parse_qs(parsed.query)
                target_id = qs.get("target_id", [""])[0]
                self._get_diff_files(target_id)
            elif path == "/api/scan-stats":
                qs = parse_qs(parsed.query)
                target_id = qs.get("target_id", [""])[0]
                self._get_scan_stats(target_id)
            elif path == "/api/async-status":
                self._get_async_status()
            else:
                self._send_error("Not found", 404)
        except Exception as e:
            traceback.print_exc()
            self._send_error(str(e), 500)

    def do_POST(self):
        """处理POST请求"""
        try:
            parsed = urlparse(self.path)
            path = parsed.path

            # 读取请求体
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8", errors="ignore")
            data = json.loads(body) if body else {}

            # 路由分发
            if path == "/api/tasks/create":
                self._create_task(data)
            elif path == "/api/tasks/start":
                self._start_task(data)
            elif path == "/api/tasks/stop":
                self._stop_task(data)
            elif path == "/api/tasks/delete":
                self._delete_task(data)
            else:
                self._send_error("Not found", 404)
        except Exception as e:
            traceback.print_exc()
            self._send_error(str(e), 500)

    def do_DELETE(self):
        """处理DELETE请求"""
        try:
            parsed = urlparse(self.path)
            path = parsed.path

            if path.startswith("/api/target/"):
                target_id = path.split("/")[-1]
                self._delete_target(target_id)
            else:
                self._send_error("Not found", 404)
        except Exception as e:
            traceback.print_exc()
            self._send_error(str(e), 500)

    # ============ API 接口实现 ============

    def _get_stats(self):
        """获取总体统计信息"""
        stats = {
            "total_targets": 0,
            "active_scans": 0,
            "total_requests": GlobalRequestCounter.get_count() if GlobalRequestCounter else 0,
            "async_analysis": {}
        }

        # 获取目标数量
        if os.path.isdir(_RESULTS_ROOT):
            stats["total_targets"] = len([d for d in os.listdir(_RESULTS_ROOT)
                                        if os.path.isdir(os.path.join(_RESULTS_ROOT, d))])

        # 获取正在运行的扫描
        with _SCAN_LOCK:
            stats["active_scans"] = len(_ACTIVE_SCANS)

        # 获取异步分析状态
        if AsyncAnalysisManager:
            try:
                manager = AsyncAnalysisManager()
                manager_stats = manager.get_stats()
                stats["async_analysis"] = manager_stats
            except Exception:
                pass

        self._send_json(stats)

    def _get_targets(self):
        """获取所有目标列表"""
        targets = []

        if not os.path.isdir(_RESULTS_ROOT):
            self._send_json({"targets": targets})
            return

        for name in sorted(os.listdir(_RESULTS_ROOT)):
            path = os.path.join(_RESULTS_ROOT, name)
            if not os.path.isdir(path):
                continue

            db_path = os.path.join(path, "results.db")
            if not os.path.isfile(db_path):
                continue

            target = {"id": name, "name": name}

            # 从数据库获取目标信息
            try:
                conn = sqlite3.connect(db_path)
                cur = conn.cursor()

                # 目标基本信息
                cur.execute("SELECT original_url, domain, port, scan_time FROM meta_target_info LIMIT 1")
                row = cur.fetchone()
                if row:
                    target.update({
                        "url": row[0] or "",
                        "domain": row[1] or "",
                        "port": row[2],
                        "scan_time": row[3] or ""
                    })

                # 汇总信息
                cur.execute("SELECT total_api, valid_api, total_requests FROM summary LIMIT 1")
                row = cur.fetchone()
                if row:
                    target.update({
                        "total_api": row[0] or 0,
                        "valid_api": row[1] or 0,
                        "total_requests": row[2] or 0
                    })

                # 风险统计
                cur.execute("SELECT COUNT(1) FROM risk_danger_api_urls")
                danger = cur.fetchone()[0] if cur.fetchone() else 0
                cur.execute("SELECT COUNT(1) FROM risk_safe_api_urls")
                safe = cur.fetchone()[0] if cur.fetchone() else 0
                target["risk_total"] = (danger or 0) + (safe or 0)

                # 差异文件
                cur.execute("SELECT COUNT(1) FROM step8_diff_files")
                target["diff_files"] = cur.fetchone()[0] or 0

                # 敏感信息统计
                sensitive = {"high": 0, "medium": 0, "low": 0}
                cur.execute("SELECT severity, COUNT(1) FROM step8_sensitive GROUP BY severity")
                for row in cur.fetchall():
                    severity = (row[0] or "").lower()
                    if severity in sensitive:
                        sensitive[severity] = row[1] or 0
                target["sensitive"] = sensitive

                conn.close()
            except Exception:
                pass

            targets.append(target)

        self._send_json({"targets": targets, "total": len(targets)})

    def _get_target_detail(self, target_id):
        """获取目标详细信息"""
        if not target_id:
            self._send_error("Target ID is required")
            return

        db_path = self._get_db_path(target_id)
        if not db_path:
            self._send_error("Target not found", 404)
            return

        detail = {"id": target_id}

        # 从数据库获取详细信息
        try:
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()

            # 目标信息
            cur.execute("SELECT * FROM meta_target_info LIMIT 1")
            row = cur.fetchone()
            if row:
                cols = [d[0] for d in cur.description]
                for i, col in enumerate(cols):
                    detail[col] = row[i]

            # 步骤统计
            steps = []
            for step_num in range(1, 9):
                table_name = f"summary" if step_num == 0 else f"step{step_num}_summary"
                cur.execute(f"SELECT * FROM {table_name} LIMIT 1")
                row = cur.fetchone()
                if row:
                    cols = [d[0] for d in cur.description]
                    step_data = {"step": step_num}
                    for i, col in enumerate(cols):
                        step_data[col] = row[i]
                    steps.append(step_data)
            detail["steps"] = steps

            conn.close()
        except Exception as e:
            self._send_error(str(e))
            return

        self._send_json(detail)

    def _get_apis(self, target_id):
        """获取API列表"""
        if not target_id:
            self._send_error("Target ID is required")
            return

        db_path = self._get_db_path(target_id)
        if not db_path:
            self._send_error("Target not found", 404)
            return

        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        page = int(qs.get("page", ["1"])[0])
        size = int(qs.get("size", ["50"])[0])
        search = qs.get("search", [""])[0]
        method = qs.get("method", [""])[0]

        offset = (page - 1) * size

        # 构建查询
        where = []
        params = []

        if search:
            where.append("url LIKE ?")
            params.append(f"%{search}%")
        if method:
            where.append("method = ?")
            params.append(method)

        where_clause = " WHERE " + " AND ".join(where) if where else ""
        count_query = f"SELECT COUNT(1) FROM step4_api_url{where_clause}"
        data_query = f"SELECT * FROM step4_api_url{where_clause} ORDER BY url LIMIT ? OFFSET ?"

        try:
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()

            # 获取总数
            cur.execute(count_query, params)
            total = cur.fetchone()[0] if cur.fetchone() else 0

            # 获取数据
            cur.execute(data_query, params + [size, offset])
            rows = cur.fetchall()

            apis = []
            for row in rows:
                cols = [d[0] for d in cur.description]
                api = {}
                for i, col in enumerate(cols):
                    api[col] = row[i]
                apis.append(api)

            conn.close()

            self._send_json({
                "apis": apis,
                "total": total,
                "page": page,
                "size": size,
                "pages": (total + size - 1) // size
            })
        except Exception as e:
            self._send_error(str(e))

    def _get_sensitive(self, target_id):
        """获取敏感信息列表"""
        if not target_id:
            self._send_error("Target ID is required")
            return

        db_path = self._get_db_path(target_id)
        if not db_path:
            self._send_error("Target not found", 404)
            return

        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        severity = qs.get("severity", [""])[0]
        page = int(qs.get("page", ["1"])[0])
        size = int(qs.get("size", ["50"])[0])

        offset = (page - 1) * size

        # 构建查询
        where = []
        params = []

        if severity:
            where.append("severity = ?")
            params.append(severity)

        where_clause = " WHERE " + " AND ".join(where) if where else ""
        count_query = f"SELECT COUNT(1) FROM step8_sensitive{where_clause}"
        data_query = f"SELECT * FROM step8_sensitive{where_clause} ORDER BY severity DESC LIMIT ? OFFSET ?"

        try:
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()

            # 获取总数
            cur.execute(count_query, params)
            total = cur.fetchone()[0] if cur.fetchone() else 0

            # 获取数据
            cur.execute(data_query, params + [size, offset])
            rows = cur.fetchall()

            sensitive_data = []
            for row in rows:
                cols = [d[0] for d in cur.description]
                item = {}
                for i, col in enumerate(cols):
                    item[col] = row[i]
                sensitive_data.append(item)

            conn.close()

            self._send_json({
                "sensitive": sensitive_data,
                "total": total,
                "page": page,
                "size": size,
                "pages": (total + size - 1) // size
            })
        except Exception as e:
            self._send_error(str(e))

    def _get_response(self, target_id, response_id):
        """获取响应详情"""
        if not target_id or not response_id:
            self._send_error("Target ID and Response ID are required")
            return

        db_path = self._get_db_path(target_id)
        if not db_path:
            self._send_error("Target not found", 404)
            return

        # 从 response_log 表获取
        response = self._execute_query(db_path,
            "SELECT * FROM response_log WHERE id = ?",
            (response_id,), fetch_one=True)

        if not response:
            self._send_error("Response not found", 404)
            return

        self._send_json({"response": response})

    def _get_request_log(self, target_id):
        """获取请求日志"""
        if not target_id:
            self._send_error("Target ID is required")
            return

        db_path = self._get_db_path(target_id)
        if not db_path:
            self._send_error("Target not found", 404)
            return

        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        page = int(qs.get("page", ["1"])[0])
        size = int(qs.get("size", ["50"])[0])

        offset = (page - 1) * size

        try:
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()

            # 获取总数
            cur.execute("SELECT COUNT(1) FROM request_log")
            total = cur.fetchone()[0] if cur.fetchone() else 0

            # 获取数据
            cur.execute("SELECT * FROM request_log ORDER BY timestamp DESC LIMIT ? OFFSET ?", (size, offset))
            rows = cur.fetchall()

            logs = []
            for row in rows:
                cols = [d[0] for d in cur.description]
                log = {}
                for i, col in enumerate(cols):
                    log[col] = row[i]
                logs.append(log)

            conn.close()

            self._send_json({
                "logs": logs,
                "total": total,
                "page": page,
                "size": size,
                "pages": (total + size - 1) // size
            })
        except Exception as e:
            self._send_error(str(e))

    def _get_diff_files(self, target_id):
        """获取差异文件列表"""
        if not target_id:
            self._send_error("Target ID is required")
            return

        db_path = self._get_db_path(target_id)
        if not db_path:
            self._send_error("Target not found", 404)
            return

        diffs = self._execute_query(db_path,
            "SELECT * FROM step8_diff_files ORDER BY content_hash")

        self._send_json({"diff_files": diffs, "total": len(diffs)})

    def _get_scan_stats(self, target_id):
        """获取扫描统计"""
        if not target_id:
            self._send_error("Target ID is required")
            return

        db_path = self._get_db_path(target_id)
        if not db_path:
            self._send_error("Target not found", 404)
            return

        stats = {}

        try:
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()

            # 汇总表
            cur.execute("SELECT * FROM summary LIMIT 1")
            row = cur.fetchone()
            if row:
                cols = [d[0] for d in cur.description]
                for i, col in enumerate(cols):
                    stats[col] = row[i]

            # 各步骤统计
            for step in range(1, 9):
                table = f"step{step}_summary"
                try:
                    cur.execute(f"SELECT * FROM {table} LIMIT 1")
                    row = cur.fetchone()
                    if row:
                        cols = [d[0] for d in cur.description]
                        step_stats = {}
                        for i, col in enumerate(cols):
                            step_stats[col] = row[i]
                        stats[f"step{step}"] = step_stats
                except Exception:
                    pass

            conn.close()
        except Exception as e:
            self._send_error(str(e))
            return

        self._send_json(stats)

    def _get_async_status(self):
        """获取异步分析状态"""
        if not AsyncAnalysisManager:
            self._send_json({"ast": None, "sourcemap": None, "regex": None})
            return

        try:
            manager = AsyncAnalysisManager()
            stats = manager.get_stats()
            self._send_json(stats)
        except Exception:
            self._send_json({"ast": None, "sourcemap": None, "regex": None})

    def _create_task(self, data):
        """创建扫描任务"""
        url = data.get("url")
        if not url:
            self._send_error("URL is required")
            return

        # 生成任务ID
        import hashlib
        task_id = hashlib.md5(url.encode()).hexdigest()[:12]
        task_dir = os.path.join(_RESULTS_ROOT, task_id)

        # 创建任务目录
        if os.path.exists(task_dir):
            self._send_error("Task already exists")
            return

        os.makedirs(task_dir, exist_ok=True)

        # 保存任务配置
        config_file = os.path.join(task_dir, "config.json")
        with open(config_file, "w", encoding="utf-8") as f:
            json.dump({
                "url": url,
                "cookies": data.get("cookies", ""),
                "js_depth": data.get("js_depth", 3),
                "attack_type": data.get("attack_type", 0),
                "status": "pending",
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
            }, f, ensure_ascii=False, indent=2)

        self._send_json({
            "task_id": task_id,
            "status": "created",
            "message": "Task created successfully"
        })

    def _start_task(self, data):
        """启动扫描任务"""
        task_id = data.get("task_id")
        if not task_id:
            self._send_error("Task ID is required")
            return

        with _SCAN_LOCK:
            if task_id in _ACTIVE_SCANS:
                self._send_error("Task is already running")
                return

        # TODO: 实际启动扫描任务
        # 这里需要集成到主扫描逻辑
        self._send_json({
            "task_id": task_id,
            "status": "started",
            "message": "Task started"
        })

    def _stop_task(self, data):
        """停止扫描任务"""
        task_id = data.get("task_id")
        if not task_id:
            self._send_error("Task ID is required")
            return

        with _SCAN_LOCK:
            if task_id in _ACTIVE_SCANS:
                del _ACTIVE_SCANS[task_id]
                self._send_json({
                    "task_id": task_id,
                    "status": "stopped",
                    "message": "Task stopped"
                })
            else:
                self._send_error("Task is not running")

    def _delete_task(self, data):
        """删除扫描任务"""
        task_id = data.get("task_id")
        if not task_id:
            self._send_error("Task ID is required")
            return

        task_dir = os.path.join(_RESULTS_ROOT, task_id)

        # 先停止任务
        with _SCAN_LOCK:
            if task_id in _ACTIVE_SCANS:
                del _ACTIVE_SCANS[task_id]

        # 删除目录
        if os.path.exists(task_dir):
            import shutil
            shutil.rmtree(task_dir)
            self._send_json({
                "task_id": task_id,
                "status": "deleted",
                "message": "Task deleted"
            })
        else:
            self._send_error("Task not found", 404)

    def _delete_target(self, target_id):
        """删除目标（数据库中删除）"""
        if not target_id:
            self._send_error("Target ID is required")
            return

        target_dir = os.path.join(_RESULTS_ROOT, target_id)

        if os.path.exists(target_dir):
            import shutil
            shutil.rmtree(target_dir)
            self._send_json({
                "target_id": target_id,
                "status": "deleted",
                "message": "Target deleted"
            })
        else:
            self._send_error("Target not found", 404)


def run_api_server(host="127.0.0.1", port=8089):
    """启动API服务器"""
    global _RESULTS_ROOT

    # 确保results目录存在
    os.makedirs(_RESULTS_ROOT, exist_ok=True)

    server = HTTPServer((host, port), APIRequestHandler)
    print(f"[API Server] Starting on http://{host}:{port}")
    print(f"[API Server] Results root: {_RESULTS_ROOT}")

    # 在后台线程中运行
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    return server


if __name__ == "__main__":
    run_api_server()
