import os
import json
import time
import threading
import sqlite3
from queue import Queue
from functools import lru_cache
import re

try:
    from plugins.nodeCommon import *
    from plugins.enhanced_sourcemap_detector import SourceMapIntegration
    from plugins.ast_analyzer import ASTAnalyzer
except Exception as e:
    try:
        from nodeCommon import *
        from enhanced_sourcemap_detector import SourceMapIntegration
        try:
            from ast_analyzer import ASTAnalyzer
        except ImportError:
            pass
    except ImportError:
        pass

# 全局单例管理器
class DeferredAnalysisManager:
    """
    延迟分析管理器 - 将耗时操作移至后台执行
    将 AST 扫描、正则匹配等操作延迟到最后阶段执行
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._initialized = True
        self.analysis_queue = Queue()
        self.workers = []
        self.running = False
        self.results = {
            'ast_apis': [],
            'ast_urls': [],
            'sourcemaps': [],
            'js_urls_found': [],
            'static_urls_found': [],
        }
        self.progress_callback = None
        self._results_lock = threading.Lock()

    def set_progress_callback(self, callback):
        """设置进度回调函数"""
        self.progress_callback = callback

    def _report_progress(self, message):
        """报告进度"""
        if self.progress_callback:
            try:
                self.progress_callback(message)
            except Exception:
                pass
        else:
            logger_print_content(f"[延迟分析] {message}")

    def enqueue_task(self, task_type, task_data):
        """
        将任务加入队列

        Args:
            task_type: 任务类型 ('ast_analysis', 'sourcemap', 'regex_match')
            task_data: 任务数据字典
        """
        self.analysis_queue.put({
            'type': task_type,
            'data': task_data,
            'timestamp': time.time()
        })

    def _worker_loop(self, worker_id):
        """工作线程循环"""
        self._report_progress(f"[Worker-{worker_id}] 启动")

        while self.running:
            try:
                task = self.analysis_queue.get(timeout=1)
                self._process_task(task, worker_id)
                self.analysis_queue.task_done()
            except Exception as e:
                if self.running:
                    continue
                break

        self._report_progress(f"[Worker-{worker_id}] 退出")

    def _process_task(self, task, worker_id):
        """处理单个任务"""
        task_type = task['type']
        task_data = task['data']

        try:
            if task_type == 'ast_analysis':
                self._process_ast_analysis(task_data, worker_id)
            elif task_type == 'sourcemap':
                self._process_sourcemap(task_data, worker_id)
            elif task_type == 'regex_match':
                self._process_regex_match(task_data, worker_id)
            else:
                self._report_progress(f"[Worker-{worker_id}] 未知任务类型: {task_type}")
        except Exception as e:
            self._report_progress(f"[Worker-{worker_id}] 任务处理失败: {str(e)}")

    def _process_ast_analysis(self, task_data, worker_id):
        """处理 AST 分析任务"""
        file_path = task_data.get('file_path')
        url = task_data.get('url')
        db_path = task_data.get('db_path')

        if not file_path or not os.path.exists(file_path):
            return

        try:
            self._report_progress(f"[Worker-{worker_id}] AST分析: {os.path.basename(file_path)}")

            analyzer = ASTAnalyzer()
            ast_res = analyzer.analyze_file(file_path)

            apis = ast_res.get('apis', [])
            ast_urls = ast_res.get('urls', [])

            if apis or ast_urls:
                self._report_progress(f"[Worker-{worker_id}] AST发现: {len(apis)}个接口, {len(ast_urls)}个URL")

                # 保存结果到数据库
                if db_path:
                    try:
                        conn = sqlite3.connect(db_path)
                        conn.execute("CREATE TABLE IF NOT EXISTS step9_deferred_ast_analysis (file_path TEXT, api_json TEXT, url_json TEXT, url TEXT, timestamp REAL)")
                        conn.execute("INSERT INTO step9_deferred_ast_analysis (file_path, api_json, url_json, url, timestamp) VALUES (?, ?, ?, ?, ?)",
                                     (file_path, json.dumps(apis), json.dumps(ast_urls), url or '', time.time()))
                        conn.commit()
                        conn.close()
                    except Exception:
                        pass

                # 累计结果
                with self._results_lock:
                    self.results['ast_apis'].extend(apis)
                    self.results['ast_urls'].extend(ast_urls)

        except Exception as e:
            self._report_progress(f"[Worker-{worker_id}] AST分析失败: {str(e)}")

    def _process_sourcemap(self, task_data, worker_id):
        """处理 SourceMap 任务"""
        url = task_data.get('url')
        text = task_data.get('text')
        folder_path = task_data.get('folder_path')
        db_path = task_data.get('db_path')
        base_url = task_data.get('base_url')

        if not url or not text or not folder_path:
            return

        try:
            self._report_progress(f"[Worker-{worker_id}] SourceMap检测: {url}")

            sourcemap_integration = SourceMapIntegration()
            enhanced_sourcemaps = sourcemap_integration.detect_sourcemap_urls_enhanced(url, text)

            if enhanced_sourcemaps:
                self._report_progress(f"[Worker-{worker_id}] 发现 {len(enhanced_sourcemaps)} 个SourceMap")

                for sm_url in enhanced_sourcemaps:
                    try:
                        restored_files, ast_findings = sourcemap_integration.restore_and_scan(sm_url, folder_path, db_path)

                        # 保存AST分析结果
                        if ast_findings and db_path:
                            try:
                                conn = sqlite3.connect(db_path)
                                conn.execute("CREATE TABLE IF NOT EXISTS step9_deferred_sourcemaps (file_path TEXT, api_json TEXT, url_json TEXT, sourcemap_url TEXT, timestamp REAL)")
                                for finding in ast_findings:
                                    conn.execute("INSERT INTO step9_deferred_sourcemaps (file_path, api_json, url_json, sourcemap_url, timestamp) VALUES (?, ?, ?, ?, ?)",
                                                 (finding['file'], json.dumps(finding['apis']), json.dumps(finding['urls']), sm_url, time.time()))
                                conn.commit()
                                conn.close()

                                with self._results_lock:
                                    for finding in ast_findings:
                                        self.results['ast_apis'].extend(finding['apis'])
                                        self.results['ast_urls'].extend(finding['urls'])
                            except Exception:
                                pass

                        # 将还原的文件内容加入正则匹配队列
                        if restored_files:
                            for r_file in restored_files:
                                try:
                                    with open(r_file, 'r', encoding='utf-8', errors='ignore') as f:
                                        r_content = f.read()
                                    self.enqueue_task('regex_match', {
                                        'content': r_content,
                                        'ref_url': sm_url,
                                        'folder_path': folder_path,
                                        'db_path': db_path,
                                        'is_sourcemap_file': True
                                    })
                                except Exception:
                                    pass

                    except Exception as e:
                        self._report_progress(f"[Worker-{worker_id}] SourceMap还原失败: {str(e)}")

                with self._results_lock:
                    self.results['sourcemaps'].extend(enhanced_sourcemaps)

        except Exception as e:
            self._report_progress(f"[Worker-{worker_id}] SourceMap检测失败: {str(e)}")

    def _process_regex_match(self, task_data, worker_id):
        """处理正则匹配任务"""
        content = task_data.get('content', '')
        ref_url = task_data.get('ref_url', '')
        folder_path = task_data.get('folder_path')
        db_path = task_data.get('db_path')
        is_sourcemap_file = task_data.get('is_sourcemap_file', False)
        base_url = task_data.get('base_url')
        scheme = task_data.get('scheme', 'http')
        base = task_data.get('base', '')
        root_path = task_data.get('root_path', '/')
        domain = task_data.get('domain', '')

        if not content:
            return

        try:
            if is_sourcemap_file:
                self._report_progress(f"[Worker-{worker_id}] 正则匹配(SM): {os.path.basename(ref_url)}")

            # 正则提取规则
            js_patterns = [
                r'http[^\s\'\'"\>\<\:\(\)\[\,]+?\.js\b',
                r'["\']/[^\s\'\'"\>\<\:\(\)\[\,]+?\.js\b',
                r'=[^\s\'\'"\>\<\:\(\)\[\,]+?\.js\b',
                r'=["\'][^\s\'\'"\>\<\:\(\)\[\,]+?\.js\b',
            ]
            staticUrl_patterns = [
                r'["\']http[^\s\'\'"\>\<\)\(]+?[\"\']',
                r'=http[^\s\'\'"\>\<\)\(]+',
                r'[\"\']/[^\s\'\'"\>\<\:\)\(\u4e00-\u9fa5]+?["\']',
            ]

            # 提取 JS URL
            js_urls = set()
            for js_pattern in js_patterns:
                js_paths = regex.findall(js_pattern, content)
                js_paths = ["".join(x.strip("\"'")) for x in js_paths]
                js_urls.update(js_paths)

            if js_urls:
                self._report_progress(f"[Worker-{worker_id}] 发现 {len(js_urls)} 个JS URL")

                # 保存到数据库
                if db_path:
                    try:
                        conn = sqlite3.connect(db_path)
                        conn.execute("CREATE TABLE IF NOT EXISTS step9_deferred_js_urls (url TEXT, referer TEXT, timestamp REAL)")
                        for js_url in js_urls:
                            conn.execute("INSERT INTO step9_deferred_js_urls (url, referer, timestamp) VALUES (?, ?, ?)",
                                       (js_url, ref_url, time.time()))
                        conn.commit()
                        conn.close()
                    except Exception:
                        pass

                with self._results_lock:
                    self.results['js_urls_found'].extend(js_urls)

            # 提取静态资源 URL
            static_urls = set()
            for staticUrl_pattern in staticUrl_patterns:
                static_paths = regex.findall(staticUrl_pattern, content)
                static_paths = [x.strip('\'" ').rstrip('/') for x in static_paths]
                static_urls.update(static_paths)

            if static_urls:
                self._report_progress(f"[Worker-{worker_id}] 发现 {len(static_urls)} 个静态URL")

                # 保存到数据库
                if db_path:
                    try:
                        conn = sqlite3.connect(db_path)
                        conn.execute("CREATE TABLE IF NOT EXISTS step9_deferred_static_urls (url TEXT, referer TEXT, timestamp REAL)")
                        for static_url in static_urls:
                            conn.execute("INSERT INTO step9_deferred_static_urls (url, referer, timestamp) VALUES (?, ?, ?)",
                                       (static_url, ref_url, time.time()))
                        conn.commit()
                        conn.close()
                    except Exception:
                        pass

                with self._results_lock:
                    self.results['static_urls_found'].extend(static_urls)

            # Webpack 提取
            wp_js = self._webpack_js_find(content)
            if wp_js:
                self._report_progress(f"[Worker-{worker_id}] 发现 {len(wp_js)} 个Webpack分片")
                with self._results_lock:
                    self.results['js_urls_found'].extend(wp_js)

        except Exception as e:
            self._report_progress(f"[Worker-{worker_id}] 正则匹配失败: {str(e)}")

    def _webpack_js_find(self, js_content):
        """Webpack JS 提取"""
        try:
            paths = set()
            m = regex.search(r'return\s+[a-zA-Z]\.p\+"([^"]+)".*\{(.*)\}\[[a-zA-Z]\]\+"\.js"\}', js_content)
            if m:
                base_path = m.group(1)
                json_string = m.group(2)
                pairs = json_string.split(',')
                formatted_pairs = []
                for pair in pairs:
                    try:
                        key, value = pair.split(':', 1)
                    except Exception:
                        continue
                    if not key.strip().startswith('"'):
                        continue
                    if not value.strip().startswith('"'):
                        continue
                    formatted_pairs.append(key + ':' + value)
                try:
                    chunk_mapping = json.loads('{' + ','.join(formatted_pairs) + '}')
                    for key, value in chunk_mapping.items():
                        paths.add('/' + base_path + key + '.' + value + '.js')
                except Exception:
                    pass
            for m in regex.finditer(r'__webpack_require__\.u\s*=\s*function\(\w+\)\s*\{\s*return\s*"([^"]+)"\s*\+\s*\w+\s*\+\s*"([^"]+)"', js_content):
                dirprefix, suffix = m.groups()
                for c in regex.findall(r'__webpack_require__\.e\(\s*[\'"]([^\'"]+)[\'"]\s*\)', js_content):
                    paths.add('/' + dirprefix + c + suffix)
            for m in regex.finditer(r'webpackChunkName\s*:\s*[\'"]([^\'"]+)[\'"]', js_content):
                name = m.group(1)
                if name and not name.endswith('.js'):
                    paths.add('./' + name + '.js')
            for m in regex.finditer(r'import\(\s*[\'"]([^\'"]+)[\'"]\s*\)', js_content):
                p = m.group(1).strip()
                if p:
                    paths.add(p)
            return list(paths)
        except Exception:
            return []

    def start(self, num_workers=8):
        """启动后台分析线程"""
        if self.running:
            return

        self.running = True
        self._report_progress(f"启动 {num_workers} 个后台分析线程")

        for i in range(num_workers):
            worker = threading.Thread(
                target=self._worker_loop,
                args=(i,),
                daemon=True,
                name=f"DeferredAnalysisWorker-{i}"
            )
            worker.start()
            self.workers.append(worker)

    def stop(self, timeout=30):
        """停止后台分析线程"""
        self._report_progress("正在停止后台分析...")
        self.running = False

        # 等待队列中的任务完成
        start_time = time.time()
        while not self.analysis_queue.empty() and (time.time() - start_time) < timeout:
            time.sleep(0.5)

        self._report_progress(f"后台分析已停止，队列剩余: {self.analysis_queue.qsize()}")

        return self.get_results()

    def wait_for_completion(self, timeout=300):
        """等待所有分析任务完成"""
        start_time = time.time()
        while not self.analysis_queue.empty() and (time.time() - start_time) < timeout:
            time.sleep(1)
            self._report_progress(f"剩余任务: {self.analysis_queue.qsize()}")

        return self.get_results()

    def get_results(self):
        """获取分析结果"""
        with self._results_lock:
            return {
                'ast_apis': self.results['ast_apis'][:],
                'ast_urls': self.results['ast_urls'][:],
                'sourcemaps': self.results['sourcemaps'][:],
                'js_urls_found': self.results['js_urls_found'][:],
                'static_urls_found': self.results['static_urls_found'][:],
            }

    def get_stats(self):
        """获取统计信息"""
        with self._results_lock:
            return {
                'queue_size': self.analysis_queue.qsize(),
                'workers_count': len(self.workers),
                'ast_apis_count': len(self.results['ast_apis']),
                'ast_urls_count': len(self.results['ast_urls']),
                'sourcemaps_count': len(self.results['sourcemaps']),
                'js_urls_count': len(self.results['js_urls_found']),
                'static_urls_count': len(self.results['static_urls_found']),
            }
