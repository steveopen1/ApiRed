import os
import json
import time
import threading
import sqlite3
from queue import Queue, Empty
from concurrent.futures import ThreadPoolExecutor, as_completed
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


class AsyncAnalysisManager:
    """
    异步分析管理器 - 将耗时操作改为非阻塞执行

    与 DeferredAnalysisManager 的区别：
    - 这个管理器确保分析结果在第五步/第七步前可用
    - 使用线程池异步执行，不阻塞主下载流程
    - 提供 wait_for_ready() 方法确保关键数据准备完成
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
        self.ast_executor = None
        self.sourcemap_executor = None
        self.regex_executor = None

        # 结果存储
        self._ast_results = {}  # {file_path: result}
        self._sourcemap_results = {}  # {sourcemap_url: result}
        self._regex_results = []  # [{'url': ..., 'js_urls': [...], 'static_urls': [...]}]

        # 状态追踪
        self._ast_submitted = 0
        self._ast_completed = 0
        self._sourcemap_submitted = 0
        self._sourcemap_completed = 0
        self._regex_submitted = 0
        self._regex_completed = 0

        self._lock = threading.RLock()

    def start(self, max_workers=8):
        """启动异步分析线程池"""
        if self.ast_executor is None or self.ast_executor._shutdown:
            ast_workers = max_workers // 2
            self.ast_executor = ThreadPoolExecutor(max_workers=ast_workers, thread_name_prefix="AST-Worker")
            logger_print_content(f"[异步分析] AST分析线程池已启动 (max={ast_workers})")

        if self.sourcemap_executor is None or self.sourcemap_executor._shutdown:
            sm_workers = max_workers // 2
            self.sourcemap_executor = ThreadPoolExecutor(max_workers=sm_workers, thread_name_prefix="SourceMap-Worker")
            logger_print_content(f"[异步分析] SourceMap分析线程池已启动 (max={sm_workers})")

        if self.regex_executor is None or self.regex_executor._shutdown:
            regex_workers = max_workers // 4 or 1
            self.regex_executor = ThreadPoolExecutor(max_workers=regex_workers, thread_name_prefix="Regex-Worker")
            logger_print_content(f"[异步分析] 正则匹配线程池已启动 (max={regex_workers})")

    def submit_ast_analysis(self, file_path, url, db_path, callback=None):
        """
        提交 AST 分析任务（异步，不阻塞）

        Args:
            callback: 分析完成后的回调函数 callback(result, success)
        """
        if self.ast_executor is None:
            self.start()

        def _ast_task():
            try:
                logger_print_content(f"[AST-异步] 开始分析: {os.path.basename(file_path)}")
                analyzer = ASTAnalyzer()
                result = analyzer.analyze_file(file_path)

                # 保存到数据库
                if db_path:
                    try:
                        conn = sqlite3.connect(db_path)
                        conn.execute("CREATE TABLE IF NOT EXISTS step2_ast_analysis (file_path TEXT, api_json TEXT, url_json TEXT)")
                        apis = result.get('apis', [])
                        urls = result.get('urls', [])
                        conn.execute("INSERT INTO step2_ast_analysis (file_path, api_json, url_json) VALUES (?, ?, ?)",
                                     (file_path, json.dumps(apis), json.dumps(urls)))
                        conn.commit()
                        conn.close()
                    except Exception:
                        pass

                # 缓存结果
                with self._lock:
                    self._ast_results[file_path] = result
                    self._ast_completed += 1

                if callback:
                    callback(result, True)
                return result

            except Exception as e:
                logger_print_content(f"[AST-异步] 分析失败: {os.path.basename(file_path)} - {str(e)}")
                with self._lock:
                    self._ast_completed += 1
                if callback:
                    callback(None, False)
                return None

        self._ast_submitted += 1
        self.ast_executor.submit(_ast_task)

    def submit_sourcemap_analysis(self, url, text, folder_path, db_path, base_url, scheme, root_path, callback=None):
        """
        提交 SourceMap 分析任务（异步，不阻塞）
        """
        if self.sourcemap_executor is None:
            self.start()

        def _sourcemap_task():
            try:
                logger_print_content(f"[SourceMap-异步] 开始检测: {url}")

                sourcemap_integration = SourceMapIntegration()
                enhanced_sourcemaps = sourcemap_integration.detect_sourcemap_urls_enhanced(url, text)

                results = []
                for sm_url in enhanced_sourcemaps:
                    try:
                        restored_files, ast_findings = sourcemap_integration.restore_and_scan(sm_url, folder_path, db_path)

                        # 保存 AST 分析结果到数据库
                        if ast_findings and db_path:
                            try:
                                conn = sqlite3.connect(db_path)
                                conn.execute("CREATE TABLE IF NOT EXISTS step2_ast_analysis (file_path TEXT, api_json TEXT, url_json TEXT)")
                                for finding in ast_findings:
                                    conn.execute("INSERT INTO step2_ast_analysis (file_path, api_json, url_json) VALUES (?, ?, ?)",
                                                 (finding['file'], json.dumps(finding['apis']), json.dumps(finding['urls'])))
                                conn.commit()
                                conn.close()
                            except Exception:
                                pass

                        # 对还原的文件进行接口提取（添加到正则队列）
                        if restored_files:
                            for r_file in restored_files:
                                try:
                                    with open(r_file, 'r', encoding='utf-8', errors='ignore') as f:
                                        r_content = f.read()
                                    # 递归提交正则任务
                                    self.submit_regex_analysis(
                                        content=r_content,
                                        ref_url=sm_url,
                                        folder_path=folder_path,
                                        db_path=db_path,
                                        is_sourcemap_file=True
                                    )
                                except Exception:
                                    pass

                        results.append({
                            'sourcemap_url': sm_url,
                            'restored_files': restored_files,
                            'ast_findings': ast_findings
                        })
                    except Exception as e:
                        logger_print_content(f"[SourceMap-异步] 还原失败: {sm_url} - {str(e)}")

                with self._lock:
                    self._sourcemap_results[url] = results
                    self._sourcemap_completed += 1

                if callback:
                    callback(results, True)
                return results

            except Exception as e:
                logger_print_content(f"[SourceMap-异步] 检测失败: {url} - {str(e)}")
                with self._lock:
                    self._sourcemap_completed += 1
                if callback:
                    callback(None, False)
                return None

        self._sourcemap_submitted += 1
        self.sourcemap_executor.submit(_sourcemap_task)

    def submit_regex_analysis(self, content, ref_url, folder_path, db_path=None, is_sourcemap_file=False, callback=None):
        """
        提交正则匹配任务（异步，不阻塞）

        主要用于提取 JS URL 和静态资源 URL
        """
        if self.regex_executor is None:
            self.start()

        def _regex_task():
            try:
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
                    js_paths = re.findall(js_pattern, content)
                    js_paths = ["".join(x.strip("\"'")) for x in js_paths]
                    js_urls.update(js_paths)

                # 提取静态资源 URL
                static_urls = set()
                for staticUrl_pattern in staticUrl_patterns:
                    static_paths = re.findall(staticUrl_pattern, content)
                    static_paths = [x.strip('\'" ').rstrip('/') for x in static_paths]
                    static_urls.update(static_paths)

                # Webpack 提取
                wp_js = self._webpack_js_find(content)
                if wp_js:
                    js_urls.update(wp_js)

                result = {
                    'ref_url': ref_url,
                    'js_urls': list(js_urls),
                    'static_urls': list(static_urls),
                    'webpack_js': wp_js
                }

                with self._lock:
                    self._regex_results.append(result)
                    self._regex_completed += 1

                if callback:
                    callback(result, True)
                return result

            except Exception as e:
                logger_print_content(f"[Regex-异步] 匹配失败: {ref_url} - {str(e)}")
                with self._lock:
                    self._regex_completed += 1
                if callback:
                    callback(None, False)
                return None

        self._regex_submitted += 1
        self.regex_executor.submit(_regex_task)

    def _webpack_js_find(self, js_content):
        """Webpack JS 提取"""
        try:
            paths = set()
            m = re.search(r'return\s+[a-zA-Z]\.p\+"([^"]+)".*\{(.*)\}\[[a-zA-Z]\]\+"\.js"\}', js_content)
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
            for m in re.finditer(r'__webpack_require__\.u\s*=\s*function\(\w+\)\s*\{\s*return\s*"([^"]+)"\s*\+\s*\w+\s*\+\s*"([^"]+)"', js_content):
                dirprefix, suffix = m.groups()
                for c in re.findall(r'__webpack_require__\.e\(\s*[\'"]([^\'"]+)[\'"]\s*\)', js_content):
                    paths.add('/' + dirprefix + c + suffix)
            for m in re.finditer(r'webpackChunkName\s*:\s*[\'"]([^\'"]+)[\'"]', js_content):
                name = m.group(1)
                if name and not name.endswith('.js'):
                    paths.add('./' + name + '.js')
            for m in re.finditer(r'import\(\s*[\'"]([^\'"]+)[\'"]\s*\)', js_content):
                p = m.group(1).strip()
                if p:
                    paths.add(p)
            return list(paths)
        except Exception:
            return []

    def wait_for_ast_ready(self, timeout=30):
        """
        等待所有 AST 分析任务完成

        在第五步（无参接口扫描）和第六步（参数提取）前调用
        确保 AST 发现的接口和参数可用于 fuzzing
        """
        logger_print_content(f"[异步分析] 等待 AST 分析完成... (已提交:{self._ast_submitted}, 已完成:{self._ast_completed})")

        start_time = time.time()
        while self._ast_completed < self._ast_submitted and (time.time() - start_time) < timeout:
            time.sleep(0.5)

        if self._ast_completed >= self._ast_submitted:
            logger_print_content(f"[异步分析] AST 分析已完成: {self._ast_completed}/{self._ast_submitted}")
            return True
        else:
            logger_print_content(f"[异步分析] AST 分析未完全完成: {self._ast_completed}/{self._ast_submitted}")
            return False

    def wait_for_sourcemap_ready(self, timeout=30):
        """
        等待所有 SourceMap 分析任务完成

        确保还原的接口可用于 fuzzing
        """
        logger_print_content(f"[异步分析] 等待 SourceMap 分析完成... (已提交:{self._sourcemap_submitted}, 已完成:{self._sourcemap_completed})")

        start_time = time.time()
        while self._sourcemap_completed < self._sourcemap_submitted and (time.time() - start_time) < timeout:
            time.sleep(0.5)

        if self._sourcemap_completed >= self._sourcemap_submitted:
            logger_print_content(f"[异步分析] SourceMap 分析已完成: {self._sourcemap_completed}/{self._sourcemap_submitted}")
            return True
        else:
            logger_print_content(f"[异步分析] SourceMap 分析未完全完成: {self._sourcemap_completed}/{self._sourcemap_submitted}")
            return False

    def get_stats(self):
        """获取统计信息"""
        with self._lock:
            return {
                'ast': {
                    'submitted': self._ast_submitted,
                    'completed': self._ast_completed,
                    'pending': self._ast_submitted - self._ast_completed
                },
                'sourcemap': {
                    'submitted': self._sourcemap_submitted,
                    'completed': self._sourcemap_completed,
                    'pending': self._sourcemap_submitted - self._sourcemap_completed
                },
                'regex': {
                    'submitted': self._regex_submitted,
                    'completed': self._regex_completed,
                    'pending': self._regex_submitted - self._regex_completed
                }
            }

    def shutdown(self, wait=True):
        """关闭分析线程池"""
        if wait:
            logger_print_content(f"[异步分析] 等待剩余任务完成...")
            stats = self.get_stats()
            logger_print_content(f"[异步分析] AST剩余: {stats['ast']['pending']}, "
                             f"SourceMap剩余: {stats['sourcemap']['pending']}, "
                             f"Regex剩余: {stats['regex']['pending']}")

        if self.ast_executor:
            self.ast_executor.shutdown(wait=wait)
        if self.sourcemap_executor:
            self.sourcemap_executor.shutdown(wait=wait)
        if self.regex_executor:
            self.regex_executor.shutdown(wait=wait)
