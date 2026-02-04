import json
import sqlite3
import os
from urllib.parse import urlparse, parse_qs
from collections import defaultdict

class ContextDeduplicator:
    def __init__(self, db_path):
        self.db_path = db_path
        self.dynamic_requests = []
        self.ast_findings = []
        self.regex_apis = []
        self.regex_context_map = {}
        self.merged_apis = {}

    def load_data(self):
        """加载所有相关数据"""
        if not self.db_path or not os.path.exists(self.db_path):
            return False

        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            
            # 1. 加载动态请求
            try:
                cursor = conn.execute("SELECT * FROM step1_all_load_urls")
                self.dynamic_requests = [dict(row) for row in cursor.fetchall()]
            except Exception:
                pass

            # 2. 加载AST分析结果
            try:
                cursor = conn.execute("SELECT * FROM step2_ast_analysis")
                self.ast_findings = [dict(row) for row in cursor.fetchall()]
            except Exception:
                pass

            # 3. 加载正则提取结果
            try:
                cursor = conn.execute("SELECT * FROM step3_api_paths")
                self.regex_apis = [row['api_path'] for row in cursor.fetchall()]
            except Exception:
                pass
            
            # 3.1 加载正则上下文详情
            try:
                cursor = conn.execute("SELECT api_path, regex_context_json FROM step3_api_paths_meta WHERE regex_context_json IS NOT NULL")
                rows = cursor.fetchall()
                ctx_map = {}
                for row in rows:
                    path = row['api_path']
                    ctx = None
                    try:
                        ctx = json.loads(row['regex_context_json'])
                    except Exception:
                        ctx = None
                    if not ctx:
                        continue
                    items = ctx_map.get(path) or []
                    items.append({
                        'file': ctx.get('file'),
                        'loc': ctx.get('loc', 0),
                        'context': ctx.get('context') or '',
                        'raw_url': ctx.get('raw_url') or ''
                    })
                    ctx_map[path] = items
                self.regex_context_map = ctx_map
            except Exception:
                pass

            conn.close()
            return True
        except Exception as e:
            print(f"[ContextDeduplicator] 数据加载失败: {e}")
            return False

    def process(self):
        """执行关联与去重逻辑"""
        # 以 (method, path) 或 path 为键进行合并
        
        # 1. 处理动态请求 (这是最准确的来源)
        for req in self.dynamic_requests:
            url = req.get('url', '')
            if not url or not url.startswith('http'):
                continue
                
            parsed = urlparse(url)
            path = parsed.path
            method = req.get('method', 'GET').upper()
            
            key = f"{method}:{path}"
            
            if key not in self.merged_apis:
                self.merged_apis[key] = {
                    'path': path,
                    'method': method,
                    'full_url': url,
                    'sources': ['dynamic'],
                    'dynamic_info': {
                        'headers': req.get('headers'),
                        'post_data': req.get('post_data'),
                        'referer': req.get('referer')
                    },
                    'ast_info': [],
                    'regex_match': False,
                    'params': parse_qs(parsed.query)
                }
            else:
                # 已经存在，合并信息
                entry = self.merged_apis[key]
                if 'dynamic' not in entry['sources']:
                    entry['sources'].append('dynamic')
                # 补充动态信息（如果之前没有）
                if not entry.get('dynamic_info'):
                    entry['dynamic_info'] = {
                        'headers': req.get('headers'),
                        'post_data': req.get('post_data'),
                        'referer': req.get('referer')
                    }

        # 2. 处理AST分析结果
        for finding in self.ast_findings:
            file_path = finding.get('file_path', '')
            try:
                apis = json.loads(finding.get('api_json', '[]'))
                urls = json.loads(finding.get('url_json', '[]'))
                
                # 处理明确的API调用
                for api in apis:
                    url_val = api.get('url', '')
                    method = api.get('method', 'UNKNOWN').upper()
                    
                    # 尝试标准化URL
                    path = self._normalize_path(url_val)
                    if not path: continue
                    
                    # 尝试匹配现有记录
                    matched = False
                    
                    # 优先匹配 Method + Path
                    if method != 'UNKNOWN':
                        key = f"{method}:{path}"
                        if key in self.merged_apis:
                            self._merge_ast_info(self.merged_apis[key], file_path, api)
                            matched = True
                    
                    # 如果没匹配上，尝试只匹配 Path (可能AST没分析出Method，或者动态请求用了不同Method)
                    if not matched:
                        # 查找所有匹配该Path的记录
                        found_path_match = False
                        for key, entry in self.merged_apis.items():
                            if entry['path'] == path:
                                self._merge_ast_info(entry, file_path, api)
                                found_path_match = True
                        
                        if not found_path_match:
                            # 完全是新的
                            new_key = f"{method}:{path}"
                            self.merged_apis[new_key] = {
                                'path': path,
                                'method': method,
                                'full_url': url_val if url_val.startswith('http') else None,
                                'sources': ['ast'],
                                'dynamic_info': None,
                                'ast_info': [{
                                    'file': file_path,
                                    'raw_url': url_val,
                                    'tool': api.get('tool'),
                                    'args': api.get('args'),
                                    'loc': api.get('loc'),
                                    'context': api.get('context'),
                                    'type': api.get('type'),
                                    'params': api.get('params', [])
                                }],
                                'regex_match': False,
                                'params': {} # 可以尝试从args解析
                            }
                            
                # 处理AST中发现的URL字符串 (可能是接口，也可能是资源)
                for url_item in urls:
                    url_val = url_item.get('value', '')
                    path = self._normalize_path(url_val)
                    if not path: continue
                    
                    # 同样逻辑匹配
                    found = False
                    for key, entry in self.merged_apis.items():
                        if entry['path'] == path:
                            # 标记该接口在AST中以字符串形式出现
                            entry['sources'].append('ast_string')
                            entry['ast_info'].append({
                                'file': file_path,
                                'raw_url': url_val,
                                'type': url_item.get('type', 'string_literal'),
                                'loc': url_item.get('loc'),
                                'context': url_item.get('context')
                            })
                            found = True
                    
                    if not found:
                         # 作为一个潜在的GET接口加入
                        new_key = f"UNKNOWN:{path}"
                        if new_key not in self.merged_apis:
                            self.merged_apis[new_key] = {
                                'path': path,
                                'method': 'UNKNOWN',
                                'full_url': url_val if url_val.startswith('http') else None,
                                'sources': ['ast_string'],
                                'dynamic_info': None,
                                'ast_info': [{
                                    'file': file_path,
                                    'raw_url': url_val,
                                    'type': url_item.get('type', 'string_literal'),
                                    'loc': url_item.get('loc'),
                                    'context': url_item.get('context')
                                }],
                                'regex_match': False,
                                'params': {}
                            }

            except json.JSONDecodeError:
                pass

        # 3. 处理正则提取结果 (作为补充验证)
        for api_path in self.regex_apis:
            path = self._normalize_path(api_path)
            if not path: continue
            
            found = False
            for key, entry in self.merged_apis.items():
                if entry['path'] == path:
                    entry['regex_match'] = True
                    if 'regex' not in entry['sources']:
                        entry['sources'].append('regex')
                    found = True
            
            if not found:
                # 仅正则发现的
                new_key = f"UNKNOWN:{path}"
                if new_key not in self.merged_apis:
                     self.merged_apis[new_key] = {
                        'path': path,
                        'method': 'UNKNOWN',
                        'full_url': None,
                        'sources': ['regex'],
                        'dynamic_info': None,
                        'ast_info': [],
                        'regex_match': True,
                        'params': {}
                    }

    def _normalize_path(self, url_or_path):
        if not url_or_path: return None
        try:
            if url_or_path.startswith('http'):
                return urlparse(url_or_path).path
            else:
                # 处理相对路径或绝对路径
                if '?' in url_or_path:
                    url_or_path = url_or_path.split('?')[0]
                if not url_or_path.startswith('/'):
                    url_or_path = '/' + url_or_path
                return url_or_path
        except:
            return None

    def _merge_ast_info(self, entry, file_path, api):
        if 'ast' not in entry['sources']:
            entry['sources'].append('ast')
        
        # 检查是否重复
        for info in entry['ast_info']:
            if info.get('file') == file_path and info.get('loc') == api.get('loc'):
                return

        entry['ast_info'].append({
            'file': file_path,
            'raw_url': api.get('url'),
            'tool': api.get('tool'),
            'method': api.get('method'), # AST分析出的Method
            'args': api.get('args'),
            'loc': api.get('loc'),
            'context': api.get('context'),
            'type': api.get('type'),
            'params': api.get('params', [])
        })
        
        # 如果当前entry method未知，且AST有明确Method，更新之
        if entry['method'] == 'UNKNOWN' and api.get('method') and api.get('method') != 'UNKNOWN':
            entry['method'] = api.get('method').upper()
            # 此时key可能就不准确了，但我们在dict里的引用是对的

    def save_html_report(self, output_path):
        """保存HTML分析报告，包含代码上下文"""
        try:
            report_data = list(self.merged_apis.values())
            report_data.sort(key=lambda x: (
                'dynamic' in x['sources'] and 'ast' in x['sources'],
                'dynamic' in x['sources'],
                'ast' in x['sources']
            ), reverse=True)

            html_content = """
            <!DOCTYPE html>
            <html lang="zh-CN">
            <head>
                <meta charset="UTF-8">
                <title>API 接口分析详情报告</title>
                <style>
                    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; margin: 20px; background: #f5f5f5; }
                    .container { max-width: 1400px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
                    h1 { color: #333; border-bottom: 2px solid #eee; padding-bottom: 10px; }
                    table { width: 100%; border-collapse: collapse; margin-top: 20px; }
                    th, td { text-align: left; padding: 12px; border-bottom: 1px solid #eee; vertical-align: top; }
                    th { background-color: #f8f9fa; font-weight: 600; color: #555; }
                    tr:hover { background-color: #f9f9f9; }
                    .tag { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; margin-right: 4px; }
                    .tag-dynamic { background: #e3f2fd; color: #1565c0; }
                    .tag-ast { background: #e8f5e9; color: #2e7d32; }
                    .tag-regex { background: #fff3e0; color: #ef6c00; }
                    .method { font-weight: bold; min-width: 60px; display: inline-block; }
                    .method-GET { color: #61affe; }
                    .method-POST { color: #49cc90; }
                    .method-PUT { color: #fca130; }
                    .method-DELETE { color: #f93e3e; }
                    .code-block { background: #2d2d2d; color: #ccc; padding: 10px; border-radius: 4px; font-family: Consolas, Monaco, monospace; font-size: 12px; overflow-x: auto; margin-top: 5px; white-space: pre; }
                    .source-file { font-size: 12px; color: #666; margin-bottom: 4px; }
                    details { margin-top: 5px; }
                    summary { cursor: pointer; color: #007bff; font-size: 13px; }
                    .ast-item { border-left: 3px solid #007bff; padding-left: 10px; margin-bottom: 10px; }
                    .highlight { color: #fff; font-weight: bold; }
                    .highlight-url { background-color: #ffff00; color: #000; font-weight: bold; padding: 0 2px; border-radius: 2px; }
                    .highlight-method { background-color: #007bff; color: #fff; font-weight: bold; padding: 0 2px; border-radius: 2px; }
                    .highlight-param { background-color: #28a745; color: #fff; font-weight: bold; padding: 0 2px; border-radius: 2px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>API 接口分析详情报告</h1>
                    <p>总计发现接口: {total_count}</p>
                    <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:10px;">
                        <input id="searchInput" style="padding:8px 10px;border:1px solid #ddd;border-radius:6px;font-size:14px;min-width:220px;" placeholder="搜索 Path/URL/参数">
                        <select id="methodSelect" style="padding:8px 10px;border:1px solid #ddd;border-radius:6px;font-size:14px;">
                            <option value="">全部方法</option>
                            <option value="GET">GET</option>
                            <option value="POST">POST</option>
                            <option value="PUT">PUT</option>
                            <option value="DELETE">DELETE</option>
                        </select>
                        <label><input type="checkbox" id="srcDynamic" checked style="margin-right:6px;">动态</label>
                        <label><input type="checkbox" id="srcAst" checked style="margin-right:6px;">AST</label>
                        <label><input type="checkbox" id="srcRegex" checked style="margin-right:6px;">正则</label>
                    </div>
                    <table>
                        <thead>
                            <tr>
                                <th style="width: 80px">Method</th>
                                <th style="width: 300px">Path</th>
                                <th style="width: 150px">Sources</th>
                                <th>Details (Code Context & Dynamic Info)</th>
                            </tr>
                        </thead>
                        <tbody id="apiTableBody">
            """.replace('{total_count}', str(len(report_data)))

            for api in report_data:
                method_class = f"method-{api['method']}"
                sources_html = ""
                if 'dynamic' in api['sources']: sources_html += '<span class="tag tag-dynamic">Dynamic</span>'
                if 'ast' in api['sources'] or 'ast_string' in api['sources']: sources_html += '<span class="tag tag-ast">AST</span>'
                if 'regex' in api['sources']: sources_html += '<span class="tag tag-regex">Regex</span>'

                details_html = ""

                # 动态详情
                if api.get('dynamic_info'):
                    d_info = api['dynamic_info']
                    details_html += f"""
                    <details>
                        <summary>动态监控详情</summary>
                        <div style="font-size: 12px; color: #555; margin-top: 5px;">
                            <div><strong>Full URL:</strong> {api.get('full_url', '')} <button style="display:inline-block;margin-left:6px;padding:2px 6px;font-size:12px;border:1px solid #ddd;border-radius:4px;cursor:pointer;background:#fafafa;" onclick="copyText('{api.get('full_url', '')}')">复制</button></div>
                            <div><strong>Post Data:</strong> {d_info.get('post_data', '')}</div>
                            <div><strong>Headers:</strong> {str(d_info.get('headers', ''))[:200]}...</div>
                        </div>
                    </details>
                    """

                # 正则匹配详情（仅当没有AST信息时显示）
                if 'regex' in api.get('sources', []) and not api.get('ast_info'):
                    details_html += "<details><summary>正则匹配详情 (Code Context)</summary>"
                    path_key = api.get('path')
                    ctx_items = self.regex_context_map.get(path_key) or []
                    if ctx_items:
                        for info in ctx_items:
                            context_code = info.get('context', '') or ''
                            if context_code:
                                esc = context_code.replace('<', '&lt;').replace('>', '&gt;')
                                raw_url = info.get('raw_url', '')
                                if raw_url:
                                    esc = esc.replace(str(raw_url), f'<span class="highlight-url">{raw_url}</span>')
                                details_html += f"""
                                <div class="ast-item">
                                    <div class="source-file">File: {info.get('file', 'unknown')} (Line: {info.get('loc', 0)})</div>
                                    <div style="margin-bottom:5px">
                                        <span class="method method-UNKNOWN">UNKNOWN</span>
                                        <span style="font-family:monospace">{raw_url}</span>
                                        <button style="display:inline-block;margin-left:6px;padding:2px 6px;font-size:12px;border:1px solid #ddd;border-radius:4px;cursor:pointer;background:#fafafa;" onclick="copyText('{raw_url}')">复制</button>
                                    </div>
                                    <div class="code-block">{esc}</div>
                                </div>
                                """
                    else:
                        details_html += """
                        <div style="font-size: 12px; color: #555; margin-top: 5px;">
                            <div><strong>发现方式:</strong> JavaScript 正则表达式匹配</div>
                            <div><strong>说明:</strong> 该API通过正则模式从JS文件中提取，未包含代码上下文信息。</div>
                        </div>
                        """
                    details_html += "</details>"

                # AST 详情 (代码上下文)
                if api.get('ast_info'):
                    details_html += """<details open><summary>静态分析详情 (Code Context)</summary>"""
                    for info in api['ast_info']:
                        context_code = info.get('context', '')
                        
                        # HTML 转义
                        if context_code:
                            context_code = context_code.replace('<', '&lt;').replace('>', '&gt;')
                            
                            # 1. 高亮 URL
                            url_val = info.get('url', '') or info.get('raw_url', '')
                            if url_val and len(str(url_val)) > 1:
                                context_code = context_code.replace(str(url_val), f'<span class="highlight-url">{url_val}</span>')
                            
                            # 2. 高亮 Method
                            method_val = info.get('method', 'UNKNOWN')
                            if method_val and method_val != 'UNKNOWN':
                                # 尝试高亮大写和小写形式
                                context_code = context_code.replace(method_val.upper(), f'<span class="highlight-method">{method_val.upper()}</span>')
                                if method_val.lower() != method_val.upper():
                                    context_code = context_code.replace(method_val.lower(), f'<span class="highlight-method">{method_val.lower()}</span>')

                            # 3. 高亮 Params
                            params = info.get('params', []) or info.get('args', []) # 兼容不同字段名
                            if params and isinstance(params, list):
                                for param in params:
                                    if param and isinstance(param, str) and len(param) > 1:
                                        context_code = context_code.replace(param, f'<span class="highlight-param">{param}</span>')

                        # 构建 Params 展示 HTML
                        params_html = ""
                        params = info.get('params', []) or info.get('args', [])
                        if params:
                             params_html = f"<div style='margin-bottom:5px'><span class='tag'>Params:</span> <code style='color:#e83e8c'>{params}</code></div>"

                        details_html += f"""
                        <div class="ast-item">
                            <div class="source-file">File: {info.get('file', 'unknown')} (Line: {info.get('loc', 0)})</div>
                            <div style="margin-bottom:5px">
                                <span class="method method-{info.get('method', 'UNKNOWN')}">{info.get('method', 'UNKNOWN')}</span>
                                <span style="font-family:monospace">{info.get('raw_url', '') or info.get('url', '')}</span>
                                <button style="display:inline-block;margin-left:6px;padding:2px 6px;font-size:12px;border:1px solid #ddd;border-radius:4px;cursor:pointer;background:#fafafa;" onclick="copyText('{info.get('raw_url', '') or info.get('url', '')}')">复制</button>
                            </div>
                            {params_html}
                            <div class="code-block">{context_code}</div>
                        </div>
                        """
                    details_html += "</details>"

                html_content += f"""
                <tr data-method="{api['method']}" data-sources="{','.join(api.get('sources', []))}" data-path="{api['path'].lower()}">
                    <td><span class="method {method_class}">{api['method']}</span></td>
                    <td>{api['path']} <button style="display:inline-block;margin-left:6px;padding:2px 6px;font-size:12px;border:1px solid #ddd;border-radius:4px;cursor:pointer;background:#fafafa;" onclick="copyText('{api['path']}')">复制</button></td>
                    <td>{sources_html}</td>
                    <td>{details_html}</td>
                </tr>
                """

            html_content += """
                        </tbody>
                    </table>
                    <script>
                        function copyText(t){ if(!t) return; if(navigator.clipboard && navigator.clipboard.writeText){ navigator.clipboard.writeText(t); } }
                        const searchInput = document.getElementById('searchInput');
                        const methodSelect = document.getElementById('methodSelect');
                        const srcDynamic = document.getElementById('srcDynamic');
                        const srcAst = document.getElementById('srcAst');
                        const srcRegex = document.getElementById('srcRegex');
                        function applyFilter(){
                            const q = (searchInput && searchInput.value || '').toLowerCase();
                            const m = methodSelect && methodSelect.value || '';
                            const sDyn = srcDynamic && srcDynamic.checked;
                            const sAst = srcAst && srcAst.checked;
                            const sReg = srcRegex && srcRegex.checked;
                            const rows = document.querySelectorAll('#apiTableBody tr');
                            rows.forEach(r=>{
                                const rm = r.getAttribute('data-method') || '';
                                const rs = (r.getAttribute('data-sources') || '').split(',');
                                const rp = r.getAttribute('data-path') || '';
                                let ok = true;
                                if(m && rm !== m) ok = false;
                                if(ok){
                                    if(!sDyn && rs.includes('dynamic')) ok = false;
                                    if(!sAst && (rs.includes('ast') || rs.includes('ast_string'))) ok = false;
                                    if(!sReg && rs.includes('regex')) ok = false;
                                }
                                if(ok && q){
                                    const text = r.innerText.toLowerCase();
                                    if(!(rp.includes(q) || text.includes(q))) ok = false;
                                }
                                r.style.display = ok ? '' : 'none';
                            });
                        }
                        if(searchInput) searchInput.addEventListener('input', applyFilter);
                        if(methodSelect) methodSelect.addEventListener('input', applyFilter);
                        if(srcDynamic) srcDynamic.addEventListener('input', applyFilter);
                        if(srcAst) srcAst.addEventListener('input', applyFilter);
                        if(srcRegex) srcRegex.addEventListener('input', applyFilter);
                        applyFilter();
                    </script>
                </div>
            </body>
            </html>
            """
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            return True
        except Exception as e:
            print(f"[ContextDeduplicator] HTML报告保存失败: {e}")
            return False

    def save_report(self, output_path):
        """保存分析报告"""
        report_data = list(self.merged_apis.values())
        
        # 排序：优先显示 动态+AST 同时覆盖的，其次是 动态，最后是 其他
        report_data.sort(key=lambda x: (
            'dynamic' in x['sources'] and 'ast' in x['sources'],
            'dynamic' in x['sources'],
            'ast' in x['sources']
        ), reverse=True)
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"[ContextDeduplicator] 报告保存失败: {e}")
            return False

    def save_to_db(self):
        """保存到数据库"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute("CREATE TABLE IF NOT EXISTS step9_context_apis (method TEXT, path TEXT, sources TEXT, context_json TEXT)")
            conn.execute("DELETE FROM step9_context_apis")
            
            data = []
            for entry in self.merged_apis.values():
                context = {
                    'dynamic': entry['dynamic_info'],
                    'ast': entry['ast_info'],
                    'params': entry['params']
                }
                data.append((
                    entry['method'],
                    entry['path'],
                    ','.join(entry['sources']),
                    json.dumps(context, ensure_ascii=False)
                ))
            
            conn.executemany("INSERT INTO step9_context_apis (method, path, sources, context_json) VALUES (?, ?, ?, ?)", data)
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"[ContextDeduplicator] 数据库保存失败: {e}")
            return False

def run_context_deduplication(db_path, output_dir):
    print(f"[INFO] 开始上下文关联与去重分析...")
    deduplicator = ContextDeduplicator(db_path)
    if deduplicator.load_data():
        deduplicator.process()
        
        # 确保 manage 目录存在
        manage_dir = os.path.join(output_dir, 'manage')
        if not os.path.exists(manage_dir):
            os.makedirs(manage_dir)

        report_path = os.path.join(manage_dir, 'api_context_report.json')
        deduplicator.save_report(report_path)
        
        html_report_path = os.path.join(manage_dir, 'api_context_report.html')
        deduplicator.save_html_report(html_report_path)
        
        deduplicator.save_to_db()
        
        print(f"[SUCCESS] 分析完成，报告已生成: {report_path} 及 {html_report_path}")
        print(f"[INFO] 总共整合了 {len(deduplicator.merged_apis)} 个唯一接口")
        return deduplicator.merged_apis
    else:
        print(f"[ERROR] 数据加载失败")
        return {}
