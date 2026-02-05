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
                    norm_path = self._normalize_path(path)
                    if not norm_path:
                        continue
                    ctx = None
                    try:
                        ctx = json.loads(row['regex_context_json'])
                    except Exception:
                        ctx = None
                    if not ctx:
                        continue
                    items = ctx_map.get(norm_path) or []
                    items.append({
                        'file': ctx.get('file'),
                        'loc': ctx.get('loc', 0),
                        'context': ctx.get('context') or '',
                        'raw_url': ctx.get('raw_url') or ''
                    })
                    ctx_map[norm_path] = items
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

        for entry in self.merged_apis.values():
            ast_items = entry.get('ast_info') or []
            if ast_items:
                if any((i.get('type') != 'string_literal') for i in ast_items):
                    entry['sources'] = [s for s in entry.get('sources', []) if s != 'ast_string']
                entry['sources'] = [s for s in entry.get('sources', []) if s != 'regex']
                entry['regex_match'] = False
                try:
                    entry['sources'] = list(dict.fromkeys(entry['sources']))
                except Exception:
                    pass

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
            'params': api.get('params', []),
            'param_sources': api.get('param_sources', [])
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

            file_groups = {}
            for entry in report_data:
                for ai in entry.get('ast_info') or []:
                    f = ai.get('file') or ''
                    if not f:
                        continue
                    if f not in file_groups:
                        file_groups[f] = []
                    file_groups[f].append({
                        'path': entry.get('path'),
                        'method': ai.get('method', 'UNKNOWN'),
                        'url': ai.get('raw_url', '') or ai.get('url', ''),
                        'loc': ai.get('loc', 0),
                        'context': ai.get('context', ''),
                        'params': ai.get('params', []) if isinstance(ai.get('params', []), list) else [],
                        'param_sources': ai.get('param_sources', []),
                        'type': ai.get('type', ''),
                        'tool': ai.get('tool', '')
                    })
            for f, items in list(file_groups.items()):
                by_loc = {}
                for it in items:
                    loc = int(it.get('loc') or 0)
                    cur = by_loc.get(loc)
                    if not cur:
                        by_loc[loc] = {
                            'path': it.get('path'),
                            'method': it.get('method', 'UNKNOWN'),
                            'url': it.get('url', ''),
                            'loc': loc,
                            'context': it.get('context', ''),
                            'params': list(it.get('params', [])) if isinstance(it.get('params', []), list) else [],
                            'param_sources': list(it.get('param_sources', [])) if isinstance(it.get('param_sources', []), list) else []
                        }
                    else:
                        if (not cur.get('url')) or cur.get('url') == 'UNKNOWN':
                            if it.get('url'):
                                cur['url'] = it.get('url')
                        if cur.get('method', 'UNKNOWN') == 'UNKNOWN' and it.get('method') and it.get('method') != 'UNKNOWN':
                            cur['method'] = it.get('method')
                        p = it.get('params', []) if isinstance(it.get('params', []), list) else []
                        cur['params'] = list(dict.fromkeys((cur['params'] or []) + p))
                        ps = it.get('param_sources', []) if isinstance(it.get('param_sources', []), list) else []
                        cur['param_sources'] = list((cur['param_sources'] or []) + ps)
                        if not cur.get('context') and it.get('context'):
                            cur['context'] = it.get('context')
                        if not cur.get('path') and it.get('path'):
                            cur['path'] = it.get('path')
                enriched = []
                try:
                    lines = []
                    if os.path.exists(f):
                        with open(f, 'r', encoding='utf-8', errors='ignore') as _rf:
                            lines = _rf.read().splitlines()
                    for it in list(by_loc.values()):
                        ln = int(it.get('loc') or 0)
                        s = max(0, ln - 30)
                        e = min(len(lines), ln + 30) if lines else ln
                        win_text = "\n".join(lines[s:e]) if lines else (it.get('context') or '')
                        h = hashlib.md5((win_text or '').encode('utf-8', 'ignore')).hexdigest()
                        it2 = dict(it)
                        it2['s'] = s
                        it2['e'] = e
                        it2['hash'] = h
                        enriched.append(it2)
                    clusters = []
                    used = [False] * len(enriched)
                    for i in range(len(enriched)):
                        if used[i]:
                            continue
                        g = [enriched[i]]
                        used[i] = True
                        for j in range(i + 1, len(enriched)):
                            if used[j]:
                                continue
                            if enriched[j]['hash'] == enriched[i]['hash']:
                                used[j] = True
                                g.append(enriched[j])
                        clusters.append(g)
                    merged = []
                    def overlap(a, b):
                        return not (a[1] < b[0] or b[1] < a[0])
                    N = 6
                    for g in clusters:
                        r = (min([x['s'] for x in g]), max([x['e'] for x in g]))
                        locs = sorted(list({int(x.get('loc') or 0) for x in g}))
                        merged_into = False
                        for mg in merged:
                            rr = mg['range']
                            if overlap(r, rr) or any(abs(p - q) <= N for p in locs for q in mg['locs']):
                                mg['locs'] = sorted(list({*mg['locs'], *locs}))
                                mg['range'] = (min(mg['range'][0], r[0]), max(mg['range'][1], r[1]))
                                mg['params'] = list(dict.fromkeys((mg['params'] or []) + (g[0].get('params', []) if isinstance(g[0].get('params', []), list) else [])))
                                mg['param_sources'] = list((mg['param_sources'] or []) + (g[0].get('param_sources', []) if isinstance(g[0].get('param_sources', []), list) else []))
                                if (not mg['url']) or mg['url'] == 'UNKNOWN':
                                    if g[0].get('url'):
                                        mg['url'] = g[0].get('url')
                                if mg['method'] == 'UNKNOWN' and g[0].get('method') and g[0].get('method') != 'UNKNOWN':
                                    mg['method'] = g[0].get('method')
                                merged_into = True
                                break
                        if not merged_into:
                            merged.append({
                                'path': g[0].get('path'),
                                'method': g[0].get('method', 'UNKNOWN'),
                                'url': g[0].get('url', ''),
                                'loc': int(g[0].get('loc') or 0),
                                'locs': locs,
                                's': r[0],
                                'e': r[1],
                                'context': g[0].get('context', ''),
                                'params': g[0].get('params', []) if isinstance(g[0].get('params', []), list) else [],
                                'param_sources': g[0].get('param_sources', []) if isinstance(g[0].get('param_sources', []), list) else [],
                                'range': r
                            })
                    file_groups[f] = merged
                except Exception:
                    file_groups[f] = list(by_loc.values())
            multi_file_groups = {k: v for k, v in file_groups.items() if len(v) >= 2}


            html_content = """
            <!DOCTYPE html>
            <html lang="zh-CN">
            <head>
                <meta charset="UTF-8">
                <title>API 接口分析详情报告</title>
                <style>
                    ::-webkit-scrollbar { width: 8px; height: 8px; }
                    ::-webkit-scrollbar-track { background: #f5f5f5; }
                    ::-webkit-scrollbar-thumb { background: #ccc; border-radius: 4px; }
                    ::-webkit-scrollbar-thumb:hover { background: #999; }
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
                    .tag-kind { display:inline-block; padding:2px 6px; border-radius:4px; font-size:12px; margin-left:8px; border:1px solid #ddd; }
                    .kind-interface { background:#e8f4ff; color:#0969da; }
                    .kind-param { background:#e9fbe8; color:#1f883d; }
                    .kind-other { background:#eee; color:#666; }
                    .loc-chip { display:inline-block; padding:0 6px; margin-left:6px; font-size:12px; border:1px solid #ddd; border-radius:10px; background:#fff; cursor:pointer; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>API 接口分析详情报告</h1>
                    <p>总计发现接口: {total_count}</p>
            """.replace('{total_count}', str(len(report_data)))

            html_content += """
                    <style>
                        .card-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 12px; margin-top: 16px; }
                        .file-card { border: 1px solid #eee; border-radius: 8px; padding: 12px; background: #fafafa; }
                        .file-card h3 { margin: 0 0 8px 0; font-size: 14px; }
                        .open-btn { display:inline-block;padding:4px 8px;font-size:12px;border:1px solid #ddd;border-radius:4px;background:#fff;cursor:pointer; }
                        .modal { position: fixed; left:0; top:0; width:100%; height:100%; background: rgba(0,0,0,0.5); display:none; align-items:center; justify-content:center; padding:20px; }
                        .modal-content { width: 95%; max-width: 1200px; background:#fff; border-radius:8px; overflow:hidden; display:flex; flex-direction:row; }
                        .modal-left { flex: 2; padding: 16px; border-right: 1px solid #eee; }
                        .modal-right { flex: 1; padding: 16px; max-height: 80vh; overflow:auto; }
                    .iface-item { padding:6px 8px; border-bottom:1px solid #f0f0f0; cursor:pointer; }
                        .iface-item:hover { background:#f5f5f5; }
                    .iface-item.active { background:#e6f2ff; border-left:3px solid #0969da; }
                        .modal-header { display:flex; align-items:center; justify-content:space-between; padding:10px 16px; border-bottom:1px solid #eee; }
                        .close-btn { border:none; background:#f44336; color:#fff; padding:6px 10px; border-radius:4px; cursor:pointer; }
                    </style>
                    <details open>
                        <summary>AST 文件卡片视图</summary>
                        <div class="card-grid">
            """

            for file_path, items in multi_file_groups.items():
                card_id = f"card_{abs(hash(file_path))}"
                html_content += f"""
                            <div class="file-card">
                                <h3>{file_path}</h3>
                                <div>匹配接口数量: {len(items)}</div>
                                <button class="open-btn" onclick="openFileCard('{card_id}')">打开卡片</button>
                            </div>
                            <div id="{card_id}" class="modal">
                                <div class="modal-content">
                                    <div class="modal-left">
                                        <div class="modal-header">
                                            <div style="font-size:13px">{file_path}</div>
                                            <div><button class="close-btn" onclick="closeFileCard('{card_id}')">关闭</button></div>
                                        </div>
                                        <div id="{card_id}_viewer" class="code-block"></div>
                                        <div id="{card_id}_status" style="font-size:12px;color:#666;margin-top:6px;">当前行: -</div>
                                    </div>
                                    <div class="modal-right">
                """
                for idx, it in enumerate(items):
                    url_show = it.get('url', '')
                    method_show = (it.get('method') or 'UNKNOWN')
                    param_sources = it.get('param_sources', []) or []
                    param_names = [p.get('name') for p in param_sources if isinstance(p, dict) and p.get('name')]
                    if not param_names and isinstance(it.get('params', []), list):
                        param_names = it.get('params', [])
                    sources_set = sorted({(p.get('source') if isinstance(p, dict) else '') for p in param_sources} - {''})
                    has_params = bool(param_names)
                    has_interface = bool((url_show and url_show != 'UNKNOWN') or (method_show and method_show != 'UNKNOWN'))
                    kind_labels = []
                    kind_classes = []
                    if has_interface:
                        kind_labels.append('接口')
                        kind_classes.append('kind-interface')
                    if has_params:
                        kind_labels.append('参数')
                        kind_classes.append('kind-param')
                    tags_html = "".join([f"<span class='tag-kind {cls}'>{lbl}</span>" for (lbl, cls) in zip(kind_labels, kind_classes)]) or "<span class='tag-kind kind-other'>其他</span>"
                    source_hint = f"源: {','.join(sources_set)}" if sources_set else ''
                    params_info_html = ""
                    if has_params:
                        params_info_html = "<div style='font-size:12px;color:#333'>Params: [" + ", ".join(param_names) + "]</div>"
                    context_code_long = it.get('context', '')
                    try:
                        if os.path.exists(file_path):
                            ln2 = int((it.get('locs') or [it.get('loc') or 0])[0] or 0)
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as _f2:
                                lines2 = _f2.read().splitlines()
                                s2 = int(it.get('s') or max(0, ln2 - 30))
                                e2 = int(it.get('e') or min(len(lines2), ln2 + 30))
                                buf2 = []
                                for j2 in range(s2, e2):
                                    prefix2 = '> ' if (j2 + 1) == ln2 else '  '
                                    buf2.append(f"{prefix2}{j2+1}: {lines2[j2]}")
                                context_code_long = "\n".join(buf2)
                    except Exception:
                        context_code_long = context_code_long or ''
                    esc_long = (context_code_long or '').replace('<', '&lt;').replace('>', '&gt;')
                    if url_show:
                        esc_long = esc_long.replace(str(url_show), f"<span class='highlight-url'>{url_show}</span>")
                    if method_show and method_show != 'UNKNOWN':
                        esc_long = esc_long.replace(method_show.upper(), f"<span class='highlight-method'>{method_show.upper()}</span>")
                        if method_show.lower() != method_show.upper():
                            esc_long = esc_long.replace(method_show.lower(), f"<span class='highlight-method'>{method_show.lower()}</span>")
                    if param_names:
                        for pn in param_names:
                            if pn and isinstance(pn, str) and len(pn) > 1:
                                esc_long = esc_long.replace(pn, f"<span class='highlight-param'>{pn}</span>")
                    esc_long = esc_long.replace('"', '&quot;').replace("'", '&#39;')
                    locs = it.get('locs') or [int(it.get('loc') or 0)]
                    locs_html = " ".join([f"<span class='loc-chip' onclick=\"jumpOnly('{card_id}', {ln})\">{ln}</span>" for ln in locs])
                    html_content += f"""
                                        <div class="iface-item" onclick="switchInterface('{card_id}', {int(locs[0] if isinstance(locs, list) and locs else (it.get('loc') or 0))})" data-view-long="{esc_long}" data-loc="{int(locs[0] if isinstance(locs, list) and locs else (it.get('loc') or 0))}" data-locs="{','.join([str(x) for x in (locs if isinstance(locs, list) else [int(it.get('loc') or 0)])])}">
                                            <div>
                                                <span class="method method-{method_show}">{method_show}</span>
                                                <span style="font-family:monospace">{url_show}</span>
                                                {tags_html}
                                            </div>
                                            <div style="font-size:12px;color:#666">{it.get('path','')} {source_hint} | Line: {int(locs[0] if isinstance(locs, list) and locs else (it.get('loc') or 0))} {locs_html}</div>
                                            {params_info_html}
                                        </div>
                    """
                html_content += f"""
                                    </div>
                                </div>
                            </div>
                """
            html_content += """
                        </div>
                    </details>
            """

            html_content += """
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
                # 根据规则：若存在 AST 匹配（ast_info 非空），则不显示 Regex 标签
                effective_sources = list(api.get('sources', []))
                if api.get('ast_info'):
                    try:
                        effective_sources = [s for s in effective_sources if s != 'regex']
                    except Exception:
                        pass
                sources_html = ""
                if 'dynamic' in effective_sources: sources_html += '<span class="tag tag-dynamic">Dynamic</span>'
                if ('ast' in effective_sources) or ('ast_string' in effective_sources) or api.get('ast_info'): sources_html += '<span class="tag tag-ast">AST</span>'
                if 'regex' in effective_sources and not api.get('ast_info'): sources_html += '<span class="tag tag-regex">Regex</span>'

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
                    norm_key = self._normalize_path(path_key)
                    ctx_items = self.regex_context_map.get(norm_key) or []
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
                    ast_infos = api['ast_info'] or []
                    has_non_string_literal = any((i.get('type') != 'string_literal') for i in ast_infos)
                    display_infos = [i for i in ast_infos if (i.get('type') != 'string_literal')] if has_non_string_literal else ast_infos
                    for info in display_infos:
                        file_is_multi = info.get('file') in multi_file_groups
                        context_code = info.get('context', '')
                        if not context_code:
                            try:
                                fp = info.get('file')
                                ln = int(info.get('loc') or 0)
                                if fp and ln > 0 and os.path.exists(fp):
                                    with open(fp, 'r', encoding='utf-8', errors='ignore') as _f:
                                        lines = _f.read().splitlines()
                                        s = max(0, ln - 6)
                                        e = min(len(lines), ln + 6)
                                        buf = []
                                        for idx in range(s, e):
                                            prefix = '> ' if (idx + 1) == ln else '  '
                                            buf.append(f"{prefix}{idx+1}: {lines[idx]}")
                                        context_code = "\n".join(buf)
                            except Exception:
                                context_code = ''
                        
                        if context_code and not file_is_multi:
                            context_code = context_code.replace('<', '&lt;').replace('>', '&gt;')
                            
                            url_val = info.get('url', '') or info.get('raw_url', '')
                            if url_val and len(str(url_val)) > 1:
                                context_code = context_code.replace(str(url_val), f'<span class=\"highlight-url\">{url_val}</span>')
                            
                            method_val = info.get('method', 'UNKNOWN')
                            if method_val and method_val != 'UNKNOWN':
                                context_code = context_code.replace(method_val.upper(), f'<span class=\"highlight-method\">{method_val.upper()}</span>')
                                if method_val.lower() != method_val.upper():
                                    context_code = context_code.replace(method_val.lower(), f'<span class=\"highlight-method\">{method_val.lower()}</span>')

                            ps = info.get('param_sources', []) or []
                            param_names = [p.get('name') for p in ps if isinstance(p, dict) and p.get('name')]
                            params_list = param_names if param_names else (info.get('params', []) if isinstance(info.get('params', []), list) else [])
                            if params_list:
                                for param in params_list:
                                    if param and isinstance(param, str) and len(param) > 1:
                                        context_code = context_code.replace(param, f'<span class=\"highlight-param\">{param}</span>')

                        params_html = ""
                        ps = info.get('param_sources', []) or []
                        param_names = [p.get('name') for p in ps if isinstance(p, dict) and p.get('name')]
                        if not param_names and isinstance(info.get('params', []), list):
                            param_names = info.get('params', [])
                        if param_names:
                             params_html = f"<div style='margin-bottom:5px'><span class='tag'>Params:</span> <code style='color:#e83e8c'>{param_names}</code></div>"

                        full_context_html = ""
                        try:
                            fp = info.get('file')
                            ln = int(info.get('loc') or 0)
                            if fp and ln > 0 and os.path.exists(fp):
                                with open(fp, 'r', encoding='utf-8', errors='ignore') as _f:
                                    lines = _f.read().splitlines()
                                    s2 = max(0, ln - 30)
                                    e2 = min(len(lines), ln + 30)
                                    buf2 = []
                                    for idx in range(s2, e2):
                                        prefix2 = '> ' if (idx + 1) == ln else '  '
                                        buf2.append(f"{prefix2}{idx+1}: {lines[idx]}")
                                    fc = "\n".join(buf2)
                                    fc = fc.replace('<', '&lt;').replace('>', '&gt;')
                                    url_val2 = info.get('url', '') or info.get('raw_url', '')
                                    if url_val2 and len(str(url_val2)) > 1:
                                        fc = fc.replace(str(url_val2), f"<span class='highlight-url'>{url_val2}</span>")
                                    method_val2 = info.get('method', 'UNKNOWN')
                                    if method_val2 and method_val2 != 'UNKNOWN':
                                        fc = fc.replace(method_val2.upper(), f"<span class='highlight-method'>{method_val2.upper()}</span>")
                                        if method_val2.lower() != method_val2.upper():
                                            fc = fc.replace(method_val2.lower(), f"<span class='highlight-method'>{method_val2.lower()}</span>")
                                    ps2 = info.get('param_sources', []) or []
                                    param_names2 = [p.get('name') for p in ps2 if isinstance(p, dict) and p.get('name')]
                                    params_list2 = param_names2 if param_names2 else (info.get('params', []) if isinstance(info.get('params', []), list) else [])
                                    if params_list2:
                                        for param in params_list2:
                                            if param and isinstance(param, str) and len(param) > 1:
                                                fc = fc.replace(param, f"<span class='highlight-param'>{param}</span>")
                                    full_context_html = f"<details><summary>查看完整上下文</summary><div class='code-block'>{fc}</div></details>"
                        except Exception:
                            full_context_html = ""

                        if file_is_multi:
                            card_id = f"card_{abs(hash(info.get('file')))}"
                            details_html += f"""
                            <div class="ast-item">
                                <div class="source-file">File: {info.get('file', 'unknown')} (Line: {info.get('loc', 0)})</div>
                                <div style="margin-bottom:5px">
                                    <span class="method method-{info.get('method', 'UNKNOWN')}">{info.get('method', 'UNKNOWN')}</span>
                                    <span style="font-family:monospace">{info.get('raw_url', '') or info.get('url', '')}</span>
                                    <button style="display:inline-block;margin-left:6px;padding:2px 6px;font-size:12px;border:1px solid #ddd;border-radius:4px;cursor:pointer;background:#fafafa;" onclick="copyText('{info.get('raw_url', '') or info.get('url', '')}')">复制</button>
                                    <button class="open-btn" style="margin-left:8px" onclick="openFileCardTarget('{card_id}', {int(info.get('loc') or 0)})">打开文件卡片</button>
                                </div>
                                {params_html}
                            </div>
                            """
                        else:
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
                                {full_context_html}
                            </div>
                            """
                    details_html += "</details>"

                # data-sources 用于筛选，同步遵循显示规则（隐藏 regex 当 AST 覆盖）
                html_content += f"""
                <tr data-method="{api['method']}" data-sources="{','.join(effective_sources)}" data-path="{api['path'].lower()}">
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
                    <script>
                        function openFileCard(id){
                            var m = document.getElementById(id);
                            if(!m) return;
                            m.style.display='flex';
                            var rightList = m.querySelectorAll('.modal-right .iface-item');
                            rightList.forEach(function(el){ el.classList.remove('active'); });
                            var first = m.querySelector('.modal-right .iface-item');
                            var viewer = document.getElementById(id+'_viewer');
                            var status = document.getElementById(id+'_status');
                            if(first && viewer){
                                first.classList.add('active');
                                var v = first.getAttribute('data-view-long') || '';
                                viewer.innerHTML = v;
                                var loc = first.getAttribute('data-loc') || '-';
                                if(status){ status.textContent = '当前行: ' + loc; }
                            }
                        }
                        function closeFileCard(id){
                            var m = document.getElementById(id);
                            if(m){ m.style.display='none'; }
                        }
                        function openFileCardTarget(id, loc){
                            openFileCard(id);
                            try{
                                var m = document.getElementById(id);
                                var items = m ? m.querySelectorAll('.modal-right .iface-item') : [];
                                var target = null;
                                items.forEach(function(el){
                                    var locs = (el.getAttribute('data-locs') || '').split(',').map(function(x){ return parseInt(x || '0'); });
                                    if(locs.indexOf(parseInt(loc || '0')) !== -1){ target = el; }
                                });
                                if(target){
                                    var v = target.getAttribute('data-view-long') || '';
                                    var viewer = document.getElementById(id+'_viewer');
                                    var status = document.getElementById(id+'_status');
                                    var rightList = m.querySelectorAll('.modal-right .iface-item');
                                    rightList.forEach(function(el){ el.classList.remove('active'); });
                                    target.classList.add('active');
                                    if(viewer && v){ viewer.innerHTML = v; viewer.scrollTop = 0; }
                                    if(status){ status.textContent = '当前行: ' + (loc || '-'); }
                                    target.scrollIntoView({behavior:'smooth', block:'center'});
                                }
                            }catch(e){}
                        }
                        function switchInterface(id, loc){
                            var m = document.getElementById(id);
                            if(!m) return;
                            var ev = window.event;
                            var t = ev && ev.currentTarget;
                            var v = t && t.getAttribute('data-view-long');
                            var viewer = document.getElementById(id+'_viewer');
                            var status = document.getElementById(id+'_status');
                            if(viewer && v){ viewer.innerHTML = v; viewer.scrollTop = 0; }
                            var rightList = m.querySelectorAll('.modal-right .iface-item');
                            rightList.forEach(function(el){ el.classList.remove('active'); });
                            if(t){ t.classList.add('active'); }
                            if(status){ status.textContent = '当前行: ' + (loc || '-'); }
                        }
                        function jumpOnly(id, loc){
                            var status = document.getElementById(id+'_status');
                            if(status){ status.textContent = '当前行: ' + (loc || '-'); }
                        }
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
