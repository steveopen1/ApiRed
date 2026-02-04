import os
import re
import sqlite3
from urllib.parse import urlparse, unquote, urljoin
import requests

try:
    from plugins.nodeCommon import *
except Exception:
    try:
        from nodeCommon import *
    except Exception:
        def decode_path_safely(path): return path
try:
    from plugins.ast_analyzer import ASTAnalyzer
except Exception:
    try:
        from ast_analyzer import ASTAnalyzer
    except Exception:
        ASTAnalyzer = None

def _extract_dynamic_imports(text):
    paths = set()
    try:
        # import("...") / import('...') / import(/* webpackChunkName */ "...")
        for m in re.finditer(r'import\(\s*[\'"]([^\'"]+)[\'"]\s*\)', text):
            p = m.group(1).strip()
            if p:
                # 解码路径（处理URL编码和错误编码的中文）
                p = decode_path_safely(p)
                paths.add(p)
        # require.ensure([...], ...) / __webpack_require__.e("chunk") / chunk mapping
        for m in re.finditer(r'["\'](\./[^"\']+\.js)["\']', text):
            p = m.group(1).strip()
            if p:
                p = decode_path_safely(p)
                paths.add(p)
        # webpack chunkfile name hints: "chunkName":"xyz", path "./xyz.js"
        for m in re.finditer(r'["\'](?:chunkName|name)["\']\s*:\s*["\']([^"\']+)["\']', text):
            hint = m.group(1).strip()
            if hint and not hint.endswith('.js'):
                hint = decode_path_safely(hint)
                paths.add(f'./{hint}.js')
    except Exception:
        pass
    return list(paths)

def is_wrapped_html_js(path):
    """检测是否是 JS 包装的 HTML 页面，例如 ./xxx.html-abc12345.js"""
    return bool(re.search(r'\.html-[a-f0-9]{6,10}\.js$', path, re.IGNORECASE))

def restore_dynamic_js_modules(folder_path, db_path=None):
    cache_root = os.path.join(folder_path, "js")
    if not os.path.isdir(cache_root):
        cache_root = os.path.join(folder_path, "js_cache")
    found = set()
    wrapped_html_pages = []  # 记录疑似包装HTML的JS
    ast_found = set()
    base_url = ""
    if db_path:
        try:
            conn0 = sqlite3.connect(db_path)
            try:
                cur0 = conn0.execute("SELECT original_url FROM meta_target_info LIMIT 1")
                row0 = cur0.fetchone()
                if row0:
                    base_url = row0[0] or ""
            except Exception:
                pass
            conn0.close()
        except Exception:
            pass
    
    for root, _, files in os.walk(cache_root):
        for name in files:
            if not name.endswith(".js"):
                continue
            fp = os.path.join(root, name)
            try:
                with open(fp, "rt", encoding="utf-8") as f:
                    text = f.read()
            except Exception:
                continue
            if ASTAnalyzer:
                try:
                    analyzer = ASTAnalyzer()
                    res = analyzer.analyze_file(fp)
                    for di in res.get('dynamic_imports', []) or []:
                        p = str(di.get('value') or '').strip()
                        if p:
                            p = decode_path_safely(p)
                            ast_found.add(p.replace("\\", "/"))
                except Exception:
                    pass
            for p in _extract_dynamic_imports(text):
                # 规范化去除多余字符
                p = p.replace("\\", "/").strip()
                if p:
                    found.add(p)
                    # 检测是否是包装HTML的JS
                    if is_wrapped_html_js(p):
                        wrapped_html_pages.append(p)
    
    out = sorted(set(list(found) + list(ast_found)))
    if db_path:
        try:
            conn = sqlite3.connect(db_path)
            
            # 获取基准URL用于补全
            target_base_url = base_url

            conn.execute("CREATE TABLE IF NOT EXISTS step2_dynamic_js_paths (path TEXT UNIQUE)")
            for p in out:
                try:
                    conn.execute("INSERT OR IGNORE INTO step2_dynamic_js_paths(path) VALUES(?)", (p,))
                except Exception:
                    pass
            
            # 标记包装HTML的JS为敏感信息
            if wrapped_html_pages:
                try:
                    conn.execute("CREATE TABLE IF NOT EXISTS step8_sensitive (name TEXT, matches TEXT, url TEXT, file TEXT, severity TEXT, evidence TEXT)")
                    for p in wrapped_html_pages:
                        # 修复可能的乱码
                        clean_p = decode_path_safely(p)
                        # 补全完整URL
                        full_url = p
                        if target_base_url and not p.startswith(('http://', 'https://')):
                            from urllib.parse import urljoin, quote
                            full_url = urljoin(target_base_url, p)
                            # 对 URL 进行 quote 处理
                            try:
                                parts = full_url.split('://', 1)
                                if len(parts) == 2:
                                    scheme, rest = parts
                                    host_parts = rest.split('/', 1)
                                    if len(host_parts) == 2:
                                        host, path_part = host_parts
                                        full_url = f"{scheme}://{host}/{quote(path_part)}"
                            except Exception: pass
                            
                        try:
                            conn.execute(
                                "INSERT INTO step8_sensitive(name, matches, url, file, severity, evidence) VALUES(?,?,?,?,?,?)",
                                ("JS Wrapped HTML Page", clean_p, full_url, clean_p, "high", f"[Dynamic Import] 发现包装HTML页面的JS模块: {clean_p}")
                            )
                        except Exception:
                            pass
                except Exception:
                    pass
            
            try:
                download_dir = os.path.join(folder_path, "js_dynamic")
                try:
                    os.makedirs(download_dir, exist_ok=True)
                except Exception:
                    pass
                for rel in out:
                    try:
                        rel2 = rel.strip()
                        if not rel2:
                            continue
                        if rel2.startswith('./'):
                            rel2 = rel2[2:]
                        if rel2.startswith('/'):
                            full_url = urljoin(target_base_url, rel2)
                        else:
                            full_url = urljoin(target_base_url.rstrip('/') + '/', rel2)
                        ok = False
                        try:
                            r = requests.get(full_url, timeout=10, verify=False)
                            if r.status_code == 200 and r.text:
                                ok = True
                                fn = os.path.basename(rel2)
                                fp_out = os.path.join(download_dir, fn)
                                try:
                                    with open(fp_out, "w", encoding="utf-8") as wf:
                                        wf.write(r.text)
                                except Exception:
                                    pass
                                try:
                                    conn.execute(
                                        "INSERT INTO step8_sensitive(name, matches, url, file, severity, evidence) VALUES(?,?,?,?,?,?)",
                                        ("Dynamic JS Module", rel, full_url, fp_out, "medium", "")
                                    )
                                except Exception:
                                    pass
                        except Exception:
                            pass
                    except Exception:
                        pass
            except Exception:
                pass
            
            conn.commit()
            conn.close()
        except Exception:
            pass
