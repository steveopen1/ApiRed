import os
import re
import threading
from collections import defaultdict
from hashlib import sha256
import shutil
import sqlite3
import yaml
import json
import hashlib
import os

try:
    from plugins.nodeCommon import *
except Exception as e:
    from nodeCommon import *

unified_rules = []
try:
    root_dir = os.path.dirname(os.path.dirname(__file__))
    cfg_path = os.path.join(root_dir, 'config.yaml')
    if os.path.exists(cfg_path):
        with open(cfg_path, 'r', encoding='utf-8') as f:
            cfg = yaml.safe_load(f) or {}
            unified_rules = (cfg.get('rules') or [])
except Exception:
    pass

def reconstruct_url_from_filename(filename):
    """
    智能将本地 RESPONSE 文件名逆向还原为原始 URL
    支持 JS_, GET_, POST_DATA_, POST_JSON_ 等前缀格式
    """
    try:
        name = os.path.basename(filename)
        # 移除前缀
        prefixes = ['GET_PARAMETERS_', 'POST_DATA_PARAMETERS_', 'POST_JSON_PARAMETERS_', 
                    'GET_', 'POST_DATA_', 'POST_JSON_', 'JS_', 'PARAMETERS_']
        for p in prefixes:
            if name.startswith(p):
                name = name[len(p):]
                break
        
        if name.endswith('.txt'): name = name[:-4]
        if name.endswith('.resp'): name = name[:name.rfind('_')] # 处理包含TS的.resp
        
        # 还原协议和路径
        url = name.replace('___', '://').replace('_', '/')
        if '://' not in url: url = 'https://' + url
        return url
    except Exception:
        return ""

# 编译并统一规则池
unified_rules_list = []
logger_print_content(f"[敏感信息扫描] 开始加载规则...")
for rule in unified_rules:
    if not rule.get('enabled', True): continue
    try:
        rule['compiled_pattern'] = re.compile(rule['pattern'])
        unified_rules_list.append(rule)
    except Exception as e:
        logger_print_content(f"规则 {rule.get('id')} 正则编译失败: {e}")
logger_print_content(f"[敏感信息扫描] 成功加载 {len(unified_rules_list)} 条规则")

try:
    from plugins.sensitive_report import generate_sensitive_report
except Exception:
    try:
        from sensitive_report import generate_sensitive_report
    except Exception:
        def generate_sensitive_report(*args, **kwargs): pass

# 导入HTML还原模块
try:
    from plugins.htmlRestorer import restore_html_pages
except Exception:
    try:
        from htmlRestorer import restore_html_pages
    except Exception:
        def restore_html_pages(*args, **kwargs): return []

# 导入URL扫描模块
try:
    from plugins.url_scanner import scan_urls_for_sensitive_info
except Exception:
    try:
        from url_scanner import scan_urls_for_sensitive_info
    except Exception:
        def scan_urls_for_sensitive_info(*args, **kwargs): return []

# 差异化response
def diff_response_api(folder_path, filePath_url_info, db_path=None, existing_conn=None):
    if db_path and os.path.isfile(db_path):
        try:
            return diff_response_api_sqlite(folder_path, filePath_url_info, db_path, existing_conn)
        except Exception as e:
            logger_print_content(f"SQLite diff failed, falling back to file scan: {e}")
            pass
            
    return diff_response_api_fallback(folder_path, filePath_url_info)

def diff_response_api_sqlite(folder_path, filePath_url_info, db_path, existing_conn=None):
    diff_response_info = []
    diff_response_dir = f"{folder_path}/差异化response"
    os.makedirs(diff_response_dir, exist_ok=True)
    hash_file_path = os.path.join(f"{folder_path}/8-1-响应包diff_hash.txt")
    
    should_close = False
    if existing_conn:
        conn = existing_conn
    else:
        conn = sqlite3.connect(db_path, timeout=60)
        should_close = True
        
    try:
        # Check if response_files table exists and has data
        try:
            cursor = conn.execute("SELECT COUNT(*) FROM response_files")
            if cursor.fetchone()[0] == 0:
                 conn.close()
                 return diff_response_api_fallback(folder_path, filePath_url_info)
        except Exception:
             if should_close: conn.close()
             return diff_response_api_fallback(folder_path, filePath_url_info)
        
        cursor = conn.execute("""
            SELECT rf.content_hash, COUNT(*), rf.length, GROUP_CONCAT(rf.file_path, '|')
            FROM response_files rf
            INNER JOIN response_log rl ON rf.request_id = rl.id
            WHERE rl.res_type LIKE '%json%' OR rl.res_type LIKE '%xml%'
            GROUP BY rf.content_hash
            ORDER BY COUNT(*) ASC, rf.length DESC
        """)
        
        with open(hash_file_path, 'wt', encoding='utf-8') as hash_file, open(f"./result.txt", 'at', encoding='utf-8') as result_file:
             for row in cursor:
                 content_hash, count, size, paths_str = row
                 paths = paths_str.split('|')
                 
                 hash_file.write(f"{content_hash} ({count} 次, 大小: {size} 字节):\n")
                 for path in paths:
                     hash_file.write(f"{path}\n")
                 
                 if count < 10:
                     result_file.writelines(f"{content_hash} ({count} 次, 大小: {size} 字节):\n")
                     for path in paths:
                        url = filePath_url_info.get(path, "") or reconstruct_url_from_filename(path)
                        url_check = url.split('?', 1)[0].lower() if url else ""
                        if url_check.endswith('.js'):
                            continue
                        result_file.write(f"{path}\n")
                        diff_response_info.append([content_hash, count, size, url, path])
                         
                        # Copy file
                        try:
                            dest_path = os.path.join(diff_response_dir, os.path.basename(path))
                            if not os.path.exists(dest_path):
                                shutil.copy2(path, dest_path)
                                logger_print_content(f"文件 {path} 已复制到 {dest_path}")
                        except Exception:
                            pass
    finally:
        if should_close: conn.close()
    return diff_response_info

def diff_response_api_fallback(folder_path, filePath_url_info):
    diff_response_info = []
    content_count = defaultdict(list)
    file_sizes = {}

    diff_response_dir = f"{folder_path}/差异化response"
    os.makedirs(diff_response_dir, exist_ok=True)

    hash_file_path = os.path.join(f"{folder_path}/8-1-响应包diff_hash.txt")
    
    # Collect all file paths first
    all_file_paths = []
    for root, _, files in os.walk(f"{folder_path}/response"):
        for file in files:
            all_file_paths.append(os.path.join(root, file))
            
    # Parallel hash computation
    if all_file_paths:
        # Use ThreadPoolExecutor for IO bound tasks
        max_workers = min(32, (os.cpu_count() or 1) * 4)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_path = {executor.submit(_compute_file_hash_worker, path): path for path in all_file_paths}
            
            for future in as_completed(future_to_path):
                result = future.result()
                if result:
                    content_hash, path, file_size = result
                    content_count[content_hash].append(path)
                    if content_hash not in file_sizes:
                        file_sizes[content_hash] = file_size

    with open(hash_file_path, 'wt', encoding='utf-8') as hash_file, open(f"./result.txt", 'at', encoding='utf-8') as result_file:
        sorted_hashes = sorted(content_count.items(), key=lambda item: (len(item[1]), -file_sizes[item[0]]))
        for content_hash, paths in sorted_hashes:
            size = file_sizes[content_hash]
            hash_file.write(f"{content_hash} ({len(paths)} 次, 大小: {size} 字节):\n")
            for path in paths:
                hash_file.write(f"{path}\n")

            if len(paths) < 10:
                result_file.writelines(f"{content_hash} ({len(paths)} 次, 大小: {size} 字节):\n")
                for path in paths:
                    url = filePath_url_info.get(path, "") or reconstruct_url_from_filename(path)
                    url_check = url.split('?', 1)[0].lower() if url else ""
                    if url_check.endswith('.js'):
                        continue
                    result_file.write(f"{path}\n")
                    diff_response_info.append([content_hash, len(paths), size, url, path])

        for paths in content_count.values():
            if len(paths) < 10:
                for path in paths:
                    url = filePath_url_info.get(path, "") or reconstruct_url_from_filename(path)
                    url_check = url.split('?', 1)[0].lower() if url else ""
                    if url_check.endswith('.js'):
                        continue
                    dest_path = os.path.join(diff_response_dir, os.path.basename(path))
                    try:
                        shutil.copy2(path, dest_path)
                        logger_print_content(f"文件 {path} 已复制到 {dest_path}")
                    except Exception: pass

    return diff_response_info

from concurrent.futures import ProcessPoolExecutor, as_completed, ThreadPoolExecutor
import bisect

def _scan_text_logic(url, text, file_path, rules):
    findings = []
    # 1. URL Scan
    if url:
        for rule in rules:
            for match in rule['compiled_pattern'].finditer(url):
                ms = match.group()
                if not ms: continue
                findings.append({
                    "id": rule['id'], "name": rule['name'], "match": ms,
                    "url": url, "file": file_path, "severity": rule['severity'],
                    "context": f"[URL Match] {url}",
                    "line": 0, "group": rule['group'], "source": rule['source']
                })

    if not text: return findings
    
    # 2. Content Scan
    line_starts = [0]
    for m in re.finditer(r'\n', text): line_starts.append(m.end())
    
    for rule in rules:
        for match in rule['compiled_pattern'].finditer(text):
            ms = match.group()
            if not ms: continue
            s, e = match.span()
            
            # Use bisect for faster line lookup
            ln = bisect.bisect_right(line_starts, s)
            
            findings.append({
                "id": rule['id'], "name": rule['name'], "match": ms,
                "url": url, "file": file_path, "severity": rule['severity'],
                "context": text[max(0, s-200):min(len(text), e+200)],
                "line": ln, "group": rule['group'], "source": rule['source']
            })
    return findings

def _unified_scan_worker_db(row_data, rules):
    """从数据库行记录进行扫描匹配"""
    rid, url, text, res_type = row_data[0], row_data[1], row_data[2], row_data[3]
    file_path = row_data[4] if len(row_data) > 4 else url
    if url: url = decode_path_safely(url)
    return _scan_text_logic(url, text, file_path, rules)

def _unified_scan_file_worker(url, file_path, rules):
    """直接读取文件进行扫描 (IO优化: 避免主进程读取文件内容)"""
    try:
        if url: url = decode_path_safely(url)
        if os.path.exists(file_path):
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                text = f.read()
            return _scan_text_logic(url, text, file_path, rules)
    except Exception:
        pass
    return []

def _compute_file_hash_worker(path):
    """计算文件哈希 (IO优化: 分块读取)"""
    try:
        hash_sha256 = sha256()
        file_size = os.path.getsize(path)
        with open(path, 'rb') as f:
            # Check header
            header = f.read(100)
            # Simple check for JSON/XML content
            if not (header.startswith(b'{') or header.startswith(b'[') or header.startswith(b'<')):
                return None
            hash_sha256.update(header)
            while True:
                chunk = f.read(65536) # 64KB chunks
                if not chunk: break
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest(), path, file_size
    except Exception:
        return None

def disposeResults_api(folder_path, filePath_url_info, db_path=None, aiScan=False):
    if not db_path or not os.path.exists(db_path):
        logger_print_content(f"[敏感信息扫描] 数据库文件不存在或路径为空: {db_path}")
        return {"diff_response_info": [], "hae_api_info": [], "sensitive_data_info": []}

    # 检查数据库文件大小
    db_size = os.path.getsize(db_path)
    if db_size == 0:
        logger_print_content(f"[敏感信息扫描] 数据库文件为空 (0字节): {db_path}")
        return {"diff_response_info": [], "hae_api_info": [], "sensitive_data_info": []}

    conn = sqlite3.connect(db_path, timeout=60)

    # 检查必要的表是否存在
    try:
        tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        table_names = [t[0] for t in tables]
        required_tables = ['response_log', 'step2_js_cache', 'step2_dynamic_js_paths']
        missing_tables = [t for t in required_tables if t not in table_names]
        if missing_tables:
            logger_print_content(f"[敏感信息扫描] 数据库缺少必要的表: {missing_tables}")
            logger_print_content(f"[敏感信息扫描] 现有表: {table_names}")
        else:
            logger_print_content(f"[敏感信息扫描] 数据库包含 {len(table_names)} 个表，符合要求")
    except Exception as e:
        logger_print_content(f"[敏感信息扫描] 检查数据库表时出错: {e}")
        conn.close()
        return {"diff_response_info": [], "hae_api_info": [], "sensitive_data_info": []}

    # --- Metadata Loading ---
    target_base_url = ""
    try:
        cur = conn.execute("SELECT original_url FROM meta_target_info LIMIT 1")
        row = cur.fetchone()
        if row:
            target_base_url = row[0]
            if '?' in target_base_url: target_base_url = target_base_url.split('?')[0]
            if not target_base_url.endswith('/') and not target_base_url.endswith(('.html', '.htm', '.php', '.jsp', '.asp')):
                 target_base_url += '/'
            elif '/' in target_base_url:
                 target_base_url = target_base_url.rsplit('/', 1)[0] + '/'
    except Exception: pass
    
    if not target_base_url and filePath_url_info:
        for path, u in filePath_url_info.items():
            if u.lower().endswith('.js') and '/assets/' in u.lower():
                target_base_url = u.split('/assets/')[0] + '/assets/'
                break
        if not target_base_url:
            for path, u in filePath_url_info.items():
                if u.lower().endswith('.js'):
                    target_base_url = u.rsplit('/', 1)[0] + '/'
                    break

    dynamic_js_paths = []
    alive_urls = []
    js_cache_map = {}
    
    try:
        cur = conn.execute("SELECT path FROM step2_dynamic_js_paths")
        dynamic_js_paths = [r[0] for r in cur.fetchall()]
        
        try:
            cur = conn.execute("SELECT url FROM step2_alive_js_static")
            alive_urls = [r[0] for r in cur.fetchall()]
        except Exception: pass
        
        try:
            from urllib.parse import unquote
            cur = conn.execute("SELECT url FROM step2_js_cache")
            for row in cur.fetchall():
                u = row[0]
                if not u: continue
                fname = u.split('/')[-1]
                if '?' in fname: fname = fname.split('?')[0]
                decoded_fname = unquote(fname)
                js_cache_map[decoded_fname] = u
                js_cache_map[fname] = u
        except Exception: pass
    except Exception: pass

    # --- Scanning Phase ---
    total_findings = []
    rules_compact = [{'id':r.get('id'), 'name':r.get('name'), 'compiled_pattern':r['compiled_pattern'], 'severity':r.get('severity'), 'group':r.get('group'), 'source':r.get('source')} for r in unified_rules_list]
    
    max_workers = min(os.cpu_count() or 1, 8)
    BATCH_SIZE = 1000
    
    # Use ProcessPoolExecutor for CPU bound tasks (Regex)
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        # 1. Main Data Scan (Streamed from DB) - 扫描所有响应包
        try:
            count_cur = conn.execute("SELECT COUNT(*) FROM response_log")
            count = count_cur.fetchone()[0]
            if count > 0:
                logger_print_content(f"[敏感信息扫描] 开始扫描 {count} 条响应记录 (包含所有请求类型)...")
                logger_print_content(f"[敏感信息扫描] 注意：扫描所有响应包可能需要较长时间...")

                cur_scan = conn.execute("SELECT id, url, response, res_type FROM response_log")
                while True:
                    rows = cur_scan.fetchmany(BATCH_SIZE)
                    if not rows: break

                    futures = [executor.submit(_unified_scan_worker_db, row, rules_compact) for row in rows]
                    for f in as_completed(futures):
                        total_findings.extend(f.result())

                    # Explicitly release memory
                    del futures
                    del rows
        except Exception as e:
            logger_print_content(f"[敏感信息扫描] 主数据扫描出错: {e}")

        # 2. JS Cache Scan (Streamed & File Worker)
        try:
            # Count first
            count_cur = conn.execute("SELECT COUNT(*) FROM step2_js_cache")
            js_count = count_cur.fetchone()[0]
            
            if js_count > 0:
                logger_print_content(f"[敏感信息扫描] 开始扫描 {js_count} 个缓存JS文件 (并行IO)...")
                
                cur_js = conn.execute("SELECT url, path FROM step2_js_cache")
                while True:
                    rows = cur_js.fetchmany(BATCH_SIZE)
                    if not rows: break
                    
                    # Use _unified_scan_file_worker to read files in worker process
                    # row: (url, path)
                    futures = [executor.submit(_unified_scan_file_worker, row[0], row[1], rules_compact) for row in rows]
                    for f in as_completed(futures):
                        total_findings.extend(f.result())
                    del futures
                    del rows
        except Exception as e:
             logger_print_content(f"[敏感信息扫描] JS缓存扫描出错: {e}")

    conn.close()
    
    # 3. 单独扫描动态JS路径（针对URL模式规则 + 专门的包装HTML识别）
    # 专门用于匹配 .html-xxx.js 模式的正则
    wrapped_html_pattern = re.compile(r'\.html-[a-f0-9]{6,10}\.js', re.IGNORECASE)
    
    if dynamic_js_paths:
        logger_print_content(f"[敏感信息扫描] 开始扫描 {len(dynamic_js_paths)} 个动态JS路径...")
        matched_count = 0
        
        for path in dynamic_js_paths:
            # 修复可能存在的编码乱码
            clean_path = decode_path_safely(path)
            
            # Double check for common mojibake if decode_path_safely failed
            # "å®‰" (Installation -> 安装) pattern check
            if "å®‰" in clean_path or "ç®€ä»‹" in clean_path:
                try:
                    # Attempt aggressively to fix it
                    test = clean_path.encode('cp1252').decode('utf-8')
                    if test != clean_path:
                        clean_path = test
                except Exception:
                    pass

            # 补全完整URL，便于用户直接查看
            full_url = clean_path

            # 优先尝试从 JS 缓存中查找对应的完整 URL
            fname_key = os.path.basename(clean_path)
            # 处理可能的 ./ 前缀 或者 其他路径分隔符
            if '/' in clean_path: fname_key = clean_path.split('/')[-1]
            
            if fname_key in js_cache_map:
                full_url = js_cache_map[fname_key]
            elif target_base_url and not clean_path.startswith(('http://', 'https://')):
                from urllib.parse import urljoin, quote
                # 统一使用 urljoin 拼接，注意要用 clean_path
                # 如果 target_base_url 是 https://example.com/assets/ 而 clean_path 是 ./foo.js -> https://example.com/assets/foo.js
                # 如果 clean_path 是 /foo.js -> https://example.com/foo.js
                full_url = urljoin(target_base_url, clean_path)
                
                # 对 URL 进行必要的编码处理，确保其包含中文时也能直接点击
                try:
                    # 只有当包含非ascii字符时才进行 quote
                    if any(ord(c) > 127 for c in full_url):
                        parts = full_url.split('://', 1)
                        if len(parts) == 2:
                            scheme, rest = parts
                            # 分割 path 和 query
                            if '?' in rest:
                                rest_path, query = rest.split('?', 1)
                                query = '?' + query
                            else:
                                rest_path, query = rest, ""
                            
                            # 处理 rest_path 中的 unicode
                            # e.g. domain.com/foo/安装.html
                            path_parts = rest_path.split('/')
                            # host is first part usually? no, rest is host/path...
                            # e.g. example.com/foo/bar
                            
                            new_parts = []
                            for i, part in enumerate(path_parts):
                                # Host part (first one) usually doesn't need quote if ascii, but if IDN... assume ascii host for now or simple quote
                                if i == 0: 
                                    new_parts.append(part)
                                else:
                                    new_parts.append(quote(part))
                            
                            full_url = f"{scheme}://{'/'.join(new_parts)}{query}"
                except Exception:
                    pass
            
            # 如果 full_url 还是相对路径，说明找不到 target_base_url，尝试用 path 里的信息猜一个？
            # 或者是用户希望看到的不仅仅是 ./xxx
            if full_url.startswith('./') or full_url.startswith('/'):
                 # 没救了，但是我们可以试着找一下原始JS请求的 referer? 难。
                 # 无论如何，report里尽量展示 clean_path
                 pass

            # 首先检查是否是包装HTML的JS文件
            if wrapped_html_pattern.search(clean_path):
                matched_count += 1
                total_findings.append({
                    "id": "js_wrapped_html_url", 
                    "name": "JS Wrapped HTML Filename",
                    "match": clean_path,
                    "url": full_url, 
                    "file": clean_path, 
                    "severity": "high",
                    "context": f"[Dynamic JS Import] 发现包装HTML页面的JS模块: {clean_path}",
                    "line": 0, 
                    "group": "Sensitive Information", 
                    "source": "custom"
                })
            
            # 然后用完整规则集扫描
            for rule in rules_compact:
                try:
                    for match in rule['compiled_pattern'].finditer(clean_path):
                        ms = match.group()
                        if not ms: continue
                        # 避免重复添加 js_wrapped_html_url 规则的结果
                        if rule['id'] == 'js_wrapped_html_url':
                            continue
                        total_findings.append({
                            "id": rule['id'], "name": rule['name'], "match": ms,
                            "url": full_url, "file": clean_path, "severity": rule['severity'],
                            "context": f"[Dynamic JS Import] {clean_path}",
                            "line": 0, "group": rule['group'], "source": rule['source']
                        })
                except Exception:
                    pass
        
        if matched_count > 0:
            logger_print_content(f"[敏感信息扫描] 发现 {matched_count} 个高危的JS包装HTML页面")

    # 4. 扫描存活的JS和静态资源URL
    if alive_urls:
        url_findings = scan_urls_for_sensitive_info(alive_urls, rules_compact)
        total_findings.extend(url_findings)

    # 5. 扫描 sourcemap 还原后的文件
    sourcemap_restore_dir = os.path.join(folder_path, 'sourcemap_restored')
    if os.path.exists(sourcemap_restore_dir):
        logger_print_content(f"[敏感信息扫描] 开始扫描 sourcemap_restored 目录...")
        sourcemap_files = []

        # 黑名单：排除不需要扫描的文件类型
        BLACKLIST_EXTENSIONS = {
            # 图片
            '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.svg', '.webp', '.tiff', '.psd',
            # 字体
            '.ttf', '.otf', '.woff', '.woff2', '.eot',
            # 媒体
            '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.mkv', '.wav', '.ogg',
            # 压缩
            '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2',
            # 其他二进制
            '.exe', '.dll', '.so', '.dylib', '.bin',
            # 文档
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'
        }

        # 递归遍历 sourcemap_restored 目录
        for root, dirs, files in os.walk(sourcemap_restore_dir):
            for file in files:
                # 获取文件扩展名（小写）
                ext = os.path.splitext(file)[1].lower()

                # 如果在黑名单中，跳过
                if ext in BLACKLIST_EXTENSIONS:
                    continue

                full_path = os.path.join(root, file)
                # 计算相对路径用于显示
                rel_path = os.path.relpath(full_path, folder_path)
                sourcemap_files.append((full_path, rel_path))

        if sourcemap_files:
            logger_print_content(f"[敏感信息扫描] 发现 {len(sourcemap_files)} 个 sourcemap 还原文件，开始扫描...")
            sourcemap_count = 0

            for full_path, rel_path in sourcemap_files:
                try:
                    with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    # 使用完整规则集扫描
                    for rule in rules_compact:
                        try:
                            for match in rule['compiled_pattern'].finditer(content):
                                ms = match.group()
                                if not ms: continue

                                # 计算行号
                                line_num = content[:match.start()].count('\n') + 1

                                total_findings.append({
                                    "id": rule['id'],
                                    "name": rule['name'],
                                    "match": ms,
                                    "url": f"[sourcemap] {rel_path}",
                                    "file": rel_path,
                                    "severity": rule['severity'],
                                    "context": content[max(0, match.start()-200):min(len(content), match.end()+200)],
                                    "line": line_num,
                                    "group": rule['group'],
                                    "source": "custom"
                                })
                                sourcemap_count += 1
                        except Exception:
                            pass
                except Exception as e:
                    logger_print_content(f"[敏感信息扫描] 扫描文件失败 {rel_path}: {e}")

            if sourcemap_count > 0:
                logger_print_content(f"[敏感信息扫描] 从 sourcemap_restored 发现 {sourcemap_count} 条敏感信息")

    # 兼容性适配
    unique_hae, unique_sens, unique_combined = [], [], []
    seen_hae, seen_sens, seen_combined = set(), set(), set()
    
    for f in total_findings:
        # 1. 构建标准敏感信息条目 (用于增强报告和敏感信息列表)
        sens_entry = (f['id'], f['match'], f['url'], f['file'], f['severity'], f['context'], f['line'], f['group'], "")
        k_sens = (f['id'], f['match'], f['url'])

        # 添加到总集合 (用于增强版报告，包含所有类型)
        if k_sens not in seen_combined:
            unique_combined.append(sens_entry)
            seen_combined.add(k_sens)

        # 2. 根据来源分流
        if f['source'] == 'hae':
            # HAE 来源：添加到 HAE 列表
            k_hae = (f['name'], f['url'])
            if k_hae not in seen_hae:
                unique_hae.append((f['name'], (f['match'],), f['url'], f['file']))
                seen_hae.add(k_hae)
        else:
            # 非 HAE 来源：添加到纯敏感信息列表 (用于Web视图的敏感信息表格，避免与HAE表格重复)
            if k_sens not in seen_sens:
                unique_sens.append(sens_entry)
                seen_sens.add(k_sens)

    # 4. 调用HTML还原功能，处理被JS包装的HTML页面
    restored_html_results = []
    try:
        restored_html_results = restore_html_pages(folder_path, db_path)
        if restored_html_results:
            logger_print_content(f"[HTML还原] 成功还原 {len(restored_html_results)} 个包装HTML页面")
            # 将还原结果添加到敏感信息中
            for r in restored_html_results:
                entry = (
                    "restored_html_page",  # id
                    r.get('filename', ''),  # match
                    r.get('source_url', ''),  # url  
                    r.get('local_path', ''),  # file
                    "high",  # severity
                    f"[已还原] 原始文件: {r.get('source_url', '')} -> 还原到: {r.get('local_path', '')}",  # context
                    0,  # line
                    "Sensitive Information",  # group
                    ""  # description
                )
                # 添加到 pure sensitive list
                unique_sens.append(entry)
                # 添加到 combined list
                unique_combined.append(entry)
                
    except Exception as e:
        logger_print_content(f"[HTML还原] 还原失败: {e}")
    
    # 最后生成统一的敏感信息报告
    # 移除 generate_sensitive_report 调用，因为它已经在 ChkApi.py 中被调用
    # try: generate_sensitive_report(folder_path, unique_sens, aiScan)
    # except Exception: pass
    
    return {
        "diff_response_info": diff_response_api(folder_path, filePath_url_info, db_path),
        "hae_api_info": unique_hae,
        "sensitive_data_info": unique_sens,
        "combined_data_info": unique_combined,
        "restored_html_pages": restored_html_results
    }

# --- 异步流式扫描支持 ---
class RealTimeSensitiveScanner:
    """
    支持异步流式扫描的敏感信息扫描器
    """
    def __init__(self, db_path=None):
        self.rules = [{'id':r.get('id'), 'name':r.get('name'), 'compiled_pattern':r['compiled_pattern'], 'severity':r.get('severity'), 'group':r.get('group'), 'source':r.get('source')} for r in unified_rules_list]
        self.findings_buffer = []
        self.lock = threading.Lock()
        self.db_path = db_path
        self.executor = ThreadPoolExecutor(max_workers=min(os.cpu_count() or 1, 4))
        
    def scan_content(self, url, content, file_path=""):
        """
        异步提交扫描任务
        """
        if not content:
            return
        
        self.executor.submit(self._scan_worker, url, content, file_path)

    def _scan_worker(self, url, content, file_path):
        """
        实际执行扫描的工作函数
        """
        try:
            findings = _scan_text_logic(url, content, file_path, self.rules)
            if findings:
                with self.lock:
                    self.findings_buffer.extend(findings)
                    
                # 如果有数据库连接，尝试实时写入（可选，目前主要是收集）
                if self.db_path and os.path.exists(self.db_path):
                    self._save_to_db(findings)
        except Exception as e:
            # 避免在线程中打印过多日志导致混乱
            pass

    def _save_to_db(self, findings):
        """
        将发现的敏感信息实时写入数据库 (step8_sensitive)
        """
        try:
            conn = sqlite3.connect(self.db_path, timeout=10)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS step8_sensitive (
                    name TEXT, matches TEXT, url TEXT, file TEXT, 
                    severity TEXT, evidence TEXT, line_number INTEGER, 
                    category TEXT, description TEXT
                )
            """)
            
            data = []
            for f in findings:
                data.append((
                    f['id'], str(f['match']), f['url'], f['file'], 
                    f['severity'], f['context'], f['line'], 
                    f['group'], ""
                ))
            
            conn.executemany("INSERT INTO step8_sensitive(name, matches, url, file, severity, evidence, line_number, category, description) VALUES(?,?,?,?,?,?,?,?,?)", data)
            conn.commit()
            conn.close()
        except Exception:
            pass

    def stop(self):
        """
        停止扫描器，等待所有任务完成
        """
        self.executor.shutdown(wait=True)
        return self.findings_buffer
