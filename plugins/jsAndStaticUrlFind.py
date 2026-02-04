import json
import time
import hashlib
import sqlite3
import os
proxies = None

try:
    from plugins.nodeCommon import *
except Exception as e:
    from nodeCommon import *

try:
    from plugins.enhanced_sourcemap_detector import SourceMapIntegration
except Exception as e:
    try:
        from enhanced_sourcemap_detector import SourceMapIntegration
    except Exception:
        SourceMapIntegration = None

try:
    from plugins.ast_analyzer import ASTAnalyzer
except Exception as e:
    try:
        from ast_analyzer import ASTAnalyzer
    except Exception:
        ASTAnalyzer = None

try:
    from plugins.async_analysis import AsyncAnalysisManager
except Exception as e:
    try:
        from async_analysis import AsyncAnalysisManager
    except Exception:
        AsyncAnalysisManager = None

# 全局异步分析管理器（单例）
_async_manager = None

def get_async_manager():
    """获取异步分析管理器单例"""
    global _async_manager
    if _async_manager is None and AsyncAnalysisManager is not None:
        _async_manager = AsyncAnalysisManager()
        # 自动启动线程池
        _async_manager.start()
    return _async_manager


domainblacklist=[
    "www.w3.org", "example.com", "github.com", "example.org", "www.google", "googleapis.com"
]

def jsFilter(lst):
    tmp = []
    for line in lst:
        line = line.replace("\\/", "/")
        line = line.replace(" ", "")
        line = line.replace("\"", "")
        line = line.replace("'", "")
        line = line.replace("./", "/")
        line = line.replace("%3A", ":")
        line = line.replace("%2F", "/")
        # 新增排除\\
        line = line.replace("\\\\", "")
        if line.endswith("\\"):
            line = line.rstrip("\\")
        if line.startswith("="):
            line = line.lstrip("=")
        for x in domainblacklist:
            if x in line:
                line = ""
                break
        tmp.append(line)
    return tmp


def staticUrlFilter(domain, base_paths):
    tmp = []
    for base_path in base_paths:
        # Cleanup
        base_path = base_path.replace("\\/", "/")
        base_path = base_path.replace("\\\\", "")
        if base_path.endswith("\\"):
            base_path = base_path.rstrip("\\")
            
        if len(base_path) < 3 or base_path.endswith('.js') or any(ext in base_path.lower() for ext in staticUrlExtBlackList):
            continue
        elif 'http' in base_path:
            if domain not in base_path :
                pass
            else:
                tmp.append(base_path)
        else:
            tmp.append(base_path)
    return list(set(tmp))

def webpack_js_find(js_content):
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

def get_new_url(scheme, base, root_path, path):
    if path == "" or path == '//' or path == '/':
        return ''
    path_parts = path.split('/')
    if path.startswith("https:") or path.startswith("http:"):
        new_url = path
    elif path.startswith("//"):
        new_url = scheme + ":" + path
    elif path.startswith("/"):
        new_url = base + path
    elif path.startswith("js/"):
        new_url = base + '/' + path
    elif len(path_parts) > 1:
        new_url = base + '/' + path
    else:
        new_url = base + root_path + path

    return new_url
 
def rewrite_internal_host(url, base):
    try:
        pu = urlparse(url)
        if pu.hostname in ('127.0.0.1', 'localhost'):
            b = urlparse(base)
            host = b.hostname or ''
            port = pu.port or b.port
            scheme = b.scheme or (pu.scheme or 'http')
            netloc = host if not port else f"{host}:{port}"
            path = pu.path or '/'
            query = ('?' + pu.query) if pu.query else ''
            return f"{scheme}://{netloc}{path}{query}"
    except Exception:
        pass
    return url



import threading
from queue import Queue, Empty

def js_and_staticUrl_find(i, headers, js_and_staticUrl_info, urls, domain, js_and_staticUrl_alive_info_tmp, folder_path, filePath_url_info, db_path=None, max_depth=3):
    task_queue = Queue()
    enqueue_lock = threading.Lock()
    enqueued = set()

    def enqueue_url(target_url, depth):
        if not target_url:
            return
        with enqueue_lock:
            if target_url in enqueued:
                return
            enqueued.add(target_url)
        task_queue.put((target_url, depth))

    for seed in list(urls):
        enqueue_url(seed, 0)

    while True:
        try:
            url, current_depth = task_queue.get_nowait()
        except Empty:
            break
        try:
            get_js_and_staticUrl(
                i, headers, js_and_staticUrl_info, url, urls, domain,
                js_and_staticUrl_alive_info_tmp, folder_path, filePath_url_info,
                db_path, current_depth, max_depth, task_queue, enqueue_url
            )
        finally:
            task_queue.task_done()

def get_js_and_staticUrl(i, headers, js_and_staticUrl_info, url, urls, domain, js_and_staticUrl_alive_info_tmp, folder_path, filePath_url_info, db_path=None, current_depth=0, max_depth=3, task_queue=None, enqueue_fn=None):
    try:
        GlobalRequestCounter.increment()
        session = get_http_session(proxies)
        res = session.get(url=url, headers=headers, timeout=TIMEOUT, verify=False, allow_redirects=False, stream=True)
        code = res.status_code
        if code != 200:
            logger_print_content(f"[状态码非200，过滤掉] [{code}] {url}")
            return

        Content_Disposition = res.headers.get('Content-Disposition')# 获取网页源代码
        logger_print_content(f"[Content-Disposition] {url} {Content_Disposition}")
        if Content_Disposition:
            if 'attachment' in Content_Disposition:
                logger_print_content(f"[下载文件，过滤掉] {url} {Content_Disposition}")
                return

        # logger_print_content(f"[线程{i}] 处理 {url} 获取页面里的js url")

        # Fix encoding issues (requests defaults to ISO-8859-1 if header missing)
        if res.encoding == 'ISO-8859-1':
             res.encoding = 'utf-8'
        
        try:
             text = res.text
        except Exception:
             text = res.content.decode('utf-8', 'ignore')

        logger_print_content(f"[线程{i}] {url} 获取页面里的js url\t状态码:{code}\t长度:{len(text)}")

        file_name = re.sub(r'[^a-zA-Z0-9\.]', '_', url)
        file_path = f'{folder_path}/js_response/JS_{file_name}.txt'
        filePath_url_info[file_path] = url
        save_response_to_file(file_path, text)

        try:
            os.makedirs(f"{folder_path}/js/", exist_ok=True)
        except Exception:
            pass
        h = hashlib.sha256(text.encode('utf-8', errors='ignore')).hexdigest()
        # 使用原始JS文件名进行缓存
        try:
            base_name = os.path.basename(urlparse(url).path)
            if not base_name or not base_name.endswith('.js'):
                base_name = f"{h}.js"
        except Exception:
            base_name = f"{h}.js"
        cache_dir = f'{folder_path}/js'
        try:
            os.makedirs(cache_dir, exist_ok=True)
        except Exception:
            pass
        base_path = f'{cache_dir}/{base_name}'
        cache_path = base_path
        if not os.path.isfile(base_path):
            with open(base_path, 'wt', encoding='utf-8') as cf:
                cf.write(text)
        else:
            try:
                with open(base_path, 'rt', encoding='utf-8') as ef:
                    existing = ef.read()
                if existing != text:
                    name_no_ext = base_name[:-3] if base_name.lower().endswith('.js') else base_name
                    unique_name = f"{name_no_ext}.{h[:8]}.js"
                    cache_path = f'{cache_dir}/{unique_name}'
                    if not os.path.isfile(cache_path):
                        with open(cache_path, 'wt', encoding='utf-8') as cf:
                            cf.write(text)
            except Exception:
                pass
        if db_path:
            try:
                conn = sqlite3.connect(db_path)
                conn.execute("CREATE TABLE IF NOT EXISTS step2_js_cache (url TEXT, content_hash TEXT, length INTEGER, path TEXT)")
                conn.execute("INSERT INTO step2_js_cache(url, content_hash, length, path) VALUES(?,?,?,?)", (url, h, len(text), cache_path))
                conn.commit()
                conn.close()
            except Exception:
                pass

    except Exception:
        return

    def schedule_url(target_url):
        if not target_url or current_depth >= max_depth:
            return
        if enqueue_fn:
            enqueue_fn(target_url, current_depth + 1)
        elif task_queue is not None:
            task_queue.put((target_url, current_depth + 1))

    # --- 真正的深度控制：如果达到或超过深度，直接停止挖掘逻辑 ---
    if current_depth >= max_depth:
        # 记录探测到的存活信息后直接返回，不进行正则提取
        js_and_staticUrl_alive_info_tmp.append({"url": url, "code": code, "length": len(text)})
        return

    js_and_staticUrl_alive_info_tmp.append({"url": url, "code": code, "length": len(text)})

    # 获取url的相关元素
    parsed_url = urlparse(url)
    scheme = parsed_url.scheme
    path = parsed_url.path
    host = parsed_url.hostname
    port = parsed_url.port
    base = f"{scheme}://{host}"
    if port: base += f":{port}"

    root_path = "/"
    pattern = re.compile(r'/.*/{1}|/')
    root_result = pattern.findall(path)
    if root_result: root_path = root_result[0]

    # 正则提取规则 ...
    js_patterns = [
        r'http[^\s\'’"\>\<\:\(\)\[\,]+?\.js\b',
        r'["\']/[^\s\'’"\>\<\:\(\)\[\,]+?\.js\b',
        r'=[^\s\'’"\>\<\:\(\)\[\,]+?\.js\b',
        r'=["\'][^\s\'’"\>\<\:\(\)\[\,]+?\.js\b',
    ]
    staticUrl_patterns = [
        r'["\']http[^\s\'’"\>\<\)\(]+?[\"\']',
        r'=http[^\s\'’"\>\<\)\(]+',
        r'[\"\']/[^\s\'’"\>\<\:\)\(\u4e00-\u9fa5]+?["\']',
    ]

    # 封装提取逻辑
    def process_content_for_urls(content, ref_url, is_sourcemap_file=False):
        # 1. 提取 JS
        for js_pattern in js_patterns:
            js_paths = re.findall(js_pattern, content)
            js_paths = ["".join(x.strip("\"'")) for x in js_paths]
            js_paths = jsFilter(list(set(js_paths)))
            if not js_paths: continue

            if not is_sourcemap_file:
                logger_print_content(f"[+][D{current_depth+1}] {ref_url} 扫描到新JS并加入队列")
            
            js_and_staticUrl_info['js_paths'].extend(js_paths)
            for js_path in js_paths:
                new_js_url = get_new_url(scheme, base, root_path, js_path)
                new_js_url = rewrite_internal_host(new_js_url, base)
                if new_js_url and new_js_url not in urls:
                    urls.append(new_js_url)
                    if not is_blacklisted(new_js_url):
                        schedule_url(new_js_url)
                js_and_staticUrl_info['js_url'].append({'url': new_js_url, 'referer': ref_url, 'url_type': "js_url"})

        # 2. 提取 静态资源
        for staticUrl_pattern in staticUrl_patterns:
            static_paths = re.findall(staticUrl_pattern, content)
            static_paths = [x.strip('\'" ').rstrip('/') for x in static_paths]
            static_paths = staticUrlFilter(domain, list(set(static_paths)))
            if not static_paths: continue
            if len(static_paths) > 20 and not is_sourcemap_file: continue # 限制数量防止刷屏

            if not is_sourcemap_file:
                logger_print_content(f"[+][D{current_depth+1}] {ref_url} 扫描到静态资源并入队")
            
            js_and_staticUrl_info['static_paths'].extend(static_paths)
            for static_path in static_paths:
                static_url = get_new_url(scheme, base, root_path, static_path)
                static_url = rewrite_internal_host(static_url, base)
                if static_url and static_url not in urls:
                    urls.append(static_url)
                    if not is_blacklisted(static_url):
                        schedule_url(static_url)
                js_and_staticUrl_info['static_url'].append({'url': static_url, 'referer': ref_url, 'url_type': "static_url"})

        # 3. Webpack 提取
        wp_js = webpack_js_find(content)
        if wp_js:
            if not is_sourcemap_file:
                logger_print_content(f"[+][D{current_depth+1}] 【WEBPACK】{ref_url} 扫描到新分片")
            js_and_staticUrl_info['js_paths'].extend(wp_js)
            for js_path in wp_js:
                new_js_url = get_new_url(scheme, base, root_path, js_path)
                new_js_url = rewrite_internal_host(new_js_url, base)
                if new_js_url and new_js_url not in urls:
                    urls.append(new_js_url)
                    if not is_blacklisted(new_js_url):
                        schedule_url(new_js_url)
                js_and_staticUrl_info['js_url'].append({'url': new_js_url, 'referer': ref_url, 'url_type': "js_url"})

    # 处理主响应内容
    process_content_for_urls(text, url)

    # 4. AST 静态分析 - 改为异步非阻塞执行
    # 异步执行，不阻塞主下载流程，但结果仍可在第五步/第六步前使用
    is_js_file = url.lower().endswith('.js') or 'javascript' in res.headers.get('Content-Type', '').lower()

    if is_js_file and len(text) > 100 and len(text) < 2 * 1024 * 1024: # 2MB limit
        try:
            manager = get_async_manager()
            if manager:
                # 提交异步任务，立即返回
                manager.submit_ast_analysis(file_path, url, db_path)
                logger_print_content(f"[+][D{current_depth+1}] 【异步】{url} AST分析已提交")
        except Exception as e:
            # 异步分析失败不影响主流程
            pass

    # 5. 增强版SourceMap检测 - 改为异步非阻塞执行
    # 异步执行，不阻塞主下载流程，但还原的接口仍可用于 fuzzing
    parsed_path_lower = urlparse(url).path.lower()
    if parsed_path_lower.endswith('.js'):
        try:
            manager = get_async_manager()
            if manager:
                # 提交异步任务，立即返回
                manager.submit_sourcemap_analysis(
                    url=url,
                    text=text,
                    folder_path=folder_path,
                    db_path=db_path,
                    base_url=base,
                    scheme=scheme,
                    root_path=root_path
                )
                logger_print_content(f"[+][D{current_depth+1}] 【异步】{url} SourceMap检测已提交")
        except Exception as e:
            # 异步分析失败不影响主流程
            pass

    # print("\n")





def js_find_api(domain, urls, cookies, folder_path, filePath_url_info, db_path=None, max_depth=3):
    try:
        os.makedirs(f"{folder_path}/js_response/")
    except Exception as e:
        pass

    global queue
    js_and_staticUrl_info = {
        "js_paths": [],
        "js_url": [],
        "static_paths": [],
        "static_url": [],
    }

    js_and_staticUrl_alive_info_tmp = []

    if cookies:
        headers['Cookie'] = cookies
    
    # Use standard Queue
    queue = Queue()
    # Deduplication set for queue
    queued_urls = set(urls)
    
    for url in urls:
        queue.put((url, 0))

    max_workers = min((os.cpu_count() or 4) * 4, 64)
    workers = []

    def worker_loop(worker_id):
        while True:
            try:
                url, depth = queue.get(timeout=1)
            except Empty:
                break
            try:
                get_js_and_staticUrl(
                    worker_id, headers, js_and_staticUrl_info, url, urls,
                    domain, js_and_staticUrl_alive_info_tmp, folder_path,
                    filePath_url_info, db_path, depth, max_depth, queue, None
                )
            finally:
                queue.task_done()

    for idx in range(max_workers):
        t = threading.Thread(target=worker_loop, args=(idx,), daemon=True)
        workers.append(t)
        t.start()

    for t in workers:
        t.join()

    js_and_staticUrl_info['js_paths'] = list(set(js_and_staticUrl_info['js_paths']))
    js_and_staticUrl_info['static_paths'] = list(set(js_and_staticUrl_info['static_paths']))

    print(js_and_staticUrl_alive_info_tmp)

    js_and_staticUrl_alive_info = []
    
    found_urls_map = {item['url']: item for item in (js_and_staticUrl_info['js_url'] + js_and_staticUrl_info['static_url'])}
    
    for _1 in js_and_staticUrl_alive_info_tmp:
        url = _1['url']
        code = _1['code']
        length = _1['length']
        
        if code == 404:
            continue
            
        if url in found_urls_map:
            match = found_urls_map[url]
            js_and_staticUrl_alive_info.append({
                "url": url, 
                "code": code, 
                "length": length, 
                "url_type": match['url_type'], 
                "referer": match['referer']
            })
        else:
            url_lower = url.lower()
            url_type = 'js_url' if url_lower.endswith('.js') else 'static_url'
            if not url_lower.endswith('.js'):
                url_type = 'static_url'
                
            js_and_staticUrl_alive_info.append({
                "url": url, 
                "code": code, 
                "length": length, 
                "url_type": url_type, 
                "referer": "Seed/Initial"
            })

    print(js_and_staticUrl_alive_info)
    return js_and_staticUrl_info, js_and_staticUrl_alive_info
