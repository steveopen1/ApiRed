try:
    from plugins.nodeCommon import *
except Exception as e:
    from nodeCommon import *

import os
import re
import posixpath
from urllib.parse import urlparse
import threading
from queue import Queue, Empty

RR_CONFIG = {}
DB_WRITER = None
proxies = None
RETRY_LOCK = threading.Lock()
RETRY_SEEN = set()
EXEC_LOCK = threading.Lock()
EXEC_SEEN = set()

def _normalize_url(url):
    try:
        parsed = urlparse(url)
        path = parsed.path
        if path:
            clean_path = posixpath.normpath(path)
            if clean_path == '.':
                clean_path = '/'
            if path.startswith('/') and not clean_path.startswith('/'):
                clean_path = '/' + clean_path
            parsed = parsed._replace(path=clean_path)
            return parsed.geturl()
        return url
    except:
        return url

def _execute_request(method, i, api_urls_queue, api_url, headers, folder_path, api_url_res, filePath_url_info, referer_url, res_type, res_code, text, request_id, file_path, parameter=""):
    filePath_url_info[file_path] = api_url
    save_response_to_file(file_path, text)
    api_url_res.append({
        "url": api_url,
        'method': method,
        "res_type": res_type,
        "res_code": res_code,
        'res_size': len(text),
        'referer_url': referer_url,
        'file_path': file_path,
        'parameter': parameter,
        "response": "" if method != 'POST_DATA' else text,
        'request_id': request_id
    })

def get_url(i, referer_url, api_urls_queue, api_url, headers, folder_path, api_url_res, filePath_url_info, prefixes=None, current_depth=0):
    try:
        norm_current_url_exec = _normalize_url(api_url)
        with EXEC_LOCK:
            key = ('GET', norm_current_url_exec)
            if key in EXEC_SEEN:
                return
            EXEC_SEEN.add(key)
        GlobalRequestCounter.increment()
        res = http_get(url=api_url, headers=headers, allow_redirects=False, proxies=proxies)
        res_code, res_type, text = res.status_code, res.headers.get('Content-Type', ""), res.text
        logger_print_content(f"[线程{i}] 剩下:{api_urls_queue.qsize()} [GET] {api_url}\t状态码:{res_code}\t响应包大小:{len(text)}")
        
        # 404 重试逻辑：如果是自然提取的 URL (depth=0) 且返回 404，尝试添加前缀
        if res_code == 404 and current_depth == 0 and prefixes:
            from urllib.parse import urlparse, urlunparse
            u = urlparse(api_url)
            norm_current_url = _normalize_url(api_url)
            for prefix in prefixes:
                clean_prefix = prefix.rstrip('/')
                clean_path = u.path if u.path.startswith('/') else '/' + u.path
                new_path = clean_prefix + clean_path
                new_url_parts = list(u)
                new_url_parts[2] = new_path
                new_url = urlunparse(new_url_parts)
                
                norm_new_url = _normalize_url(new_url)
                if norm_new_url != norm_current_url:
                    with RETRY_LOCK:
                        if norm_new_url not in RETRY_SEEN:
                            RETRY_SEEN.add(norm_new_url)
                            api_urls_queue.put((norm_new_url, 1))

        file_name = re.sub(r'[^a-zA-Z0-9\.]', '_', api_url)
        file_path = os.path.join(folder_path, 'response', f'GET_{file_name}.txt')
        rid = record_req_resp_unified(DB_WRITER, RR_CONFIG, folder_path, api_url, 'GET', headers, headers.get('Cookie',''), text, res_code, res_type, True, referer_url, file_path)
        _execute_request('GET', i, api_urls_queue, api_url, headers, folder_path, api_url_res, filePath_url_info, referer_url, res_type, res_code, text, rid, file_path)
    except Exception: pass

def post_data_url(i, referer_url, api_urls_queue, api_url, headers, folder_path, api_url_res, filePath_url_info, prefixes=None, current_depth=0):
    try:
        norm_current_url_exec = _normalize_url(api_url)
        with EXEC_LOCK:
            key = ('POST_DATA', norm_current_url_exec)
            if key in EXEC_SEEN:
                return
            EXEC_SEEN.add(key)
        GlobalRequestCounter.increment()
        h = get_request_headers(headers.get('Cookie'), "application/x-www-form-urlencoded")
        res = http_post(url=api_url, data="", headers=h, allow_redirects=False, proxies=proxies)
        res_code, res_type, text = res.status_code, res.headers.get('Content-Type', ""), res.text
        logger_print_content(f"[线程{i}] 剩下:{api_urls_queue.qsize()} [POST_DATA] {api_url}\t状态码:{res_code}")
        
        if res_code == 404 and current_depth == 0 and prefixes:
            from urllib.parse import urlparse, urlunparse
            u = urlparse(api_url)
            norm_current_url = _normalize_url(api_url)
            for prefix in prefixes:
                clean_prefix = prefix.rstrip('/')
                clean_path = u.path if u.path.startswith('/') else '/' + u.path
                new_path = clean_prefix + clean_path
                new_url_parts = list(u)
                new_url_parts[2] = new_path
                new_url = urlunparse(new_url_parts)
                
                norm_new_url = _normalize_url(new_url)
                if norm_new_url != norm_current_url:
                    with RETRY_LOCK:
                        if norm_new_url not in RETRY_SEEN:
                            RETRY_SEEN.add(norm_new_url)
                            api_urls_queue.put((norm_new_url, 1))

        file_name = re.sub(r'[^a-zA-Z0-9\.]', '_', api_url)
        file_path = os.path.join(folder_path, 'response', f'POST_DATA_{file_name}.txt')
        rid = record_req_resp_unified(DB_WRITER, RR_CONFIG, folder_path, api_url, 'POST_DATA', h, h.get('Cookie',''), text, res_code, res_type, True, referer_url, file_path)
        _execute_request('POST_DATA', i, api_urls_queue, api_url, headers, folder_path, api_url_res, filePath_url_info, referer_url, res_type, res_code, text, rid, file_path)
    except Exception: pass

def post_json_url(i, referer_url, api_urls_queue, api_url, headers, folder_path, api_url_res, filePath_url_info, prefixes=None, current_depth=0):
    try:
        norm_current_url_exec = _normalize_url(api_url)
        with EXEC_LOCK:
            key = ('POST_JSON', norm_current_url_exec)
            if key in EXEC_SEEN:
                return
            EXEC_SEEN.add(key)
        GlobalRequestCounter.increment()
        h = get_request_headers(headers.get('Cookie'), "application/json")
        res = http_post(url=api_url, json={}, headers=h, allow_redirects=False, proxies=proxies)
        res_code, res_type, text = res.status_code, res.headers.get('Content-Type', ""), res.text
        logger_print_content(f"[线程{i}] 剩下:{api_urls_queue.qsize()} [POST_JSON] {api_url}\t状态码:{res_code}")
        
        if res_code == 404 and current_depth == 0 and prefixes:
            from urllib.parse import urlparse, urlunparse
            u = urlparse(api_url)
            norm_current_url = _normalize_url(api_url)
            for prefix in prefixes:
                clean_prefix = prefix.rstrip('/')
                clean_path = u.path if u.path.startswith('/') else '/' + u.path
                new_path = clean_prefix + clean_path
                new_url_parts = list(u)
                new_url_parts[2] = new_path
                new_url = urlunparse(new_url_parts)
                
                norm_new_url = _normalize_url(new_url)
                if norm_new_url != norm_current_url:
                    with RETRY_LOCK:
                        if norm_new_url not in RETRY_SEEN:
                            RETRY_SEEN.add(norm_new_url)
                            api_urls_queue.put((norm_new_url, 1))

        file_name = re.sub(r'[^a-zA-Z0-9\.]', '_', api_url)
        file_path = os.path.join(folder_path, 'response', f'POST_JSON_{file_name}.txt')
        rid = record_req_resp_unified(DB_WRITER, RR_CONFIG, folder_path, api_url, 'POST_JSON', h, h.get('Cookie',''), text, res_code, res_type, True, referer_url, file_path)
        _execute_request('POST_JSON', i, api_urls_queue, api_url, headers, folder_path, api_url_res, filePath_url_info, referer_url, res_type, res_code, text, rid, file_path)
    except Exception: pass

def req_api_url(i, referer_url, api_urls_queue, api_url, headers, folder_path, api_url_res, filePath_url_info, prefixes=None, method=None):
    # 如果队列项是元组 (url, depth)，则解包；否则默认为 depth=0
    current_depth = 0
    if isinstance(api_url, tuple):
        api_url, current_depth = api_url

    # 如果指定了方法，只执行该方法；否则执行所有
    should_get = method == 'GET' or method is None
    should_post = method == 'POST' or method is None

    # 执行请求 (传入 prefixes 和 current_depth 用于 404 重试)
    # 静态资源后缀过滤 (不进行 POST Fuzz)
    is_static = False
    try:
        path = urlparse(api_url).path.lower()
        if any(path.endswith(ext) for ext in staticFileExtBlackList):
            is_static = True
    except:
        pass

    if should_get:
        get_url(i, referer_url, api_urls_queue, api_url, headers, folder_path, api_url_res, filePath_url_info, prefixes, current_depth)
    
    # 只有非静态资源，或者明确指定了 POST 方法时，才执行 POST Fuzz
    if should_post and not is_static:
        post_data_url(i, referer_url, api_urls_queue, api_url, headers, folder_path, api_url_res, filePath_url_info, prefixes, current_depth)
        post_json_url(i, referer_url, api_urls_queue, api_url, headers, folder_path, api_url_res, filePath_url_info, prefixes, current_depth)

def apiUrlReq(i, referer_url, api_urls_queue, headers, folder_path, api_url_res, filePath_url_info, prefixes=None, url_methods=None):
    while not api_urls_queue.empty():
        try:
            item = api_urls_queue.get(timeout=1)
            # 获取 URL 字符串用于查找方法
            url_str = item[0] if isinstance(item, tuple) else item
            method = url_methods.get(url_str) if url_methods else None
            
            req_api_url(i, referer_url, api_urls_queue, item, headers, folder_path, api_url_res, filePath_url_info, prefixes, method)
        except Empty: break
        except Exception: pass

def apiUrlReqNoParameter_api(referer_url, api_path_urls, cookies, folder_path, filePath_url_info, db_path=None, rr_config=None, prefixes=None, url_methods=None, ignore_get_urls=None):
    global RR_CONFIG, DB_WRITER
    RR_CONFIG = rr_config or {}
    logger_print_content("开始无参响应检测(所有响应均记录):")
    os.makedirs(f"{folder_path}/response/", exist_ok=True)
    if db_path: DB_WRITER = DatabaseWriter(db_path)
    
    # 初始化去重集合，将忽略列表中的URL标记为已执行GET
    if ignore_get_urls:
        with EXEC_LOCK:
            for u in ignore_get_urls:
                norm_u = _normalize_url(u)
                EXEC_SEEN.add(('GET', norm_u))
            logger_print_content(f"[*] 已跳过 {len(ignore_get_urls)} 个在前期探测中已请求过的 GET 接口")

    api_url_res, api_urls_queue = [], Queue(-1)
    danger_urls, safe_urls = [], []
    seen = set()
    for api_url in api_path_urls:
        norm_url = _normalize_url(api_url)
        if norm_url in seen:
            continue
        seen.add(norm_url)
        if any(dangerApi in urlparse(norm_url).path.lower() for dangerApi in dangerApiList):
            danger_urls.append(norm_url)
        else:
            safe_urls.append(norm_url)
            # 初始深度为 0
            api_urls_queue.put((norm_url, 0))

    # 写入文本报告
    with open(f'{folder_path}/危险API接口.txt', 'at', encoding='utf-8') as f1:
        for u in danger_urls: f1.write(f"{u}\n")
    with open(f'{folder_path}/安全API接口.txt', 'at', encoding='utf-8') as f2:
        for u in safe_urls: f2.write(f"{u}\n")

    # 写入数据库分类表
    if db_path:
        try:
            conn = sqlite3.connect(db_path)
            conn.executemany("INSERT INTO risk_danger_api_urls(url) VALUES(?)", [(u,) for u in danger_urls])
            conn.executemany("INSERT INTO risk_safe_api_urls(url) VALUES(?)", [(u,) for u in safe_urls])
            conn.commit()
            conn.close()
        except Exception: pass

    threads = []
    for i in range(80):
        t = threading.Thread(target=apiUrlReq, args=(i, referer_url, api_urls_queue, headers, folder_path, api_url_res, filePath_url_info, prefixes, url_methods))
        threads.append(t); t.start()
    for t in threads: t.join()
    if DB_WRITER: DB_WRITER.stop(); DB_WRITER = None
    return api_url_res
