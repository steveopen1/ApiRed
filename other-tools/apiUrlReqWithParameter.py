try:
    from plugins.nodeCommon import *
except Exception as e:
    from nodeCommon import *

import os
import re

RR_CONFIG2 = {}
DB_WRITER = None
proxies = None
REALTIME_SCANNER = None
import threading
EXEC_LOCK = threading.Lock()
EXEC_SEEN = set()
import posixpath
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

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

def get_url(i, referer_url, api_urls_queue, api_url, headers, folder_path, api_url_res, parameters, filePath_url_info, prefixes=None, current_depth=0):
    try:
        norm_exec = _normalize_url(api_url)
        with EXEC_LOCK:
            if ('GET', norm_exec) in EXEC_SEEN:
                return
            EXEC_SEEN.add(('GET', norm_exec))
        GlobalRequestCounter.increment()
        query_string = "&".join([f"{p}=" for p in parameters]) if parameters else ""
        api_parameters_url = f"{api_url}?{query_string}" if query_string else api_url
        res = requests.get(url=api_parameters_url, headers=headers, timeout=TIMEOUT, verify=False, allow_redirects=False, proxies=proxies)
        res_code, res_type, text = res.status_code, res.headers.get('Content-Type', ""), res.text
        logger_print_content(f"[线程{i}] 剩下:{api_urls_queue.qsize()} [GET] {api_parameters_url}\t状态码:{res_code}")
        
        if REALTIME_SCANNER:
             REALTIME_SCANNER.scan_content(api_parameters_url, text, "")

        if res_code == 404 and current_depth == 0 and prefixes:
            from urllib.parse import urlparse, urlunparse
            u = urlparse(api_parameters_url)
            norm_current_url = api_parameters_url
            for prefix in _limit_prefixes(prefixes):
                clean_prefix = ('/' + prefix.strip('/')).rstrip('/')
                clean_path = u.path if u.path.startswith('/') else '/' + u.path
                new_path = clean_prefix + clean_path
                new_url_parts = list(u)
                new_url_parts[2] = new_path
                new_url = urlunparse(new_url_parts)
                if new_url != norm_current_url:
                    try:
                        api_urls_queue.put((new_url, 1))
                    except Exception: pass

        file_path = ""
        rid = record_req_resp_unified(DB_WRITER, RR_CONFIG2, folder_path, api_parameters_url, 'GET', dict(res.request.headers), headers.get('Cookie',''), text, res_code, res_type, False, referer_url, file_path, "", dict(res.headers))
        # OOM优化
        api_url_res.append({"url": api_parameters_url, 'method': 'GET', "res_type": res_type, "res_code": res_code, 'res_size': len(text), 'referer_url': referer_url, 'file_path': file_path, 'parameter': query_string, "response": "", 'request_id': rid})
    except Exception: pass

def post_data_url(i, referer_url, api_urls_queue, api_url, headers, folder_path, api_url_res, parameters, filePath_url_info, prefixes=None, current_depth=0):
    try:
        norm_exec = _normalize_url(api_url)
        with EXEC_LOCK:
            if ('POST_DATA', norm_exec) in EXEC_SEEN:
                return
            EXEC_SEEN.add(('POST_DATA', norm_exec))
        GlobalRequestCounter.increment()
        query_string = "&".join([f"{p}=" for p in parameters])
        h = get_request_headers(headers.get('Cookie'), "application/x-www-form-urlencoded")
        res = requests.post(url=api_url, data=query_string, headers=h, timeout=TIMEOUT, verify=False, allow_redirects=False, proxies=proxies)
        res_code, res_type, text = res.status_code, res.headers.get('Content-Type', ""), res.text
        logger_print_content(f"[线程{i}] 剩下:{api_urls_queue.qsize()} [POST_DATA] {api_url}\t状态码:{res_code}")
        
        if REALTIME_SCANNER:
             REALTIME_SCANNER.scan_content(api_url, text, "")

        if res_code == 404 and current_depth == 0 and prefixes:
            from urllib.parse import urlparse, urlunparse
            u = urlparse(api_url)
            norm_current_url = api_url
            for prefix in _limit_prefixes(prefixes):
                clean_prefix = ('/' + prefix.strip('/')).rstrip('/')
                clean_path = u.path if u.path.startswith('/') else '/' + u.path
                new_path = clean_prefix + clean_path
                new_url_parts = list(u)
                new_url_parts[2] = new_path
                new_url = urlunparse(new_url_parts)
                if new_url != norm_current_url:
                    try:
                        api_urls_queue.put((new_url, 1))
                    except Exception: pass

        file_path = ""
        rid = record_req_resp_unified(DB_WRITER, RR_CONFIG2, folder_path, api_url, 'POST_DATA', dict(res.request.headers), h.get('Cookie',''), text, res_code, res_type, False, referer_url, file_path, query_string, dict(res.headers))
        api_url_res.append({"url": api_url, 'method': 'POST_DATA', "res_type": res_type, "res_code": res_code, 'res_size': len(text), 'referer_url': referer_url, 'file_path': file_path, 'parameter': query_string, "response": text, 'request_id': rid})
    except Exception: pass

def post_json_url(i, referer_url, api_urls_queue, api_url, headers, folder_path, api_url_res, parameters, filePath_url_info, prefixes=None, current_depth=0):
    try:
        norm_exec = _normalize_url(api_url)
        with EXEC_LOCK:
            if ('POST_JSON', norm_exec) in EXEC_SEEN:
                return
            EXEC_SEEN.add(('POST_JSON', norm_exec))
        GlobalRequestCounter.increment()
        query_params = {p: '' for p in parameters}
        query_string = json.dumps(query_params)
        h = get_request_headers(headers.get('Cookie'), "application/json")
        res = requests.post(url=api_url, json=query_params, headers=h, timeout=TIMEOUT, verify=False, allow_redirects=False, proxies=proxies)
        res_code, res_type, text = res.status_code, res.headers.get('Content-Type', ""), res.text
        logger_print_content(f"[线程{i}] 剩下:{api_urls_queue.qsize()} [POST_JSON] {api_url}\t状态码:{res_code}")
        
        if REALTIME_SCANNER:
             REALTIME_SCANNER.scan_content(api_url, text, "")

        if res_code == 404 and current_depth == 0 and prefixes:
            from urllib.parse import urlparse, urlunparse
            u = urlparse(api_url)
            norm_current_url = api_url
            for prefix in _limit_prefixes(prefixes):
                clean_prefix = ('/' + prefix.strip('/')).rstrip('/')
                clean_path = u.path if u.path.startswith('/') else '/' + u.path
                new_path = clean_prefix + clean_path
                new_url_parts = list(u)
                new_url_parts[2] = new_path
                new_url = urlunparse(new_url_parts)
                if new_url != norm_current_url:
                    try:
                        api_urls_queue.put((new_url, 1))
                    except Exception: pass

        file_path = ""
        rid = record_req_resp_unified(DB_WRITER, RR_CONFIG2, folder_path, api_url, 'POST_JSON', dict(res.request.headers), h.get('Cookie',''), text, res_code, res_type, False, referer_url, file_path, query_string, dict(res.headers))
        # OOM优化
        api_url_res.append({"url": api_url, 'method': 'POST_JSON', "res_type": res_type, "res_code": res_code, 'res_size': len(text), 'referer_url': referer_url, 'file_path': file_path, 'parameter': query_string, "response": "", 'request_id': rid})
    except Exception: pass

def req_api_url(i, referer_url, api_urls_queue, api_url, headers, folder_path, api_url_res, parameters, filePath_url_info, method=None, prefixes=None):
    should_get = True if method is None else (method == 'GET')
    should_post = True if method == 'POST' else False

    # 静态资源判定：对静态资源仅执行 GET（不附加参数），跳过POST与POST_JSON
    is_static = False
    try:
        path = urlparse(api_url).path.lower()
        if any(path.endswith(ext) for ext in staticFileExtBlackList):
            is_static = True
    except Exception:
        pass
    current_depth = 0
    if isinstance(api_url, tuple):
        api_url, current_depth = api_url

    if should_get:
        get_url(i, referer_url, api_urls_queue, api_url, headers, folder_path, api_url_res, [] if is_static else parameters, filePath_url_info, prefixes, current_depth)
    if should_post and not is_static:
        post_data_url(i, referer_url, api_urls_queue, api_url, headers, folder_path, api_url_res, parameters, filePath_url_info, prefixes, current_depth)
        post_json_url(i, referer_url, api_urls_queue, api_url, headers, folder_path, api_url_res, parameters, filePath_url_info, prefixes, current_depth)

def apiUrlReqWithParameter(i, referer_url, api_urls_queue, headers, folder_path, api_url_res, parameters, filePath_url_info, url_methods=None, prefixes=None):
    while not api_urls_queue.empty():
        try:
            item = api_urls_queue.get(timeout=1)
            url_str = item[0] if isinstance(item, tuple) else item
            method = url_methods.get(url_str) if url_methods else None
            req_api_url(i, referer_url, api_urls_queue, item, headers, folder_path, api_url_res, parameters, filePath_url_info, method, prefixes)
        except Empty: break
        except Exception: pass

def apiUrlReqWithParameter_api(referer_url, xml_json_api_url, cookies, folder_path, parameters, filePath_url_info, db_path=None, rr_config=None, url_methods=None, scanner=None, prefixes=None):
    global RR_CONFIG2, DB_WRITER
    RR_CONFIG2 = rr_config or {}
    if db_path: DB_WRITER = DatabaseWriter(db_path)
    
    global REALTIME_SCANNER
    REALTIME_SCANNER = scanner
    
    api_url_res = []
    headers['Cookie'] = cookies or ''
    api_urls_queue = Queue(-1)

    cfg = RR_CONFIG2 if isinstance(RR_CONFIG2, dict) else {}
    preprobe_enabled = bool(cfg.get('preprobe_enabled', True))
    preprobe_threshold = int(cfg.get('preprobe_threshold', 100))
    preprobe_budget = int(cfg.get('preprobe_budget', 128))
    responsive_set = set()
    try:
        if preprobe_enabled and len(xml_json_api_url) >= preprobe_threshold and preprobe_budget > 0:
            sample = list(xml_json_api_url)[:preprobe_budget]
            responsive_set = _preprobe_responsive_urls(sample, headers, budget=preprobe_budget)
    except Exception:
        responsive_set = set()
    ordered = []
    try:
        for u in xml_json_api_url:
            if u in responsive_set:
                ordered.append(u)
        for u in xml_json_api_url:
            if u not in responsive_set:
                ordered.append(u)
    except Exception:
        ordered = list(xml_json_api_url)

    for api_url in ordered: 
        api_urls_queue.put((api_url, 0))
    
    urls_count = len(ordered)
    min_threads = 8
    max_threads = 32
    try:
        min_threads = int((cfg.get('min_threads') or min_threads))
        max_threads = int((cfg.get('max_threads') or max_threads))
    except Exception:
        pass
    thread_count = min(max_threads, max(min_threads, urls_count // 50 if urls_count else min_threads))
    
    threads = []
    for i in range(thread_count):
        t = threading.Thread(target=apiUrlReqWithParameter, args=(i, referer_url, api_urls_queue, headers, folder_path, api_url_res, parameters, filePath_url_info, url_methods, prefixes))
        threads.append(t); t.start()
    for t in threads: t.join()
    if DB_WRITER: DB_WRITER.stop(); DB_WRITER = None
    return api_url_res

def _limit_prefixes(prefixes):
    try:
        if not prefixes: return []
        cfg = RR_CONFIG2 if isinstance(RR_CONFIG2, dict) else {}
        limit = int((cfg.get('prefix_retry_limit') or 3))
        if limit < 1: return []
        return list(prefixes)[:limit]
    except Exception:
        return list(prefixes)[:3]

def _preprobe_responsive_urls(urls, headers, budget=None):
    ok_codes = set(list(range(200,400)) + [401,403,405,500])
    preprobe_timeout = 2
    try:
        cfg = RR_CONFIG2 if isinstance(RR_CONFIG2, dict) else {}
        preprobe_timeout = int((cfg.get('preprobe_timeout') or preprobe_timeout))
        if preprobe_timeout <= 0: preprobe_timeout = 2
    except Exception:
        pass
    responsive = set()
    try:
        if isinstance(budget, int) and budget > 0:
            urls = list(urls)[:budget]
    except Exception:
        pass
    max_workers = min(len(urls), min(os.cpu_count() or 4, 16))
    try:
        def _head(u):
            try:
                res = requests.head(url=u, headers=headers, timeout=preprobe_timeout, verify=False, allow_redirects=False, proxies=proxies)
                return (u, (res.status_code in ok_codes))
            except Exception:
                return (u, False)
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futs = [ex.submit(_head, u) for u in urls]
            for f in as_completed(futs):
                try:
                    u, ok = f.result()
                    if ok: responsive.add(u)
                except Exception:
                    pass
    except Exception:
        pass
    return responsive
