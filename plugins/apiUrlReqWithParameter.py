try:
    from plugins.nodeCommon import *
except Exception as e:
    from nodeCommon import *

import os
import re
from queue import Queue, Empty

RR_CONFIG2 = {}
DB_WRITER = None
proxies = None

def get_url(i, referer_url, api_urls_queue, api_url, headers, folder_path, api_url_res, parameters, filePath_url_info):
    try:
        GlobalRequestCounter.increment()
        query_string = "&".join([f"{p}=" for p in parameters]) if parameters else ""
        api_parameters_url = f"{api_url}?{query_string}" if query_string else api_url
        res = http_get(url=api_parameters_url, headers=headers, allow_redirects=False, proxies=proxies)
        res_code, res_type, text = res.status_code, res.headers.get('Content-Type', ""), res.text
        logger_print_content(f"[线程{i}] 剩下:{api_urls_queue.qsize()} [GET] {api_parameters_url}\t状态码:{res_code}")
        
        file_name = re.sub(r'[^a-zA-Z0-9\.]', '_', api_url)
        file_path = os.path.join(folder_path, 'response', f'GET_PARAMETERS_{file_name}.txt')
        filePath_url_info[file_path] = api_url
        save_response_to_file(file_path, text)
        
        rid = record_req_resp_unified(DB_WRITER, RR_CONFIG2, folder_path, api_parameters_url, 'GET', headers, headers.get('Cookie',''), text, res_code, res_type, False, referer_url, api_parameters_url, query_string)
        api_url_res.append({"url": api_parameters_url, 'method': 'GET', "res_type": res_type, "res_code": res_code, 'res_size': len(text), 'referer_url': referer_url, 'file_path': api_parameters_url, 'parameter': query_string, "response": "", 'request_id': rid})
    except Exception: pass

def post_data_url(i, referer_url, api_urls_queue, api_url, headers, folder_path, api_url_res, parameters, filePath_url_info):
    try:
        GlobalRequestCounter.increment()
        query_string = "&".join([f"{p}=" for p in parameters])
        h = get_request_headers(headers.get('Cookie'), "application/x-www-form-urlencoded")
        res = http_post(url=api_url, data=query_string, headers=h, allow_redirects=False, proxies=proxies)
        res_code, res_type, text = res.status_code, res.headers.get('Content-Type', ""), res.text
        logger_print_content(f"[线程{i}] 剩下:{api_urls_queue.qsize()} [POST_DATA] {api_url}\t状态码:{res_code}")
        
        file_name = re.sub(r'[^a-zA-Z0-9\.]', '_', api_url)
        file_path = os.path.join(folder_path, 'response', f'POST_DATA_PARAMETERS_{file_name}.txt')
        filePath_url_info[file_path] = api_url
        save_response_to_file(file_path, text)
        
        rid = record_req_resp_unified(DB_WRITER, RR_CONFIG2, folder_path, api_url, 'POST_DATA', h, h.get('Cookie',''), text, res_code, res_type, False, referer_url, file_path, query_string)
        api_url_res.append({"url": api_url, 'method': 'POST_DATA', "res_type": res_type, "res_code": res_code, 'res_size': len(text), 'referer_url': referer_url, 'file_path': file_path, 'parameter': query_string, "response": text, 'request_id': rid})
    except Exception: pass

def post_json_url(i, referer_url, api_urls_queue, api_url, headers, folder_path, api_url_res, parameters, filePath_url_info):
    try:
        GlobalRequestCounter.increment()
        query_params = {p: '' for p in parameters}
        query_string = json.dumps(query_params)
        h = get_request_headers(headers.get('Cookie'), "application/json")
        res = http_post(url=api_url, json=query_params, headers=h, allow_redirects=False, proxies=proxies)
        res_code, res_type, text = res.status_code, res.headers.get('Content-Type', ""), res.text
        logger_print_content(f"[线程{i}] 剩下:{api_urls_queue.qsize()} [POST_JSON] {api_url}\t状态码:{res_code}")
        
        file_name = re.sub(r'[^a-zA-Z0-9\.]', '_', api_url)
        file_path = os.path.join(folder_path, 'response', f'POST_JSON_PARAMETERS_{file_name}.txt')
        filePath_url_info[file_path] = api_url
        save_response_to_file(file_path, text)
        
        rid = record_req_resp_unified(DB_WRITER, RR_CONFIG2, folder_path, api_url, 'POST_JSON', h, h.get('Cookie',''), text, res_code, res_type, False, referer_url, file_path, query_string)
        # OOM优化
        api_url_res.append({"url": api_url, 'method': 'POST_JSON', "res_type": res_type, "res_code": res_code, 'res_size': len(text), 'referer_url': referer_url, 'file_path': file_path, 'parameter': query_string, "response": "", 'request_id': rid})
    except Exception: pass

def req_api_url(i, referer_url, api_urls_queue, api_url, headers, folder_path, api_url_res, parameters, filePath_url_info, method=None):
    should_get = method == 'GET' or method is None
    should_post = method == 'POST' or method is None

    # 静态资源判定：对静态资源仅执行 GET（不附加参数），跳过POST与POST_JSON
    is_static = False
    try:
        path = urlparse(api_url).path.lower()
        if any(path.endswith(ext) for ext in staticFileExtBlackList):
            is_static = True
    except Exception:
        pass

    if should_get:
        get_url(i, referer_url, api_urls_queue, api_url, headers, folder_path, api_url_res, [] if is_static else parameters, filePath_url_info)
    if should_post and not is_static:
        post_data_url(i, referer_url, api_urls_queue, api_url, headers, folder_path, api_url_res, parameters, filePath_url_info)
        post_json_url(i, referer_url, api_urls_queue, api_url, headers, folder_path, api_url_res, parameters, filePath_url_info)

def apiUrlReqWithParameter(i, referer_url, api_urls_queue, headers, folder_path, api_url_res, parameters, filePath_url_info, url_methods=None):
    while not api_urls_queue.empty():
        try:
            api_url = api_urls_queue.get(timeout=1)
            method = url_methods.get(api_url) if url_methods else None
            req_api_url(i, referer_url, api_urls_queue, api_url, headers, folder_path, api_url_res, parameters, filePath_url_info, method)
        except Empty: break
        except Exception: pass

def apiUrlReqWithParameter_api(referer_url, xml_json_api_url, cookies, folder_path, parameters, filePath_url_info, db_path=None, rr_config=None, url_methods=None):
    global RR_CONFIG2, DB_WRITER
    RR_CONFIG2 = rr_config or {}
    if db_path: DB_WRITER = DatabaseWriter(db_path)
    api_url_res = []
    headers['Cookie'] = cookies or ''
    api_urls_queue = Queue(-1)
    for api_url in xml_json_api_url: api_urls_queue.put(api_url)
    threads = []
    for i in range(80):
        t = threading.Thread(target=apiUrlReqWithParameter, args=(i, referer_url, api_urls_queue, headers, folder_path, api_url_res, parameters, filePath_url_info, url_methods))
        threads.append(t); t.start()
    for t in threads: t.join()
    if DB_WRITER: DB_WRITER.stop(); DB_WRITER = None
    return api_url_res
