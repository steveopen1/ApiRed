import os
import sys
import re
from optparse import OptionParser
from collections import Counter
import openpyxl
import json
import datetime
import threading
import webbrowser
import time
import hashlib
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
import sqlite3
import traceback
import requests
from plugins.nodeCommon import *
from plugins.jsAndStaticUrlFind import *
from plugins.apiPathFind import *
from plugins.saveToExcel import saveToExcel
from plugins.webdriverFind import *
from plugins.apiUrlReqNoParameter import *
from plugins.getParameter import *
from plugins.apiUrlReqWithParameter import *
from plugins.disposeResults import *
from plugins.jsDynamicImportRestore import restore_dynamic_js_modules
from plugins.htmlRestorer import restore_html_pages
from plugins.sensitive_report import generate_sensitive_report
from plugins.ai_engine import AIEngine
import tldextract
import shutil
import posixpath
from urllib.parse import urlparse, urlunparse

# 全局URL去重缓存
url_deduplication_cache = set()
original_url_count = 0
deduplicated_url_count = 0
skipped_duplicate_count = 0

def normalize_url(url):
    """
    规范化 URL，去除路径中的 /./ 和 /../ 等冗余部分
    """
    if not url:
        return url
    try:
        parsed = urlparse(url)
        # 仅处理路径部分
        path = parsed.path
        if path:
            # 使用 posixpath 处理 URL 路径 (总是使用 /)
            clean_path = posixpath.normpath(path)
            # posixpath.normpath 会把空路径处理为 .
            if clean_path == '.':
                clean_path = '/'
            # 确保绝对路径以 / 开头 (normpath 可能在某些情况下移除前导 /，如果原路径有的话应该保留)
            if path.startswith('/') and not clean_path.startswith('/'):
                clean_path = '/' + clean_path
            
            parsed = parsed._replace(path=clean_path)
            return parsed.geturl()
        return url
    except:
        return url

def get_base_domain(url):
    ext = tldextract.extract(url)
    return ext.domain

def is_json_text(t):
    try:
        json.loads(t or "")
        return True
    except Exception:
        return False

def record_step_stats(db_path, step_name, count):
    if not db_path: return
    try:
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE IF NOT EXISTS stats_execution (step_name TEXT, request_count INTEGER)")
        conn.execute("INSERT INTO stats_execution (step_name, request_count) VALUES (?, ?)", (step_name, count))
        conn.commit()
        conn.close()
    except Exception: pass

def filter_base_urls(base_domain, url):
    # ip则直接返回
    if is_ip(urlparse(url).netloc):
        return url
    # 域名则需要判断是否是目标的域名
    else:
        if base_domain in url:
            return url
        else:
            logger_print_content(f"[非目标站] {url}")
            return ""


# 获取访问url加载的js url
def indexJsFind(url, cookies,timeout=0.1, proxies=None):
    if cookies:
        headers['Cookie'] = cookies
    all_load_url = [{'url': url, 'referer': url, 'url_type': 'base_url'}]

    try:
        # 待定：考虑是否要禁用url跳转
        GlobalRequestCounter.increment()
        res = requests.get(url=url, headers=headers, timeout=TIMEOUT, verify=False, proxies=proxies)
        soup = BeautifulSoup(res.text, 'html.parser')
        scripts = soup.find_all('script')
        js_paths = [script['src'] for script in scripts if script.get('src')]
        for js_path in js_paths:
            # print(url, js_path.rstrip('/'))
            all_load_url.append({'url': urljoin(url, js_path.rstrip('/')), 'referer': url, 'url_type': 'js'})
        # ['static/js/elicons.626b260a.js', 'static/js/modules.d59689f1.js', 'static/js/app.397cfa65.js']
        return all_load_url
    except Exception as e:
        return all_load_url

def _is_valid_path(path):
    """验证路径是否为有效的URL路径格式"""
    if not path or not isinstance(path, str):
        return False
    
    # 长度检查
    if len(path) > 200:  # 限制路径长度
        return False
    
    # 检查是否包含明显的非路径内容
    if any(keyword in path.lower() for keyword in ['警告', 'warning', 'error', '错误', 'const', 'var ', 'function']):
        return False
    
    # 检查是否包含非法字符（中文字符、特殊控制字符等）
    import re
    
    # 检查是否包含中文字符或其他非ASCII字符
    if re.search(r'[^\x00-\x7F]', path):  # 非ASCII字符
        return False
    
    # 检查控制字符
    if re.search(r'[\x00-\x1f\x7f-\x9f]', path):  # 控制字符
        return False
    
    # 允许的路径字符：字母、数字、常见符号、斜杠等
    valid_pattern = r'^[a-zA-Z0-9._~:/?#[\]@!$&\'()*+,;=%-]+$'
    
    # 检查路径格式
    if not re.match(valid_pattern, path):
        return False
    
    # 检查路径结构
    if path.count('/') > 20:  # 限制路径深度
        return False
    
    # 检查重复模式
    if re.search(r'(.)\1{10,}', path):  # 重复字符超过10次
        return False
        
    return True

def _is_valid_url(url):
    """验证URL是否为有效格式"""
    try:
        if not url or not isinstance(url, str):
            return False
        
        # 长度检查
        if len(url) > 500:  # 限制URL长度
            return False
        
        # 基本格式验证
        if not url.startswith(('http://', 'https://')):
            return False
        
        # 尝试解析URL
        parsed = urlparse(url)
        
        # 检查必需组件
        if not parsed.scheme or not parsed.netloc:
            return False
        
        # 检查域名格式
        if not re.match(r'^[a-zA-Z0-9.-]+$', parsed.netloc):
            return False
        
        # 检查路径格式
        if parsed.path and not _is_valid_path(parsed.path):
            return False
        
        return True
    except Exception:
        return False

def filter_data(base_domain, all_load_url, all_api_paths, dedupe='on', base_override=None, basepath=None, target_root_url=None):
    """
    从提供的 URL 数据和 API 路径数据中提取并构建基本的 URL 列表。

    参数:
    url_data (list of dicts): 包含 URL 加载信息的字典列表，关键字包括 'url_type' 和 'url'。
    api_data (list of dicts): 包含 API 路径的字典列表，关键字包括 'url_type' 和 'api_path'。
    target_root_url (str): 目标根路径，如 http://example.com:8080，用于兜底。

    返回:
    list: 去重后的基本 URL 列表。
    """

    # 从all_load_url提取出base_url: https://aaa.com/dddd
    base_urls = []
    # 从all_load_url提取出根路径：http://bbb.com
    tree_urls = []
    # 从all_load_url提取出路径带有api字符串：http://ccc.com/xxxapi
    path_with_api_urls = []

    # 从all_api_paths提取出有api字符串的接口 ['/gateway/api', '/marketing_api', '/api', '/pages/appdownload/api', '/restapi', '/oapi']
    path_with_api_paths = []
    # 从all_api_paths提取出没有api字符串的接口
    path_with_no_api_paths = []


    '''
    自动加载有：http://x.x.x.x:8082/prod-api/auth/tenant/list
    js的接口里有：/auth/tenant/list
    则获取到base_url为http://x.x.x.x:8082/prod-api
    '''
    for item in all_load_url:
        try:
            if item['url_type'] == 'no_js':
                item_url = item['url']
                
                # 验证URL格式
                if not _is_valid_url(item_url):
                    logger_print_content(f'[跳过] 无效URL格式: {item_url}')
                    continue
                
                url_parse = urlparse(item_url)

                # 过滤掉非目标站的url
                if not filter_base_urls(base_domain, item['url']):
                    continue

                # http://aaa.com
                if url_parse.path in ['/', '']:
                    logger_print_content(f'[根路径] {item_url}')
                    tree_urls.append(item_url)
                    continue

                # 保存 所有目标资产的根路径url
                tree_url = f"{url_parse.scheme}://{url_parse.netloc}"
                logger_print_content(f'[根路径] {tree_url}')
                tree_urls.append(tree_url)

                # 路径有api/ 字符串的
                api_path_index = url_parse.path.find('api/')
                # print(api_path_index)
                if api_path_index != -1:
                    path_with_api_url = f"{url_parse.scheme}://{url_parse.netloc}{url_parse.path[:api_path_index]}api"
                    logger_print_content(f'[api] {path_with_api_url}')
                    path_with_api_urls.append(path_with_api_url)
                    base_url = path_with_api_url.rsplit('/', 1)[0]
                    if urlparse(base_url).path:
                        base_urls.append(base_url.rstrip('/'))
                    continue

                # 截获base_url, 例如自动加载了https://x.x.x.x/dddd/eee/fff，js获取到的api_path接口有/eee/fff，则base_url为https://x.x.x.x/dddd
                else:
                    for api in all_api_paths:
                        try:
                            if api['url_type'] == 'api_path' and api['api_path'] != '/' and not api['api_path'].startswith('http') and len(api['api_path']) > 2 and url_parse.path != api['api_path']:
                                url_parse = urlparse(item['url'])
                                api_index = url_parse.path.find(api['api_path'])
                                if api_index != -1:
                                    base_url = f"{url_parse.scheme}://{url_parse.netloc}{url_parse.path[:api_index]}".rstrip('/')
                                    # base_url = item['url'][:api_index]  # 在 API 路径开始的地方截断 URL
                                    if not is_blacklisted(base_url) and urlparse(base_url).path:
                                        logger_print_content(f'[截获] {base_url}')
                                        base_urls.append(base_url.rstrip('/'))
                        except Exception as e:
                            logger_print_content(f'[跳过] API路径处理异常: {api.get("api_path", "unknown")} - {str(e)}')
                            continue
        except Exception as e:
            logger_print_content(f'[跳过] URL处理异常: {item.get("url", "unknown")} - {str(e)}')
            continue
    base_urls = list(set(base_urls))
    tree_urls = list(set(tree_urls))
    path_with_api_urls = list(set(path_with_api_urls))
    logger_print_content(f"自动加载的根路径 {len(tree_urls)} tree_urls = {tree_urls}")
    logger_print_content(f"自动加载的子路径 {len(base_urls)} base_urls = {base_urls}")
    logger_print_content(f"自动加载的API路径 {len(path_with_api_urls)} path_with_api_urls = {path_with_api_urls}")

    # 第二次遍历：从 all_api_paths 获取所有带api字符串
    for api in all_api_paths:
        # js_url = api['url']

        # 过滤掉非目标站的url
        # if not filter_base_urls(base_domain, js_url):
        #     continue

        api_path = api['api_path']
        if api['url_type'] == 'api_path' and api_path != '/' and not api_path.startswith('http') and len(api_path) > 2 :
            # 验证api_path是否为有效的URL路径格式
            try:
                # 先检查是否包含非法字符，避免urlparse异常
                if not _is_valid_path(api_path):
                    logger_print_content(f"[跳过] 无效API路径格式: {api_path}")
                    continue
                    
                path_parse = urlparse(api_path)
                # print(api['api_path'], path_parse)
                api_path_index = api_path.find('api/')
                if api_path_index != -1:
                    path_with_api_path = f"/{api_path[:api_path_index].lstrip('/')}api"
                    path_with_api_paths.append(path_with_api_path)
                    # print(f"path_with_api_path = {path_with_api_path}")


                    path_with_no_api_path = f"/{api_path[api_path_index+4:]}"
                    path_with_no_api_paths.append(path_with_no_api_path)
                    # print(f"path_with_no_api_path = {path_with_no_api_path}")
                else:
                    path_with_no_api_path = f"/{api_path.lstrip('/')}"
                    path_with_no_api_paths.append(path_with_no_api_path)
                    # print(f"path_with_no_api_path = {path_with_no_api_path}")
            except Exception as e:
                logger_print_content(f"[跳过] API路径解析异常: {api_path} - {str(e)}")
                continue

    # 用户指定 basepath 时覆盖/补充
    if basepath:
        bp = '/' + basepath.lstrip('/').rstrip('/')
    else:
        bp = None

    # 把path_with_api_urls的api路径加进去
    for path_with_api_url in path_with_api_urls:
        try:
            # 验证URL格式
            if not _is_valid_url(path_with_api_url):
                logger_print_content(f'[跳过] 无效path_with_api_url格式: {path_with_api_url}')
                continue
            parsed_path = urlparse(path_with_api_url).path
            if _is_valid_path(parsed_path):
                path_with_api_paths.append(f"/{parsed_path.lstrip('/')}")
        except Exception as e:
            logger_print_content(f'[跳过] path_with_api_url解析异常: {path_with_api_url} - {str(e)}')
            continue
    # 覆盖或默认 basepath
    if bp:
        path_with_api_paths = [bp]
    elif not path_with_api_paths:
        path_with_api_paths.append('/api')
    path_with_api_paths = list(set(path_with_api_paths))
    # 规范 path_with_no_api_paths，若指定了 basepath，则剥离已有前缀，避免二次拼接
    normalized_no_api_paths = []
    for p in path_with_no_api_paths:
        q = p
        if bp and q.startswith(bp + '/'):
            q = q[len(bp):]
            if not q.startswith('/'):
                q = '/' + q
        normalized_no_api_paths.append(q)
    path_with_no_api_paths = list(set(normalized_no_api_paths))
    logger_print_content(f"带有API字符串的接口 {len(path_with_api_paths)} path_with_api_paths = {path_with_api_paths}")
    logger_print_content(f"没有API字符串的接口 {len(path_with_no_api_paths)} path_with_no_api_paths = {path_with_no_api_paths}")

    # 自动加载的根路径 0 tree_urls = [] 
    # 自动加载的子路径 0 base_urls = [] 
    # 这导致下面的循环无法执行，all_path_with_api_urls 也就为空
    # 修复：如果 tree_urls 和 base_urls 都为空，尝试从 all_load_url 或 base_domain 恢复
    if not tree_urls and not base_urls:
        # 优先使用 target_root_url (包含了端口和协议)
        if target_root_url:
            logger_print_content(f"[自动修复] 未发现根路径，使用 target_root_url 作为默认根路径: {target_root_url}")
            tree_urls.append(target_root_url)
        elif base_domain:
             # 尝试构建一个默认的 tree_url
             if not base_domain.startswith('http'):
                 default_tree = f"http://{base_domain}"
             else:
                 default_tree = base_domain
             
             # 简单的验证，防止加入完全无效的 url
             if _is_valid_url(default_tree):
                logger_print_content(f"[自动修复] 未发现根路径，使用 base_domain 作为默认根路径: {default_tree}")
                tree_urls.append(default_tree)
        
        # 再次尝试从 all_load_url 中提取，这次放宽条件
        for item in all_load_url:
             if item.get('url'):
                 u = item['url']
                 if _is_valid_url(u) and filter_base_urls(base_domain, u):
                     parsed = urlparse(u)
                     root = f"{parsed.scheme}://{parsed.netloc}"
                     if root not in tree_urls:
                         tree_urls.append(root)

    # 组合
    all_path_with_api_urls = []
    # 用户指定 baseurl 时加入 base_urls
    if base_override:
        bo = base_override.rstrip('/')
        if bo:
            base_urls.append(bo)
    base_urls = list(set(base_urls))
    for _1 in base_urls + tree_urls:
        if path_with_api_paths == ['/api']:
            all_path_with_api_urls.append(f"{_1}")
        for _2 in path_with_api_paths:
            path_with_api_url = normalize_url(f"{_1}{_2}")
            # print(path_with_api_url)
            all_path_with_api_urls.append(path_with_api_url)
    
    # 修复：如果 all_path_with_api_urls 为空，但我们有 path_with_api_paths 和 tree_urls/base_urls，应该至少尝试组合
    if not all_path_with_api_urls and (tree_urls or base_urls):
        # 如果 tree_urls 为空，使用 base_domain 作为默认根路径
        targets = base_urls + tree_urls
        if not targets and base_domain:
             # 确保 base_domain 是 URL 格式
             if not base_domain.startswith('http'):
                 targets = [f"http://{base_domain}"]
             else:
                 targets = [base_domain]
        
        for _1 in targets:
             for _2 in path_with_api_paths:
                path_with_api_url = normalize_url(f"{_1}{_2}")
                all_path_with_api_urls.append(path_with_api_url)
    
    # 如果还是为空，尝试使用 tree_urls 直接填充（如果 path_with_api_paths 为空的情况）
    if not all_path_with_api_urls and tree_urls:
         all_path_with_api_urls = tree_urls[:]

    all_path_with_api_urls = list(set(all_path_with_api_urls))
    logger_print_content(f"根路径和base路径拼接js匹配出来的API字符串接口 {len(all_path_with_api_urls)} all_path_with_api_urls = {all_path_with_api_urls}")
    
    # 确定用于拼接的根路径 (优先使用自然根路径)
    resolved_roots = list(set(base_urls + tree_urls))
    if not resolved_roots and base_domain:
         if not base_domain.startswith('http'):
             resolved_roots = [f"http://{base_domain}"]
         else:
             resolved_roots = [base_domain]
    if not resolved_roots: # 最后的兜底
         resolved_roots = all_path_with_api_urls

    api_urls = []
    # 使用 resolved_roots (不带强制前缀) 进行拼接，实现"自然提取优先"
    for _1 in resolved_roots:
        for _2 in path_with_no_api_paths:
            api_url = normalize_url(f"{_1}{_2}")
            # print(api_url)
            api_urls.append(api_url)
        for _3 in self_api_path:
            api_url = normalize_url(f"{_1}/{_3}")
            api_urls.append(api_url)
    api_urls = list(set(api_urls))
    
    # URL去重处理
    global url_deduplication_cache, original_url_count, deduplicated_url_count, skipped_duplicate_count
    original_url_count = len(api_urls)
    
    if str(dedupe).lower() == 'on':
        unique_api_urls = []
        for api_url in api_urls:
            # 双重保险：再次规范化
            api_url = normalize_url(api_url)
            if api_url not in url_deduplication_cache:
                url_deduplication_cache.add(api_url)
                unique_api_urls.append(api_url)
            else:
                skipped_duplicate_count += 1
        api_urls = unique_api_urls
        deduplicated_url_count = len(unique_api_urls)
        logger_print_content(f"组合出来的所有api路径 {original_url_count} -> 去重后 {deduplicated_url_count} (跳过重复 {skipped_duplicate_count})")
    else:
        deduplicated_url_count = original_url_count
        logger_print_content(f"组合出来的所有api路径 {original_url_count} (去重功能已关闭)")

    api_info = {
        'tree_urls': tree_urls,
        'base_urls': base_urls,
        'path_with_api_paths': path_with_api_paths,
        'path_with_no_api_paths': path_with_no_api_paths,
        'all_path_with_api_urls': all_path_with_api_urls,
        'api_urls': api_urls,
    }

    for api_url in api_urls:
        print(api_url)

    return api_info


def save_list_to_excel(excelSavePath, excel, title, list_result):
    sheet = saveToExcel(excelSavePath, excel, title)
    sheet.save_list_to_excel(title, list_result)

def save_dict_to_excel(excelSavePath, excel, title, list_dict_result):
    sheet = saveToExcel(excelSavePath, excel, title)
    if list_dict_result:
        sheet.save_dict_to_excel(list_dict_result)

# 第八步：处理结果
def deal_results(excelSavePath, excel, folder_path, filePath_url_info, db_path=None, aiScan=False):
    # 第八步：处理结果
    logger_print_content(f" 第八步：处理结果")
    # 整理response结果,差异化
    disposeResults_info = disposeResults_api(folder_path, filePath_url_info, db_path, aiScan)
    with open(f'{folder_path}/所有变量列表.txt', 'at', encoding='utf-8') as f9:
        f9.writelines(f"disposeResults_info = {disposeResults_info}\n")

    diff_response_info = disposeResults_info['diff_response_info']
    diff_response_info_dict = [{"content_hash": _[0], "length": _[1], "size": _[2], "url": _[3], "path": _[4]} for _ in diff_response_info]
    save_dict_to_excel(excelSavePath, excel, '响应包diff_hash', diff_response_info_dict)

    hae_api_info = disposeResults_info['hae_api_info']
    hae_api_info_dict = [{"name": _[0], "matches": str(_[1]), "url": _[2], "file": _[3]} for _ in hae_api_info]
    save_dict_to_excel(excelSavePath, excel, 'hae检测结果', hae_api_info_dict)

    sensitive_data_info = disposeResults_info['sensitive_data_info']
    sensitive_data_info_dict = [{"name": _[0], "matches": str(_[1]), "url": _[2], "file": _[3], "severity": (_[4] if len(_) > 4 else 'medium'), "evidence": (_[5] if len(_) > 5 else '')} for _ in sensitive_data_info]
    save_dict_to_excel(excelSavePath, excel, '敏感信息检测结果', sensitive_data_info_dict)

    try:
        db_path = os.path.join(folder_path, "results.db")
        if os.path.isfile(db_path):
            conn = sqlite3.connect(db_path, timeout=60)
            try:
                conn.execute("CREATE TABLE IF NOT EXISTS step8_diff_hash (content_hash TEXT, length INTEGER, size INTEGER, url TEXT, path TEXT)")
                conn.execute("CREATE TABLE IF NOT EXISTS step8_hae (name TEXT, matches TEXT, url TEXT, file TEXT)")
                conn.execute("CREATE TABLE IF NOT EXISTS step8_sensitive (name TEXT, matches TEXT, url TEXT, file TEXT, severity TEXT, evidence TEXT)")
                try:
                    conn.execute("ALTER TABLE step8_sensitive ADD COLUMN severity TEXT")
                except Exception:
                    pass
                try:
                    conn.execute("ALTER TABLE step8_sensitive ADD COLUMN evidence TEXT")
                except Exception:
                    pass
                conn.execute("DELETE FROM step8_diff_hash")
                conn.execute("DELETE FROM step8_hae")
                conn.execute("DELETE FROM step8_sensitive")
                if diff_response_info_dict:
                    conn.executemany("INSERT INTO step8_diff_hash(content_hash,length,size,url,path) VALUES(?,?,?,?,?)",
                                     [(_["content_hash"], int(_["length"]), int(_["size"]), _["url"], _["path"]) for _ in diff_response_info_dict])
                if hae_api_info_dict:
                    conn.executemany("INSERT INTO step8_hae(name,matches,url,file) VALUES(?,?,?,?)",
                                     [(_["name"], _["matches"], _["url"], _["file"]) for _ in hae_api_info_dict])
                if sensitive_data_info_dict:
                    conn.executemany("INSERT INTO step8_sensitive(name,matches,url,file,severity,evidence) VALUES(?,?,?,?,?,?)",
                                     [(_["name"], _["matches"], _["url"], _["file"], _.get("severity","medium"), _.get("evidence","")) for _ in sensitive_data_info_dict])
                conn.commit()
            finally:
                conn.close()
    except Exception as e:
        logger_print_content(f"写入step8结果到DB失败: {e}")

    # 还原包装 HTML 页面
    try:
        restore_html_pages(folder_path, db_path)
    except Exception: pass

    # 生成敏感信息检测增强HTML报告
    try:
        # 使用 combined_data_info (包含HAE和普通敏感信息) 生成增强报告，确保报告内容完整
        combined_data_info = disposeResults_info.get('combined_data_info', sensitive_data_info)
        if combined_data_info:
            logger_print_content("  正在生成敏感信息检测增强报告...")
            report_path = generate_sensitive_report(folder_path, combined_data_info, aiScan, db_path)
            logger_print_content(f"  敏感信息报告已生成: {report_path}")
    except Exception as e:
        logger_print_content(f"  生成敏感信息报告失败: {e}")

    # 关闭异步分析线程池
    try:
        from plugins.async_analysis import AsyncAnalysisManager
        manager = AsyncAnalysisManager()
        if manager:
            logger_print_content("=" * 80)
            logger_print_content("关闭异步分析线程池...")
            logger_print_content("=" * 80)
            manager.shutdown(wait=True)
            stats = manager.get_stats()
            logger_print_content(f"[异步分析最终统计] AST: {stats['ast']['completed']}/{stats['ast']['submitted']}, "
                             f"SourceMap: {stats['sourcemap']['completed']}/{stats['sourcemap']['submitted']}, "
                             f"Regex: {stats['regex']['completed']}/{stats['regex']['submitted']}")
    except Exception as e:
        logger_print_content(f"关闭异步分析失败: {e}")

    return disposeResults_info

def run_url(url, cookies, chrome, attackType, noApiScan, dedupe='on', store='db', rr_config=None, proxy=None, proxy_mode='', infoScan=False, js_depth=3, aiScan=False):
    js_paths = []
    static_paths = []
    results_json = {}
    conn = None

    # 重置去重缓存，确保每次扫描任务独立
    global url_deduplication_cache, original_url_count, deduplicated_url_count, skipped_duplicate_count
    url_deduplication_cache.clear()
    original_url_count = 0
    deduplicated_url_count = 0
    skipped_duplicate_count = 0

    # 优先级最高：结果目录处理（存在则询问是否删除重扫或退出）
    folder_name = re.sub(r'[^a-zA-Z0-9\.]', '_', url)
    current_path = os.getcwd()
    folder_path = os.path.join(current_path, "results", folder_name)
    try:
        if os.path.exists(folder_path):
            logger_print_content(f"[提示] 发现历史扫描结果: {folder_path}")
            try:
                choice = input("是否删除? [y/N]: ").strip().lower()
            except Exception:
                choice = "n"
            if choice in ("y", "yes"):
                try:
                    shutil.rmtree(folder_path)
                    os.makedirs(folder_path, exist_ok=True)
                    logger_print_content("[操作] 已删除历史结果并重新创建目录")
                except Exception as de:
                    logger_print_content(f"[错误] 删除历史结果失败: {de}")
                    return
            else:
                exit("[操作] 保留历史结果，退出扫描任务")
        else:
            os.makedirs(folder_path, exist_ok=True)
    except Exception as e:
        logger_print_content(f"[错误] 结果目录处理异常: {e}")
        return

    # 开局先探测目标URL是否存活
    logger_print_content(f"[存活检测] 正在探测目标URL是否存活: {url}")
    try:
        import requests
        from urllib.parse import urlparse

        # 配置代理
        proxies = None
        if proxy:
            proxies = {
                'http': proxy,
                'https': proxy
            }

        # 探测目标URL存活状态
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
            response = requests.get(url, headers=headers, proxies=proxies, timeout=10, allow_redirects=True)
            status_code = response.status_code
            content_length = len(response.content)

            # 判断存活标准：状态码为200-399且返回内容不为空
            if 200 <= status_code < 400 and content_length > 0:
                logger_print_content(f"[存活检测] ✓ 目标URL存活 (状态码: {status_code}, 内容长度: {content_length} 字节)")
                target_alive = True
            else:
                logger_print_content(f"[存活检测] ✗ 目标URL不可访问 (状态码: {status_code}, 内容长度: {content_length} 字节)")
                target_alive = False
        except requests.exceptions.Timeout:
            logger_print_content(f"[存活检测] ✗ 目标URL连接超时")
            target_alive = False
        except requests.exceptions.ConnectionError:
            logger_print_content(f"[存活检测] ✗ 目标URL连接失败（无法访问）")
            target_alive = False
        except Exception as e:
            logger_print_content(f"[存活检测] ✗ 目标URL检测异常: {str(e)}")
            target_alive = False

    except ImportError:
        logger_print_content("[警告] 无法导入requests模块，跳过存活检测，继续扫描")
        target_alive = True
    except Exception as e:
        logger_print_content(f"[警告] 存活检测失败，继续扫描: {str(e)}")
        target_alive = True

    # 如果目标不存活，直接返回，不创建文件夹和报告
    if not target_alive:
        logger_print_content("="*80)
        logger_print_content(f"[终止] 目标URL {url} 不可访问，终止扫描任务")
        logger_print_content(f"[提示] 请检查:")
        logger_print_content(f"  1. URL是否正确")
        logger_print_content(f"  2. 目标服务是否正在运行")
        logger_print_content(f"  3. 网络连接是否正常")
        logger_print_content(f"  4. 是否需要配置代理")
        logger_print_content("="*80)
        return

    db_path = os.path.join(folder_path, "results.db")
    try:
        conn = sqlite3.connect(db_path, timeout=60)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("CREATE TABLE IF NOT EXISTS meta_target_info (original_url TEXT, domain TEXT, port INTEGER, scan_time TEXT)")
        try:
            conn.execute("ALTER TABLE meta_target_info ADD COLUMN end_time TEXT")
        except Exception: pass
        conn.execute("CREATE TABLE IF NOT EXISTS meta_all_vars (json TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS step1_all_load_urls (url TEXT, referer TEXT, url_type TEXT, method TEXT, headers TEXT, post_data TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS step1_js_urls (url TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS step1_no_js_urls (url TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS step2_js_paths (path TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS step2_dynamic_js_paths (path TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS step2_alive_js (url TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS step2_alive_static (url TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS step2_alive_js_static (url TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS step2_js_cache (url TEXT, content_hash TEXT, length INTEGER, path TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS request_log (id TEXT PRIMARY KEY, url TEXT, method TEXT, headers TEXT, cookies TEXT, timestamp TEXT, is_no_param INTEGER, referer_url TEXT, body TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS response_log (id TEXT PRIMARY KEY, url TEXT, method TEXT, res_code INTEGER, res_type TEXT, response TEXT, timestamp TEXT, format TEXT, file_path TEXT, is_no_param INTEGER)")
        conn.execute("CREATE TABLE IF NOT EXISTS response_files (method TEXT, url TEXT, file_path TEXT, content_hash TEXT, length INTEGER, request_id TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS step3_api_paths (api_path TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS step3_api_paths_meta (api_path TEXT, referer TEXT, url_type TEXT, regex_context_json TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS step4_tree_urls (url TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS step4_base_urls (url TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS step4_path_with_api_urls (url TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS step4_path_with_api_paths (path TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS step4_path_with_no_api_paths (path TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS step4_api_urls (url TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS step5_no_param_responses (url TEXT, method TEXT, res_code INTEGER, res_type TEXT, response TEXT, request_id TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS step5_xml_json_urls (url TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS step5_xml_json_responses (url TEXT, method TEXT, res_code INTEGER, res_type TEXT, response TEXT, request_id TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS step6_parameters (param TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS step7_with_param_responses (url TEXT, method TEXT, res_code INTEGER, res_type TEXT, response TEXT, parameter TEXT, request_id TEXT)")
        try:
            conn.execute("ALTER TABLE step5_no_param_responses ADD COLUMN request_id TEXT")
        except Exception: pass
        try:
            conn.execute("ALTER TABLE step5_xml_json_responses ADD COLUMN request_id TEXT")
        except Exception: pass
        try:
            conn.execute("ALTER TABLE step7_with_param_responses ADD COLUMN request_id TEXT")
        except Exception: pass
        conn.execute("CREATE TABLE IF NOT EXISTS step8_diff_hash (content_hash TEXT, length INTEGER, size INTEGER, url TEXT, path TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS step8_hae (name TEXT, matches TEXT, url TEXT, file TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS step8_sensitive (name TEXT, matches TEXT, url TEXT, file TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS risk_danger_api_urls (url TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS risk_safe_api_urls (url TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS stats_execution (step_name TEXT, request_count INTEGER)")
        conn.execute("CREATE TABLE IF NOT EXISTS summary (total_api INTEGER, valid_api INTEGER, total_requests INTEGER)")
        
        # 尝试增加字段
        try: conn.execute("ALTER TABLE summary ADD COLUMN total_requests INTEGER")
        except Exception: pass
        
        # 创建索引
        conn.execute("CREATE INDEX IF NOT EXISTS idx_step5_np_url ON step5_no_param_responses(url)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_step5_xj_url ON step5_xml_json_urls(url)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_step5_xj_resp_url ON step5_xml_json_responses(url)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_step7_wp_url ON step7_with_param_responses(url)")
        conn.execute("CREATE TABLE IF NOT EXISTS risk_danger_api_urls (url TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS risk_safe_api_urls (url TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS step8_restored_html (url TEXT, local_path TEXT, content TEXT, filename TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS stats_execution (step_name TEXT, request_count INTEGER)")
        # 提交表创建操作
        conn.commit()
    except Exception as e:
        logger_print_content(f"初始化数据库失败: {e}")
        if 'conn' in locals():
            conn.close()
        return

    # 判断是否存活
    try:
        if cookies:
            headers['Cookie'] = cookies
        requests.get(url=url, headers=headers, timeout=TIMEOUT, verify=False)
    except Exception as e:
        return

    domain = urlparse(url).netloc
    parsed_url_obj = urlparse(url)
    target_root_url = f"{parsed_url_obj.scheme}://{parsed_url_obj.netloc}"
    base_domain = get_base_domain(url)
    port = 80
    if '://' in url:
        scheme = url.split('://', 1)[0].lower()
        if ':' in domain:
            try:
                port = int(domain.split(':', 1)[1])
            except:
                port = 443 if scheme == 'https' else 80
        else:
            port = 443 if scheme == 'https' else 80
    scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    excel = openpyxl.Workbook()
    excel.remove(excel[excel.sheetnames[0]])  # 删除第一个默认的表

    # 保存目标基础信息到数据库，供后续插件使用
    if conn:
        try:
            conn.execute("INSERT INTO meta_target_info (original_url, domain, port, scan_time) VALUES (?, ?, ?, ?)", 
                         (url, domain, port, scan_time))
            conn.commit()
        except Exception as e:
            logger_print_content(f"写入meta_target_info失败: {e}")

    excel_name = domain
    excelSavePath = '{}/{}.xlsx'.format(folder_path, excel_name)

    # 文件路径对应的url
    filePath_url_info = {}
    all_load_url = []
    js_and_staticUrl_alive_info = []
    all_api_paths = []
    api_info = {
        'tree_urls': [],
        'base_urls': [],
        'path_with_api_paths': [],
        'path_with_no_api_paths': [],
        'all_path_with_api_urls': [],
        'api_urls': [],
    }
    parameters = []
    all_api_url_xml_json_res = []

    # 第一步先获取该页面加载了哪些js和base url
    proxies_dict = None
    if proxy:
        proxies_dict = {"http": proxy, "https": proxy}
    js_use_proxy = bool(proxy and (proxy_mode in ('js','all')))
    api_use_proxy = bool(proxy and (proxy_mode in ('api','all')))

    if chrome == 'on':
        logger_print_content(f"第一步:调用webdriver获取{url}加载的js和no_js url")
        try:
            import plugins.webdriverFind as wf
            wf.PROXY_SERVER = proxy if js_use_proxy else None
        except Exception:
            pass
        all_load_url = webdriverFind(url, cookies)
        logger_print_content(f"[*] all_load_url = {all_load_url}")
    else:
        logger_print_content(f"第一步:访问{url}获取js和no_js url")
        all_load_url = indexJsFind(url, cookies, proxies=proxies_dict if js_use_proxy else None)
        logger_print_content(f"[*] all_load_url = {all_load_url}")

    # 自动加载js的url列表
    js_load_urls = []
    # 自动加载base的url列表
    no_js_load_urls = []

    for _ in all_load_url:
        if _.get('url_type', None) == 'js':
            js_load_urls.append(_['url'])
        elif _.get('url_type', None) == 'no_js':
            # IP直接返回，域名则需要判断是否是目标的域名
            if filter_base_urls(base_domain, _['url']):
                no_js_load_urls.append(_['url'])

    js_load_urls = list(set(js_load_urls))
    no_js_load_urls = list(set(no_js_load_urls))
    logger_print_content(f"js_load_urls = {js_load_urls}\n\n")
    logger_print_content(f"no_js_load_urls = {no_js_load_urls}\n\n")

    save_dict_to_excel(excelSavePath, excel, '首页自动加载的所有URL列表', all_load_url)
    save_list_to_excel(excelSavePath, excel, '首页自动加载的JS_URL列表', js_load_urls)
    save_list_to_excel(excelSavePath, excel, '首页自动加载的属于目标的非JS_URL列表', no_js_load_urls)

    if conn:
        try:
            conn.executemany("INSERT INTO step1_all_load_urls(url, referer, url_type, method, headers, post_data) VALUES(?,?,?,?,?,?)", 
                             [(d.get('url',''), d.get('referer',''), d.get('url_type',''), d.get('method',''), str(d.get('headers',{})), d.get('post_data','')) for d in all_load_url])
            conn.executemany("INSERT INTO step1_js_urls(url) VALUES(?)", [(u,) for u in js_load_urls])
            conn.executemany("INSERT INTO step1_no_js_urls(url) VALUES(?)", [(u,) for u in no_js_load_urls])
            conn.commit()
            record_step_stats(db_path, "Step 1: 首页加载探测", 1)
        except Exception as e:
            logger_print_content(f"写入step1到DB失败: {e}")

    if store == 'txt':
        with open(f'{folder_path}/1-1首页自动加载的所有URL列表.txt', 'at', encoding='utf-8') as f1, open(f'{folder_path}/1-2首页自动加载的JS_URL列表.txt', 'at', encoding='utf-8') as f2, open(f'{folder_path}/1-3首页自动加载的属于目标的非JS_URL列表.txt', 'at', encoding='utf-8') as f3, open(f'{folder_path}/所有变量列表.txt', 'at', encoding='utf-8') as f9:
            f9.writelines(f"url = {url}\n")
            f9.writelines(f"cookies = {cookies}\n")
            f9.writelines(f"all_load_url = {all_load_url}\n")
            f9.writelines(f"js_load_urls = {js_load_urls}\n")
            f9.writelines(f"no_js_load_urls = {no_js_load_urls}\n")
            f9.writelines(f"-"*100 + '\n')
            for load_url in all_load_url:
                f1.writelines(f"{load_url}\n")
            for js_url in js_load_urls:
                f2.writelines(f"{js_url}\n")
            for no_js_load_url in no_js_load_urls:
                f3.writelines(f"{no_js_load_url}\n")

    # 第二步：访问加载的js和no_js url，提取出新的js
    logger_print_content(f"第二步：访问加载的js和no_js url，提取出新的js")
    # 从加载的js和no_js url，提取出新的js
    js_find_urls = []
    # js_urls = js_load_urls
    # base_urls = base_load_urls
    try:
        import plugins.jsAndStaticUrlFind as jsf
        jsf.proxies = proxies_dict if js_use_proxy else None
    except Exception:
        pass
    js_and_staticUrl_info, js_and_staticUrl_alive_info = js_find_api(domain, js_load_urls + no_js_load_urls, cookies, folder_path, filePath_url_info, db_path if store=='db' else None, max_depth=js_depth)
    logger_print_content(f"[*] 第二步访问加载的js和base url，提取出新的js和static url\n[*] js_and_staticUrl_info = {js_and_staticUrl_info}")
    for _ in js_and_staticUrl_alive_info:
        if _['url_type'] == 'js_url':
            js_find_urls.append(_['url'])
    js_find_urls = list(set(js_find_urls))
    all_js_urls = list(set(js_load_urls + js_find_urls))
    logger_print_content(f"[*] 获取到的所有js url\n[*] all_js_urls = {all_js_urls}\n\n")

    all_alive_staticUrl = []
    for _ in js_and_staticUrl_alive_info:
        if _['url_type'] == 'static_url':
            all_alive_staticUrl.append(_['url'])

    all_alive_js_and_staticUrl = []
    for _ in js_and_staticUrl_alive_info:
        all_alive_js_and_staticUrl.append(_['url'])

    save_list_to_excel(excelSavePath, excel, '提取出的js路径', js_and_staticUrl_info['js_paths'])
    save_list_to_excel(excelSavePath, excel, '所有存活的js(自动加载的js和拼接的js)', all_js_urls)
    save_list_to_excel(excelSavePath, excel, '所有存活的静态url', all_alive_staticUrl)
    save_list_to_excel(excelSavePath, excel, '所有存活的js和静态url', all_alive_js_and_staticUrl)

    if conn:
        try:
            conn.executemany("INSERT INTO step2_js_paths(path) VALUES(?)", [(p,) for p in js_and_staticUrl_info['js_paths']])
            # 动态JS模块还原（扫描 js_cache）
            dyn_paths = restore_dynamic_js_modules(folder_path, db_path if store=='db' else None)
            if dyn_paths:
                conn.executemany("INSERT INTO step2_dynamic_js_paths(path) VALUES(?)", [(p,) for p in dyn_paths])
            conn.executemany("INSERT INTO step2_alive_js(url) VALUES(?)", [(u,) for u in all_js_urls])
            conn.executemany("INSERT INTO step2_alive_static(url) VALUES(?)", [(u,) for u in all_alive_staticUrl])
            conn.executemany("INSERT INTO step2_alive_js_static(url) VALUES(?)", [(u,) for u in all_alive_js_and_staticUrl])
            conn.commit()
            record_step_stats(db_path, "Step 2: JS与资源采集", len(js_and_staticUrl_alive_info))
        except Exception as e:
            logger_print_content(f"写入step2到DB失败: {e}")

    if store == 'txt':
        with open(f'{folder_path}/2-1-提取出的js路径.txt', 'at', encoding='utf-8') as f, open(f'{folder_path}/2-2-所有存活的js(自动加载的js和拼接的js).txt', 'at', encoding='utf-8') as f2, open(f'{folder_path}/2-3-所有存活的静态url.txt', 'at', encoding='utf-8') as f3, open(f'{folder_path}/2-4-所有存活的js和静态url.txt', 'at', encoding='utf-8') as f4, open(f'{folder_path}/所有变量列表.txt', 'at', encoding='utf-8') as f9:
            # f9.writelines(f"js_urls = {[url] + js_load_urls}\n")
            f9.writelines(f"js_and_staticUrl_alive_info = {js_and_staticUrl_alive_info}\n")
            f9.writelines(f"js_and_staticUrl_info = {js_and_staticUrl_info}\n")
            f9.writelines(f"js_and_staticUrl_info['js_paths'] = {js_and_staticUrl_info['js_paths']}\n")
            f9.writelines(f"js_and_staticUrl_info['js_url'] = {js_and_staticUrl_info['js_url']}\n")
            f9.writelines(f"js_and_staticUrl_info['static_paths'] = {js_and_staticUrl_info['static_paths']}\n")
            f9.writelines(f"js_and_staticUrl_info['static_url'] = {js_and_staticUrl_info['static_url']}\n")
            f9.writelines(f"all_alive_staticUrl = {all_alive_staticUrl}\n")
            f9.writelines(f"all_alive_js_and_staticUrl = {all_alive_js_and_staticUrl}\n")
            f9.writelines(f"all_js_urls = {all_js_urls}\n")
            f9.writelines(f"-"*100 + '\n')

            for js_path in js_and_staticUrl_info['js_paths']:
                js_paths.append(js_path)
                f.writelines(f"{js_path}\n")

            for js_url in all_js_urls:
                f2.writelines(f"{js_url}\n")

            for _ in all_alive_staticUrl:
                f3.writelines(f"{_}\n")

            for _ in all_alive_js_and_staticUrl:
                f4.writelines(f"{_}\n")

            # for staticUrl_path in js_and_staticUrl_info['static_paths']:
            #     if staticUrl_path.startswith('http'):
            #         static_paths.append(staticUrl_path)
            #         f3.writelines(f"{staticUrl_path}\n")

    if noApiScan == 0:

        # 第三步：访问所有js url，从网页源码中匹配出api接口
        logger_print_content(f"第三步：访问所有js url，从网页源码中匹配出api接口")
        try:
            import plugins.apiPathFind as apf
            apf.proxies = proxies_dict if js_use_proxy else None
        except Exception:
            pass
        all_api_paths = apiPathFind_api(all_alive_js_and_staticUrl, cookies, folder_path)
        logger_print_content(f"[*] 所有api接口\n[*] all_api_paths = {all_api_paths}")

        save_dict_to_excel(excelSavePath, excel, '从所有js里获取到的API_PATH列表', all_api_paths)
        if conn:
            try:
                conn.executemany("INSERT INTO step3_api_paths(api_path) VALUES(?)", [(d.get('api_path','') if isinstance(d,dict) else str(d),) for d in all_api_paths])
                meta_rows = []
                for d in all_api_paths:
                    if isinstance(d, dict):
                        api_path_val = d.get('api_path', '')
                        referer_val = d.get('referer', '')
                        url_type_val = d.get('url_type', '')
                        rc = d.get('regex_context')
                        rc_json = json.dumps(rc, ensure_ascii=False) if rc else None
                        meta_rows.append((api_path_val, referer_val, url_type_val, rc_json))
                if meta_rows:
                    conn.executemany("INSERT INTO step3_api_paths_meta(api_path, referer, url_type, regex_context_json) VALUES(?,?,?,?)", meta_rows)
                conn.commit()
            except Exception as e:
                logger_print_content(f"写入step3到DB失败: {e}")

        if infoScan:
            logger_print_content("检测到 --infoscan 模式，将跳过接口探测阶段，直接进入敏感信息匹配...")
            getJsUrl_info = {
                'all_load_url': all_load_url,
                'js_load_urls': js_load_urls,
                'no_js_load_urls': no_js_load_urls,
                'js_and_staticUrl_info': js_and_staticUrl_info,
                'js_and_staticUrl_alive_info': js_and_staticUrl_alive_info,
                'all_js_urls': all_js_urls,
                'all_api_paths': all_api_paths,
                'api_info': api_info,
                'parameters': [],
                'all_api_url_xml_json_res': []
            }
            
            # 必须先关闭当前连接，释放数据库锁，因为 deal_results 内部会重新连接数据库
            if conn:
                conn.close()
                conn = None

            # 跳过后续步骤，直接去第八步
            disposeResults_info = deal_results(excelSavePath, excel, folder_path, filePath_url_info, db_path, aiScan)
            getJsUrl_info['disposeResults_info'] = disposeResults_info
            
            # 重新连接以保存 summary
            try:
                conn = sqlite3.connect(db_path)
                conn.execute("DELETE FROM summary")
                conn.execute("INSERT INTO summary(total_api, valid_api, total_requests) VALUES(?,?,?)", (0, 0, GlobalRequestCounter.get_count()))
                conn.execute("DELETE FROM meta_all_vars")
                conn.execute("INSERT INTO meta_all_vars(json) VALUES(?)", (json.dumps(getJsUrl_info, ensure_ascii=False),))
                conn.commit()
            except Exception as e:
                logger_print_content(f"写入 summary 失败: {e}")
            finally:
                if conn:
                    conn.close()
            
            return getJsUrl_info
        if store == 'txt':
            with open(f'{folder_path}/3-从所有js里获取到的API_PATH列表.txt', 'at', encoding='utf-8') as f, open(f'{folder_path}/所有变量列表.txt', 'at', encoding='utf-8') as f9:
                for api_path in all_api_paths:
                    f.writelines(f"{api_path}\n")
                f9.writelines(f"all_api_paths = {all_api_paths}\n")


        # 步骤 3.5: 执行上下文关联与去重分析
        logger_print_content(f"步骤 3.5: 执行上下文关联与去重分析...")
        try:
            from plugins.context_deduplication import run_context_deduplication
            context_apis = run_context_deduplication(db_path if store=='db' else None, folder_path)
            
            # 将新发现的接口添加到 all_api_paths 以供 Step 4 使用
            # 注意：all_api_paths 是一个字典列表，每个元素包含 'url_type' 和 'api_path'
            added_count = 0
            existing_paths = set()
            for item in all_api_paths:
                if isinstance(item, dict) and 'api_path' in item:
                    existing_paths.add(item['api_path'])
            
            for key, entry in context_apis.items():
                path = entry.get('path')
                full_url = entry.get('full_url')
                
                # 如果有完整URL，提取Base URL并添加到 base_urls
                if full_url and full_url.startswith('http'):
                    try:
                        parsed = urlparse(full_url)
                        if path and path != '/':
                             # 尝试反推 Base URL: full_url - path
                             # 注意：这里需要谨慎，因为 path 可能只是 full_url 的一部分后缀
                             if full_url.endswith(path):
                                 base = full_url[:-len(path)].rstrip('/')
                                 if base:
                                     api_info['base_urls'].append(base)
                                     logger_print_content(f"[Context] 发现新的 Base URL: {base}")
                        
                        # 或者直接取 parse 后的 scheme+netloc+dirname
                        # 简单策略：scheme://netloc
                        root = f"{parsed.scheme}://{parsed.netloc}"
                        # 只有当它是新的且有效时才添加
                        if root not in api_info['tree_urls']:
                             api_info['tree_urls'].append(root)

                    except Exception: pass

                if path and path not in existing_paths:
                    # 构造符合 filter_data 要求的字典结构
                    new_entry = {
                        'url_type': 'api_path',
                        'api_path': path,
                        'url': '' # 默认为空
                    }
                    all_api_paths.append(new_entry)
                    existing_paths.add(path) # 更新已存在集合，防止重复添加
                    added_count += 1
            
            logger_print_content(f"[*] 经过去重与关联分析，新增接口路径数: {added_count}，当前累计接口路径数: {len(all_api_paths)}")
        except Exception as e:
            logger_print_content(f"[-] 上下文关联分析失败: {e}")


        # 第四步梳理: API接口，整理出所有的API URL
        api_info = filter_data(base_domain, all_load_url, all_api_paths, dedupe, base_override=rr_config.get('base_override'), basepath=rr_config.get('basepath'), target_root_url=target_root_url)

        # Step 3.5 补充逻辑：将上下文分析发现的完整 URL 直接添加到最终 API 列表中
        # 这样可以避免 filter_data 因为 Base URL 缺失而过滤掉这些接口
        try:
             # 从 Step 3.5 的 context_apis 中再次遍历（如果前面 context_apis 变量还在作用域内）
             # 如果 context_apis 不在作用域，我们可以从 all_api_paths 倒推，但不够准确
             # 实际上 context_apis 是在上一个 try 块定义的，如果成功，这里应该能访问到
             if 'context_apis' in locals():
                 added_full_urls = 0
                 for key, entry in context_apis.items():
                     full_url = entry.get('full_url')
                     if full_url and full_url.startswith('http'):
                         full_url = normalize_url(full_url)
                         # 简单的过滤：确保是目标域
                         if filter_base_urls(base_domain, full_url):
                             if full_url not in api_info['api_urls']:
                                 api_info['api_urls'].append(full_url)
                                 added_full_urls += 1
                 if added_full_urls > 0:
                     logger_print_content(f"[*] 从上下文分析中直接合并了 {added_full_urls} 个完整 URL 到最终列表")
        except Exception as e:
            logger_print_content(f"[-] 合并上下文完整URL失败: {e}")


        save_list_to_excel(excelSavePath, excel, '从自动加载的URL里提取出来的根路径', api_info['tree_urls'])
        save_list_to_excel(excelSavePath, excel, '从自动加载的URL里提取出来的BASE_URL', api_info['base_urls'])
        save_list_to_excel(excelSavePath, excel, '带有API字符串接口的url', api_info['all_path_with_api_urls'])
        save_list_to_excel(excelSavePath, excel, '带有API字符串的接口', api_info['path_with_api_paths'])
        save_list_to_excel(excelSavePath, excel, '没有API字符串的接口', api_info['path_with_no_api_paths'])
        save_list_to_excel(excelSavePath, excel, '组合出来的最终的所有API_URL', api_info['api_urls'])

        if conn:
            try:
                conn.executemany("INSERT INTO step4_tree_urls(url) VALUES(?)", [(u,) for u in api_info['tree_urls']])
                conn.executemany("INSERT INTO step4_base_urls(url) VALUES(?)", [(u,) for u in api_info['base_urls']])
                conn.executemany("INSERT INTO step4_path_with_api_urls(url) VALUES(?)", [(u,) for u in api_info['all_path_with_api_urls']])
                conn.executemany("INSERT INTO step4_path_with_api_paths(path) VALUES(?)", [(p,) for p in api_info['path_with_api_paths']])
                conn.executemany("INSERT INTO step4_path_with_no_api_paths(path) VALUES(?)", [(p,) for p in api_info['path_with_no_api_paths']])
                conn.executemany("INSERT INTO step4_api_urls(url) VALUES(?)", [(u,) for u in api_info['api_urls']])
                conn.commit()
            except Exception as e:
                logger_print_content(f"写入step4到DB失败: {e}")

        if store == 'txt':
            with open(f'{folder_path}/4-1-从自动加载的URL里提取出来的根路径.txt', 'at', encoding='utf-8') as f, open(f'{folder_path}/4-2-从自动加载的URL里提取出来的BASE_URL.txt', 'at', encoding='utf-8') as f2, open(f'{folder_path}/4-3-带有API字符串接口的url.txt', 'at', encoding='utf-8') as f3, open(f'{folder_path}/4-4-带有API字符串的接口.txt', 'at', encoding='utf-8') as f4, open(f'{folder_path}/4-5-没有API字符串的接口.txt', 'at', encoding='utf-8') as f5, open(f'{folder_path}/4-6-组合出来的最终的所有API_URL.txt', 'at', encoding='utf-8') as f6, open(f'{folder_path}/所有变量列表.txt', 'at', encoding='utf-8') as f9:
                f9.writelines(f"api_info = {api_info}\n")
                f9.writelines(f"tree_urls = {api_info['tree_urls']}\n")
                f9.writelines(f"base_urls = {api_info['base_urls']}\n")
                f9.writelines(f"path_with_api_paths = {api_info['path_with_api_paths']}\n")
                f9.writelines(f"path_with_no_api_paths = {api_info['path_with_no_api_paths']}\n")
                f9.writelines(f"all_path_with_api_urls = {api_info['all_path_with_api_urls']}\n")
                f9.writelines(f"api_urls = {api_info['api_urls']}\n")
                f9.writelines(f"-"*100 + '\n')

                for tree_url in api_info['tree_urls']:
                    f.writelines(f"{tree_url}\n")

                for base_url in api_info['base_urls']:
                    f2.writelines(f"{base_url}\n")

                for path_with_api_url in api_info['all_path_with_api_urls']:
                    f3.writelines(f"{path_with_api_url}\n")

                for path_with_api_path in api_info['path_with_api_paths']:
                    f4.writelines(f"{path_with_api_path}\n")

                for path_with_no_api_path in api_info['path_with_no_api_paths']:
                    f5.writelines(f"{path_with_no_api_path}\n")

                for api_url in api_info['api_urls']:
                    f6.writelines(f"{api_url}\n")



        if attackType == 0:
            api_urls_raw = api_info['api_urls']
            api_urls = []
            _seen_urls = set()
            for u in api_urls_raw:
                nu = normalize_url(u)
                if nu not in _seen_urls:
                    _seen_urls.add(nu)
                    api_urls.append(nu)

            if len(api_urls) > 200000:
                return
            # 所有api请求的响应包
            all_api_url_xml_json_res = []

            # 第五步：梳理所有API接口并访问
            # 在此步骤前等待 AST 分析完成，确保 AST 发现的接口可用
            try:
                from plugins.async_analysis import AsyncAnalysisManager
                manager = AsyncAnalysisManager()
                if manager:
                    logger_print_content("=" * 80)
                    logger_print_content("等待 AST 异步分析完成（确保发现接口可用）...")
                    logger_print_content("=" * 80)
                    manager.wait_for_ast_ready(timeout=60)
                    stats = manager.get_stats()
                    logger_print_content(f"[异步分析] AST状态: 已完成 {stats['ast']['completed']}/{stats['ast']['submitted']}")
            except Exception as e:
                logger_print_content(f"[异步分析] 等待AST完成失败: {e}")

            logger_print_content(f"第五步：无参三种形式请求所有API接口")
            
            # 构建 URL 到 Method 的映射，用于减少不必要的请求
            url_methods = {}
            if 'all_load_url' in locals():
                for item in all_load_url:
                    u = item.get('url')
                    m = item.get('method')
                    if u and m:
                        url_methods[u] = m
                        # 尝试保存规范化后的 URL
                        try:
                            norm_u = normalize_url(u)
                            if norm_u and norm_u != u:
                                url_methods[norm_u] = m
                        except: pass
            
            try:
                import plugins.apiUrlReqNoParameter as np
                np.proxies = proxies_dict if api_use_proxy else None
            except Exception:
                pass
            # 传入 path_with_api_paths 作为 prefixes，用于 404 时的 fallback 重试
            
            # 收集之前步骤已请求过的 URL (Step 1 + Step 2)
            ignore_get_urls = set()
            # Step 1: 首页加载
            if 'url' in locals():
                ignore_get_urls.add(url)
            # Step 2: JS/静态资源探测
            if 'js_and_staticUrl_alive_info' in locals():
                for info in js_and_staticUrl_alive_info:
                    if info.get('url'):
                        ignore_get_urls.add(info['url'])
                        
            api_url_res = apiUrlReqNoParameter_api(url, api_urls, cookies, folder_path, filePath_url_info, db_path if store=='db' else None, {"db_path": db_path if store=='db' else None, **(rr_config or {})}, prefixes=api_info.get('path_with_api_paths'), url_methods=url_methods, ignore_get_urls=list(ignore_get_urls))


            # 非404，xml和json的api接口
            xml_json_api_url = []
            if store == 'txt':
                with open(f'{folder_path}/5-1-无参三种形式请求API接口响应结果.txt', 'at', encoding='utf-8') as f1, open(f'{folder_path}/5-2-XML_JSON的API_URL列表.txt', 'at', encoding='utf-8') as f2, open(f'{folder_path}/5-3-XML_JSON的API_URL无参的RESPONSE结果.txt', 'at', encoding='utf-8') as f3, open(f'{folder_path}/所有变量列表.txt', 'at', encoding='utf-8') as f9:
                    f9.writelines(f"无参 api_url_res = {api_url_res}\n")
                    f9.writelines(f"-"*100)
                    for _ in api_url_res:
                        f1.writelines(f"{_}\n")
                        if 'xml' in str(_['res_type']).lower() or 'json' in str(_['res_type']).lower():
                            f2.writelines(f"{_['url']}\n")
                            f3.writelines(f"{_}\n")
                            xml_json_api_url.append(_['url'])
                            all_api_url_xml_json_res.append(_)
            else:
                for _ in api_url_res:
                    if 'xml' in str(_['res_type']).lower() or 'json' in str(_['res_type']).lower():
                        xml_json_api_url.append(_['url'])
                        all_api_url_xml_json_res.append(_)
            _seen_xml = set()
            xml_json_api_url = []
            for u in all_api_url_xml_json_res:
                nu = normalize_url(u.get('url',''))
                if nu and nu not in _seen_xml:
                    _seen_xml.add(nu)
                    xml_json_api_url.append(nu)

            save_dict_to_excel(excelSavePath, excel, '无参三种形式请求API接口响应结果', api_url_res)
            save_list_to_excel(excelSavePath, excel, 'XML_JSON的API_URL列表', xml_json_api_url)
            save_dict_to_excel(excelSavePath, excel, 'XML_JSON的API_URL无参的RESPONSE结果', all_api_url_xml_json_res)
            if conn:
                try:
                    conn.executemany("INSERT INTO step5_no_param_responses(url, method, res_code, res_type, response, request_id) VALUES(?,?,?,?,?,?)",
                                     [(_.get('url',''), _.get('method',''), int(_.get('res_code',0)), _.get('res_type',''), _.get('response',''), _.get('request_id','')) for _ in api_url_res])
                    conn.executemany("INSERT INTO step5_xml_json_urls(url) VALUES(?)", [(u,) for u in xml_json_api_url])
                    conn.executemany("INSERT INTO step5_xml_json_responses(url, method, res_code, res_type, response, request_id) VALUES(?,?,?,?,?,?)",
                                     [(_.get('url',''), _.get('method',''), int(_.get('res_code',0)), _.get('res_type',''), _.get('response',''), _.get('request_id','')) for _ in all_api_url_xml_json_res])
                    conn.commit()
                    record_step_stats(db_path, "Step 5: 无参接口扫描", len(api_url_res))
                except Exception as e:
                    logger_print_content(f"写入step5到DB失败: {e}")

            # 第六步：提取参数
            logger_print_content(f"第六步：提取参数")
            parameters = getParameter_api(folder_path)
            ast_parameters = []
            ast_param_map = []
            try:
                if os.path.isfile(db_path):
                    try:
                        conn_ast = sqlite3.connect(db_path)
                        try:
                            conn_ast.execute("CREATE TABLE IF NOT EXISTS step6_parameters(param TEXT)")
                            conn_ast.execute("CREATE TABLE IF NOT EXISTS step6_parameters_map (url TEXT, method TEXT, param TEXT, source TEXT, tool TEXT, file_path TEXT, loc INTEGER)")
                            cur_ast = conn_ast.execute("SELECT file_path, api_json FROM step2_ast_analysis")
                            rows = cur_ast.fetchall()
                            for row in rows:
                                file_path = None
                                api_json = None
                                if isinstance(row, (list, tuple)):
                                    file_path = row[0]
                                    api_json = row[1]
                                elif isinstance(row, dict):
                                    file_path = row.get('file_path')
                                    api_json = row.get('api_json')
                                try:
                                    apis = json.loads(api_json or '[]')
                                    if isinstance(apis, list):
                                        for api in apis:
                                            params_list = api.get('params', [])
                                            param_sources = api.get('param_sources', [])
                                            if isinstance(params_list, list):
                                                for pname in params_list:
                                                    if isinstance(pname, str) and pname:
                                                        ast_parameters.append(pname)
                                            if isinstance(param_sources, list):
                                                for ps in param_sources:
                                                    try:
                                                        pname = ps.get('name')
                                                        psrc = ps.get('source') or 'unknown'
                                                        if isinstance(pname, str) and pname:
                                                            ast_param_map.append({
                                                                'url': api.get('url') or '',
                                                                'method': str(api.get('method') or '').upper() or 'UNKNOWN',
                                                                'param': pname,
                                                                'source': psrc,
                                                                'tool': api.get('tool') or '',
                                                                'file_path': file_path or '',
                                                                'loc': int(api.get('loc') or 0)
                                                            })
                                                    except Exception:
                                                        pass
                                except Exception:
                                    pass
                        except Exception:
                            pass
                        try:
                            conn_ast.close()
                        except Exception:
                            pass
                    except Exception:
                        pass
            except Exception:
                pass
            if ast_parameters:
                try:
                    ast_parameters = [p for p in ast_parameters if isinstance(p, str) and p]
                    if not isinstance(parameters, list):
                        parameters = []
                    for p in ast_parameters:
                        if p not in parameters:
                            parameters.append(p)
                except Exception:
                    pass
            save_list_to_excel(excelSavePath, excel, '提取的所有参数', parameters)
            if conn:
                try:
                    conn.executemany("INSERT INTO step6_parameters(param) VALUES(?)", [(p,) for p in parameters])
                    if ast_param_map:
                        data = []
                        for item in ast_param_map:
                            url = normalize_url(item.get('url','') or '')
                            method = item.get('method','UNKNOWN')
                            param = item.get('param','')
                            source = item.get('source','unknown')
                            tool = item.get('tool','')
                            file_path = item.get('file_path','')
                            loc = int(item.get('loc') or 0)
                            if param:
                                data.append((url, method, param, source, tool, file_path, loc))
                        if data:
                            conn.execute("CREATE TABLE IF NOT EXISTS step6_parameters_map (url TEXT, method TEXT, param TEXT, source TEXT, tool TEXT, file_path TEXT, loc INTEGER)")
                            conn.executemany("INSERT INTO step6_parameters_map(url, method, param, source, tool, file_path, loc) VALUES(?,?,?,?,?,?,?)", data)
                    conn.commit()
                except Exception as e:
                    logger_print_content(f"写入step6到DB失败: {e}")
            if store == 'txt':
                with open(f'{folder_path}/6-提取的所有参数.txt', 'at', encoding='utf-8') as f, open(f'{folder_path}/所有变量列表.txt', 'at', encoding='utf-8') as f9:
                    f9.writelines(f"parameters = {parameters}\n")
                    f9.writelines(f"-"*100 + '\n')
                    for parameter in parameters:
                        f.writelines(f"{parameter}\n")

            # 第七步：携带参数请求
            if parameters:
                # 在此步骤前等待 SourceMap 分析完成，确保还原的接口可用
                try:
                    from plugins.async_analysis import AsyncAnalysisManager
                    manager = AsyncAnalysisManager()
                    if manager:
                        logger_print_content("=" * 80)
                        logger_print_content("等待 SourceMap 异步分析完成（确保还原接口可用）...")
                        logger_print_content("=" * 80)
                        manager.wait_for_sourcemap_ready(timeout=60)
                        stats = manager.get_stats()
                        logger_print_content(f"[异步分析] SourceMap状态: 已完成 {stats['sourcemap']['completed']}/{stats['sourcemap']['submitted']}")
                except Exception as e:
                    logger_print_content(f"[异步分析] 等待SourceMap完成失败: {e}")

                logger_print_content(f"第七步：有参三种形式请求所有API接口")
                try:
                    import plugins.apiUrlReqWithParameter as wp
                    wp.proxies = {"http": proxy, "https": proxy} if api_use_proxy else None
                except Exception:
                    pass
                api_url_res = apiUrlReqWithParameter_api(url, xml_json_api_url, cookies, folder_path, parameters, filePath_url_info, db_path if store=='db' else None, {"db_path": db_path if store=='db' else None, **(rr_config or {})}, url_methods=url_methods)
                api_url_res = api_url_res if isinstance(api_url_res, list) else []
                save_dict_to_excel(excelSavePath, excel, '有参三种形式请求XML_JSON的API接口响应结果', api_url_res)

                if store == 'txt':
                    with open(f'{folder_path}/7-1-有参三种形式请求XML_JSON的API接口响应结果.txt', 'at', encoding='utf-8') as f1, open(f'{folder_path}/7-2-XML_JSON的API_URL有参的RESPONSE结果.txt', 'at', encoding='utf-8') as f3, open(f'{folder_path}/所有变量列表.txt', 'at', encoding='utf-8') as f9:
                        f9.writelines(f"xml_json_api_url = {xml_json_api_url}\n")
                        f9.writelines(f"有参 api_url_res = {api_url_res}\n")
                        f9.writelines(f"-"*100 + '\n')
                        for _ in api_url_res:
                            f1.writelines(f"{_}\n")
                            f3.writelines(f"{_}\n")
                            all_api_url_xml_json_res.append(_)
                if conn:
                    try:
                        conn.executemany("INSERT INTO step7_with_param_responses(url, method, res_code, res_type, response, parameter, request_id) VALUES(?,?,?,?,?,?,?)",
                        [(_.get('url',''), _.get('method',''), int(_.get('res_code',0)), _.get('res_type',''), _.get('response',''), _.get('parameter',''), _.get('request_id','')) for _ in api_url_res])
                        conn.commit()
                        record_step_stats(db_path, "Step 7: 有参接口测试", len(api_url_res))
                    except Exception as e:
                        logger_print_content(f"写入step7到DB失败: {e}")

    disposeResults_info = deal_results(excelSavePath, excel, folder_path, filePath_url_info, db_path, aiScan)


    getJsUrl_info = {
        "all_load_urls": all_load_url,                                   # 1-1首页自动加载的所有URL列表.txt
        # "js_load_urls": js_load_urls,                                    # 1-2首页自动加载的JS_URL列表.txt
        # "no_js_load_urls": no_js_load_urls,                              # 1-3首页自动加载的属于目标的非JS_URL列表.txt
        #
        # "all_js_urls": all_js_urls,                                      # 2-1-所有存活的js路径-自动加载的js和拼接的js.txt
        # "js_paths": js_and_staticUrl_info['js_paths'],                   # 2-2-提取出的js路径.txt
        # "static_paths": js_and_staticUrl_info['static_paths'],           # 2-3-提取出的静态url路径.txt
        "js_and_staticUrl_alive_info": js_and_staticUrl_alive_info,      # 2-4-存活的js和静态URL.txt

        "all_api_paths": all_api_paths,                                  # 3-从所有js里获取到的API_PATH列表.txt

        "tree_urls" : api_info['tree_urls'],                             # 4-1-从自动加载的URL里提取出来的根路径.txt
        "base_urls": api_info['base_urls'],                              # 4-2-从自动加载的URL里提取出来的BASE_URL.txt
        "all_path_with_api_urls": api_info['all_path_with_api_urls'],    # 4-3-从自动加载的URL里提取出来的路径带有api字符串的URL.txt
        "path_with_api_paths": api_info['path_with_api_paths'],          # 4-4-从所有js里获取到的路径里有API字符串的接口列表.txt
        "path_with_no_api_paths": api_info['path_with_no_api_paths'],    # 4-5-从所有js里获取到的路径里没有API字符串的接口列表.txt
        # "api_urls": [],                                                # 4-6-组合出来的最终的所有API_URL.txt

        "parameters": parameters,                                        # 6-提取的所有参数.txt

        "all_api_url_xml_json_res": all_api_url_xml_json_res,            # 5-3-XML_JSON的API_URL无参的RESPONSE结果.txt 和 7-2-XML_JSON的API_URL有参的RESPONSE结果.txt

        "disposeResults_info": disposeResults_info,
    }
    if store == 'txt':
        with open(f'{folder_path}/所有变量列表.txt', 'at', encoding='utf-8') as f9:
            f9.writelines(f"getJsUrl_info = {getJsUrl_info}\n")

    logger_print_content('------------------------------------------------------------------------------------------------------------------------------------')

    if conn:
        try:
            end_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            conn.execute("DELETE FROM meta_target_info")
            conn.execute("INSERT INTO meta_target_info(original_url, domain, port, scan_time, end_time) VALUES(?,?,?,?,?)",
                         (url, domain.split(':')[0], port, scan_time, end_time))
            total_api = len(api_info.get("api_urls", []))
            valid_api = len([_ for _ in getJsUrl_info.get("all_api_url_xml_json_res", []) if isinstance(_, dict) and _.get("res_code") == 200])
            
            # 计算总请求量 (使用全局计数器以保持与命令行一致)
            # cur_stats = conn.execute("SELECT SUM(request_count) FROM stats_execution")
            # total_reqs = cur_stats.fetchone()[0] or 0
            total_reqs = GlobalRequestCounter.get_count()
            
            conn.execute("DELETE FROM summary")
            conn.execute("INSERT INTO summary(total_api, valid_api, total_requests) VALUES(?,?,?)", (total_api, valid_api, total_reqs))
            try:
                conn.execute("DELETE FROM meta_all_vars")
                conn.execute("INSERT INTO meta_all_vars(json) VALUES(?)", (json.dumps(getJsUrl_info, ensure_ascii=False),))
            except Exception:
                pass
            conn.commit()
        except Exception as e:
            logger_print_content(f"写入summary到DB失败: {e}")
    try:
        backfill_response_dir_to_db(folder_path, db_path, filePath_url_info)
    except Exception as e:
        logger_print_content(f"回填response目录到DB失败: {e}")
    try:
        backfill_rr_log_to_db(folder_path, db_path)
    except Exception as e:
        logger_print_content(f"回填rr_log到DB失败: {e}")

    # 统一保存Excel
    try:
        excel.save(excelSavePath)
    except Exception as e:
        logger_print_content(f"保存Excel失败: {e}")

    if store == 'db':
        txt_files = [
            '1-1首页自动加载的所有URL列表.txt',
            '1-2首页自动加载的JS_URL列表.txt',
            '1-3首页自动加载的属于目标的非JS_URL列表.txt',
            '2-1-提取出的js路径.txt',
            '2-2-所有存活的js(自动加载的js和拼接的js).txt',
            '2-3-所有存活的静态url.txt',
            '2-4-所有存活的js和静态url.txt',
            '3-从所有js里获取到的API_PATH列表.txt',
            '4-1-从自动加载的URL里提取出来的根路径.txt',
            '4-2-从自动加载的URL里提取出来的BASE_URL.txt',
            '4-3-带有API字符串接口的url.txt',
            '4-4-带有API字符串的接口.txt',
            '4-5-没有API字符串的接口.txt',
            '4-6-组合出来的最终的所有API_URL.txt',
            '5-1-无参三种形式请求API接口响应结果.txt',
            '5-2-XML_JSON的API_URL列表.txt',
            '5-3-XML_JSON的API_URL无参的RESPONSE结果.txt',
            '6-提取的所有参数.txt',
            '7-1-有参三种形式请求XML_JSON的API接口响应结果.txt',
            '7-2-XML_JSON的API_URL有参的RESPONSE结果.txt',
            '危险API接口.txt',
            '安全API接口.txt',
            '所有变量列表.txt',
        ]
        for name in txt_files:
            p = os.path.join(folder_path, name)
            try:
                if os.path.isfile(p):
                    os.remove(p)
            except Exception:
                pass
    return getJsUrl_info

def manage_interactive():
    # 启用Windows ANSI支持
    os.system('')

    current_path = os.getcwd()
    results_root = os.path.join(current_path, "results")
    if not os.path.isdir(results_root):
        try:
            os.makedirs(results_root, exist_ok=True)
        except Exception:
            print("[!] 无法创建results目录")
            return

    print("[*] 正在启动Web管理界面...")
    print("[*] API服务器地址: http://127.0.0.1:8089")

    # 启动API服务器
    try:
        from plugins.api_server import run_api_server
        api_server = run_api_server(host="127.0.0.1", port=8089)
    except Exception as e:
        print(f"[!] API服务器启动失败: {e}")

    # 直接启动 Web 服务，进入大厅模式
    start_web_view(results_root, manage_mode=True, api_server=api_server)

class ResultsHandler(BaseHTTPRequestHandler):
    selected_dir = ""
    results_root = ""
    # 随机 Token 映射表
    PATH_TO_TOKEN = {}
    TOKEN_TO_PATH = {}

    @classmethod
    def get_token(cls, path):
        """为路径获取或生成Token"""
        path = os.path.abspath(path)
        if path in cls.PATH_TO_TOKEN:
            return cls.PATH_TO_TOKEN[path]
        token = uuid.uuid4().hex
        cls.PATH_TO_TOKEN[path] = token
        cls.TOKEN_TO_PATH[token] = path
        return token
    
    @classmethod
    def resolve_token(cls, token):
        """根据Token获取路径"""
        return cls.TOKEN_TO_PATH.get(token)

    def get_safe_path(self, req_id):
        """
        根据 Token 获取安全路径
        """
        if not req_id: return ""
        # 尝试解析 Token
        path = self.resolve_token(req_id)
        if path and os.path.exists(path):
             return path
        
        # 兼容旧逻辑：如果不是 token 且是目录名，尝试直接拼接（仅在初始化未完成时）
        # 但为了安全，严格限制
        return ""

    def do_GET(self):
        # 统一获取 id 参数（如果存在）
        try:
            from urllib.parse import urlparse, parse_qs
            _qs = parse_qs(urlparse(self.path).query)
            _req_id = (_qs.get('id') or [''])[0]
        except:
            _req_id = ""

        # 如果有 id，尝试解析并更新上下文（仅针对本次请求，但由于 selected_dir 是类变量，这里仍有副作用，
        # 不过下文我们将优先使用局部变量）
        current_dir = ""
        if _req_id:
             _path = self.get_safe_path(_req_id)
             if _path:
                 current_dir = _path
        
        # 如果没有 id，回退到类变量（兼容旧逻辑，但对于敏感操作应拒绝）
        if not current_dir:
            current_dir = self.selected_dir

        if self.path.startswith("/api/data"):
            try:
                # 强制要求有效目录
                if not current_dir or not os.path.isdir(current_dir):
                     raise Exception("No project selected or invalid token")
                
                data_dict = build_results_from_db(current_dir)
                data = json.dumps(data_dict, ensure_ascii=False).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                self.wfile.write(data)
            except Exception as e:
                traceback.print_exc()
                self.send_response(500)
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))
            return
        if self.path.startswith("/api/delete"):
            try:
                from urllib.parse import urlparse, parse_qs
                qs = parse_qs(urlparse(self.path).query)
                req_id = (qs.get('id') or [''])[0]
                if not req_id:
                     # 兼容旧逻辑（虽然前端已改，但为了保险）
                     d = (qs.get('dir') or [''])[0]
                     if d and os.path.isabs(d):
                         # 拒绝绝对路径删除，强制要求 ID
                         raise Exception("forbidden: use id instead of dir")
                
                d = self.get_safe_path(req_id)
                if not d:
                    raise Exception("forbidden or not found")
                
                shutil.rmtree(d)
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                self.wfile.write(b'{"status":"ok"}')
            except Exception as e:
                traceback.print_exc()
                self.send_response(500)
                self.end_headers()
                self.wfile.write(json.dumps({"status":"error","msg":str(e)}).encode("utf-8"))
            return
        if self.path.startswith("/sensitive_report"):
            try:
                if not current_dir:
                     raise Exception("No project selected")
                
                report_path = os.path.join(current_dir, "sensitive_info_advanced.html")
                # 二次校验路径安全性
                if os.path.isfile(report_path) and report_path.startswith(os.path.abspath(current_dir)):
                    with open(report_path, "rb") as f:
                        buf = f.read()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(buf)
                else:
                    self.send_response(404)
                    self.end_headers()
                    self.wfile.write(b"Sensitive report not found. Please ensure scan is completed.")
            except Exception:
                traceback.print_exc()
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b'{}')
            return
        if self.path.startswith("/api_context_report"):
            try:
                if not current_dir:
                     raise Exception("No project selected")
                
                report_path = os.path.join(current_dir, "manage", "api_context_report.html")
                # 二次校验路径安全性
                if os.path.isfile(report_path) and report_path.startswith(os.path.abspath(current_dir)):
                    with open(report_path, "rb") as f:
                        buf = f.read()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(buf)
                else:
                    self.send_response(404)
                    self.end_headers()
                    self.wfile.write(b"Context report not found. Please ensure scan is completed.")
            except Exception:
                traceback.print_exc()
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b'{}')
            return
        if self.path.startswith("/api/aggregate"):
            try:
                root = self.results_root or (os.path.dirname(self.selected_dir) if self.selected_dir else os.path.join(os.getcwd(),"results"))
                out = []
                for name in sorted(os.listdir(root)):
                    p = os.path.join(root, name)
                    dbp = os.path.join(p, "results.db")
                    if not os.path.isfile(dbp):
                        continue
                    # 不再直接暴露绝对路径，而是暴露目录名作为ID
                    # 使用随机 Token 代替目录名
                    token = self.get_token(p)
                    d = {"id": token, "dir": name} # dir 仅用于显示，id 用于操作
                    try:
                        conn = sqlite3.connect(dbp)
                        cur = conn.cursor()
                        cur.execute("SELECT original_url, domain, port, scan_time FROM meta_target_info LIMIT 1")
                        r = cur.fetchone()
                        if r:
                            d.update({"original_url": r[0], "domain": r[1], "port": r[2], "scan_time": r[3]})
                        cur.execute("SELECT total_api, valid_api, total_requests FROM summary LIMIT 1")
                        s = cur.fetchone()
                        if s:
                            d.update({"total_api": s[0] or 0, "valid_api": s[1] or 0, "total_requests": s[2] or 0})
                        try:
                            cur.execute("SELECT COUNT(1) FROM risk_danger_api_urls")
                            cd = cur.fetchone(); danger = int(cd[0]) if cd else 0
                            cur.execute("SELECT COUNT(1) FROM risk_safe_api_urls")
                            cs = cur.fetchone(); safe = int(cs[0]) if cs else 0
                            d.update({"risk_total": danger + safe})
                        except Exception:
                            d.update({"risk_total": 0})
                        try:
                            cur.execute("SELECT COUNT(1) FROM step8_diff_files")
                            cdf = cur.fetchone(); diffc = int(cdf[0]) if cdf else 0
                            d.update({"diff_files": diffc})
                        except Exception:
                            d.update({"diff_files": 0})
                        sev = {"high":0,"medium":0,"low":0}
                        try:
                            cur.execute("SELECT severity, COUNT(1) FROM step8_sensitive GROUP BY severity")
                            for row in cur.fetchall():
                                k = str(row[0] or "").lower()
                                if k in sev:
                                    sev[k] = sev.get(k,0) + int(row[1] or 0)
                        except Exception:
                            pass
                        d.update({"sensitive": sev})
                    except Exception:
                        pass
                    finally:
                        try:
                            conn.close()
                        except Exception:
                            pass
                    out.append(d)
                data = json.dumps({"targets": out}, ensure_ascii=False).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                self.wfile.write(data)
            except Exception:
                traceback.print_exc()
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b'{}')
            return
        if self.path.startswith("/api/search"):
            try:
                from urllib.parse import urlparse, parse_qs
                qs = parse_qs(urlparse(self.path).query)
                dataset = (qs.get('dataset') or ['response_log'])[0]
                req_id = (qs.get('request_id') or [''])[0]
                url_kw = (qs.get('url') or [''])[0]
                start = (qs.get('start') or [''])[0]
                end = (qs.get('end') or [''])[0]
                method = (qs.get('method') or [''])[0]
                res_code = (qs.get('res_code') or [''])[0]
                res_type = (qs.get('res_type') or [''])[0]
                min_len = (qs.get('min_len') or [''])[0]
                max_len = (qs.get('max_len') or [''])[0]
                sort = (qs.get('sort') or ['timestamp'])[0]
                order = (qs.get('order') or ['desc'])[0]
                page = int((qs.get('page') or ['1'])[0] or '1')
                size = int((qs.get('size') or ['20'])[0] or '20')
                
                if not current_dir:
                    raise Exception("No project selected")

                result = search_rr(current_dir, req_id, url_kw, start, end, method, res_code, res_type, min_len, max_len, sort, order, page, size, dataset)
                data = json.dumps(result, ensure_ascii=False).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                self.wfile.write(data)
            except Exception:
                traceback.print_exc()
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b'{}')
            return
        if self.path.startswith("/aggregate"):
            html = """
<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>ChkApi 聚合总览</title><style>
:root{--bg:#0f172a;--card:#111827;--text:#e5e7eb;--muted:#94a3b8;--accent:#22d3ee;--border:#1f2937}
*{box-sizing:border-box}html,body{height:100%}body{margin:0;background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial}
.hdr{display:flex;align-items:center;justify-content:space-between;padding:12px 16px;border-bottom:1px solid var(--border);background:#0b1220}
.ttl{margin:0;font-size:16px}.muted{color:var(--muted)}.toolbar{display:flex;gap:8px;padding:10px 16px;border-bottom:1px solid var(--border)}
.toolbar input{background:#0d1b2a;color:var(--text);border:1px solid var(--border);border-radius:8px;padding:8px;width:360px}
.btn{background:#0ea5e9;color:white;border:0;border-radius:8px;padding:8px 10px;cursor:pointer}.btn.alt{background:#334155}
.list{padding:16px;display:grid;grid-template-columns:repeat(3,minmax(240px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:12px}
.kv{display:flex;justify-content:space-between;margin:4px 0}.kv .k{color:#cbd5e1}
.row{display:flex;gap:8px;margin-top:8px}
.link{color:#93c5fd;text-decoration:none}
</style></head><body>
<div class="hdr"><h3 class="ttl">ChkApi 聚合总览</h3><div class="muted"><a class="link" href="/">单目标视图</a></div></div>
<div class="toolbar"><input id="q" placeholder="搜索URL/域名/时间"/><button class="btn alt" id="refresh">刷新</button></div>
<div class="list" id="list"></div>
<script>
let data=[];
function render(){
  const q=document.getElementById('q').value.trim().toLowerCase();
  const list=document.getElementById('list'); list.innerHTML='';
  let arr=data;
  if(q){arr=arr.filter(x=>JSON.stringify(x).toLowerCase().includes(q))}
  for(const t of arr){
    const d=document.createElement('div'); d.className='card';
    d.innerHTML = `
      <div class="kv"><div class="k">URL</div><div>${t.original_url||''}</div></div>
      <div class="kv"><div class="k">域名</div><div>${t.domain||''}</div></div>
      <div class="kv"><div class="k">时间</div><div>${t.scan_time||''}</div></div>
      <div class="kv"><div class="k">总请求量</div><div style="color:#0ea5e9;font-weight:bold">${t.total_requests||0}</div></div>
      <div class="kv"><div class="k">总API</div><div>${t.total_api||0}</div></div>
      <div class="kv"><div class="k">有效API</div><div>${t.valid_api||0}</div></div>
      <div class="kv"><div class="k">风险URL</div><div>${t.risk_total||0}</div></div>
      <div class="kv"><div class="k">差异文件</div><div>${t.diff_files||0}</div></div>
      <div class="kv"><div class="k">敏感(高/中/低)</div><div>${(t.sensitive&&t.sensitive.high)||0} / ${(t.sensitive&&t.sensitive.medium)||0} / ${(t.sensitive&&t.sensitive.low)||0}</div></div>
      <div class="row">
        <a class="btn" href="/?id=${encodeURIComponent(t.id||'')}">查看</a>
        <button class="btn" style="background:#ef4444;margin-left:8px" onclick="delDir('${encodeURIComponent(t.id||'').replace(/'/g, "\\'")}')">删除</button>
      </div>
    `;
    list.appendChild(d);
  }
}
function delDir(d){
  if(!confirm('确定要删除该项目结果吗？删除后不可恢复！'))return;
  fetch('/api/delete?id='+d).then(r=>r.json()).then(j=>{
    if(j.status==='ok'){load()}else{alert('删除失败:'+j.msg)}
  })
}
function load(){fetch('/api/aggregate').then(r=>r.json()).then(j=>{data=j.targets||[];render()})}
document.getElementById('q').addEventListener('input',render);
document.getElementById('refresh').addEventListener('click',load);
load();
</script></body></html>
"""
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(html.encode("utf-8"))
            return
        if self.path.startswith("/api/response_file"):
            try:
                from urllib.parse import urlparse, parse_qs
                qs = parse_qs(urlparse(self.path).query)
                p = (qs.get('path') or [''])[0]
                if not p:
                    raise Exception("no path")
                
                # 检查 current_dir 是否有效
                if not current_dir or not os.path.isdir(current_dir):
                    raise Exception("No project selected")

                # 仅允许读取当前 current_dir 下的文件
                p = os.path.abspath(p)
                if not p.startswith(os.path.abspath(current_dir)):
                    raise Exception("forbidden")
                with open(p, "rb") as f:
                    buf = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Disposition", "attachment; filename=%s" % os.path.basename(p))
                self.end_headers()
                self.wfile.write(buf)
            except Exception:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b'')
            return
        if self.path.startswith("/"):
            try:
                from urllib.parse import urlparse, parse_qs
                qs = parse_qs(urlparse(self.path).query)
                req_id = (qs.get('id') or [''])[0]
                if req_id:
                     d = self.get_safe_path(req_id)
                     if d:
                         dbp = os.path.join(d, "results.db")
                         if os.path.isdir(d) and os.path.isfile(dbp):
                             ResultsHandler.selected_dir = d
                # 兼容 dir 参数，但仅作为后备，且不再推荐
                elif (qs.get('dir') or [''])[0]:
                    pass 
            except Exception:
                pass
            html = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>ChkApi 报告视图</title>
<style>
:root{--bg:#0f172a;--card:#111827;--text:#e5e7eb;--muted:#94a3b8;--accent:#22d3ee;--border:#1f2937;--good:#10b981;--bad:#ef4444}
*{box-sizing:border-box}
html,body{height:100%}
body{margin:0;background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial}
.layout{display:flex;height:100%}
.aside{width:280px;border-right:1px solid var(--border);padding:16px 12px;overflow:auto}
.main{flex:1;display:flex;flex-direction:column;min-width:0}
.header{display:flex;align-items:center;justify-content:space-between;padding:12px 16px;border-bottom:1px solid var(--border);background:#0b1220}
.title{font-size:16px;margin:0}
.meta{font-size:12px;color:var(--muted)}
.navgrp{margin-top:12px}
.navgrp>div{font-weight:600;color:#cbd5e1;margin-bottom:6px}
.nav{list-style:none;margin:0;padding:0}
.nav li{margin:2px 0}
.nav a{display:flex;justify-content:space-between;align-items:center;color:#cbd5e1;text-decoration:none;padding:8px;border-radius:8px}
.nav a:hover{background:#0d1b2a}
.badge{min-width:24px;text-align:center;background:#0f766e;color:#d1fae5;border-radius:999px;font-size:12px;padding:2px 8px}
.toolbar{display:flex;gap:8px;padding:10px 16px;border-bottom:1px solid var(--border)}
.toolbar input,.toolbar select{background:#0d1b2a;color:var(--text);border:1px solid var(--border);border-radius:8px;padding:8px;width:320px}
.toolbar .spacer{flex:1}
.btn{background:#0ea5e9;color:white;border:0;border-radius:8px;padding:8px 10px;cursor:pointer}
.btn.alt{background:#334155}
.btn:hover{filter:brightness(1.1)}
.content{padding:16px;overflow:auto}
.cards{display:grid;grid-template-columns:repeat(4,minmax(160px,1fr));gap:12px;margin-bottom:12px}
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:12px}
.card h4{margin:0 0 6px 0;font-size:13px;color:#cbd5e1}
.card .num{font-size:22px;font-weight:700}
.list{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:8px}
.table{width:100%;border-collapse:collapse}
.table th,.table td{border-bottom:1px solid var(--border);padding:8px;text-align:left;font-size:12px;color:#cbd5e1}
.table tr:hover{background:#0d1b2a}
.modal{position:fixed;left:0;top:0;width:100%;height:100%;background:rgba(2,6,23,0.8);display:none;align-items:center;justify-content:center;z-index:9999}
.modal .card{width:min(900px,95%);max-height:85%;overflow:auto}
.modal .titlebar{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}
.json .key{color:#93c5fd}
.json .string{color:#10b981}
.json .number{color:#f59e0b}
.json .bool{color:#f97316}
.json .null{color:#ef4444}
.item{border-bottom:1px dashed var(--border);padding:8px 6px}
.item:last-child{border-bottom:0}
.item .row{display:flex;gap:8px;align-items:center}
.item .tag{font-size:12px;color:#93c5fd;background:#0b3b6f;border:1px solid #1e3a8a;border-radius:6px;padding:2px 6px}
.item pre{margin:8px 0 0 0;background:#0b1220;color:#e5e7eb;white-space:pre-wrap;word-break:break-word;border:1px solid var(--border);border-radius:8px;padding:10px}

.risk-tools{display:none;gap:8px}
.muted{color:var(--muted)}
.loading-overlay{position:fixed;top:0;left:0;width:100%;height:100%;background:var(--bg);display:flex;flex-direction:column;align-items:center;justify-content:center;z-index:10000}
.spinner{width:48px;height:48px;border:4px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin 1s linear infinite;margin-bottom:16px}
@keyframes spin{to{transform:rotate(360deg)}}
</style>
</head>
<body>
<div id="loading" class="loading-overlay">
  <div class="spinner"></div>
  <div style="color:var(--accent);font-weight:600;font-size:18px">正在从数据库加载数据...</div>
  <div class="muted" style="margin-top:8px">数据量较大时可能需要几秒钟</div>
</div>
<div class="layout">
  <aside class="aside">
    <div class="navgrp"><div>概览</div>
      <ul class="nav">
        <li><a href="#" data-sec="overview">总览 <span class="badge" id="count_overview">0</span></a></li>
      </ul>
    </div>
    <div class="navgrp"><div>JS组</div>
      <ul class="nav">
        <li><a href="#" data-sec="step1_all_load_urls">首页自动加载URL <span class="badge" id="count_step1_all_load_urls">0</span></a></li>
        <li><a href="#" data-sec="step1_js_extract">JS提取API_PATH <span class="badge" id="count_step1_js_extract">0</span></a></li>
        <li><a href="#" data-sec="step1_no_js_urls">非JS资源URL <span class="badge" id="count_step1_no_js_urls">0</span></a></li>
        <li><a href="#" data-sec="step2_js_paths">JS路径原始 <span class="badge" id="count_step2_js_paths">0</span></a></li>
        <li><a href="#" data-sec="step2_dynamic_js_paths">动态JS模块 <span class="badge" id="count_step2_dynamic_js_paths">0</span></a></li>
        <li><a href="#" data-sec="step2_alive_static">存活静态资源 <span class="badge" id="count_step2_alive_static">0</span></a></li>
        <li><a href="#" data-sec="step2_alive_js_static">JS与静态资源 <span class="badge" id="count_step2_alive_js_static">0</span></a></li>
        <li><a href="#" data-sec="step2_js_cache">JS缓存 <span class="badge" id="count_step2_js_cache">0</span></a></li>
        <li><a href="#" data-sec="step2_alive_js">存活JS <span class="badge" id="count_step2_alive_js">0</span></a></li>
        <li><a href="#" data-sec="step8_restored_html">JS 静态解包 <span class="badge" id="count_step8_restored_html">0</span></a></li>
      </ul>
    </div>
    <div class="navgrp"><div>API组</div>
      <ul class="nav">
        <li><a href="#" data-sec="step2_base_url">BASE_URL <span class="badge" id="count_step2_base_url">0</span></a></li>
        <li><a href="#" data-sec="step3_api_paths">API路径 <span class="badge" id="count_step3_api_paths">0</span></a></li>
        <li><a href="#" data-sec="step4_api_url">最终API_URL <span class="badge" id="count_step4_api_url">0</span></a></li>
        <li><a href="#" data-sec="step4_path_with_api_urls">路径含API的URL <span class="badge" id="count_step4_path_with_api_urls">0</span></a></li>
        <li><a href="#" data-sec="step4_path_with_api_paths">路径含API的接口 <span class="badge" id="count_step4_path_with_api_paths">0</span></a></li>
        <li><a href="#" data-sec="step4_path_with_no_api_paths">路径不含API的接口 <span class="badge" id="count_step4_path_with_no_api_paths">0</span></a></li>
        <li><a href="#" data-sec="risk">全量接口(分类) <span class="badge" id="count_risk">0</span></a></li>
        <li><a href="#" onclick="const id=new URLSearchParams(window.location.search).get('id');if(id)window.open('/api_context_report?id='+id);else alert('请先选择目标');return false;">接口上下文报告 <span class="badge" style="background:#0ea5e9">NEW</span></a></li>
      </ul>
    </div>
    <div class="navgrp"><div>响应</div>
      <ul class="nav">
        <li><a href="#" data-sec="response_log">全量响应日志 <span class="badge" id="count_response_log">0</span></a></li>
      </ul>
    </div>
    <div class="navgrp"><div>漏洞与风险</div>
      <ul class="nav">
        <li><a href="#" data-sec="step6_vulnerability">漏洞检测 <span class="badge" id="count_step6_vulnerability">0</span></a></li>
        <li><a href="#" data-sec="step6_sensitive_stats">敏感信息统计 <span class="badge" id="count_step6_sensitive_stats">0</span></a></li>
      </ul>
    </div>
    <div class="navgrp"><div>差异文件</div>
      <ul class="nav">
        <li><a href="#" data-sec="step8_diff_files">差异化响应文件 <span class="badge" id="count_step8_diff_files">0</span></a></li>
      </ul>
    </div>

  </aside>
  <div class="main">
    <div class="header">
      <div>
        <h3 class="title" id="title">ChkApi 报告视图</h3>
        <div class="meta" id="subtitle">目标 | 扫描时间</div>
      </div>
      <div style="text-align:right">
        <div class="meta">本地视图 · 127.0.0.1:8088</div>
        <div style="margin-top:4px"><a href="/aggregate" style="color:var(--accent);text-decoration:none;font-size:13px">← 返回大厅</a></div>
      </div>
    </div>
    <div class="toolbar" style="flex-wrap:wrap">
      <input type="text" id="q" placeholder="搜索URL/关键词"/>
      <select id="ruleName" style="display:none"><option value="">全部规则</option></select>
      <select id="sensitiveSeverity" style="display:none"><option value="">全部等级</option><option value="high">高</option><option value="medium">中</option><option value="low">低</option></select>
      
      <!-- <select id="pageSize" style="display:none"><option>20</option><option>50</option><option>100</option></select> -->
      <label class="meta" id="serverPagingWrap" style="display:none"><input type="checkbox" id="serverPaging"/> 后端分页</label>
      <!-- <button class="btn alt" id="prevPage" style="display:none"> < </button> -->
      <!-- <button class="btn alt" id="nextPage" style="display:none"> > </button> -->
      <div class="risk-tools" id="risk_controls">
        <button class="btn alt" id="exportDangerJson">危险JSON</button>
        <button class="btn alt" id="exportDangerUrls">危险URL</button>
        <button class="btn alt" id="exportDangerPaths">危险接口路径</button>
        <button class="btn" id="exportSafeJson">安全JSON</button>
        <button class="btn" id="exportSafeUrls">安全URL</button>
        <button class="btn" id="exportSafePaths">安全接口路径</button>
      </div>
      <button class="btn alt" id="copySection">复制当前分区</button>
      <div class="spacer"></div>
    </div>
    <div class="content">
      <div class="cards" id="cards">
        <div class="card"><h4>总API</h4><div class="num" id="card_total_api">0</div></div>
        <div class="card"><h4>有效API</h4><div class="num" id="card_valid_api">0</div></div>
        <div class="card"><h4>风险URL</h4><div class="num" id="card_risk_total">0</div></div>
        <div class="card"><h4>差异文件</h4><div class="num" id="card_diff_total">0</div></div>
        <div class="card"><h4>敏感高</h4><div class="num" id="card_sensitive_high">0</div></div>
        <div class="card"><h4>敏感中</h4><div class="num" id="card_sensitive_medium">0</div></div>
        <div class="card"><h4>敏感低</h4><div class="num" id="card_sensitive_low">0</div></div>
      </div>
      <div class="list" id="list"></div>
      <div class="muted" style="margin-top:8px">提示：点击左侧分区查看详细列表；支持关键词搜索与规则筛选</div>
    </div>
  </div>
</div>
<script>
let data=null;let currentSec="step4_api_url";
let currentPage=1;
let pageSize=10000;
let serverPaging=false;
let currentByteSort='desc'; // 'asc', 'desc' or ''
let currentMethodSort='asc'; // 'asc', 'desc'
let currentSortField='timestamp'; // Default sort

function setText(id, val){const el=document.getElementById(id); if(el) el.textContent=String(val||0)}
function renderHeader(){
  const ti=data?.target_info||{};
  const url=ti.original_url||'';
  const scan=ti.scan_time||'';
  document.getElementById('title').textContent=(url?url:'ChkApi 报告视图');
  document.getElementById('subtitle').textContent=(url||'')+' | '+(scan||'');
}
function buildRawRequest(reqId) {
    if(!reqId) return "";
    const req = (data?.stage_data?.request_log || []).find(x => x.id === reqId);
    if(!req) return "";
    
    let path = "";
    let host = "";
    try { 
        const url = new URL(req.url);
        path = url.pathname + url.search;
        host = url.host;
    } catch(e) { 
        path = req.url;
    }
    
    let raw = `${req.method} ${path} HTTP/1.1\n`;
    if(host) raw += `Host: ${host}\n`;
    
    let headers = {};
    try { 
        headers = typeof req.headers === 'string' ? JSON.parse(req.headers) : req.headers;
    } catch(e) {}
    
    for (let k in headers) {
        if (k.toLowerCase() === 'host') continue;
        raw += `${k}: ${headers[k]}\n`;
    }
    if (req.cookies) {
        raw += `Cookie: ${req.cookies}\n`;
    }
    raw += `\n`;
    if (req.body) {
        raw += req.body;
    }
    return raw;
}
function openModal(title, txt, reqId, aiReason){
    const reqTxt = buildRawRequest(reqId);
    let modal=document.getElementById('__modal__');
    if(!modal){
      modal=document.createElement('div'); modal.className='modal'; modal.id='__modal__';
      const card=document.createElement('div'); card.className='card';
      const tb=document.createElement('div'); tb.className='titlebar';
      const h=document.createElement('h4'); h.textContent=title||'查看响应';
      const close=document.createElement('button'); close.className='btn'; close.textContent='关闭';
      close.onclick=()=>{modal.style.display='none';}
      tb.appendChild(h); tb.appendChild(close);
      const body = document.createElement('div'); body.id='modal-body';
      card.appendChild(tb); card.appendChild(body);
      modal.appendChild(card);
      document.body.appendChild(modal);
    }
    const body=modal.querySelector('#modal-body');
    body.innerHTML = '';
    
    if(aiReason) {
        const div = document.createElement('div');
        div.style.background = '#064e3b';
        div.style.color = '#d1fae5';
        div.style.padding = '12px';
        div.style.borderRadius = '6px';
        div.style.marginBottom = '12px';
        div.style.border = '1px solid #059669';
        div.innerHTML = '<strong style="color:#34d399">🤖 AI 判定依据:</strong> <span style="white-space:pre-wrap">' + aiReason + '</span>';
        body.appendChild(div);
    }
    
    if(reqTxt) {
        const hReq = document.createElement('div'); hReq.style.fontWeight='bold'; hReq.style.margin='10px 0 5px'; hReq.textContent = 'Request Package:';
        const preReq = document.createElement('pre'); preReq.className='json'; preReq.style.background='#0a1219'; preReq.style.padding='10px'; preReq.style.fontSize='12px';
        preReq.textContent = reqTxt;
        body.appendChild(hReq); body.appendChild(preReq);
        const hRes = document.createElement('div'); hRes.style.fontWeight='bold'; hRes.style.margin='15px 0 5px'; hRes.textContent = 'Response Package:';
        body.appendChild(hRes);
    }

    const pre=document.createElement('pre'); pre.className='json'; pre.style.whiteSpace='pre-wrap';
    try{
      const obj=JSON.parse(txt);
      pre.textContent = JSON.stringify(obj,null,2);
    }catch(e){
      pre.textContent=txt;
    }
    body.appendChild(pre);
    modal.style.display='flex';
}

function renderHtmlModal(title, htmlContent) {
    let modal = document.getElementById('common-modal');
    if(!modal){
      modal=document.createElement('div'); modal.id='common-modal'; modal.className='modal';
      const card=document.createElement('div'); card.className='card';
      const tb=document.createElement('div'); tb.className='titlebar';
      const h=document.createElement('h3'); h.id='modal-title';
      const close=document.createElement('button'); close.className='btn'; close.textContent='关闭';
      close.onclick=()=>{modal.style.display='none';}
      tb.appendChild(h); tb.appendChild(close);
      const body = document.createElement('div'); body.id='modal-body';
      card.appendChild(tb); card.appendChild(body);
      modal.appendChild(card);
      document.body.appendChild(modal);
    }
    const h=modal.querySelector('#modal-title'); h.textContent = "解包内容详情 - " + title;
    const body=modal.querySelector('#modal-body');
    body.innerHTML = '';
    
    // 使用 Iframe 进行内容隔离和正常渲染
    const iframe = document.createElement('iframe');
    iframe.style.width = '100%';
    iframe.style.height = '600px';
    iframe.style.border = '1px solid var(--border)';
    iframe.style.borderRadius = '8px';
    iframe.style.background = '#fff';
    body.appendChild(iframe);
    
    const doc = iframe.contentWindow.document;
    doc.open();
    doc.write(htmlContent);
    doc.close();
    
    modal.style.display='flex';
}
function toggleByteSort(){
    if(currentSortField !== 'length'){
        currentSortField = 'length';
        currentByteSort = 'desc';
    } else {
        if(currentByteSort === 'desc') currentByteSort = 'asc';
        else if(currentByteSort === 'asc') {
             // Reset to default? Or keep toggling? User said "click once desc, again asc". 
             // Let's assume toggling between asc/desc.
             currentByteSort = 'desc';
        }
    }
    renderSection(currentSec);
}
function toggleMethodSort(){
    if(currentSortField !== 'method'){
        currentSortField = 'method';
        currentMethodSort = 'asc';
    } else {
        if(currentMethodSort === 'asc') currentMethodSort = 'desc';
        else currentMethodSort = 'asc';
    }
    renderSection(currentSec);
}
function renderCards(){
  const s=data?.stage_data||{};
  const sum=s.step7_summary||{};
  const risk=s.risk||{};
  setText('card_total_api', sum.total_api||0);
  setText('card_valid_api', sum.valid_api||0);
  setText('card_risk_total', (Array.isArray(risk.danger)?risk.danger.length:0)+(Array.isArray(risk.safe)?risk.safe.length:0));
  setText('card_diff_total', Array.isArray(s.step8_diff_files)?s.step8_diff_files.length:0);
  const sev=s.step6_sensitive_severity_dist||{};
  setText('card_sensitive_high', sev.high||0);
  setText('card_sensitive_medium', sev.medium||0);
  setText('card_sensitive_low', sev.low||0);
}
function renderCounts(){
  const s=data?.stage_data||{};
  const getLen=v=>Array.isArray(v)?v.length:0;
  setText('count_step1_all_load_urls', getLen(s.step1_all_load_urls));
  setText('count_step1_js_extract', getLen(s.step1_js_extract));
  setText('count_step1_no_js_urls', getLen(s.step1_no_js_urls));
  setText('count_step2_js_paths', getLen(s.step2_js_paths));
  setText('count_step2_dynamic_js_paths', getLen(s.step2_dynamic_js_paths));
  setText('count_step2_alive_js', getLen(s.step2_alive_js));
  setText('count_step2_alive_static', getLen(s.step2_alive_static));
  setText('count_step2_alive_js_static', getLen(s.step2_alive_js_static));
  setText('count_step2_js_cache', getLen(s.step2_js_cache));
  setText('count_step2_base_url', getLen(s.step2_base_url));
  setText('count_step3_api_paths', getLen(s.step3_api_paths));
  setText('count_step4_api_url', getLen(s.step4_api_url));
  setText('count_step4_path_with_api_urls', getLen(s.step4_path_with_api_urls));
  setText('count_step4_path_with_api_paths', getLen(s.step4_path_with_api_paths));
  setText('count_step4_path_with_no_api_paths', getLen(s.step4_path_with_no_api_paths));
  setText('count_step5_responses', getLen(s.step5_responses));
  setText('count_step5_xml_json_urls', getLen(s.step5_xml_json_urls));
  setText('count_step5_xml_json_responses', getLen(s.step5_xml_json_responses));
  setText('count_step7_with_param_responses', getLen(s.step7_with_param_responses));
  setText('count_response_log', getLen(s.response_log));
  const vul=s.step6_vulnerability||{};
  setText('count_step6_vulnerability', getLen(vul.diff_response_info)+getLen(vul.hae_api_info)+getLen(vul.sensitive_data_info));
  setText('count_step6_sensitive_stats', getLen(s.step6_sensitive_stats));
  setText('count_step8_diff_files', getLen(s.step8_diff_files));
  setText('count_step8_restored_html', getLen(s.step8_restored_html));
  const risk=s.risk||{};
  setText('count_risk', getLen(risk.danger)+getLen(risk.safe));
  const sum=s.step7_summary||{};
  document.getElementById('count_overview').textContent=String((sum.total_api||0));
}
function sanitizeUrlStr(s){return String(s||'').replace(/[`'"]/g,'').trim()}
function getRiskArrays(){
  const r=(data?.stage_data?.risk)||{danger:[],safe:[]};
  return {danger:(r.danger||[]).map(sanitizeUrlStr).filter(Boolean),safe:(r.safe||[]).map(sanitizeUrlStr).filter(Boolean)}
}
function urlsToPaths(arr){
  const out=[];
  for(const u of arr){
    try{const x=new URL(u); out.push(x.pathname||'/')}
    catch(e){
      const i=u.indexOf('://');
      if(i>-1){const rest=u.substring(i+3);const j=rest.indexOf('/');out.push(j>-1?rest.substring(j):'/')}
      else{out.push(u)}
    }
  }
  return out
}
function renderListItems(sec){
  const list=document.getElementById('list'); list.innerHTML='';
  const s=data?.stage_data||{};
  let value=s[sec];
  document.getElementById('risk_controls').style.display = (sec==='risk' ? 'flex' : 'none');
  const ruleSel=document.getElementById('ruleName');
  const sevSel=document.getElementById('sensitiveSeverity');
  // const mSel=document.getElementById('respMethod');
  // const cInp=document.getElementById('respCode');
  // const tInp=document.getElementById('respType');
  // const minLenInp=document.getElementById('minLen');
  // const maxLenInp=document.getElementById('maxLen');
  // const sortSel=document.getElementById('sortBy');
  // const orderSel=document.getElementById('sortOrder');
  // const psSel=document.getElementById('pageSize');
  // const prevBtn=document.getElementById('prevPage');
  // const nextBtn=document.getElementById('nextPage');
  const spWrap=document.getElementById('serverPagingWrap');
  const sp=document.getElementById('serverPaging');
  
  // Reset displays
  // [mSel,cInp,tInp,minLenInp,maxLenInp,sortSel,orderSel,psSel,prevBtn,nextBtn,spWrap].forEach(e=>e.style.display='none');
  // [psSel,prevBtn,nextBtn,spWrap].forEach(e=>e.style.display='none');
  if(spWrap) spWrap.style.display='none';

  if(sec==='step6_vulnerability'){
    ruleSel.style.display='block';
    const vul=value||{};
    const names=[];
    for(const x of (vul.hae_api_info||[])){if(x&&x.name){names.push(String(x.name))}}
    for(const x of (vul.sensitive_data_info||[])){if(x&&x.name){names.push(String(x.name))}}
    const uniq=Array.from(new Set(names)).sort();
    const current=ruleSel.value;
    const opts=[''].concat(uniq);
    const hash=JSON.stringify(opts);
    if(ruleSel._optsHash!==hash){
      ruleSel.innerHTML='<option value="">全部规则</option><option value="[AI确认]" style="color:#10b981;font-weight:bold">★ 仅显示 AI 确认</option>'+uniq.map(n=>'<option value="'+n+'">'+n+'</option>').join('');
      ruleSel._optsHash=hash;
      if(uniq.indexOf(current)>=0){ruleSel.value=current}else{ruleSel.value=''}
    }
    sevSel.style.display='none'; sevSel.value='';
  }else{
    ruleSel.style.display='none';
    ruleSel.value='';
    if(sec==='step6_sensitive_stats'){sevSel.style.display='block'}else{sevSel.style.display='none'; sevSel.value=''}
    if(sec==='response_log'){
      const tip=document.createElement('div'); tip.className='muted'; tip.style.marginBottom='10px'; tip.textContent='响应日志记录了所有请求的详细信息，包括URL、方法、状态码、类型及响应内容等。';
      list.appendChild(tip);
      // [mSel,cInp,tInp,minLenInp,maxLenInp,sortSel,orderSel,psSel,prevBtn,nextBtn,spWrap].forEach(e=>e.style.display='inline-block');
      // [psSel,prevBtn,nextBtn,spWrap].forEach(e=>e.style.display='inline-block');
      if(spWrap) spWrap.style.display='inline-block';
      // mSel.style.display='block';
    }
  }
  const q=document.getElementById('q').value.trim().toLowerCase();
  const pushItem=(label, obj)=>{
    const div=document.createElement('div'); div.className='item';
    const row=document.createElement('div'); row.className='row';
    const tag=document.createElement('span'); tag.className='tag'; tag.textContent=label;
    row.appendChild(tag); div.appendChild(row);
    const pre=document.createElement('pre'); pre.textContent=typeof obj==='string'?obj:JSON.stringify(obj,null,2); div.appendChild(pre);
    list.appendChild(div);
  };
  if(sec==='overview'){
    const ti=data?.target_info||{};
    const stats=data?.stage_data?.stats_execution||[];
    
    // 基础卡片
    let duration = '';
    if (ti.scan_time && ti.end_time) {
        const start = new Date(ti.scan_time.replace(/-/g, '/')).getTime();
        const end = new Date(ti.end_time.replace(/-/g, '/')).getTime();
        if (!isNaN(start) && !isNaN(end)) {
            const diff = end - start;
            if (diff >= 0) {
                const h = Math.floor(diff / 3600000);
                const m = Math.floor((diff % 3600000) / 60000);
                const s = Math.floor((diff % 60000) / 1000);
                duration = `${h}h ${m}m ${s}s`;
            }
        }
    }

    // 目标基本信息可视化
    const targetInfoDiv = document.createElement('div');
    targetInfoDiv.className = 'item';
    targetInfoDiv.innerHTML = `
        <div class="row"><span class="tag">目标基本信息</span></div>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-top: 12px;">
            <div style="background:var(--card); padding:12px; border-radius:8px; border:1px solid var(--border)">
                <div style="color:var(--muted); font-size:12px; margin-bottom:4px">原始 URL</div>
                <div style="font-weight:500; word-break:break-all">${ti.original_url || '-'}</div>
            </div>
            <div style="background:var(--card); padding:12px; border-radius:8px; border:1px solid var(--border)">
                <div style="color:var(--muted); font-size:12px; margin-bottom:4px">主域名</div>
                <div style="font-weight:500">${ti.domain || '-'}</div>
            </div>
            <div style="background:var(--card); padding:12px; border-radius:8px; border:1px solid var(--border)">
                <div style="color:var(--muted); font-size:12px; margin-bottom:4px">端口</div>
                <div style="font-weight:500">${ti.port || '-'}</div>
            </div>
            <div style="background:var(--card); padding:12px; border-radius:8px; border:1px solid var(--border)">
                <div style="color:var(--muted); font-size:12px; margin-bottom:4px">开始时间</div>
                <div style="font-weight:500">${ti.scan_time || '-'}</div>
            </div>
            <div style="background:var(--card); padding:12px; border-radius:8px; border:1px solid var(--border)">
                <div style="color:var(--muted); font-size:12px; margin-bottom:4px">结束时间</div>
                <div style="font-weight:500">${ti.end_time || '-'}</div>
            </div>
            <div style="background:var(--card); padding:12px; border-radius:8px; border:1px solid var(--border)">
                <div style="color:var(--muted); font-size:12px; margin-bottom:4px">耗时</div>
                <div style="font-weight:500; color:#10b981">${duration || '-'}</div>
            </div>
        </div>
    `;
    list.appendChild(targetInfoDiv);
    
    // 执行统计可视化
    const statsDiv = document.createElement('div');
    statsDiv.className = 'item';
    
    // 补全所有步骤，确保即使没有记录也显示为0
    const expectedSteps = [
        "Step 1: 首页加载探测",
        "Step 2: JS与资源采集",
        "Step 3: 接口提取",
        "Step 4: API URL 探测",
        "Step 5: 无参接口扫描"
    ];
    
    // 将现有的 stats 转为 Map 方便查找
    const statsMap = new Map();
    if (stats && Array.isArray(stats)) {
        stats.forEach(s => {
            if (s && s.length >= 2) {
                statsMap.set(s[0], s[1]);
            }
        });
    }
    
    // 构建完整的 stats 列表
    const fullStats = expectedSteps.map(stepName => {
        return [stepName, statsMap.get(stepName) || 0];
    });
    
    // 如果有额外的步骤（不在预期列表中），也添加进来
    statsMap.forEach((count, name) => {
        if (!expectedSteps.includes(name)) {
            fullStats.push([name, count]);
        }
    });

    let totalReqs = 0;
    fullStats.forEach(s => totalReqs += s[1]);
    
    let statsHtml = `
        <div class="row"><span class="tag">执行性能与请求分布</span></div>
        <div style="padding:16px; background:var(--card); border-radius:12px; margin-top:12px; border:1px solid var(--border)">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px">
                <div>
                   <div style="color:var(--muted); font-size:12px">累计发送 HTTP 请求</div>
                   <div style="font-size:28px; font-weight:bold; color:#38bdf8">${totalReqs}</div>
                </div>
                <div style="text-align:right">
                   <div style="color:var(--muted); font-size:12px">发现 API 总数</div>
                   <div style="font-size:28px; font-weight:bold; color:#10b981">${data?.stage_data?.step7_summary?.total_api||0}</div>
                </div>
            </div>
            <div style="margin-top:10px">
                <table class="table" style="background:transparent; margin:0">
                    <thead><tr><th style="padding-left:0">探测阶段</th><th style="text-align:right">请求次数</th><th style="width:160px">占比</th></tr></thead>
                    <tbody>`;
    
    fullStats.forEach(s => {
        const percent = totalReqs > 0 ? (s[1]/totalReqs*100).toFixed(1) : 0;
        statsHtml += `
            <tr>
                <td style="padding-left:0">${s[0]}</td>
                <td style="text-align:right; font-weight:bold">${s[1]}</td>
                <td>
                    <div style="width:100%; height:8px; background:#1e293b; border-radius:4px; overflow:hidden; display:flex">
                        <div style="width:${percent}%; height:100%; background:linear-gradient(90deg, #0ea5e9, #38bdf8)"></div>
                    </div>
                </td>
            </tr>`;
    });
    
    statsHtml += `</tbody></table></div></div>`;
    statsDiv.innerHTML = statsHtml;
    list.appendChild(statsDiv);
    return;
  }
  // openModal moved to global scope
  if(sec==='response_log'){
    // pageSize = parseInt(psSel.value||'20')||20;
    pageSize = 10000;
    const getVal=(id, defVal='')=>{const el=document.getElementById(id); return el?el.value:defVal};
    const m=getVal('respMethod',''); 
    const code=(getVal('respCode','').trim());
    const typ=(getVal('respType','').trim().toLowerCase());
    const minL=parseInt(getVal('minLen','')); 
    const maxL=parseInt(getVal('maxLen',''));
    let sSort = currentSortField;
    let sOrder = currentByteSort;
    if(sSort === 'method') sOrder = currentMethodSort;
    
    serverPaging = !!sp.checked;
    let total=0, pages=1, pageArr=[];
    if(serverPaging){
      const qs=new URLSearchParams({
        method:m,res_code:code,res_type:typ,
        min_len:isNaN(minL)?'':minL, max_len:isNaN(maxL)?'':maxL,
        sort:sSort,order:sOrder,page:currentPage,size:pageSize
      });
      fetch('/api/search?'+qs.toString()).then(r=>r.json()).then(j=>{
        const resp=j.response||[];
        total=j.total||resp.length;
        pages=Math.max(1, Math.ceil(total/pageSize));
        const table=document.createElement('table'); table.className='table';
        let byteLabel = '字节数';
        if(currentSortField === 'length'){
            byteLabel += (currentByteSort==='asc' ? ' ↑' : ' ↓');
        }
        table.innerHTML = `<thead><tr><th>URL</th><th>方法</th><th>状态码</th><th>类型</th><th>时间</th><th style="cursor:pointer;user-select:none" onclick="toggleByteSort()">${byteLabel}</th><th>操作</th></tr></thead><tbody></tbody>`;
        const tbody=table.querySelector('tbody');
        resp.forEach(r=>{
          if (!r.hasOwnProperty('response')) {
              console.warn('response字段缺失:', r);
              r.response = '';
          }
          const tr=document.createElement('tr');
          const fp=r.file_path||'';
          const rawTxt=r.response||'';
          const bytes = (typeof r.bytes==='number') ? r.bytes : (new TextEncoder().encode(rawTxt)).length;
          tr.innerHTML=`<td>${r.url||''}</td><td>${r.method||''}</td><td>${r.res_code||''}</td><td>${r.res_type||''}</td><td>${r.timestamp||''}</td><td>${bytes}</td><td><div style="display:flex;gap:4px"><button class="btn alt" style="font-size:12px" data-txt="${encodeURIComponent(rawTxt)}" data-rid="${r.id||''}">查看详情</button> ${fp?'<a class="btn" style="background:#0ea5e9;text-decoration:none;font-size:12px" href="/api/response_file?path='+encodeURIComponent(fp)+'" download>下载</a>':''}</div></td>`;
          const btn=tr.querySelector('button[data-txt]');
          btn.addEventListener('click',()=>{openModal('响应详情', decodeURIComponent(btn.getAttribute('data-txt')||''), btn.getAttribute('data-rid'))});
          tbody.appendChild(tr);
        });
        list.appendChild(table);
        const pag=document.createElement('div'); pag.className='muted'; pag.textContent=`第 ${j.page||currentPage}/${Math.max(1, Math.ceil(total/pageSize))} 页，共 ${total} 条`;
        list.appendChild(pag);
      });
      // prevBtn.onclick=()=>{ if(currentPage>1){currentPage--; renderSection('response_log')} };
      // nextBtn.onclick=()=>{ currentPage++; renderSection('response_log') };
      return;
    }
    let arr=Array.isArray(value)?value:[];
    arr=arr.filter(x=>{
      if(m && String(x.method||'')!==m) return false;
      if(code && String(x.res_code||'')!==code) return false;
      if(typ && String(x.res_type||'').toLowerCase().indexOf(typ)<0) return false;
      if(!isNaN(minL)){
         const b = (typeof x.bytes==='number') ? x.bytes : (new TextEncoder().encode(x.response||'')).length;
         if(b < minL) return false;
      }
      if(!isNaN(maxL)){
         const b = (typeof x.bytes==='number') ? x.bytes : (new TextEncoder().encode(x.response||'')).length;
         if(b > maxL) return false;
      }
      return true;
    });
    
    // Sort
    // Pre-calc bytes
    arr.forEach(x=>{if(typeof x.bytes!=='number') x.bytes=(new TextEncoder().encode(x.response||'')).length});

    arr.sort((a,b)=>{
        let va, vb;
        if(sSort==='length'){
            va=a.bytes; vb=b.bytes;
        }else if(sSort==='res_code'){
            va=parseInt(a.res_code||0); vb=parseInt(b.res_code||0);
        }else if(sSort==='method'){
            va=String(a.method||''); vb=String(b.method||'');
        }else if(sSort==='res_type'){
            va=String(a.res_type||''); vb=String(b.res_type||'');
        }else{
            va=String(a.timestamp||''); vb=String(b.timestamp||'');
        }
        if(va<vb) return sOrder==='asc'?-1:1;
        if(va>vb) return sOrder==='asc'?1:-1;
        return 0;
    });

    total=arr.length;
    pages=Math.max(1, Math.ceil(total/pageSize));
    currentPage=Math.min(currentPage, pages);
    const start=(currentPage-1)*pageSize, end=start+pageSize;
    pageArr=arr.slice(start,end);
    const table=document.createElement('table'); table.className='table';
    let byteLabel = '字节数';
    if(currentSortField === 'length'){
        byteLabel += (currentByteSort==='asc' ? ' ↑' : ' ↓');
    }
    table.innerHTML = `<thead><tr><th>URL</th><th>方法</th><th>状态码</th><th>类型</th><th>时间</th><th style="cursor:pointer;user-select:none" onclick="toggleByteSort()">${byteLabel}</th><th>操作</th></tr></thead><tbody></tbody>`;
    const tbody=table.querySelector('tbody');
    pageArr.forEach(r=>{
      if (!r.hasOwnProperty('response')) {
          console.warn('response字段缺失:', r);
          r.response = '';
      }
      const tr=document.createElement('tr');
      const fp=r.file_path||'';
      const rawTxt = r.response||'';
      const bytes = (typeof r.bytes==='number') ? r.bytes : (new TextEncoder().encode(rawTxt)).length;
      tr.innerHTML=`<td>${r.url||''}</td><td>${r.method||''}</td><td>${r.res_code||''}</td><td>${r.res_type||''}</td><td>${r.timestamp||''}</td><td>${bytes}</td><td><div style="display:flex;gap:4px"><button class="btn alt" style="font-size:12px" data-txt="${encodeURIComponent(rawTxt)}" data-rid="${r.id||''}">查看</button> ${fp?'<a class="btn" style="background:#0ea5e9;text-decoration:none;font-size:12px" href="/api/response_file?path='+encodeURIComponent(fp)+'" download>下载</a>':''}</div></td>`;
      const btn=tr.querySelector('button[data-txt]');
      btn.addEventListener('click',()=>{openModal('记录详情', decodeURIComponent(btn.getAttribute('data-txt')||''), btn.getAttribute('data-rid'))});
      tbody.appendChild(tr);
    });
    list.appendChild(table);
    const pag=document.createElement('div'); pag.className='muted'; pag.textContent=`第 ${currentPage}/${pages} 页，共 ${total} 条`;
    list.appendChild(pag);
    // prevBtn.onclick=()=>{ if(currentPage>1){currentPage--; renderListItems('response_log')} };
    // nextBtn.onclick=()=>{ if(currentPage<pages){currentPage++; renderListItems('response_log')} };
    return;
  }
  const renderRespTable=(arr, cols, dataset)=>{
    // pageSize = parseInt(document.getElementById('pageSize').value||'20')||20;
    pageSize = 10000;
    // const prevBtn=document.getElementById('prevPage');
    // const nextBtn=document.getElementById('nextPage');
    
    // Controls (Removed)
    
    // [prevBtn,nextBtn].forEach(e=>e.style.display='inline-block');
    // document.getElementById('pageSize').style.display='inline-block';

    const sp=document.getElementById('serverPaging');
    const serverPaging = !!sp.checked;
    
    // Determine sort field and order
    let sSort = currentSortField;
    let sOrder = currentByteSort;
    if(sSort === 'method') sOrder = currentMethodSort;
    
    let total=arr.length, pages=Math.max(1, Math.ceil(total/pageSize)), pageArr=arr;
    if(serverPaging){
      const mapSec = {step5_responses:'step5', step5_xml_json_responses:'step5_xml_json', step7_with_param_responses:'step7'};
      
      const qs=new URLSearchParams({
          dataset:mapSec[dataset]||'step5', 
          method:'', res_code:'', res_type:'',
          min_len:'', max_len:'',
          sort:sSort, order:sOrder, page:currentPage, size:pageSize
      });
      fetch('/api/search?'+qs.toString()).then(r=>r.json()).then(j=>{
        total=j.total||0; pages=j.pages||Math.max(1, Math.ceil((j.total||0)/pageSize)); pageArr=j.response||[];
        draw(pageArr, total, pages);
      });
    }else{
      // Client filtering/sorting
      let tmp = arr.slice();
      // Pre-calculate bytes to optimize sort
      tmp.forEach(x=>{
          if(typeof x.bytes!=='number'){
              x.bytes=(new TextEncoder().encode(x.response||'')).length;
          }
      });
      
      tmp.sort((a,b)=>{
        let va, vb;
        if(sSort==='length'){
            va=a.bytes; vb=b.bytes;
        }else if(sSort==='res_code'){
            va=parseInt(a.status_code||a.res_code||0); vb=parseInt(b.status_code||b.res_code||0);
        }else if(sSort==='method'){
            va=String(a.method||''); vb=String(b.method||'');
        }else if(sSort==='res_type'){
            va=String(a.response_type||a.res_type||''); vb=String(b.response_type||b.res_type||'');
        }else{
            va=String(a.timestamp||''); vb=String(b.timestamp||'');
        }
        if(va<vb) return sOrder==='asc'?-1:1;
        if(va>vb) return sOrder==='asc'?1:-1;
        return 0;
    });
      
      total=tmp.length;
      pages=Math.max(1, Math.ceil(total/pageSize));
      currentPage=Math.min(currentPage, pages);
      const start=(currentPage-1)*pageSize, end=start+pageSize;
      pageArr=tmp.slice(start,end);
      draw(pageArr, total, pages);
    }
    function draw(pageArr, total, pages){
    const table=document.createElement('table'); table.className='table';
    const colsNoOp = (Array.isArray(cols)?cols:[]).filter(c=>c!=='操作');
    
    // Build Headers
    let theadHtml = '<thead><tr>';
    colsNoOp.forEach(c=>{
        if(c==='方法'){
            let methodLabel = '方法';
            if(currentSortField === 'method'){
                methodLabel += (currentMethodSort==='asc' ? ' ↑' : ' ↓');
            }
            theadHtml += `<th style="cursor:pointer;user-select:none" onclick="toggleMethodSort()">${methodLabel}</th>`;
        } else {
            theadHtml += `<th>${c}</th>`;
        }
    });
    
    let byteLabel = '字节数';
    if(currentSortField === 'length'){
        byteLabel += (currentByteSort==='asc' ? ' ↑' : ' ↓');
    }
    theadHtml += `<th style="cursor:pointer;user-select:none" onclick="toggleByteSort()">${byteLabel}</th><th>操作</th></tr></thead>`;
    
    table.innerHTML=theadHtml + '<tbody></tbody>';
    const tbody=table.querySelector('tbody');
    pageArr.forEach(r=>{
      const url=r.url||''; const method=(r.method||''); const code=(r.status_code||r.res_code||''); const typ=(r.response_type||r.res_type||''); const resp=r.response||'';
      const bytes=(typeof r.bytes==='number')?r.bytes:(new TextEncoder().encode(resp)).length;
      const param = r.parameter || r.body || '';
      const paramDisplay = (param.length > 50) ? (param.substring(0, 50) + '...') : param;
      const paramTitle = param.replace(/"/g, '&quot;');

      const tr=document.createElement('tr');
      let rowHtml = `<td>${url}</td><td>${method}</td><td>${code}</td><td>${typ}</td>`;
      if(cols.includes('参数')){
          rowHtml += `<td title="${paramTitle}" style="max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;cursor:help">${paramDisplay}</td>`;
      }
      rowHtml += `<td>${bytes}</td><td><button class="btn alt" data-txt="${encodeURIComponent(resp)}" data-rid="${r.request_id||r.id||''}">查看详情</button> <button class="btn" data-dl="${encodeURIComponent(resp)}">下载</button></td>`;
      tr.innerHTML=rowHtml;
      tr.querySelector('button[data-txt]').onclick=()=>openModal('有参响应详情', decodeURIComponent(tr.querySelector('button[data-txt]').getAttribute('data-txt')||''), tr.querySelector('button[data-txt]').getAttribute('data-rid'));
      tr.querySelector('button[data-dl]').onclick=()=>{
        const txt=decodeURIComponent(tr.querySelector('button[data-dl]').getAttribute('data-dl')||'');
        const blob=new Blob([txt],{type:'text/plain'}); const a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download='response.txt'; a.click();
      };
      tbody.appendChild(tr);
    });
    list.appendChild(table);
    const pag=document.createElement('div'); pag.className='muted'; pag.textContent=`第 ${currentPage}/${pages} 页，共 ${total} 条`;
    list.appendChild(pag);
    // prevBtn.onclick=()=>{ if(currentPage>1){currentPage--; renderSection(currentSec)} };
    // nextBtn.onclick=()=>{ if(currentPage<pages){currentPage++; renderSection(currentSec)} };
    }
  };
  if(Array.isArray(value)){
    let arr=value;
    if(sec==='step5_responses'){
        arr=arr.filter(x=>String(x.res_type||x.response_type||'').toLowerCase().includes('application/json'));
    }
    if(q){arr=arr.filter(x=>JSON.stringify(x).toLowerCase().includes(q))}
    if(sec==='step6_sensitive_stats'){
      const sev=sevSel.value;
      if(sev){arr=arr.filter(x=>String(x.severity||'').toLowerCase()===sev)}
    }
    if(sec==='step5_responses' || sec==='step5_xml_json_responses' || sec==='step7_with_param_responses'){
      if(sec==='step5_responses'){
         const tip=document.createElement('div'); tip.className='muted'; tip.style.marginBottom='10px'; tip.textContent='无参响应目前仅显示响应类型为application/json:';
         list.appendChild(tip);
      }
      if(sec==='step7_with_param_responses'){
         const tip=document.createElement('div'); tip.className='muted'; tip.style.marginBottom='10px'; tip.textContent='有参响应区块显示了带有参数的API请求及其响应结果。';
         list.appendChild(tip);
      }
      if(sec==='step5_xml_json_responses'){
         const tip=document.createElement('div'); tip.className='muted'; tip.style.marginBottom='10px'; tip.textContent='XML/JSON的响应区块显示了响应类型为XML或JSON的API接口的详细响应内容。';
         list.appendChild(tip);
      }
      document.getElementById('serverPagingWrap').style.display='inline-block';
      const cols = ['URL','方法','状态码','类型'];
      if(sec==='step7_with_param_responses') cols.push('参数');
      cols.push('操作');
      renderRespTable(arr, cols, sec);
    }else{
      if(sec==='step5_xml_json_urls'){
          const tip=document.createElement('div'); tip.className='muted'; tip.style.marginBottom='10px'; tip.textContent='XML/JSON的URL区块显示了响应类型为XML或JSON的API接口地址。';
          list.appendChild(tip);
      }
      if(sec==='step1_all_load_urls'){
          const tip=document.createElement('div'); tip.className='muted'; tip.style.marginBottom='10px'; tip.textContent='首页自动加载URL显示了访问目标首页时自动触发加载的所有URL资源。';
          list.appendChild(tip);
      }
      if(sec==='step1_js_extract'){
          const tip=document.createElement('div'); tip.className='muted'; tip.style.marginBottom='10px'; tip.textContent='JS提取API_PATH显示了从首页加载的JS文件中提取出的潜在API路径。';
          list.appendChild(tip);
      }
      if(sec==='step1_no_js_urls'){
          const tip=document.createElement('div'); tip.className='muted'; tip.style.marginBottom='10px'; tip.textContent='非JS资源URL显示了首页加载的非JavaScript类型的资源URL（如图片、CSS等）。';
          list.appendChild(tip);
      }
      if(sec==='step2_js_paths'){
          const tip=document.createElement('div'); tip.className='muted'; tip.style.marginBottom='10px'; tip.textContent='JS路径原始显示了从JS文件中提取的原始路径信息，未经过滤处理。';
          list.appendChild(tip);
      }
      if(sec==='step2_dynamic_js_paths'){
          const tip=document.createElement('div'); tip.className='muted'; tip.style.marginBottom='10px'; tip.textContent='动态JS模块显示了通过动态导入（dynamic import）方式加载的JS模块路径。';
          list.appendChild(tip);
      }
      if(sec==='step2_alive_js'){
          const tip=document.createElement('div'); tip.className='muted'; tip.style.marginBottom='10px'; tip.textContent='存活JS显示了经检测状态码为200且内容不为空的有效JS文件URL。';
          list.appendChild(tip);
      }
      if(sec==='step2_alive_static'){
          const tip=document.createElement('div'); tip.className='muted'; tip.style.marginBottom='10px'; tip.textContent='存活静态资源显示了经检测有效的静态资源URL（如CSS、图片等）。';
          list.appendChild(tip);
      }
      if(sec==='step2_alive_js_static'){
          const tip=document.createElement('div'); tip.className='muted'; tip.style.marginBottom='10px'; tip.textContent='JS与静态资源显示了存活的JS文件和静态资源的合集。';
          list.appendChild(tip);
      }
      if(sec==='step2_js_cache'){
          const tip=document.createElement('div'); tip.className='muted'; tip.style.marginBottom='10px'; tip.textContent='JS缓存显示了已缓存的JS文件信息，避免重复请求。';
          list.appendChild(tip);
      }
      if(sec==='step8_restored_html'){
          const tip=document.createElement('div'); tip.className='muted'; tip.style.marginBottom='10px'; tip.textContent='JS静态解包识别并提取了被封装在 JS 文件中的 HTML 页面（常见于 Vite/VitePress/Webpack 等打包工具生成的资源）。';
          list.appendChild(tip);
          
          if(arr.length === 0){
              list.innerHTML += '<div style="padding:20px; color:var(--muted)">未发现可解包的 JS 页面资源</div>';
              return;
          }
          const table = document.createElement('table'); table.className='table';
          table.innerHTML = '<thead><tr><th>源 JS URL</th><th>还原文件名</th><th>操作</th></tr></thead><tbody></tbody>';
          const tbody = table.querySelector('tbody');
          arr.forEach(item => {
              const tr = document.createElement('tr');
              tr.innerHTML = `<td><a href="${item.url}" target="_blank" style="color:var(--accent)">${item.url}</a></td><td>${item.filename}</td><td><button class="btn" style="font-size:12px">查看解包内容</button></td>`;
              tr.querySelector('button').onclick = () => renderHtmlModal(item.filename, item.content);
              tbody.appendChild(tr);
          });
          list.appendChild(table);
          return;
      }
      // arr.forEach(x=>pushItem(sec, x));
      pushItem(sec, arr);
    }
  }else{
    let obj=value||{};
    if(sec==='step6_vulnerability'){
      const ruleSel=document.getElementById('ruleName');
      ruleSel.style.display='inline-block';
      const diff=(obj.diff_response_info||[]);
      const hae=(obj.hae_api_info||[]);
      const sen=(obj.sensitive_data_info||[]);
      
      // 动态填充规则列表
      if(ruleSel.options.length <= 1){
          const allNames = [...new Set([...hae.map(x=>x.name), ...sen.map(x=>x.name)])].sort();
          
          // Add AI Filter Option
          const aiOpt = document.createElement('option');
          aiOpt.value = '[AI确认]'; aiOpt.textContent = '★ 仅显示 AI 确认';
          aiOpt.style.color = '#10b981';
          aiOpt.style.fontWeight = 'bold';
          ruleSel.appendChild(aiOpt);
          
          allNames.forEach(n => {
              const opt = document.createElement('option');
              opt.value = n; opt.textContent = n;
              ruleSel.appendChild(opt);
          });
      }

      const sel=ruleSel.value;
      const filterArr=(arr)=>{
        let a=arr;
        if(sel){
            if(sel === '[AI确认]'){
                a = a.filter(x => x.ai_is_sensitive === 1 || x.ai_is_sensitive === true);
            } else {
                a=a.filter(x=>String(x.name||'')===sel);
            }
        }
        if(q){a=a.filter(x=>JSON.stringify(x).toLowerCase().includes(q))}
        return a;
      };

      // 渲染敏感信息
      const senFil = filterArr(sen);
      if(senFil.length > 0){
        const h4 = document.createElement('h4');
        h4.innerHTML = `敏感信息检测结果 <a href="/sensitive_report" target="_blank" class="btn" style="padding:4px 8px;font-size:12px;margin-left:10px;text-decoration:none">查看增强版网页报告</a>`;
        list.appendChild(h4);
        const table = document.createElement('table'); table.className='table';
        table.innerHTML = '<thead><tr><th>规则名称</th><th>命中内容</th><th>等级</th><th>URL/文件</th><th>操作</th></tr></thead><tbody></tbody>';
        const tbody = table.querySelector('tbody');
        senFil.forEach(item => {
          const tr = document.createElement('tr');
          const sev = item.severity || 'medium';
          const sevColor = sev === 'high' ? '#ef4444' : (sev === 'medium' ? '#f59e0b' : '#10b981');
          const sourceUrl = item.url || '';
          const aiTag = (item.ai_is_sensitive===1 || item.ai_is_sensitive===true) ? '<span title="AI已确认" style="color:#10b981;margin-left:4px;cursor:help">★</span>' : '';
          tr.innerHTML = `<td>${item.name}${aiTag}</td><td><code style="background:#0d1b2a;padding:2px 4px">${item.matches}</code></td><td><span class="badge" style="background:${sevColor}">${sev}</span></td><td title="${sourceUrl}"><a href="${sourceUrl||'#'}" target="_blank" style="color:var(--accent);text-decoration:none">${sourceUrl||'文件扫描'}</a></td><td><button class="btn alt" style="font-size:12px">证据</button></td>`;
          tr.querySelector('button').onclick = () => openModal('证据查看', item.evidence || '', null, (item.ai_is_sensitive===1||item.ai_is_sensitive===true)?item.ai_reason:'');
          tbody.appendChild(tr);
        });
        list.appendChild(table);
      }

      // 渲染 HAE
      const haeFil = filterArr(hae);
      if(haeFil.length > 0){
        const h4 = document.createElement('h4'); h4.textContent = 'HAE 检测结果';
        list.appendChild(h4);
        const table = document.createElement('table'); table.className='table';
        table.innerHTML = '<thead><tr><th>插件名称</th><th>命中内容</th><th>URL/文件</th></tr></thead><tbody></tbody>';
        const tbody = table.querySelector('tbody');
        haeFil.forEach(item => {
          const tr = document.createElement('tr');
          const sourceUrl = item.url || '';
          tr.innerHTML = `<td>${item.name}</td><td>${item.matches}</td><td title="${sourceUrl}"><a href="${sourceUrl||'#'}" target="_blank" style="color:var(--accent);text-decoration:none">${sourceUrl||'文件扫描'}</a></td>`;
          tbody.appendChild(tr);
        });
        list.appendChild(table);
      }

      // 渲染 Diff
      const diffFil = q ? diff.filter(x=>JSON.stringify(x).toLowerCase().includes(q)) : diff;
      if(diffFil.length > 0){
        const h4 = document.createElement('h4'); h4.textContent = '响应包差异记录';
        list.appendChild(h4);
        const table = document.createElement('table'); table.className='table';
        table.innerHTML = '<thead><tr><th>Hash</th><th>长度</th><th>大小</th><th>URL</th></tr></thead><tbody></tbody>';
        const tbody = table.querySelector('tbody');
        diffFil.forEach(item => {
          const tr = document.createElement('tr');
          tr.innerHTML = `<td>${item.content_hash}</td><td>${item.length}</td><td>${item.size}</td><td><a href="${item.url}" target="_blank" style="color:var(--accent);text-decoration:none">${item.url}</a></td>`;
          tbody.appendChild(tr);
        });
        list.appendChild(table);
      }
      
      if(senFil.length===0 && haeFil.length===0 && diffFil.length===0){
        list.innerHTML = '<div class="muted">未找到匹配的漏洞或风险记录</div>';
      }
    }else if(sec==='risk'){
      const danger = obj.danger || [];
      const safe = obj.safe || [];
      
      if(danger.length > 0){
        const h4 = document.createElement('h4'); h4.textContent = '危险 API 接口'; h4.style.color = '#ef4444';
        list.appendChild(h4);
        const table = document.createElement('table'); table.className='table';
        table.innerHTML = '<thead><tr><th>URL</th></tr></thead><tbody></tbody>';
        const tbody = table.querySelector('tbody');
        danger.filter(u => !q || u.toLowerCase().includes(q)).forEach(u => {
          const tr = document.createElement('tr'); tr.innerHTML = `<td>${u}</td>`;
          tbody.appendChild(tr);
        });
        list.appendChild(table);
      }
      
      if(safe.length > 0){
        const h4 = document.createElement('h4'); h4.textContent = '安全 API 接口'; h4.style.color = '#10b981';
        list.appendChild(h4);
        const table = document.createElement('table'); table.className='table';
        table.innerHTML = '<thead><tr><th>URL</th></tr></thead><tbody></tbody>';
        const tbody = table.querySelector('tbody');
        safe.filter(u => !q || u.toLowerCase().includes(q)).forEach(u => {
          const tr = document.createElement('tr'); tr.innerHTML = `<td>${u}</td>`;
          tbody.appendChild(tr);
        });
        list.appendChild(table);
      }
      
      if(danger.length === 0 && safe.length === 0){
        list.innerHTML = '<div class="muted">暂未发现分类接口数据</div>';
      }
    }else{
      if(q){obj=JSON.parse(JSON.stringify(obj))}
      pushItem(sec, obj);
    }
  }
}
function renderSection(sec){
    currentSec=sec; 
    if(!data) return; 
    // 默认隐藏特定的过滤器，除非在特定分区
    document.getElementById('ruleName').style.display='none';
    document.getElementById('sensitiveSeverity').style.display='none';
    renderListItems(sec)
}
function load(){
  // 获取 URL 中的 id 参数
  const params = new URLSearchParams(window.location.search);
  const id = params.get('id') || '';
  
  fetch('/api/data?id=' + encodeURIComponent(id))
    .then(r=>r.json())
    .then(j=>{
      if(j.error){
        alert("加载失败: " + j.error);
        return;
      }
      data=j;
      renderHeader();
      renderCards();
      renderCounts();
      renderSection(currentSec);
      document.getElementById('loading').style.display='none';
    })
    .catch(e=>{
      alert("请求异常: " + e);
      document.getElementById('loading').style.display='none';
    });
}
window.addEventListener('popstate', load);
document.querySelectorAll('a[data-sec]').forEach(a=>{
  a.addEventListener('click',e=>{e.preventDefault();renderSection(a.dataset.sec)});
});
document.getElementById('q').addEventListener('input',()=>renderSection(currentSec));
document.getElementById('ruleName').addEventListener('change',()=>renderSection(currentSec));
document.getElementById('sensitiveSeverity').addEventListener('change',()=>renderSection(currentSec));

// New listeners
// document.getElementById('respMethod').addEventListener('change',()=>renderSection(currentSec));
// document.getElementById('respCode').addEventListener('input',()=>renderSection(currentSec));
// document.getElementById('respType').addEventListener('input',()=>renderSection(currentSec));
// document.getElementById('minLen').addEventListener('input',()=>renderSection(currentSec));
// document.getElementById('maxLen').addEventListener('input',()=>renderSection(currentSec));
// document.getElementById('sortBy').addEventListener('change',()=>renderSection(currentSec));
// document.getElementById('sortOrder').addEventListener('change',()=>renderSection(currentSec));


document.getElementById('exportDangerJson').addEventListener('click',()=>{
  const {danger}=getRiskArrays(); const blob=new Blob([JSON.stringify(danger,null,2)],{type:'application/json'}); const a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download='risk-danger.json'; a.click();
});
document.getElementById('exportDangerUrls').addEventListener('click',()=>{
  const {danger}=getRiskArrays(); const text=danger.join('\\n'); const blob=new Blob([text],{type:'text/plain'}); const a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download='risk-danger-urls.txt'; a.click();
});
document.getElementById('exportDangerPaths').addEventListener('click',()=>{
  const {danger}=getRiskArrays(); const paths=urlsToPaths(danger); const text=paths.join('\\n'); const blob=new Blob([text],{type:'text/plain'}); const a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download='risk-danger-paths.txt'; a.click();
});
document.getElementById('exportSafeJson').addEventListener('click',()=>{
  const {safe}=getRiskArrays(); const blob=new Blob([JSON.stringify(safe,null,2)],{type:'application/json'}); const a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download='risk-safe.json'; a.click();
});
document.getElementById('exportSafeUrls').addEventListener('click',()=>{
  const {safe}=getRiskArrays(); const text=safe.join('\\n'); const blob=new Blob([text],{type:'text/plain'}); const a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download='risk-safe-urls.txt'; a.click();
});
document.getElementById('exportSafePaths').addEventListener('click',()=>{
  const {safe}=getRiskArrays(); const paths=urlsToPaths(safe); const text=paths.join('\\n'); const blob=new Blob([text],{type:'text/plain'}); const a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download='risk-safe-paths.txt'; a.click();
});
document.getElementById('copySection').addEventListener('click',()=>{
  const s=data?.stage_data||{}; let v=s[currentSec];
  let text='';
  if(Array.isArray(v)){text=v.map(x=>typeof x==='string'?x:JSON.stringify(x)).join('\\n')}
  else{ text=JSON.stringify(v) }
  try{navigator.clipboard.writeText((text||'').trim())}catch(e){}
});
load();
</script>
</body>
</html>
"""
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(html.encode("utf-8"))
            return
        self.send_response(404)
        self.end_headers()

def start_web_view(selected_dir, manage_mode=False, api_server=None):
    ResultsHandler.selected_dir = selected_dir if not manage_mode else ""
    try:
        ResultsHandler.results_root = os.path.dirname(selected_dir) if not manage_mode else selected_dir
    except Exception:
        ResultsHandler.results_root = ""
    server = HTTPServer(("127.0.0.1", 8088), ResultsHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    if manage_mode:
        # 使用独立 Web 界面文件
        web_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'web', 'index.html')
        webbrowser.open(f"file://{web_file}")
    else:
        # 单任务模式，预先注册当前目录，否则无法访问
        if selected_dir:
            token = ResultsHandler.get_token(selected_dir)
            webbrowser.open(f"http://127.0.0.1:8088/?id={token}")
        else:
            webbrowser.open("http://127.0.0.1:8088/")
    try:
        while t.is_alive():
            # 等待Web服务器线程和API服务器线程
            api_thread = getattr(api_server, "_thread", None) if api_server else None
            if api_thread and not api_thread.is_alive():
                break
            time.sleep(0.5)
    except KeyboardInterrupt:
        server.shutdown()
        if api_server:
            api_server.shutdown()
        server.server_close()
        pass

def parse_url_from_filename(filename):
    """
    从文件名解析URL
    例如: GET_PARAMETERS_https___paas.lenovo.com.cn_api_change.txt
    返回: https://paas.lenovo.com.cn/api/change
    """
    # 移除前缀和后缀
    if filename.startswith("GET_PARAMETERS_"):
        name = filename[len("GET_PARAMETERS_"):]
    elif filename.startswith("POST_DATA_PARAMETERS_"):
        name = filename[len("POST_DATA_PARAMETERS_"):]
    elif filename.startswith("POST_JSON_PARAMETERS_"):
        name = filename[len("POST_JSON_PARAMETERS_"):]
    elif filename.startswith("GET_"):
        name = filename[len("GET_"):]
    elif filename.startswith("POST_DATA_"):
        name = filename[len("POST_DATA_"):]
    elif filename.startswith("POST_JSON_"):
        name = filename[len("POST_JSON_"):]
    else:
        name = filename
    
    # 移除.txt后缀
    if name.endswith(".txt"):
        name = name[:-4]
    
    # 将___替换为://，将_替换为/
    url = name.replace("___", "://").replace("_", "/")
    
    # 处理特殊情况
    if "://" not in url:
        url = "https://" + url
    
    return url

def backfill_response_dir_to_db(folder_path, db_path, filePath_url_info):
    response_dir = os.path.join(folder_path, "response")
    if not os.path.isdir(response_dir) or not os.path.isfile(db_path):
        return
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("CREATE TABLE IF NOT EXISTS response_files (method TEXT, url TEXT, file_path TEXT UNIQUE, content_hash TEXT, length INTEGER, request_id TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS step8_diff_files (method TEXT, url TEXT, file_path TEXT UNIQUE, content_hash TEXT, length INTEGER)")
        
        # Ensure request_log and response_log tables exist for backfilling
        conn.execute("CREATE TABLE IF NOT EXISTS request_log (id TEXT PRIMARY KEY, url TEXT, method TEXT, headers TEXT, cookies TEXT, timestamp TEXT, is_no_param INTEGER, referer_url TEXT, body TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS response_log (id TEXT, url TEXT, method TEXT, res_code INTEGER, res_type TEXT, response TEXT, timestamp TEXT, format TEXT, file_path TEXT, is_no_param INTEGER)")
        
        try:
            conn.execute("ALTER TABLE step8_diff_files ADD COLUMN response TEXT")
        except Exception:
            pass
        try:
            conn.execute("ALTER TABLE response_files ADD COLUMN request_id TEXT")
        except Exception:
            pass
        
        # 创建索引
        conn.execute("CREATE INDEX IF NOT EXISTS idx_diff_files_hash ON step8_diff_files(content_hash)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_resp_files_reqid ON response_files(request_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_resp_files_hash ON response_files(content_hash)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_req_log_id ON request_log(id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_resp_log_id ON response_log(id)")

        for root, dirs, files in os.walk(response_dir):
            for name in files:
                if not name.endswith(".txt"):
                    continue
                file_path = os.path.join(root, name)
                try:
                    with open(file_path, "rt", encoding="utf-8") as f:
                        text = f.read()
                except Exception:
                    continue
                h = hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()
                length = len(text)
                base = os.path.basename(name)
                if base.startswith("GET_PARAMETERS_"):
                    method = "GET"
                    target_table = "step7_with_param_responses"
                elif base.startswith("POST_DATA_PARAMETERS_"):
                    method = "POST_DATA"
                    target_table = "step7_with_param_responses"
                elif base.startswith("POST_JSON_PARAMETERS_"):
                    method = "POST_JSON"
                    target_table = "step7_with_param_responses"
                elif base.startswith("GET_"):
                    method = "GET"
                    target_table = "step5_no_param_responses"
                elif base.startswith("POST_DATA_"):
                    method = "POST_DATA"
                    target_table = "step5_no_param_responses"
                elif base.startswith("POST_JSON_"):
                    method = "POST_JSON"
                    target_table = "step5_no_param_responses"
                else:
                    method = ""
                    target_table = ""
                
                # 优先从映射获取URL
                url = filePath_url_info.get(file_path, "")
                # 如果获取不到，尝试通过 normalized path 获取
                if not url:
                     # 尝试使用 replace 统一分隔符
                     url = filePath_url_info.get(file_path.replace("\\", "/"), "")
                if not url:
                     url = filePath_url_info.get(file_path.replace("/", "\\"), "")

                # 如果仍然为空，尝试从文件名解析
                if not url:
                    url = parse_url_from_filename(name)
                
                # Backfill to response_log and request_log
                rid = ""
                try:
                    rid = str(uuid.uuid4())
                    ts = datetime.datetime.fromtimestamp(os.path.getmtime(file_path)).strftime("%Y-%m-%d %H:%M:%S")
                    
                    # Determine format/res_type
                    is_json = False
                    try:
                        if text.strip().startswith(('{', '[')):
                             __import__('json').loads(text)
                             is_json = True
                    except: pass
                    
                    res_type = "application/json" if is_json else "text/plain"
                    fmt = "json" if is_json else "text"
                    
                    # Insert dummy request
                    conn.execute("INSERT OR IGNORE INTO request_log(id,url,method,headers,cookies,timestamp,is_no_param,referer_url,body) VALUES(?,?,?,?,?,?,?,?,?)",
                                 (rid, url, method, "{}", "", ts, 1, "", ""))
                                 
                    # Insert response
                    conn.execute("INSERT OR IGNORE INTO response_log(id,url,method,res_code,res_type,response,timestamp,format,file_path,is_no_param) VALUES(?,?,?,?,?,?,?,?,?,?)",
                                 (rid, url, method, 200, res_type, text, ts, fmt, file_path, 1))
                except Exception as e:
                    # logger_print_content(f"Backfill log error: {e}")
                    pass

                try:
                    conn.execute("INSERT OR IGNORE INTO response_files(method,url,file_path,content_hash,length,request_id) VALUES(?,?,?,?,?,?)", (method, url, file_path, h, length, rid))
                    if target_table:
                        cur = conn.cursor()
                        cur.execute(f"SELECT COUNT(*) FROM {target_table} WHERE url=? AND method=? AND response=?", (url, method, text))
                        c = cur.fetchone()[0]
                        if c == 0:
                            if target_table == "step5_no_param_responses":
                                ok = False
                                try:
                                    __import__('json').loads(text)
                                    ok = True
                                except Exception:
                                    ok = False
                                if ok:
                                    conn.execute("INSERT INTO step5_no_param_responses(url, method, res_code, res_type, response) VALUES(?,?,?,?,?)", (url, method, 200, 'application/json', text))
                                    conn.execute("INSERT INTO step5_xml_json_responses(url, method, res_code, res_type, response) VALUES(?,?,?,?,?)", (url, method, 200, 'application/json', text))
                            else:
                                conn.execute("INSERT INTO step7_with_param_responses(url, method, res_code, res_type, response) VALUES(?,?,?,?,?)", (url, method, 200, '', text))
                    conn.commit()
                except Exception:
                    pass
        diff_dir = os.path.join(folder_path, "差异化response")
        if os.path.isdir(diff_dir):
            for root, dirs, files in os.walk(diff_dir):
                for name in files:
                    if not name.endswith(".txt"):
                        continue
                    file_path = os.path.join(root, name)
                    try:
                        with open(file_path, "rt", encoding="utf-8") as f:
                            text = f.read()
                    except Exception:
                        continue
                    h = hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()
                    length = len(text)
                    base = os.path.basename(name)
                    if base.startswith("GET_"):
                        method = "GET"
                    elif base.startswith("POST_DATA_"):
                        method = "POST_DATA"
                    elif base.startswith("POST_JSON_"):
                        method = "POST_JSON"
                    else:
                        method = ""
                    original_path = os.path.join(folder_path, "response", base)
                    
                    # 优先从映射获取URL
                    url = filePath_url_info.get(original_path, "")
                    # 尝试 path normalization
                    if not url:
                        url = filePath_url_info.get(original_path.replace("\\", "/"), "")
                    if not url:
                        url = filePath_url_info.get(original_path.replace("/", "\\"), "")
                    
                    # 如果仍然为空，尝试从文件名解析
                    if not url:
                        url = parse_url_from_filename(name)

                    try:
                        conn.execute("INSERT OR IGNORE INTO step8_diff_files(method,url,file_path,content_hash,length,response) VALUES(?,?,?,?,?,?)", (method, url, file_path, h, length, text))
                        conn.commit()
                    except Exception:
                        pass
    finally:
        conn.close()

def backfill_rr_log_to_db(folder_path, db_path):
    """
    回填 request_log 和 response_log 表的数据，数据来源为 data/request/*.req 和 data/response/*.resp
    """
    data_dir = os.path.join(folder_path, "data")
    req_dir = os.path.join(data_dir, "request")
    resp_dir = os.path.join(data_dir, "response")
    
    if not os.path.isdir(req_dir) or not os.path.isdir(resp_dir) or not os.path.isfile(db_path):
        return

    conn = sqlite3.connect(db_path)
    try:
        # 确保表存在
        conn.execute("CREATE TABLE IF NOT EXISTS request_log (id TEXT PRIMARY KEY, url TEXT, method TEXT, headers TEXT, cookies TEXT, timestamp TEXT, is_no_param INTEGER, referer_url TEXT, body TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS response_log (id TEXT, url TEXT, method TEXT, res_code INTEGER, res_type TEXT, response TEXT, timestamp TEXT, format TEXT, file_path TEXT, is_no_param INTEGER)")
        
        try:
            conn.execute("ALTER TABLE request_log ADD COLUMN body TEXT")
        except Exception:
            pass

        # 建立索引
        conn.execute("CREATE INDEX IF NOT EXISTS idx_req_log_id ON request_log(id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_resp_log_id ON response_log(id)")

        # 读取所有请求
        req_map = {} # id -> req_data
        for root, dirs, files in os.walk(req_dir):
            for name in files:
                if not name.endswith(".req"): continue
                try:
                    with open(os.path.join(root, name), "rt", encoding="utf-8") as f:
                        data = json.load(f)
                        rid = data.get("id")
                        if rid:
                            req_map[rid] = data
                except: pass
        
        # 插入 request_log
        req_values = []
        for rid, d in req_map.items():
            req_values.append((
                rid, d.get("url",""), d.get("method",""), 
                json.dumps(d.get("headers",{}), ensure_ascii=False) if isinstance(d.get("headers"), dict) else str(d.get("headers","")),
                d.get("cookies",""), d.get("timestamp",""), 
                1 if d.get("is_no_param") else 0, d.get("referer_url",""),
                d.get("body","")
            ))
        
        if req_values:
            conn.executemany("INSERT OR IGNORE INTO request_log(id,url,method,headers,cookies,timestamp,is_no_param,referer_url,body) VALUES(?,?,?,?,?,?,?,?,?)", req_values)

        # 读取所有响应
        resp_values = []
        for root, dirs, files in os.walk(resp_dir):
            for name in files:
                if not name.endswith(".resp"): continue
                # filename: {rid}_{fmt}_{ts}.resp
                try:
                    base = name[:-5] # remove .resp
                    parts = base.split("_")
                    if len(parts) >= 3:
                        rid = parts[0]
                        fmt = parts[1]
                        
                        req = req_map.get(rid)
                        if not req: continue
                        
                        with open(os.path.join(root, name), "rt", encoding="utf-8") as f:
                            text = f.read()
                        
                        resp_values.append((
                            rid, req.get("url",""), req.get("method",""), 
                            200, # Default to 200 as lost
                            "application/json" if fmt=="json" else ("text/xml" if fmt=="xml" else "text/plain"),
                            text, req.get("timestamp",""), fmt, 
                            os.path.join(root, name), 
                            1 if req.get("is_no_param") else 0
                        ))
                except: pass

        if resp_values:
            conn.executemany("INSERT OR IGNORE INTO response_log(id,url,method,res_code,res_type,response,timestamp,format,file_path,is_no_param) VALUES(?,?,?,?,?,?,?,?,?,?)", resp_values)

        conn.commit()
    except Exception as e:
        logger_print_content(f"回填 request/response log 失败: {e}")
    finally:
        conn.close()

def build_results_from_db(selected_dir):
    db_path = os.path.join(selected_dir, "results.db")
    result = {
        "target_info": {},
        "stage_data": {
            "step1_all_load_urls": [],
            "step1_js_extract": [],
            "step1_no_js_urls": [],
            "step2_base_url": [],
            "step2_js_paths": [],
            "step2_dynamic_js_paths": [],
            "step2_alive_js": [],
            "step2_alive_static": [],
            "step2_alive_js_static": [],
            "step3_api_paths": [],
            "step4_api_url": [],
            "step4_path_with_api_urls": [],
            "step4_path_with_api_paths": [],
            "step4_path_with_no_api_paths": [],
            "step5_responses": [],
            "step5_xml_json_urls": [],
            "step5_xml_json_responses": [],
            "step7_with_param_responses": [],
            "step6_vulnerability": {},
            "step6_sensitive_stats": [],
            "step7_summary": {},
            "risk": {"danger": [], "safe": []},
            "all_variables": {},
            "step2_js_cache": [],
            "step8_diff_files": []
        }
    }
    if not os.path.isfile(db_path):
        return result
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        try:
            cur.execute("SELECT original_url, domain, port, scan_time, end_time FROM meta_target_info LIMIT 1")
            row = cur.fetchone()
            if row:
                result["target_info"] = {"original_url": row[0], "domain": row[1], "port": row[2], "scan_time": row[3], "end_time": row[4] if len(row)>4 else ""}
        except Exception: pass

        try:
            cur.execute("SELECT url, referer, url_type FROM step1_all_load_urls")
            result["stage_data"]["step1_all_load_urls"] = [{"url": r[0], "referer": r[1], "url_type": r[2]} for r in cur.fetchall()]
        except Exception: pass

        try:
            cur.execute("SELECT url FROM step1_js_urls")
            result["stage_data"]["step1_js_extract"] = [r[0] for r in cur.fetchall()]
        except Exception: pass

        try:
            cur.execute("SELECT url FROM step1_no_js_urls")
            result["stage_data"]["step1_no_js_urls"] = [r[0] for r in cur.fetchall()]
        except Exception: pass

        try:
            cur.execute("SELECT url FROM step4_base_urls")
            result["stage_data"]["step2_base_url"] = [r[0] for r in cur.fetchall()]
        except Exception: pass

        try:
            cur.execute("SELECT path FROM step2_js_paths")
            result["stage_data"]["step2_js_paths"] = [r[0] for r in cur.fetchall()]
        except Exception: pass

        try:
            cur.execute("SELECT path FROM step2_dynamic_js_paths")
            result["stage_data"]["step2_dynamic_js_paths"] = [r[0] for r in cur.fetchall()]
        except Exception: pass

        try:
            cur.execute("SELECT url FROM step2_alive_js")
            result["stage_data"]["step2_alive_js"] = [r[0] for r in cur.fetchall()]
        except Exception: pass

        try:
            cur.execute("SELECT url FROM step2_alive_static")
            result["stage_data"]["step2_alive_static"] = [r[0] for r in cur.fetchall()]
        except Exception: pass

        try:
            cur.execute("SELECT url FROM step2_alive_js_static")
            result["stage_data"]["step2_alive_js_static"] = [r[0] for r in cur.fetchall()]
        except Exception: pass

        try:
            cur.execute("SELECT url, content_hash, length, path FROM step2_js_cache")
            result["stage_data"]["step2_js_cache"] = [{"url": r[0], "hash": r[1], "length": r[2], "path": r[3]} for r in cur.fetchall()]
        except Exception: pass

        try:
            cur.execute("SELECT api_path FROM step3_api_paths")
            result["stage_data"]["step3_api_paths"] = [r[0] for r in cur.fetchall()]
        except Exception: pass

        try:
            cur.execute("SELECT url FROM step4_api_urls")
            result["stage_data"]["step4_api_url"] = [r[0] for r in cur.fetchall()]
        except Exception: pass

        try:
            cur.execute("SELECT url FROM step4_path_with_api_urls")
            result["stage_data"]["step4_path_with_api_urls"] = [r[0] for r in cur.fetchall()]
        except Exception: pass

        try:
            cur.execute("SELECT path FROM step4_path_with_api_paths")
            result["stage_data"]["step4_path_with_api_paths"] = [r[0] for r in cur.fetchall()]
        except Exception: pass

        try:
            cur.execute("SELECT path FROM step4_path_with_no_api_paths")
            result["stage_data"]["step4_path_with_no_api_paths"] = [r[0] for r in cur.fetchall()]
        except Exception: pass

        try:
            cur.execute("SELECT url, method, res_code, res_type, response, request_id FROM step5_no_param_responses")
            result["stage_data"]["step5_responses"] = [{"url": r[0], "method": r[1], "status_code": r[2], "response_type": r[3], "response": r[4], "request_id": r[5]} for r in cur.fetchall()]
        except Exception: pass

        try:
            cur.execute("SELECT url FROM step5_xml_json_urls")
            result["stage_data"]["step5_xml_json_urls"] = [r[0] for r in cur.fetchall()]
        except Exception: pass

        try:
            cur.execute("SELECT url, method, res_code, res_type, response, request_id FROM step5_xml_json_responses")
            result["stage_data"]["step5_xml_json_responses"] = [{"url": r[0], "method": r[1], "status_code": r[2], "response_type": r[3], "response": r[4], "request_id": r[5]} for r in cur.fetchall()]
        except Exception: pass

        try:
            cur.execute("SELECT url, method, res_code, res_type, response, parameter, request_id FROM step7_with_param_responses")
            result["stage_data"]["step7_with_param_responses"] = [{"url": r[0], "method": r[1], "status_code": r[2], "response_type": r[3], "response": r[4], "parameter": r[5], "request_id": r[6]} for r in cur.fetchall()]
        except Exception: pass

        # step6 vulnerability
        diff = []
        try:
            cur.execute("SELECT content_hash, length, size, url, path FROM step8_diff_hash")
            diff = [{"content_hash": r[0], "length": r[1], "size": r[2], "url": r[3], "path": r[4]} for r in cur.fetchall()]
        except Exception: pass

        hae = []
        try:
            cur.execute("SELECT name, matches, url, file FROM step8_hae")
            hae = [{"name": r[0], "matches": r[1], "url": r[2], "file": r[3]} for r in cur.fetchall()]
        except Exception: pass

        sens = []
        try:
            cur.execute("SELECT name, matches, url, file, severity, evidence, ai_is_sensitive, ai_reason FROM step8_sensitive")
            sens = [{"name": r[0], "matches": r[1], "url": r[2], "file": r[3], "severity": r[4], "evidence": r[5], "ai_is_sensitive": r[6], "ai_reason": r[7]} for r in cur.fetchall()]
        except Exception:
            try:
                cur.execute("SELECT name, matches, url, file, severity, evidence, ai_is_sensitive FROM step8_sensitive")
                sens = [{"name": r[0], "matches": r[1], "url": r[2], "file": r[3], "severity": r[4], "evidence": r[5], "ai_is_sensitive": r[6], "ai_reason": ""} for r in cur.fetchall()]
            except Exception:
                try:
                    cur.execute("SELECT name, matches, url, file, severity, evidence FROM step8_sensitive")
                    sens = [{"name": r[0], "matches": r[1], "url": r[2], "file": r[3], "severity": r[4], "evidence": r[5], "ai_is_sensitive": 0, "ai_reason": ""} for r in cur.fetchall()]
                except Exception:
                    try:
                        cur.execute("SELECT name, matches, url, file FROM step8_sensitive")
                        sens = [{"name": r[0], "matches": r[1], "url": r[2], "file": r[3], "ai_is_sensitive": 0, "ai_reason": ""} for r in cur.fetchall()]
                    except Exception: pass

        result["stage_data"]["step6_vulnerability"] = {"diff_response_info": diff, "hae_api_info": hae, "sensitive_data_info": sens}
        
        # 统计敏感规则命中次数
        try:
            stats = {}
            for srow in sens:
                n = str(srow.get("name","")).strip()
                if not n: continue
                stats[n] = stats.get(n, 0) + 1
            result["stage_data"]["step6_sensitive_stats"] = [{"name": k, "count": v} for k, v in sorted(stats.items(), key=lambda kv: (-kv[1], kv[0]))]
            sev_dist = {"high":0,"medium":0,"low":0}
            for srow in sens:
                sev = str(srow.get("severity","")).lower()
                if sev in sev_dist: sev_dist[sev] += 1
            result["stage_data"]["step6_sensitive_severity_dist"] = sev_dist
        except Exception:
            result["stage_data"]["step6_sensitive_stats"] = []

        try:
            try:
                cur.execute("SELECT method, url, file_path, content_hash, length, response FROM step8_diff_files")
                result["stage_data"]["step8_diff_files"] = [{"method": r[0], "url": r[1], "file_path": r[2], "content_hash": r[3], "length": r[4], "response": r[5]} for r in cur.fetchall()]
            except Exception:
                cur.execute("SELECT method, url, file_path, content_hash, length FROM step8_diff_files")
                result["stage_data"]["step8_diff_files"] = [{"method": r[0], "url": r[1], "file_path": r[2], "content_hash": r[3], "length": r[4]} for r in cur.fetchall()]
        except Exception:
            result["stage_data"]["step8_diff_files"] = []

        try:
            cur.execute("SELECT url FROM risk_danger_api_urls")
            result["stage_data"]["risk"]["danger"] = [r[0] for r in cur.fetchall()]
            cur.execute("SELECT url FROM risk_safe_api_urls")
            result["stage_data"]["risk"]["safe"] = [r[0] for r in cur.fetchall()]
        except Exception: pass

        try:
            cur.execute("SELECT total_api, valid_api FROM summary LIMIT 1")
            s = cur.fetchone()
            if s:
                result["stage_data"]["step7_summary"] = {"total_api": s[0], "valid_api": s[1]}
        except Exception: pass

        try:
            cur.execute("SELECT json FROM meta_all_vars LIMIT 1")
            av = cur.fetchone()
            if av and av[0]:
                try:
                    result["stage_data"]["all_variables"] = json.loads(av[0])
                except Exception:
                    result["stage_data"]["all_variables"] = {}
        except Exception: pass

        try:
            cur.execute("SELECT id,url,method,headers,cookies,timestamp,is_no_param,referer_url,body FROM request_log ORDER BY timestamp DESC")
            result["stage_data"]["request_log"] = [{"id": r[0], "url": r[1], "method": r[2], "headers": r[3], "cookies": r[4], "timestamp": r[5], "is_no_param": r[6], "referer_url": r[7], "body": r[8]} for r in cur.fetchall()]
        except Exception:
            result["stage_data"]["request_log"] = []

        try:
            cur.execute("SELECT t1.id,t1.url,t1.method,t1.res_code,t1.res_type,t1.timestamp,t1.format,t1.file_path,t1.is_no_param,t1.response,t2.body FROM response_log t1 LEFT JOIN request_log t2 ON t1.id=t2.id ORDER BY t1.timestamp DESC")
            result["stage_data"]["response_log"] = [{"id": r[0], "url": r[1], "method": r[2], "res_code": r[3], "res_type": r[4], "timestamp": r[5], "format": r[6], "file_path": r[7], "is_no_param": r[8], "response": r[9], "parameter": r[10]} for r in cur.fetchall()]
        except Exception:
            result["stage_data"]["response_log"] = []

        try:
            cur.execute("SELECT step_name, request_count FROM stats_execution")
            result["stage_data"]["stats_execution"] = [r for r in cur.fetchall()]
        except Exception:
            result["stage_data"]["stats_execution"] = []

        try:
            cur.execute("SELECT url, local_path, content, filename FROM step8_restored_html")
            result["stage_data"]["step8_restored_html"] = [{"url": r[0], "local_path": r[1], "content": r[2], "filename": r[3]} for r in cur.fetchall()]
        except Exception:
            result["stage_data"]["step8_restored_html"] = []
    except Exception:
        traceback.print_exc()
    finally:
        conn.close()
    return result

def search_rr(selected_dir, request_id, url_kw, start, end, method='', res_code='', res_type='', min_length=None, max_length=None, sort='timestamp', order='desc', page=1, size=20, dataset='response_log'):
    db_path = os.path.join(selected_dir, "results.db")
    res = {"request": [], "response": [], "diff_files": [], "page": page, "size": size}
    if not os.path.isfile(db_path):
        return res
    
    # 确保索引存在以优化查询速度
    try:
        idx_conn = sqlite3.connect(db_path)
        idx_conn.execute("CREATE INDEX IF NOT EXISTS idx_req_log_ts ON request_log(timestamp)")
        idx_conn.execute("CREATE INDEX IF NOT EXISTS idx_req_log_url ON request_log(url)")
        idx_conn.execute("CREATE INDEX IF NOT EXISTS idx_resp_log_ts ON response_log(timestamp)")
        idx_conn.execute("CREATE INDEX IF NOT EXISTS idx_resp_log_url ON response_log(url)")
        idx_conn.execute("CREATE INDEX IF NOT EXISTS idx_resp_log_code ON response_log(res_code)")
        idx_conn.execute("CREATE INDEX IF NOT EXISTS idx_resp_log_method ON response_log(method)")
        idx_conn.execute("CREATE INDEX IF NOT EXISTS idx_step5_np_url ON step5_no_param_responses(url)")
        idx_conn.execute("CREATE INDEX IF NOT EXISTS idx_step7_wp_url ON step7_with_param_responses(url)")
        idx_conn.execute("CREATE INDEX IF NOT EXISTS idx_diff_files_reqid ON step8_diff_files(request_id)")
        
        # 针对 LENGTH(response) 排序的表达式索引
        try:
            idx_conn.execute("CREATE INDEX IF NOT EXISTS idx_step5_np_len ON step5_no_param_responses(LENGTH(response))")
            idx_conn.execute("CREATE INDEX IF NOT EXISTS idx_step5_xj_len ON step5_xml_json_responses(LENGTH(response))")
            idx_conn.execute("CREATE INDEX IF NOT EXISTS idx_step7_wp_len ON step7_with_param_responses(LENGTH(response))")
            idx_conn.execute("CREATE INDEX IF NOT EXISTS idx_resp_log_len ON response_log(LENGTH(response))")
        except Exception:
            pass # 可能部分旧版本 SQLite 不支持表达式索引

        idx_conn.commit()
        idx_conn.close()
    except Exception:
        pass

    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        where_req = []
        params_req = []
        where_resp = []
        params_resp = []
        where_diff = []
        params_diff = []
        if request_id:
            where_req.append("id=?"); params_req.append(request_id)
            where_resp.append("id=?"); params_resp.append(request_id)
            where_diff.append("request_id=?"); params_diff.append(request_id)
        if url_kw:
            where_req.append("url LIKE ?"); params_req.append(f"%{url_kw}%")
            where_resp.append("url LIKE ?"); params_resp.append(f"%{url_kw}%")
        if start:
            where_req.append("timestamp>=?"); params_req.append(start)
            where_resp.append("timestamp>=?"); params_resp.append(start)
        if end:
            where_req.append("timestamp<=?"); params_req.append(end)
            where_resp.append("timestamp<=?"); params_resp.append(end)
        if method:
            where_resp.append("method=?"); params_resp.append(method)
        if res_code:
            where_resp.append("res_code=?"); params_resp.append(res_code)
        if res_type:
            where_resp.append("res_type LIKE ?"); params_resp.append(f"%{res_type}%")
        if min_length:
            where_resp.append("LENGTH(response) >= ?"); params_resp.append(min_length)
        if max_length:
            where_resp.append("LENGTH(response) <= ?"); params_resp.append(max_length)

        q_req = "SELECT id,url,method,headers,cookies,timestamp,is_no_param,referer_url FROM request_log"
        if dataset == 'step5':
            q_resp = "SELECT url,method,res_code,res_type,response,request_id FROM step5_no_param_responses"
            q_count = "SELECT COUNT(1) FROM step5_no_param_responses"
        elif dataset == 'step5_xml_json':
            q_resp = "SELECT url,method,res_code,res_type,response,request_id FROM step5_xml_json_responses"
            q_count = "SELECT COUNT(1) FROM step5_xml_json_responses"
        elif dataset == 'step7':
            q_resp = "SELECT url,method,res_code,res_type,response,parameter,request_id FROM step7_with_param_responses"
            q_count = "SELECT COUNT(1) FROM step7_with_param_responses"
        else:
            # Join request_log to fill missing URL if possible
            q_resp = """
            SELECT 
                t1.id, 
                COALESCE(t1.url, t2.url) as url, 
                t1.method, 
                t1.res_code, 
                t1.res_type, 
                t1.response, 
                t1.timestamp, 
                t1.format, 
                t1.file_path, 
                t1.is_no_param,
                t2.body
            FROM response_log t1 
            LEFT JOIN request_log t2 ON t1.id = t2.id
            """
            q_count = "SELECT COUNT(1) FROM response_log"
        q_diff = "SELECT method,url,file_path,content_hash,length,response,request_id FROM step8_diff_files"
        if where_req:
            q_req += " WHERE " + " AND ".join(where_req)
        if where_resp:
            if dataset == 'response_log':
                 fixed_where = []
                 for w in where_resp:
                     if any(w.startswith(c) for c in ['url', 'method', 'res_code', 'res_type', 'timestamp', 'format', 'file_path', 'is_no_param', 'id']):
                         if w.startswith("LENGTH"): fixed_where.append(w)
                         else: fixed_where.append("t1." + w)
                     else:
                         fixed_where.append("t1." + w)
                 q_resp += " WHERE " + " AND ".join(fixed_where)
                 q_count += " WHERE " + " AND ".join(where_resp)
            else:
                q_resp += " WHERE " + " AND ".join(where_resp)
                q_count += " WHERE " + " AND ".join(where_resp)
        if where_diff:
            q_diff += " WHERE " + " AND ".join(where_diff)
        sort = (sort or 'timestamp').lower()
        order = 'DESC' if (str(order).lower()=='desc') else 'ASC'
        
        valid_sorts = ['timestamp', 'res_code', 'method', 'res_type', 'length']
        if sort == 'length':
            sort_sql = 'LENGTH(response)'
        elif sort in valid_sorts:
            sort_sql = sort
        else:
            sort_sql = 'timestamp' if dataset == 'response_log' else 'res_code'
            
        if dataset != 'response_log' and sort_sql == 'timestamp':
             sort_sql = 'res_code'

        q_resp += f" ORDER BY {sort_sql} {order}"
        try:
            size = int(size)
            page = max(1, int(page))
        except Exception:
            size = 10000; page = 1
        offset = (page-1)*size
        q_resp += f" LIMIT {size} OFFSET {offset}"
        
        # Debug Log
        print(f"[DEBUG SQL] QUERY: {q_resp} | PARAMS: {params_resp}")
        start_time = time.time()
        
        cur.execute(q_req, params_req)
        res["request"] = [{"id": r[0], "url": r[1], "method": r[2], "headers": r[3], "cookies": r[4], "timestamp": r[5], "is_no_param": r[6], "referer_url": r[7]} for r in cur.fetchall()]
        cur.execute(q_resp, params_resp)
        rows = cur.fetchall()
        
        print(f"[DEBUG SQL] EXECUTION TIME: {time.time() - start_time:.4f}s")
        
        resp = []
        if dataset == 'response_log':
            for r in rows:
                txt = r[5] or ''
                b = len((txt or '').encode('utf-8', errors='ignore'))
                resp.append({"id": r[0], "url": r[1], "method": r[2], "res_code": r[3], "res_type": r[4], "response": txt, "timestamp": r[6], "format": r[7], "file_path": r[8], "is_no_param": r[9], "bytes": b, "parameter": r[10] or ""})
        else:
            for r in rows:
                txt = r[4] or ''
                b = len((txt or '').encode('utf-8', errors='ignore'))
                param = ""
                rid = ""
                if dataset == 'step7' and len(r) > 6:
                    param = r[5]
                    rid = r[6]
                elif len(r) > 5:
                    rid = r[5]
                resp.append({"url": r[0], "method": r[1], "res_code": r[2], "res_type": r[3], "response": txt, "bytes": b, "parameter": param, "request_id": rid})
        res["response"] = resp
        try:
            cur.execute(q_count, params_resp)
            c = cur.fetchone()
            res["total"] = int(c[0]) if c else len(res["response"])
            tot = res["total"]; res["pages"] = max(1, (tot + size - 1)//size); res["page"] = page; res["size"] = size
        except Exception:
            res["total"] = len(res["response"]); res["pages"] = max(1, (res["total"] + size - 1)//size)
        cur.execute(q_diff, params_diff)
        res["diff_files"] = [{"method": r[0], "url": r[1], "file_path": r[2], "content_hash": r[3], "length": r[4], "response": r[5], "request_id": r[6]} for r in cur.fetchall()]
    finally:
        conn.close()
    return res

def main():
    if len(sys.argv) == 1:
        # 如果没有参数，显示帮助信息并退出
        parser = OptionParser()
        parser.add_option('-u', '--url', dest='url', type='str', help='target url')
        parser.add_option('--file', dest='file', type='str', help='target file')
        # ... (其他选项)
        # 这里只是为了触发help，实际上不需要完整定义
        print("Use -h for help")
        return

    usage = "Usage: %prog -u <url> [options]"
    parse = OptionParser(usage=usage)
    parse.add_option('-u', '--url', dest='url', type='str', help='target url')
    parse.add_option('--file', dest='file', type='str', help='target file')
    parse.add_option('--cookies', dest='cookies', type='str', help='cookie')
    parse.add_option('--chrome', dest='chrome', action='store_true', default=False, help='use chrome headless to capture url')
    parse.add_option('--attack', dest='attackType', type='int', default=0, help='0: all, 1: only sensitive info scan (no api fuzz)')
    parse.add_option('--no-api-scan', dest='noApiScan', type='int', default=0, help='0: default, 1: no api path finding')
    parse.add_option('--dedupe', dest='dedupe', type='int', default=1, help='1: deduplicate urls (default), 0: no deduplication')
    parse.add_option('--infoscan', dest='infoScan', action='store_true', default=False, help='仅进行敏感信息扫描（不探测API）')
    parse.add_option('--js-depth', dest='js_depth', type='int', default=3, help='JS 跟踪深度，默认 3')
    parse.add_option('--ai-scan', dest='aiScan', action='store_true', default=False, help='启用 AI 辅助扫描 (逻辑漏洞分析)')
    parse.add_option('--manage', dest='manage', action='store_true', help='结果管理交互模式')
    parse.add_option('--store', dest='store', type='str', default='db', help='结果存储方式: db|txt')
    parse.add_option('--rr-subdir', dest='rr_subdir', type='str', default='data', help='请求/响应关联存储子目录')
    parse.add_option('--rr-keep-days', dest='rr_keep_days', type='int', default=30, help='请求/响应文件保留天数')
    parse.add_option('--rr-no-param-flag', dest='rr_no_param_flag', type='str', default='on', help='无参响应标记开关 on/off')
    parse.add_option('--proxy', dest='proxy', type='str', help='代理地址，例如 http://127.0.0.1:8080')
    parse.add_option('--mode', dest='proxy_mode', type='str', help='代理模式: js|api|all')
    parse.add_option('--baseurl', dest='base_override', type='str', help='指定基础 BaseURL，例如 http://qtzhbm.xdf.cn/portal/')
    parse.add_option('--basepath', dest='basepath', type='str', help='指定接口前缀 BasePath，例如 /api')
    parse.add_option('--header', dest='header', action='append', help='自定义请求头，格式为 Key: Value，可多次使用')

    options, args = parse.parse_args()
    
    if options.manage:
        manage_interactive()
        return

    url = options.url
    file_path = options.file
    cookies = options.cookies
    chrome = options.chrome
    attackType = options.attackType
    noApiScan = options.noApiScan
    dedupe = options.dedupe
    infoScan = options.infoScan
    js_depth = options.js_depth
    aiScan = options.aiScan
    store = options.store
    rr_subdir = options.rr_subdir
    rr_keep_days = options.rr_keep_days
    rr_no_param_flag = options.rr_no_param_flag
    proxy = options.proxy
    proxy_mode = options.proxy_mode
    base_override = options.base_override
    basepath = options.basepath
    headers_list = options.header

    rr_config = {
        'subdir': rr_subdir,
        'keep_days': rr_keep_days,
        'no_param_flag': (rr_no_param_flag == 'on'),
        'base_override': base_override,
        'basepath': basepath,
        'headers': headers_list
    }

    if aiScan:
        print("[AI] Initializing AI Engine and testing connectivity...")
        ai_engine = AIEngine()
        if not ai_engine.test_connectivity():
            sys.exit(1)

    if infoScan:
        print(f"[*] 模式: --infoscan")
        print(f"[*] 目标: {url or file_path}")
        print(f"[*] 深度: {js_depth}")
        print(f"[*] AI增强: {'是' if aiScan else '否'}")
        attackType = 1 # 强制设置为仅敏感信息扫描模式
        noApiScan = 1  # 不进行API探测

    if file_path:
        with open(file_path, 'r', encoding='utf-8') as f:
            urls = f.readlines()
            for u in urls:
                u = u.strip()
                if u:
                    run_url(u, cookies, chrome, attackType, noApiScan, dedupe, store, rr_config, proxy, proxy_mode, infoScan, js_depth, aiScan)
    elif url:
        run_url(url, cookies, chrome, attackType, noApiScan, dedupe, store, rr_config, proxy, proxy_mode, infoScan, js_depth, aiScan)
    else:
        parse.print_help()

    # 统计总请求量
    from plugins.nodeCommon import GlobalRequestCounter
    print(f"\n[统计] 本次扫描总计发送请求: {GlobalRequestCounter.get_count()} 次")

if __name__ == '__main__':
    main()
# ====== 新增：独立后端 API =====
# 支持管理界面的数据查询和操作
if __name__ == '__api__':
    run_api_server()
