import json
import time
import hashlib
import sqlite3
import os
proxies = None

try:
    from plugins.nodeCommon import *
    from plugins.enhanced_sourcemap_detector import SourceMapIntegration
    from plugins.ast_analyzer import ASTAnalyzer
except Exception as e:
    from nodeCommon import *
    from enhanced_sourcemap_detector import SourceMapIntegration
    try:
        from ast_analyzer import ASTAnalyzer
    except ImportError:
        pass


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
        rp = (root_path or '/')
        rp_clean = rp.rstrip('/')
        p_clean = path.lstrip('/')
        if rp_clean and (p_clean.startswith(rp_clean.lstrip('/'))):
            new_url = base + '/' + p_clean
        else:
            new_url = base + rp + path

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



from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Empty

def js_and_staticUrl_find(i, headers, js_and_staticUrl_info, urls, domain, js_and_staticUrl_alive_info_tmp, folder_path, filePath_url_info, db_path=None, max_depth=3):
    # This wrapper function is no longer needed with ThreadPoolExecutor but kept for compatibility if called externally
    while not queue.empty():
        try:
            url, current_depth = queue.get(timeout=1)
            get_js_and_staticUrl(i, headers, js_and_staticUrl_info, url, urls, domain, js_and_staticUrl_alive_info_tmp, folder_path, filePath_url_info, db_path, current_depth, max_depth)
            queue.task_done()
        except Exception:
            break

def _process_content_for_urls_external(content, ref_url, domain, urls, js_and_staticUrl_info):
    try:
        parsed_url = urlparse(ref_url)
        scheme = parsed_url.scheme
        path = parsed_url.path
        host = parsed_url.hostname
        port = parsed_url.port
        base = f"{scheme}://{host}" + (f":{port}" if port else "")
        root_path = "/"
        pattern = re.compile(r'/.*/{1}|/')
        root_result = pattern.findall(path)
        if root_result:
            root_path = root_result[0]
    except Exception:
        return
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
    for js_pattern in js_patterns:
        try:
            js_paths = re.findall(js_pattern, content or "")
            js_paths = ["".join(x.strip("\"'")) for x in js_paths]
            js_paths = jsFilter(list(set(js_paths)))
            for js_path in js_paths:
                new_js_url = get_new_url(scheme, base, root_path, js_path)
                new_js_url = rewrite_internal_host(new_js_url, base)
                if new_js_url and new_js_url not in urls:
                    urls.append(new_js_url)
                js_and_staticUrl_info['js_url'].append({'url': new_js_url, 'referer': ref_url, 'url_type': "js_url"})
        except Exception:
            pass
    for staticUrl_pattern in staticUrl_patterns:
        try:
            static_paths = re.findall(staticUrl_pattern, content or "")
            static_paths = [x.strip('\'" ').rstrip('/') for x in static_paths]
            static_paths = staticUrlFilter(domain, list(set(static_paths)))
            for static_path in static_paths:
                static_url = get_new_url(scheme, base, root_path, static_path)
                static_url = rewrite_internal_host(static_url, base)
                if static_url and static_url not in urls:
                    urls.append(static_url)
                js_and_staticUrl_info['static_url'].append({'url': static_url, 'referer': ref_url, 'url_type': "static_url"})
        except Exception:
            pass

def _seed_urls_from_response_log(db_path, domain, urls, js_and_staticUrl_info, limit=50000):
    if not db_path:
        return
    try:
        conn = sqlite3.connect(db_path)
        try:
            cur = conn.execute("SELECT url, response, res_type FROM response_log WHERE response IS NOT NULL AND response != '' LIMIT ?", (limit,))
            rows = cur.fetchall()
            for ref_url, content, res_type in rows:
                if not ref_url or not content:
                    continue
                low_ct = str(res_type or "").lower()
                if ('javascript' in low_ct) or ('html' in low_ct) or ('text' in low_ct) or (low_ct == ''):
                    _process_content_for_urls_external(content, ref_url, domain, urls, js_and_staticUrl_info)
        except Exception:
            pass
        conn.close()
    except Exception:
        pass

def get_js_and_staticUrl(i, headers, js_and_staticUrl_info, url, urls, domain, js_and_staticUrl_alive_info_tmp, folder_path, filePath_url_info, db_path=None, current_depth=0, max_depth=3, ast_tasks_list=None):
    try:
        GlobalRequestCounter.increment()
        res = requests.get(url=url, headers=headers, timeout=TIMEOUT, verify=False, allow_redirects=False, stream=True, proxies=proxies)
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

        # logger_print_content(f"[线程{i}] 剩下:{queue.qsize()} {url} 获取页面里的js url")
        # res = requests.get(url=url, headers=headers, timeout=TIMEOUT, verify=False, allow_redirects=False)
        # logger_print_content(f"[线程{i}] 剩下:{queue.qsize()} {url} 获取页面里的js url\t状态码:{res.status_code}\t长度:{len(res.text)}")

        # Fix encoding issues (requests defaults to ISO-8859-1 if header missing)
        if res.encoding == 'ISO-8859-1':
             res.encoding = 'utf-8'
        
        try:
             text = res.text
        except Exception:
             text = res.content.decode('utf-8', 'ignore')

        logger_print_content(f"[线程{i}] 剩下:{queue.qsize()} {url} 获取页面里的js url\t状态码:{code}\t长度:{len(text)}")

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
                    if current_depth < max_depth:
                        try:
                            if not is_blacklisted(new_js_url):
                                queue.put((new_js_url, current_depth + 1))
                        except Exception:
                            pass
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
                    if current_depth < max_depth:
                        try:
                            if not is_blacklisted(static_url):
                                queue.put((static_url, current_depth + 1))
                        except Exception:
                            pass
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
                    if current_depth < max_depth:
                        try:
                            if not is_blacklisted(new_js_url):
                                queue.put((new_js_url, current_depth + 1))
                        except Exception:
                            pass
                js_and_staticUrl_info['js_url'].append({'url': new_js_url, 'referer': ref_url, 'url_type': "js_url"})

    # 处理主响应内容
    process_content_for_urls(text, url)

    # 4. AST 静态分析 (直接对下载的 JS 文件进行分析)
    # 如果文件是 .js 结尾，或者内容特征像 JS
    is_js_file = url.lower().endswith('.js') or 'javascript' in res.headers.get('Content-Type', '').lower()
    
    # 限制分析条件：是JS文件，且不是太小(没意义)或太大(超时)，且没有被SourceMap覆盖(SourceMap流程会自己做AST)
    # 这里我们直接做，因为SourceMap是异步的，而且SourceMap分析的是还原后的代码，这里分析的是混淆/未混淆的原代码，互为补充
    if is_js_file and len(text) > 100 and len(text) < 2 * 1024 * 1024: # 2MB limit
        if ast_tasks_list is not None:
             ast_tasks_list.append({
                 'file_path': file_path, 
                 'url': url, 
                 'db_path': db_path,
                 'base': base, 
                 'scheme': scheme, 
                 'root_path': root_path,
                 'current_depth': current_depth,
                 'max_depth': max_depth
             })
        else:
            try:
                logger_print_content(f"[+][D{current_depth+1}] 【AST】正在对 {url} 进行静态分析...")
                analyzer = ASTAnalyzer()
                # file_path 已在上方保存 (lines 173-176)
                # file_path = f'{folder_path}/js_response/JS_{file_name}.txt'
                
                ast_res = analyzer.analyze_file(file_path)
                
                # 处理分析结果
                apis = ast_res.get('apis', [])
                ast_urls = ast_res.get('urls', [])
                
                if apis or ast_urls:
                    logger_print_content(f"[+][D{current_depth+1}] 【AST】{url} 分析完成: 发现 {len(apis)} 个接口, {len(ast_urls)} 个URL")
                    
                    # 保存结果到数据库
                    if db_path:
                        try:
                            conn = sqlite3.connect(db_path)
                            conn.execute("CREATE TABLE IF NOT EXISTS step2_ast_analysis (file_path TEXT, api_json TEXT, url_json TEXT)")
                            conn.execute("INSERT INTO step2_ast_analysis (file_path, api_json, url_json) VALUES (?, ?, ?)",
                                         (file_path, json.dumps(apis), json.dumps(ast_urls)))
                            conn.commit()
                            conn.close()
                        except Exception as e:
                            pass

                    # 将发现的 URL 加入队列
                    for url_item in ast_urls:
                        u = url_item.get('value')
                        if u and isinstance(u, str):
                            if u.startswith('http'):
                                new_url = rewrite_internal_host(u, base)
                            elif u.startswith('/'):
                                new_url = rewrite_internal_host(get_new_url(scheme, base, root_path, u), base)
                            else:
                                continue
                                
                            if new_url and new_url not in urls:
                                urls.append(new_url)
                                if current_depth < max_depth:
                                    try:
                                        if not is_blacklisted(new_url):
                                            queue.put((new_url, current_depth + 1))
                                    except Exception:
                                        pass
                                js_and_staticUrl_info['static_url'].append({'url': new_url, 'referer': url, 'url_type': "ast_found_url"})
                                
            except Exception as e:
                # logger_print_content(f"[-][D{current_depth+1}] 【AST】分析失败: {str(e)}")
                pass

    # 5. 增强版SourceMap检测
    # 仅对 .js 文件进行检测，避免对 PHP/HTML/API 接口进行无意义的 SourceMap 探测
    parsed_path_lower = urlparse(url).path.lower()
    if parsed_path_lower.endswith('.js'):
        try:
            sourcemap_integration = SourceMapIntegration()
            enhanced_sourcemaps = sourcemap_integration.detect_sourcemap_urls_enhanced(url, text)
            if enhanced_sourcemaps:
                logger_print_content(f"[+][D{current_depth+1}] 【SOURCEMAP】{url} 发现 {len(enhanced_sourcemaps)} 个增强SourceMap")
                for sm_url in enhanced_sourcemaps:
                    # 立即进行还原和扫描
                    try:
                        restored_files, ast_findings = sourcemap_integration.restore_and_scan(sm_url, folder_path, db_path)
                        
                        # 保存AST分析结果到数据库
                        if ast_findings and db_path:
                            try:
                                conn = sqlite3.connect(db_path)
                                conn.execute("CREATE TABLE IF NOT EXISTS step2_ast_analysis (file_path TEXT, api_json TEXT, url_json TEXT)")
                                for finding in ast_findings:
                                    conn.execute("INSERT INTO step2_ast_analysis (file_path, api_json, url_json) VALUES (?, ?, ?)",
                                                 (finding['file'], json.dumps(finding['apis']), json.dumps(finding['urls'])))
                                conn.commit()
                                conn.close()
                                
                                # 将AST发现的URL加入扫描队列
                                for finding in ast_findings:
                                    for url_item in finding.get('urls', []):
                                        u = url_item.get('value')
                                        if u and isinstance(u, str):
                                            # 简单的URL处理
                                            if u.startswith('http'):
                                                new_url = rewrite_internal_host(u, base)
                                            elif u.startswith('/'):
                                                new_url = rewrite_internal_host(get_new_url(scheme, base, root_path, u), base)
                                            else:
                                                continue
                                                
                                            if new_url and new_url not in urls:
                                                urls.append(new_url)
                                                if current_depth < max_depth:
                                                    try:
                                                        if not is_blacklisted(new_url):
                                                            queue.put((new_url, current_depth + 1))
                                                    except Exception as e:
                                                        logger_print_content(f"[-][D{current_depth+1}] 队列添加失败: {str(e)}")
                                                js_and_staticUrl_info['static_url'].append({'url': new_url, 'referer': sm_url, 'url_type': "ast_found_url"})
                            except Exception as e:
                                logger_print_content(f"[-][D{current_depth+1}] AST结果处理失败: {str(e)}")

                        # 对还原的文件进行接口提取
                        if restored_files:
                            logger_print_content(f"[+][D{current_depth+1}] 【SOURCEMAP】正在分析 {len(restored_files)} 个还原文件中的接口...")
                            for r_file in restored_files:
                                try:
                                    with open(r_file, 'r', encoding='utf-8', errors='ignore') as f:
                                        r_content = f.read()
                                        process_content_for_urls(r_content, url, is_sourcemap_file=True)
                                except: pass
                    except Exception as e:
                        logger_print_content(f"[-][D{current_depth+1}] 【SOURCEMAP】{sm_url} 还原失败: {str(e)}")

                    if sm_url and sm_url not in urls:
                        urls.append(sm_url)
                        queue.put((sm_url, current_depth + 1))
                    js_and_staticUrl_info['js_url'].append({'url': sm_url, 'referer': url, 'url_type': "sourcemap_url"})
        except Exception as e:
            logger_print_content(f"[-][D{current_depth+1}] 【SOURCEMAP】{url} 增强检测失败: {str(e)}")

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
    
    if db_path:
        try:
            _seed_urls_from_response_log(db_path, domain, urls, js_and_staticUrl_info)
        except Exception:
            pass
    
    # Use standard Queue
    queue = Queue()
    # Deduplication set for queue
    queued_urls = set(urls)
    
    for url in urls:
        queue.put((url, 0))

    # Use ThreadPoolExecutor for better management
    max_workers = min(os.cpu_count() or 4, 32) # Increased threads for IO bound task
    
    ast_tasks_list = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        while not queue.empty() or getattr(executor, '_work_queue', None) and executor._work_queue.qsize() > 0:
            try:
                # Get task with timeout
                url_data = queue.get(timeout=1)
                url, depth = url_data
                
                # Submit task
                executor.submit(get_js_and_staticUrl, 0, headers, js_and_staticUrl_info, url, urls, domain, js_and_staticUrl_alive_info_tmp, folder_path, filePath_url_info, db_path, depth, max_depth, ast_tasks_list)
                
            except Empty:
                # Wait a bit to see if new tasks are added
                time.sleep(0.5)
                if queue.empty():
                    break
            except Exception:
                pass
    
    # 批量执行 AST 分析
    if ast_tasks_list:
        try:
            logger_print_content(f"[+] [AST] 开始批量分析 {len(ast_tasks_list)} 个 JS 文件...")
            analyzer = ASTAnalyzer()
            
            batch_size = 20
            for i in range(0, len(ast_tasks_list), batch_size):
                batch_tasks = ast_tasks_list[i:i+batch_size]
                file_paths = [t['file_path'] for t in batch_tasks]
                
                results = analyzer.analyze_files_batch(file_paths)
                
                if not results:
                    continue
                    
                for j, res in enumerate(results):
                    if j >= len(batch_tasks): break
                    task = batch_tasks[j]
                    
                    if 'error' in res:
                        continue
                        
                    apis = res.get('apis', [])
                    ast_urls = res.get('urls', [])
                    
                    if apis or ast_urls:
                        logger_print_content(f"[+][D{task['current_depth']+1}] 【AST】{task['url']} 分析完成: 发现 {len(apis)} 个接口, {len(ast_urls)} 个URL")
                        
                        if task['db_path']:
                            try:
                                conn = sqlite3.connect(task['db_path'])
                                conn.execute("CREATE TABLE IF NOT EXISTS step2_ast_analysis (file_path TEXT, api_json TEXT, url_json TEXT)")
                                conn.execute("INSERT INTO step2_ast_analysis (file_path, api_json, url_json) VALUES (?, ?, ?)",
                                             (task['file_path'], json.dumps(apis), json.dumps(ast_urls)))
                                conn.commit()
                                conn.close()
                            except Exception:
                                pass

                        for url_item in ast_urls:
                            u = url_item.get('value')
                            if u and isinstance(u, str):
                                new_url = None
                                if u.startswith('http'):
                                    new_url = rewrite_internal_host(u, task['base'])
                                elif u.startswith('/'):
                                    new_url = rewrite_internal_host(get_new_url(task['scheme'], task['base'], task['root_path'], u), task['base'])
                                
                                if new_url and new_url not in urls:
                                    urls.append(new_url)
                                    js_and_staticUrl_info['static_url'].append({'url': new_url, 'referer': task['url'], 'url_type': "ast_found_url"})

        except Exception as e:
            logger_print_content(f"[-] [AST] 批量分析异常: {e}")

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
