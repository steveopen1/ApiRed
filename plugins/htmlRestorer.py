import os
import re
import json
import html
from urllib.parse import unquote

try:
    from plugins.nodeCommon import decode_path_safely
except Exception:
    try:
        from nodeCommon import decode_path_safely
    except Exception:
        def decode_path_safely(path): return path

def extract_html_from_js(js_content):
    """
    尝试从 JS 包装文件中提取 HTML 正文
    支持常见的 Vite/Webpack/VuePress 静态资源打包格式
    """
    if not js_content:
        return ""
    
    # 多种提取模式
    patterns = [
        # VuePress/Vite 常见格式: export default "..."
        r'export\s+default\s+[\'"`](.*?)[\'"`]\s*;?\s*$',
        # 模板字符串中的完整HTML
        r'[\'"`](\s*<!DOCTYPE\s+html>.*?</html>\s*)[\'"`]',
        r'[\'"`](\s*<html.*?>.*?</html>\s*)[\'"`]',
        # 变量赋值模式
        r'(?:const|let|var)\s+\w+\s*=\s*[\'"`](.*?)[\'"`]\s*;',
        # VuePress markdown 渲染结果
        r'pageData\s*=\s*JSON\.parse\s*\(\s*[\'"`](\{.*?\})[\'"`]\s*\)',
        # 局部HTML片段
        r'[\'"`](\s*<div[^>]*class=[\'"]?(?:theme-default-content|page-content|markdown-body)[\'"]?[^>]*>.*?</div>\s*)[\'"`]',
    ]
    
    for p in patterns:
        match = re.search(p, js_content, re.DOTALL | re.IGNORECASE)
        if match:
            raw_html = match.group(1)
            if len(raw_html) < 50:  # 内容过短，跳过
                continue
            # 处理转义字符
            try:
                # 预处理：处理常见的转义序列
                # 替换 \u003c -> <, \u003e -> >, 等
                decoded = raw_html
                # unicode escape
                decoded = re.sub(r'\\u([0-9a-fA-F]{4})', lambda m: chr(int(m.group(1), 16)), decoded)
                # 基本转义
                decoded = decoded.replace('\\n', '\n').replace('\\r', '\r')
                decoded = decoded.replace('\\t', '\t').replace('\\"', '"')
                decoded = decoded.replace("\\'", "'").replace('\\/', '/')
                # HTML实体解码
                decoded = html.unescape(decoded)
                return decoded
            except Exception:
                return html.unescape(raw_html)
    
    return ""

def restore_html_pages(folder_path, db_path=None):
    """
    遍历数据库中的资源，寻找 .html-xxx.js 的包装文件并还原
    数据来源:
    1. response_log 表: 实际请求到的响应内容
    2. step2_js_cache 表: JS缓存文件
    3. step2_dynamic_js_paths 表: 动态导入的JS路径（需要读取本地文件）
    """
    import sqlite3
    if not db_path or not os.path.exists(db_path):
        return []

    restored_results = []
    output_dir = os.path.join(folder_path, "restored_pages")
    processed_urls = set()  # 去重
    
    conn = sqlite3.connect(db_path, timeout=60)
    
    # 尝试获取基准URL
    target_base_url = ""
    try:
        cur = conn.execute("SELECT original_url FROM meta_target_info LIMIT 1")
        row = cur.fetchone()
        if row:
            target_base_url = row[0]
            if '?' in target_base_url: target_base_url = target_base_url.split('?')[0]
            if not target_base_url.endswith('/') and not target_base_url.endswith(('.html', '.htm')):
                 target_base_url += '/'
            elif '/' in target_base_url:
                 target_base_url = target_base_url.rsplit('/', 1)[0] + '/'
    except Exception:
        pass
        
    try:
        # 数据源1: 从 response_log 中查找疑似包装文件的记录
        try:
            cur = conn.execute("SELECT url, response FROM response_log WHERE url LIKE '%.html-%.js%'")
            rows = cur.fetchall()
            for url, content in rows:
                if not content or url in processed_urls:
                    continue
                processed_urls.add(url)
                
                restored_html = extract_html_from_js(content)
                if restored_html and len(restored_html) > 100:
                    if not os.path.exists(output_dir):
                        os.makedirs(output_dir)
                    # 生成本地文件名，通过安全解码修复乱码
                    try:
                        basename = decode_path_safely(os.path.basename(url))
                    except Exception:
                        basename = os.path.basename(url)
                    safe_name = re.sub(r'[<>:"/\\|?*]', '_', basename)
                    if not safe_name.endswith('.html'):
                        safe_name = safe_name.replace('.js', '') + '.html'
                    
                    local_path = os.path.join(output_dir, safe_name)
                    with open(local_path, 'w', encoding='utf-8') as f:
                        f.write(restored_html)
                    
                    comp_url = decode_path_safely(url)
                    if target_base_url and not comp_url.startswith(('http://', 'https://')):
                         from urllib.parse import urljoin, quote
                         try:
                            comp_url = urljoin(target_base_url, comp_url)
                            parts = comp_url.split('://', 1)
                            if len(parts) == 2:
                                s, r = parts
                                h, p = r.split('/', 1)
                                comp_url = f"{s}://{h}/{quote(p)}"
                         except Exception: pass
                        
                    restored_results.append({
                        "source_url": comp_url,
                        "local_path": local_path,
                        "html_content": restored_html,
                        "filename": safe_name
                    })
        except Exception as e:
            print(f"[!] 扫描response_log失败: {e}")
        
        # 数据源2: 从 step2_js_cache 中查找
        try:
            cur = conn.execute("SELECT url, path FROM step2_js_cache WHERE url LIKE '%.html-%.js%'")
            rows = cur.fetchall()
            for url, local_file in rows:
                if not local_file or url in processed_urls:
                    continue
                if not os.path.isfile(local_file):
                    continue
                processed_urls.add(url)
                
                try:
                    with open(local_file, 'r', encoding='utf-8') as f:
                        content = f.read()
                except:
                    continue
                    
                restored_html = extract_html_from_js(content)
                if restored_html and len(restored_html) > 100:
                    if not os.path.exists(output_dir):
                        os.makedirs(output_dir)
                    try:
                        basename = decode_path_safely(os.path.basename(url))
                    except Exception:
                        basename = os.path.basename(url)
                    safe_name = re.sub(r'[<>:"/\\|?*]', '_', basename)
                    if not safe_name.endswith('.html'):
                        safe_name = safe_name.replace('.js', '') + '.html'
                    
                    local_path = os.path.join(output_dir, safe_name)
                    with open(local_path, 'w', encoding='utf-8') as f:
                        f.write(restored_html)
                    
                    comp_url = decode_path_safely(url)
                    if target_base_url and not comp_url.startswith(('http://', 'https://')):
                         from urllib.parse import urljoin, quote
                         try:
                            comp_url = urljoin(target_base_url, comp_url)
                            parts = comp_url.split('://', 1)
                            if len(parts) == 2:
                                s, r = parts
                                h, p = r.split('/', 1)
                                comp_url = f"{s}://{h}/{quote(p)}"
                         except Exception: pass
                        
                    restored_results.append({
                        "source_url": comp_url,
                        "local_path": local_path,
                        "html_content": restored_html,
                        "filename": safe_name
                    })
        except Exception as e:
            print(f"[!] 扫描step2_js_cache失败: {e}")
        
        # 数据源3: 从 step2_dynamic_js_paths 获取路径，尝试在本地js目录中查找
        try:
            cur = conn.execute("SELECT path FROM step2_dynamic_js_paths WHERE path LIKE '%.html-%.js%'")
            paths = [r[0] for r in cur.fetchall()]
            
            js_dir = os.path.join(folder_path, "js")
            if not os.path.isdir(js_dir):
                js_dir = os.path.join(folder_path, "js_cache")
            
            for rel_path in paths:
                if rel_path in processed_urls:
                    continue
                processed_urls.add(rel_path)
                
                # 尝试在js目录中找到对应文件
                # rel_path 可能是 ./xxx.html-abc.js，需要转换
                filename = os.path.basename(rel_path)
                # 在js目录下搜索
                found_file = None
                for root, _, files in os.walk(js_dir):
                    if filename in files:
                        found_file = os.path.join(root, filename)
                        break
                
                if not found_file:
                    continue
                    
                try:
                    with open(found_file, 'r', encoding='utf-8') as f:
                        content = f.read()
                except:
                    continue
                    
                restored_html = extract_html_from_js(content)
                if restored_html and len(restored_html) > 100:
                    if not os.path.exists(output_dir):
                        os.makedirs(output_dir)
                    try:
                        basename = decode_path_safely(filename)
                    except Exception:
                        basename = filename
                    safe_name = re.sub(r'[<>:"/\\|?*]', '_', basename)
                    if not safe_name.endswith('.html'):
                        safe_name = safe_name.replace('.js', '') + '.html'
                    
                    local_path = os.path.join(output_dir, safe_name)
                    with open(local_path, 'w', encoding='utf-8') as f:
                        f.write(restored_html)
                        
                    comp_url = decode_path_safely(rel_path)
                    if target_base_url and not comp_url.startswith(('http://', 'https://')):
                         from urllib.parse import urljoin, quote
                         try:
                            comp_url = urljoin(target_base_url, comp_url)
                            parts = comp_url.split('://', 1)
                            if len(parts) == 2:
                                s, r = parts
                                h, p = r.split('/', 1)
                                comp_url = f"{s}://{h}/{quote(p)}"
                         except Exception: pass

                    restored_results.append({
                        "source_url": comp_url,
                        "local_path": local_path,
                        "html_content": restored_html,
                        "filename": safe_name
                    })
        except Exception as e:
            print(f"[!] 扫描step2_dynamic_js_paths失败: {e}")
                    
        # 存入数据库
        if restored_results:
            conn.execute("CREATE TABLE IF NOT EXISTS step8_restored_html (url TEXT, local_path TEXT, content TEXT, filename TEXT)")
            conn.execute("DELETE FROM step8_restored_html")
            conn.executemany("INSERT INTO step8_restored_html VALUES (?,?,?,?)", 
                             [(r['source_url'], r['local_path'], r['html_content'], r['filename']) for r in restored_results])
            conn.commit()
            print(f"[+] 成功还原 {len(restored_results)} 个 HTML 包装页面到 {output_dir}")
    except Exception as e:
        print(f"[!] HTML 还原失败: {e}")
    finally:
        conn.close()
        
    return restored_results

