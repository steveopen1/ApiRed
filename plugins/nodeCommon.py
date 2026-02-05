import os
import re
import uuid
import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin
import ipaddress
import requests
import json
import time
from queue import Queue, Empty
import sqlite3
import hashlib
import json
import uuid
import datetime
import threading
from time import strftime,gmtime
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from tldextract import tldextract

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import datetime
import logging
from urllib.parse import urlparse
import threading
import json
from traceback import print_exc

TIMEOUT = 30

# 完善黑名单功能
apiRootBlackList=["\\","#","$","@","*","+","-","|","!","%","^","~","[","]"]#api根黑名单，这里的值不可能出现在根API 起始值 中
apiRootBlackListDuringSpider=[x for x in apiRootBlackList if x!="#"]#过滤爬取中 api根

urlblacklist=[".js?", ".css?", ".jpeg?", ".jpg?", ".png?", ".gif?", "github.com", "www.w3.org", "example.com","example.org", "<", ">", "{", "}", "[", "]", "|", "^", ";", "/js/", "location.href", "javascript:void"]

fileExtBlackList=["exe","apk","mp4","mkv","mp3","flv","js","css","less","woff","vue","svg","png","jpg","jpeg","tif","bmp","gif","psd","exif","fpx","avif","apng","webp","swf",",","ico","svga","html","htm","shtml","ts","eot","lrc","tpl","cur","success","error","complete",]
urlextblacklist=["."+x if not x.startswith(",") else x for x in fileExtBlackList]

self_api_path = ['add', 'ls', 'focus', 'calc', 'download', 'bind', 'execute', 'logininfo', 'create', 'decrypt', 'new', 'update', 'click', 'shell', 'export', 'menu', 'retrieve', 'message', 'admin', 'calculate', 'append', 'check', 'crypt', 'rename', 'exec', 'detail', 'clone', 'query', 'verify', 'authenticate', 'move', 'toggle', 'make', 'modify', 'upload', 'help', 'demo', 'alert', 'mode', 'gen', 'msg', 'edit', 'vrfy', 'enable', 'run', 'open', 'post', 'proxy', 'subtract', 'initiate', 'read', 'encrypt', 'auth', 'snd', 'view', 'save', 'config', 'get', 'alter', 'forceLogout', 'build', 'list', 'show', 'online', 'test', 'pull', 'notice',  'change', 'put', 'status', 'search', 'mod', 'send', 'load', ]

# staticUrl_exts = ['.html', '.htm', '.jsp', '.jspx', '.asp', '.aspx', '.php']
staticExtBlackList=["pdf","docx","doc", "exe","apk","mp4","mkv","mp3","flv","css","less","woff","vue","svg","png","jpg","jpeg","tif","bmp","gif","psd","exif","fpx","avif","apng","webp","swf","ico","svga","ts","eot","lrc","tpl","cur","success","error","complete","zip","rar","7z"]
staticUrlExtBlackList=[f".{ext}" for ext in staticExtBlackList]

staticFileExtBlackList = ["pdf","docx","doc", "exe","apk","mp4","mkv","mp3","flv","css","less","woff","vue","svg","png","jpg","jpeg","tif","bmp","gif","psd","exif","fpx","avif","apng","webp","swf","ico","svga","ts","eot","lrc","tpl","cur","success","error","complete",]
staticFileExtBlackList = [f".{ext}" for ext in staticFileExtBlackList]



#移除敏感高危接口  delete remove drop update shutdown restart
#todo 这里需要修改为在api中判断而不是在url中，域名中有可能出现列表中的值
#todo 识别非webpack站点，仅输出js信息 输出匹配敏感信息?
dangerApiList=["del","delete","insert","logout","remove","drop","shutdown","stop","poweroff","restart","rewrite","terminate","deactivate","halt","disable"]

requestMethodRegex = [
    {"regex": r'request method\s\'get\'\snot supported', "tag": "missing", "desc": "method not supported"},
    {"regex": r'request method\s\'post\'\snot supported', "tag": "missing", "desc": "method not supported"},
    {"regex": r'invalid request method', "tag": "missing", "desc": "method not supported"},
    {"regex":r'不支持get请求方法，支持以下post',"tag":"missing","desc":"不支持的方法"},
    {"regex":r'(不支持\w*?(请求)|(方式)|(方法))',"tag":"missing","desc":"不支持的方法"},
]

#todo 扩充参数缺失关键字库
missingRegex=[
            {"regex":r'参数.+不能为空',"tag":"missing","desc":"参数不能为空"},
            {"regex":r'不能为空',"tag":"missing","desc":"参数不能为空"},
            {"regex":r'缺少参数',"tag":"missing","desc":"缺少参数"},
            {"regex":r'is missing',"tag":"missing","desc":"is missing"},
            {"regex":r'parameter.+is not present',"tag":"missing","desc":"is not present"},
            {"regex":r'参数缺失',"tag":"missing","desc":"参数缺失"},
            {"regex":r'参数异常',"tag":"missing","desc":"参数异常"},
            {"regex":r'参数错误',"tag":"missing","desc":"参数错误"},
            {"regex":r'参数不完整',"tag":"missing","desc":"参数不完整"},
            {"regex":r'非法的?参数',"tag":"missing","desc":"非法参数"},
        ]

# 配置日志记录器
logging.basicConfig(filename='ChkApi.log', level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# 创建一个日志记录器
logger = logging.getLogger('my_logger')

# logger.debug('这是一个调试信息')
# logger.info('这是一个信息')
# logger.warning('这是一个警告')
# logger.error('这是一个错误')
# logger.critical('这是一个严重错误')

# base url中禁止出现下面的根域名
BLACK_DOMAIN = ['127.0.0.1']
# base url中的host禁止出现下面的聂荣
BLACK_URL = ['127.0.0.1']

# 响应包禁止出现的内容
# BLACK_TEXT = ['''<RecommendDoc>https://api.aliyun.com''', 'FAIL_SYS_API_NOT_FOUNDED::请求API不存在', '"未找到API注册信息"', '"miss header param x-ca-key"', '"message":"No message available"']
BLACK_TEXT = ['''<RecommendDoc>https://api.aliyun.com''', '''<Code>MethodNotAllowed</Code>''', '<Code>AccessDenied</Code>',
              'FAIL_SYS_API_NOT_FOUNDED::请求API不存在', '"未找到API注册信息"', '"status":400,', '"status":403', '"msg":"参数错误"',
              '"miss header param x-ca-key"', '"message":"No message available"', '"code":1003,"message":"The specified token is expired or invalid."',
              '{"csrf":"', '"status":401,"error":"Unauthorized"', '''"Request method 'POST' not supported"''', '"error":"Internal Server Error"',
              '"code":"HttpRequestMethodNotSupported"', '"accessErrorId"', '<status>403</status>', '"code":"AUTHX_01002"']


webChatBotOpen = True          # 开启微信机器人

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.75 Safari/537.36",
}
headers_post_data = {
    "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.75 Safari/537.36",
    # "Content-Type": "application/x-www-form-urlencoded",
}
headers_post_json = {
    "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.75 Safari/537.36",
    "Content-Type": "application/json",
}

# 打印内容并保存到日志里
def logger_print_content(content):
    print(content)
    logger.info(content)

def get_current_ts():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def get_current_ts_safe():
    return datetime.datetime.now().strftime("%Y-%m-%d %H-%M-%S")

def getCurrentTime():
    return datetime.datetime.now().strftime("%Y-%m-%d")

def getCurrentTime2():
    return datetime.datetime.now().strftime('%Y_%m_%d_%H_%M_%S')

def get_request_headers(cookies=None, content_type=None):
    h = headers.copy()
    if cookies:
        h['Cookie'] = cookies
    if content_type:
        h['Content-Type'] = content_type
    return h

class DatabaseWriter:
    def __init__(self, db_path):
        self.db_path = db_path
        self.queue = Queue()
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=OFF;")
        conn.execute("PRAGMA cache_size=-64000;")
        conn.execute("PRAGMA temp_store=MEMORY;")
        
        batch_req = []
        batch_resp = []
        batch_files = []
        last_commit = time.time()
        
        while self.running or not self.queue.empty():
            try:
                task = self.queue.get(timeout=0.1)
                if task[0] == 'req': batch_req.append(task[1])
                elif task[0] == 'resp': batch_resp.append(task[1])
                elif task[0] == 'file': batch_files.append(task[1])
                
                if len(batch_req) + len(batch_resp) + len(batch_files) >= 1000:
                    self._commit(conn, batch_req, batch_resp, batch_files)
                    batch_req, batch_resp, batch_files = [], [], []
                    last_commit = time.time()
            except Empty:
                if (batch_req or batch_resp or batch_files) and time.time() - last_commit > 2:
                    self._commit(conn, batch_req, batch_resp, batch_files)
                    batch_req, batch_resp, batch_files = [], [], []
                    last_commit = time.time()
                continue
            except Exception: pass
        self._commit(conn, batch_req, batch_resp, batch_files)
        conn.close()

    def _commit(self, conn, reqs, resps, files):
        try:
            if reqs: conn.executemany("INSERT OR REPLACE INTO request_log(id,url,method,headers,cookies,timestamp,is_no_param,referer_url,body) VALUES(?,?,?,?,?,?,?,?,?)", reqs)
            if resps:
                try:
                    conn.executemany("INSERT INTO response_log(id,url,method,res_code,res_type,response,timestamp,format,file_path,is_no_param,response_headers) VALUES(?,?,?,?,?,?,?,?,?,?,?)", resps)
                except Exception:
                    conn.executemany("INSERT INTO response_log(id,url,method,res_code,res_type,response,timestamp,format,file_path,is_no_param) VALUES(?,?,?,?,?,?,?,?,?,?)", [tuple(r[:10]) for r in resps])
            if files: conn.executemany("INSERT OR IGNORE INTO response_files(method,url,file_path,content_hash,length,request_id) VALUES(?,?,?,?,?,?)", files)
            conn.commit()
        except Exception: pass

    def add_req(self, data): self.queue.put(('req', data))
    def add_resp(self, data): self.queue.put(('resp', data))
    def add_file(self, data): self.queue.put(('file', data))
    def stop(self):
        self.running = False
        if self.thread.is_alive(): self.thread.join()

def _infer_content_type_by_body(text):
    try:
        s = (text or "")
        if not isinstance(s, str):
            s = str(s)
        t = s.lstrip()
        if not t:
            return ""
        if t.startswith(")]}',"):
            t = t.split("\n", 1)[-1].lstrip()
        if t.startswith("{") or t.startswith("["):
            try:
                json.loads(t)
                return "application/json"
            except Exception:
                pass
        tl = t.lower()
        if tl.startswith("<!doctype html") or "<html" in tl[:2048]:
            return "text/html"
        if tl.startswith("<?xml") or ("<" in t[:32] and ">" in t[:128]):
            try:
                import xml.etree.ElementTree as ET
                ET.fromstring(t[:200000])
                return "application/xml"
            except Exception:
                pass
        return "text/plain"
    except Exception:
        return ""

def record_req_resp_unified(db_writer, config, folder_path, api_url, method, headers_map, cookies, text, res_code, res_type, is_no_param, referer_url, file_path, body=None, response_headers=None):
    """
    统一采集核心：不再向磁盘写入 Response 内容文件。
    将所有数据流向数据库。
    """
    try:
        rid = str(uuid.uuid4())
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        m = str(method or "").upper()
        if m in ("GET", "HEAD"):
            body = ""
        ct = str(res_type or "").strip()
        rh = response_headers
        if rh is None:
            rh = {}
        try:
            if hasattr(rh, "items"):
                rh = dict(rh)
        except Exception:
            rh = {}
        if not ct:
            ct = str((rh or {}).get("Content-Type") or "").strip()
        inferred_ct = ""
        if not ct:
            inferred_ct = _infer_content_type_by_body(text)
            ct = inferred_ct
        else:
            low = ct.lower()
            if ("text/plain" in low) or ("application/octet-stream" in low):
                inferred_ct = _infer_content_type_by_body(text)
                if inferred_ct and inferred_ct != "text/plain":
                    ct = inferred_ct
        fmt = 'json' if ('json' in str(ct).lower()) else ('xml' if ('xml' in str(ct).lower()) else 'text')
        
        # 即使入参有 file_path (旧逻辑遗留)，我们也统一使用原始 api_url 作为标识
        log_url = api_url
        rh_json = ""
        try:
            rh_json = json.dumps(rh or {}, ensure_ascii=False)
        except Exception:
            rh_json = ""
        
        if db_writer:
            # 1. 记录请求头信息
            db_writer.add_req((rid, log_url, method, json.dumps(headers_map, ensure_ascii=False), cookies or "", ts, 1 if is_no_param else 0, referer_url, body or ""))
            # 2. 记录完整响应体到数据库 (text 字段)
            db_writer.add_resp((rid, log_url, method, int(res_code), str(ct or ''), text or "", ts, fmt, file_path or "", 1 if is_no_param else 0, rh_json))
            
            # 响应包去重逻辑 (使用哈希进行增量记录)
            if text:
                h = hashlib.sha256((text).encode("utf-8", errors="ignore")).hexdigest()
                db_writer.add_file((method, log_url, file_path or "", h, len(text), rid))
        return rid
    except Exception: return None



# 列表分割
def batch(iterable, n=1):
    l = len(iterable)
    for ndx in range(0, l, n):
        yield iterable[ndx:min(ndx + n, l)]


def check_url_alive(url):
    try:
        GlobalRequestCounter.increment()
        requests.get(url=url, headers=headers, timeout=10, proxies=None, verify=False)
        return True
    except Exception as e:
        return False

# 去重并保持有序
def remove_duplicates(lst):
    # Using dict.fromkeys() to remove duplicates and maintain order
    return list(dict.fromkeys(lst))

def list_files(directory):
    all_files = []  # 创建一个新的列表来存储结果
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.startswith(('GET', 'POST')):
                full_path = os.path.join(root, file)
                # print(full_path)
                all_files.append(full_path)
    return all_files


def is_blacklisted(url):
    """
    检查 URL 的根域名是否在黑名单中。

    参数:
    url (str): 要检查的 URL。
    black_domains (list): 域名黑名单。

    返回:
    bool: 如果域名在黑名单中返回 True，否则返回 False。
    """
    parsed_domain = tldextract.extract(url)
    if parsed_domain.suffix:
        domain = f"{parsed_domain.domain}.{parsed_domain.suffix}"
    # 127.0.0.1
    else:
        domain = f"{parsed_domain.domain}"

    if domain in BLACK_DOMAIN:
        return True

    url_parse = urlparse(url)
    netloc = url_parse.netloc
    for blackurl in BLACK_URL:
        if blackurl in netloc:
            return True

    return False


def save_response_to_file(file_path, text):
    try:
        with open(file_path, 'wt', encoding='utf-8') as f:
            f.write(text if isinstance(text, str) else str(text))
    except Exception:
        pass

def _reason_phrase(code):
    try:
        c = int(code)
    except Exception:
        return "UNKNOWN"
    m = {
        200: "OK",
        201: "CREATED",
        202: "ACCEPTED",
        204: "NO CONTENT",
        301: "MOVED PERMANENTLY",
        302: "FOUND",
        304: "NOT MODIFIED",
        400: "BAD REQUEST",
        401: "UNAUTHORIZED",
        403: "FORBIDDEN",
        404: "NOT FOUND",
        405: "METHOD NOT ALLOWED",
        409: "CONFLICT",
        415: "UNSUPPORTED MEDIA TYPE",
        422: "UNPROCESSABLE ENTITY",
        429: "TOO MANY REQUESTS",
        500: "INTERNAL SERVER ERROR",
        502: "BAD GATEWAY",
        503: "SERVICE UNAVAILABLE",
        504: "GATEWAY TIMEOUT",
    }
    return m.get(c, "UNKNOWN")

def _to_header_items(h):
    try:
        if h is None:
            return []
        if hasattr(h, "items"):
            return list(h.items())
        if isinstance(h, dict):
            return list(h.items())
        return []
    except Exception:
        return []

def format_http_log(method, url, req_headers, req_body, res_status, res_headers, res_body):
    try:
        from urllib.parse import urlparse
        u = urlparse(url or "")
        path = (u.path or "/") + (("?" + u.query) if u.query else "")
        host = u.netloc or ""
    except Exception:
        path = str(url or "")
        host = ""
    m = str(method or "GET").upper()

    req_lines = [f"{m} {path} HTTP/1.1"]
    if host:
        req_lines.append(f"Host: {host}")
    seen = set()
    for k, v in _to_header_items(req_headers):
        if not k:
            continue
        lk = str(k).lower()
        if lk == "host":
            continue
        if lk in seen:
            continue
        seen.add(lk)
        req_lines.append(f"{k}: {v}")
    rb = "" if req_body is None else str(req_body)
    if rb:
        try:
            clen = len(rb.encode("utf-8", errors="ignore"))
            if "content-length" not in seen:
                req_lines.append(f"Content-Length: {clen}")
        except Exception:
            pass
    req_raw = "\n".join(req_lines) + "\n\n" + rb

    code = res_status
    reason = _reason_phrase(code)
    res_lines = [f"HTTP/1.1 {code} {reason}"]
    seen2 = set()
    for k, v in _to_header_items(res_headers):
        if not k:
            continue
        lk = str(k).lower()
        if lk in seen2:
            continue
        seen2.add(lk)
        res_lines.append(f"{k}: {v}")
    body = "" if res_body is None else str(res_body)
    if body:
        try:
            clen = len(body.encode("utf-8", errors="ignore"))
            if "content-length" not in seen2:
                res_lines.append(f"Content-Length: {clen}")
        except Exception:
            pass
    res_raw = "\n".join(res_lines) + "\n\n" + body

    return req_raw + "\n" + "=" * 50 + "\n" + res_raw

def is_domain(s):
    domain_regex = r'^(?!\d+\.\d+\.\d+\.\d+$)([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\.?$'
    match = re.match(domain_regex, s)
    if match:
        return True
    return False


# 判断是否是IP
def is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False

def decode_path_safely(path):
    """
    安全解码路径，支持多种编码场景：
    1. URL编码（%XX）
    2. Unicode转义（\\uXXXX）
    3. 错误编码的UTF-8字节（如 ç®€ä»‹ -> 简介）
    4. 修复 CP1252 解码产生的 U+FFFD 损坏
    """
    if not path or not isinstance(path, str):
        return path
    
    result = path
    try:
        # 1. 首先尝试URL解码
        from urllib.parse import unquote
        decoded_url = unquote(result)
        if decoded_url != result:
            result = decoded_url
        
        # 2. 处理 Unicode 转义序列 (如 \\u4f20)
        if '\\u' in result:
            try:
                # Use "unicode_escape" to handle \uXXXX
                result = result.encode('utf-8').decode('unicode_escape')
            except Exception:
                pass
        
        # 3. 检测并修复错误编码的UTF-8
        # 这种情况通常是 UTF-8 字节被错误地识别为了 Latin-1 或 CP1252
        if any(ord(c) > 127 for c in result):
            # 方案A: 尝试 CP1252 逆向 (支持 U+2014 等字符)
            try:
                # 如果包含 U+FFFD (Replacement Character)，说明之前的解码因为字节未定义而失败
                # Windows-1252 未定义字节: 0x81, 0x8D, 0x8F, 0x90, 0x9D
                if '\ufffd' in result:
                    b = bytearray()
                    valid = True
                    for char in result:
                        try:
                            b.extend(char.encode('cp1252'))
                        except UnicodeEncodeError:
                            if char == '\ufffd':
                                b.append(0) # 占位符
                            else:
                                valid = False; break
                    
                    if valid:
                        import itertools
                        undefined_bytes = [0x81, 0x8d, 0x8f, 0x90, 0x9d]
                        zeros = [i for i, x in enumerate(b) if x == 0]
                        # 仅当缺失字节较少时尝试穷举，避免性能问题
                        if zeros and len(zeros) <= 4:
                            for p in itertools.product(undefined_bytes, repeat=len(zeros)):
                                temp_b = bytearray(b)
                                for i, v in zip(zeros, p): temp_b[i] = v
                                try:
                                    fixed = temp_b.decode('utf-8')
                                    return fixed # 成功修复
                                except UnicodeDecodeError:
                                    continue
                
                # 正常 CP1252 逆向
                test_bytes = result.encode('cp1252')
                fixed = test_bytes.decode('utf-8')
                if fixed != result:
                    result = fixed
                    return result
            except Exception:
                pass

            # 方案B: 尝试 Latin-1 逆向 (无损映射 bytes 0-255)
            try:
                test_bytes = result.encode('latin-1')
                fixed = test_bytes.decode('utf-8')
                if fixed != result:
                    result = fixed
            except Exception:
                pass
                
    except Exception:
        pass
    
    return result

# 统计总请求量
class GlobalRequestCounter:
    _instance = None
    _lock = threading.Lock()
    count = 0

    @classmethod
    def increment(cls):
        with cls._lock:
            cls.count += 1
            
    @classmethod
    def get_count(cls):
        with cls._lock:
            return cls.count
