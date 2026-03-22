import os
import json
import subprocess
import platform
import tempfile
import re
import signal

LARGE_FILE_THRESHOLD = 500 * 1024
CHUNK_SIZE = 200 * 1024
TIMEOUT_SECONDS = 300

THIRD_PARTY_PATTERNS = [
    r'jquery[\-\.]?\d*[\.\d]*\.min\.js',
    r'bootstrap[\-\.]?\d*[\.\d]*\.min\.js',
    r'vue[\-\.]?\d*[\.\d]*\.min\.js',
    r'react[\-\.]?\d*[\.\d]*\.min\.js',
    r'axios[\-\.]?\d*[\.\d]*\.min\.js',
    r'lodash[\-\.]?\d*[\.\d]*\.min\.js',
    r'echarts[\-\.]?\d*[\.\d]*\.min\.js',
    r'china\.js',
    r'xlsx[\-\.]?\d*[\.\d]*\.min\.js',
    r'swiper[\-\.]?\d*[\.\d]*\.min\.js',
    r'popper[\-\.]?\d*[\.\d]*\.min\.js',
    r'toastr[\-\.]?\d*[\.\d]*\.min\.js',
    r'jstree[\-\.]?\d*[\.\d]*\.min\.js',
    r'select2[\-\.]?\d*[\.\d]*\.min\.js',
    r'summernote[\-\.]?\d*[\.\d]*\.min\.js',
    r'qrcode[\-\.]?\d*[\.\d]*\.min\.js',
    r'xss[\-\.]?\d*[\.\d]*\.min\.js',
    r'adapter[\-\.]?\d*[\.\d]*\.min\.js',
    r'srs[\-\.]?\d*[\.\d]*\.min\.js',
    r'renderer[\-\.]?\d*[\.\d]*\.min\.js',
    r'layui[\-\.]?\d*[\.\d]*\.min\.js',
]

QUICK_API_REGEX = re.compile(
    r'(?:fetch|axios|ajax|\$http|\.get\(|\.post\(|\.put\(|\.delete\()\s*[\'"`](/[^\'"`\s]+)[\'"`\s]',
    re.IGNORECASE
)

QUICK_URL_REGEX = re.compile(
    r'["\']((?:https?:)?//[^\s"\'`]+|/(?:api|callback|rest|service|v\d)[^\s"\'`]*?)["\']',
    re.IGNORECASE
)


class TimeoutError(Exception):
    pass


def timeout_handler(signum, frame):
    raise TimeoutError("AST analysis timeout")


class ASTAnalyzer:
    def __init__(self):
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.parser_script = os.path.join(self.base_dir, 'js_analysis', 'ast_parser.js')
        self.third_party_patterns = [re.compile(p, re.IGNORECASE) for p in THIRD_PARTY_PATTERNS]
        
    def is_third_party_js(self, url):
        """检查是否为第三方库 JS"""
        url_lower = url.lower()
        for pattern in self.third_party_patterns:
            if pattern.search(url_lower):
                return True
        return False
    
    def quick_regex_analysis(self, text, url):
        """快速正则预处理，用于大文件和第三方库"""
        apis = []
        urls = []
        
        for match in QUICK_API_REGEX.finditer(text):
            path = match.group(2)
            if path and len(path) > 1 and len(path) < 500:
                apis.append({
                    'value': path,
                    'type': 'quick_regex',
                    'source': url
                })
        
        for match in QUICK_URL_REGEX.finditer(text):
            found_url = match.group(1)
            if found_url and len(found_url) > 4 and len(found_url) < 500:
                if not found_url.startswith('//'):
                    urls.append({
                        'value': found_url,
                        'type': 'quick_regex',
                        'source': url
                    })
        
        return {'apis': apis, 'urls': urls}
    
    def analyze_file_with_timeout(self, file_path, timeout=TIMEOUT_SECONDS):
        """带超时机制的 AST 分析"""
        if not os.path.exists(file_path):
            return {'error': 'File not found'}
        
        try:
            cmd = ['node', self.parser_script, file_path]
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding='utf-8'
            )
            
            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                return {'error': 'Timeout', 'apis': [], 'urls': []}
            
            if process.returncode != 0 and not stdout:
                return {'error': stderr, 'apis': [], 'urls': []}
            
            if not stdout:
                return {'apis': [], 'urls': []}
            
            try:
                result = json.loads(stdout)
                return result
            except json.JSONDecodeError:
                return {'error': 'Invalid JSON', 'apis': [], 'urls': []}
                
        except Exception as e:
            return {'error': str(e), 'apis': [], 'urls': []}
    
    def analyze_chunk(self, chunk_text, url):
        """分析单个文本分片"""
        try:
            temp_file = None
            try:
                with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.js', encoding='utf-8') as f:
                    f.write(chunk_text)
                    temp_file = f.name
                
                result = self.analyze_file_with_timeout(temp_file, timeout=30)
                return result
            finally:
                if temp_file and os.path.exists(temp_file):
                    try:
                        os.remove(temp_file)
                    except:
                        pass
        except Exception:
            return {'apis': [], 'urls': []}
    
    def analyze_large_file_chunked(self, file_path, url):
        """分片分析大型 JS 文件"""
        try:
            file_size = os.path.getsize(file_path)
            if file_size <= LARGE_FILE_THRESHOLD:
                return self.analyze_file_with_timeout(file_path)
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            total_apis = []
            total_urls = []
            chunk_count = (len(content) + CHUNK_SIZE - 1) // CHUNK_SIZE
            
            for i in range(0, len(content), CHUNK_SIZE):
                chunk = content[i:i + CHUNK_SIZE]
                chunk_num = i // CHUNK_SIZE + 1
                
                result = self.analyze_chunk(chunk, f"{url} [chunk {chunk_num}/{chunk_count}]")
                
                if 'apis' in result:
                    total_apis.extend(result['apis'])
                if 'urls' in result:
                    total_urls.extend(result['urls'])
            
            return {'apis': total_apis, 'urls': total_urls}
        except Exception:
            return {'apis': [], 'urls': []}
    
    def analyze_file(self, file_path, url=None):
        """分析 JS 文件，支持大文件优化"""
        if not os.path.exists(file_path):
            return {'error': 'File not found'}
        
        file_size = os.path.getsize(file_path)
        
        if self.is_third_party_js(file_path):
            return self.quick_regex_analysis_from_file(file_path)
        
        if file_size > LARGE_FILE_THRESHOLD:
            return self.analyze_large_file_chunked(file_path, url or file_path)
        
        return self.analyze_file_with_timeout(file_path)
    
    def quick_regex_analysis_from_file(self, file_path):
        """对文件进行快速正则分析"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            return self.quick_regex_analysis(content, file_path)
        except Exception:
            return {'apis': [], 'urls': []}
    
    def analyze_files_batch(self, file_paths, urls=None):
        """批量分析 JS 文件，优化大文件和第三方库"""
        if not file_paths:
            return []
        
        valid_paths = [(p, urls[i] if urls and i < len(urls) else p) 
                      for i, p in enumerate(file_paths) if os.path.exists(p)]
        
        if not valid_paths:
            return []
        
        results = []
        
        for file_path, url in valid_paths:
            if self.is_third_party_js(url or file_path):
                result = self.quick_regex_analysis_from_file(file_path)
            elif os.path.getsize(file_path) > LARGE_FILE_THRESHOLD:
                result = self.analyze_large_file_chunked(file_path, url)
            else:
                result = self.analyze_file_with_timeout(file_path)
            results.append(result)
        
        return results
