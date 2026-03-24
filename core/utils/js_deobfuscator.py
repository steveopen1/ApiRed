"""
JavaScript Deobfuscation Module
JavaScript 混淆还原模块
参考 FLUX JS 代码混淆还原实现
支持 eval/atob/fromCharCode/Hex/Unicode 解码
"""

import re
import base64
import urllib.parse
import json
import logging
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


class JSDeobfuscator:
    """
    JavaScript 混淆还原器
    
    支持的混淆技术：
    - eval() 字符串执行
    - atob()/btoa() Base64 编解码
    - String.fromCharCode() 字符码转换
    - \\x 十六进制编码
    - \\u Unicode 编码
    - URL 编码
    - 拼接字符串重组
    """
    
    def __init__(self):
        self.max_depth = 5
        self.max_string_length = 10000
    
    def deobfuscate(self, content: str) -> Tuple[str, bool]:
        """
        还原混淆的 JavaScript 代码
        
        Args:
            content: 混淆的 JavaScript 代码
            
        Returns:
            Tuple[str, bool]: (还原后的代码, 是否进行了还原)
        """
        original = content
        depth = 0
        changed = True
        
        while changed and depth < self.max_depth:
            changed = False
            content, was_changed = self._single_pass(content)
            if was_changed:
                changed = True
            depth += 1
        
        return content, content != original
    
    def _single_pass(self, content: str) -> Tuple[str, bool]:
        """单次还原尝试"""
        content, c1 = self._decode_atob(content)
        content, c2 = self._decode_btoa(content)
        content, c3 = self._decode_fromcharcode(content)
        content, c4 = self._decode_hex_escape(content)
        content, c5 = self._decode_unicode_escape(content)
        content, c6 = self._decode_url_encoding(content)
        content, c7 = self._decode_string_concatenation(content)
        
        return content, any([c1, c2, c3, c4, c5, c6, c7])
    
    def _decode_atob(self, content: str) -> Tuple[str, bool]:
        """解码 atob() Base64 编码"""
        pattern = r'atob\(\s*["\']([^"\']+)["\']\s*\)'
        
        def replace_atob(match):
            try:
                encoded = match.group(1)
                decoded = base64.b64decode(encoded).decode('utf-8', errors='ignore')
                if len(decoded) < self.max_string_length:
                    return f'"{decoded}"'
            except Exception:
                pass
            return match.group(0)
        
        new_content = re.sub(pattern, replace_atob, content)
        return new_content, new_content != content
    
    def _decode_btoa(self, content: str) -> Tuple[str, bool]:
        """解码 btoa() Base64 编码 (对编码后的内容进行还原)"""
        pattern = r'btoa\(\s*["\']([^"\']+)["\']\s*\)'
        
        def replace(match):
            try:
                decoded = match.group(1)
                encoded = base64.b64encode(decoded.encode()).decode()
                return f'atob("{encoded}")'
            except Exception:
                pass
            return match.group(0)
        
        new_content = re.sub(pattern, replace, content)
        return new_content, new_content != content
    
    def _decode_fromcharcode(self, content: str) -> Tuple[str, bool]:
        """解码 String.fromCharCode()"""
        pattern = r'String\.fromCharCode\(([^)]+)\)'
        
        def replace(match):
            try:
                args = match.group(1)
                char_codes = [int(x.strip()) for x in args.split(',') if x.strip().isdigit()]
                if char_codes:
                    decoded = ''.join(chr(code) for code in char_codes if 0 <= code <= 1114111)
                    if len(decoded) < self.max_string_length:
                        return f'"{decoded}"'
            except Exception:
                pass
            return match.group(0)
        
        new_content = re.sub(pattern, replace, content)
        return new_content, new_content != content
    
    def _decode_hex_escape(self, content: str) -> Tuple[str, bool]:
        """解码 \\xHH 十六进制转义"""
        pattern = r'\\x([0-9a-fA-F]{2})'
        
        def replace(match):
            try:
                hex_seq = match.group(1)
                char = bytes.fromhex(hex_seq).decode('utf-8', errors='ignore')
                return char
            except Exception:
                return match.group(0)
        
        new_content = re.sub(pattern, replace, content)
        return new_content, new_content != content
    
    def _decode_unicode_escape(self, content: str) -> Tuple[str, bool]:
        """解码 \\uHHHH Unicode 转义"""
        pattern = r'\\u([0-9a-fA-F]{4})'
        
        def replace(match):
            try:
                unicode_seq = match.group(1)
                char = bytes.fromhex(unicode_seq).decode('utf-16-le', errors='ignore')
                return char
            except Exception:
                return match.group(0)
        
        new_content = re.sub(pattern, replace, content)
        return new_content, new_content != content
    
    def _decode_url_encoding(self, content: str) -> Tuple[str, bool]:
        """解码 URL 编码"""
        try:
            new_content = urllib.parse.unquote(content)
            return new_content, new_content != content
        except Exception:
            return content, False
    
    def _decode_string_concatenation(self, content: str) -> Tuple[str, bool]:
        """解码字符串拼接 (e.g., 'foo' + 'bar' -> 'foobar')"""
        pattern = r'["\'](\w+)["\']\s*\+\s*["\'](\w*)["\']'
        
        iterations = 0
        max_iterations = 10
        changed = True
        
        while changed and iterations < max_iterations:
            changed = False
            new_content = re.sub(pattern, self._merge_strings, content)
            if new_content != content:
                changed = True
                content = new_content
            iterations += 1
        
        return content, changed
    
    def _merge_strings(self, match) -> str:
        """合并字符串"""
        return f'"{match.group(1)}{match.group(2)}"'


def deobfuscate_js(content: str) -> str:
    """
    便捷函数：还原 JavaScript 混淆
    
    Args:
        content: 混淆的 JavaScript 代码
        
    Returns:
        str: 还原后的代码
    """
    deobfuscator = JSDeobfuscator()
    result, _ = deobfuscator.deobfuscate(content)
    return result
