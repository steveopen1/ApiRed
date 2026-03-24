"""
DOM XSS Taint Analysis Module
DOM XSS 静态污点分析模块
参考 FLUX v3.0 DOM XSS 检测实现
追踪 source (location.hash) 到 sink (innerHTML) 的数据流
"""

import re
import logging
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class TaintFlow:
    """污点流"""
    source: str
    sink: str
    path: str
    severity: str


class DOMXSSTainter:
    """
    DOM XSS 静态污点分析器
    
    检测 source-to-sink 数据流：
    Source: location, location.hash, location.search, document.URL, etc.
    Sink: innerHTML, outerHTML, document.write, eval, setTimeout, etc.
    """
    
    SOURCES = [
        'location',
        'location.hash',
        'location.href',
        'location.search',
        'location.pathname',
        'document.URL',
        'document.documentURI',
        'document.referrer',
        'window.name',
        'sessionStorage',
        'localStorage',
        'history.pushState',
        'history.replaceState',
        'postMessage',
    ]
    
    SINK_PATTERNS = {
        'innerHTML': [
            (r'\.innerHTML\s*=', 'DOM XSS: innerHTML 赋值 location 类 source'),
            (r'\{\{[^}]*\}\}', 'DOM XSS: 模板中的双花括号'),
        ],
        'outerHTML': [
            (r'\.outerHTML\s*=', 'DOM XSS: outerHTML 赋值'),
        ],
        'document.write': [
            (r'document\.write\s*\([^)]+\)', 'DOM XSS: document.write'),
        ],
        'eval': [
            (r'eval\s*\([^)]+(?:location|hash|search)[^)]*\)', 'DOM XSS: eval 使用 location'),
            (r'eval\s*\([^)]+\)', 'DOM XSS: eval 可能的注入点'),
        ],
        'setTimeout': [
            (r'setTimeout\s*\([^)]+(?:location|hash)[^)]+', 'DOM XSS: setTimeout 使用 location'),
        ],
        'setInterval': [
            (r'setInterval\s*\([^)]+(?:location|hash)[^)]+', 'DOM XSS: setInterval 使用 location'),
        ],
        'script.src': [
            (r'\.src\s*=\s*[^"\';]+(?:location|hash|search)', 'DOM XSS: script.src 使用 location'),
        ],
        'script.textContent': [
            (r'\.textContent\s*=\s*[^"\';]+(?:location|hash)', 'DOM XSS: script.textContent 使用 location'),
        ],
        'jq_html': [
            (r'\$\([^)]+\)\.html\s*\([^)]+(?:location|hash)', 'DOM XSS: jQuery .html() 使用 location'),
            (r'\.html\s*\([^)]+(?:location|hash)', 'DOM XSS: .html() 使用 location'),
        ],
    }
    
    SAFE_PATTERNS = [
        r'["\'][^"\']*encodeURI(?:Component)?\s*\(',
        r'["\'][^"\']*escape\s*\(',
        r'["\'][^"\']*\.replace\s*\([^)]*["\'][^)]*["\']',
        r'["\'][^"\']*template literal',
        r'\$强劲',
    ]
    
    def __init__(self):
        self.findings: List[TaintFlow] = []
        self.js_source_patterns = self._compile_source_patterns()
    
    def _compile_source_patterns(self) -> List[re.Pattern]:
        """编译 source 匹配模式"""
        patterns = [
            r'(?:window\.)?location(?:(?:\.hash)|(?:\.href)|(?:\.search)|(?:\.pathname))?',
            r'document\.URL',
            r'document\.documentURI',
            r'document\.referrer',
            r'window\.name',
            r'(?:session|local)Storage',
            r'history\.pushState',
            r'history\.replaceState',
        ]
        return [re.compile(p, re.IGNORECASE) for p in patterns]
    
    def analyze(self, js_content: str) -> List[TaintFlow]:
        """
        分析 JavaScript 代码中的 DOM XSS
        
        Args:
            js_content: JavaScript 代码
            
        Returns:
            List[TaintFlow]: 发现的污点流
        """
        self.findings.clear()
        
        source_positions = self._find_sources(js_content)
        
        for source, source_pos in source_positions:
            sinks = self._find_sinks_after_position(js_content, source_pos)
            for sink, sink_pattern in sinks:
                path = self._extract_path_between(js_content, source_pos, sink)
                if path and not self._is_safe_path(path):
                    flow = TaintFlow(
                        source=source,
                        sink=sink,
                        path=path,
                        severity='high'
                    )
                    self.findings.append(flow)
                    logger.warning(f"DOM XSS: {source} -> {sink}")
        
        return self.findings
    
    def _find_sources(self, content: str) -> List[Tuple[str, int]]:
        """查找所有 source 及其位置"""
        sources = []
        
        for pattern in self.js_source_patterns:
            for match in pattern.finditer(content):
                sources.append((match.group(), match.start()))
        
        location_refs = re.finditer(r'\blocation\b(?!\s*\[)', content)
        for match in location_refs:
            sources.append(('location', match.start()))
        
        hash_refs = re.finditer(r'\blocation\.hash\b', content)
        for match in hash_refs:
            sources.append(('location.hash', match.start()))
        
        return sorted(sources, key=lambda x: x[1])
    
    def _find_sinks_after_position(self, content: str, source_pos: int) -> List[Tuple[str, str]]:
        """查找 source 位置之后的 sink"""
        sinks = []
        remaining = content[source_pos:]
        
        for sink_type, patterns in self.SINK_PATTERNS.items():
            for pattern, description in patterns:
                for match in re.finditer(pattern, remaining):
                    sinks.append((f'{sink_type}: {description}', description))
                    break
        
        return sinks
    
    def _extract_path_between(self, content: str, source_pos: int, sink_pos: int) -> str:
        """提取 source 和 sink 之间的代码路径"""
        start = max(0, source_pos - 50)
        end = min(len(content), source_pos + 500)
        return content[start:end]
    
    def _is_safe_path(self, path: str) -> bool:
        """检查路径是否是安全的"""
        for pattern in self.SAFE_PATTERNS:
            if re.search(pattern, path):
                return True
        return False
    
    def get_all_findings(self) -> List[TaintFlow]:
        """获取所有发现"""
        return self.findings


class DOMXSSScanner:
    """
    DOM XSS 扫描器
    
    便捷接口，扫描 JavaScript 代码中的 DOM XSS
    """
    
    def __init__(self):
        self.analyzer = DOMXSSTainter()
    
    def scan(self, js_content: str) -> List[Dict[str, Any]]:
        """
        扫描 JavaScript 代码
        
        Args:
            js_content: JavaScript 代码
            
        Returns:
            List[Dict]: 发现的问题列表
        """
        flows = self.analyzer.analyze(js_content)
        
        results = []
        for flow in flows:
            results.append({
                'type': 'DOM_XSS',
                'source': flow.source,
                'sink': flow.sink,
                'path': flow.path[:200] + '...' if len(flow.path) > 200 else flow.path,
                'severity': flow.severity,
                'evidence': f'{flow.source} -> {flow.sink}'
            })
        
        return results


def scan_dom_xss(js_content: str) -> List[Dict[str, Any]]:
    """
    便捷函数：扫描 DOM XSS
    """
    scanner = DOMXSSScanner()
    return scanner.scan(js_content)
