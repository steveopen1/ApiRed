"""
GF Library - Pattern-Based Security Scanner
类似 tomnomnom/gf 的安全扫描模式库

功能:
- 多种模式库 (SQLI, XSS, SSRF, IDOR, etc.)
- 多种输出格式 (JSON, CSV, Text)
- grep 风格 CLI
- stdin/文件输入
- 管道操作支持
- 模式组合和继承
"""

import re
import os
import sys
import json
import csv
import yaml
import argparse
import logging
logger = logging.getLogger(__name__)
from typing import Dict, List, Any, Optional, Callable, Set, Iterator, TextIO
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse


@dataclass
class Pattern:
    """安全扫描模式"""
    name: str
    pattern: str
    severity: str
    description: str = ""
    category: str = "general"
    tags: List[str] = field(default_factory=list)
    false_positive: Optional[str] = None
    _compiled_regex: Optional[re.Pattern] = field(default_factory=None, repr=False)
    _compiled_fp_regex: Optional[re.Pattern] = field(default_factory=None, repr=False)
    
    def __post_init__(self):
        if self._compiled_regex is None:
            try:
                self._compiled_regex = re.compile(self.pattern, re.IGNORECASE | re.DOTALL)
            except re.error:
                self._compiled_regex = None
        if self.false_positive and self._compiled_fp_regex is None:
            try:
                self._compiled_fp_regex = re.compile(self.false_positive, re.IGNORECASE)
            except re.error:
                self._compiled_fp_regex = None
    
    def match(self, text: str) -> Optional[re.Match]:
        """匹配模式"""
        if self._compiled_regex is None:
            return None
        try:
            return self._compiled_regex.search(text)
        except re.error:
            return None
    
    def is_false_positive(self, text: str) -> bool:
        """判断是否为假阳性"""
        if not self.false_positive or self._compiled_fp_regex is None:
            return False
        try:
            return bool(self._compiled_fp_regex.search(text))
        except re.error:
            return False


@dataclass
class Match:
    """匹配结果"""
    pattern_name: str
    matched_text: str
    line_number: int
    line_content: str
    severity: str
    category: str
    context: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'pattern': self.pattern_name,
            'matched': self.matched_text[:100],
            'line': self.line_number,
            'severity': self.severity,
            'category': self.category,
            'context': self.context[:200] if self.context else ''
        }


@dataclass
class ScanResult:
    """扫描结果"""
    file_path: str
    total_lines: int
    total_matches: int
    matches_by_severity: Dict[str, int] = field(default_factory=dict)
    matches_by_category: Dict[str, int] = field(default_factory=dict)
    matches: List[Match] = field(default_factory=list)
    scan_time: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'file': self.file_path,
            'total_lines': self.total_lines,
            'total_matches': self.total_matches,
            'matches_by_severity': self.matches_by_severity,
            'matches_by_category': self.matches_by_category,
            'matches': [m.to_dict() for m in self.matches],
            'scan_time': self.scan_time
        }


class PatternLoader:
    """模式加载器"""
    
    DEFAULT_PATTERNS_DIR = str(Path(__file__).parent.parent.parent / "rules")
    
    def __init__(self, patterns_dir: Optional[str] = None):
        self.patterns_dir = patterns_dir or self.DEFAULT_PATTERNS_DIR
        self._patterns: Dict[str, List[Pattern]] = {}
        self._load_all_patterns()
    
    def _load_all_patterns(self):
        """加载所有模式文件"""
        if not os.path.exists(self.patterns_dir):
            self._load_builtin_patterns()
            return
        
        for filename in os.listdir(self.patterns_dir):
            if filename.endswith('.yaml') or filename.endswith('.yml'):
                category = filename.rsplit('.', 1)[0]
                self._load_yaml_patterns(category, os.path.join(self.patterns_dir, filename))
            elif filename.endswith('.json'):
                category = filename.rsplit('.', 1)[0]
                self._load_json_patterns(category, os.path.join(self.patterns_dir, filename))
    
    def _load_yaml_patterns(self, category: str, filepath: str):
        """从 YAML 加载模式"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            
            patterns = []
            for p in data.get('patterns', []):
                patterns.append(Pattern(
                    name=p.get('name', 'unnamed'),
                    pattern=p.get('pattern', ''),
                    severity=p.get('severity', 'medium'),
                    description=p.get('description', ''),
                    category=category,
                    tags=p.get('tags', []),
                    false_positive=p.get('false_positive')
                ))
            
            self._patterns[category] = patterns
        except Exception as e:
            logger.exception(f"Failed to load {filepath}: {e}")
    
    def _load_json_patterns(self, category: str, filepath: str):
        """从 JSON 加载模式"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            patterns = []
            for p in data.get('patterns', []):
                patterns.append(Pattern(
                    name=p.get('name', 'unnamed'),
                    pattern=p.get('pattern', ''),
                    severity=p.get('severity', 'medium'),
                    description=p.get('description', ''),
                    category=category,
                    tags=p.get('tags', []),
                    false_positive=p.get('false_positive')
                ))
            
            self._patterns[category] = patterns
            logger.debug(f"Loaded {len(patterns)} patterns from {filepath}")
        except Exception as e:
            logger.exception(f"Failed to load {filepath}: {e}")
    
    def _load_builtin_patterns(self):
        """加载内置模式"""
        self._patterns = {
            'sqli': self._get_sqli_patterns(),
            'xss': self._get_xss_patterns(),
            'ssrf': self._get_ssrf_patterns(),
            'idor': self._get_idor_patterns(),
            'auth': self._get_auth_patterns(),
            'ssti': self._get_ssti_patterns(),
            'open_redirect': self._get_redirect_patterns(),
            'cmd_injection': self._get_cmd_patterns(),
        }
    
    def _get_sqli_patterns(self) -> List[Pattern]:
        return [
            Pattern("sqli_union", r"UNION\s+(ALL\s+)?SELECT", "critical", "SQL UNION 注入", "sqli", tags=["sql", "injection"]),
            Pattern("sqli_error", r"(mysql|postgresql|oracle|sqlite).*?error|syntax error", "high", "SQL 错误信息", "sqli", tags=["sql", "error"]),
            Pattern("sqli_boolean", r"(\bor\b|\band\b).*(=|>|<|LIKE)", "high", "布尔盲注", "sqli", tags=["sql", "blind"]),
            Pattern("sqli_time", r"(SLEEP|BENCHMARK|WAITFOR|DELAY)", "high", "时间盲注", "sqli", tags=["sql", "time-based"]),
            Pattern("sqli_comment", r"(--|#|/\*|\*/)", "medium", "SQL 注释", "sqli", tags=["sql"]),
            Pattern("sqli_union_select", r"'\s*OR\s*'1'\s*=\s*'1", "critical", "经典 OR 注入", "sqli", tags=["sql", "classic"]),
        ]
    
    def _get_xss_patterns(self) -> List[Pattern]:
        return [
            Pattern("xss_script", r"<script[^>]*>.*?</script>", "critical", "Script 标签 XSS", "xss", tags=["xss", "stored"]),
            Pattern("xss_img", r"<img[^>]+onerror\s*=", "critical", "Img onerror XSS", "xss", tags=["xss", "reflected"]),
            Pattern("xss_svg", r"<svg[^>]+onload\s*=", "critical", "SVG onload XSS", "xss", tags=["xss"]),
            Pattern("xss_event", r"on\w+\s*=\s*[\"']", "high", "事件处理器 XSS", "xss", tags=["xss"]),
            Pattern("xss_link", r"javascript\s*:", "high", "JavaScript 伪协议", "xss", tags=["xss"]),
            Pattern("xss_iframe", r"<iframe[^>]+src\s*=", "medium", "Iframe 注入", "xss", tags=["xss"]),
        ]
    
    def _get_ssrf_patterns(self) -> List[Pattern]:
        return [
            Pattern("ssrf_localhost", r"localhost|127\.0\.0\.1|0\.0\.0\.0", "high", "本地主机访问", "ssrf", tags=["ssrf"]),
            Pattern("ssrf_metadata", r"169\.254\.169\.254|metadata\.google", "critical", "云元数据服务", "ssrf", tags=["ssrf", "cloud"]),
            Pattern("ssrf_internal", r"10\.\d+|172\.(1[6-9]|2\d|3[01])|192\.168", "high", "内网 IP 访问", "ssrf", tags=["ssrf"]),
            Pattern("ssrf_url", r"url\s*=\s*[\"']?http", "high", "URL 参数", "ssrf", tags=["ssrf"]),
            Pattern("ssrf_redirect", r"(redirect|next|data|channel|page)\s*=\s*http", "medium", "重定向参数", "ssrf", tags=["ssrf"]),
        ]
    
    def _get_idor_patterns(self) -> List[Pattern]:
        return [
            Pattern("idor_user", r"(user|account|profile)[_-]?id\s*=", "high", "用户 ID 参数", "idor", tags=["idor"]),
            Pattern("idor_numeric", r"id\s*=\s*\d+", "medium", "数字 ID 参数", "idor", tags=["idor"]),
            Pattern("idor_order", r"(order|transaction|payment)[_-]?id\s*=", "high", "订单/交易 ID", "idor", tags=["idor", "payment"]),
            Pattern("idor_path", r"/users?/\d+", "high", "路径中的用户 ID", "idor", tags=["idor"]),
            Pattern("idor_admin", r"/(admin|manage|backend)/", "critical", "管理后台路径", "idor", tags=["idor", "admin"]),
        ]
    
    def _get_auth_patterns(self) -> List[Pattern]:
        return [
            Pattern("auth_bearer", r"Bearer\s+[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+", "high", "JWT Token", "auth", tags=["auth", "jwt"]),
            Pattern("auth_basic", r"Basic\s+[a-zA-Z0-9]+=*", "high", "Basic Auth", "auth", tags=["auth"]),
            Pattern("auth_api_key", r"api[_-]?key\s*=\s*['\"]?[a-zA-Z0-9]{20,}", "high", "API Key", "auth", tags=["auth", "apikey"]),
            Pattern("auth_password", r"password\s*=\s*['\"]?[^\s&']+", "critical", "密码泄露", "auth", tags=["auth", "password"], false_positive="placeholder|example|test"),
        ]
    
    def _get_ssti_patterns(self) -> List[Pattern]:
        return [
            Pattern("ssti_jinja", r"{{.*?}}", "high", "Jinja2 模板注入", "ssti", tags=["ssti", "template"]),
            Pattern("ssti_twig", r"{{.*?}}|{%.*?%}", "high", "Twig 模板注入", "ssti", tags=["ssti", "template"]),
            Pattern("ssti_erb", r"<%.*?%>", "high", "ERB 模板注入", "ssti", tags=["ssti", "template"]),
        ]
    
    def _get_redirect_patterns(self) -> List[Pattern]:
        return [
            Pattern("redirect_param", r"(redirect|return|next|url|dest|callback)\s*=\s*http", "medium", "重定向参数", "open_redirect", tags=["redirect"]),
            Pattern("redirect_slash", r"//[a-zA-Z0-9]", "high", "协议 Relative 跳转", "open_redirect", tags=["redirect"]),
            Pattern("redirect_meta", r"<meta[^>]+url\s*=", "medium", "Meta 标签跳转", "open_redirect", tags=["redirect"]),
        ]
    
    def _get_cmd_patterns(self) -> List[Pattern]:
        return [
            Pattern("cmd_pipe", r"[|;]\s*(cat|ls|echo|wget|curl|nc)", "critical", "命令注入管道", "cmd_injection", tags=["command"]),
            Pattern("cmd_backtick", r"`[^`]+`", "high", "反引号命令执行", "cmd_injection", tags=["command"]),
            Pattern("cmd_substitution", r"\$\([^)]+\)", "high", "$() 命令替换", "cmd_injection", tags=["command"]),
        ]
    
    def get_patterns(self, category: Optional[str] = None) -> List[Pattern]:
        """获取模式"""
        if category:
            return self._patterns.get(category, [])
        all_patterns = []
        for patterns in self._patterns.values():
            all_patterns.extend(patterns)
        return all_patterns
    
    def get_categories(self) -> List[str]:
        """获取所有分类"""
        return list(self._patterns.keys())
    
    def add_pattern(self, pattern: Pattern):
        """添加自定义模式"""
        category = pattern.category
        if category not in self._patterns:
            self._patterns[category] = []
        self._patterns[category].append(pattern)


class GFLibrary:
    """
    GF Library 核心类
    
    用法:
        gf = GFLibrary()
        
        # 扫描文件
        result = gf.scan_file('target.js', patterns=['sqli', 'xss'])
        
        # 扫描 URL
        results = gf.scan_urls(['http://target.com/api'], patterns=['ssrf'])
        
        # 批量扫描
        for result in gf.scan_directory('./js_files', recursive=True):
            print(result.file_path, result.total_matches)
    """
    
    def __init__(
        self,
        patterns_dir: Optional[str] = None,
        default_severity: str = 'medium'
    ):
        self.loader = PatternLoader(patterns_dir)
        self.default_severity = default_severity
        self._cache: Dict[str, List[Match]] = {}
        self._stats = {
            'files_scanned': 0,
            'total_matches': 0,
            'patterns_used': set()
        }
    
    def scan_file(
        self,
        filepath: str,
        patterns: Optional[List[str]] = None,
        categories: Optional[List[str]] = None,
        include_context: int = 2
    ) -> Optional[ScanResult]:
        """扫描单个文件"""
        if not os.path.exists(filepath):
            return None
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception:
            logger.exception(f"Failed to read file: {filepath}")
            return None
        
        return self._scan_lines(
            filepath, lines, patterns, categories, include_context
        )
    
    def scan_text(
        self,
        text: str,
        patterns: Optional[List[str]] = None,
        categories: Optional[List[str]] = None,
        source: str = "text"
    ) -> ScanResult:
        """扫描文本内容"""
        text_hash = hashlib.md5(text.encode()).hexdigest()
        
        cache_key = f"{text_hash}:{','.join(sorted(patterns or []))}:{','.join(sorted(categories or []))}"
        
        if cache_key in self._cache:
            cached_result = self._cache[cache_key]
            cached_result.file_path = source
            return cached_result
        
        lines = text.splitlines()
        result = self._scan_lines(
            source, lines, patterns, categories, include_context=0
        )
        
        if result.total_matches > 0:
            self._cache[cache_key] = result
        
        return result
    
    def _scan_lines(
        self,
        source: str,
        lines: List[str],
        patterns: Optional[List[str]] = None,
        categories: Optional[List[str]] = None,
        include_context: int = 2
    ) -> ScanResult:
        """扫描行列表"""
        result = ScanResult(
            file_path=source,
            total_lines=len(lines),
            total_matches=0
        )
        
        pattern_list = self._get_pattern_list(patterns, categories)
        
        for i, line in enumerate(lines, 1):
            for pattern in pattern_list:
                match = pattern.match(line)
                if match and not pattern.is_false_positive(line):
                    matched_text = match.group(0)
                    
                    context_start = max(0, i - include_context - 1)
                    context_end = min(len(lines), i + include_context)
                    context = '\n'.join(f"{j}: {lines[j-1]}" for j in range(context_start + 1, context_end + 1))
                    
                    match_obj = Match(
                        pattern_name=pattern.name,
                        matched_text=matched_text,
                        line_number=i,
                        line_content=line.strip(),
                        severity=pattern.severity,
                        category=pattern.category,
                        context=context
                    )
                    
                    result.matches.append(match_obj)
                    result.total_matches += 1
                    
                    result.matches_by_severity[pattern.severity] = \
                        result.matches_by_severity.get(pattern.severity, 0) + 1
                    result.matches_by_category[pattern.category] = \
                        result.matches_by_category.get(pattern.category, 0) + 1
                    
                    self._stats['total_matches'] += 1
                    self._stats['patterns_used'].add(pattern.name)
        
        self._stats['files_scanned'] += 1
        return result
    
    def _get_pattern_list(
        self,
        patterns: Optional[List[str]],
        categories: Optional[List[str]]
    ) -> List[Pattern]:
        """获取要使用的模式列表"""
        if patterns:
            all_patterns = self.loader.get_patterns()
            return [p for p in all_patterns if p.name in patterns]
        elif categories:
            pattern_list = []
            for cat in categories:
                pattern_list.extend(self.loader.get_patterns(cat))
            return pattern_list
        else:
            return self.loader.get_patterns()
    
    def scan_urls(
        self,
        urls: List[str],
        patterns: Optional[List[str]] = None,
        categories: Optional[List[str]] = None
    ) -> List[ScanResult]:
        """扫描 URL 列表 (获取响应体后扫描)"""
        results = []
        
        for url in urls:
            try:
                import requests
                resp = requests.get(url, timeout=10, verify=False)
                content = resp.text
                
                result = self.scan_text(
                    content,
                    patterns=patterns,
                    categories=categories,
                    source=url
                )
                results.append(result)
            except Exception:
                continue
        
        return results
    
    def scan_directory(
        self,
        directory: str,
        patterns: Optional[List[str]] = None,
        categories: Optional[List[str]] = None,
        recursive: bool = True,
        extensions: Optional[List[str]] = None
    ) -> Iterator[ScanResult]:
        """扫描目录"""
        if extensions is None:
            extensions = ['.js', '.html', '.htm', '.txt', '.json', '.xml']
        
        for root, dirs, files in os.walk(directory):
            for filename in files:
                if any(filename.endswith(ext) for ext in extensions):
                    filepath = os.path.join(root, filename)
                    result = self.scan_file(filepath, patterns, categories)
                    if result and result.total_matches > 0:
                        yield result
            
            if not recursive:
                break
    
    def grep(
        self,
        input_text: str,
        patterns: Optional[List[str]] = None,
        categories: Optional[List[str]] = None
    ) -> List[Match]:
        """grep 风格扫描"""
        result = self.scan_text(
            input_text,
            patterns=patterns,
            categories=categories,
            source="stdin"
        )
        return result.matches
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            **self._stats,
            'patterns_used': list(self._stats['patterns_used']),
            'categories_available': self.loader.get_categories()
        }
    
    def reset_statistics(self):
        """重置统计"""
        self._stats = {
            'files_scanned': 0,
            'total_matches': 0,
            'patterns_used': set()
        }


class OutputFormatter:
    """输出格式化器"""
    
    @staticmethod
    def to_json(results: List[ScanResult], pretty: bool = True) -> str:
        """输出为 JSON"""
        data = [r.to_dict() for r in results]
        return json.dumps(data, indent=2 if pretty else None, ensure_ascii=False)
    
    @staticmethod
    def to_csv(results: List[ScanResult]) -> str:
        """输出为 CSV"""
        import io
        output = io.StringIO()
        writer = csv.writer(output)
        
        writer.writerow([
            'File', 'Line', 'Category', 'Severity',
            'Pattern', 'Matched', 'Context'
        ])
        
        for result in results:
            for match in result.matches:
                writer.writerow([
                    result.file_path,
                    match.line_number,
                    match.category,
                    match.severity,
                    match.pattern_name,
                    match.matched_text[:50],
                    match.context[:100].replace('\n', ' | ')
                ])
        
        return output.getvalue()
    
    @staticmethod
    def to_text(results: List[ScanResult], color: bool = True) -> str:
        """输出为文本"""
        output = []
        
        severity_colors = {
            'critical': '\033[91m' if color else '',
            'high': '\033[93m' if color else '',
            'medium': '\033[94m' if color else '',
            'low': '\033[92m' if color else '',
            'info': '\033[90m' if color else ''
        }
        reset = '\033[0m' if color else ''
        
        for result in results:
            output.append(f"\n{result.file_path} ({result.total_matches} matches)")
            output.append('=' * 60)
            
            for match in result.matches:
                color_code = severity_colors.get(match.severity, '')
                output.append(
                    f"{color_code}[{match.severity.upper()}] "
                    f"{result.file_path}:{match.line_number} "
                    f"[{match.category}] {match.pattern_name}{reset}"
                )
                output.append(f"  {match.line_content[:100]}")
        
        return '\n'.join(output)
    
    @staticmethod
    def format_summary(results: List[ScanResult]) -> str:
        """输出摘要"""
        total_files = len(results)
        total_matches = sum(r.total_matches for r in results)
        
        severity_counts = {}
        category_counts = {}
        
        for result in results:
            for sev, count in result.matches_by_severity.items():
                severity_counts[sev] = severity_counts.get(sev, 0) + count
            for cat, count in result.matches_by_category.items():
                category_counts[cat] = category_counts.get(cat, 0) + count
        
        lines = [
            f"\nScan Summary",
            f"{'=' * 40}",
            f"Files scanned:    {total_files}",
            f"Total matches:    {total_matches}",
            f"",
            f"Severity:",
        ]
        
        for sev in ['critical', 'high', 'medium', 'low', 'info']:
            if sev in severity_counts:
                lines.append(f"  {sev.capitalize()}:     {severity_counts[sev]}")
        
        lines.append(f"\nCategory:")
        for cat, count in sorted(category_counts.items(), key=lambda x: -x[1]):
            lines.append(f"  {cat}:     {count}")
        
        return '\n'.join(lines)


def create_gf_cli() -> argparse.ArgumentParser:
    """创建 GF CLI"""
    parser = argparse.ArgumentParser(
        description='GF - Pattern-Based Security Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        'patterns',
        nargs='*',
        help='Pattern names to use (e.g., sqli xss ssrf)'
    )
    
    parser.add_argument(
        '-c', '--category',
        action='append',
        help='Category patterns to use'
    )
    
    parser.add_argument(
        '-f', '--file',
        help='Input file'
    )
    
    parser.add_argument(
        '-d', '--directory',
        help='Input directory'
    )
    
    parser.add_argument(
        '-r', '--recursive',
        action='store_true',
        help='Recursive scan (for directories)'
    )
    
    parser.add_argument(
        '-o', '--output',
        choices=['text', 'json', 'csv', 'summary'],
        default='text',
        help='Output format'
    )
    
    parser.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored output'
    )
    
    parser.add_argument(
        '-l', '--list',
        action='store_true',
        help='List available patterns'
    )
    
    parser.add_argument(
        '--patterns-dir',
        help='Custom patterns directory'
    )
    
    return parser


def main():
    """GF CLI 主函数"""
    parser = create_gf_cli()
    args = parser.parse_args()
    
    if args.list:
        loader = PatternLoader(args.patterns_dir)
        print("\nAvailable Categories:")
        for cat in loader.get_categories():
            patterns = loader.get_patterns(cat)
            print(f"\n{cat} ({len(patterns)} patterns):")
            for p in patterns:
                print(f"  - {p.name}: {p.description} [{p.severity}]")
        return
    
    gf = GFLibrary(args.patterns_dir)
    results = []
    
    if args.file:
        result = gf.scan_file(args.file, args.patterns, args.category)
        if result:
            results.append(result)
    
    elif args.directory:
        for result in gf.scan_directory(
            args.directory,
            args.patterns,
            args.category,
            args.recursive
        ):
            results.append(result)
    
    else:
        input_text = sys.stdin.read()
        result = gf.scan_text(input_text, args.patterns, args.category, "stdin")
        if result:
            results.append(result)
    
    if not results:
        print("No matches found.")
        return
    
    if args.output == 'json':
        print(OutputFormatter.to_json(results))
    elif args.output == 'csv':
        print(OutputFormatter.to_csv(results))
    elif args.output == 'summary':
        print(OutputFormatter.format_summary(results))
    else:
        print(OutputFormatter.to_text(results, not args.no_color))


if __name__ == '__main__':
    main()
