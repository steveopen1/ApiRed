"""
URL Greper Module
批量 URL 筛选工具 - 类似 tomnomnom/gf
从海量 URL 中快速筛选可能存在 IDOR 漏洞的端点
"""

import re
import os
import yaml
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs, urlencode
from pathlib import Path


@dataclass
class IDORPattern:
    """IDOR 模式"""
    name: str
    pattern: str
    severity: str
    description: str = ""
    pattern_type: str = "param"  # param, path, action
    
    def match(self, text: str) -> bool:
        """匹配模式"""
        try:
            return bool(re.search(self.pattern, text, re.IGNORECASE))
        except re.error:
            return False


@dataclass
class URLMatch:
    """URL 匹配结果"""
    url: str
    matched_patterns: List[str]
    severity: str
    id_params: Dict[str, str]
    priority_score: int
    reason: str


class PatternLoader:
    """模式加载器 - 支持 YAML 配置和内置模式"""
    
    DEFAULT_PATTERNS_DIR = "rules"
    
    def __init__(self, custom_rules_path: Optional[str] = None):
        self.custom_rules_path = custom_rules_path
        self._id_patterns: List[IDORPattern] = []
        self._path_patterns: List[IDORPattern] = []
        self._action_patterns: List[IDORPattern] = []
        self._exclude_patterns: List[IDORPattern] = []
        self._resource_weights: Dict[str, int] = {}
        self._action_weights: Dict[str, int] = {}
        self._path_weights: Dict[str, int] = {}
        
        self._load_default_rules()
        if custom_rules_path:
            self._load_custom_rules(custom_rules_path)
    
    def _load_default_rules(self):
        """加载默认规则"""
        default_rules_path = Path(__file__).parent.parent / "rules" / "idor_patterns.yaml"
        if default_rules_path.exists():
            self._load_from_yaml(str(default_rules_path))
        else:
            self._load_builtin_patterns()
    
    def _load_builtin_patterns(self):
        """加载内置模式 (备用)"""
        self._id_patterns = [
            IDORPattern("user_id", r"(user[_-]?id|userid|uid)", "high", "用户ID参数", "param"),
            IDORPattern("account_id", r"(account[_-]?id|accountid)", "high", "账户ID参数", "param"),
            IDORPattern("profile_id", r"(profile[_-]?id|profileid)", "medium", "资料ID", "param"),
            IDORPattern("order_id", r"(order[_-]?id|orderid)", "high", "订单ID", "param"),
            IDORPattern("transaction_id", r"(transaction[_-]?id|transactionid)", "critical", "交易ID", "param"),
            IDORPattern("payment_id", r"(payment[_-]?id|paymentid)", "critical", "支付ID", "param"),
            IDORPattern("document_id", r"(document[_-]?id|doc[_-]?id)", "high", "文档ID", "param"),
            IDORPattern("file_id", r"(file[_-]?id|fileid)", "medium", "文件ID", "param"),
            IDORPattern("post_id", r"(post[_-]?id|postid)", "low", "帖子ID", "param"),
            IDORPattern("id", r"\bid\b", "medium", "通用ID", "param"),
        ]
        
        self._path_patterns = [
            IDORPattern("user_detail", r"/users?/\d+", "high", "用户详情页", "path"),
            IDORPattern("orders", r"/orders?", "high", "订单页面", "path"),
            IDORPattern("transactions", r"/transactions?", "high", "交易页面", "path"),
            IDORPattern("admin", r"/(admin|administrator|manage)/", "critical", "管理后台", "path"),
            IDORPattern("api_endpoint", r"/api/.*", "medium", "API端点", "path"),
            IDORPattern("export", r"/(export|download)/", "high", "导出功能", "path"),
        ]
        
        self._exclude_patterns = [
            IDORPattern("captcha", r"(captcha|verify|recaptcha)", "info", "验证码", "exclude"),
            IDORPattern("pagination", r"(page|limit|offset)", "info", "分页", "exclude"),
            IDORPattern("search", r"(search|query|q=|keyword)", "info", "搜索", "exclude"),
        ]
        
        self._resource_weights = {
            "transaction": 10, "payment": 10, "invoice": 8, "order": 7,
            "user": 6, "account": 6, "session": 6, "document": 5,
            "file": 5, "profile": 4, "product": 2, "post": 2, "other": 1
        }
        
        self._action_weights = {
            "delete": 10, "payment": 10, "export": 8, "edit": 6, "view": 4
        }
    
    def _load_from_yaml(self, yaml_path: str):
        """从 YAML 文件加载规则"""
        try:
            with open(yaml_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            
            for pattern in data.get('id_patterns', []):
                self._id_patterns.append(IDORPattern(
                    name=pattern['name'],
                    pattern=pattern['pattern'],
                    severity=pattern.get('severity', 'medium'),
                    description=pattern.get('description', ''),
                    pattern_type='param'
                ))
            
            for pattern in data.get('path_patterns', []):
                self._path_patterns.append(IDORPattern(
                    name=pattern['name'],
                    pattern=pattern['pattern'],
                    severity=pattern.get('severity', 'medium'),
                    description=pattern.get('description', ''),
                    pattern_type='path'
                ))
            
            for pattern in data.get('action_patterns', []):
                self._action_patterns.append(IDORPattern(
                    name=pattern['name'],
                    pattern=pattern['pattern'],
                    severity=pattern.get('severity', 'medium'),
                    description=pattern.get('description', ''),
                    pattern_type='action'
                ))
            
            for pattern in data.get('exclude_patterns', []):
                self._exclude_patterns.append(IDORPattern(
                    name=pattern['name'],
                    pattern=pattern['pattern'],
                    severity='info',
                    description=pattern.get('description', ''),
                    pattern_type='exclude'
                ))
            
            priority_rules = data.get('priority_rules', {})
            self._resource_weights = priority_rules.get('resource_weights', {})
            self._action_weights = priority_rules.get('action_weights', {})
            self._path_weights = priority_rules.get('path_weights', {})
            
        except Exception as e:
            print(f"Failed to load YAML rules: {e}")
            self._load_builtin_patterns()
    
    def _load_custom_rules(self, rules_dir: str):
        """加载自定义规则目录"""
        rules_path = Path(rules_dir)
        if not rules_path.exists():
            return
        
        for yaml_file in rules_path.glob("*.yaml"):
            self._load_from_yaml(str(yaml_file))
    
    def get_id_patterns(self) -> List[IDORPattern]:
        return self._id_patterns
    
    def get_path_patterns(self) -> List[IDORPattern]:
        return self._path_patterns
    
    def get_action_patterns(self) -> List[IDORPattern]:
        return self._action_patterns
    
    def get_exclude_patterns(self) -> List[IDORPattern]:
        return self._exclude_patterns


class URLGreper:
    """
    URL 批量筛选器
    类似 tomnomnom/gf 的 URL 筛选功能
    
    用法:
        greper = URLGreper()
        results = greper.scan_urls(urls)
        high_risk = greper.filter_by_severity(results, ['critical', 'high'])
    """
    
    def __init__(self, custom_rules_path: Optional[str] = None):
        self.pattern_loader = PatternLoader(custom_rules_path)
        self._matched_cache: Set[str] = set()
    
    def scan_url(self, url: str) -> Optional[URLMatch]:
        """
        扫描单个 URL
        
        Returns:
            URLMatch 如果匹配到 IDOR 模式，否则返回 None
        """
        if url in self._matched_cache:
            return None
        
        try:
            parsed = urlparse(url)
            path = parsed.path
            query = parsed.query
            
            matched_patterns = []
            id_params = {}
            severity = "low"
            priority_score = 0
            reasons = []
            
            for pattern in self.pattern_loader.get_exclude_patterns():
                if pattern.match(path) or pattern.match(query):
                    return None
            
            for pattern in self.pattern_loader.get_id_patterns():
                if pattern.match(query):
                    matched_patterns.append(pattern.name)
                    if query:
                        params = parse_qs(query)
                        for param_name, param_values in params.items():
                            if re.search(pattern.pattern, param_name, re.IGNORECASE):
                                id_params[param_name] = param_values[0] if param_values else ""
                    severity = self._get_higher_severity(severity, pattern.severity)
                    priority_score += self.pattern_loader._resource_weights.get(pattern.name, 1)
                    reasons.append(pattern.description)
            
            path_id_matches = self._extract_path_ids(path)
            if path_id_matches:
                matched_patterns.extend(path_id_matches.keys())
                id_params.update(path_id_matches)
                severity = self._get_higher_severity(severity, "high")
                priority_score += 5
                reasons.append("路径中的ID参数")
            
            for pattern in self.pattern_loader.get_path_patterns():
                if pattern.match(path):
                    matched_patterns.append(pattern.name)
                    severity = self._get_higher_severity(severity, pattern.severity)
                    priority_score += self.pattern_loader._path_weights.get(pattern.name, 1)
                    if pattern.description:
                        reasons.append(pattern.description)
            
            for pattern in self.pattern_loader.get_action_patterns():
                if pattern.match(path):
                    matched_patterns.append(pattern.name)
                    severity = self._get_higher_severity(severity, pattern.severity)
                    priority_score += self.pattern_loader._action_weights.get(pattern.name, 1)
            
            if matched_patterns:
                self._matched_cache.add(url)
                return URLMatch(
                    url=url,
                    matched_patterns=list(set(matched_patterns)),
                    severity=severity,
                    id_params=id_params,
                    priority_score=priority_score,
                    reason="; ".join(reasons) if reasons else f"匹配到: {', '.join(set(matched_patterns))}"
                )
                
        except Exception:
            pass
        
        return None
    
    def _extract_path_ids(self, path: str) -> Dict[str, str]:
        """从 URL 路径中提取 ID"""
        id_params = {}
        
        path_parts = path.strip('/').split('/')
        for i, part in enumerate(path_parts):
            if part.isdigit() and i > 0:
                prev_part = path_parts[i - 1].rstrip('s')
                id_params[f"path_{prev_part}_id"] = part
            elif re.match(r'^[a-zA-Z]{1,3}\d+$', part):
                id_params[f"path_shortcode"] = part
        
        return id_params
    
    def _get_higher_severity(self, current: str, new: str) -> str:
        """比较返回更高的严重性"""
        severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
        current_level = severity_order.get(current.lower(), 0)
        new_level = severity_order.get(new.lower(), 0)
        return current if current_level >= new_level else new
    
    def scan_urls(self, urls: List[str]) -> List[URLMatch]:
        """批量扫描 URL"""
        results = []
        for url in urls:
            match = self.scan_url(url)
            if match:
                results.append(match)
        return results
    
    def filter_by_severity(
        self,
        matches: List[URLMatch],
        severities: List[str]
    ) -> List[URLMatch]:
        """按严重性过滤"""
        return [m for m in matches if m.severity in severities]
    
    def filter_by_pattern(
        self,
        matches: List[URLMatch],
        pattern_names: List[str]
    ) -> List[URLMatch]:
        """按匹配模式过滤"""
        result = []
        for match in matches:
            if any(p in match.matched_patterns for p in pattern_names):
                result.append(match)
        return result
    
    def sort_by_priority(
        self,
        matches: List[URLMatch],
        reverse: bool = True
    ) -> List[URLMatch]:
        """按优先级排序"""
        return sorted(matches, key=lambda x: x.priority_score, reverse=reverse)
    
    def get_statistics(self, matches: List[URLMatch]) -> Dict[str, Any]:
        """获取匹配统计"""
        stats = {
            'total': len(matches),
            'by_severity': {},
            'by_pattern': {},
            'with_id_params': 0
        }
        
        for match in matches:
            stats['by_severity'][match.severity] = stats['by_severity'].get(match.severity, 0) + 1
            
            for pattern in match.matched_patterns:
                stats['by_pattern'][pattern] = stats['by_pattern'].get(pattern, 0) + 1
            
            if match.id_params:
                stats['with_id_params'] += 1
        
        return stats
    
    def reset_cache(self):
        """重置缓存"""
        self._matched_cache.clear()


def load_gf_patterns(gf_dir: Optional[str] = None) -> PatternLoader:
    """
    加载 GF 模式
    兼容 tomnomnom/gf 的模式文件格式
    
    Args:
        gf_dir: GF 模式目录，默认为 ~/.gf
    """
    if gf_dir is None:
        gf_dir = os.path.expanduser("~/.gf")
    
    if os.path.exists(gf_dir):
        return PatternLoader(gf_dir)
    
    return PatternLoader()


def quick_scan(urls: List[str], min_severity: str = "medium") -> List[URLMatch]:
    """
    快速扫描
    
    Args:
        urls: URL 列表
        min_severity: 最低严重性 (critical/high/medium/low)
    
    Returns:
        匹配到的 URL 列表
    """
    greper = URLGreper()
    matches = greper.scan_urls(urls)
    
    severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
    min_level = severity_order.get(min_severity.lower(), 0)
    
    filtered = [
        m for m in matches 
        if severity_order.get(m.severity.lower(), 0) >= min_level
    ]
    
    return greper.sort_by_priority(filtered)
