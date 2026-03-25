#!/usr/bin/env python3
"""
指纹识别引擎 - 基于 FLUX v5.2.1
核心特性:
- 25,000+ 指纹规则
- 多特征交叉验证机制
- 置信度评分系统
- 通用关键词过滤
"""

import re
import json
import hashlib
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


@dataclass
class FingerprintRule:
    """统一指纹规则结构"""
    name: str
    method: str
    keyword: List[str]
    level: str
    category: str
    icon: str = "🔍"
    severity: str = "Info"


@dataclass
class FingerprintResult:
    """指纹识别结果"""
    name: str
    category: str
    version: str = ""
    confidence: int = 0
    evidence: str = ""
    icon: str = "🔍"
    severity: str = "Info"
    level: str = "L2"
    matches: List[Dict] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return asdict(self)


class FingerprintEngine:
    """指纹识别引擎"""

    WEIGHTS = {
        'faviconhash': 0.45,
        'header': 0.20,
        'body_keyword': 0.20,
        'title': 0.10,
        'url_path': 0.05
    }

    CONFIDENCE_THRESHOLDS = {
        'report': 60,
        'high': 75,
        'verify': 40
    }

    WAF_SIGNATURES = {
        '阿里云盾': ['yundun', 'CDNPROXY', 'yundununblock'],
        '腾讯云WAF': ['qcloudwaf', 'waf.tencent', 'waf.qcloud'],
        '华为云WAF': ['hwcloudwaf', 'waf.huaweicloud'],
        '安全狗': ['safedog', 'waf.safedog'],
        '360网站卫士': ['360wzb', '360wzws'],
        '知道创宇': ['zdbama', 'kcyuner'],
        '安恒信息': ['anHengWAF'],
        '长亭科技': ['chtlWAF', 'x地WAF'],
        'FortiWeb': ['FortiWeb', 'fortiweb'],
        'Imperva': ['Imperva', 'incapsula'],
        'Akamai': ['AkamaiGHost', 'Akamai'],
        'Cloudflare': ['Cloudflare', 'cf-ray'],
        'AWS WAF': ['AWSALB', 'AWS-WAF'],
        'F5 BIG-IP': ['BigIP', 'F5-ESMS'],
        'ModSecurity': ['ModSecurity'],
        'OpenResty': ['openresty'],
        'Nginx': ['nginx'],
        'Apache': ['Apache'],
        'IIS': ['Microsoft-IIS'],
    }

    FILTER_KEYWORDS = [
        'login', 'admin', 'dashboard', 'manage', 'system',
        'user', 'password', 'signin', 'register', 'auth',
        'search', 'home', 'index', 'about', 'contact',
        'product', 'service', 'help', 'support', 'error'
    ]

    def __init__(self, session=None, config_path: str = None):
        self.session = session
        self.rules: List[FingerprintRule] = []
        self.favicon_hashes: Dict[str, str] = {}
        self.config = self._load_config(config_path)
        self.weights = self.config.get('fingerprint_weights', self.WEIGHTS)
        self.thresholds = self.config.get('confidence_thresholds', self.CONFIDENCE_THRESHOLDS)
        self._init_rules()

    def _load_config(self, config_path: str = None) -> Dict:
        if config_path and Path(config_path).exists():
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                logger.debug(f"加载配置文件失败: {e}")
        return {
            'fingerprint_weights': self.WEIGHTS,
            'confidence_thresholds': self.CONFIDENCE_THRESHOLDS
        }

    def _init_rules(self):
        self._load_builtin_rules()
        self._load_external_rules()
        self.rules = self._deduplicate_rules(self.rules)
        logger.info(f"[*] 指纹库加载完成: {len(self.rules)} 条规则")

    def _load_builtin_rules(self):
        builtin_rules = [
            FingerprintRule("致远OA", "faviconhash", ["1578525679"], "L1", "OA"),
            FingerprintRule("泛微OA", "faviconhash", ["1578525679"], "L1", "OA"),
            FingerprintRule("ThinkPHP", "header", ["X-Powered-By: ThinkPHP"], "L1", "Framework"),
            FingerprintRule("Nginx", "header", ["Server: nginx"], "L1", "WebServer"),
            FingerprintRule("Apache", "header", ["Server: Apache"], "L1", "WebServer"),
            FingerprintRule("IIS", "header", ["Server: Microsoft-IIS"], "L1", "WebServer"),
            FingerprintRule("Spring Boot", "body", ["Whitelabel Error Page", "spring-boot"], "L2", "Framework"),
            FingerprintRule("Swagger UI", "body", ["swagger-ui", "Swagger UI"], "L2", "DevTool"),
            FingerprintRule("WordPress", "body", ["/wp-content/", "/wp-includes/"], "L2", "CMS"),
            FingerprintRule("phpMyAdmin", "body", ["phpMyAdmin", "pma_theme_name"], "L2", "Database"),
            FingerprintRule("Next.js", "body", ["__NEXT_DATA__", "next.js", "next-router"], "L2", "Framework"),
            FingerprintRule("Vue.js", "body", ["vue", "Vue"], "L2", "Framework"),
            FingerprintRule("React", "body", ["react", "React"], "L2", "Framework"),
            FingerprintRule("jQuery", "body", ["jquery", "jQuery"], "L3", "Library"),
            FingerprintRule("Bootstrap", "body", ["bootstrap", "Bootstrap"], "L3", "Framework"),
        ]
        for rule in builtin_rules:
            self._add_rule(rule)

    def _load_external_rules(self):
        fingerprint_files = [
            'data/fingerprints_merged.json',
            'data/fingerprints.json',
            '/workspace/data/fingerprints_merged.json',
        ]
        for fp_file in fingerprint_files:
            fp_path = Path(fp_file)
            if fp_path.exists():
                try:
                    with open(fp_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    
                    count = self._parse_and_add_rules(data)
                    logger.info(f"[*] 加载外部指纹库: {fp_file} ({count} 条规则)")
                except Exception as e:
                    logger.debug(f"加载指纹库失败 {fp_file}: {e}")

    def _parse_and_add_rules(self, data) -> int:
        """
        解析指纹库数据，支持两种格式：
        1. dict格式: {"指纹名": [规则列表], ...}
        2. list格式: [{"name": "...", "method": "...", ...}, ...]
        3. 嵌套dict格式: {"fingerprint": [...], ...}
        """
        count = 0
        
        if isinstance(data, dict):
            if 'fingerprint' in data and isinstance(data['fingerprint'], list):
                data = data['fingerprint']
            else:
                for name, rules in data.items():
                    if isinstance(rules, list):
                        for item in rules:
                            rule = self._parse_fingerprint_rule(item, name)
                            if rule:
                                self._add_rule(rule)
                                count += 1
                    elif isinstance(rules, dict):
                        rule = self._parse_fingerprint_rule(rules, name)
                        if rule:
                            self._add_rule(rule)
                            count += 1
        elif isinstance(data, list):
            for item in data:
                rule = self._parse_fingerprint_rule(item)
                if rule:
                    self._add_rule(rule)
                    count += 1
        return count

    def _parse_fingerprint_rule(self, item: Dict, default_name: str = None) -> Optional[FingerprintRule]:
        try:
            name = item.get('name', item.get('cms', default_name))
            if not name:
                return None

            method = item.get('method', item.get('type', 'body'))
            keyword = item.get('keyword', item.get('keywords', item.get('path', [])))
            if isinstance(keyword, str):
                keyword = [keyword]
            if not keyword:
                return None

            level = item.get('level', self._get_level_from_method(method))
            category = item.get('category', self._get_category(name))
            icon = item.get('icon', "🔍")
            severity = item.get('severity', "Info")

            return FingerprintRule(
                name=name,
                method=method,
                keyword=keyword,
                level=level,
                category=category,
                icon=icon,
                severity=severity
            )
        except Exception:
            return None

    def _get_level_from_method(self, method: str) -> str:
        level_map = {
            'faviconhash': 'L1',
            'header': 'L1',
            'body': 'L2',
            'url': 'L3',
            'title': 'L3'
        }
        return level_map.get(method, 'L2')

    def _get_category(self, name: str) -> str:
        name_lower = name.lower()
        if any(k in name_lower for k in ['oa', 'office']):
            return 'OA'
        if any(k in name_lower for k in ['cms', 'blog', 'wordpress', 'drupal', 'joomla']):
            return 'CMS'
        if any(k in name_lower for k in ['spring', 'django', 'flask', 'express', 'laravel']):
            return 'Framework'
        if any(k in name_lower for k in ['nginx', 'apache', 'iis', 'tomcat']):
            return 'WebServer'
        if any(k in name_lower for k in ['database', 'mysql', 'postgresql', 'mongodb']):
            return 'Database'
        if any(k in name_lower for k in ['ai', 'llm', 'ollama', 'vllm', 'openai']):
            return 'AI'
        return 'Other'

    def _add_rule(self, rule: FingerprintRule):
        self.rules.append(rule)

    def _deduplicate_rules(self, rules: List[FingerprintRule]) -> List[FingerprintRule]:
        seen = set()
        unique = []
        for rule in rules:
            key = (rule.name, tuple(rule.keyword))
            if key not in seen:
                seen.add(key)
                unique.append(rule)
        return unique

    def scan(self, target_url: str, response=None) -> List[FingerprintResult]:
        results = []
        if response:
            results = self.match(response)
        return results

    def match(self, response) -> List[FingerprintResult]:
        results = []
        if not response:
            return results

        body = response.text if hasattr(response, 'text') else str(response)
        headers = dict(response.headers) if hasattr(response, 'headers') else {}
        status_code = response.status_code if hasattr(response, 'status_code') else 0
        url = response.url if hasattr(response, 'url') else ''

        parsed_url = urlparse(url)
        url_path = parsed_url.path

        scores: Dict[str, Tuple[int, List[Dict]]] = {}

        for rule in self.rules:
            if self._should_filter(rule):
                continue

            matches = self._check_rule(rule, body, headers, url_path)
            if matches:
                if rule.name not in scores:
                    scores[rule.name] = (0, [])
                current_score, current_matches = scores[rule.name]
                rule_score = self._calculate_rule_score(rule, matches)
                scores[rule.name] = (current_score + rule_score, current_matches + matches)

        for name, (score, matches) in scores.items():
            if score >= self.thresholds['verify']:
                result = self._create_result(name, matches, score)
                if result:
                    results.append(result)

        results.sort(key=lambda x: x.confidence, reverse=True)
        return results[:20]

    def _should_filter(self, rule: FingerprintRule) -> bool:
        name_lower = rule.name.lower()
        for keyword in self.FILTER_KEYWORDS:
            if keyword in name_lower and len(name_lower) < 20:
                return True
        return False

    def _check_rule(self, rule: FingerprintRule, body: str, headers: Dict, url_path: str) -> List[Dict]:
        matches = []
        method = rule.method.lower()

        if method == 'body':
            body_lower = body.lower()
            for keyword in rule.keyword:
                if keyword.lower() in body_lower:
                    matches.append({'type': 'body', 'keyword': keyword})
        elif method == 'header':
            headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
            header_str = str(headers_lower)
            for keyword in rule.keyword:
                keyword_lower = keyword.lower()
                if keyword_lower in header_str:
                    matches.append({'type': 'header', 'keyword': keyword})
        elif method == 'url':
            for keyword in rule.keyword:
                if keyword.lower() in url_path.lower():
                    matches.append({'type': 'url', 'keyword': keyword})
        elif method == 'faviconhash':
            pass

        return matches

    def _calculate_rule_score(self, rule: FingerprintRule, matches: List[Dict]) -> int:
        weight = self.weights.get(rule.method, 0.1)
        base_score = weight * 100 * len(matches)

        if rule.level == 'L1':
            base_score *= 1.5
        elif rule.level == 'L3':
            base_score *= 0.7

        return int(min(base_score, 100))

    def _create_result(self, name: str, matches: List[Dict], score: int) -> Optional[FingerprintResult]:
        category = 'Other'
        for rule in self.rules:
            if rule.name == name:
                category = rule.category
                break

        confidence = min(score, 100)
        severity = 'Info'
        if confidence >= 80:
            severity = 'High'
        elif confidence >= 60:
            severity = 'Medium'

        level = 'L2'
        for rule in self.rules:
            if rule.name == name:
                level = rule.level
                break

        return FingerprintResult(
            name=name,
            category=category,
            confidence=confidence,
            evidence=', '.join([m['keyword'] for m in matches[:3]]),
            severity=severity,
            level=level,
            matches=matches
        )

    def detect_waf(self, response) -> Optional[str]:
        if not response:
            return None

        headers = dict(response.headers)
        body = response.text if hasattr(response, 'text') else ''

        headers_str = str(headers).lower()
        body_lower = body.lower()

        for waf_name, signatures in self.WAF_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in headers_str or sig.lower() in body_lower:
                    logger.info(f"[*] 检测到WAF: {waf_name}")
                    return waf_name

        return None

    def get_fingerprints(self) -> List[FingerprintRule]:
        return self.rules

    def get_stats(self) -> Dict:
        categories = {}
        methods = {}
        levels = {'L1': 0, 'L2': 0, 'L3': 0}

        for rule in self.rules:
            categories[rule.category] = categories.get(rule.category, 0) + 1
            methods[rule.method] = methods.get(rule.method, 0) + 1
            levels[rule.level] = levels.get(rule.level, 0) + 1

        return {
            'total': len(self.rules),
            'categories': categories,
            'methods': methods,
            'levels': levels
        }


__all__ = ['FingerprintEngine', 'FingerprintRule', 'FingerprintResult']
