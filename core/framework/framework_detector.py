"""
Framework Rule Engine
可扩展的框架识别规则引擎
"""

import re
import os
import yaml
import hashlib
import asyncio
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class FrameworkMatch:
    """框架匹配结果"""
    name: str
    confidence: float
    api_pattern: Optional[str] = None
    response_behavior: Optional[Dict] = None
    matched_indicators: List[str] = None
    
    def __post_init__(self):
        if self.matched_indicators is None:
            self.matched_indicators = []


@dataclass
class FrameworkIndicator:
    """框架指标"""
    indicator_type: str
    pattern: str
    weight: float
    description: str = ""
    
    def match(self, target_info: Dict) -> bool:
        """匹配指标"""
        if self.indicator_type == "file":
            return bool(re.search(self.pattern, target_info.get('js_files', '')))
        elif self.indicator_type == "path":
            return bool(re.search(self.pattern, target_info.get('api_paths', '')))
        elif self.indicator_type == "content":
            return bool(re.search(self.pattern, target_info.get('response_content', '')))
        elif self.indicator_type == "header":
            return bool(re.search(self.pattern, target_info.get('headers', '')))
        elif self.indicator_type == "response":
            return bool(re.search(self.pattern, target_info.get('response_patterns', '')))
        return False


class FrameworkRule:
    """框架规则"""
    
    def __init__(self, name: str, data: Dict):
        self.name = name
        self.data = data
        self.confidence_threshold = data.get('framework', {}).get('confidence_threshold', 50)
        self.indicators: List[FrameworkIndicator] = []
        self._parse_indicators()
    
    def _parse_indicators(self):
        """解析指标"""
        for ind in self.data.get('detection', {}).get('indicators', []):
            self.indicators.append(FrameworkIndicator(
                indicator_type=ind.get('type', 'content'),
                pattern=ind.get('pattern', ''),
                weight=ind.get('weight', 10),
                description=ind.get('description', '')
            ))
    
    def calculate_score(self, target_info: Dict) -> float:
        """计算匹配分数"""
        score = 0.0
        matched = []
        
        for indicator in self.indicators:
            if indicator.match(target_info):
                score += indicator.weight
                matched.append(indicator.description or indicator.pattern)
        
        return score, matched
    
    def is_matched(self, target_info: Dict) -> bool:
        """是否匹配"""
        score, _ = self.calculate_score(target_info)
        return score >= self.confidence_threshold
    
    def get_api_pattern(self) -> Optional[Dict]:
        """获取 API 模式"""
        return self.data.get('api_pattern')
    
    def get_response_behavior(self) -> Optional[Dict]:
        """获取响应行为"""
        return self.data.get('response_behavior')


class FrameworkDetector:
    """
    框架检测器
    支持 YAML 规则文件的可扩展框架识别
    """
    
    def __init__(self, rules_dir: Optional[str] = None):
        self.rules: Dict[str, FrameworkRule] = {}
        
        if rules_dir is None:
            rules_dir = Path(__file__).parent / 'fingerprints'
        
        self.rules_dir = Path(rules_dir)
        self._load_builtin_rules()
    
    def _load_builtin_rules(self):
        """加载内置规则"""
        if self.rules_dir.exists():
            for rule_file in self.rules_dir.glob("*.yaml"):
                try:
                    with open(rule_file, 'r', encoding='utf-8') as f:
                        rule_data = yaml.safe_load(f)
                    
                    name = rule_data.get('framework', {}).get('name', rule_file.stem)
                    self.rules[name] = FrameworkRule(name, rule_data)
                except Exception as e:
                    logger.debug(f"Failed to load rule {rule_file}: {e}")
    
    def load_custom_rule(self, rule_data: Dict) -> bool:
        """加载自定义规则"""
        try:
            name = rule_data.get('framework', {}).get('name', 'custom')
            self.rules[name] = FrameworkRule(name, rule_data)
            return True
        except Exception as e:
            logger.debug(f"Failed to load custom rule: {e}")
            return False
    
    def load_rule_file(self, file_path: str) -> bool:
        """从文件加载规则"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                rule_data = yaml.safe_load(f)
            return self.load_custom_rule(rule_data)
        except Exception as e:
            logger.debug(f"Failed to load rule file {file_path}: {e}")
            return False
    
    def detect(self, target_info: Dict) -> List[FrameworkMatch]:
        """
        检测目标框架
        
        Args:
            target_info: 目标信息，包含：
                - js_files: JS 文件名或路径
                - api_paths: API 路径
                - response_content: 响应内容
                - headers: 响应头
        
        Returns:
            匹配的框架列表，按置信度排序
        """
        results = []
        
        for name, rule in self.rules.items():
            score, matched = rule.calculate_score(target_info)
            
            if score >= rule.confidence_threshold:
                results.append(FrameworkMatch(
                    name=name,
                    confidence=min(score / 100, 1.0),
                    api_pattern=rule.get_api_pattern(),
                    response_behavior=rule.get_response_behavior(),
                    matched_indicators=matched
                ))
        
        return sorted(results, key=lambda x: x.confidence, reverse=True)
    
    def detect_best(self, target_info: Dict) -> Optional[FrameworkMatch]:
        """检测最佳匹配的框架"""
        matches = self.detect(target_info)
        return matches[0] if matches else None
    
    def get_api_pattern(self, framework_name: str) -> Optional[Dict]:
        """获取框架的 API 模式"""
        rule = self.rules.get(framework_name)
        return rule.get_api_pattern() if rule else None
    
    def get_components(self, framework_name: str) -> List[str]:
        """获取框架的组件列表"""
        pattern = self.get_api_pattern(framework_name)
        return pattern.get('components', []) if pattern else []
    
    def get_actions(self, framework_name: str) -> List[str]:
        """获取框架的动作列表"""
        pattern = self.get_api_pattern(framework_name)
        return pattern.get('actions', []) if pattern else []
    
    def generate_endpoints(self, framework_name: str) -> List[str]:
        """基于框架生成端点"""
        pattern = self.get_api_pattern(framework_name)
        if not pattern:
            return []
        
        endpoints = []
        structure = pattern.get('structure', '{component}/{action}')
        components = pattern.get('components', [])
        actions = pattern.get('actions', [])
        base_path = pattern.get('base_path', '')
        
        for comp in components:
            for action in actions:
                endpoint = f"{base_path}{structure.format(component=comp, action=action)}"
                endpoints.append(endpoint)
        
        return endpoints
    
    async def verify_endpoints(
        self, 
        endpoints: List[str], 
        http_client, 
        base_url: str,
        timeout: float = 5.0
    ) -> List[str]:
        """
        验证端点是否真实存在（多来源验证）
        
        验证标准：
        1. 响应状态码在 200-399 范围内
        2. Content-Type 包含 json 或 xml
        3. 响应体可解析为 JSON 或 XML
        
        Args:
            endpoints: 待验证的端点列表
            http_client: HTTP 客户端
            base_url: 目标基础 URL
            timeout: 请求超时时间
            
        Returns:
            验证通过的端点列表
        """
        verified = []
        
        async def probe_endpoint(endpoint: str) -> Optional[str]:
            full_url = base_url.rstrip('/') + endpoint
            try:
                response = await http_client.request(full_url, method='GET', timeout=timeout)
                if not response:
                    return None
                    
                status_code = response.status_code
                if status_code < 200 or status_code >= 400:
                    return None
                
                content_type = response.headers.get('Content-Type', '').lower()
                
                is_json = 'json' in content_type
                is_xml = 'xml' in content_type
                
                if not is_json and not is_xml:
                    content = response.content[:500] if response.content else b''
                    try:
                        content_str = content.decode('utf-8', errors='ignore')
                        if content_str.strip().startswith(('{', '[')):
                            is_json = True
                        elif '<' in content_str and ('xml' in content_str.lower() or 'response' in content_str.lower()):
                            is_xml = True
                    except:
                        pass
                
                if is_json or is_xml:
                    return endpoint
                    
            except Exception:
                pass
            return None
        
        tasks = [probe_endpoint(ep) for ep in endpoints]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if result and isinstance(result, str):
                verified.append(result)
        
        logger.info(f"Framework endpoint verification: {len(verified)}/{len(endpoints)} passed")
        return verified
    
    def list_rules(self) -> List[str]:
        """列出所有已加载的规则"""
        return list(self.rules.keys())
    
    async def llm_assisted_detect(self, target_info: Dict, llm_client=None) -> Optional[FrameworkMatch]:
        """
        LLM 辅助框架识别
        
        当规则匹配不确定时，使用 LLM 进行辅助判断
        
        Args:
            target_info: 目标信息
            llm_client: LLM 客户端（需要有 chat 方法）
        
        Returns:
            可能的框架匹配
        """
        if not llm_client:
            return self.detect_best(target_info)
        
        js_files = target_info.get('js_files', '')
        api_paths = target_info.get('api_paths', '')
        response_content = target_info.get('response_content', '')[:500]
        headers = target_info.get('headers', '')
        
        prompt = f"""Analyze this target to identify its framework or custom system.

JS Files found: {js_files[:200]}
API Paths found: {api_paths[:200]}
Response content: {response_content[:300]}
Headers: {headers}

What framework or custom system does this appear to use?
Consider these patterns:
1. VC Framework: /callComponent/{{component}}/{{action}}, 智慧小区
2. Spring Boot: /api/v1/, org.springframework
3. Express.js: /api/, X-Powered-By: Express
4. Django: /admin/, csrftoken
5. Laravel: /api/, XSRF-TOKEN
6. Custom enterprise frameworks

Respond with JSON format:
{{"framework": "framework name or 'custom/unknown'", "confidence": "high/medium/low", "api_pattern": "RESTful/Component/RPC/etc", "key_indicators": ["list of indicators found"]}}

Only output JSON."""
        
        try:
            response = await llm_client.chat([{"role": "user", "content": prompt}])
            
            if not response:
                return self.detect_best(target_info)
            
            import json
            import re
            json_match = re.search(r'\{[^{}]*"framework"[^{}]*\}', response, re.DOTALL)
            if json_match:
                result = json.loads(json_match.group())
                
                framework_name = result.get('framework', 'unknown')
                confidence = result.get('confidence', 'low')
                
                confidence_map = {'high': 0.9, 'medium': 0.7, 'low': 0.5}
                conf_value = confidence_map.get(confidence.lower(), 0.5)
                
                api_pattern = result.get('api_pattern', '')
                
                if api_pattern.lower() == 'component' or '/callcomponent' in api_paths.lower():
                    pattern_str = '/callComponent/{component}/{action}'
                elif api_pattern.lower() == 'rpc':
                    pattern_str = '/rpc/{service}/{method}'
                else:
                    pattern_str = '/api/v1/{resource}'
                
                return FrameworkMatch(
                    name=framework_name,
                    confidence=conf_value,
                    api_pattern={'structure': pattern_str},
                    matched_indicators=result.get('key_indicators', [])
                )
        except Exception as e:
            logger.debug(f"LLM assisted detection failed: {e}")
        
        return self.detect_best(target_info)


def load_default_fingerprints() -> FrameworkDetector:
    """加载默认指纹库"""
    detector = FrameworkDetector()
    return detector


class MergedFingerprintRule:
    """
    指纹规则
    
    支持多特征匹配：
    - body_keyword: body 关键词匹配
    - header: header 匹配
    - url_path: URL 路径匹配
    - faviconhash: Favicon Hash 完全匹配
    """
    
    METHOD_BODY = 'body'
    METHOD_HEADER = 'header'
    METHOD_URL = 'url'
    METHOD_FAVICON = 'faviconhash'
    METHOD_COOKIE = 'cookie'
    
    def __init__(self, name: str, category: str, level: str, patterns: Dict):
        self.name = name
        self.category = category
        self.level = level
        self.patterns = patterns
        self._compiled_patterns = self._compile_patterns()
    
    def _compile_patterns(self) -> Dict:
        """预编译正则表达式"""
        compiled = {}
        for method, patterns in self.patterns.items():
            if isinstance(patterns, list):
                compiled[method] = [
                    re.compile(p, re.IGNORECASE) for p in patterns
                ]
            elif isinstance(patterns, str):
                compiled[method] = [re.compile(patterns, re.IGNORECASE)]
        return compiled
    
    def match(self, body: str = "", headers: Dict = None, url: str = "", cookies: str = "", favicon_hash: str = "") -> Tuple[bool, float, List[str]]:
        """
        多特征匹配
        
        Returns:
            Tuple[bool, float, List[str]]: (是否匹配, 置信度, 匹配的证据)
        """
        if headers is None:
            headers = {}
        headers_str = str(headers).lower()
        cookies_str = cookies.lower() if cookies else ""
        
        matched_methods = []
        evidence = []
        
        for method, patterns in self._compiled_patterns.items():
            for pattern in patterns:
                if method == self.METHOD_BODY and body:
                    if pattern.search(body):
                        matched_methods.append('body')
                        evidence.append(f"body:{pattern.pattern}")
                elif method == self.METHOD_HEADER and headers_str:
                    if pattern.search(headers_str):
                        matched_methods.append('header')
                        evidence.append(f"header:{pattern.pattern}")
                elif method == self.METHOD_URL and url:
                    if pattern.search(url.lower()):
                        matched_methods.append('url')
                        evidence.append(f"url:{pattern.pattern}")
                elif method == self.METHOD_COOKIE and cookies_str:
                    if pattern.search(cookies_str):
                        matched_methods.append('cookie')
                        evidence.append(f"cookie:{pattern.pattern}")
                elif method == self.METHOD_FAVICON and favicon_hash:
                    if pattern.search(favicon_hash):
                        matched_methods.append('faviconhash')
                        evidence.append(f"faviconhash:{pattern.pattern}")
        
        if not matched_methods:
            return False, 0.0, []
        
        confidence = self._calculate_confidence(matched_methods, len(evidence))
        return True, confidence, evidence
    
    def _calculate_confidence(self, matched_methods: List[str], total_matches: int) -> float:
        """
        计算置信度
        
        FLUX 置信度规则：
        - faviconhash 完全匹配: 0.98
        - 至少 2 个不同 method 匹配: min(score * 0.85, 0.92)
        - 单个 method 匹配: score * 0.5
        """
        if self.METHOD_FAVICON in matched_methods:
            return 0.98
        
        if len(matched_methods) >= 2:
            base_score = 0.5 + (0.1 * min(total_matches - 1, 4))
            return min(base_score * 0.85, 0.92)
        
        base_score = 0.3 + (0.1 * min(total_matches - 1, 3))
        return min(base_score * 0.5, 0.7)


class MergedFingerprintEngine:
    """
    指纹识别引擎
    
    使用大规模指纹库进行识别
    """
    
    def __init__(self):
        self.rules: List[MergedFingerprintRule] = []
        self.category_rules: Dict[str, List[MergedFingerprintRule]] = {}
    
    def load_from_yaml(self, yaml_path: Path):
        """从 YAML 文件加载指纹"""
        with open(yaml_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        for category, items in data.items():
            if not isinstance(items, list):
                continue
            
            for item in items:
                if isinstance(item, dict) and 'name' in item:
                    rule = MergedFingerprintRule(
                        name=item['name'],
                        category=category,
                        level=item.get('level', 'L1'),
                        patterns=item.get('patterns', [])
                    )
                    self.rules.append(rule)
                    
                    if category not in self.category_rules:
                        self.category_rules[category] = []
                    self.category_rules[category].append(rule)
    
    def analyze(
        self,
        body: str = "",
        headers: Dict = None,
        url: str = "",
        cookies: str = "",
        favicon_hash: str = ""
    ) -> List[Tuple[str, str, float, List[str]]]:
        """
        分析并识别指纹
        
        Returns:
            List[Tuple[name, category, confidence, evidence]]
        """
        if headers is None:
            headers = {}
        
        results = []
        
        for rule in self.rules:
            matched, confidence, evidence = rule.match(
                body=body,
                headers=headers,
                url=url,
                cookies=cookies,
                favicon_hash=favicon_hash
            )
            
            if matched and confidence >= 0.5:
                results.append((rule.name, rule.category, confidence, evidence))
        
        results.sort(key=lambda x: x[2], reverse=True)
        return results
