"""
Framework Rule Engine
可扩展的框架识别规则引擎
"""

import re
import os
import yaml
import hashlib
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from pathlib import Path


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
                    print(f"Failed to load rule {rule_file}: {e}")
    
    def load_custom_rule(self, rule_data: Dict) -> bool:
        """加载自定义规则"""
        try:
            name = rule_data.get('framework', {}).get('name', 'custom')
            self.rules[name] = FrameworkRule(name, rule_data)
            return True
        except Exception:
            return False
    
    def load_rule_file(self, file_path: str) -> bool:
        """从文件加载规则"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                rule_data = yaml.safe_load(f)
            return self.load_custom_rule(rule_data)
        except Exception:
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
            print(f"LLM assisted detection failed: {e}")
        
        return self.detect_best(target_info)


def load_default_fingerprints() -> FrameworkDetector:
    """加载默认指纹库"""
    return FrameworkDetector()
