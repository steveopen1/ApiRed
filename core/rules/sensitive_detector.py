"""
Sensitive Information Rule Engine
规则化敏感信息检测引擎
基于 0x727/ChkApi rule.yaml
"""

import re
import yaml
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass
from pathlib import Path


@dataclass
class SensitiveRule:
    """敏感信息检测规则"""
    name: str
    f_regex: str
    scope: str  # any, request, response body, header
    sensitive: bool
    description: str
    color: str = "green"
    
    def __post_init__(self):
        try:
            self._compiled = re.compile(self.f_regex, re.VERBOSE | re.IGNORECASE)
        except Exception:
            self._compiled = None
    
    def match(self, text: str) -> List[str]:
        """在文本中匹配规则"""
        if not self._compiled or not text:
            return []
        try:
            return self._compiled.findall(text)
        except Exception:
            return []


@dataclass
class SensitiveFinding:
    """敏感信息发现"""
    rule_name: str
    match_value: str
    scope: str
    sensitive: bool
    description: str
    position: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'rule_name': self.rule_name,
            'match_value': self.match_value[:100] if len(self.match_value) > 100 else self.match_value,
            'scope': self.scope,
            'sensitive': self.sensitive,
            'description': self.description
        }


class SensitiveRuleEngine:
    """
    敏感信息规则引擎
    
    支持：
    - YAML 规则文件加载
    - 多规则并行匹配
    - 按组分类检测
    - 高亮标记输出
    """
    
    def __init__(self, rules_path: Optional[str] = None):
        self.rules: List[SensitiveRule] = []
        self.rules_by_group: Dict[str, List[SensitiveRule]] = {}
        self._loaded = False
        
        if rules_path:
            self.load_rules(rules_path)
        else:
            self.load_default_rules()
    
    def load_rules(self, rules_path: str) -> bool:
        """从 YAML 文件加载规则"""
        try:
            with open(rules_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            
            if not data or 'rules' not in data:
                return False
            
            for group_data in data['rules']:
                group_name = group_data.get('group', 'Unknown')
                group_rules = []
                
                for rule_data in group_data.get('rule', []):
                    if rule_data.get('loaded', True):
                        rule = SensitiveRule(
                            name=rule_data.get('name', 'unnamed'),
                            f_regex=rule_data.get('f_regex', ''),
                            scope=rule_data.get('scope', 'any'),
                            sensitive=rule_data.get('sensitive', False),
                            description=rule_data.get('description', ''),
                            color=rule_data.get('color', 'green')
                        )
                        if rule.f_regex:
                            self.rules.append(rule)
                            group_rules.append(rule)
                
                if group_rules:
                    self.rules_by_group[group_name] = group_rules
            
            self._loaded = True
            return True
        except Exception as e:
            print(f"Failed to load rules: {e}")
            return False
    
    def load_default_rules(self):
        """加载默认规则"""
        default_rules_path = Path(__file__).parent / 'sensitive_rules.yaml'
        if default_rules_path.exists():
            self.load_rules(str(default_rules_path))
    
    def detect(self, text: str, groups: Optional[List[str]] = None) -> List[SensitiveFinding]:
        """
        在文本中检测敏感信息
        
        Args:
            text: 待检测文本
            groups: 指定规则组（None 表示全部）
        
        Returns:
            检测到的敏感信息列表
        """
        findings = []
        
        rules_to_check = self.rules
        if groups:
            rules_to_check = []
            for g in groups:
                if g in self.rules_by_group:
                    rules_to_check.extend(self.rules_by_group[g])
        
        for rule in rules_to_check:
            matches = rule.match(text)
            for match in matches:
                if isinstance(match, tuple):
                    match = ' '.join(str(m) for m in match if m)
                
                if match:
                    findings.append(SensitiveFinding(
                        rule_name=rule.name,
                        match_value=str(match),
                        scope=rule.scope,
                        sensitive=rule.sensitive,
                        description=rule.description
                    ))
        
        return findings
    
    def detect_all(self, text: str) -> Dict[str, List[SensitiveFinding]]:
        """按组分类检测"""
        results = {}
        
        for group_name, rules in self.rules_by_group.items():
            group_findings = []
            for rule in rules:
                matches = rule.match(text)
                for match in matches:
                    if isinstance(match, tuple):
                        match = ' '.join(str(m) for m in match if m)
                    if match:
                        group_findings.append(SensitiveFinding(
                            rule_name=rule.name,
                            match_value=str(match),
                            scope=rule.scope,
                            sensitive=rule.sensitive,
                            description=rule.description
                        ))
            if group_findings:
                results[group_name] = group_findings
        
        return results
    
    def get_sensitive_findings(self, text: str) -> List[SensitiveFinding]:
        """仅获取敏感信息发现"""
        all_findings = self.detect(text)
        return [f for f in all_findings if f.sensitive]
    
    def get_highlights(self, text: str) -> Dict[str, List[Dict]]:
        """获取高亮标记"""
        highlights = {}
        
        for finding in self.detect(text):
            if finding.rule_name not in highlights:
                highlights[finding.rule_name] = []
            highlights[finding.rule_name].append({
                'match': finding.match_value,
                'description': finding.description,
                'sensitive': finding.sensitive
            })
        
        return highlights
    
    def get_rule_count(self) -> int:
        """获取规则数量"""
        return len(self.rules)
    
    def get_group_count(self) -> int:
        """获取规则组数量"""
        return len(self.rules_by_group)


def create_rule_engine(rules_path: Optional[str] = None) -> SensitiveRuleEngine:
    """创建规则引擎"""
    return SensitiveRuleEngine(rules_path)
