"""
Smart Click Scorer Module
智能点击评分模块
参考 FLUX v5.0 轻量交互引擎
"""

from typing import List, Dict, Any, Tuple, Set
from dataclasses import dataclass
import re


@dataclass
class ClickCandidate:
    """可点击元素"""
    element_tag: str
    text: str
    attributes: Dict[str, str]
    href: str
    xpath: str
    score: float = 0.0
    clickable: bool = True
    risk_level: str = 'low'


class SmartClickScorer:
    """
    智能点击评分器
    
    对页面元素进行评分，决定是否点击
    - 避开危险操作 (delete, pay, logout 等)
    - 优先高价值元素 (menu, nav, tab 等)
    - 控制点击预算
    """
    
    HIGH_VALUE_TAGS = ['a', 'button', 'input']
    
    HIGH_VALUE_PATTERNS = [
        (r'menu', 3.0),
        (r'nav', 3.0),
        (r'tab', 2.5),
        (r'accordion', 2.5),
        (r'sidebar', 2.5),
        (r'dropdown', 2.0),
        (r'select', 2.0),
        (r'link', 1.5),
        (r'click', 1.5),
        (r'toggle', 1.5),
        (r'expander', 1.5),
        (r'pagination', 1.0),
        (r'breadcrumb', 0.8),
    ]
    
    DANGEROUS_PATTERNS = [
        (r'delete', -10.0),
        (r'del', -10.0),
        (r'remove', -10.0),
        (r'drop', -10.0),
        (r'truncate', -10.0),
        (r'destroy', -10.0),
        (r'logout', -8.0),
        (r'log-out', -8.0),
        (r'sign.?out', -8.0),
        (r'exit', -8.0),
        (r'quit', -8.0),
        (r'pay', -7.0),
        (r'payment', -7.0),
        (r'buy', -7.0),
        (r'purchase', -7.0),
        (r'submit', -5.0),
        (r'save', -5.0),
        (r'apply', -5.0),
        (r'confirm', -5.0),
        (r'cancel', -3.0),
        (r'close', -3.0),
        (r'back', -2.0),
        (r'refresh', -2.0),
        (r'reload', -2.0),
    ]
    
    THIRD_PARTY_DOMAINS = [
        'google-analytics.com',
        'googletagmanager.com',
        'facebook.net',
        'facebook.com/tr',
        'doubleclick.net',
        'analytics',
        'tracking',
        'segment.io',
        'mixpanel.com',
        'hotjar.com',
        'zendesk.com',
        'intercom.io',
        'drift.com',
        'marketo.com',
        'pardot.com',
        'eloqua.com',
        'hubspot.com',
        'mouseflow.com',
        'crazyegg.com',
        'quantserve.com',
        'scorecardresearch.com',
        'cdn.*\\.js',
    ]
    
    ANALYTICS_PATTERNS = [
        '/analytics',
        '/tracking',
        '/pixel',
        '/beacon',
        '/log',
        '/collect',
        '/event',
    ]
    
    def __init__(self, budget: int = 20):
        """
        初始化智能点击评分器
        
        Args:
            budget: 最大点击预算
        """
        self.budget = budget
        self.clicked_urls: Set[str] = set()
        self.click_count = 0
    
    def can_click(self) -> bool:
        """检查是否还能点击"""
        return self.click_count < self.budget
    
    def reset(self):
        """重置点击计数器"""
        self.clicked_urls.clear()
        self.click_count = 0
    
    def score_element(
        self,
        tag: str,
        text: str,
        href: str = "",
        attributes: Dict[str, str] = None
    ) -> ClickCandidate:
        """
        对元素进行评分
        
        Args:
            tag: HTML 标签
            text: 元素文本
            href: 链接地址
            attributes: 元素属性
            
        Returns:
            ClickCandidate: 评分后的元素
        """
        if attributes is None:
            attributes = {}
        
        candidate = ClickCandidate(
            element_tag=tag.lower(),
            text=text,
            attributes=attributes,
            href=href,
            xpath=""
        )
        
        if not self.can_click():
            candidate.clickable = False
            candidate.score = -100.0
            candidate.risk_level = 'blocked'
            return candidate
        
        score = 5.0
        
        tag_lower = tag.lower()
        text_lower = text.lower()
        href_lower = href.lower()
        
        if tag_lower == 'a':
            score += 2.0
        elif tag_lower == 'button':
            score += 1.5
        elif tag_lower == 'input':
            if attributes.get('type', '').lower() in ['submit', 'button']:
                score += 1.0
        
        for pattern, bonus in self.HIGH_VALUE_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                score += bonus
                break
        
        for pattern, penalty in self.DANGEROUS_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                score += penalty
                candidate.risk_level = 'dangerous'
                break
        
        if href_lower:
            for pattern, penalty in self.DANGEROUS_PATTERNS:
                if re.search(pattern, href_lower, re.IGNORECASE):
                    score += penalty
                    candidate.risk_level = 'dangerous'
                    break
            
            if href_lower.startswith('javascript:'):
                score += 1.0
            
            if self._is_third_party(href_lower):
                score -= 5.0
        
        if attributes.get('disabled'):
            score -= 10.0
            candidate.clickable = False
        
        if attributes.get('hidden'):
            score -= 5.0
        
        if '{id}' in href_lower or '{pk}' in href_lower:
            score += 1.5
        
        candidate.score = score
        
        if score < 0:
            candidate.clickable = False
            candidate.risk_level = 'dangerous'
        
        return candidate
    
    def should_click(self, candidate: ClickCandidate) -> bool:
        """
        判断是否应该点击
        
        Args:
            candidate: 点击候选元素
            
        Returns:
            bool: 是否应该点击
        """
        if not candidate.clickable:
            return False
        
        if candidate.score < 0:
            return False
        
        if candidate.href and candidate.href in self.clicked_urls:
            return False
        
        return self.can_click()
    
    def record_click(self, href: str):
        """
        记录已点击的链接
        
        Args:
            href: 点击的链接
        """
        if href and href.startswith('http'):
            self.clicked_urls.add(href)
        self.click_count += 1
    
    def _is_third_party(self, href: str) -> bool:
        """检查是否为第三方链接"""
        for domain in self.THIRD_PARTY_DOMAINS:
            if re.search(domain, href, re.IGNORECASE):
                return True
        for pattern in self.ANALYTICS_PATTERNS:
            if pattern in href:
                return True
        return False
    
    def filter_candidates(
        self,
        candidates: List[ClickCandidate]
    ) -> List[ClickCandidate]:
        """
        过滤并排序候选元素
        
        Args:
            candidates: 候选元素列表
            
        Returns:
            List[ClickCandidate]: 排序后的可点击元素
        """
        clickable = [c for c in candidates if self.should_click(c)]
        
        clickable.sort(key=lambda x: x.score, reverse=True)
        
        return clickable[:self.budget]


def is_dangerous_operation(text: str, href: str = "") -> bool:
    """
    便捷函数：判断是否为危险操作
    
    Args:
        text: 元素文本
        href: 链接地址
        
    Returns:
        bool: 是否危险
    """
    scorer = SmartClickScorer()
    candidate = scorer.score_element('a', text, href)
    return candidate.risk_level == 'dangerous'


def is_high_value_element(text: str) -> bool:
    """
    便捷函数：判断是否是高价值元素
    
    Args:
        text: 元素文本
        
    Returns:
        bool: 是否高价值
    """
    scorer = SmartClickScorer()
    candidate = scorer.score_element('a', text)
    return candidate.score > 6.0
