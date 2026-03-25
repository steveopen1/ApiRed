#!/usr/bin/env python3
"""
状态化动态 Spider - 基于 FLUX v1.1
BFS状态队列调度，多维去重
"""

import asyncio
import hashlib
import logging
from typing import List, Dict, Set, Optional, Tuple, Callable
from dataclasses import dataclass, field
from collections import deque
from urllib.parse import urlparse, urljoin

logger = logging.getLogger(__name__)


@dataclass
class PageState:
    """页面状态"""
    url: str
    title: str = ""
    html_hash: str = ""
    links: List[str] = field(default_factory=list)
    forms: List[Dict] = field(default_factory=list)
    inputs: List[Dict] = field(default_factory=list)
    route_path: str = ""
    source_page: str = ""
    click_chain: List[str] = field(default_factory=list)
    depth: int = 0
    timestamp: float = 0.0


class StateBudget:
    """状态预算控制"""
    def __init__(self, max_states: int = 100, max_clicks_total: int = 50,
                 max_clicks_per_page: int = 3, max_depth: int = 5,
                 max_pages_per_domain: int = 50, max_route_states: int = 20):
        self.max_states = max_states
        self.max_clicks_total = max_clicks_total
        self.max_clicks_per_page = max_clicks_per_page
        self.max_depth = max_depth
        self.max_pages_per_domain = max_pages_per_domain
        self.max_route_states = max_route_states

        self.current_states = 0
        self.current_clicks = 0
        self.visited_domains: Dict[str, int] = {}

    def can_add_state(self) -> bool:
        return self.current_states < self.max_states

    def can_click(self, page_url: str = "") -> bool:
        if self.current_clicks >= self.max_clicks_total:
            return False
        domain = urlparse(page_url).netloc if page_url else "unknown"
        clicks_on_page = sum(1 for url in self.click_history if url == page_url)
        return clicks_on_page < self.max_clicks_per_page

    def add_state(self):
        self.current_states += 1

    def add_click(self, page_url: str):
        self.current_clicks += 1
        self.click_history.append(page_url)

    def is_exceeded(self) -> bool:
        return self.current_states >= self.max_states


@dataclass
class ClickTarget:
    """点击目标"""
    url: str
    element_type: str
    element_text: str
    element_attrs: Dict
    score: float
    is_dangerous: bool = False


class ClickTargetEvaluator:
    """点击目标评分器"""

    HIGH_VALUE_ELEMENTS = {
        'a': ['menu', 'nav', 'tab', 'accordion', 'dropdown', 'link', 'button'],
        'button': ['menu', 'nav', 'tab', 'dropdown', 'toggle', 'btn'],
        'div': ['menu', 'nav', 'tab', 'accordion', 'dropdown', 'panel'],
    }

    DANGEROUS_ELEMENTS = {
        'delete', 'remove', 'logout', 'signout', 'exit', 'quit',
        'submit', 'send', 'post', 'pay', 'purchase', 'buy',
        'reset', 'clear', 'drop', 'truncate', 'shutdown', 'reboot',
    }

    def evaluate(self, element: Dict, context: str = "") -> ClickTarget:
        element_type = element.get('tag', 'unknown').lower()
        element_text = element.get('text', '').lower()
        element_attrs = element.get('attrs', {})

        href = element_attrs.get('href', '')
        url = href if href.startswith('http') else urljoin(context, href) if href else ''

        score = self._calculate_score(element_type, element_text, element_attrs, context)
        is_dangerous = self._is_dangerous(element_text)

        return ClickTarget(
            url=url,
            element_type=element_type,
            element_text=element.get('text', ''),
            element_attrs=element_attrs,
            score=score,
            is_dangerous=is_dangerous
        )

    def _calculate_score(self, element_type: str, element_text: str,
                        element_attrs: Dict, context: str) -> float:
        score = 0.5

        if element_type in self.HIGH_VALUE_ELEMENTS:
            for keyword in self.HIGH_VALUE_ELEMENTS.get(element_type, []):
                if keyword in element_text:
                    score += 0.2
                    break

        if element_attrs.get('id'):
            id_lower = element_attrs['id'].lower()
            for keyword in ['menu', 'nav', 'tab', 'content', 'panel']:
                if keyword in id_lower:
                    score += 0.15
                    break

        if element_attrs.get('class'):
            class_lower = element_attrs['class'].lower()
            for keyword in ['menu', 'nav', 'tab', 'content', 'panel', 'accordion']:
                if keyword in class_lower:
                    score += 0.1
                    break

        if 'dropdown' in element_text or 'select' in element_type:
            score += 0.1

        return min(score, 1.0)

    def _is_dangerous(self, element_text: str) -> bool:
        text_lower = element_text.lower()
        for keyword in self.DANGEROUS_ELEMENTS:
            if keyword in text_lower:
                return True
        return False


class StateDeduplicator:
    """状态去重器"""

    def __init__(self):
        self.seen_urls: Set[str] = set()
        self.seen_hashes: Set[str] = set()
        self.seen_routes: Set[str] = set()
        self.seen_click_chains: Set[str] = set()

    def add_state(self, state: PageState) -> bool:
        url_key = self._normalize_url(state.url)
        if url_key in self.seen_urls:
            return False
        self.seen_urls.add(url_key)

        if state.html_hash:
            if state.html_hash in self.seen_hashes:
                return False
            self.seen_hashes.add(state.html_hash)

        if state.route_path:
            route_key = f"{urlparse(url_key).path}:{state.route_path}"
            if route_key in self.seen_routes:
                return False
            self.seen_routes.add(route_key)

        if state.click_chain:
            chain_key = '|'.join(state.click_chain)
            if chain_key in self.seen_click_chains:
                return False
            self.seen_click_chains.add(chain_key)

        return True

    def _normalize_url(self, url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    def is_duplicate(self, state: PageState) -> bool:
        url_key = self._normalize_url(state.url)
        return url_key in self.seen_urls


class StateQueue:
    """状态队列"""

    def __init__(self, budget: StateBudget):
        self.budget = budget
        self.queue = deque()
        self.pending_clicks: Dict[str, List[ClickTarget]] = {}

    def add(self, state: PageState, priority: int = 0):
        if self.budget.can_add_state():
            self.queue.append(state)
            self.budget.add_state()

    def add_with_clicks(self, state: PageState, clicks: List[ClickTarget]):
        if self.budget.can_add_state():
            self.queue.append(state)
            self.budget.add_state()
            if clicks:
                self.pending_clicks[state.url] = clicks

    def pop(self) -> Optional[PageState]:
        if self.queue:
            return self.queue.popleft()
        return None

    def get_pending_clicks(self, url: str) -> List[ClickTarget]:
        return self.pending_clicks.get(url, [])

    def is_empty(self) -> bool:
        return len(self.queue) == 0

    def size(self) -> int:
        return len(self.queue)


async def bfs_spider(start_url: str, session,
                   max_depth: int = 3,
                   evaluator: ClickTargetEvaluator = None,
                   on_page_discovered: Callable = None) -> List[PageState]:
    budget = StateBudget(max_depth=max_depth)
    deduplicator = StateDeduplicator()
    state_queue = StateQueue(budget)
    evaluator = evaluator or ClickTargetEvaluator()

    initial_state = PageState(url=start_url, depth=0)
    state_queue.add(initial_state)
    discovered_states = []

    while not state_queue.is_empty() and not budget.is_exceeded():
        current_state = state_queue.pop()
        if not current_state:
            continue

        try:
            response = await session.get(current_state.url)
            html = response.text if hasattr(response, 'text') else ''

            state = _parse_page_state(current_state.url, html, current_state)
            state.click_chain = current_state.click_chain

            if deduplicator.add_state(state):
                discovered_states.append(state)
                if on_page_discovered:
                    on_page_discovered(state)

            links = _extract_links(html, current_state.url)
            for link_url in links:
                if budget.can_add_state():
                    new_state = PageState(
                        url=link_url,
                        depth=current_state.depth + 1,
                        source_page=current_state.url,
                        click_chain=current_state.click_chain + [current_state.url]
                    )
                    state_queue.add(new_state)

        except Exception as e:
            logger.debug(f"Spider error: {e}")

    return discovered_states


def _parse_page_state(url: str, html: str, parent_state: PageState) -> PageState:
    import re
    title_match = re.search(r'<title>(.*?)</title>', html, re.I)
    title = title_match.group(1) if title_match else ''

    html_hash = hashlib.md5(html.encode()).hexdigest()

    link_pattern = r'<a[^>]+href=["\']([^"\']+)["\']'
    links = [m.group(1) for m in re.finditer(link_pattern, html, re.I)]

    form_pattern = r'<form[^>]*>(.*?)</form>'
    forms = []
    for form_match in re.finditer(form_pattern, html, re.DOTALL | re.I):
        forms.append({'html': form_match.group(0)[:200]})

    return PageState(
        url=url,
        title=title.strip(),
        html_hash=html_hash,
        links=links,
        forms=forms,
        depth=parent_state.depth,
        source_page=parent_state.source_page,
        click_chain=parent_state.click_chain
    )


def _extract_links(html: str, base_url: str) -> List[str]:
    import re
    links = []
    link_pattern = r'<a[^>]+href=["\']([^"\']+)["\']'
    for match in re.finditer(link_pattern, html, re.I):
        href = match.group(1)
        if href and not href.startswith(('javascript:', '#', 'mailto:', 'tel:')):
            if href.startswith('http'):
                links.append(href)
            elif href.startswith('/'):
                parsed = urlparse(base_url)
                links.append(f"{parsed.scheme}://{parsed.netloc}{href}")
    return links


__all__ = ['StateBudget', 'StateDeduplicator', 'StateQueue', 'ClickTargetEvaluator', 'PageState', 'bfs_spider']
