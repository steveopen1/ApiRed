"""
Scanner Agent
扫描Agent - 负责JS/API发现
"""

import re
import time
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse
from .base import BaseAgent, AgentConfig, AgentResult, Action


class ScannerAgent(BaseAgent):
    """扫描Agent - 负责JS资源发现和API端点提取"""
    
    def __init__(self, config: AgentConfig, llm_client: Optional[Any] = None):
        super().__init__(config, llm_client)
        self.target = ""
        self.js_results = []
        self.api_results = []
        self.static_urls = []
    
    async def plan(self, context: Dict) -> List[Action]:
        actions = [
            Action(
                action_type="js_discovery",
                params={'target': context.get('target', '')},
                priority=10
            ),
            Action(
                action_type="api_extraction",
                params={'js_content': context.get('js_content', '')},
                priority=8,
                dependencies=['js_discovery']
            ),
            Action(
                action_type="static_resource_discovery",
                params={'target': context.get('target', '')},
                priority=6
            ),
            Action(
                action_type="endpoint_aggregation",
                params={},
                priority=5,
                dependencies=['api_extraction', 'static_resource_discovery']
            )
        ]
        return actions
    
    async def execute(self, action: Action) -> AgentResult:
        start_time = time.time()
        
        try:
            if action.action_type == "js_discovery":
                result = await self._discover_js(action.params.get('target', ''))
            elif action.action_type == "api_extraction":
                result = await self._extract_apis(action.params.get('js_content', ''))
            elif action.action_type == "static_resource_discovery":
                result = await self._discover_static(action.params.get('target', ''))
            elif action.action_type == "endpoint_aggregation":
                result = await self._aggregate_endpoints()
            else:
                result = AgentResult(
                    agent_name=self.name,
                    action_type=action.action_type,
                    success=False,
                    error=f"Unknown action type: {action.action_type}"
                )
            
            result.duration = time.time() - start_time
            return result
            
        except Exception as e:
            return AgentResult(
                agent_name=self.name,
                action_type=action.action_type,
                success=False,
                error=str(e),
                duration=time.time() - start_time
            )
    
    async def _discover_js(self, target: str) -> AgentResult:
        """JS资源发现"""
        import requests
        from bs4 import BeautifulSoup
        
        js_urls = []
        
        try:
            response = requests.get(target, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            scripts = soup.find_all('script', src=True)
            for script in scripts:
                src = script.get('src', '')
                if src:
                    full_url = self._normalize_url(target, src)
                    js_urls.append(full_url)
            
            return AgentResult(
                agent_name=self.name,
                action_type="js_discovery",
                success=True,
                data={'js_urls': js_urls}
            )
            
        except Exception as e:
            return AgentResult(
                agent_name=self.name,
                action_type="js_discovery",
                success=False,
                error=str(e)
            )
    
    async def _extract_apis(self, js_content: str) -> AgentResult:
        """从JS内容提取API端点"""
        endpoints = []
        
        patterns = [
            r'["\'](\/api\/[^\s"\']+)["\']',
            r'["\'](\/v\d+\/[^\s"\']+)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.[a-z]+\(["\']([^"\']+)',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, js_content)
            endpoints.extend(matches)
        
        endpoints = list(set(endpoints))
        
        return AgentResult(
            agent_name=self.name,
            action_type="api_extraction",
            success=True,
            data={'endpoints': endpoints}
        )
    
    async def _discover_static(self, target: str) -> AgentResult:
        """静态资源发现"""
        return AgentResult(
            agent_name=self.name,
            action_type="static_resource_discovery",
            success=True,
            data={'resources': []}
        )
    
    async def _aggregate_endpoints(self) -> AgentResult:
        """端点聚合去重"""
        all_endpoints = []
        
        for result in self.memory:
            if result.success and result.data:
                endpoints = result.data.get('endpoints', [])
                all_endpoints.extend(endpoints)
        
        unique = list(set(all_endpoints))
        
        return AgentResult(
            agent_name=self.name,
            action_type="endpoint_aggregation",
            success=True,
            data={'unique_endpoints': unique}
        )
    
    def _normalize_url(self, base: str, path: str) -> str:
        """URL规范化"""
        if path.startswith('http'):
            return path
        elif path.startswith('//'):
            return 'https:' + path
        elif path.startswith('/'):
            parsed = urlparse(base)
            return f"{parsed.scheme}://{parsed.netloc}{path}"
        else:
            return base.rstrip('/') + '/' + path
    
    async def think(self, prompt: str, context: Optional[Dict] = None) -> str:
        """LLM增强端点发现"""
        return await super().think(prompt, context)
    
    async def chat(self, messages: List[Dict], system: str = "") -> str:
        """LLM对话"""
        return await super().chat(messages, system)
    
    async def analyze_js(self, js_content: str) -> List[str]:
        """从 JS 中发现 API 端点"""
        if not self.llm_client:
            return []
        
        prompt = f"""Analyze this JavaScript code and extract API endpoint patterns, paths, and routes. Focus on:
1. API base URLs
2. Endpoint paths
3. HTTP methods
4. Request parameters

JS Code:
{js_content[:2000]}

Please list all discovered API endpoints, one per line. Format: METHOD /path"""
        
        try:
            response = await self.chat([{"role": "user", "content": prompt}])
            
            if not response:
                return []
            
            endpoints = []
            for line in response.split('\n'):
                line = line.strip()
                if line and ('/' in line or line.startswith('GET') or line.startswith('POST') or 
                           line.startswith('PUT') or line.startswith('DELETE') or line.startswith('PATCH')):
                    line = re.sub(r'^[-*\d.)\s]+', '', line)
                    if line.startswith('/') or any(line.startswith(m) for m in ['GET ', 'POST ', 'PUT ', 'DELETE ', 'PATCH ']):
                        endpoints.append(line)
            
            return list(set(endpoints))
        except Exception as e:
            import logging
            logging.getLogger(__name__).error(f"analyze_js error: {e}")
            return []
