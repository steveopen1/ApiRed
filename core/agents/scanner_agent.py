"""
Scanner Agent
扫描Agent - 负责JS/API发现
"""

import re
import time
import json
import logging
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse
from .base import BaseAgent, AgentConfig, AgentResult, Action
from ..knowledge_base import KnowledgeBase


class ScannerAgent(BaseAgent):
    """扫描Agent - LLM驱动的智能路径发现"""
    
    def __init__(self, config: AgentConfig, llm_client: Optional[Any] = None):
        super().__init__(config, llm_client)
        self.target = ""
        self.js_results = []
        self.api_results = []
        self.static_urls = []
        self.prediction_cache = {}
        self.knowledge_base: Optional[KnowledgeBase] = None
    
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
        import aiohttp
        from bs4 import BeautifulSoup
        import asyncio
        
        js_urls = []
        
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(target) as response:
                    text = await response.text()
            
            soup = BeautifulSoup(text, 'html.parser')
            
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

    async def predict_endpoints(self, js_content: str, known_endpoints: List[str], 
                            framework_pattern: str = None) -> List[str]:
        """
        基于 JS 代码和已知端点预测新的 API 路径
        
        支持的 API 模式：
        - RESTful: /api/v1/users, /api/v1/users/:id
        - 组件调用: /callComponent/{component}/{action}
        - RPC: /rpc/{service}/{method}
        - 命令式: /cmd?command={cmd}
        
        Args:
            js_content: JS 文件内容
            known_endpoints: 已知的 API 端点列表
            framework_pattern: 框架特定模式（如 "{component}/{action}"）
        
        Returns:
            预测的新端点列表
        """
        cache_key = hash((js_content[:1000], tuple(sorted(known_endpoints[:10])), framework_pattern or ''))
        if cache_key in self.prediction_cache:
            return self.prediction_cache[cache_key]
        
        pattern_hint = ""
        if framework_pattern:
            pattern_hint = f"\nFramework API pattern: {framework_pattern}"
        
        prompt = f"""Analyze this JavaScript code and API patterns to predict additional API endpoints that might exist but weren't explicitly found.

Known endpoints:
{chr(10).join(known_endpoints[:20])}

JavaScript code (first 3000 chars):
{js_content[:3000]}
{pattern_hint}

IMPORTANT: This target may use NON-RESTful API patterns. Consider these patterns:
1. Component-based: /callComponent/{'{component}'}/{'{action}'}  (e.g., /callComponent/login/getSysInfo)
2. RPC-style: /rpc/{'{service}'}/{'{method}'}  (e.g., /rpc/user/getInfo)
3. Command-style: /cmd?command={'{cmd}'}  (e.g., /cmd?command=getUserInfo)
4. RESTful: /api/v1/{'resource'}/{'{id}'}
5. Custom: /{'{module}'}/{'{controller}'}/{'{action}'}

Based on the patterns found in the JavaScript, predict what other API endpoints might exist.
List only the most likely endpoints, one per line, without explanation.
For component-based APIs, use format: /callComponent/component/action
For RPC APIs, use format: /rpc/service/method
For RESTful APIs, use format: /api/v1/resource or /api/v1/resource/id"""
        
        try:
            response = await self.chat([{"role": "user", "content": prompt}])
            if not response:
                return self._rule_based_prediction(known_endpoints, framework_pattern)
            
            predicted = self._parse_endpoints(response)
            predicted = [ep for ep in predicted if ep not in known_endpoints]
            self.prediction_cache[cache_key] = predicted
            return predicted
        except Exception as e:
            import logging
            logging.getLogger(__name__).error(f"predict_endpoints error: {e}")
            return self._rule_based_prediction(known_endpoints, framework_pattern)
    
    def _rule_based_prediction(self, known_endpoints: List[str], framework_pattern: str = None) -> List[str]:
        """无 LLM 时的规则预测"""
        predicted = []
        
        components = ['login', 'admin', 'system', 'user', 'role', 'config', 'dict', 'log']
        actions = ['getSysInfo', 'getConfig', 'getUserInfo', 'list', 'get', 'add', 'edit', 'delete', 'query', 'export', 'import']
        
        if framework_pattern and '{component}' in framework_pattern and '{action}' in framework_pattern:
            base_path = framework_pattern.split('{component}')[0]
            for comp in components:
                for action in actions:
                    endpoint = f"{base_path}{comp}/{action}"
                    if endpoint not in known_endpoints:
                        predicted.append(endpoint)
        
        for comp in components:
            for action in actions:
                endpoint = f"/callComponent/{comp}/{action}"
                if endpoint not in known_endpoints:
                    predicted.append(endpoint)
        
        common_resources = ['users', 'orders', 'products', 'auth', 'admin']
        for resource in common_resources:
            if f"/api/v1/{resource}" not in known_endpoints:
                predicted.append(f"/api/v1/{resource}")
        
        return predicted[:50]
    
    async def analyze_api_context(self, endpoint: str, response_content: str) -> Dict:
        """
        分析 API 上下文，提取关联资源和参数
        
        Returns:
            包含关联端点、参数模式、业务逻辑线索的字典
        """
        if not self.llm_client:
            return {"related_endpoints": [], "parameters": [], "business_logic": []}
        
        prompt = f"""Analyze this API endpoint and its response to extract context and relationships.

Endpoint: {endpoint}

Response content (first 2000 chars):
{response_content[:2000]}

Please analyze and return in JSON format:
{{
    "related_endpoints": ["list of potentially related endpoints found in response"],
    "parameters": ["inferred parameter names and types"],
    "business_logic": ["business logic clues found in the response"]
}}

Only output the JSON, without explanation."""
        
        try:
            response = await self.chat([{"role": "user", "content": prompt}])
            if not response:
                return {"related_endpoints": [], "parameters": [], "business_logic": []}
            
            json_match = re.search(r'\{[^{}]*\}', response, re.DOTALL)
            if json_match:
                result = json.loads(json_match.group())
                return result
            return {"related_endpoints": [], "parameters": [], "business_logic": []}
        except Exception as e:
            logging.getLogger(__name__).error(f"analyze_api_context error: {e}")
            return {"related_endpoints": [], "parameters": [], "business_logic": []}
    
    async def suggest_fuzz_targets(self, base_url: str, context: Dict) -> List[Dict]:
        """
        建议 Fuzz 目标和方法
        
        Returns:
            包含路径、参数、方法的字典列表
        """
        if not self.llm_client:
            return []
        
        context_str = json.dumps(context, ensure_ascii=False)[:2000] if context else ""
        
        prompt = f"""Based on the following API context, suggest fuzzing targets and methods.

Base URL: {base_url}

Context:
{context_str}

Suggest fuzz targets in JSON format:
[
    {{
        "path": "/example/path",
        "method": "GET|POST|PUT|DELETE",
        "params": ["param1", "param2"],
        "fuzz_strategy": "description of fuzzing approach"
    }}
]

Only output the JSON array."""
        
        try:
            response = await self.chat([{"role": "user", "content": prompt}])
            if not response:
                return []
            
            json_match = re.search(r'\[[\s\S]*\]', response)
            if json_match:
                targets = json.loads(json_match.group())
                return targets
            return []
        except Exception as e:
            logging.getLogger(__name__).error(f"suggest_fuzz_targets error: {e}")
            return []
    
    def _parse_endpoints(self, llm_response: str) -> List[str]:
        """解析 LLM 响应，提取端点列表"""
        endpoints = []
        for line in llm_response.strip().split('\n'):
            line = line.strip()
            if line.startswith('/') or line.startswith('http'):
                line = re.sub(r'^[-*\d.)\s]+', '', line)
                if line.startswith('/') or line.startswith('http'):
                    endpoints.append(line)
        return list(set(endpoints))
