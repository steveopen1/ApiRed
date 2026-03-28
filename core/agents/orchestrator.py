"""
Agent Orchestrator Module
Agent 编排器 - 负责协调多个 Agent 的任务执行
"""

import asyncio
import os
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import logging

from ..knowledge_base import KnowledgeBase, APIEndpoint, Finding
from ..dashboard.models import TaskStatus

logger = logging.getLogger(__name__)


AI_ENV_VARS = {
    'DEEPSEEK_API_KEY': 'DeepSeek API Key',
    'OPENAI_API_KEY': 'OpenAI API Key',
    'ANTHROPIC_API_KEY': 'Anthropic API Key',
    'CUSTOM_API_KEY': 'Custom API Key',
    'AI_PROVIDER': 'AI Provider (deepseek/openai/anthropic/custom)',
    'AI_BASE_URL': 'AI Base URL',
    'AI_MODEL': 'AI Model ID',
    'AI_API_FORMAT': 'API Format (openai/anthropic)',
}


def check_ai_config() -> Dict[str, str]:
    """
    检查 AI 配置环境变量
    
    Returns:
        Dict of missing env vars and their descriptions
    """
    missing = {}
    for var, desc in AI_ENV_VARS.items():
        value = os.environ.get(var, '').strip()
        if not value and var.endswith('_API_KEY'):
            missing[var] = desc
    return missing


PROVIDER_MODEL_PREFIX = {
    "anthropic": "anthropic/",
    "deepseek": "deepseek/",
    "gemini": "gemini/",
    "mistral": "mistral/",
    "ollama": "ollama/",
    "openai": "",
}

LLM_MODEL_MAPPING = {
    "claude-sonnet-4-20250514": "anthropic/claude-sonnet-4-20250514",
    "claude-opus-4-20250514": "anthropic/claude-opus-4-20250514",
    "claude-3-5-sonnet-20241022": "anthropic/claude-3-5-sonnet-20241022",
    "gpt-4o": "openai/gpt-4o",
    "gpt-4o-mini": "openai/gpt-4o-mini",
    "deepseek-chat": "deepseek/deepseek-chat",
    "deepseek-coder": "deepseek/deepseek-coder",
}

def get_ai_config() -> Dict[str, str]:
    """
    获取 AI 配置（统一使用 Config 类）
    
    Returns:
        Dict of AI configuration
    """
    from ..utils.config import Config
    
    config = Config()
    ai_config = config.get_ai_config()
    
    model = ai_config.get('model', 'deepseek-chat')
    api_format = ai_config.get('api_format', 'openai')
    
    llm_model_id = ""
    if model in LLM_MODEL_MAPPING:
        llm_model_id = LLM_MODEL_MAPPING[model]
    elif api_format in PROVIDER_MODEL_PREFIX:
        prefix = PROVIDER_MODEL_PREFIX[api_format]
        if prefix and not model.startswith(prefix.rstrip('/') + '/'):
            llm_model_id = f"{prefix.rstrip('/')}/{model}"
        else:
            llm_model_id = model
    else:
        llm_model_id = model
    
    return {
        'provider': ai_config.get('provider', 'deepseek'),
        'api_key': ai_config.get('api_key', ''),
        'base_url': ai_config.get('base_url', 'https://api.deepseek.com/v1'),
        'model': model,
        'api_format': api_format,
        'llm_model_id': llm_model_id,
    }


def print_ai_config_guide():
    """打印 AI 配置指南"""
    current_config = get_ai_config()
    
    api_key_display = ('*' * 20) if current_config['api_key'] else 'NOT SET'
    
    print(f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                     AI Configuration Required                          ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                        ║
║  Agent 模式需要配置 AI API 密钥才能使用 LLM 功能。                     ║
║  使用 llm 库统一管理，支持多种模型提供商。                             ║
║                                                                        ║
║  当前配置:                                                              ║
║    Provider: {current_config['provider']:20}                   ║
║    Model: {current_config['model']:30}                   ║
║    LLM Model ID: {current_config['llm_model_id']:30}         ║
║    API Format: {current_config['api_format']:20}                    ║
║    API Key: {api_key_display:20}                    ║
║                                                                        ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                        ║
║  OpenAI Models:                                                        ║
║    gpt-4o, gpt-4o-mini, gpt-4-turbo, gpt-3.5-turbo                    ║
║                                                                        ║
║  Anthropic Models (Claude):                                             ║
║    claude-3-5-sonnet, claude-3-5-haiku, claude-opus-4, claude-sonnet-4 ║
║                                                                        ║
║  Google Gemini Models:                                                  ║
║    gemini-2.0-flash, gemini-2.0-pro, gemini-1.5-flash, gemini-1.5-pro  ║
║                                                                        ║
║  DeepSeek Models:                                                       ║
║    deepseek-chat, deepseek-coder                                       ║
║                                                                        ║
║  Mistral Models:                                                       ║
║    mistral-large, mistral-small, mistral-medium, codestral             ║
║                                                                        ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                        ║
║  配置示例:                                                             ║
║                                                                        ║
║  OpenAI:                                                               ║
║    export OPENAI_API_KEY="sk-xxxx"                                     ║
║    export AI_MODEL="gpt-4o-mini"                                        ║
║    export AI_API_FORMAT="openai"                                        ║
║                                                                        ║
║  Anthropic:                                                            ║
║    export ANTHROPIC_API_KEY="sk-ant-xxxx"                              ║
║    export AI_MODEL="claude-3-5-sonnet"                                  ║
║    export AI_API_FORMAT="anthropic"                                     ║
║                                                                        ║
║  Google Gemini:                                                        ║
║    export GEMINI_API_KEY="xxxx"                                        ║
║    export AI_MODEL="gemini-2.0-flash"                                  ║
║    export AI_API_FORMAT="gemini"                                        ║
║                                                                        ║
║  DeepSeek:                                                             ║
║    export DEEPSEEK_API_KEY="sk-xxxx"                                   ║
║    export AI_MODEL="deepseek-chat"                                      ║
║    export AI_API_FORMAT="deepseek"                                     ║
║                                                                        ║
║  Mistral:                                                             ║
║    export MISTRAL_API_KEY="xxxx"                                       ║
║    export AI_MODEL="mistral-large"                                     ║
║    export AI_API_FORMAT="mistral"                                       ║
║                                                                        ║
║  Ollama (本地):                                                        ║
║    export AI_MODEL="llama3"                                            ║
║    export AI_API_FORMAT="ollama"                                        ║
║                                                                        ║
║  自定义 API (硅基流动等):                                              ║
║    export CUSTOM_API_KEY="your-api-key"                                 ║
║    export AI_BASE_URL="https://api.siliconflow.cn/v1"                  ║
║    export AI_MODEL="Qwen/Qwen2.5-72B-Instruct"                         ║
║    export AI_API_FORMAT="openai"                                        ║
║                                                                        ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                        ║
║  查看所有可用模型:                                                     ║
║    python -c "import llm; print([m.model_id for m in llm.get_models()])"║
║                                                                        ║
║  或者使用传统模式 (无需配置 AI):                                  ║
║    python main.py scan -u http://example.com                           ║
║                                                                        ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """)


@dataclass
class Task:
    """扫描任务"""
    task_id: str
    agent_name: str
    task_type: str
    params: Dict[str, Any]
    status: TaskStatus = TaskStatus.PENDING
    result: Any = None
    error: str = ""
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    started_at: str = ""
    completed_at: str = ""


@dataclass
class ScanContext:
    """扫描上下文"""
    target: str
    cookies: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    concurrency: int = 50
    ai_enabled: bool = False
    knowledge_base: Optional[KnowledgeBase] = None
    
    def __post_init__(self):
        if self.knowledge_base is None:
            self.knowledge_base = KnowledgeBase()


class AgentInterface:
    """Agent 接口定义（支持规则+AI双引擎）"""
    
    def __init__(self, name: str, llm_client=None):
        self.name = name
        self.knowledge_base: Optional[KnowledgeBase] = None
        self.llm_client = llm_client
        self.ai_enabled = False
    
    async def initialize(self, context: ScanContext) -> None:
        """初始化 Agent"""
        self.knowledge_base = context.knowledge_base
        self.ai_enabled = getattr(context, 'ai_enabled', False) and self.llm_client is not None
        if self.ai_enabled:
            logger.info(f"{self.name}: AI mode enabled")
        else:
            logger.info(f"{self.name}: Rule-based mode (AI not available)")
    
    async def execute(self, context: ScanContext) -> Any:
        """执行任务"""
        raise NotImplementedError
    
    async def cleanup(self) -> None:
        """清理资源"""
        pass
    
    async def think(self, prompt: str, context: Optional[Dict] = None) -> str:
        """AI思考 - 使用LLM分析当前状态"""
        if not self.llm_client:
            return ""
        
        try:
            import json
            context_str = json.dumps(context, ensure_ascii=False) if context else ""
            full_prompt = f"{prompt}\n\n上下文信息:\n{context_str}" if context_str else prompt
            
            response = self.llm_client.chat(
                messages=[{"role": "user", "content": full_prompt}],
                system="你是一个专业的安全分析助手，负责分析API和漏洞信息。"
            )
            
            if hasattr(response, 'success') and response.success:
                return getattr(response, 'result', str(response))
            elif isinstance(response, str):
                return response
            return ""
        except Exception as e:
            logger.debug(f"{self.name} think error: {e}")
            return ""
    
    async def chat(self, messages: List[Dict], system: str = "") -> str:
        """AI对话"""
        if not self.llm_client:
            return ""
        
        try:
            response = self.llm_client.chat(
                messages=messages,
                system=system or "你是一个专业的安全分析助手。"
            )
            
            if hasattr(response, 'success') and response.success:
                return getattr(response, 'result', str(response))
            elif isinstance(response, str):
                return response
            return ""
        except Exception as e:
            logger.debug(f"{self.name} chat error: {e}")
            return ""


class Orchestrator:
    """
    Agent 编排器
    负责协调多个 Agent 的任务执行
    """
    
    def __init__(self, context: ScanContext):
        self.context = context
        self.knowledge_base = context.knowledge_base
        self.agents: Dict[str, AgentInterface] = {}
        self.tasks: Dict[str, Task] = {}
        self.task_queue: asyncio.Queue = asyncio.Queue()
        self._running = False
        self._callbacks: Dict[str, List[Callable]] = {
            'task_start': [],
            'task_progress': [],
            'task_complete': [],
            'task_fail': [],
            'scan_complete': [],
        }
    
    def register_agent(self, agent: AgentInterface) -> None:
        """注册 Agent"""
        self.agents[agent.name] = agent
        logger.info(f"Agent registered: {agent.name}")
    
    def on(self, event: str, callback: Callable) -> None:
        """注册事件回调"""
        if event in self._callbacks:
            self._callbacks[event].append(callback)
    
    def _emit(self, event: str, data: Any) -> None:
        """触发事件"""
        for callback in self._callbacks.get(event, []):
            try:
                callback(data)
            except Exception as e:
                logger.error(f"Callback error: {e}")
    
    async def _initialize_agents(self) -> None:
        """初始化所有 Agent"""
        for agent in self.agents.values():
            try:
                await agent.initialize(self.context)
            except Exception as e:
                logger.error(f"Agent {agent.name} initialization failed: {e}")
    
    async def _execute_task(self, task: Task) -> Any:
        """执行单个任务"""
        task.status = TaskStatus.RUNNING
        task.started_at = datetime.now().isoformat()
        self._emit('task_start', task)
        
        agent = self.agents.get(task.agent_name)
        if not agent:
            task.status = TaskStatus.FAILED
            task.error = f"Agent not found: {task.agent_name}"
            self._emit('task_fail', task)
            return None
        
        try:
            result = await asyncio.wait_for(
                agent.execute(self.context),
                timeout=task.params.get('timeout', 300)
            )
            task.status = TaskStatus.COMPLETED
            task.result = result
            task.completed_at = datetime.now().isoformat()
            self._emit('task_complete', task)
            return result
        except asyncio.TimeoutError:
            task.status = TaskStatus.FAILED
            task.error = "Task timeout"
            self._emit('task_fail', task)
        except Exception as e:
            task.status = TaskStatus.FAILED
            task.error = str(e)
            self._emit('task_fail', task)
        
        return None
    
    async def run(self, task_definitions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        执行任务链
        
        task_definitions 格式:
        [
            {
                'agent': 'discover',
                'task_type': 'js_collect',
                'params': {'depth': 3},
                'depends_on': []
            },
            ...
        ]
        """
        self._running = True
        start_time = datetime.now()
        
        try:
            await self._initialize_agents()
            
            completed_tasks: Dict[str, Task] = {}
            pending_tasks = task_definitions.copy()
            
            while pending_tasks:
                ready_tasks = []
                
                for task_def in pending_tasks[:]:
                    depends_on = task_def.get('depends_on', [])
                    
                    if all(dep in completed_tasks for dep in depends_on):
                        ready_tasks.append(task_def)
                        pending_tasks.remove(task_def)
                
                if not ready_tasks:
                    if pending_tasks:
                        logger.error("Circular dependency detected or blocked tasks")
                        break
                    continue
                
                tasks_batch = []
                for task_def in ready_tasks:
                    task = Task(
                        task_id=f"{task_def['agent']}_{datetime.now().timestamp()}",
                        agent_name=task_def['agent'],
                        task_type=task_def.get('task_type', ''),
                        params=task_def.get('params', {})
                    )
                    self.tasks[task.task_id] = task
                    tasks_batch.append(task)
                
                results = await asyncio.gather(
                    *[self._execute_task(task) for task in tasks_batch],
                    return_exceptions=True
                )
                
                for task, result in zip(tasks_batch, results):
                    if isinstance(result, Exception):
                        task.status = TaskStatus.FAILED
                        task.error = str(result)
                    completed_tasks[task.agent_name] = task
                
                self._emit('task_progress', {
                    'completed': len(completed_tasks),
                    'pending': len(pending_tasks),
                    'total': len(task_definitions)
                })
            
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            result = {
                'success': True,
                'duration': duration,
                'completed_tasks': len(completed_tasks),
                'failed_tasks': sum(1 for t in completed_tasks.values() if t.status == TaskStatus.FAILED),
                'knowledge_base': self.knowledge_base.export(),
            }
            
            self._emit('scan_complete', result)
            return result
            
        finally:
            self._running = False
            for agent in self.agents.values():
                try:
                    await agent.cleanup()
                except Exception as e:
                    logger.warning(f"Agent cleanup error for {agent.name}: {e}")
    
    async def run_simple(self, agent_name: str, params: Dict[str, Any]) -> Any:
        """运行单个 Agent（简化接口）"""
        if agent_name not in self.agents:
            raise ValueError(f"Agent not found: {agent_name}")
        
        await self._initialize_agents()
        
        task = Task(
            task_id=f"{agent_name}_{datetime.now().timestamp()}",
            agent_name=agent_name,
            task_type="simple",
            params=params
        )
        
        return await self._execute_task(task)
    
    def get_knowledge_base(self) -> KnowledgeBase:
        """获取知识库"""
        return self.knowledge_base
    
    def get_tasks(self) -> List[Task]:
        """获取任务列表"""
        return list(self.tasks.values())


class SimpleOrchestrator:
    """
    简化编排器
    用于快速执行单个 Agent 任务
    """
    
    @staticmethod
    async def quick_run(
        agent: AgentInterface,
        target: str,
        **kwargs
    ) -> Any:
        """快速运行单个 Agent"""
        context = ScanContext(
            target=target,
            **kwargs
        )
        
        await agent.initialize(context)
        result = await agent.execute(context)
        await agent.cleanup()
        
        return result
