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

logger = logging.getLogger(__name__)


class TaskStatus(Enum):
    """任务状态"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


AI_ENV_VARS = {
    'DEEPSEEK_API_KEY': 'DeepSeek API Key',
    'OPENAI_API_KEY': 'OpenAI API Key',
    'ANTHROPIC_API_KEY': 'Anthropic API Key',
    'AI_PROVIDER': 'AI Provider (deepseek/openai/anthropic)',
    'AI_BASE_URL': 'AI Base URL',
    'AI_MODEL': 'AI Model',
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


def print_ai_config_guide():
    """打印 AI 配置指南"""
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                     AI Configuration Required                          ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                        ║
║  Agent 模式需要配置 AI API 密钥才能使用 LLM 功能。                     ║
║                                                                        ║
║  配置方式:                                                              ║
║                                                                        ║
║  1. DeepSeek (推荐):                                                   ║
║     export DEEPSEEK_API_KEY="sk-xxxxxxx"                              ║
║                                                                        ║
║  2. OpenAI:                                                            ║
║     export OPENAI_API_KEY="sk-xxxxxxx"                               ║
║                                                                        ║
║  3. Anthropic:                                                         ║
║     export ANTHROPIC_API_KEY="sk-ant-xxxxxxx"                         ║
║                                                                        ║
║  查看更多: https://github.com/chaitin/MonkeyCodeOfficialPlugins         ║
║                                                                        ║
║  或者使用传统模式 (无需配置 AI):                                        ║
║     python main.py scan -u http://example.com                           ║
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
    """Agent 接口定义"""
    
    def __init__(self, name: str):
        self.name = name
        self.knowledge_base: Optional[KnowledgeBase] = None
    
    async def initialize(self, context: ScanContext) -> None:
        """初始化 Agent"""
        self.knowledge_base = context.knowledge_base
    
    async def execute(self, context: ScanContext) -> Any:
        """执行任务"""
        raise NotImplementedError
    
    async def cleanup(self) -> None:
        """清理资源"""
        pass


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
                except Exception:
                    pass
    
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
