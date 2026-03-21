"""
Base Agent Module
Agent基类定义 - 所有Agent的基类
"""

import asyncio
import time
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import json
import logging

logger = logging.getLogger(__name__)


class AgentStatus(Enum):
    """Agent状态"""
    IDLE = "idle"
    RUNNING = "running"
    WAITING = "waiting"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class AgentConfig:
    """Agent配置"""
    name: str
    model: str = "deepseek-chat"
    max_tokens: int = 2000
    temperature: float = 0.7
    timeout: int = 60
    retry_count: int = 3
    system_prompt: str = ""
    
    def to_dict(self) -> Dict:
        return {
            'name': self.name,
            'model': self.model,
            'max_tokens': self.max_tokens,
            'temperature': self.temperature,
            'timeout': self.timeout,
            'retry_count': self.retry_count
        }


@dataclass
class Action:
    """Agent动作"""
    action_type: str
    params: Dict[str, Any]
    priority: int = 5
    dependencies: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            'action_type': self.action_type,
            'params': self.params,
            'priority': self.priority,
            'dependencies': self.dependencies
        }


@dataclass
class AgentResult:
    """Agent执行结果"""
    agent_name: str
    action_type: str
    success: bool
    data: Any = None
    error: str = ""
    duration: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            'agent_name': self.agent_name,
            'action_type': self.action_type,
            'success': self.success,
            'data': self.data,
            'error': self.error,
            'duration': self.duration,
            'timestamp': self.timestamp,
            'metadata': self.metadata
        }


class AgentMemory:
    """Agent 记忆存储"""
    
    def __init__(self):
        self.short_term: List[Dict] = []
        self.long_term: List[Dict] = []
    
    def add(self, content: str, memory_type: str = 'short') -> None:
        entry = {
            'content': content,
            'timestamp': datetime.now().isoformat()
        }
        if memory_type == 'short':
            self.short_term.append(entry)
            if len(self.short_term) > 50:
                self.short_term.pop(0)
        else:
            self.long_term.append(entry)
    
    def get_recent(self, n: int = 5) -> List[Dict]:
        return self.short_term[-n:] if self.short_term else []
    
    def get_all(self) -> Dict[str, List[Dict]]:
        return {
            'short_term': self.short_term.copy(),
            'long_term': self.long_term.copy()
        }
    
    def clear(self) -> None:
        self.short_term.clear()
        self.long_term.clear()


class BaseAgent(ABC):
    """Agent基类"""
    
    def __init__(self, config: AgentConfig, llm_client: Optional[Any] = None):
        self.config = config
        self.name = config.name
        self.status = AgentStatus.IDLE
        self.memory_obj = AgentMemory()
        self.memory: List[AgentResult] = []
        self._observers: List[Callable] = []
        self._lock = asyncio.Lock()
        self.llm_client = llm_client
    
    @abstractmethod
    async def plan(self, context: Dict) -> List[Action]:
        """规划Action列表"""
        pass
    
    @abstractmethod
    async def execute(self, action: Action) -> AgentResult:
        """执行单个Action"""
        pass
    
    async def run(self, context: Dict) -> List[AgentResult]:
        """运行Agent完整流程"""
        self.status = AgentStatus.RUNNING
        results = []
        
        actions = await self.plan(context)
        actions = self._sort_actions(actions)
        
        for action in actions:
            if self._check_dependencies(action):
                result = await self.execute(action)
                results.append(result)
                self.memory.append(result)
                self._notify_observers(result)
                
                if not result.success:
                    logger.warning(f"{self.name} action {action.action_type} failed")
        
        self.status = AgentStatus.COMPLETED
        return results
    
    def _sort_actions(self, actions: List[Action]) -> List[Action]:
        """按优先级排序Action"""
        return sorted(actions, key=lambda a: a.priority, reverse=True)
    
    def _check_dependencies(self, action: Action) -> bool:
        """检查依赖是否满足"""
        for dep_result in self.memory:
            if dep_result.action_type in action.dependencies:
                if not dep_result.success:
                    return False
        return True
    
    async def think(self, prompt: str, context: Optional[Dict] = None) -> str:
        """LLM思考 - 分析当前状态并生成下一步计划"""
        if not self.llm_client:
            logger.warning(f"{self.name}: LLM client not configured")
            return ""
        
        try:
            context_str = json.dumps(context, ensure_ascii=False) if context else ""
            full_prompt = f"{prompt}\n\n上下文信息:\n{context_str}" if context_str else prompt
            
            response = self.llm_client.chat(
                messages=[{"role": "user", "content": full_prompt}],
                system=self.config.system_prompt or "你是一个专业的AI助手，负责分析和规划任务。"
            )
            
            if response.success:
                self.memory_obj.add(f"think: {prompt[:50]}... -> {response.result[:100]}...", "short")
                return response.result
            else:
                logger.error(f"{self.name} think failed: {response.error}")
                return ""
        except Exception as e:
            logger.error(f"{self.name} think error: {e}")
            return ""
    
    async def chat(self, messages: List[Dict], system: str = "") -> str:
        """LLM对话 - 与LLM交互获取响应"""
        if not self.llm_client:
            logger.warning(f"{self.name}: LLM client not configured")
            return ""
        
        try:
            system_prompt = system or self.config.system_prompt or ""
            response = self.llm_client.chat(messages=messages, system=system_prompt)
            
            if response.success:
                self.memory_obj.add(f"chat: {messages[-1]['content'][:50]}... -> {response.result[:50]}...", "short")
                return response.result
            else:
                logger.error(f"{self.name} chat failed: {response.error}")
                return ""
        except Exception as e:
            logger.error(f"{self.name} chat error: {e}")
            return ""
    
    async def reflect(self, result: Any, action_type: str = "") -> None:
        """反思 - 将结果存储到记忆"""
        try:
            result_str = str(result)[:500]
            reflection = f"action: {action_type} -> result: {result_str}"
            self.memory_obj.add(reflection, "long")
            
            if len(self.memory_obj.long_term) > 100:
                important = self.memory_obj.long_term[-20:]
                self.memory_obj.long_term = important
        except Exception as e:
            logger.error(f"{self.name} reflect error: {e}")
    
    def add_observer(self, observer: Callable):
        """添加观察者"""
        self._observers.append(observer)
    
    def _notify_observers(self, result: AgentResult):
        """通知观察者"""
        for observer in self._observers:
            try:
                observer(result)
            except Exception as e:
                logger.error(f"Observer error: {e}")
    
    def get_memory(self, action_type: Optional[str] = None) -> List[AgentResult]:
        """获取记忆"""
        if action_type:
            return [r for r in self.memory if r.action_type == action_type]
        return self.memory.copy()
    
    def clear_memory(self):
        """清空记忆"""
        self.memory.clear()
    
    @property
    def is_running(self) -> bool:
        return self.status == AgentStatus.RUNNING
    
    def to_dict(self) -> Dict:
        return {
            'name': self.name,
            'status': self.status.value,
            'memory_size': len(self.memory),
            'config': self.config.to_dict()
        }


class AgentFactory:
    """Agent工厂类"""
    _agents: Dict[str, type] = {}
    
    @classmethod
    def register(cls, name: str, agent_class: type):
        cls._agents[name] = agent_class
    
    @classmethod
    def create(cls, name: str, config: AgentConfig) -> BaseAgent:
        if name not in cls._agents:
            raise ValueError(f"Agent {name} not registered")
        return cls._agents[name](config)
    
    @classmethod
    def list_agents(cls) -> List[str]:
        return list(cls._agents.keys())
