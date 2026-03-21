import pytest
from core.agents.base import BaseAgent, AgentConfig, AgentMemory


class TestAgentMemory:
    def test_memory_creation(self):
        memory = AgentMemory()
        assert memory is not None
        assert memory.short_term == []
        assert memory.long_term == []
    
    def test_memory_add_short(self):
        memory = AgentMemory()
        memory.add("test content", "short")
        assert len(memory.short_term) == 1
        assert memory.short_term[0]['content'] == "test content"
    
    def test_memory_add_long(self):
        memory = AgentMemory()
        memory.add("test content", "long")
        assert len(memory.long_term) == 1
    
    def test_memory_get_recent(self):
        memory = AgentMemory()
        memory.add("content1", "short")
        memory.add("content2", "short")
        recent = memory.get_recent(1)
        assert len(recent) == 1
        assert recent[0]['content'] == "content2"


class TestAgentConfig:
    def test_agent_config_creation(self):
        config = AgentConfig(name="TestAgent")
        assert config.name == "TestAgent"
        assert config.model == "deepseek-chat"
        assert config.max_tokens == 2000
    
    def test_agent_config_custom(self):
        config = AgentConfig(
            name="CustomAgent",
            model="gpt-4",
            max_tokens=4000
        )
        assert config.name == "CustomAgent"
        assert config.model == "gpt-4"
        assert config.max_tokens == 4000
