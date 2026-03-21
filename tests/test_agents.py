import pytest
from core.agents.base import BaseAgent


class TestBaseAgent:
    def test_base_agent_creation(self):
        agent = BaseAgent()
        assert agent is not None
    
    def test_base_agent_has_name_property(self):
        agent = BaseAgent()
        assert hasattr(agent, 'name')
