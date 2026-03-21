"""
Framework Detection Module
可扩展的框架识别系统
"""

from .rule_engine import FrameworkRuleEngine, load_default_fingerprints

__all__ = ['FrameworkRuleEngine', 'load_default_fingerprints']
