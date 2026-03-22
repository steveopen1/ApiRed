"""
ApiRed Core Module
Red Team API Security Scanner Core
"""

__version__ = "3.1"
__author__ = "ApiRed Team"

from .engine import ScanEngine, EngineConfig, run_engine, run_multi_target, ScanResultAggregator
from .scanner import ChkApiScanner

__all__ = [
    'ScanEngine',
    'EngineConfig', 
    'run_engine',
    'run_multi_target',
    'ScanResultAggregator',
    'ChkApiScanner',
]
