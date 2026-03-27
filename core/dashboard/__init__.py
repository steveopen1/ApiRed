"""
Dashboard Module
Web Dashboard components for ApiRed
"""

from .models import (
    ScanTask,
    TaskStatus,
    ScanMode,
    EngineConfig,
    ScanProgress,
    Finding,
    FindingType,
    LogEntry,
    LogLevel,
    APIEndpoint,
    Vulnerability,
    ScanResult,
    ServerConfig,
)

from .events import (
    EventType,
    WSMessage,
    EventEmitter,
    ClientMessage,
    ClientMessageType,
)

from .task_manager import TaskManager

from .orchestrator import ScanOrchestrator

from .server import DashboardServer, run_server

__all__ = [
    'ScanTask',
    'TaskStatus',
    'ScanMode',
    'EngineConfig',
    'ScanProgress',
    'Finding',
    'FindingType',
    'LogEntry',
    'LogLevel',
    'APIEndpoint',
    'Vulnerability',
    'ScanResult',
    'ServerConfig',
    'EventType',
    'WSMessage',
    'EventEmitter',
    'ClientMessage',
    'ClientMessageType',
    'TaskManager',
    'ScanOrchestrator',
    'DashboardServer',
    'run_server',
]
