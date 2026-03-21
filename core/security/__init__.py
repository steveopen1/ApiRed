"""
Security Module
安全检测模块
"""

from .security_detector import (
    AuthStatus,
    VulnType,
    UnauthorizedResult,
    IDORResult,
    SensitiveFinding,
    UnauthorizedDetector,
    IDORDetector,
    SensitiveAggregator,
    LargeResponseSplitter,
    SecurityReportGenerator
)

__all__ = [
    'AuthStatus',
    'VulnType',
    'UnauthorizedResult',
    'IDORResult',
    'SensitiveFinding',
    'UnauthorizedDetector',
    'IDORDetector',
    'SensitiveAggregator',
    'LargeResponseSplitter',
    'SecurityReportGenerator'
]
