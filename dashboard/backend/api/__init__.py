"""
Dashboard Backend API
"""

from .projects import router as projects_router
from .targets import router as targets_router
from .scans import router as scans_router
from .reports import router as reports_router

__all__ = [
    'projects_router',
    'targets_router',
    'scans_router',
    'reports_router',
]
