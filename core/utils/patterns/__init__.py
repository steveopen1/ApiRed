"""
GF Patterns - Security Scanning Pattern Library

This package contains pattern files for various vulnerability types.
Patterns are loaded by GFLibrary for security scanning.
"""

from pathlib import Path

PATTERNS_DIR = Path(__file__).parent

__all__ = ['PATTERNS_DIR']
