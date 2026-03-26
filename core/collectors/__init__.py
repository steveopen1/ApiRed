"""
Collectors Module
采集模块

.. deprecated::
    EnhancedEndpointAggregator 已移至 core.unified_fusion.UnifiedFusionEngine
"""

from .js_collector import JSFingerprintCache, JSParser, ParsedJSResult
from .api_collector import (
    APIAggregator,
    APIRouter,
    BaseURLAnalyzer,
    ServiceAnalyzer,
    APIPathCombiner,
    APIFindResult
)
from .browser_collector import HeadlessBrowserCollector, BrowserResource, check_browser_dependencies
from .inline_js_parser import InlineJSParser, ResponseBasedAPIDiscovery
from .api_path_finder import ApiPathFinder, ApiPathCombiner, DiscoveredAPI
from .js_ast_analyzer import JavaScriptASTAnalyzer, JSASTDifferentialAnalyzer, extract_api_paths_from_js

__all__ = [
    'JSFingerprintCache',
    'JSParser',
    'ParsedJSResult',
    'APIAggregator',
    'APIRouter',
    'BaseURLAnalyzer',
    'ServiceAnalyzer',
    'APIPathCombiner',
    'APIFindResult',
    'HeadlessBrowserCollector',
    'BrowserResource',
    'check_browser_dependencies',
    'InlineJSParser',
    'ResponseBasedAPIDiscovery',
    'ApiPathFinder',
    'ApiPathCombiner',
    'DiscoveredAPI',
    'JavaScriptASTAnalyzer',
    'JSASTDifferentialAnalyzer',
    'extract_api_paths_from_js',
]
