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
from .api_path_finder import ApiPathFinder, ApiPathCombiner, DiscoveredAPI, ResponseDiffer
from .js_ast_analyzer import JavaScriptASTAnalyzer, JSASTDifferentialAnalyzer, extract_api_paths_from_js
from .swagger_discoverer import SwaggerDiscoverer, SwaggerDoc, SwaggerEndpoint, discover_swagger
from .api_bypass import APIBypasser, SmartBypasser, BypassResult, BypassTechnique, quick_bypass
from .passive_sources import PassiveSourceCollector, PassiveSource, collect_passive, TokenBucket
from .smart_filter import SmartFilter, ScoredEndpoint, SmartFilter, ResponseClusterAnalyzer, prioritize_endpoints, EndpointValue

__all__ = [
    # JS & API Collection
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
    'ResponseDiffer',
    'JavaScriptASTAnalyzer',
    'JSASTDifferentialAnalyzer',
    'extract_api_paths_from_js',
    # Swagger/OpenAPI Discovery
    'SwaggerDiscoverer',
    'SwaggerDoc',
    'SwaggerEndpoint',
    'discover_swagger',
    # API Bypass
    'APIBypasser',
    'SmartBypasser',
    'BypassResult',
    'BypassTechnique',
    'quick_bypass',
    # Passive Sources
    'PassiveSourceCollector',
    'PassiveSource',
    'collect_passive',
    'TokenBucket',
    # Smart Filter
    'SmartFilter',
    'ScoredEndpoint',
    'ResponseClusterAnalyzer',
    'prioritize_endpoints',
    'EndpointValue',
]
