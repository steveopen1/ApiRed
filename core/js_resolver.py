#!/usr/bin/env python3
"""
JS 智能解析与拼接模块 - 基于 FLUX v5.2.1
智能解析 JS URL，处理各种路径格式和构建产物
"""

import re
import json
import logging
from typing import List, Dict, Set, Optional, Tuple
from urllib.parse import urljoin, urlparse, urlunparse
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class JSDiscoveryRecord:
    """JS 发现记录"""
    url: str
    original_ref: str
    source_page: str
    discovery_method: str
    confidence: str
    is_secondary_fuzz: bool = False
    fuzz_attempts: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)


class JSResolver:
    """JS URL 智能解析器"""

    WEBPACK_PATTERNS = {
        'public_path': [
            r'__webpack_require__\.p\s*=\s*["\']([^"\']+)["\']',
            r'publicPath\s*:\s*["\']([^"\']+)["\']',
            r'__webpack_public_path__\s*=\s*["\']([^"\']+)["\']',
        ],
        'chunk_name': [
            r'webpackChunkName\s*:\s*["\']([^"\']+)["\']',
            r'import\s*\(\s*\/\*\s*webpackChunkName:\s*["\']([^"\']+)["\']',
        ],
        'runtime_chunk': [
            r'runtime~[a-f0-9]+\.js',
            r'runtime\.[a-f0-9]+\.js',
        ],
        'manifest': [
            r'webpack-manifest\.json',
            r'asset-manifest\.json',
            r'manifest\.json',
            r'build-manifest\.json',
        ]
    }

    VITE_PATTERNS = {
        'manifest': [
            r'\.vite\/manifest\.json',
            r'vite-manifest\.json',
        ],
        'dynamic_import': [
            r'import\s*\(\s*["\']([^"\']+\.(js|ts|tsx|jsx))["\']\s*\)',
        ],
        'asset_ref': [
            r'__VITE_ASSET__["\']([^"\']+)["\']',
        ]
    }

    FRAMEWORK_PATTERNS = {
        'next_js': [
            r'/_next/static/[^/]+/pages/[^/]+\.js',
            r'/_next/static/chunks/[^/]+\.js',
            r'/_next/static/[^/]+/_buildManifest\.js',
        ],
        'nuxt_js': [
            r'/_nuxt/[^/]+\.js',
            r'/_nuxt/static/[^/]+\.js',
        ],
    }

    STATIC_DIRS = [
        '/static/', '/assets/', '/js/', '/scripts/', '/dist/',
        '/build/', '/public/', '/resources/', '/cdn/',
        '/_next/', '/_nuxt/', '/.vite/', '/webpack/',
    ]

    BUILD_DIRS = [
        'dist', 'build', 'public', 'static', 'assets',
        'js', 'scripts', 'bundle', 'chunks',
    ]

    def __init__(self, base_url: str):
        self.base_url = base_url
        self.parsed_base = urlparse(base_url)
        self.origin = f"{self.parsed_base.scheme}://{self.parsed_base.netloc}"
        self.base_path = self.parsed_base.path.rsplit('/', 1)[0] if '/' in self.parsed_base.path else ''
        self.resource_prefixes: Set[str] = set()
        self.webpack_public_path: Optional[str] = None
        self.vite_base: Optional[str] = None

    def resolve(self, ref: str, source_page: str = "", discovery_method: str = "unknown") -> Optional[JSDiscoveryRecord]:
        if not ref or len(ref) < 2:
            return None

        ref = ref.strip().strip('"\'')

        if ref.startswith(('http://', 'https://')):
            return JSDiscoveryRecord(
                url=ref,
                original_ref=ref,
                source_page=source_page,
                discovery_method=discovery_method,
                confidence='high'
            )

        if ref.startswith('//'):
            url = f"{self.parsed_base.scheme}:{ref}"
            return JSDiscoveryRecord(
                url=url,
                original_ref=ref,
                source_page=source_page,
                discovery_method=discovery_method,
                confidence='high'
            )

        if ref.startswith('/'):
            url = urljoin(self.origin, ref)
            return JSDiscoveryRecord(
                url=url,
                original_ref=ref,
                source_page=source_page,
                discovery_method=discovery_method,
                confidence='high'
            )

        if source_page:
            url = urljoin(source_page, ref)
        else:
            url = urljoin(self.base_url, ref)

        return JSDiscoveryRecord(
            url=url,
            original_ref=ref,
            source_page=source_page or self.base_url,
            discovery_method=discovery_method,
            confidence='medium'
        )

    def extract_from_html(self, html: str, source_page: str) -> List[JSDiscoveryRecord]:
        records = []
        base_href = self._extract_base_href(html)
        if base_href:
            self.resource_prefixes.add(base_href)

        script_pattern = r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']'
        for match in re.finditer(script_pattern, html, re.I):
            ref = match.group(1)
            record = self.resolve(ref, source_page, 'script_src')
            if record:
                records.append(record)

        link_pattern = r'<link[^>]+(?:preload|prefetch)[^>]+href=["\']([^"\']+\.js)["\']'
        for match in re.finditer(link_pattern, html, re.I):
            ref = match.group(1)
            record = self.resolve(ref, source_page, 'link_preload')
            if record:
                records.append(record)

        import_pattern = r'import\s*\(\s*["\']([^"\']+\.js)["\']\s*\)'
        for match in re.finditer(import_pattern, html, re.I):
            ref = match.group(1)
            record = self.resolve(ref, source_page, 'dynamic_import')
            if record:
                records.append(record)

        return records

    def extract_from_js(self, js_content: str, source_url: str) -> List[JSDiscoveryRecord]:
        records = []
        self._detect_webpack_config(js_content)
        self._detect_vite_config(js_content)
        self._detect_framework_config(js_content)

        patterns = [
            (r'["\'`]([^"\']+\.js[^"\']*)["\']', 'string_match'),
            (r'src\s*=\s*["\']([^"\']+\.js[^"\']*)["\']', 'src_attribute'),
            (r'import\s+["\']([^"\']+\.js)["\']', 'import_statement'),
            (r'import\s*\(\s*["\']([^"\']+\.js)["\']\s*\)', 'dynamic_import'),
            (r'require\s*\(\s*["\']([^"\']+\.js)["\']\s*\)', 'require_call'),
            (r'webpackChunkName\s*:\s*["\']([^"\']+)["\']', 'webpack_chunk'),
        ]

        for pattern, method in patterns:
            for match in re.finditer(pattern, js_content, re.MULTILINE):
                ref = match.group(1)
                if self._is_js_file(ref):
                    record = self.resolve(ref, source_url, method)
                    if record:
                        records.append(record)

        return records

    def _detect_webpack_config(self, js_content: str):
        for pattern_name, patterns in self.WEBPACK_PATTERNS.items():
            if pattern_name == 'public_path':
                for pattern in patterns:
                    matches = re.finditer(pattern, js_content)
                    for match in matches:
                        if match.groups():
                            self.webpack_public_path = match.group(1)
                            self.resource_prefixes.add(self.webpack_public_path)
                            logger.debug(f"[*] 检测到Webpack public_path: {self.webpack_public_path}")
                            return

    def _detect_vite_config(self, js_content: str):
        for pattern_name, patterns in self.VITE_PATTERNS.items():
            if pattern_name == 'manifest':
                for pattern in patterns:
                    if re.search(pattern, js_content):
                        logger.debug(f"[*] 检测到Vite manifest模式")
                        break

    def _detect_framework_config(self, js_content: str):
        for framework, patterns in self.FRAMEWORK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, js_content):
                    logger.debug(f"[*] 检测到{framework}框架")
                    break

    def _extract_base_href(self, html: str) -> Optional[str]:
        match = re.search(r'<base[^>]+href=["\']([^"\']+)["\']', html, re.I)
        if match:
            return match.group(1)
        return None

    def _is_js_file(self, path: str) -> bool:
        if not path:
            return False
        path_lower = path.lower()
        js_indicators = ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.css']
        invalid_indicators = ['node_modules', 'data:', 'blob:', 'javascript:']
        return any(path_lower.endswith(ext) for ext in js_indicators) and not any(ind in path_lower for ind in invalid_indicators)

    def generate_fuzz_candidates(self, js_url: str) -> List[str]:
        candidates = []
        parsed = urlparse(js_url)
        path_parts = parsed.path.rsplit('/', 1)
        if len(path_parts) > 1:
            dir_path = path_parts[0]
            filename = path_parts[1]

            for static_dir in self.STATIC_DIRS:
                candidates.append(f"{self.origin}{static_dir}{filename}")

            base_name = filename.rsplit('.', 1)[0] if '.' in filename else filename
            extensions = ['.js', '.jsx', '.ts', '.tsx', '.min.js', '.bundle.js', '.chunk.js']

            for ext in extensions:
                candidates.append(f"{dir_path}/{base_name}{ext}")

            chunk_patterns = [
                f"{dir_path}/{base_name}.chunk.js",
                f"{dir_path}/{base_name}-chunk.js",
                f"{dir_path}/chunk-{filename}",
                f"{dir_path}/{filename.replace('.js', '.chunk.js')}",
            ]
            candidates.extend(chunk_patterns)

        return list(set(candidates))

    def resolve_from_manifest(self, manifest_url: str, js_content: str) -> List[JSDiscoveryRecord]:
        records = []
        try:
            manifest = json.loads(js_content)
            if isinstance(manifest, dict):
                if 'entrypoints' in manifest or 'main' in manifest:
                    for key, value in manifest.items():
                        if isinstance(value, str) and self._is_js_file(value):
                            record = self.resolve(value, manifest_url, 'manifest')
                            if record:
                                records.append(record)
                if 'files' in manifest:
                    for file_path in manifest.get('files', []):
                        if self._is_js_file(file_path):
                            record = self.resolve(file_path, manifest_url, 'manifest')
                            if record:
                                records.append(record)
                if 'assets' in manifest:
                    for asset_name, asset_path in manifest.get('assets', {}).items():
                        if isinstance(asset_path, str) and self._is_js_file(asset_path):
                            record = self.resolve(asset_path, manifest_url, 'webpack_manifest')
                            if record:
                                records.append(record)
        except json.JSONDecodeError:
            pass
        return records


def extract_js_urls(html: str, base_url: str) -> List[str]:
    resolver = JSResolver(base_url)
    records = resolver.extract_from_html(html, base_url)
    return [record.url for record in records]


def extract_endpoints_from_js(js_content: str, js_url: str) -> List[str]:
    endpoints = []
    patterns = [
        r'["\'`](?:/api/[^"\']+)["\']',
        r'["\'`](?:/v\d+/[^"\']+)["\']',
        r'["\'`](?:/rest/[^"\']+)["\']',
        r'fetch\s*\(\s*["\']([^"\']+)["\']',
        r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
        r'\.get\s*\(\s*["\']([^"\']+)["\']',
        r'\.post\s*\(\s*["\']([^"\']+)["\']',
        r'\.put\s*\(\s*["\']([^"\']+)["\']',
        r'\.delete\s*\(\s*["\']([^"\']+)["\']',
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, js_content, re.I):
            url = match.group(1)
            if url.startswith('/') or url.startswith('http'):
                endpoints.append(url)
    return list(set(endpoints))


__all__ = ['JSResolver', 'JSDiscoveryRecord', 'extract_js_urls', 'extract_endpoints_from_js']
