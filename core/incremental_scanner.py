"""
Incremental Scanner Module
增量扫描支持模块
"""

import os
import sqlite3
import json
import hashlib
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse


@dataclass
class ScanSnapshot:
    """扫描快照"""
    snapshot_id: str
    target: str
    timestamp: str
    api_hashes: Set[str] = field(default_factory=set)
    js_hashes: Set[str] = field(default_factory=set)
    api_count: int = 0
    js_count: int = 0


class IncrementalScanner:
    """增量扫描器 - 支持断点续扫和增量扫描"""
    
    def __init__(self, storage_path: str):
        self.storage_path = storage_path
        self._init_storage()
    
    def _init_storage(self):
        """初始化存储"""
        os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
        
        conn = sqlite3.connect(self.storage_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_snapshots (
                snapshot_id TEXT PRIMARY KEY,
                target TEXT,
                timestamp TEXT,
                api_count INTEGER,
                js_count INTEGER
            )
        """)
        
        conn.execute("""
            CREATE TABLE IF NOT EXISTS api_snapshot (
                snapshot_id TEXT,
                api_hash TEXT,
                api_path TEXT,
                method TEXT,
                status TEXT,
                FOREIGN KEY(snapshot_id) REFERENCES scan_snapshots(snapshot_id)
            )
        """)
        
        conn.execute("""
            CREATE TABLE IF NOT EXISTS js_snapshot (
                snapshot_id TEXT,
                js_hash TEXT,
                js_url TEXT,
                FOREIGN KEY(snapshot_id) REFERENCES scan_snapshots(snapshot_id)
            )
        """)
        
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_api_snapshot_hash 
            ON api_snapshot(api_hash)
        """)
        
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_js_snapshot_hash 
            ON js_snapshot(js_hash)
        """)
        
        conn.commit()
        conn.close()
    
    def compute_api_hash(self, api: Dict) -> str:
        """计算 API 哈希"""
        key = f"{api.get('method', 'GET')}:{api.get('path', '')}"
        return hashlib.md5(key.encode()).hexdigest()[:16]
    
    def compute_js_hash(self, js_url: str, content_hash: str = "") -> str:
        """计算 JS 哈希"""
        key = f"{js_url}:{content_hash}"
        return hashlib.md5(key.encode()).hexdigest()[:16]
    
    def save_snapshot(
        self,
        target: str,
        apis: List[Dict],
        js_urls: List[str]
    ) -> str:
        """保存扫描快照"""
        snapshot_id = hashlib.md5(
            f"{target}:{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        conn = sqlite3.connect(self.storage_path)
        
        conn.execute("""
            INSERT INTO scan_snapshots 
            (snapshot_id, target, timestamp, api_count, js_count)
            VALUES (?, ?, ?, ?, ?)
        """, (
            snapshot_id,
            target,
            datetime.now().isoformat(),
            len(apis),
            len(js_urls)
        ))
        
        for api in apis:
            api_hash = self.compute_api_hash(api)
            conn.execute("""
                INSERT INTO api_snapshot 
                (snapshot_id, api_hash, api_path, method, status)
                VALUES (?, ?, ?, ?, ?)
            """, (
                snapshot_id,
                api_hash,
                api.get('path', ''),
                api.get('method', 'GET'),
                api.get('status', '')
            ))
        
        for js_url in js_urls:
            js_hash = self.compute_js_hash(js_url)
            conn.execute("""
                INSERT INTO js_snapshot 
                (snapshot_id, js_hash, js_url)
                VALUES (?, ?, ?)
            """, (snapshot_id, js_hash, js_url))
        
        conn.commit()
        conn.close()
        
        return snapshot_id
    
    def get_latest_snapshot(self, target: str) -> Optional[ScanSnapshot]:
        """获取最新快照"""
        conn = sqlite3.connect(self.storage_path)
        
        row = conn.execute("""
            SELECT snapshot_id, target, timestamp, api_count, js_count
            FROM scan_snapshots
            WHERE target = ?
            ORDER BY timestamp DESC
            LIMIT 1
        """, (target,)).fetchone()
        
        if not row:
            conn.close()
            return None
        
        snapshot_id = row[0]
        
        api_hashes = set(
            r[0] for r in conn.execute(
                "SELECT api_hash FROM api_snapshot WHERE snapshot_id = ?",
                (snapshot_id,)
            ).fetchall()
        )
        
        js_hashes = set(
            r[0] for r in conn.execute(
                "SELECT js_hash FROM js_snapshot WHERE snapshot_id = ?",
                (snapshot_id,)
            ).fetchall()
        )
        
        conn.close()
        
        return ScanSnapshot(
            snapshot_id=snapshot_id,
            target=row[1],
            timestamp=row[2],
            api_hashes=api_hashes,
            js_hashes=js_hashes,
            api_count=row[3],
            js_count=row[4]
        )
    
    def get_new_apis(
        self,
        target: str,
        current_apis: List[Dict]
    ) -> List[Dict]:
        """获取新增的 API"""
        latest = self.get_latest_snapshot(target)
        
        if not latest:
            return current_apis
        
        new_apis = []
        for api in current_apis:
            api_hash = self.compute_api_hash(api)
            if api_hash not in latest.api_hashes:
                new_apis.append(api)
        
        return new_apis
    
    def get_new_js_urls(
        self,
        target: str,
        current_js_urls: List[str]
    ) -> List[str]:
        """获取新增的 JS URL"""
        latest = self.get_latest_snapshot(target)
        
        if not latest:
            return current_js_urls
        
        new_js = []
        for js_url in current_js_urls:
            js_hash = self.compute_js_hash(js_url)
            if js_hash not in latest.js_hashes:
                new_js.append(js_url)
        
        return new_js
    
    def get_removed_apis(
        self,
        target: str,
        current_apis: List[Dict]
    ) -> List[Dict]:
        """获取已删除的 API"""
        latest = self.get_latest_snapshot(target)
        
        if not latest:
            return []
        
        current_hashes = {self.compute_api_hash(api) for api in current_apis}
        removed_hashes = latest.api_hashes - current_hashes
        
        if not removed_hashes:
            return []
        
        conn = sqlite3.connect(self.storage_path)
        removed_apis = []
        
        for api_hash in removed_hashes:
            row = conn.execute("""
                SELECT api_path, method, status
                FROM api_snapshot
                WHERE snapshot_id = ? AND api_hash = ?
            """, (latest.snapshot_id, api_hash)).fetchone()
            
            if row:
                removed_apis.append({
                    'path': row[0],
                    'method': row[1],
                    'status': row[2]
                })
        
        conn.close()
        return removed_apis


class URLDeduplicator:
    """URL 去重器 - 支持多种去重策略"""
    
    def __init__(self, strategy: str = "simple"):
        self.strategy = strategy
        self.seen_urls: Set[str] = set()
        self.seen_hashes: Set[str] = set()
    
    def normalize_url(self, url: str) -> str:
        """规范化 URL"""
        try:
            parsed = urlparse(url)
            
            path = parsed.path or '/'
            path = path.rstrip('/')
            
            normalized = f"{parsed.scheme}://{parsed.netloc}{path}"
            
            if parsed.query:
                normalized += f"?{parsed.query}"
            
            return normalized.lower()
        except (ValueError, AttributeError) as e:
            logger.debug(f"URL normalization error: {e}")
            return url.lower()
    
    def compute_content_hash(self, content: str, length: int = 500) -> str:
        """计算内容哈希（用于响应去重）"""
        preview = content[:length]
        return hashlib.md5(preview.encode()).hexdigest()[:16]
    
    def is_duplicate(self, url: str) -> bool:
        """检查 URL 是否重复"""
        normalized = self.normalize_url(url)
        
        if self.strategy == "simple":
            if normalized in self.seen_urls:
                return True
            self.seen_urls.add(normalized)
            return False
        
        url_hash = hashlib.md5(normalized.encode()).hexdigest()[:16]
        if url_hash in self.seen_hashes:
            return True
        self.seen_hashes.add(url_hash)
        return False
    
    def reset(self):
        """重置去重器"""
        self.seen_urls.clear()
        self.seen_hashes.clear()


class ResponseDeduplicator:
    """响应内容去重器"""
    
    def __init__(self, similarity_threshold: float = 0.9):
        self.similarity_threshold = similarity_threshold
        self.response_hashes: Dict[str, str] = {}
    
    def compute_response_hash(
        self,
        status_code: int,
        content: str,
        length_bucket: str = "medium"
    ) -> str:
        """计算响应哈希"""
        content_hash = hashlib.md5(content[:1000].encode()).hexdigest()[:8]
        return f"{status_code}:{length_bucket}:{content_hash}"
    
    def get_length_bucket(self, length: int) -> str:
        """获取长度分桶"""
        if length == 0:
            return "empty"
        if length < 100:
            return "tiny"
        if length < 1000:
            return "small"
        if length < 10000:
            return "medium"
        if length < 100000:
            return "large"
        return "huge"
    
    def is_duplicate_response(
        self,
        url: str,
        status_code: int,
        content: str
    ) -> Tuple[bool, str]:
        """检查响应是否重复"""
        length_bucket = self.get_length_bucket(len(content))
        response_hash = self.compute_response_hash(status_code, content, length_bucket)
        
        if url in self.response_hashes:
            existing_hash = self.response_hashes[url]
            
            if existing_hash == response_hash:
                return True, "exact_match"
            
            existing_parts = existing_hash.split(':')
            if existing_parts[0] == str(status_code) and existing_parts[1] == length_bucket:
                return True, "similar"
        
        self.response_hashes[url] = response_hash
        return False, ""
    
    def get_unique_responses(self) -> Dict[str, str]:
        """获取唯一响应"""
        return self.response_hashes.copy()
    
    def reset(self):
        """重置"""
        self.response_hashes.clear()
