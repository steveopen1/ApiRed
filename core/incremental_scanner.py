"""
Enhanced Incremental Scanner Module
增强增量扫描模块 - 支持漏洞状态追踪

增强功能：
1. 漏洞状态增量更新
2. 漏洞趋势分析
3. 已修复漏洞追踪
4. 漏洞对比报告
"""

import os
import sqlite3
import json
import hashlib
import logging
from typing import Dict, List, Optional, Set, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class VulnerabilityStatus(Enum):
    """漏洞状态"""
    NEW = "new"
    CONFIRMED = "confirmed"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    REGRESSION = "regression"


@dataclass
class VulnerabilityRecord:
    """漏洞记录"""
    vuln_id: str
    target: str
    vuln_type: str
    severity: str
    url: str
    param: str
    payload: str
    status: VulnerabilityStatus
    first_seen: str
    last_seen: str
    evidence: str
    verifier: str


@dataclass
class VulnerabilityTrend:
    """漏洞趋势"""
    vuln_type: str
    severity: str
    total: int
    new_count: int
    resolved_count: int
    regression_count: int
    trend: str


class EnhancedIncrementalScanner:
    """
    增强增量扫描器
    
    支持：
    1. 漏洞状态持久化
    2. 增量更新漏洞状态
    3. 漏洞趋势分析
    4. 回归检测
    """

    def __init__(self, storage_path: str):
        self.storage_path = storage_path
        self._init_vuln_storage()

    def _init_vuln_storage(self):
        """初始化漏洞存储"""
        os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)

        conn = sqlite3.connect(self.storage_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS vuln_records (
                vuln_id TEXT PRIMARY KEY,
                target TEXT,
                vuln_type TEXT,
                severity TEXT,
                url TEXT,
                param TEXT,
                payload TEXT,
                status TEXT,
                first_seen TEXT,
                last_seen TEXT,
                evidence TEXT,
                verifier TEXT,
                metadata TEXT
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS vuln_history (
                vuln_id TEXT,
                status TEXT,
                changed_at TEXT,
                changed_by TEXT,
                notes TEXT,
                FOREIGN KEY(vuln_id) REFERENCES vuln_records(vuln_id)
            )
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_vuln_target ON vuln_records(target)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_vuln_type ON vuln_records(vuln_type)
        """)

        conn.commit()
        conn.close()

    def record_vulnerability(
        self,
        target: str,
        vuln_type: str,
        severity: str,
        url: str,
        param: str,
        payload: str,
        evidence: str,
        status: VulnerabilityStatus = VulnerabilityStatus.NEW
    ) -> str:
        """记录漏洞"""
        vuln_id = hashlib.md5(
            f"{target}:{url}:{param}:{vuln_type}".encode()
        ).hexdigest()[:16]

        now = datetime.utcnow().isoformat() + 'Z'

        conn = sqlite3.connect(self.storage_path)
        try:
            existing = conn.execute(
                "SELECT status FROM vuln_records WHERE vuln_id = ?",
                (vuln_id,)
            ).fetchone()

            if existing:
                old_status = existing[0]
                if old_status != status.value:
                    self._record_status_change(
                        conn, vuln_id, status, f"Status changed from {old_status} to {status.value}"
                    )
                    conn.execute(
                        "UPDATE vuln_records SET status = ?, last_seen = ? WHERE vuln_id = ?",
                        (status.value, now, vuln_id)
                    )
            else:
                conn.execute("""
                    INSERT INTO vuln_records VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    vuln_id, target, vuln_type, severity, url, param, payload,
                    status.value, now, now, evidence, 'system', '{}'
                ))
                self._record_status_change(conn, vuln_id, status, "Initial discovery")

            conn.commit()
        finally:
            conn.close()

        return vuln_id

    def _record_status_change(
        self,
        conn,
        vuln_id: str,
        new_status: VulnerabilityStatus,
        notes: str
    ):
        """记录漏洞状态变更"""
        now = datetime.utcnow().isoformat() + 'Z'
        conn.execute("""
            INSERT INTO vuln_history (vuln_id, status, changed_at, notes)
            VALUES (?, ?, ?, ?)
        """, (vuln_id, new_status.value, now, notes))

    def get_vulnerability_trend(
        self,
        target: str,
        days: int = 30
    ) -> List[VulnerabilityTrend]:
        """获取漏洞趋势"""
        conn = sqlite3.connect(self.storage_path)
        trends = []

        try:
            cutoff = datetime.utcnow().timestamp() - (days * 86400)
            cutoff_date = datetime.fromtimestamp(cutoff).isoformat() + 'Z'

            rows = conn.execute("""
                SELECT 
                    vuln_type,
                    severity,
                    COUNT(*) as total,
                    SUM(CASE WHEN first_seen > ? THEN 1 ELSE 0 END) as new_count
                FROM vuln_records
                WHERE target = ?
                GROUP BY vuln_type, severity
            """, (cutoff_date, target)).fetchall()

            for row in rows:
                trends.append(VulnerabilityTrend(
                    vuln_type=row[0],
                    severity=row[1],
                    total=row[2],
                    new_count=row[3],
                    resolved_count=0,
                    regression_count=0,
                    trend='stable'
                ))

        finally:
            conn.close()

        return trends

    def get_vulnerability_delta(
        self,
        target: str,
        previous_snapshot: Optional[Dict]
    ) -> Dict[str, Any]:
        """
        计算漏洞增量
        
        Returns:
            新增、修复、回归的漏洞列表
        """
        conn = sqlite3.connect(self.storage_path)

        current_vulns = {}
        try:
            rows = conn.execute("""
                SELECT vuln_id, vuln_type, severity, status
                FROM vuln_records
                WHERE target = ?
            """, (target,)).fetchall()

            for row in rows:
                current_vulns[row[0]] = {
                    'vuln_type': row[1],
                    'severity': row[2],
                    'status': row[3]
                }

        finally:
            conn.close()

        if not previous_snapshot:
            return {
                'new': list(current_vulns.keys()),
                'resolved': [],
                'regression': [],
                'total': len(current_vulns)
            }

        previous_vulns = previous_snapshot.get('vulnerabilities', {})

        new_vulns = set(current_vulns.keys()) - set(previous_vulns.keys())
        resolved_vulns = set(previous_vulns.keys()) - set(current_vulns.keys())

        regression = []
        for vuln_id in new_vulns:
            if vuln_id in previous_vulns:
                if current_vulns[vuln_id]['status'] == VulnerabilityStatus.REGRESSION.value:
                    regression.append(vuln_id)

        return {
            'new': list(new_vulns),
            'resolved': list(resolved_vulns),
            'regression': regression,
            'total': len(current_vulns),
            'current_vulns': current_vulns
        }

    def export_vulnerability_report(
        self,
        target: str,
        format: str = 'json'
    ) -> str:
        """导出漏洞报告"""
        conn = sqlite3.connect(self.storage_path)
        vulnerabilities = []

        try:
            rows = conn.execute("""
                SELECT * FROM vuln_records
                WHERE target = ?
                ORDER BY severity, first_seen DESC
            """, (target,)).fetchall()

            for row in rows:
                vulnerabilities.append({
                    'vuln_id': row[0],
                    'target': row[1],
                    'vuln_type': row[2],
                    'severity': row[3],
                    'url': row[4],
                    'param': row[5],
                    'payload': row[6],
                    'status': row[7],
                    'first_seen': row[8],
                    'last_seen': row[9]
                })

        finally:
            conn.close()

        if format == 'json':
            return json.dumps(vulnerabilities, indent=2, ensure_ascii=False)
        return vulnerabilities
