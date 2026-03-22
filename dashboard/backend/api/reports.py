"""
Reports API
报告API - 报告生成和导出
"""

import json
from typing import Optional
from datetime import datetime
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel

router = APIRouter(prefix="/api/reports", tags=["reports"])

class ReportSummary(BaseModel):
    project_name: str
    total_targets: int
    total_apis: int
    critical_vulns: int
    high_vulns: int
    medium_vulns: int
    low_vulns: int
    scan_date: str

@router.get("/{project_id}/summary", response_model=ReportSummary)
async def get_report_summary(project_id: int):
    """获取报告摘要"""
    return ReportSummary(
        project_name="Sample Project",
        total_targets=10,
        total_apis=100,
        critical_vulns=2,
        high_vulns=5,
        medium_vulns=10,
        low_vulns=15,
        scan_date=datetime.now().isoformat()
    )

@router.get("/{project_id}/export")
async def export_report(project_id: int, format: str = Query(default="json")):
    """导出报告
    
    支持格式: json, html, pdf
    """
    if format == "json":
        data = {
            "project_id": project_id,
            "project_name": "Sample Project",
            "scan_date": datetime.now().isoformat(),
            "summary": {
                "total_targets": 10,
                "total_apis": 100,
                "vulnerabilities": {
                    "critical": 2,
                    "high": 5,
                    "medium": 10,
                    "low": 15
                }
            },
            "targets": []
        }
        return Response(
            content=json.dumps(data, indent=2, ensure_ascii=False),
            media_type="application/json",
            headers={
                "Content-Disposition": f"attachment; filename=report_{project_id}.json"
            }
        )
    
    elif format == "html":
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>ApiRed Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #00d4ff; }}
        .summary {{ background: #f5f5f5; padding: 20px; border-radius: 8px; }}
        .vuln-critical {{ color: #ff4757; }}
        .vuln-high {{ color: #ffa500; }}
        .vuln-medium {{ color: #ffbe00; }}
        .vuln-low {{ color: #00d4ff; }}
    </style>
</head>
<body>
    <h1>ApiRed Security Report</h1>
    <div class="summary">
        <h2>Project: Sample Project</h2>
        <p>Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <h3>Vulnerability Summary</h3>
        <ul>
            <li class="vuln-critical">Critical: 2</li>
            <li class="vuln-high">High: 5</li>
            <li class="vuln-medium">Medium: 10</li>
            <li class="vuln-low">Low: 15</li>
        </ul>
    </div>
</body>
</html>
        """
        return Response(
            content=html_content,
            media_type="text/html",
            headers={
                "Content-Disposition": f"attachment; filename=report_{project_id}.html"
            }
        )
    
    elif format == "pdf":
        return Response(
            content=b"PDF content placeholder",
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=report_{project_id}.pdf"
            }
        )
    
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {format}")

@router.get("/{project_id}/vulnerabilities")
async def get_vulnerabilities(project_id: int):
    """获取漏洞列表"""
    return {
        "vulnerabilities": []
    }
