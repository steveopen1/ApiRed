"""
Dashboard Backend Main
ApiRed Dashboard 后端API服务
"""

import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="ApiRed Dashboard API",
    description="ApiRed 多目标管理Dashboard API",
    version="4.2.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from .api import projects, targets, scans, reports
from .db import db

app.include_router(projects.router)
app.include_router(targets.router)
app.include_router(scans.router)
app.include_router(reports.router)

@app.get("/")
async def root():
    return {
        "name": "ApiRed Dashboard API",
        "version": "4.2.0",
        "status": "running"
    }

@app.get("/health")
async def health():
    return {"status": "healthy"}

@app.get("/api/overview")
async def overview():
    stats = db.get_overview_stats()
    return {
        "total_projects": stats.get("total_projects", 0),
        "active_targets": stats.get("active_targets", 0),
        "total_apis": stats.get("total_apis", 0),
        "critical_vulns": stats.get("critical_vulns", 0),
        "high_vulns": stats.get("high_vulns", 0),
        "medium_vulns": stats.get("medium_vulns", 0),
        "low_vulns": stats.get("low_vulns", 0),
        "scan_trend": []
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)
