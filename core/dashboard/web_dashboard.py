"""
Web Dashboard Module
专业 Web 控制面板 - 支持 Agent 模式和纯规则模式
"""

import json
import os
import time
import threading
import subprocess
import signal
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import secrets
import logging
import hashlib

logger = logging.getLogger(__name__)

CONFIG_FILE = os.path.expanduser("~/.apired/dashboard_config.json")


@dataclass
class ScanTask:
    """扫描任务"""
    task_id: str
    target: str
    status: str = "pending"
    progress: int = 0
    start_time: str = ""
    end_time: str = ""
    pid: int = 0
    output_path: str = ""
    error: str = ""
    scan_mode: str = "rule"  # rule | agent
    config: Dict[str, Any] = field(default_factory=dict)


class ConfigManager:
    """配置管理器"""
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._lock = threading.RLock()
        self._config: Dict[str, Any] = {}
        self._ensure_config_dir()
        self._load_config()
    
    def _ensure_config_dir(self):
        config_dir = os.path.dirname(CONFIG_FILE)
        if config_dir:
            os.makedirs(config_dir, exist_ok=True)
    
    def _load_config(self):
        """加载配置"""
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                    self._config = json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load config: {e}")
                self._config = self._get_default_config()
        else:
            self._config = self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """获取默认配置"""
        return {
            "scan_mode": "rule",
            "ai_provider": "anthropic",
            "api_keys": {},
            "model_preferences": {
                "anthropic": "claude-sonnet-4-20250514",
                "openai": "gpt-4o",
                "gemini": "gemini-2.0-flash",
                "deepseek": "deepseek-chat",
                "mistral": "mistral-large-latest",
                "ollama": "llama3.2"
            },
            "scan_defaults": {
                "concurrency": 50,
                "js_depth": 3,
                "verify_ssl": True,
                "attack_mode": "all"
            },
            "theme": "dark"
        }
    
    def _save_config(self):
        """保存配置"""
        try:
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump(self._config, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Failed to save config: {e}")
    
    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            return self._config.get(key, default)
    
    def set(self, key: str, value: Any):
        with self._lock:
            self._config[key] = value
            self._save_config()
    
    def get_all(self) -> Dict[str, Any]:
        with self._lock:
            config_copy = self._config.copy()
            # Mask API keys for security
            if 'api_keys' in config_copy:
                masked_keys = {}
                for provider, key in config_copy['api_keys'].items():
                    if key:
                        masked_keys[provider] = mask_api_key(key)
                    else:
                        masked_keys[provider] = ""
                config_copy['api_keys'] = masked_keys
            return config_copy
    
    def update(self, updates: Dict[str, Any]):
        with self._lock:
            for key, value in updates.items():
                if key == 'api_keys':
                    # Merge API keys
                    if 'api_keys' not in self._config:
                        self._config['api_keys'] = {}
                    for provider, api_key in value.items():
                        if api_key and not api_key.startswith('***'):
                            self._config['api_keys'][provider] = api_key
                else:
                    self._config[key] = value
            self._save_config()
    
    def get_api_key(self, provider: str) -> Optional[str]:
        with self._lock:
            keys = self._config.get('api_keys', {})
            return keys.get(provider)
    
    def set_api_key(self, provider: str, api_key: str):
        with self._lock:
            if 'api_keys' not in self._config:
                self._config['api_keys'] = {}
            self._config['api_keys'][provider] = api_key
            self._save_config()


def mask_api_key(key: str) -> str:
    """掩码 API Key"""
    if not key or len(key) < 8:
        return "***"
    return key[:4] + "***" + key[-4:]


class TaskManager:
    """任务管理器"""
    
    def __init__(self):
        self.tasks: Dict[str, ScanTask] = {}
        self._lock = threading.Lock()
    
    def create_task(self, target: str, config: Optional[Dict] = None, scan_mode: str = "rule") -> ScanTask:
        """创建扫描任务"""
        task_id = secrets.token_hex(8)
        task = ScanTask(
            task_id=task_id,
            target=target,
            config=config or {},
            scan_mode=scan_mode,
            start_time=datetime.now().isoformat()
        )
        with self._lock:
            self.tasks[task_id] = task
        return task
    
    def get_task(self, task_id: str) -> Optional[ScanTask]:
        with self._lock:
            return self.tasks.get(task_id)
    
    def update_task(self, task_id: str, **kwargs):
        with self._lock:
            if task_id in self.tasks:
                for key, value in kwargs.items():
                    if hasattr(self.tasks[task_id], key):
                        setattr(self.tasks[task_id], key, value)
    
    def list_tasks(self) -> List[Dict]:
        with self._lock:
            return [asdict(t) for t in self.tasks.values()]
    
    def delete_task(self, task_id: str) -> bool:
        with self._lock:
            if task_id in self.tasks:
                task = self.tasks[task_id]
                if task.pid > 0:
                    try:
                        os.kill(task.pid, signal.SIGTERM)
                    except:
                        pass
                del self.tasks[task_id]
                return True
            return False
    
    def clear_completed(self):
        """清除已完成任务"""
        with self._lock:
            completed = [tid for tid, t in self.tasks.items() if t.status in ('completed', 'failed', 'stopped')]
            for tid in completed:
                del self.tasks[tid]


# 专业的 Dashboard HTML
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ApiRed - Professional API Security Scanner</title>
    <style>
        :root {
            --bg-primary: #0a0e17;
            --bg-secondary: #111827;
            --bg-tertiary: #1f2937;
            --border-color: #374151;
            --text-primary: #f9fafb;
            --text-secondary: #9ca3af;
            --text-muted: #6b7280;
            --accent-primary: #3b82f6;
            --accent-secondary: #6366f1;
            --accent-gradient: linear-gradient(135deg, #3b82f6, #6366f1);
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --info: #06b6d4;
        }
        
        * { box-sizing: border-box; margin: 0; padding: 0; }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            line-height: 1.5;
        }
        
        .header {
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border-color);
            padding: 16px 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 100;
        }
        
        .logo {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .logo-icon {
            width: 36px;
            height: 36px;
            background: var(--accent-gradient);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            font-size: 18px;
        }
        
        .logo-text {
            font-size: 1.25rem;
            font-weight: 600;
            background: var(--accent-gradient);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .logo-subtitle {
            font-size: 0.75rem;
            color: var(--text-muted);
        }
        
        .nav-tabs {
            display: flex;
            gap: 4px;
            background: var(--bg-tertiary);
            padding: 4px;
            border-radius: 8px;
        }
        
        .nav-tab {
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            color: var(--text-secondary);
            font-size: 0.875rem;
            font-weight: 500;
            transition: all 0.2s;
            border: none;
            background: transparent;
        }
        
        .nav-tab:hover {
            color: var(--text-primary);
            background: var(--bg-secondary);
        }
        
        .nav-tab.active {
            color: var(--text-primary);
            background: var(--accent-gradient);
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 24px;
        }
        
        .page { display: none; }
        .page.active { display: block; }
        
        .card {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 20px;
        }
        
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 16px;
            border-bottom: 1px solid var(--border-color);
        }
        
        .card-title {
            font-size: 1rem;
            font-weight: 600;
            color: var(--text-primary);
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }
        
        .stat-card {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 20px;
        }
        
        .stat-value {
            font-size: 2rem;
            font-weight: 700;
            background: var(--accent-gradient);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .stat-label {
            color: var(--text-muted);
            font-size: 0.875rem;
            margin-top: 4px;
        }
        
        .form-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 20px;
        }
        
        .form-group {
            margin-bottom: 16px;
        }
        
        .form-label {
            display: block;
            font-size: 0.875rem;
            font-weight: 500;
            color: var(--text-secondary);
            margin-bottom: 8px;
        }
        
        .form-input {
            width: 100%;
            padding: 10px 14px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            color: var(--text-primary);
            font-size: 0.875rem;
            transition: border-color 0.2s;
        }
        
        .form-input:focus {
            outline: none;
            border-color: var(--accent-primary);
        }
        
        .form-input::placeholder {
            color: var(--text-muted);
        }
        
        .form-select {
            width: 100%;
            padding: 10px 14px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            color: var(--text-primary);
            font-size: 0.875rem;
            cursor: pointer;
        }
        
        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 8px;
            font-size: 0.875rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }
        
        .btn-primary {
            background: var(--accent-gradient);
            color: white;
        }
        
        .btn-primary:hover {
            opacity: 0.9;
            transform: translateY(-1px);
        }
        
        .btn-secondary {
            background: var(--bg-tertiary);
            color: var(--text-primary);
            border: 1px solid var(--border-color);
        }
        
        .btn-danger {
            background: var(--danger);
            color: white;
        }
        
        .btn-success {
            background: var(--success);
            color: white;
        }
        
        .btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        
        .mode-selector {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
            margin-bottom: 24px;
        }
        
        .mode-card {
            background: var(--bg-tertiary);
            border: 2px solid var(--border-color);
            border-radius: 12px;
            padding: 20px;
            cursor: pointer;
            transition: all 0.2s;
        }
        
        .mode-card:hover {
            border-color: var(--accent-primary);
        }
        
        .mode-card.selected {
            border-color: var(--accent-primary);
            background: rgba(59, 130, 246, 0.1);
        }
        
        .mode-card-header {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 12px;
        }
        
        .mode-icon {
            width: 40px;
            height: 40px;
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 20px;
        }
        
        .mode-icon.rule { background: rgba(16, 185, 129, 0.2); }
        .mode-icon.agent { background: rgba(99, 102, 241, 0.2); }
        
        .mode-name {
            font-weight: 600;
            font-size: 1rem;
        }
        
        .mode-desc {
            font-size: 0.8rem;
            color: var(--text-muted);
        }
        
        .api-key-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
        }
        
        .api-key-item {
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 16px;
        }
        
        .api-key-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
        }
        
        .api-provider {
            font-weight: 600;
            font-size: 0.9rem;
        }
        
        .api-status {
            font-size: 0.75rem;
            padding: 2px 8px;
            border-radius: 4px;
        }
        
        .api-status.configured {
            background: rgba(16, 185, 129, 0.2);
            color: var(--success);
        }
        
        .api-status.not-configured {
            background: rgba(107, 114, 128, 0.2);
            color: var(--text-muted);
        }
        
        .task-list {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }
        
        .task-card {
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 16px;
        }
        
        .task-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 12px;
        }
        
        .task-info {
            flex: 1;
        }
        
        .task-target {
            font-weight: 600;
            font-size: 0.95rem;
            color: var(--accent-primary);
            word-break: break-all;
        }
        
        .task-meta {
            display: flex;
            gap: 16px;
            margin-top: 4px;
            font-size: 0.8rem;
            color: var(--text-muted);
        }
        
        .task-badge {
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .task-badge.rule { background: rgba(16, 185, 129, 0.2); color: var(--success); }
        .task-badge.agent { background: rgba(99, 102, 241, 0.2); color: var(--accent-secondary); }
        .task-badge.pending { background: rgba(107, 114, 128, 0.2); color: var(--text-muted); }
        .task-badge.running { background: rgba(59, 130, 246, 0.2); color: var(--accent-primary); }
        .task-badge.completed { background: rgba(16, 185, 129, 0.2); color: var(--success); }
        .task-badge.failed { background: rgba(239, 68, 68, 0.2); color: var(--danger); }
        
        .task-progress {
            margin-top: 12px;
        }
        
        .progress-bar {
            height: 6px;
            background: var(--bg-primary);
            border-radius: 3px;
            overflow: hidden;
        }
        
        .progress-fill {
            height: 100%;
            background: var(--accent-gradient);
            transition: width 0.3s;
        }
        
        .task-actions {
            display: flex;
            gap: 8px;
            margin-top: 12px;
        }
        
        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: var(--text-muted);
        }
        
        .empty-icon {
            font-size: 48px;
            margin-bottom: 16px;
            opacity: 0.5;
        }
        
        .toast {
            position: fixed;
            bottom: 24px;
            right: 24px;
            padding: 12px 20px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            color: var(--text-primary);
            font-size: 0.875rem;
            z-index: 1000;
            animation: slideIn 0.3s ease;
        }
        
        .toast.success { border-left: 4px solid var(--success); }
        .toast.error { border-left: 4px solid var(--danger); }
        
        @keyframes slideIn {
            from { transform: translateX(100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        
        .results-table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .results-table th,
        .results-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }
        
        .results-table th {
            background: var(--bg-tertiary);
            font-weight: 600;
            font-size: 0.8rem;
            text-transform: uppercase;
            color: var(--text-muted);
        }
        
        .results-table tr:hover {
            background: var(--bg-tertiary);
        }
        
        .vuln-badge {
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
        }
        
        .vuln-badge.critical { background: rgba(239, 68, 68, 0.2); color: var(--danger); }
        .vuln-badge.high { background: rgba(245, 158, 11, 0.2); color: var(--warning); }
        .vuln-badge.medium { background: rgba(59, 130, 246, 0.2); color: var(--accent-primary); }
        .vuln-badge.low { background: rgba(16, 185, 129, 0.2); color: var(--success); }
    </style>
</head>
<body>
    <header class="header">
        <div class="logo">
            <div class="logo-icon">AR</div>
            <div>
                <div class="logo-text">ApiRed</div>
                <div class="logo-subtitle">Professional API Security Scanner</div>
            </div>
        </div>
        <nav class="nav-tabs">
            <button class="nav-tab active" data-page="scan">Scan</button>
            <button class="nav-tab" data-page="tasks">Tasks</button>
            <button class="nav-tab" data-page="settings">Settings</button>
        </nav>
    </header>
    
    <div class="container">
        <!-- Scan Page -->
        <div id="page-scan" class="page active">
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value" id="stat-total-scans">0</div>
                    <div class="stat-label">Total Scans</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="stat-running">0</div>
                    <div class="stat-label">Running</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="stat-apis">0</div>
                    <div class="stat-label">APIs Found</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="stat-vulns">0</div>
                    <div class="stat-label">Vulnerabilities</div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <h2 class="card-title">New Scan</h2>
                </div>
                
                <div class="mode-selector">
                    <div class="mode-card selected" data-mode="rule" onclick="selectMode('rule')">
                        <div class="mode-card-header">
                            <div class="mode-icon rule">⚡</div>
                            <div>
                                <div class="mode-name">Rule-based Mode</div>
                                <div class="mode-desc">Fast scanning using predefined rules</div>
                            </div>
                        </div>
                        <div style="font-size: 0.8rem; color: var(--text-muted);">
                            Best for: Quick reconnaissance, known vulnerability detection
                        </div>
                    </div>
                    <div class="mode-card" data-mode="agent" onclick="selectMode('agent')">
                        <div class="mode-card-header">
                            <div class="mode-icon agent">🤖</div>
                            <div>
                                <div class="mode-name">AI Agent Mode</div>
                                <div class="mode-desc">Intelligent scanning powered by LLM</div>
                            </div>
                        </div>
                        <div style="font-size: 0.8rem; color: var(--text-muted);">
                            Best for: Deep analysis, unknown vulnerability discovery
                        </div>
                    </div>
                </div>
                
                <div class="form-grid">
                    <div class="form-group">
                        <label class="form-label">Target URL *</label>
                        <input type="text" id="input-target" class="form-input" placeholder="https://api.example.com">
                    </div>
                    <div class="form-group">
                        <label class="form-label">Cookies (optional)</label>
                        <input type="text" id="input-cookies" class="form-input" placeholder="session=xxx; token=yyy">
                    </div>
                    <div class="form-group">
                        <label class="form-label">Concurrency</label>
                        <input type="number" id="input-concurrency" class="form-input" value="50" min="1" max="500">
                    </div>
                    <div class="form-group">
                        <label class="form-label">Attack Mode</label>
                        <select id="input-attack-mode" class="form-select">
                            <option value="all">All Tests</option>
                            <option value="collect">Collection Only</option>
                            <option value="scan">Vulnerability Scan</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label class="form-label">JS Depth</label>
                        <input type="number" id="input-js-depth" class="form-input" value="3" min="1" max="10">
                    </div>
                    <div class="form-group">
                        <label class="form-label">Output Format</label>
                        <select id="input-format" class="form-select">
                            <option value="json">JSON</option>
                            <option value="html">HTML</option>
                            <option value="all">All Formats</option>
                        </select>
                    </div>
                </div>
                
                <div style="display: flex; gap: 12px; margin-top: 20px;">
                    <button class="btn btn-primary" onclick="startScan()">
                        <span>▶</span> Start Scan
                    </button>
                    <button class="btn btn-secondary" onclick="clearCompletedTasks()">
                        Clear Completed
                    </button>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <h2 class="card-title">Quick Tasks</h2>
                </div>
                <div id="quick-tasks" class="task-list">
                    <div class="empty-state">No active tasks</div>
                </div>
            </div>
        </div>
        
        <!-- Tasks Page -->
        <div id="page-tasks" class="page">
            <div class="card">
                <div class="card-header">
                    <h2 class="card-title">All Tasks</h2>
                    <button class="btn btn-secondary" onclick="loadTasks()">Refresh</button>
                </div>
                <div id="all-tasks" class="task-list">
                    <div class="empty-state">No tasks yet</div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <h2 class="card-title">Scan Results</h2>
                </div>
                <div id="results-container">
                    <div class="empty-state">No results yet</div>
                </div>
            </div>
        </div>
        
        <!-- Settings Page -->
        <div id="page-settings" class="page">
            <div class="card">
                <div class="card-header">
                    <h2 class="card-title">AI Provider Configuration</h2>
                </div>
                <p style="color: var(--text-muted); margin-bottom: 20px; font-size: 0.875rem;">
                    Configure your AI provider API keys. Keys are stored locally and never transmitted.
                </p>
                
                <div class="api-key-grid" id="api-key-list">
                    <!-- Dynamically populated -->
                </div>
                
                <div style="margin-top: 24px; padding-top: 20px; border-top: 1px solid var(--border-color);">
                    <button class="btn btn-primary" onclick="saveSettings()">Save Settings</button>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <h2 class="card-title">Scan Defaults</h2>
                </div>
                <div class="form-grid">
                    <div class="form-group">
                        <label class="form-label">Default Concurrency</label>
                        <input type="number" id="default-concurrency" class="form-input" value="50" min="1" max="500">
                    </div>
                    <div class="form-group">
                        <label class="form-label">Default JS Depth</label>
                        <input type="number" id="default-js-depth" class="form-input" value="3" min="1" max="10">
                    </div>
                    <div class="form-group">
                        <label class="form-label">Verify SSL</label>
                        <select id="default-verify-ssl" class="form-select">
                            <option value="true">Yes</option>
                            <option value="false">No</option>
                        </select>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <div id="toast-container"></div>
    
    <script>
        let currentMode = 'rule';
        let config = {};
        
        const API_PROVIDERS = {
            'anthropic': { name: 'Anthropic Claude', models: ['claude-sonnet-4-20250514', 'claude-opus-4-20250514', 'claude-3-5-sonnet-20241022'] },
            'openai': { name: 'OpenAI', models: ['gpt-4o', 'gpt-4o-mini', 'gpt-4-turbo'] },
            'gemini': { name: 'Google Gemini', models: ['gemini-2.0-flash', 'gemini-1.5-pro', 'gemini-1.5-flash'] },
            'deepseek': { name: 'DeepSeek', models: ['deepseek-chat', 'deepseek-coder'] },
            'mistral': { name: 'Mistral AI', models: ['mistral-large-latest', 'mistral-small-latest', 'mistral-7b'] },
            'ollama': { name: 'Ollama (Local)', models: ['llama3.2', 'qwen2.5', 'codellama'] }
        };
        
        document.querySelectorAll('.nav-tab').forEach(tab => {
            tab.addEventListener('click', () => {
                document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
                tab.classList.add('active');
                document.getElementById('page-' + tab.dataset.page).classList.add('active');
            });
        });
        
        function selectMode(mode) {
            currentMode = mode;
            document.querySelectorAll('.mode-card').forEach(card => {
                card.classList.toggle('selected', card.dataset.mode === mode);
            });
        }
        
        function showToast(message, type = 'info') {
            const container = document.getElementById('toast-container');
            const toast = document.createElement('div');
            toast.className = 'toast ' + type;
            toast.textContent = message;
            container.appendChild(toast);
            setTimeout(() => toast.remove(), 3000);
        }
        
        async function loadConfig() {
            try {
                const resp = await fetch('/api/config');
                config = await resp.json();
                renderApiKeys();
                document.getElementById('default-concurrency').value = config.scan_defaults?.concurrency || 50;
                document.getElementById('default-js-depth').value = config.scan_defaults?.js_depth || 3;
                document.getElementById('default-verify-ssl').value = config.scan_defaults?.verify_ssl ? 'true' : 'false';
            } catch (e) {
                console.error('Failed to load config:', e);
            }
        }
        
        function renderApiKeys() {
            const container = document.getElementById('api-key-list');
            let html = '';
            for (const [provider, info] of Object.entries(API_PROVIDERS)) {
                const key = config.api_keys?.[provider] || '';
                const isConfigured = key && !key.startsWith('***');
                html += `
                    <div class="api-key-item">
                        <div class="api-key-header">
                            <span class="api-provider">${info.name}</span>
                            <span class="api-status ${isConfigured ? 'configured' : 'not-configured'}">
                                ${isConfigured ? 'Configured' : 'Not Set'}
                            </span>
                        </div>
                        <input type="password" class="form-input api-key-input" 
                               data-provider="${provider}" 
                               placeholder="Enter API key..."
                               value="${key}">
                    </div>
                `;
            }
            container.innerHTML = html;
        }
        
        async function saveSettings() {
            const apiKeys = {};
            document.querySelectorAll('.api-key-input').forEach(input => {
                const value = input.value.trim();
                if (value && !value.startsWith('***')) {
                    apiKeys[input.dataset.provider] = value;
                }
            });
            
            const updates = {
                api_keys: apiKeys,
                scan_defaults: {
                    concurrency: parseInt(document.getElementById('default-concurrency').value) || 50,
                    js_depth: parseInt(document.getElementById('default-js-depth').value) || 3,
                    verify_ssl: document.getElementById('default-verify-ssl').value === 'true'
                }
            };
            
            try {
                const resp = await fetch('/api/config', {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(updates)
                });
                if (resp.ok) {
                    showToast('Settings saved successfully', 'success');
                    loadConfig();
                } else {
                    showToast('Failed to save settings', 'error');
                }
            } catch (e) {
                showToast('Failed to save settings: ' + e.message, 'error');
            }
        }
        
        async function startScan() {
            const target = document.getElementById('input-target').value.trim();
            if (!target) {
                showToast('Please enter target URL', 'error');
                return;
            }
            
            const config_data = {
                cookies: document.getElementById('input-cookies').value.trim(),
                concurrency: parseInt(document.getElementById('input-concurrency').value) || 50,
                attack_mode: document.getElementById('input-attack-mode').value,
                js_depth: parseInt(document.getElementById('input-js-depth').value) || 3,
                format: document.getElementById('input-format').value
            };
            
            try {
                const resp = await fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        target: target,
                        scan_mode: currentMode,
                        config: config_data
                    })
                });
                
                const result = await resp.json();
                
                if (result.error) {
                    showToast(result.error, 'error');
                } else {
                    showToast(`Scan started: ${result.task_id}`, 'success');
                    document.getElementById('input-target').value = '';
                    loadStats();
                    loadTasks();
                }
            } catch (e) {
                showToast('Failed to start scan: ' + e.message, 'error');
            }
        }
        
        async function stopTask(taskId) {
            try {
                await fetch('/api/task/stop', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ task_id: taskId })
                });
                loadTasks();
            } catch (e) {
                showToast('Failed to stop task', 'error');
            }
        }
        
        async function deleteTask(taskId) {
            try {
                await fetch('/api/task/delete', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ task_id: taskId })
                });
                loadTasks();
                loadStats();
            } catch (e) {
                showToast('Failed to delete task', 'error');
            }
        }
        
        async function clearCompletedTasks() {
            try {
                await fetch('/api/tasks/clear', { method: 'POST' });
                loadTasks();
            } catch (e) {
                showToast('Failed to clear tasks', 'error');
            }
        }
        
        async function loadStats() {
            try {
                const resp = await fetch('/api/stats');
                const data = await resp.json();
                document.getElementById('stat-total-scans').textContent = data.total_scans || 0;
                document.getElementById('stat-running').textContent = data.running_tasks || 0;
                document.getElementById('stat-apis').textContent = data.total_apis || 0;
                document.getElementById('stat-vulns').textContent = data.total_vulns || 0;
            } catch (e) {
                console.error('Failed to load stats:', e);
            }
        }
        
        async function loadTasks() {
            try {
                const resp = await fetch('/api/tasks');
                const data = await resp.json();
                const tasks = data.tasks || [];
                
                const quickHtml = tasks.length ? tasks.slice(0, 3).map(renderTask).join('') : '<div class="empty-state">No active tasks</div>';
                document.getElementById('quick-tasks').innerHTML = quickHtml;
                
                const allHtml = tasks.length ? tasks.map(renderTask).join('') : '<div class="empty-state">No tasks yet</div>';
                document.getElementById('all-tasks').innerHTML = allHtml;
            } catch (e) {
                console.error('Failed to load tasks:', e);
            }
        }
        
        function renderTask(task) {
            return `
                <div class="task-card">
                    <div class="task-header">
                        <div class="task-info">
                            <div class="task-target">${escapeHtml(task.target)}</div>
                            <div class="task-meta">
                                <span>Mode: ${task.scan_mode || 'rule'}</span>
                                <span>${task.start_time ? new Date(task.start_time).toLocaleString() : ''}</span>
                            </div>
                        </div>
                        <div>
                            <span class="task-badge ${task.scan_mode || 'rule'}">${task.scan_mode || 'rule'}</span>
                            <span class="task-badge ${task.status}">${task.status}</span>
                        </div>
                    </div>
                    <div class="task-progress">
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: ${task.progress || 0}%"></div>
                        </div>
                    </div>
                    <div class="task-actions">
                        ${task.status === 'running' ? '<button class="btn btn-danger" onclick="stopTask(\'' + task.task_id + '\')">Stop</button>' : ''}
                        <button class="btn btn-secondary" onclick="deleteTask(\'' + task.task_id + '\')">Delete</button>
                    </div>
                </div>
            `;
        }
        
        async function loadResults() {
            try {
                const resp = await fetch('/api/results');
                const data = await resp.json();
                const results = data.results || [];
                
                if (!results.length) {
                    document.getElementById('results-container').innerHTML = '<div class="empty-state">No results yet</div>';
                    return;
                }
                
                let html = '<table class="results-table"><thead><tr><th>Target</th><th>APIs</th><th>Vulns</th><th>Time</th></tr></thead><tbody>';
                for (const r of results.slice(-20).reverse()) {
                    const vulns = r.vulnerabilities || [];
                    const critical = vulns.filter(v => v.severity === 'critical').length;
                    const high = vulns.filter(v => v.severity === 'high').length;
                    const medium = vulns.filter(v => v.severity === 'medium').length;
                    
                    html += `<tr>
                        <td>${escapeHtml(r.target_url || r.target || 'Unknown')}</td>
                        <td>${r.total_apis || 0}</td>
                        <td>
                            ${critical ? `<span class="vuln-badge critical">${critical}C</span>` : ''}
                            ${high ? `<span class="vuln-badge high">${high}H</span>` : ''}
                            ${medium ? `<span class="vuln-badge medium">${medium}M</span>` : ''}
                        </td>
                        <td>${r.start_time || '-'}</td>
                    </tr>`;
                }
                html += '</tbody></table>';
                document.getElementById('results-container').innerHTML = html;
            } catch (e) {
                console.error('Failed to load results:', e);
            }
        }
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        // Initialize
        loadConfig();
        loadStats();
        loadTasks();
        loadResults();
        
        // Auto-refresh
        setInterval(() => {
            loadStats();
            loadTasks();
        }, 5000);
        
        // Tab switching for tasks page
        document.querySelector('[data-page="tasks"]').addEventListener('click', loadResults);
    </script>
</body>
</html>
"""


class DashboardHandler(BaseHTTPRequestHandler):
    """Dashboard 请求处理器"""
    task_manager: TaskManager = None
    
    def do_GET(self):
        parsed = urlparse(self.path)
        
        if parsed.path == '/':
            self._send_html(DASHBOARD_HTML)
        elif parsed.path == '/api/tasks':
            self._send_tasks()
        elif parsed.path == '/api/results':
            self._send_results()
        elif parsed.path == '/api/stats':
            self._send_stats()
        elif parsed.path == '/api/config':
            self._send_config()
        elif parsed.path.startswith('/api/task/'):
            task_id = parsed.path.split('/')[-1]
            if parsed.path.endswith('/stop'):
                self._handle_stop_task(task_id.rsplit('/')[0])
            elif parsed.path.endswith('/delete'):
                self._handle_delete_task(task_id.rsplit('/')[0])
            else:
                self._send_task(task_id)
        else:
            self._send_json({"error": "Not found"}, 404)
    
    def do_POST(self):
        parsed = urlparse(self.path)
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8') if content_length else '{}'
        
        try:
            data = json.loads(body) if body else {}
        except:
            data = {}
        
        if parsed.path == '/api/scan':
            self._handle_start_scan(data)
        elif parsed.path == '/api/task/stop':
            self._handle_stop_task(data.get('task_id'))
        elif parsed.path == '/api/task/delete':
            self._handle_delete_task(data.get('task_id'))
        elif parsed.path == '/api/tasks/clear':
            self._handle_clear_tasks()
        elif parsed.path == '/api/config':
            self._handle_update_config(data)
        else:
            self._send_json({"error": "Not found"}, 404)
    
    def do_PUT(self):
        parsed = urlparse(self.path)
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8') if content_length else '{}'
        
        try:
            data = json.loads(body) if body else {}
        except:
            data = {}
        
        if parsed.path == '/api/config':
            self._handle_update_config(data)
        else:
            self._send_json({"error": "Not found"}, 404)
    
    def _handle_start_scan(self, data: Dict):
        """启动扫描"""
        target = data.get('target')
        if not target:
            self._send_json({"error": "target is required"}, 400)
            return
        
        config = data.get('config', {})
        scan_mode = data.get('scan_mode', 'rule')
        
        task = self.task_manager.create_task(target, config, scan_mode)
        
        threading.Thread(
            target=self._run_scan,
            args=(task.task_id, target, config, scan_mode),
            daemon=True
        ).start()
        
        self._send_json({"task_id": task.task_id, "status": "started"})
    
    def _run_scan(self, task_id: str, target: str, config: Dict, scan_mode: str):
        """运行扫描"""
        self.task_manager.update_task(task_id, status="running", progress=0)
        
        try:
            cmd = ["python3", "apired.py", "-u", target]
            
            if scan_mode == 'agent':
                cmd.append("--ai")
            
            if config.get('cookies'):
                cmd.extend(["-c", config['cookies']])
            if config.get('concurrency'):
                cmd.extend(["--concurrency", str(config['concurrency'])])
            if config.get('attack_mode'):
                mode_map = {'all': '0', 'collect': '1', 'scan': '2'}
                cmd.extend(["--at", mode_map.get(config['attack_mode'], '0')])
            if config.get('js_depth'):
                cmd.extend(["--js-depth", str(config['js_depth'])])
            if config.get('format'):
                cmd.extend(["--format", config['format']])
            
            output_path = f"./results/{target.replace('://', '_').replace('/', '_').replace('.', '_')}"
            os.makedirs(output_path, exist_ok=True)
            
            self.task_manager.update_task(task_id, progress=10, output_path=output_path)
            
            env = os.environ.copy()
            # Pass API keys to subprocess
            config_mgr = ConfigManager()
            for provider, api_key in config_mgr.get('api_keys', {}).items():
                if api_key:
                    env[f"{provider.upper()}_API_KEY"] = api_key
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=os.getcwd(),
                env=env
            )
            
            self.task_manager.update_task(task_id, pid=process.pid)
            
            for progress in range(20, 100, 10):
                time.sleep(2)
                if process.poll() is not None:
                    break
                self.task_manager.update_task(task_id, progress=progress)
            
            stdout, stderr = process.communicate()
            
            self.task_manager.update_task(
                task_id,
                status="completed" if process.returncode == 0 else "failed",
                progress=100,
                end_time=datetime.now().isoformat(),
                error=stderr.decode('utf-8', errors='ignore')[:500] if stderr else ""
            )
            
        except Exception as e:
            self.task_manager.update_task(
                task_id,
                status="failed",
                error=str(e)
            )
    
    def _handle_stop_task(self, task_id: str):
        """停止任务"""
        if not task_id:
            self._send_json({"error": "task_id is required"}, 400)
            return
        
        task = self.task_manager.get_task(task_id)
        if not task:
            self._send_json({"error": "task not found"}, 404)
            return
        
        if task.pid > 0:
            try:
                os.kill(task.pid, signal.SIGTERM)
                self.task_manager.update_task(
                    task_id,
                    status="stopped",
                    end_time=datetime.now().isoformat()
                )
                self._send_json({"task_id": task_id, "status": "stopped"})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
        else:
            self._send_json({"error": "task not running"}, 400)
    
    def _handle_delete_task(self, task_id: str):
        """删除任务"""
        if not task_id:
            self._send_json({"error": "task_id is required"}, 400)
            return
        
        success = self.task_manager.delete_task(task_id)
        if success:
            self._send_json({"task_id": task_id, "status": "deleted"})
        else:
            self._send_json({"error": "task not found"}, 404)
    
    def _handle_clear_tasks(self):
        """清除已完成任务"""
        self.task_manager.clear_completed()
        self._send_json({"status": "cleared"})
    
    def _handle_update_config(self, data: Dict):
        """更新配置"""
        config_mgr = ConfigManager()
        config_mgr.update(data)
        self._send_json({"status": "saved"})
    
    def _send_html(self, html: str):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode())
    
    def _send_json(self, data: Dict, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False).encode())
    
    def _send_tasks(self):
        tasks = self.task_manager.list_tasks()
        self._send_json({"tasks": tasks})
    
    def _send_task(self, task_id: str):
        task = self.task_manager.get_task(task_id)
        if task:
            self._send_json(asdict(task))
        else:
            self._send_json({"error": "task not found"}, 404)
    
    def _send_results(self):
        results = self._load_results()
        self._send_json({"results": results})
    
    def _send_stats(self):
        tasks = self.task_manager.list_tasks()
        results = self._load_results()
        
        total_apis = sum(r.get('total_apis', 0) for r in results)
        total_vulns = sum(len(r.get('vulnerabilities', [])) for r in results)
        running_count = sum(1 for t in tasks if t['status'] == 'running')
        
        self._send_json({
            "total_scans": len(results),
            "total_tasks": len(tasks),
            "running_tasks": running_count,
            "total_apis": total_apis,
            "total_vulns": total_vulns,
            "last_scan": results[-1].get('start_time') if results else None
        })
    
    def _send_config(self):
        config_mgr = ConfigManager()
        self._send_json(config_mgr.get_all())
    
    def _load_results(self) -> List[Dict]:
        results = []
        results_dir = "./results"
        
        if os.path.exists(results_dir):
            for target_folder in os.listdir(results_dir):
                result_file = os.path.join(
                    results_dir, target_folder, "scan_result.json"
                )
                if os.path.exists(result_file):
                    try:
                        with open(result_file, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                            results.append(data)
                    except Exception as e:
                        logger.warning(f"Failed to load scan result: {e}")
        
        return results
    
    def log_message(self, format, *args):
        print(f"[Dashboard] {args[0]}")


class WebDashboard:
    """Web 控制面板"""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 8080):
        self.host = host
        self.port = port
        self.server: Optional[HTTPServer] = None
        self.task_manager = TaskManager()
    
    def start(self, blocking: bool = True):
        DashboardHandler.task_manager = self.task_manager
        
        self.server = HTTPServer((self.host, self.port), DashboardHandler)
        
        print(f"[*] ApiRed Professional Dashboard running at http://{self.host}:{self.port}")
        print(f"[*] UI Pages:")
        print(f"    Dashboard: http://{self.host}:{self.port}/")
        print(f"[*] API Endpoints:")
        print(f"    GET  /api/tasks          - List tasks")
        print(f"    GET  /api/task/<id>      - Get task details")
        print(f"    GET  /api/results        - List results")
        print(f"    GET  /api/stats          - Statistics")
        print(f"    GET  /api/config         - Get configuration")
        print(f"    PUT  /api/config         - Update configuration")
        print(f"    POST /api/scan           - Start scan")
        print(f"    POST /api/task/stop      - Stop task")
        print(f"    POST /api/task/delete    - Delete task")
        print(f"    POST /api/tasks/clear    - Clear completed tasks")
        
        if blocking:
            self.server.serve_forever()
        else:
            thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            thread.start()
            print(f"[*] Dashboard started in background")
    
    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server = None


def run_dashboard(host: str = "0.0.0.0", port: int = 8080):
    dashboard = WebDashboard(host, port)
    dashboard.start()


if __name__ == "__main__":
    run_dashboard()
