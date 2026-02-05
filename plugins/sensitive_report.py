import os
import json
import base64
import datetime
import sqlite3
from plugins.ai_engine import AIEngine

def generate_sensitive_report(folder_path, sensitive_data_info, ai_scan_enabled=False, db_path=None):
    """
    生成现代化的敏感信息检测HTML报告
    """
    # 统计信息
    total_count = len(sensitive_data_info)
    severity_counts = {"high": 0, "medium": 0, "low": 0}
    category_counts = {}
    
    # 转换为图表数据
    items_js = []
    for item in sensitive_data_info:
        # (name, matches, url, file, severity, evidence) -> (rule_id, match, url, file, severity, context)
        # 兼容性处理，可能还有 category_name, description, line_number
        name = item[0]
        matches = str(item[1])
        url = item[2]
        file_path = item[3]
        severity = item[4] if len(item) > 4 else "medium"
        evidence = item[5] if len(item) > 5 else ""
        line_number = item[6] if len(item) > 6 else 0
        category = item[7] if len(item) > 7 else "General"
        description = item[8] if len(item) > 8 else ""
        
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        category_counts[category] = category_counts.get(category, 0) + 1
        
        items_js.append({
            "rule_id": name,
            "match": matches,
            "url": url,
            "file": file_path,
            "severity": severity,
            "context": evidence,
            "line": line_number,
            "category": category,
            "description": description
        })
    
    # AI Verification Step
    if ai_scan_enabled:
        try:
            ai_engine = AIEngine()
            if ai_engine.api_key:
                print("[AI] 正在启动敏感信息 AI 验证...")
                
                # 准备数据库更新
                conn = None
                if db_path:
                    try:
                        conn = sqlite3.connect(db_path)
                        try:
                            conn.execute("ALTER TABLE step8_sensitive ADD COLUMN ai_is_sensitive INTEGER")
                            conn.execute("ALTER TABLE step8_sensitive ADD COLUMN ai_reason TEXT")
                        except: pass
                    except: pass

                for item in items_js:
                    # Only verify high/medium severity to save cost/time
                    if item['severity'] in ['high', 'medium']:
                        print(f"[AI] 正在分析: {item['match']} (规则: {item['rule_id']})")
                        context = item.get('context', '')[:1000] 
                        ai_result = ai_engine.verify_sensitive_info(item['match'], context)
                        
                        if ai_result:
                            is_sensitive = ai_result.get('is_sensitive')
                            reason = ai_result.get('reason')
                            verdict = "确认敏感" if is_sensitive else "误报"
                            print(f"  -> AI 判定: {verdict}")
                            print(f"  -> 原因: {reason}")
                            print("-" * 40)

                            item['ai_verified'] = True
                            item['ai_is_sensitive'] = is_sensitive
                            item['ai_confidence'] = ai_result.get('confidence')
                            item['ai_reason'] = reason
                            
                            # 更新数据库
                            if conn and is_sensitive:
                                try:
                                    # 尝试更新
                                    conn.execute("UPDATE step8_sensitive SET ai_is_sensitive=1, ai_reason=? WHERE name=? AND matches=? AND url=? AND file=?", (item.get('ai_reason',''), item['rule_id'], item['match'], item['url'], item['file']))
                                    conn.commit()
                                except: pass
                            
                            # Adjust severity/description based on AI
                            if item['ai_is_sensitive'] == False and item['ai_confidence'] == 'high':
                                item['severity'] = 'low'
                                item['description'] = (item['description'] or "") + " [AI: Likely False Positive]"
                            elif item['ai_is_sensitive'] == True:
                                item['description'] = (item['description'] or "") + f" [AI Confirmed: {ai_result.get('reason')}]"
                
                if conn: conn.close()

        except Exception as e:
            print(f"[AI] Error during verification: {e}")

    # 按严重程度排序：high > medium > low
    sev_map = {"high": 0, "medium": 1, "low": 2}
    items_js.sort(key=lambda x: sev_map.get(x["severity"], 3))

    html_template = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ChkApi 敏感信息检测增强报告</title>
    <style>
        :root {
            /* 滚动条颜色变量 */
            --scrollbar-track: #f8fafc;
            --scrollbar-thumb: #cbd5e1;
            --scrollbar-thumb-hover: #94a3b8;

            /* 主色调 - 降低饱和度,增加专业感 */
            --primary: #1e40af;
            --primary-hover: #1e3a8a;
            --primary-light: #dbeafe;
            --primary-lighter: #eff6ff;

            /* 危险等级 - 更柔和的警告色 */
            --danger: #b91c1c;
            --danger-bg: #fef2f2;
            --danger-light: #fee2e2;
            --warning: #b45309;
            --warning-bg: #fffbeb;
            --warning-light: #fef3c7;
            --success: #047857;
            --success-bg: #ecfdf5;
            --success-light: #dcfce7;

            /* 中性色系 - 更有层次 */
            --gray-50: #f8fafc;
            --gray-100: #f1f5f9;
            --gray-200: #e2e8f0;
            --gray-300: #cbd5e1;
            --gray-400: #94a3b8;
            --gray-500: #64748b;
            --gray-600: #475569;
            --gray-700: #334155;
            --gray-800: #1e293b;
            --gray-900: #0f172a;

            /* 文本颜色 */
            --text-primary: #1e293b;
            --text-secondary: #64748b;
            --text-muted: #94a3b8;

            /* 背景和边框 */
            --bg-body: #f8fafc;
            --bg-card: #ffffff;
            --border: #cbd5e1;
            --border-light: #e2e8f0;

            /* 模式切换 */
            --transition-speed: 0.3s;
        }

        /* 深色模式 */
        [data-theme="dark"] {
            --scrollbar-track: #0f172a;
            --scrollbar-thumb: #334155;
            --scrollbar-thumb-hover: #475569;

            --primary: #60a5fa;
            --primary-hover: #3b82f6;
            --primary-light: #1e3a8a;
            --primary-lighter: #1e40af;

            --danger: #f87171;
            --danger-bg: #7f1d1d;
            --danger-light: #991b1b;
            --warning: #fbbf24;
            --warning-bg: #78350f;
            --warning-light: #92400e;
            --success: #34d399;
            --success-bg: #064e3b;
            --success-light: #065f46;

            --text-primary: #f1f5f9;
            --text-secondary: #cbd5e1;
            --text-muted: #94a3b8;

            --bg-body: #0f172a;
            --bg-card: #1e293b;
            --border: #334155;
            --border-light: #334155;
        }
        
        * { box-sizing: border-box; margin: 0; padding: 0; }
        
        ::-webkit-scrollbar { width: 8px; height: 8px; }
        ::-webkit-scrollbar-track { background: var(--scrollbar-track); }
        ::-webkit-scrollbar-thumb { background: var(--scrollbar-thumb); border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: var(--scrollbar-thumb-hover); }

        body {
            font-family:
                -apple-system,
                BlinkMacSystemFont,
                "Segoe UI",
                "PingFang SC",
                "Hiragino Sans GB",
                "Microsoft YaHei",
                -apple-system,
                sans-serif;
            background: var(--bg-body);
            color: var(--text-primary);
            line-height: 1.6;
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
            transition: background-color var(--transition-speed), color var(--transition-speed);
        }
        
        .layout { display: flex; min-height: 100vh; }
        
        /* 侧边栏 */
        .sidebar {
            width: 280px;
            background: linear-gradient(180deg, var(--bg-card) 0%, var(--bg-body) 100%);
            border-right: 1px solid var(--border-light);
            padding: 1.5rem;
            position: sticky;
            top: 0;
            height: 100vh;
            overflow-y: auto;
            transition: background-color var(--transition-speed), border-color var(--transition-speed);
        }
        .sidebar-title {
            font-size: 1.125rem;
            font-weight: 700;
            margin-bottom: 1.75rem;
            color: var(--primary);
            display: flex;
            align-items: center;
            gap: 0.625rem;
            letter-spacing: -0.02em;
        }
        .sidebar-title::before {
            content: '';
            display: inline-block;
            width: 20px;
            height: 20px;
            background: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%231e40af'%3E%3Cpath d='M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z'/%3E%3C/svg%3E") no-repeat center;
            flex-shrink: 0;
        }
        .sidebar-section { margin-bottom: 1.75rem; }
        .sidebar-section-title {
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            color: var(--text-muted);
            letter-spacing: 0.08em;
            margin-bottom: 0.75rem;
        }
        .nav-list { list-style: none; }
        .nav-item { margin-bottom: 0.375rem; }
        .nav-link {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.5rem 0.75rem;
            color: var(--text-secondary);
            text-decoration: none;
            border-radius: 6px;
            transition: all 0.15s cubic-bezier(0.4, 0, 0.2, 1);
            font-size: 0.875rem;
        }
        .nav-link:hover {
            background: var(--gray-100);
            color: var(--primary);
        }
        .nav-link.active {
            background: var(--primary-lighter);
            color: var(--primary);
            font-weight: 600;
        }
        .count-badge {
            background: var(--gray-200);
            color: var(--text-secondary);
            padding: 0.125rem 0.5rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 500;
        }
        
        /* 主内容区 */
        .main {
            flex: 1;
            padding: 2rem;
            max-width: 1200px;
            margin: 0 auto;
        }
        .header {
            background: linear-gradient(90deg,
                rgba(30, 64, 175, 0.03) 0%,
                rgba(30, 64, 175, 0) 100%
            );
            padding: 1.5rem 2rem;
            margin: -2rem -2rem 2rem -2rem;
            border-bottom: 1px solid var(--border-light);
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
        }
        .title-area h1 {
            font-size: 1.75rem;
            font-weight: 700;
            letter-spacing: -0.02em;
            color: var(--text-primary);
        }
        .title-area p {
            color: var(--text-secondary);
            margin-top: 0.375rem;
            font-size: 0.875rem;
        }
        
        /* 统计卡片 */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1.25rem;
            margin-bottom: 2rem;
        }
        .stat-card {
            background: var(--bg-card);
            padding: 1.25rem 1.5rem;
            border-radius: 8px;
            border: 1px solid var(--border-light);
            box-shadow:
                0 1px 2px 0 rgba(0, 0, 0, 0.05),
                0 1px 3px 1px rgba(0, 0, 0, 0.05);
            transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1), background-color var(--transition-speed);
        }
        .stat-card:hover {
            transform: translateY(-2px);
            box-shadow:
                0 4px 6px -1px rgba(0, 0, 0, 0.08),
                0 2px 4px -1px rgba(0, 0, 0, 0.04);
        }
        .stat-label {
            font-size: 0.8125rem;
            color: var(--text-secondary);
            font-weight: 500;
            letter-spacing: 0.02em;
        }
        .stat-value {
            font-size: 2rem;
            font-weight: 700;
            margin-top: 0.5rem;
            color: var(--text-primary);
            letter-spacing: -0.02em;
        }
        .stat-border-high {
            border-left: 3px solid var(--danger);
        }
        .stat-border-medium {
            border-left: 3px solid var(--warning);
        }
        .stat-border-low {
            border-left: 3px solid var(--success);
        }
        
        /* 搜索与工具栏 */
        .toolbar {
            display: flex;
            gap: 0.75rem;
            margin-bottom: 1.5rem;
        }
        .search-box { flex: 1; position: relative; }
        .search-input {
            width: 100%;
            padding: 0.625rem 0.875rem;
            border: 1px solid var(--border-light);
            border-radius: 6px;
            font-size: 0.875rem;
            background: var(--bg-card);
            color: var(--text-primary);
            transition: all 0.15s ease;
        }
        .search-input:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(30, 64, 175, 0.1);
        }
        .search-input::placeholder {
            color: var(--text-muted);
        }
        .btn {
            padding: 0.625rem 1.25rem;
            border-radius: 6px;
            font-size: 0.875rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.15s cubic-bezier(0.4, 0, 0.2, 1);
            border: 1px solid var(--border-light);
            background: var(--bg-card);
            color: var(--text-primary);
        }
        .btn:hover {
            background: var(--gray-50);
            border-color: var(--gray-300);
        }
        .btn-primary {
            background: var(--primary);
            color: #ffffff;
            border-color: var(--primary);
        }
        .btn-primary:hover {
            background: var(--primary-hover);
            border-color: var(--primary-hover);
            transform: translateY(-1px);
            box-shadow: 0 4px 6px -1px rgba(30, 64, 175, 0.2);
        }
        
        /* 结果列表 */
        .result-card {
            background: var(--bg-card);
            border: 1px solid var(--border-light);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.25rem;
            transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1), background-color var(--transition-speed), border-color var(--transition-speed);
            position: relative;
            overflow: hidden;
            box-shadow:
                0 1px 2px 0 rgba(0, 0, 0, 0.05),
                0 1px 3px 1px rgba(0, 0, 0, 0.05);
        }
        .result-card:hover {
            transform: translateY(-2px);
            box-shadow:
                0 10px 15px -3px rgba(0, 0, 0, 0.08),
                0 4px 6px -2px rgba(0, 0, 0, 0.04);
        }

        .badge {
            display: inline-flex;
            align-items: center;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.6875rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        .badge-high {
            background: var(--danger-bg);
            color: var(--danger);
            border: 1px solid var(--danger-light);
        }
        .badge-medium {
            background: var(--warning-bg);
            color: var(--warning);
            border: 1px solid var(--warning-light);
        }
        .badge-low {
            background: var(--success-bg);
            color: var(--success);
            border: 1px solid var(--success-light);
        }
        
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
            padding-bottom: 0.75rem;
            border-bottom: 1px solid var(--border-light);
            transition: border-color var(--transition-speed);
        }
        .rule-id {
            font-size: 1rem;
            font-weight: 700;
            color: var(--text-primary);
            letter-spacing: -0.01em;
        }

        .info-row {
            display: grid;
            grid-template-columns: 90px 1fr;
            gap: 0.75rem;
            margin-bottom: 0.625rem;
            font-size: 0.875rem;
        }
        .info-label {
            color: var(--text-secondary);
            font-weight: 600;
            font-size: 0.8125rem;
        }
        .info-value {
            color: var(--text-primary);
            word-break: break-all;
        }
        .info-value a {
            color: var(--primary);
            text-decoration: none;
            font-weight: 500;
        }
        .info-value a:hover {
            text-decoration: underline;
        }

        .evidence-box {
            margin-top: 1rem;
            background: var(--gray-900);
            color: #e2e8f0;
            padding: 1rem;
            border-radius: 6px;
            font-family:
                "SFMono-Regular",
                Consolas,
                "Liberation Mono",
                Menlo,
                monospace;
            font-size: 0.8125rem;
            overflow-x: auto;
            position: relative;
            line-height: 1.6;
            border: 1px solid var(--gray-700);
        }
        .evidence-title {
            position: absolute;
            top: 0.5rem;
            right: 0.75rem;
            font-size: 0.6875rem;
            text-transform: uppercase;
            color: var(--text-muted);
            font-family: sans-serif;
            letter-spacing: 0.05em;
            font-weight: 600;
        }
        .match-highlight {
            color: #fbbf24;
            font-weight: 700;
            background: rgba(251, 191, 36, 0.15);
            padding: 0 2px;
            border-radius: 2px;
        }
        
        /* 模态框 */
        .modal-overlay {
            position: fixed;
            inset: 0;
            background: rgba(0, 0, 0, 0.6);
            backdrop-filter: blur(4px);
            display: none;
            align-items: center;
            justify-content: center;
            z-index: 100;
            padding: 1rem;
        }
        .modal {
            background: var(--bg-card);
            border-radius: 12px;
            max-width: 900px;
            width: 100%;
            max-height: 90vh;
            overflow-y: auto;
            padding: 2rem;
            position: relative;
            box-shadow:
                0 20px 25px -5px rgba(0, 0, 0, 0.15),
                0 10px 10px -5px rgba(0, 0, 0, 0.08);
            transition: background-color var(--transition-speed);
        }
        .modal-close {
            position: absolute;
            top: 1rem;
            right: 1rem;
            font-size: 1.5rem;
            cursor: pointer;
            color: var(--text-muted);
            transition: color 0.15s ease, background-color var(--transition-speed);
            width: 32px;
            height: 32px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 6px;
        }
        .modal-close:hover {
            color: var(--text-primary);
            background: var(--gray-100);
        }
        
        /* 视图切换 */
        .view-table {
            display: none;
            width: 100%;
            border-collapse: collapse;
            background: var(--bg-card);
            border: 1px solid var(--border-light);
            border-radius: 8px;
            overflow: hidden;
            transition: background-color var(--transition-speed), border-color var(--transition-speed);
        }
        .view-table th {
            background: var(--gray-50);
            padding: 0.875rem 1rem;
            text-align: left;
            font-size: 0.8125rem;
            font-weight: 600;
            color: var(--text-secondary);
            border-bottom: 1px solid var(--border-light);
            letter-spacing: 0.02em;
            text-transform: uppercase;
            transition: background-color var(--transition-speed), border-color var(--transition-speed);
        }
        .view-table td {
            padding: 1rem;
            font-size: 0.875rem;
            border-bottom: 1px solid var(--border-light);
            color: var(--text-primary);
            transition: border-color var(--transition-speed);
        }
        .view-table tr:last-child td { border-bottom: none; }
        .view-table tr:hover { background: var(--gray-50); }

        [data-view="table"] .result-card { display: none; }
        [data-view="table"] .view-table { display: table; }
        
        @media (max-width: 768px) {
            .sidebar { display: none; }
            .header {
                flex-direction: column;
                gap: 1rem;
                margin: -2rem -2rem 1.5rem -2rem;
                padding: 1.25rem 1.5rem;
            }
            .toolbar { flex-wrap: wrap; }
            .stats-grid {
                grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
                gap: 1rem;
            }
        }

        /* 主题切换按钮样式 */
        .theme-toggle {
            display: flex;
            align-items: center;
            justify-content: center;
            width: 100%;
            padding: 0.625rem 0.75rem;
            margin-bottom: 1.5rem;
            background: var(--gray-100);
            border: 1px solid var(--border-light);
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.15s ease;
            gap: 0.5rem;
            font-size: 0.875rem;
            font-weight: 500;
            color: var(--text-secondary);
        }
        .theme-toggle:hover {
            background: var(--gray-200);
            color: var(--text-primary);
        }
        .theme-toggle svg {
            width: 18px;
            height: 18px;
            transition: transform 0.3s ease;
        }
        .theme-toggle:hover svg {
            transform: rotate(180deg);
        }
        [data-theme="dark"] .theme-toggle .sun-icon { display: block; }
        [data-theme="dark"] .theme-toggle .moon-icon { display: none; }
        :not([data-theme="dark"]) .theme-toggle .sun-icon { display: none; }
        :not([data-theme="dark"]) .theme-toggle .moon-icon { display: block; }
    </style>
</head>
<body>
    <div class="layout">
        <aside class="sidebar">
            <div class="sidebar-title">
                ChkApi 扫描报告
            </div>

            <button class="theme-toggle" onclick="toggleTheme()" aria-label="切换主题">
                <svg class="moon-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>
                </svg>
                <svg class="sun-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <circle cx="12" cy="12" r="5"></circle>
                    <line x1="12" y1="1" x2="12" y2="3"></line>
                    <line x1="12" y1="21" x2="12" y2="23"></line>
                    <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line>
                    <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line>
                    <line x1="1" y1="12" x2="3" y2="12"></line>
                    <line x1="21" y1="12" x2="23" y2="12"></line>
                    <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line>
                    <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line>
                </svg>
                <span>切换主题</span>
            </button>

            <div class="sidebar-section">
                <div class="sidebar-section-title">视图切换</div>
                <div class="nav-list">
                    <div class="nav-item">
                        <a href="#" class="nav-link active" onclick="switchView('card')">
                            <span>卡片模式</span>
                        </a>
                    </div>
                    <div class="nav-item">
                        <a href="#" class="nav-link" onclick="switchView('table')">
                            <span>表格模式</span>
                        </a>
                    </div>
                </div>
            </div>

            <div class="sidebar-section">
                <div class="sidebar-section-title">风险等级</div>
                <div class="nav-list">
                    <div class="nav-item">
                        <a href="#" class="nav-link" onclick="filterBySeverity('high')">
                            <span>高危风险</span>
                            <span class="count-badge" id="sidebar-count-high">0</span>
                        </a>
                    </div>
                    <div class="nav-item">
                        <a href="#" class="nav-link" onclick="filterBySeverity('medium')">
                            <span>中危风险</span>
                            <span class="count-badge" id="sidebar-count-medium">0</span>
                        </a>
                    </div>
                    <div class="nav-item">
                        <a href="#" class="nav-link" onclick="filterBySeverity('low')">
                            <span>低危风险</span>
                            <span class="count-badge" id="sidebar-count-low">0</span>
                        </a>
                    </div>
                </div>
            </div>

            <div class="sidebar-section">
                <div class="sidebar-section-title">报告导出</div>
                <div class="nav-list">
                    <div class="nav-item">
                        <a href="#" class="nav-link" onclick="exportData('json')">
                            <span>导出 JSON</span>
                        </a>
                    </div>
                    <div class="nav-item">
                        <a href="#" class="nav-link" onclick="exportData('csv')">
                            <span>导出 CSV</span>
                        </a>
                    </div>
                </div>
            </div>
        </aside>

        <main class="main">
            <header class="header">
                <div class="title-area">
                    <h1>敏感信息检测报告</h1>
                    <p id="scan-meta">检测模式: 基于正则规则集 | 生成时间: --</p>
                </div>
                <div style="display: inline-flex; align-items: center; padding: 0.5rem 1rem; background: var(--primary-lighter); color: var(--primary); border-radius: 6px; font-size: 0.8125rem; font-weight: 600; letter-spacing: 0.02em;">
                    v2.0 增强型
                </div>
            </header>

            <section class="stats-grid">
                <div class="stat-card">
                    <div class="stat-label">总发现数量</div>
                    <div class="stat-value" id="stats-total">0</div>
                </div>
                <div class="stat-card stat-border-high">
                    <div class="stat-label">高危</div>
                    <div class="stat-value" id="stats-high">0</div>
                </div>
                <div class="stat-card stat-border-medium">
                    <div class="stat-label">中危</div>
                    <div class="stat-value" id="stats-medium">0</div>
                </div>
                <div class="stat-card stat-border-low">
                    <div class="stat-label">低危</div>
                    <div class="stat-value" id="stats-low">0</div>
                </div>
            </section>

            <div class="toolbar">
                <div class="search-box">
                    <input type="text" class="search-input" id="search-input" placeholder="搜索 URL、规则名称或匹配内容..." oninput="handleFilter()">
                </div>
                <select id="rule-filter" class="search-input" style="width: 220px; display: block; flex-shrink: 0; cursor: pointer;" onchange="handleFilter()">
                    <option value="">所有规则插件</option>
                </select>
                <button class="btn btn-primary" style="flex-shrink: 0;" onclick="resetFilters()">重置筛选</button>
            </div>

            <div id="results-container">
                <!-- 结果将由 JS 渲染 -->
                <table class="view-table" id="view-table">
                    <thead>
                        <tr>
                            <th>严重程度</th>
                            <th>规则名称</th>
                            <th>匹配内容</th>
                            <th>来源文件/URL</th>
                            <th style="width: 100px;">操作</th>
                        </tr>
                    </thead>
                    <tbody id="table-body"></tbody>
                </table>
                <div id="card-container"></div>
            </div>
        </main>
    </div>

    <div class="modal-overlay" id="modal-overlay" onclick="closeModal(event)">
        <div class="modal">
            <span class="modal-close" onclick="closeModal(null)">&times;</span>
            <h2 id="modal-title" style="margin-bottom: 1.5rem;">详情预览</h2>
            <div id="modal-content"></div>
        </div>
    </div>

    <script>
        // 主题切换功能
        function toggleTheme() {
            const html = document.documentElement;
            const currentTheme = html.getAttribute('data-theme');
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';

            html.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);
        }

        // 初始化主题
        function initTheme() {
            const savedTheme = localStorage.getItem('theme');
            const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
            const initialTheme = savedTheme || (prefersDark ? 'dark' : 'light');

            document.documentElement.setAttribute('data-theme', initialTheme);
        }

        const data = {{DATA_JSON}};
        let filteredData = [...data];
        
        function init() {
            // 初始化主题
            initTheme();

            document.getElementById('scan-meta').textContent = `检测模式: 多层级风险评估组件 | 生成时间: ${new Date().toLocaleString('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' })}`;

            // 填充规则筛选下拉框
            const rules = [...new Set(data.map(item => item.rule_id))].sort();
            const filter = document.getElementById('rule-filter');
            rules.forEach(r => {
                const opt = document.createElement('option');
                opt.value = r;
                opt.textContent = r;
                filter.appendChild(opt);
            });

            updateCounts();
            render();
        }

        function updateCounts() {
            const counts = { high: 0, medium: 0, low: 0 };
            data.forEach(item => counts[item.severity]++);
            
            document.getElementById('stats-total').textContent = data.length;
            document.getElementById('stats-high').textContent = counts.high;
            document.getElementById('stats-medium').textContent = counts.medium;
            document.getElementById('stats-low').textContent = counts.low;
            
            document.getElementById('sidebar-count-high').textContent = counts.high;
            document.getElementById('sidebar-count-medium').textContent = counts.medium;
            document.getElementById('sidebar-count-low').textContent = counts.low;
        }

        function render() {
            const cardContainer = document.getElementById('card-container');
            const tableBody = document.getElementById('table-body');
            
            cardContainer.innerHTML = '';
            tableBody.innerHTML = '';

            if (filteredData.length === 0) {
                cardContainer.innerHTML = '<div style="text-align:center; padding: 3rem; color: #6b7280;">未找到匹配记录</div>';
                return;
            }

            filteredData.forEach((item, index) => {
                // 渲染卡片
                const card = document.createElement('div');
                card.className = 'result-card';
                card.innerHTML = `
                    <div class="card-header">
                        <span class="rule-id">${item.rule_id}</span>
                        <span class="badge badge-${item.severity}">${item.severity}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">匹配内容</span>
                        <span class="info-value"><code style="background:#f1f5f9;padding:2px 4px;border-radius:4px">${escapeHtml(item.match)}</code></span>
                    </div>
                    ${item.category ? `
                    <div class="info-row">
                        <span class="info-label">所属类别</span>
                        <span class="info-value">${item.category}</span>
                    </div>` : ''}
                    <div class="info-row">
                        <span class="info-label">来源 URL</span>
                        <span class="info-value"><a href="${item.url}" target="_blank">${item.url}</a></span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">本地路径</span>
                        <span class="info-value" title="${item.file}">${item.file}</span>
                    </div>
                    ${item.context ? `
                    <div class="evidence-box">
                        <div class="evidence-title">${item.line ? `上下文证据 (行: ${item.line}，附近300字符)` : `上下文证据 (附近300字符)`}</div>
                        ${highlightMatch(item.context, item.match)}
                    </div>` : ''}
                    <div style="margin-top: 1rem; display: flex; justify-content: flex-end;">
                        <button class="btn" onclick="showDetail(${index})">查看完整路径</button>
                    </div>
                `;
                cardContainer.appendChild(card);

                // 渲染表格行
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td><span class="badge badge-${item.severity}">${item.severity}</span></td>
                    <td style="font-weight:600">${item.rule_id}</td>
                    <td><code style="background:#f1f5f9;padding:2px 4px">${truncate(item.match, 30)}</code></td>
                    <td title="${item.url}">${truncate(item.url, 40)}</td>
                    <td><button class="btn btn-sm" onclick="showDetail(${index})">详情</button></td>
                `;
                tableBody.appendChild(tr);
            });
        }

        let currentSeverity = null;

        function handleFilter() {
            const q = document.getElementById('search-input').value.toLowerCase();
            const ruleF = document.getElementById('rule-filter').value;
            
            filteredData = data.filter(item => {
                const matchSearch = !q || (
                    item.rule_id.toLowerCase().includes(q) || 
                    item.match.toLowerCase().includes(q) || 
                    item.url.toLowerCase().includes(q) ||
                    item.file.toLowerCase().includes(q)
                );
                const matchRule = !ruleF || item.rule_id === ruleF;
                const matchSev = !currentSeverity || item.severity === currentSeverity;
                
                return matchSearch && matchRule && matchSev;
            });
            render();
        }

        function filterBySeverity(sev) {
            currentSeverity = (currentSeverity === sev) ? null : sev;
            // 更新 UI 状态
            document.querySelectorAll('.nav-link').forEach(link => {
                if(link.onclick && link.onclick.toString().includes('filterBySeverity')){
                     link.classList.toggle('active', currentSeverity && link.onclick.toString().includes(`'${sev}'`));
                }
            });
            handleFilter();
        }

        function resetFilters() {
            document.getElementById('search-input').value = '';
            document.getElementById('rule-filter').value = '';
            currentSeverity = null;
            document.querySelectorAll('.nav-list .active').forEach(el => el.classList.remove('active'));
            filteredData = [...data];
            render();
        }

        function switchView(view) {
            const main = document.querySelector('main');
            if (view === 'table') {
                document.getElementById('results-container').setAttribute('data-view', 'table');
            } else {
                document.getElementById('results-container').removeAttribute('data-view');
            }
            
            // 更新导航 active 状态
            document.querySelectorAll('.nav-link').forEach(link => {
                link.classList.toggle('active', 
                    (view === 'table' && link.innerHTML.includes('表格')) || 
                    (view !== 'table' && link.innerHTML.includes('卡片'))
                );
            });
        }

        function showDetail(index) {
            const item = filteredData[index];
            const content = `
                <div style="display:flex; flex-direction:column; gap: 1rem;">
                    <div style="padding-bottom: 1rem; border-bottom: 1px solid var(--border-light);">
                        <div class="info-row" style="margin-bottom: 0.5rem;">
                            <span class="info-label">规则 ID:</span>
                            <span class="info-value" style="font-weight: 600;">${item.rule_id}</span>
                        </div>
                        <div class="info-row" style="margin-bottom: 0.5rem;">
                            <span class="info-label">严重程度:</span>
                            <span><span class="badge badge-${item.severity}">${item.severity}</span></span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">匹配内容:</span>
                            <span class="info-value" style="color:var(--danger);font-weight:700;background: var(--danger-bg); padding: 0.25rem 0.5rem; border-radius: 4px; display: inline-block;">${escapeHtml(item.match)}</span>
                        </div>
                    </div>

                    <div style="padding-bottom: 1rem; border-bottom: 1px solid var(--border-light);">
                        <div class="info-row" style="margin-bottom: 0.5rem;">
                            <span class="info-label">原始 URL:</span>
                            <span class="info-value"><a href="${item.url}" target="_blank" style="word-break: break-all;">${item.url}</a></span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">本地文件:</span>
                            <span class="info-value" style="background: var(--gray-100); padding: 0.25rem 0.5rem; border-radius: 4px; font-family: monospace; font-size: 0.8125rem;">${item.file}</span>
                        </div>
                        ${item.description ? `<div class="info-row" style="margin-top: 0.5rem;"><span class="info-label">规则描述:</span><span class="info-value">${item.description}</span></div>` : ''}
                    </div>

                    <div>
                        <h4 style="margin-bottom: 0.75rem; font-size: 0.875rem; font-weight: 600; color: var(--text-secondary);">证据链提取:</h4>
                        <div class="evidence-box" style="position: relative; white-space: pre-wrap; font-size: 0.875rem; max-height: 400px; overflow-y: auto; padding-left: 88px; padding-top: 8px;">
                            <span style="position: absolute; left: 8px; top: 8px; z-index: 2; background: var(--primary); color: #ffffff; padding: 2px 10px; border-radius: 14px; font-weight: 700; letter-spacing: 0.02em; pointer-events: none;">行号: ${item.line || 0}</span>
                            ${highlightMatch(item.context, item.match)}
                        </div>
                    </div>
                </div>
            `;
            document.getElementById('modal-content').innerHTML = content;
            document.getElementById('modal-overlay').style.display = 'flex';
        }

        function closeModal(e) {
            if (!e || e.target.id === 'modal-overlay' || e.target.className === 'modal-close') {
                document.getElementById('modal-overlay').style.display = 'none';
            }
        }

        function exportData(type) {
            if (type === 'json') {
                const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `chkapi_sensitive_results_${Date.now()}.json`;
                a.click();
            } else if (type === 'csv') {
                const headers = ['Severity', 'RuleID', 'Match', 'URL', 'File'];
                const csvRows = [headers.join(',')];
                data.forEach(item => {
                    const row = [
                        item.severity,
                        item.rule_id,
                        `"${item.match.replace(/"/g, '""')}"`,
                        `"${item.url}"`,
                        `"${item.file}"`
                    ];
                    csvRows.push(row.join(','));
                });
                const blob = new Blob([csvRows.join('\\n')], { type: 'text/csv' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `chkapi_sensitive_results_${Date.now()}.csv`;
                a.click();
            }
        }

        function highlightMatch(text, match) {
            if (!match) return escapeHtml(text);
            try {
                const escapedMatch = escapeHtml(match);
                const escapedText = escapeHtml(text);
                return escapedText.replace(new RegExp(escapedMatch, 'g'), `<span class="match-highlight">${escapedMatch}</span>`);
            } catch (e) {
                return escapeHtml(text);
            }
        }

        function escapeHtml(unsafe) {
            return unsafe
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
        }

        function truncate(str, n) {
            return (str.length > n) ? str.substr(0, n-1) + '&hellip;' : str;
        }

        init();
    </script>
</body>
</html>
    """
    
    data_json = json.dumps(items_js, ensure_ascii=False)
    html_content = html_template.replace("{{DATA_JSON}}", data_json)
    
    report_path = os.path.join(folder_path, "sensitive_info_advanced.html")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    
    # 同时也生成一个精简的文本报告
    txt_report_path = os.path.join(folder_path, "sensitive_info_summary.txt")
    with open(txt_report_path, "w", encoding="utf-8") as f:
        f.write(f"ChkApi 敏感信息检测汇总报告\\n")
        f.write(f"生成时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\\n")
        f.write(f"总计发现: {total_count} 条\\n")
        f.write(f"高危: {severity_counts['high']} | 中危: {severity_counts['medium']} | 低危: {severity_counts['low']}\\n")
        f.write("-" * 50 + "\\n\\n")
        for item in items_js:
            f.write(f"[{item['severity'].upper()}] {item['rule_id']}\\n")
            f.write(f"匹配内容: {item['match']}\\n")
            f.write(f"来源: {item['url']}\\n")
            f.write(f"文件: {item['file']}\\n")
            f.write("-" * 30 + "\\n")
            
    return report_path
