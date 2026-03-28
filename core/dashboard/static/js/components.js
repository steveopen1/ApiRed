/**
 * ApiRed Dashboard - UI Components
 */

const Components = {
    /**
     * 创建统计卡片
     */
    statCard(value, label) {
        const card = document.createElement('div');
        card.className = 'stat-card';
        card.innerHTML = `
            <div class="stat-value">${value}</div>
            <div class="stat-label">${label}</div>
        `;
        return card;
    },

    /**
     * 创建任务卡片
     */
    taskCard(task) {
        const card = document.createElement('div');
        card.className = 'task-card';
        card.id = `task-${task.task_id}`;
        card.dataset.taskId = task.task_id;

        const statusBadge = this.statusBadge(task.status);
        const modeBadge = `<span class="badge badge-running">${this.escapeHtml(task.scan_mode || 'rule')}</span>`;
        const stageBadge = task.current_stage 
            ? `<span class="badge badge-stage">${this.escapeHtml(task.current_stage)}</span>` 
            : '';

        card.innerHTML = `
            <div class="task-header">
                <div>
                    <div class="task-target">${this.escapeHtml(task.target)}</div>
                    <div class="task-meta">
                        <span>${this.escapeHtml(task.scan_mode || 'rule')}</span>
                        ${task.created_at ? `<span>${new Date(task.created_at).toLocaleString()}</span>` : ''}
                    </div>
                </div>
                <div class="task-badges">
                    ${modeBadge}
                    ${stageBadge}
                    ${statusBadge}
                </div>
            </div>
            <div class="progress-container">
                <div class="progress-bar">
                    <div class="progress-fill" style="width: ${task.progress || 0}%"></div>
                </div>
                <div class="progress-text">${task.progress || 0}% ${task.current_stage ? `- ${this.escapeHtml(task.current_stage)}` : ''}</div>
            </div>
            <div class="task-stats">
                <span>APIs: <strong>${task.total_apis || 0}</strong></span>
                <span>Vulns: <strong>${task.vulnerabilities || 0}</strong></span>
                ${task.high_value_apis ? `<span>High: <strong>${task.high_value_apis}</strong></span>` : ''}
            </div>
            <div class="task-actions">
                ${task.status === 'running' ? `
                    <button class="btn btn-small btn-secondary" data-action="stop" data-task-id="${this.escapeHtml(task.task_id)}">Stop</button>
                ` : ''}
                <button class="btn btn-small btn-secondary" data-action="view" data-task-id="${this.escapeHtml(task.task_id)}">View</button>
                <button class="btn btn-small btn-danger" data-action="delete" data-task-id="${this.escapeHtml(task.task_id)}">Delete</button>
            </div>
        `;

        return card;
    },

    /**
     * 创建状态徽章
     */
    statusBadge(status) {
        const statusMap = {
            'pending': { class: 'badge-pending', text: 'Pending' },
            'running': { class: 'badge-running', text: 'Running' },
            'completed': { class: 'badge-completed', text: 'Completed' },
            'failed': { class: 'badge-failed', text: 'Failed' },
            'stopped': { class: 'badge-pending', text: 'Stopped' }
        };

        const info = statusMap[status] || statusMap['pending'];
        return `<span class="badge ${info.class}">${info.text}</span>`;
    },

    /**
     * 创建漏洞等级徽章
     */
    severityBadge(severity) {
        const severityMap = {
            'critical': { class: 'badge-high', text: 'Critical' },
            'high': { class: 'badge-high', text: 'High' },
            'medium': { class: 'badge-medium', text: 'Medium' },
            'low': { class: 'badge-low', text: 'Low' }
        };

        const info = severityMap[severity?.toLowerCase()] || { class: 'badge-pending', text: severity || 'Unknown' };
        return `<span class="badge ${info.class}">${info.text}</span>`;
    },

    /**
     * 创建模式选择卡片
     */
    modeCard(mode, title, description, selected) {
        const card = document.createElement('div');
        card.className = `mode-card ${selected ? 'selected' : ''}`;
        card.dataset.mode = mode;
        card.innerHTML = `
            <div class="mode-title">${title}</div>
            <div class="mode-desc">${description}</div>
        `;
        return card;
    },

    /**
     * 创建表格行
     */
    tableRow(cells) {
        const tr = document.createElement('tr');
        cells.forEach(cell => {
            const td = document.createElement('td');
            if (typeof cell === 'object' && cell.html) {
                td.innerHTML = cell.html;
            } else {
                td.textContent = cell;
            }
            tr.appendChild(td);
        });
        return tr;
    },

    /**
     * 创建日志条目
     */
    logEntry(level, message, timestamp) {
        const entry = document.createElement('div');
        let entryClass = 'log-entry';
        if (level === 'stage_start') {
            entryClass += ' stage-start';
            level = 'info';
        } else if (level === 'stage_complete') {
            entryClass += ' stage-end';
            level = 'info';
        } else {
            entryClass += ` ${level}`;
        }
        entry.className = entryClass;

        const time = document.createElement('span');
        time.className = 'log-time';
        time.textContent = timestamp || new Date().toLocaleTimeString();

        const msg = document.createElement('span');
        msg.className = 'log-message';
        msg.textContent = message;

        entry.appendChild(time);
        entry.appendChild(msg);

        return entry;
    },

    /**
     * 创建 Toast 通知
     */
    toast(message, type = 'info') {
        const container = document.getElementById('toast-container');
        if (!container) return;

        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.textContent = message;

        container.appendChild(toast);

        setTimeout(() => {
            toast.remove();
        }, 3000);
    },

    /**
     * HTML 转义
     */
    escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    },

    /**
     * 创建空状态
     */
    emptyState(message) {
        const div = document.createElement('div');
        div.className = 'empty-state';
        div.textContent = message;
        return div;
    },

    /**
     * 创建 API 表格
     */
    apiTable(apis) {
        if (!apis || apis.length === 0) {
            return this.emptyState('No API endpoints found');
        }

        const table = document.createElement('table');
        table.className = 'results-table';
        table.innerHTML = `
            <thead>
                <tr>
                    <th>Method</th>
                    <th>Path</th>
                    <th>Status</th>
                    <th>Score</th>
                    <th>High Value</th>
                </tr>
            </thead>
            <tbody></tbody>
        `;

        const tbody = table.querySelector('tbody');
        apis.slice(0, 100).forEach(api => {
            const row = tbody.appendChild(document.createElement('tr'));
            row.innerHTML = `
                <td><span class="badge badge-running">${api.method || 'GET'}</span></td>
                <td>${this.escapeHtml(api.path || api.full_url || '')}</td>
                <td>${api.status_code || '-'}</td>
                <td>${api.score || 0}</td>
                <td>${api.is_high_value ? '<span class="badge badge-high">Yes</span>' : 'No'}</td>
            `;
        });

        return table;
    },

    /**
     * 创建漏洞表格
     */
    vulnTable(vulns) {
        if (!vulns || vulns.length === 0) {
            return this.emptyState('No vulnerabilities found');
        }

        const table = document.createElement('table');
        table.className = 'results-table';
        table.innerHTML = `
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Type</th>
                    <th>Path</th>
                    <th>Title</th>
                </tr>
            </thead>
            <tbody></tbody>
        `;

        const tbody = table.querySelector('tbody');
        vulns.slice(0, 100).forEach(vuln => {
            const row = tbody.appendChild(document.createElement('tr'));
            row.innerHTML = `
                <td>${this.severityBadge(vuln.severity)}</td>
                <td>${this.escapeHtml(vuln.vuln_type || '')}</td>
                <td>${this.escapeHtml(vuln.endpoint_id || '')}</td>
                <td>${this.escapeHtml(vuln.title || '')}</td>
            `;
        });

        return table;
    }
};

window.Components = Components;
