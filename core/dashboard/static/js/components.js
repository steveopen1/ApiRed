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
        
        const safeTaskId = this.escapeHtmlAttribute(task.task_id || '');
        
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
                    <button class="btn btn-small btn-secondary" data-action="stop" data-task-id="${safeTaskId}">Stop</button>
                ` : ''}
                <button class="btn btn-small btn-secondary" data-action="view" data-task-id="${safeTaskId}">View</button>
                <button class="btn btn-small btn-danger" data-action="delete" data-task-id="${safeTaskId}">Delete</button>
            </div>
        `;

        return card;
    },
    
    escapeHtmlAttribute(str) {
        if (!str) return '';
        return str.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
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
     * 创建 API 表格（带分页）
     */
    apiTable(apis, options = {}) {
        if (!apis || apis.length === 0) {
            return this.emptyState('No API endpoints found');
        }

        const pageSize = options.pageSize || 50;
        const currentPage = options.currentPage || 1;
        const totalPages = Math.ceil(apis.length / pageSize);
        const startIdx = (currentPage - 1) * pageSize;
        const endIdx = startIdx + pageSize;
        const pageApis = apis.slice(startIdx, endIdx);

        const container = document.createElement('div');
        container.className = 'table-container';
        
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
        pageApis.forEach(api => {
            const row = tbody.appendChild(document.createElement('tr'));
            
            const methodCell = document.createElement('td');
            const methodSpan = document.createElement('span');
            methodSpan.className = 'badge badge-running';
            methodSpan.textContent = api.method || 'GET';
            methodCell.appendChild(methodSpan);
            row.appendChild(methodCell);
            
            const pathCell = document.createElement('td');
            pathCell.textContent = api.path || api.full_url || '';
            row.appendChild(pathCell);
            
            const statusCell = document.createElement('td');
            statusCell.textContent = api.status_code || '-';
            row.appendChild(statusCell);
            
            const scoreCell = document.createElement('td');
            scoreCell.textContent = api.score || 0;
            row.appendChild(scoreCell);
            
            const highValueCell = document.createElement('td');
            if (api.is_high_value) {
                const badge = document.createElement('span');
                badge.className = 'badge badge-high';
                badge.textContent = 'Yes';
                highValueCell.appendChild(badge);
            } else {
                highValueCell.textContent = 'No';
            }
            row.appendChild(highValueCell);
        });

        const pagination = this.paginationControls(currentPage, totalPages, (page) => {
            if (options.onPageChange) {
                options.onPageChange(page);
            }
        });

        container.appendChild(table);
        if (totalPages > 1) {
            container.appendChild(pagination);
        }

        return container;
    },

    /**
     * 创建漏洞表格（带分页）
     */
    vulnTable(vulns, options = {}) {
        if (!vulns || vulns.length === 0) {
            return this.emptyState('No vulnerabilities found');
        }

        const pageSize = options.pageSize || 50;
        const currentPage = options.currentPage || 1;
        const totalPages = Math.ceil(vulns.length / pageSize);
        const startIdx = (currentPage - 1) * pageSize;
        const endIdx = startIdx + pageSize;
        const pageVulns = vulns.slice(startIdx, endIdx);

        const container = document.createElement('div');
        container.className = 'table-container';

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
        pageVulns.forEach(vuln => {
            const row = tbody.appendChild(document.createElement('tr'));
            
            const severityCell = document.createElement('td');
            severityCell.innerHTML = this.severityBadge(vuln.severity);
            row.appendChild(severityCell);
            
            const typeCell = document.createElement('td');
            typeCell.textContent = vuln.vuln_type || '';
            row.appendChild(typeCell);
            
            const pathCell = document.createElement('td');
            pathCell.textContent = vuln.endpoint_id || '';
            row.appendChild(pathCell);
            
            const titleCell = document.createElement('td');
            titleCell.textContent = vuln.title || '';
            row.appendChild(titleCell);
        });

        const pagination = this.paginationControls(currentPage, totalPages, (page) => {
            if (options.onPageChange) {
                options.onPageChange(page);
            }
        });

        container.appendChild(table);
        if (totalPages > 1) {
            container.appendChild(pagination);
        }

        return container;
    },

    /**
     * 分页控件
     */
    paginationControls(currentPage, totalPages, onPageChange) {
        const container = document.createElement('div');
        container.className = 'pagination-controls';
        container.style.cssText = `
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 8px;
            padding: 12px;
            flex-wrap: wrap;
        `;

        const createButton = (page, text, disabled = false, className = '') => {
            const btn = document.createElement('button');
            btn.className = `btn btn-small ${className}`;
            btn.textContent = text;
            btn.disabled = disabled;
            btn.style.cssText = 'min-width: 32px; padding: 4px 8px;';
            btn.onclick = () => !disabled && onPageChange(page);
            return btn;
        };

        container.appendChild(createButton(1, '«', currentPage === 1));
        container.appendChild(createButton(currentPage - 1, '‹', currentPage === 1));

        const maxVisible = 5;
        let startPage = Math.max(1, currentPage - Math.floor(maxVisible / 2));
        let endPage = Math.min(totalPages, startPage + maxVisible - 1);
        if (endPage - startPage < maxVisible - 1) {
            startPage = Math.max(1, endPage - maxVisible + 1);
        }

        for (let i = startPage; i <= endPage; i++) {
            container.appendChild(createButton(i, i.toString(), false, i === currentPage ? 'btn-primary' : ''));
        }

        container.appendChild(createButton(currentPage + 1, '›', currentPage === totalPages));
        container.appendChild(createButton(totalPages, '»', currentPage === totalPages));

        const info = document.createElement('span');
        info.style.cssText = 'margin-left: 12px; color: #888; font-size: 12px;';
        info.textContent = `Page ${currentPage} of ${totalPages}`;
        container.appendChild(info);

        return container;
    }
};

window.Components = Components;
