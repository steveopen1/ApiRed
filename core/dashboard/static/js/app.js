/**
 * ApiRed Dashboard - Main Application
 */

class DashboardApp {
    constructor() {
        this.tasks = new Map();
        this.currentPage = 'dashboard';
        this.logs = [];
        this.maxLogs = 1000;
        this.wsClient = null;
        this.selectedTaskId = null;
        this.findings = new Map();
        this.pollingIntervalId = null;
        this.resultsCache = new Map();
        this.paginationState = {
            apis: { currentPage: 1, pageSize: 50 },
            vulns: { currentPage: 1, pageSize: 50 }
        };
    }

    async init() {
        this.wsClient = new WebSocketClient();
        this.wsClient.connect();

        this.wsClient.on('connected', () => this.onConnected());
        this.wsClient.on('disconnected', () => this.onDisconnected());
        this.wsClient.on('taskUpdate', (data) => this.onTaskUpdate(data));
        this.wsClient.on('taskStarted', (data) => this.onTaskStarted(data));
        this.wsClient.on('taskCompleted', (data) => this.onTaskCompleted(data));
        this.wsClient.on('progress', (data) => this.onProgress(data));
        this.wsClient.on('finding', (data) => this.onFinding(data));
        this.wsClient.on('log', (data) => this.onLog(data));
        this.wsClient.on('error', (data) => this.onError(data));
        this.wsClient.on('reconnectFailed', (data) => this.onReconnectFailed(data));
        this.wsClient.on('networkOnline', () => this.onNetworkOnline());
        this.wsClient.on('networkOffline', () => this.onNetworkOffline());

        this.setupNavigation();
        this.setupForms();
        await this.loadInitialData();
        this.startPolling();
        
        window.addEventListener('error', (e) => this.onGlobalError(e));
        window.addEventListener('unhandledrejection', (e) => this.onUnhandledRejection(e));
    }

    onConnected() {
        this.hideReconnectingBanner();
    }

    onDisconnected() {
    }

    onNetworkOnline() {
        this.showToast('Network restored', 'info');
        this.hideReconnectingBanner();
    }

    onNetworkOffline() {
        this.showToast('Network lost. Connection will resume when network is restored.', 'warning');
    }

    onReconnectFailed(data) {
        this.showReconnectFailedBanner();
    }
    
    showReconnectFailedBanner() {
        const existing = document.getElementById('reconnect-banner');
        if (existing) return;
        
        const banner = document.createElement('div');
        banner.id = 'reconnect-banner';
        banner.className = 'reconnect-banner';
        banner.innerHTML = `
            <span class="reconnect-icon">⚠️</span>
            <span class="reconnect-text">Connection lost. Please refresh the page to reconnect.</span>
            <button class="reconnect-btn" onclick="location.reload()">Refresh</button>
        `;
        banner.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            z-index: 10000;
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a5a 100%);
            color: white;
            padding: 12px 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 12px;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            font-size: 14px;
        `;
        document.body.appendChild(banner);
    }
    
    hideReconnectingBanner() {
        const existing = document.getElementById('reconnect-banner');
        if (existing) existing.remove();
    }

    onGlobalError(e) {
        console.error('Global error:', e.error);
        if (e.error && e.error.message) {
            this.showToast(`Error: ${e.error.message}`, 'error');
        }
    }

    onUnhandledRejection(e) {
        console.error('Unhandled promise rejection:', e.reason);
    }

    onTaskUpdate(data) {
        const { taskId, data: taskData } = data;
        if (this.tasks.has(taskId)) {
            Object.assign(this.tasks.get(taskId), taskData);
            this.renderTask(taskId);
            this.updateStats();
        }
    }

    onTaskStarted(data) {
        const task = {
            task_id: data.task_id,
            target: data.data?.target || data.target,
            status: 'running',
            scan_mode: data.data?.scan_mode || 'rule',
            progress: 0,
            total_apis: 0,
            vulnerabilities: 0,
            created_at: new Date().toISOString()
        };
        this.tasks.set(task.task_id, task);
        this.renderTasks();
        this.showToast(`Scan started: ${task.target}`, 'success');
    }

    onTaskCompleted(data) {
        const taskId = data.task_id;
        if (this.tasks.has(taskId)) {
            const task = this.tasks.get(taskId);
            task.status = 'completed';
            task.progress = 100;
            this.renderTask(taskId);
            this.updateStats();
            this.showToast(`Scan completed: ${task.target}`, 'success');
        }
    }

    onProgress(data) {
        const taskId = data.taskId;
        const progressData = data.data;

        if (this.tasks.has(taskId)) {
            const task = this.tasks.get(taskId);
            task.progress = progressData.progress || task.progress;
            task.current_stage = progressData.stage || task.current_stage;
            task.total_apis = progressData.total_apis || task.total_apis;
            task.alive_apis = progressData.alive_apis || task.alive_apis;
            task.high_value_apis = progressData.high_value_apis || task.high_value_apis;
            task.vulnerabilities = progressData.vulnerabilities || task.vulnerabilities;
            task.sensitive = progressData.sensitive || task.sensitive;
            this.renderTask(taskId);
            this.updateStats();
        }
    }

    onFinding(data) {
        const taskId = data.taskId;
        const findingData = data.data;

        if (!this.findings.has(taskId)) {
            this.findings.set(taskId, []);
        }
        this.findings.get(taskId).push(findingData);
    }

    onLog(data) {
        const { taskId, level, message } = data;
        this.appendLog(taskId, level, message);
    }

    onError(data) {
        const error = data.error || 'Unknown error';
        this.showToast(`Error: ${error}`, 'error');
    }

    setupNavigation() {
        document.querySelectorAll('.nav-tab').forEach(tab => {
            tab.addEventListener('click', () => {
                const page = tab.dataset.page;
                this.switchPage(page);
            });
        });

        document.addEventListener('click', (e) => {
            const action = e.target.dataset.action;
            const taskId = e.target.dataset.taskId;
            if (!action || !taskId) return;

            if (action === 'stop') {
                this.stopTask(taskId);
            } else if (action === 'view') {
                this.viewResults(taskId);
            } else if (action === 'delete') {
                this.deleteTask(taskId);
            }
        });
    }

    switchPage(page) {
        document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));

        document.querySelector(`[data-page="${page}"]`)?.classList.add('active');
        document.getElementById(`page-${page}`)?.classList.add('active');

        this.currentPage = page;

        if (page === 'tasks') {
            this.renderTasks();
        } else if (page === 'results' && this.selectedTaskId) {
            this.renderResults(this.selectedTaskId);
        }
    }

    setupForms() {
        const scanForm = document.getElementById('scan-form');
        if (scanForm) {
            scanForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.startScan();
            });
        }

        document.querySelectorAll('.mode-card').forEach(card => {
            card.addEventListener('click', () => {
                document.querySelectorAll('.mode-card').forEach(c => c.classList.remove('selected'));
                card.classList.add('selected');
            });
        });

        const modeCards = document.querySelectorAll('.mode-card');
        if (modeCards.length > 0) {
            modeCards[0].classList.add('selected');
        }
    }

    async loadInitialData() {
        try {
            const resp = await fetch('/api/tasks');
            const data = await resp.json();
            const tasks = data.tasks || [];
            tasks.forEach(task => {
                this.tasks.set(task.task_id, task);
            });
            this.renderTasks();
            this.updateStats();
        } catch (error) {
            console.error('Failed to load tasks:', error);
        }
    }

    async startScan() {
        const target = document.getElementById('input-target')?.value?.trim();
        if (!target) {
            this.showToast('Please enter target URL', 'error');
            return;
        }

        const selectedMode = document.querySelector('.mode-card.selected');
        const scanMode = selectedMode?.dataset.mode || 'rule';

        const config = {
            cookies: document.getElementById('input-cookies')?.value?.trim() || '',
            concurrency: parseInt(document.getElementById('input-concurrency')?.value) || 50,
            js_depth: parseInt(document.getElementById('input-js-depth')?.value) || 3,
            attack_mode: document.getElementById('input-attack-mode')?.value || 'all',
            format: document.getElementById('input-format')?.value || 'json'
        };

        if (this.wsClient && this.wsClient.isConnected) {
            this.wsClient.startScan(target, config, scanMode);
            document.getElementById('input-target').value = '';
            this.switchPage('tasks');
        } else {
            try {
                const resp = await fetch('/api/tasks', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ target, config, scan_mode: scanMode })
                });
                const data = await resp.json();
                if (data.task_id) {
                    this.showToast('Scan started', 'success');
                    await this.loadInitialData();
                    this.switchPage('tasks');
                }
            } catch (error) {
                this.showToast('Failed to start scan', 'error');
            }
        }
    }

    async stopTask(taskId) {
        try {
            if (this.wsClient && this.wsClient.isConnected) {
                this.wsClient.stopScan(taskId);
            } else {
                await fetch(`/api/tasks/${taskId}/stop`, { method: 'POST' });
            }
            this.showToast('Scan stopped', 'success');
        } catch (error) {
            this.showToast('Failed to stop scan', 'error');
        }
    }

    async deleteTask(taskId) {
        try {
            if (this.wsClient && this.wsClient.isConnected) {
                this.wsClient.deleteTask(taskId);
            } else {
                await fetch(`/api/tasks/${taskId}`, { method: 'DELETE' });
            }
            this.tasks.delete(taskId);
            this.renderTasks();
            this.updateStats();
            this.showToast('Task deleted', 'success');
        } catch (error) {
            this.showToast('Failed to delete task', 'error');
        }
    }

    async viewResults(taskId) {
        this.selectedTaskId = taskId;
        this.switchPage('results');
        await this.renderResults(taskId);
    }

    async renderResults(taskId) {
        const container = document.getElementById('results-container');
        if (!container) return;

        try {
            const resp = await fetch(`/api/results/${taskId}`);
            if (!resp.ok) throw new Error('Failed to load results');

            const data = await resp.json();
            this.resultsCache.set(taskId, data);
            
            if (!this.paginationState[taskId]) {
                this.paginationState[taskId] = {
                    apis: { currentPage: 1, pageSize: 50 },
                    vulns: { currentPage: 1, pageSize: 50 }
                };
            }
            const pageState = this.paginationState[taskId];

            const apiTableContainer = document.createElement('div');
            apiTableContainer.id = `api-table-${taskId}`;
            const vulnTableContainer = document.createElement('div');
            vulnTableContainer.id = `vuln-table-${taskId}`;
            
            apiTableContainer.appendChild(Components.apiTable(
                data.api_endpoints || [],
                {
                    currentPage: pageState.apis.currentPage,
                    pageSize: pageState.apis.pageSize,
                    onPageChange: (page) => {
                        pageState.apis.currentPage = page;
                        this.renderResults(taskId);
                    }
                }
            ));
            
            vulnTableContainer.appendChild(Components.vulnTable(
                data.vulnerabilities || [],
                {
                    currentPage: pageState.vulns.currentPage,
                    pageSize: pageState.vulns.pageSize,
                    onPageChange: (page) => {
                        pageState.vulns.currentPage = page;
                        this.renderResults(taskId);
                    }
                }
            ));

            container.innerHTML = `
                <div class="card">
                    <div class="card-header">
                        <h2 class="card-title">Results: ${this.escapeHtml(data.target_url || taskId)}</h2>
                    </div>
                    <div class="stats-grid">
                        ${Components.statCard(data.total_apis || 0, 'Total APIs').outerHTML}
                        ${Components.statCard(data.alive_apis || 0, 'Alive APIs').outerHTML}
                        ${Components.statCard(data.high_value_apis || 0, 'High Value APIs').outerHTML}
                        ${Components.statCard(data.total_vulns || 0, 'Vulnerabilities').outerHTML}
                    </div>
                </div>
                <div class="card">
                    <div class="card-header">
                        <h2 class="card-title">API Endpoints (${data.api_endpoints?.length || 0})</h2>
                    </div>
                </div>
                <div class="card">
                    <div class="card-header">
                        <h2 class="card-title">Vulnerabilities (${data.vulnerabilities?.length || 0})</h2>
                    </div>
                </div>
            `;
            
            const cards = container.querySelectorAll('.card');
            cards[1].appendChild(apiTableContainer);
            cards[2].appendChild(vulnTableContainer);
            
        } catch (error) {
            console.error('Failed to render results:', error);
            container.innerHTML = Components.emptyState('Failed to load results');
        }
    }

    renderTasks() {
        const container = document.getElementById('tasks-container');
        if (!container) return;

        const tasks = Array.from(this.tasks.values());

        if (tasks.length === 0) {
            container.innerHTML = '';
            container.appendChild(Components.emptyState('No tasks yet. Start a scan to see results here.'));
            return;
        }

        container.innerHTML = '';
        tasks.sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
            .forEach(task => {
                const card = Components.taskCard(task);
                container.appendChild(card);
            });
    }

    renderTask(taskId) {
        const container = document.getElementById('tasks-container');
        if (!container) return;

        const existingCard = document.getElementById(`task-${taskId}`);
        if (existingCard) {
            const task = this.tasks.get(taskId);
            if (task) {
                const newCard = Components.taskCard(task);
                existingCard.replaceWith(newCard);
            }
        }
    }

    updateStats() {
        const tasks = Array.from(this.tasks.values());

        const totalScans = tasks.length;
        const runningTasks = tasks.filter(t => t.status === 'running').length;
        const totalApis = tasks.reduce((sum, t) => sum + (t.total_apis || 0), 0);
        const totalVulns = tasks.reduce((sum, t) => sum + (t.vulnerabilities || 0), 0);

        const statElements = {
            'stat-total-scans': totalScans,
            'stat-running': runningTasks,
            'stat-apis': totalApis,
            'stat-vulns': totalVulns
        };

        Object.entries(statElements).forEach(([id, value]) => {
            const el = document.getElementById(id);
            if (el) el.textContent = value;
        });
    }

    updateTask(taskId, data) {
        if (this.tasks.has(taskId)) {
            Object.assign(this.tasks.get(taskId), data);
            this.renderTask(taskId);
            this.updateStats();
        }
    }

    addTask(task) {
        this.tasks.set(task.task_id, task);
        this.renderTasks();
    }

    updateTaskProgress(taskId, progress) {
        if (this.tasks.has(taskId)) {
            const task = this.tasks.get(taskId);
            task.progress = progress.progress || task.progress;
            task.current_stage = progress.stage || task.current_stage;
            task.current_phase = progress.current_phase || task.current_phase;
            task.total_apis = progress.total_apis || task.total_apis;
            task.vulnerabilities = progress.vulnerabilities || task.vulnerabilities;
            this.renderTask(taskId);
            this.updateStats();
        }
    }

    updateTaskStage(taskId, stage, stageStatus) {
        if (this.tasks.has(taskId)) {
            const task = this.tasks.get(taskId);
            task.current_stage = stage;
            task.stage_status = stageStatus;
            this.renderTask(taskId);
        }
    }

    addFinding(taskId, finding) {
        if (!this.findings.has(taskId)) {
            this.findings.set(taskId, []);
        }
        this.findings.get(taskId).push(finding);
    }

    appendLog(taskId, level, message) {
        const timestamp = new Date().toLocaleTimeString();
        this.logs.push({ taskId, level, message, timestamp });

        if (this.logs.length > this.maxLogs) {
            this.logs.shift();
        }

        const logPanel = document.getElementById('log-panel');
        if (logPanel) {
            const entry = Components.logEntry(level, message, timestamp);
            logPanel.appendChild(entry);
            logPanel.scrollTop = logPanel.scrollHeight;
        }
    }

    startPolling() {
        if (this.pollingIntervalId) return;
        this.pollingIntervalId = setInterval(async () => {
            if (this.wsClient && !this.wsClient.isConnected) {
                await this.loadInitialData();
            }
        }, 30000);
    }

    cleanup() {
        if (this.pollingIntervalId) {
            clearInterval(this.pollingIntervalId);
            this.pollingIntervalId = null;
        }
        if (this.wsClient) {
            this.wsClient.disconnect();
        }
    }

    showToast(message, type = 'info') {
        Components.toast(message, type);
    }

    escapeHtml(text) {
        return Components.escapeHtml(text);
    }
}

window.dashboardApp = new DashboardApp();

document.addEventListener('DOMContentLoaded', () => {
    window.dashboardApp.init();
});

window.addEventListener('beforeunload', () => {
    window.dashboardApp.cleanup();
});
