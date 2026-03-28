/**
 * ApiRed Dashboard - WebSocket Client
 * 负责 WebSocket 连接管理和消息处理
 */

class WebSocketClient {
    constructor(url) {
        this.url = url || this._getWebSocketUrl();
        this.ws = null;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 10;
        this.reconnectDelay = 1000;
        this.maxReconnectDelay = 30000;
        this.reconnectStartTime = null;
        this.maxReconnectDuration = 300000;
        this.heartbeatInterval = null;
        this.heartbeatTimeout = null;
        this.isConnected = false;
        this.isManualDisconnect = false;
        this.messageQueue = [];
        this.listeners = {};
        this._boundHandleOnline = this._handleOnline.bind(this);
        this._boundHandleOffline = this._handleOffline.bind(this);
        window.addEventListener('online', this._boundHandleOnline);
        window.addEventListener('offline', this._boundHandleOffline);
    }

    _getWebSocketUrl() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const host = window.location.host;
        return `${protocol}//${host}/ws`;
    }

    _handleOnline() {
        console.log('Network online, attempting reconnect...');
        this._emit('networkOnline', {});
        if (!this.isConnected && !this.isManualDisconnect) {
            this.reconnectAttempts = 0;
            this.reconnectStartTime = Date.now();
            this.connect();
        }
    }

    _handleOffline() {
        console.log('Network offline');
        this._emit('networkOffline', {});
        this._stopHeartbeat();
    }

    connect() {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            return;
        }

        if (!window.navigator.onLine) {
            console.warn('Browser is offline, waiting for network...');
            return;
        }

        this.isManualDisconnect = false;
        try {
            this.ws = new WebSocket(this.url);
            this._setupConnectionTimeout();
            this._setupEventHandlers();
        } catch (error) {
            console.error('WebSocket connection error:', error);
            this._scheduleReconnect();
        }
    }

    _setupConnectionTimeout() {
        this._clearConnectionTimeout();
        this.connectionTimeout = setTimeout(() => {
            if (this.ws && this.ws.readyState === WebSocket.CONNECTING) {
                console.warn('WebSocket connection timeout, closing...');
                this.ws.close();
                this._scheduleReconnect();
            }
        }, 10000);
    }

    _clearConnectionTimeout() {
        if (this.connectionTimeout) {
            clearTimeout(this.connectionTimeout);
            this.connectionTimeout = null;
        }
    }

    _setupEventHandlers() {
        this.ws.onopen = () => {
            this.isConnected = true;
            this.reconnectAttempts = 0;
            this.reconnectStartTime = null;
            this._clearConnectionTimeout();
            this._updateConnectionStatus(true);
            this._startHeartbeat();
            this._flushMessageQueue();
            this._emit('connected', {});
        };

        this.ws.onclose = (event) => {
            this.isConnected = false;
            this._clearConnectionTimeout();
            this._updateConnectionStatus(false);
            this._stopHeartbeat();
            this._emit('disconnected', { code: event.code, reason: event.reason });
            if (!this.isManualDisconnect) {
                this._scheduleReconnect();
            }
        };

        this.ws.onerror = (error) => {
            console.error('WebSocket error:', error);
            this._emit('error', { error: error });
        };

        this.ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                if (data.type === 'pong') {
                    this._handlePong();
                    return;
                }
                this._handleMessage(data);
            } catch (error) {
                console.error('Failed to parse message:', error);
            }
        };
    }

    _handlePong() {
        if (this.heartbeatTimeout) {
            clearTimeout(this.heartbeatTimeout);
            this.heartbeatTimeout = null;
        }
    }

    _handleMessage(data) {
        const type = data.type || data.event;
        this._emit(type, data);

        switch (type) {
            case 'task_update':
                this._handleTaskUpdate(data);
                break;
            case 'task_started':
                this._handleTaskStarted(data);
                break;
            case 'task_completed':
                this._handleTaskCompleted(data);
                break;
            case 'task_failed':
                this._handleTaskFailed(data);
                break;
            case 'progress':
                this._handleProgress(data);
                break;
            case 'pong':
                this._handlePong();
                break;
            case 'finding':
                this._handleFinding(data);
                break;
            case 'log':
                this._handleLog(data);
                break;
            case 'stage_start':
                this._handleStageStart(data);
                break;
            case 'stage_complete':
                this._handleStageComplete(data);
                break;
            case 'error':
                this._handleError(data);
                break;
            case 'connected':
                break;
        }
    }

    _handleTaskUpdate(data) {
        const taskId = data.task_id;
        const taskData = data.data || data;
        window.dashboardApp.updateTask(taskId, taskData);
        this._emit('taskUpdate', { taskId, data: taskData });
    }

    _handleTaskStarted(data) {
        window.dashboardApp.addTask({
            task_id: data.task_id,
            target: data.data?.target || data.target,
            status: 'running',
            scan_mode: data.data?.scan_mode || 'rule',
            progress: 0
        });
        this._emit('taskStarted', data);
    }

    _handleTaskCompleted(data) {
        window.dashboardApp.updateTask(data.task_id, {
            status: 'completed',
            progress: 100
        });
        this._emit('taskCompleted', data);
    }

    _handleTaskFailed(data) {
        window.dashboardApp.updateTask(data.task_id, {
            status: 'failed',
            error: data.data?.error || data.error
        });
        this._emit('taskFailed', data);
    }

    _handleProgress(data) {
        const taskId = data.task_id;
        const progressData = data.data || data;
        window.dashboardApp.updateTaskProgress(taskId, progressData);
        this._emit('progress', { taskId, data: progressData });
    }

    _handlePong(data) {
        this._clearHeartbeatTimeout();
        this._emit('pong', data);
    }

    _handleFinding(data) {
        const taskId = data.task_id;
        const findingData = data.data || data;
        window.dashboardApp.addFinding(taskId, findingData);
        this._emit('finding', { taskId, data: findingData });
    }

    _handleLog(data) {
        const taskId = data.task_id;
        const level = data.data?.level || data.level || 'info';
        const message = data.data?.message || data.message || '';
        window.dashboardApp.appendLog(taskId, level, message);
        this._emit('log', { taskId, level, message });
    }

    _handleStageStart(data) {
        const taskId = data.task_id;
        const stage = data.data?.stage || data.stage || '';
        window.dashboardApp.updateTaskStage(taskId, stage, 'running');
        this._emit('stageStart', { taskId, stage });
    }

    _handleStageComplete(data) {
        const taskId = data.task_id;
        const stage = data.data?.stage || data.stage || '';
        window.dashboardApp.updateTaskStage(taskId, stage, 'complete');
        this._emit('stageComplete', { taskId, stage });
    }

    _handleError(data) {
        const taskId = data.task_id;
        const error = data.data?.error || data.error || 'Unknown error';
        window.dashboardApp.showToast(`Error: ${error}`, 'error');
        this._emit('error', { taskId, error });
    }

    _scheduleReconnect() {
        if (this.isManualDisconnect) {
            return;
        }

        if (this.reconnectStartTime && (Date.now() - this.reconnectStartTime) > this.maxReconnectDuration) {
            console.error('Max reconnection duration reached (5 minutes)');
            this._emit('reconnectFailed', { 
                attempts: this.reconnectAttempts, 
                reason: 'max_duration',
                message: 'Connection could not be established within 5 minutes. Please refresh the page or check the server status.'
            });
            this._showReconnectFailedNotification();
            return;
        }

        if (this.reconnectAttempts >= this.maxReconnectAttempts) {
            console.error('Max reconnection attempts reached');
            this._emit('reconnectFailed', { 
                attempts: this.reconnectAttempts,
                reason: 'max_attempts',
                message: 'Unable to connect after multiple attempts. Please refresh the page or check the server status.'
            });
            this._showReconnectFailedNotification();
            return;
        }

        if (!window.navigator.onLine) {
            console.warn('Browser is offline, waiting for network...');
            return;
        }

        this.reconnectAttempts++;
        const delay = Math.min(this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1), this.maxReconnectDelay);

        console.log(`Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts})`);
        
        setTimeout(() => {
            if (!this.isManualDisconnect && window.navigator.onLine) {
                this.connect();
            }
        }, delay);
    }

    _showReconnectFailedNotification() {
        const notification = document.createElement('div');
        notification.className = 'reconnect-failed-notification';
        notification.innerHTML = `
            <div class="notification-content">
                <span class="notification-icon">⚠️</span>
                <span class="notification-message">Connection lost. Please refresh the page to reconnect.</span>
                <button class="notification-btn" onclick="location.reload()">Refresh</button>
                <button class="notification-btn-close" onclick="this.parentElement.remove()">×</button>
            </div>
        `;
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 10000;
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a5a 100%);
            color: white;
            padding: 16px 20px;
            border-radius: 8px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            animation: slideIn 0.3s ease-out;
        `;
        document.body.appendChild(notification);
        
        setTimeout(() => {
            if (notification.parentElement) {
                notification.remove();
            }
        }, 10000);
    }

    _startHeartbeat() {
        this.heartbeatInterval = setInterval(() => {
            if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                this.ws.send(JSON.stringify({ type: 'ping' }));
            }
        }, 30000);
    }

    _stopHeartbeat() {
        if (this.heartbeatInterval) {
            clearInterval(this.heartbeatInterval);
            this.heartbeatInterval = null;
        }
    }

    _flushMessageQueue() {
        while (this.messageQueue.length > 0) {
            const msg = this.messageQueue.shift();
            this.send(msg);
        }
    }

    _updateConnectionStatus(connected) {
        const statusDot = document.querySelector('.status-dot');
        if (statusDot) {
            statusDot.classList.toggle('connected', connected);
        }
    }

    send(message) {
        if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
            this.messageQueue.push(message);
            return false;
        }

        try {
            this.ws.send(JSON.stringify(message));
            return true;
        } catch (error) {
            console.error('Failed to send message:', error);
            this.messageQueue.push(message);
            return false;
        }
    }

    startScan(target, config = {}, scanMode = 'rule') {
        return this.send({
            type: 'start_scan',
            target: target,
            config: config,
            scan_mode: scanMode
        });
    }

    stopScan(taskId) {
        return this.send({
            type: 'stop_scan',
            task_id: taskId
        });
    }

    resumeScan(taskId) {
        return this.send({
            type: 'resume_scan',
            task_id: taskId
        });
    }

    deleteTask(taskId) {
        return this.send({
            type: 'delete_task',
            task_id: taskId
        });
    }

    on(event, callback) {
        if (!this.listeners[event]) {
            this.listeners[event] = [];
        }
        this.listeners[event].push(callback);
    }

    off(event, callback) {
        if (!this.listeners[event]) return;
        this.listeners[event] = this.listeners[event].filter(cb => cb !== callback);
    }

    _emit(event, data) {
        if (!this.listeners[event]) return;
        this.listeners[event].forEach(callback => {
            try {
                callback(data);
            } catch (error) {
                console.error(`Error in ${event} listener:`, error);
            }
        });
    }

    disconnect() {
        this.isManualDisconnect = true;
        this._stopHeartbeat();
        this._clearConnectionTimeout();
        if (this.ws) {
            this.ws.close();
            this.ws = null;
        }
    }

    forceReconnect() {
        this.reconnectAttempts = 0;
        this.reconnectStartTime = Date.now();
        this.disconnect();
        setTimeout(() => {
            this.isManualDisconnect = false;
            this.connect();
        }, 100);
    }

    destroy() {
        this.disconnect();
        window.removeEventListener('online', this._boundHandleOnline);
        window.removeEventListener('offline', this._boundHandleOffline);
        this.messageQueue = [];
        this.listeners = {};
    }
}

window.WebSocketClient = WebSocketClient;
