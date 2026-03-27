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
        this.heartbeatInterval = null;
        this.isConnected = false;
        this.messageQueue = [];
        this.listeners = {};
    }

    _getWebSocketUrl() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const host = window.location.host;
        return `${protocol}//${host}/ws`;
    }

    connect() {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            return;
        }

        try {
            this.ws = new WebSocket(this.url);
            this._setupEventHandlers();
        } catch (error) {
            console.error('WebSocket connection error:', error);
            this._scheduleReconnect();
        }
    }

    _setupEventHandlers() {
        this.ws.onopen = () => {
            console.log('WebSocket connected');
            this.isConnected = true;
            this.reconnectAttempts = 0;
            this._updateConnectionStatus(true);
            this._startHeartbeat();
            this._flushMessageQueue();
            this._emit('connected', {});
        };

        this.ws.onclose = (event) => {
            console.log('WebSocket closed:', event.code, event.reason);
            this.isConnected = false;
            this._updateConnectionStatus(false);
            this._stopHeartbeat();
            this._emit('disconnected', { code: event.code, reason: event.reason });
            this._scheduleReconnect();
        };

        this.ws.onerror = (error) => {
            console.error('WebSocket error:', error);
            this._emit('error', { error: error });
        };

        this.ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                this._handleMessage(data);
            } catch (error) {
                console.error('Failed to parse message:', error);
            }
        };
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
                console.log('Received connected confirmation');
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
        window.dashboardApp.showError(error);
        this._emit('error', { taskId, error });
    }

    _scheduleReconnect() {
        if (this.reconnectAttempts >= this.maxReconnectAttempts) {
            console.error('Max reconnection attempts reached');
            return;
        }

        this.reconnectAttempts++;
        const delay = Math.min(this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1), 30000);
        console.log(`Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts})`);

        setTimeout(() => {
            this.connect();
        }, delay);
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
        this._stopHeartbeat();
        if (this.ws) {
            this.ws.close();
            this.ws = null;
        }
    }
}

window.WebSocketClient = WebSocketClient;
