"""
FastAPI Web Monitor Application
实时流量监控Web界面
"""

import asyncio
import json
from typing import Optional, List
from pathlib import Path

try:
    from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query, HTTPException
    from fastapi.responses import HTMLResponse, JSONResponse
    from fastapi.staticfiles import StaticFiles
    from starlette.websockets import WebSocketState
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False


class TrafficMonitorApp:
    """流量监控Web应用"""
    
    def __init__(self, host: str = '127.0.0.1', port: int = 8081):
        self.host = host
        self.port = port
        self.app: Optional[FastAPI] = None
        self.websockets: List[WebSocket] = []
        self.flows: List[dict] = []
        self.alerts: List[dict] = []
        self.stats = {
            'total': 0,
            'apis': 0,
            'sensitive': 0,
            'alerts': 0
        }
    
    def create_app(self) -> FastAPI:
        """创建FastAPI应用"""
        if not HAS_FASTAPI:
            raise ImportError('FastAPI is required: pip install fastapi uvicorn')
        
        app = FastAPI(title='ApiRed Traffic Monitor')
        
        @app.get('/')
        async def index():
            return HTMLResponse(self._get_html())
        
        @app.get('/api/stats')
        async def get_stats():
            return JSONResponse(self.stats)
        
        @app.get('/api/flows')
        async def get_flows(
            domain: Optional[str] = None,
            limit: int = Query(default=100, le=1000)
        ):
            flows = self.flows[-limit:] if not domain else [
                f for f in self.flows[-limit:] if f.get('domain') == domain
            ]
            return JSONResponse(flows)
        
        @app.get('/api/alerts')
        async def get_alerts(limit: int = Query(default=50, le=200)):
            return JSONResponse(self.alerts[-limit:])
        
        @app.post('/api/flows/{flow_id}/scan')
        async def scan_flow(flow_id: str):
            for flow in self.flows:
                if flow.get('id') == flow_id:
                    return JSONResponse({
                        'status': 'scanning',
                        'flow': flow
                    })
            raise HTTPException(status_code=404, detail='Flow not found')
        
        @app.websocket('/ws')
        async def websocket_endpoint(websocket: WebSocket):
            await websocket.accept()
            self.websockets.append(websocket)
            
            await websocket.send_json({
                'type': 'connected',
                'stats': self.stats
            })
            
            try:
                while True:
                    data = await websocket.receive_json()
                    msg_type = data.get('type')
                    
                    if msg_type == 'get_stats':
                        await websocket.send_json({
                            'type': 'stats',
                            'data': self.stats
                        })
                    elif msg_type == 'get_flows':
                        await websocket.send_json({
                            'type': 'flows',
                            'data': self.flows[-100:]
                        })
                    elif msg_type == 'get_alerts':
                        await websocket.send_json({
                            'type': 'alerts',
                            'data': self.alerts[-50:]
                        })
            
            except WebSocketDisconnect:
                if websocket in self.websockets:
                    self.websockets.remove(websocket)
            except Exception:
                if websocket in self.websockets:
                    self.websockets.remove(websocket)
        
        self.app = app
        return app
    
    async def broadcast(self, message: dict):
        """广播消息到所有WebSocket客户端"""
        disconnected = []
        for ws in self.websockets:
            try:
                if ws.client_state == WebSocketState.CONNECTED:
                    await ws.send_json(message)
                else:
                    disconnected.append(ws)
            except Exception:
                disconnected.append(ws)
        
        for ws in disconnected:
            if ws in self.websockets:
                self.websockets.remove(ws)
    
    def add_flow(self, flow: dict):
        """添加流量"""
        self.flows.append(flow)
        self.stats['total'] += 1
        
        if flow.get('is_api'):
            self.stats['apis'] += 1
        
        if flow.get('is_sensitive'):
            self.stats['sensitive'] += 1
        
        if len(self.flows) > 10000:
            self.flows = self.flows[-5000:]
        
        asyncio.create_task(self.broadcast({
            'type': 'flow',
            'data': flow
        }))
    
    def add_alert(self, alert: dict):
        """添加告警"""
        self.alerts.append(alert)
        self.stats['alerts'] += 1
        
        if len(self.alerts) > 1000:
            self.alerts = self.alerts[-500:]
        
        asyncio.create_task(self.broadcast({
            'type': 'alert',
            'data': alert
        }))
    
    def _get_html(self) -> str:
        """获取HTML页面"""
        return '''
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ApiRed Traffic Monitor</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0f0f23;
            color: #e0e0e0;
            min-height: 100vh;
        }
        .header {
            background: #1a1a2e;
            padding: 16px 24px;
            border-bottom: 1px solid #333;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header h1 { color: #00d4ff; font-size: 20px; }
        .stats-bar {
            display: flex;
            gap: 24px;
            padding: 16px 24px;
            background: #1a1a2e;
            border-bottom: 1px solid #333;
        }
        .stat-item {
            display: flex;
            flex-direction: column;
            align-items: center;
        }
        .stat-value {
            font-size: 24px;
            font-weight: 700;
            color: #00d4ff;
        }
        .stat-label {
            font-size: 12px;
            color: #888;
            margin-top: 4px;
        }
        .main-container {
            display: flex;
            height: calc(100vh - 140px);
        }
        .flow-list {
            flex: 1;
            overflow-y: auto;
            border-right: 1px solid #333;
        }
        .flow-item {
            padding: 12px 16px;
            border-bottom: 1px solid #252540;
            cursor: pointer;
            transition: background 0.2s;
        }
        .flow-item:hover { background: #252540; }
        .flow-item.sensitive { border-left: 3px solid #ff4757; }
        .flow-item.api { border-left: 3px solid #00ff99; }
        .flow-method {
            display: inline-block;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 10px;
            font-weight: 600;
            margin-right: 8px;
        }
        .method-get { background: #00d4ff33; color: #00d4ff; }
        .method-post { background: #00ff9933; color: #00ff99; }
        .method-put { background: #ffa50033; color: #ffa500; }
        .method-delete { background: #ff475733; color: #ff4757; }
        .flow-path {
            font-size: 12px;
            font-family: Monaco, monospace;
            color: #ccc;
        }
        .flow-status {
            font-size: 11px;
            color: #888;
            margin-top: 4px;
        }
        .detail-panel {
            width: 450px;
            padding: 16px;
            overflow-y: auto;
            display: none;
        }
        .detail-panel.show { display: block; }
        .detail-section {
            margin-bottom: 16px;
        }
        .detail-section h4 {
            font-size: 12px;
            color: #666;
            margin-bottom: 8px;
            text-transform: uppercase;
        }
        .detail-section pre {
            background: #1a1a2e;
            padding: 10px;
            border-radius: 6px;
            font-size: 11px;
            overflow-x: auto;
            max-height: 200px;
            white-space: pre-wrap;
        }
        .alert-list {
            width: 300px;
            background: #1a1a2e;
            border-left: 1px solid #333;
            overflow-y: auto;
        }
        .alert-item {
            padding: 10px 14px;
            border-bottom: 1px solid #333;
        }
        .alert-item.warning { border-left: 3px solid #ffa500; }
        .alert-item.critical { border-left: 3px solid #ff4757; }
        .alert-title {
            font-size: 12px;
            font-weight: 600;
            color: #ffa500;
        }
        .alert-message {
            font-size: 11px;
            color: #888;
            margin-top: 4px;
        }
        .empty-state {
            text-align: center;
            padding: 40px;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>ApiRed Traffic Monitor</h1>
        <div id="connectionStatus">Connected</div>
    </div>
    
    <div class="stats-bar">
        <div class="stat-item">
            <span class="stat-value" id="totalCount">0</span>
            <span class="stat-label">Total</span>
        </div>
        <div class="stat-item">
            <span class="stat-value" id="apiCount">0</span>
            <span class="stat-label">APIs</span>
        </div>
        <div class="stat-item">
            <span class="stat-value" id="sensitiveCount">0</span>
            <span class="stat-label">Sensitive</span>
        </div>
        <div class="stat-item">
            <span class="stat-value" id="alertCount">0</span>
            <span class="stat-label">Alerts</span>
        </div>
    </div>
    
    <div class="main-container">
        <div class="flow-list" id="flowList">
            <div class="empty-state">Waiting for traffic...</div>
        </div>
        
        <div class="detail-panel" id="detailPanel">
            <div id="detailContent"></div>
        </div>
        
        <div class="alert-list" id="alertList">
            <div class="empty-state">No alerts</div>
        </div>
    </div>
    
    <script>
        const ws = new WebSocket(`ws://${location.host}/ws`);
        const flows = [];
        const alerts = [];
        
        ws.onopen = () => {
            document.getElementById('connectionStatus').textContent = 'Connected';
            document.getElementById('connectionStatus').style.color = '#00ff99';
        };
        
        ws.onclose = () => {
            document.getElementById('connectionStatus').textContent = 'Disconnected';
            document.getElementById('connectionStatus').style.color = '#ff4757';
        };
        
        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            
            if (data.type === 'stats') {
                document.getElementById('totalCount').textContent = data.data.total || 0;
                document.getElementById('apiCount').textContent = data.data.apis || 0;
                document.getElementById('sensitiveCount').textContent = data.data.sensitive || 0;
                document.getElementById('alertCount').textContent = data.data.alerts || 0;
            }
            
            if (data.type === 'flow') {
                addFlow(data.data);
            }
            
            if (data.type === 'alert') {
                addAlert(data.data);
            }
        };
        
        function addFlow(flow) {
            flows.push(flow);
            
            const list = document.getElementById('flowList');
            if (list.querySelector('.empty-state')) {
                list.innerHTML = '';
            }
            
            const item = document.createElement('div');
            item.className = `flow-item ${flow.is_sensitive ? 'sensitive' : ''} ${flow.is_api ? 'api' : ''}`;
            item.innerHTML = `
                <span class="flow-method method-${(flow.request_method || 'get').toLowerCase()}">${flow.request_method || 'GET'}</span>
                <span class="flow-path">${flow.request_url || ''}</span>
                <div class="flow-status">${flow.response_status || 0} • ${(flow.duration || 0).toFixed(0)}ms</div>
            `;
            item.onclick = () => showDetail(flow);
            
            list.insertBefore(item, list.firstChild);
            
            if (flows.length > 500) {
                list.removeChild(list.lastChild);
            }
        }
        
        function addAlert(alert) {
            alerts.push(alert);
            
            const list = document.getElementById('alertList');
            if (list.querySelector('.empty-state')) {
                list.innerHTML = '';
            }
            
            const item = document.createElement('div');
            item.className = `alert-item ${alert.level || 'warning'}`;
            item.innerHTML = `
                <div class="alert-title">${alert.title || ''}</div>
                <div class="alert-message">${alert.message || ''}</div>
            `;
            
            list.insertBefore(item, list.firstChild);
            
            if (alerts.length > 100) {
                list.removeChild(list.lastChild);
            }
        }
        
        function showDetail(flow) {
            const panel = document.getElementById('detailPanel');
            const content = document.getElementById('detailContent');
            
            panel.classList.add('show');
            content.innerHTML = `
                <div class="detail-section">
                    <h4>Request URL</h4>
                    <pre>${flow.request_url || ''}</pre>
                </div>
                <div class="detail-section">
                    <h4>Request Headers</h4>
                    <pre>${JSON.stringify(flow.request_headers || {}, null, 2)}</pre>
                </div>
                ${flow.request_content ? `
                <div class="detail-section">
                    <h4>Request Body</h4>
                    <pre>${flow.request_content || ''}</pre>
                </div>
                ` : ''}
                <div class="detail-section">
                    <h4>Response Status</h4>
                    <pre>${flow.response_status || 0}</pre>
                </div>
                ${flow.response_content ? `
                <div class="detail-section">
                    <h4>Response Body</h4>
                    <pre>${flow.response_content || ''}</pre>
                </div>
                ` : ''}
            `;
        }
    </script>
</body>
</html>
        '''


def create_app(host: str = '127.0.0.1', port: int = 8081) -> TrafficMonitorApp:
    """创建流量监控应用"""
    app = TrafficMonitorApp(host, port)
    return app


if __name__ == '__main__':
    import uvicorn
    
    app = create_app()
    fastapi_app = app.create_app()
    
    print(f'Starting ApiRed Traffic Monitor on http://{app.host}:{app.port}')
    uvicorn.run(fastapi_app, host=app.host, port=app.port)
