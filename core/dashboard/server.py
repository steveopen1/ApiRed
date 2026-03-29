"""
DashboardServer - HTTP/WebSocket 服务器
基于 aiohttp 实现 REST API 和 WebSocket 实时通信
"""

import asyncio
import json
import logging
import os
from typing import Optional, Any, Dict
from aiohttp import web, WSMsgType
from datetime import datetime

from .models import TaskStatus, ScanMode, ServerConfig
from .task_manager import TaskManager
from .orchestrator import ScanOrchestrator
from .events import (
    WSMessage, TaskUpdateMessage, TaskStartedMessage,
    ClientMessage, ClientMessageType, EventType
)

logger = logging.getLogger(__name__)


class DashboardServer:
    """Dashboard HTTP/WebSocket 服务器"""

    def __init__(self, config: Optional[ServerConfig] = None):
        self.config = config or ServerConfig()
        self.app: Optional[web.Application] = None
        self.runner: Optional[web.AppRunner] = None
        self.site: Optional[web.TCPSite] = None
        self.task_manager: Optional[TaskManager] = None
        self.orchestrator: Optional[ScanOrchestrator] = None
        self._ws_connections: set = set()

    def _error_response(self, message: str, status: int = 400) -> web.Response:
        """统一错误响应格式"""
        return web.json_response({
            'success': False,
            'error': message
        }, status=status)

    async def initialize(self):
        """初始化服务器"""
        self.task_manager = TaskManager(db_path="./results/dashboard.db")
        self.orchestrator = ScanOrchestrator(self.task_manager)

        self.app = web.Application(
            middlewares=[self._cors_middleware, self._body_limit_middleware],
            client_max_size=1024*1024
        )

        self._setup_routes()

        self.runner = web.AppRunner(self.app)
        await self.runner.setup()

        self.site = web.TCPSite(
            self.runner,
            host=self.config.host,
            port=self.config.port
        )

        logger.info(f"Dashboard server initialized on {self.config.host}:{self.config.port}")

    def _setup_routes(self):
        """设置路由"""
        self.app.router.add_get('/', self._handle_index)
        self.app.router.add_get('/ws', self._handle_websocket)
        self.app.router.add_get('/api/tasks', self._handle_get_tasks)
        self.app.router.add_post('/api/tasks', self._handle_create_task)
        self.app.router.add_get('/api/tasks/{task_id}', self._handle_get_task)
        self.app.router.add_post('/api/tasks/{task_id}/stop', self._handle_stop_task)
        self.app.router.add_post('/api/tasks/{task_id}/resume', self._handle_resume_task)
        self.app.router.add_delete('/api/tasks/{task_id}', self._handle_delete_task)
        self.app.router.add_get('/api/tasks/{task_id}/logs', self._handle_get_logs)
        self.app.router.add_get('/api/results', self._handle_get_results)
        self.app.router.add_get('/api/results/{task_id}', self._handle_get_result)
        self.app.router.add_get('/api/stats', self._handle_get_stats)
        self.app.router.add_get('/api/config', self._handle_get_config)
        self.app.router.add_put('/api/config', self._handle_update_config)
        self.app.router.add_get('/api/health', self._handle_health)
        self.app.router.add_get('/api/tasks/{task_id}/apis', self._handle_get_apis)
        self.app.router.add_get('/api/tasks/{task_id}/vulns', self._handle_get_vulns)
        self.app.router.add_post('/api/import/burp', self._handle_import_burp)
        self.app.router.add_post('/api/import/postman', self._handle_import_postman)
        self.app.router.add_post('/api/schedule', self._handle_create_schedule)
        self.app.router.add_get('/api/schedule', self._handle_list_schedules)
        self.app.router.add_delete('/api/schedule/{task_id}', self._handle_delete_schedule)
        self.app.router.add_get('/api/results/{task_id}/report', self._handle_get_enhanced_report)


        static_path = os.path.join(os.path.dirname(__file__), 'static')
        if os.path.exists(static_path):
            self.app.router.add_static('/static', static_path)

    @web.middleware
    async def _cors_middleware(self, request: web.Request, handler):
        """CORS 中间件"""
        if self.config.enable_cors:
            origin = request.headers.get('Origin', '')
            if origin == '*' or origin in self.config.cors_origins:
                response = await handler(request)
                if origin == '*':
                    response.headers['Access-Control-Allow-Origin'] = '*'
                else:
                    response.headers['Access-Control-Allow-Origin'] = origin
                    response.headers['Access-Control-Allow-Credentials'] = 'true'
                response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
                response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
                return response
        return await handler(request)
    
    @web.middleware
    async def _body_limit_middleware(self, request: web.Request, handler):
        """请求体大小限制中间件"""
        if request.content_length and request.content_length > 10 * 1024 * 1024:
            return self._error_response('Request body too large', 413)
        return await handler(request)
    
    async def start(self):
        """启动服务器"""
        if not self.app:
            await self.initialize()

        await self.site.start()
        print(f"[*] ApiRed Dashboard running at http://{self.config.host}:{self.config.port}")
        print(f"[*] WebSocket: ws://{self.config.host}:{self.config.port}/ws")
        print(f"[*] API Endpoints:")
        print(f"    GET  /api/tasks          - List tasks")
        print(f"    POST /api/tasks          - Create task")
        print(f"    GET  /api/tasks/:id      - Get task details")
        print(f"    POST /api/tasks/:id/stop - Stop task")
        print(f"    GET  /api/results        - Get results")
        print(f"    GET  /api/stats          - Get statistics")

    async def stop(self):
        """停止服务器"""
        for ws in self._ws_connections.copy():
            await ws.close()

        if self.site:
            await self.site.stop()
        if self.runner:
            await self.runner.cleanup()

        logger.info("Dashboard server stopped")

    async def _handle_index(self, request: web.Request):
        """处理首页请求"""
        index_path = os.path.join(os.path.dirname(__file__), 'static', 'index.html')
        if os.path.exists(index_path):
            return web.FileResponse(index_path)
        return web.Response(text="ApiRed Dashboard", content_type="text/html")

    async def _handle_websocket(self, request: web.Request):
        """处理 WebSocket 连接"""
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        self._ws_connections.add(ws)
        await self.task_manager.add_websocket(ws)

        logger.info(f"WebSocket connected, total: {len(self._ws_connections)}")

        try:
            await ws.send_json({
                'type': 'connected',
                'timestamp': datetime.now().isoformat()
            })

            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                        await self._handle_ws_message(ws, data)
                    except json.JSONDecodeError:
                        logger.warning(f"Invalid JSON from WebSocket: {msg.data}")
                elif msg.type == WSMsgType.ERROR:
                    logger.error(f"WebSocket error: {ws.exception()}")

        finally:
            self._ws_connections.discard(ws)
            await self.task_manager.remove_websocket(ws)
            logger.info(f"WebSocket disconnected, total: {len(self._ws_connections)}")

        return ws

    async def _handle_ws_message(self, ws: web.WebSocketResponse, data: Dict[str, Any]):
        """处理 WebSocket 消息"""
        try:
            client_msg = ClientMessage.from_dict(data)
        except Exception as e:
            logger.warning(f"Failed to parse client message: {e}")
            return

        msg_type = client_msg.type

        if msg_type == 'ping':
            await ws.send_json({
                'type': 'pong',
                'timestamp': datetime.now().isoformat()
            })
        elif msg_type == ClientMessageType.START_SCAN.value:
            await self._ws_handle_start_scan(ws, client_msg)
        elif msg_type == ClientMessageType.STOP_SCAN.value:
            await self._ws_handle_stop_scan(ws, client_msg)
        elif msg_type == ClientMessageType.RESUME_SCAN.value:
            await self._ws_handle_resume_scan(ws, client_msg)
        elif msg_type == ClientMessageType.DELETE_TASK.value:
            await self._ws_handle_delete_task(ws, client_msg)
        elif msg_type == ClientMessageType.GET_STATUS.value:
            await self._ws_handle_get_status(ws, client_msg)
        elif msg_type == ClientMessageType.GET_RESULTS.value:
            await self._ws_handle_get_results(ws, client_msg)

    async def _ws_handle_start_scan(self, ws: web.WebSocketResponse, msg: ClientMessage):
        """处理开始扫描"""
        if not msg.target:
            await ws.send_json({
                'type': 'error',
                'error': 'target is required'
            })
            return

        task = await self.task_manager.create_task(
            target=msg.target,
            config=msg.config,
            scan_mode=msg.config.get('scan_mode', 'rule')
        )

        await ws.send_json(TaskStartedMessage(
            task_id=task.task_id,
            target=task.target,
            scan_mode=task.scan_mode.value if hasattr(task.scan_mode, 'value') else task.scan_mode
        ).to_dict())

        asyncio.create_task(self.orchestrator.start_scan(task))

    async def _ws_handle_stop_scan(self, ws: web.WebSocketResponse, msg: ClientMessage):
        """处理停止扫描"""
        if not msg.task_id:
            await ws.send_json({'type': 'error', 'error': 'task_id is required'})
            return

        success = await self.orchestrator.stop_scan(msg.task_id)
        await ws.send_json({
            'type': 'stop_response',
            'task_id': msg.task_id,
            'success': success
        })

    async def _ws_handle_resume_scan(self, ws: web.WebSocketResponse, msg: ClientMessage):
        """处理恢复扫描"""
        if not msg.task_id:
            await ws.send_json({'type': 'error', 'error': 'task_id is required'})
            return

        success = await self.orchestrator.resume_scan(msg.task_id)
        await ws.send_json({
            'type': 'resume_response',
            'task_id': msg.task_id,
            'success': success
        })

    async def _ws_handle_delete_task(self, ws: web.WebSocketResponse, msg: ClientMessage):
        """处理删除任务"""
        if not msg.task_id:
            await ws.send_json({'type': 'error', 'error': 'task_id is required'})
            return

        success = await self.task_manager.delete_task(msg.task_id)
        await ws.send_json({
            'type': 'delete_response',
            'task_id': msg.task_id,
            'success': success
        })

    async def _ws_handle_get_status(self, ws: web.WebSocketResponse, msg: ClientMessage):
        """处理获取状态"""
        tasks = await self.task_manager.list_tasks()
        await ws.send_json({
            'type': 'status_response',
            'tasks': [t.to_dict() for t in tasks]
        })

    async def _ws_handle_get_results(self, ws: web.WebSocketResponse, msg: ClientMessage):
        """处理获取结果"""
        if msg.task_id:
            result = await self.task_manager.get_results(msg.task_id)
            await ws.send_json({
                'type': 'result_response',
                'task_id': msg.task_id,
                'result': result
            })
        else:
            results = await self.task_manager.get_results_all()
            await ws.send_json({
                'type': 'results_response',
                'results': results
            })

    async def _handle_get_tasks(self, request: web.Request):
        """获取所有任务"""
        tasks = await self.task_manager.list_tasks()
        return web.json_response({
            'tasks': [t.to_dict() for t in tasks]
        })

    async def _handle_create_task(self, request: web.Request):
        """创建任务"""
        try:
            data = await request.json()
        except json.JSONDecodeError:
            return self._error_response('Invalid JSON', 400)

        target = data.get('target')
        if not target:
            return self._error_response('target is required', 400)

        task = await self.task_manager.create_task(
            target=target,
            config=data.get('config', {}),
            scan_mode=data.get('scan_mode', 'rule')
        )

        asyncio.create_task(self.orchestrator.start_scan(task))

        return web.json_response({
            'task_id': task.task_id,
            'status': 'started'
        })

    async def _handle_get_task(self, request: web.Request):
        """获取任务详情"""
        task_id = request.match_info['task_id']
        task = await self.task_manager.get_task(task_id)

        if not task:
            return self._error_response('Task not found', 404)

        return web.json_response(task.to_dict())

    async def _handle_stop_task(self, request: web.Request):
        """停止任务"""
        task_id = request.match_info['task_id']
        success = await self.orchestrator.stop_scan(task_id)

        if not success:
            return self._error_response('Failed to stop task', 400)

        return web.json_response({'task_id': task_id, 'status': 'stopped'})

    async def _handle_resume_task(self, request: web.Request):
        """恢复任务"""
        task_id = request.match_info['task_id']
        success = await self.orchestrator.resume_scan(task_id)

        if not success:
            return self._error_response('Failed to resume task', 400)

        return web.json_response({'task_id': task_id, 'status': 'resumed'})

    async def _handle_delete_task(self, request: web.Request):
        """删除任务"""
        task_id = request.match_info['task_id']
        success = await self.task_manager.delete_task(task_id)

        if not success:
            return self._error_response('Failed to delete task', 400)

        return web.json_response({'task_id': task_id, 'status': 'deleted'})

    async def _handle_get_logs(self, request: web.Request):
        """获取任务日志"""
        task_id = request.match_info['task_id']
        limit = int(request.query.get('limit', 100))
        offset = int(request.query.get('offset', 0))

        logs = await self.task_manager.get_logs(task_id, limit, offset)
        return web.json_response({'logs': logs})

    async def _handle_get_results(self, request: web.Request):
        """获取所有结果"""
        stats = await self.task_manager.get_stats()
        return web.json_response(stats)

    async def _handle_get_result(self, request: web.Request):
        """获取任务结果"""
        task_id = request.match_info['task_id']
        result = await self.task_manager.get_results(task_id)

        if not result:
            return self._error_response('Result not found', 404)

        return web.json_response(result)

    async def _handle_get_apis(self, request: web.Request):
        """获取 API 列表"""
        task_id = request.match_info['task_id']
        result = await self.task_manager.get_results(task_id)

        if not result:
            return self._error_response('Result not found', 404)

        return web.json_response({'apis': result.get('api_endpoints', [])})

    async def _handle_get_vulns(self, request: web.Request):
        """获取漏洞列表"""
        task_id = request.match_info['task_id']
        result = await self.task_manager.get_results(task_id)

        if not result:
            return self._error_response('Result not found', 404)

        return web.json_response({'vulnerabilities': result.get('vulnerabilities', [])})

    async def _handle_get_stats(self, request: web.Request):
        """获取统计信息"""
        stats = await self.task_manager.get_stats()
        return web.json_response(stats)

    async def _handle_get_config(self, request: web.Request):
        """获取配置"""
        return web.json_response(self.config.to_dict())

    async def _handle_update_config(self, request: web.Request):
        """更新配置"""
        try:
            data = await request.json()
        except json.JSONDecodeError:
            return self._error_response('Invalid JSON', 400)

        allowed_keys = {'host', 'port', 'enable_cors', 'cors_origins', 'heartbeat_interval', 'max_log_entries', 'task_history_limit'}
        update_data = {k: v for k, v in data.items() if k in allowed_keys}

        for key, value in update_data.items():
            if key == 'port' and isinstance(value, int):
                if value < 1 or value > 65535:
                    return self._error_response('Invalid port number', 400)
            if key == 'heartbeat_interval' and isinstance(value, int):
                if value < 1:
                    return self._error_response('Invalid heartbeat_interval', 400)
            setattr(self.config, key, value)

        return web.json_response({'status': 'saved'})

    async def _handle_health(self, request: web.Request):
        """健康检查"""
        health = {
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'components': {
                'server': {'status': 'up'},
                'task_manager': {'status': 'up'},
                'orchestrator': {'status': 'up'},
            }
        }

        running_tasks = len(self.orchestrator.get_running_tasks()) if self.orchestrator else 0
        health['components']['orchestrator']['running_tasks'] = running_tasks

        return web.json_response(health)



    async def _handle_import_burp(self, request: web.Request) -> web.Response:
        """导入 BurpSuite 流量文件"""
        try:
            reader = await request.multipart()
            field = await reader.next()
            if not field:
                return self._error_response('No file provided')
            
            filename = field.filename or 'upload'
            content = await field.read()
            
            from ..collectors import BurpSuiteImporter
            importer = BurpSuiteImporter()
            
            try:
                if filename.endswith('.csv'):
                    importer.import_csv(content.decode('utf-8', errors='ignore'))
                elif filename.endswith('.json'):
                    importer.import_json(content.decode('utf-8', errors='ignore'))
                elif filename.endswith('.xml'):
                    importer.import_xml(content.decode('utf-8', errors='ignore'))
                elif filename.endswith('.har'):
                    importer.import_har(content.decode('utf-8', errors='ignore'))
                else:
                    return self._error_response('Unsupported format. Use CSV/JSON/XML/HAR')
            except Exception as parse_err:
                logger.warning(f"Parse error: {parse_err}")
            
            summary = importer.get_traffic_summary()
            endpoints = importer.get_api_endpoints()
            
            logger.info(f"BurpSuite import: {summary.get('total_transactions', 0)} transactions, {len(endpoints)} endpoints")
            
            return web.json_response({
                'success': True,
                'count': len(endpoints),
                'endpoints': endpoints,
                'summary': summary
            })
            
        except Exception as e:
            logger.error(f"BurpSuite import error: {e}")
            return self._error_response(str(e), 500)

    async def _handle_import_postman(self, request: web.Request) -> web.Response:
        """导入 Postman Collection"""
        try:
            reader = await request.multipart()
            field = await reader.next()
            if not field:
                return self._error_response('No file provided')
            
            content = await field.read()
            
            from ..collectors import PostmanCollectionImporter
            importer = PostmanCollectionImporter()
            
            try:
                importer.import_collection(content.decode('utf-8'))
            except Exception as parse_err:
                logger.warning(f"Parse error: {parse_err}")
            
            summary = importer.get_endpoints_summary()
            endpoints = importer.get_api_endpoints()
            
            logger.info(f"Postman import: {summary.get('total_endpoints', 0)} endpoints")
            
            return web.json_response({
                'success': True,
                'count': len(endpoints),
                'endpoints': endpoints,
                'summary': summary
            })
            
        except Exception as e:
            logger.error(f"Postman import error: {e}")
            return self._error_response(str(e), 500)

    async def _handle_create_schedule(self, request: web.Request) -> web.Response:
        """创建定时扫描任务"""
        try:
            data = await request.json()
            target = data.get('target', '')
            cron_expr = data.get('cron', '')
            
            if not target:
                return self._error_response('Target is required')
            if not cron_expr:
                return self._error_response('Cron expression is required')
            
            from ..scheduled_testing import CronScheduler
            import time
            
            scheduler = CronScheduler()
            task_id = f"sched_{int(time.time())}"
            
            scheduler.add_task(
                task_id=task_id,
                name=f"Scheduled: {target}",
                target=target,
                cron_expression=cron_expr,
                trigger_type='cron',
                config=data.get('config', {})
            )
            
            logger.info(f"Created schedule: {task_id} for {target} with cron {cron_expr}")
            
            return web.json_response({
                'success': True,
                'task_id': task_id,
                'message': 'Schedule created'
            })
            
        except Exception as e:
            logger.error(f"Create schedule error: {e}")
            return self._error_response(str(e), 500)

    async def _handle_list_schedules(self, request: web.Request) -> web.Response:
        """列出所有定时任务"""
        try:
            from ..scheduled_testing import CronScheduler
            
            scheduler = CronScheduler()
            summary = scheduler.get_schedule_summary()
            
            return web.json_response({
                'success': True,
                'tasks': summary.get('tasks', [])
            })
            
        except Exception as e:
            logger.error(f"List schedules error: {e}")
            return self._error_response(str(e), 500)

    async def _handle_delete_schedule(self, request: web.Request) -> web.Response:
        """删除定时任务"""
        try:
            task_id = request.match_info.get('task_id', '')
            
            from ..scheduled_testing import CronScheduler
            
            scheduler = CronScheduler()
            scheduler.remove_task(task_id)
            
            logger.info(f"Deleted schedule: {task_id}")
            
            return web.json_response({
                'success': True,
                'message': f'Task {task_id} deleted'
            })
            
        except Exception as e:
            logger.error(f"Delete schedule error: {e}")
            return self._error_response(str(e), 500)

    async def _handle_get_enhanced_report(self, request: web.Request) -> web.Response:
        """生成增强 HTML 报告"""
        try:
            task_id = request.match_info.get('task_id', '')
            
            if not self.task_manager:
                return self._error_response('Task manager not initialized')
            
            result = await self.task_manager.get_result(task_id)
            if not result:
                return self._error_response('Result not found', 404)
            
            from ..exporters.enhanced_html_reporter import EnhancedHtmlReporter
            
            output_dir = f'./results/{task_id}'
            os.makedirs(output_dir, exist_ok=True)
            report_path = os.path.join(output_dir, 'enhanced_report.html')
            
            data = result.to_dict() if hasattr(result, 'to_dict') else result
            
            reporter = EnhancedHtmlReporter()
            reporter.export(data, report_path)
            
            logger.info(f"Generated enhanced report: {report_path}")
            
            return web.json_response({
                'success': True,
                'report_path': report_path,
                'report_url': f'/results/{task_id}/enhanced_report.html'
            })
            
        except Exception as e:
            logger.error(f"Enhanced report error: {e}")
            return self._error_response(str(e), 500)

async def run_server(host: str = "0.0.0.0", port: int = 8080):
    """运行服务器"""
    server = DashboardServer(ServerConfig(host=host, port=port))
    await server.initialize()
    await server.start()

    try:
        await asyncio.Future()
    except KeyboardInterrupt:
        await server.stop()


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    asyncio.run(run_server())
