#!/usr/bin/env python3
"""
前端路由追踪模块 - 基于 FLUX v1.1
监听 history.pushState/hashchange 路由变化
"""

import re
import logging
from typing import List, Dict, Set, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class RouteChange:
    """路由变化记录"""
    timestamp: float
    old_route: str
    new_route: str
    change_type: str
    source: str
    trigger: str


class RouteTracker:
    """前端路由追踪器"""

    ROUTE_HOOK_SCRIPT = """
    (function() {
        if (window.__routeTracker) return;
        window.__routeTracker = {
            history: [],
            init: function() {
                var self = this;
                
                self.originalPushState = history.pushState;
                self.originalReplaceState = history.replaceState;
                self.originalPopState = popStateEvent;
                
                history.pushState = function(state, title, url) {
                    self.originalPushState.call(history, state, title, url);
                    self.record('pushState', url || location.href);
                };
                
                history.replaceState = function(state, title, url) {
                    self.originalReplaceState.call(history, state, title, url);
                    self.record('replaceState', url || location.href);
                };
                
                window.addEventListener('popstate', function(e) {
                    self.record('popstate', location.href);
                });
                
                window.addEventListener('hashchange', function(e) {
                    self.record('hashchange', location.href);
                });
            },
            record: function(type, url) {
                var entry = {
                    type: type,
                    url: url,
                    timestamp: Date.now(),
                    route: this.extractRoute(url)
                };
                this.history.push(entry);
                if (window.__routeTrackerCallback) {
                    window.__routeTrackerCallback(entry);
                }
            },
            extractRoute: function(url) {
                try {
                    var urlObj = new URL(url);
                    return urlObj.pathname + urlObj.search;
                } catch(e) {
                    return url.split('?')[0];
                }
            },
            getHistory: function() {
                return this.history;
            }
        };
        window.__routeTracker.init();
    })();
    """

    def __init__(self):
        self.route_changes: List[RouteChange] = []
        self.current_route: str = ""
        self.seen_routes: Set[str] = set()
        self.callback: Optional[Callable] = None

    def get_injection_script(self) -> str:
        return self.ROUTE_HOOK_SCRIPT

    def record_change(self, change_type: str, new_route: str, old_route: str = "", trigger: str = ""):
        if new_route in self.seen_routes:
            return

        self.seen_routes.add(new_route)

        change = RouteChange(
            timestamp=datetime.now().timestamp(),
            old_route=old_route or self.current_route,
            new_route=new_route,
            change_type=change_type,
            source='browser_hook',
            trigger=trigger or change_type
        )

        self.route_changes.append(change)
        self.current_route = new_route

        if self.callback:
            self.callback(change)

        logger.debug(f"[*] 路由变化: {change_type} -> {new_route}")

    def set_callback(self, callback: Callable):
        self.callback = callback

    def get_all_routes(self) -> List[str]:
        return list(self.seen_routes)

    def get_route_changes(self) -> List[RouteChange]:
        return self.route_changes

    def is_new_route(self, route: str) -> bool:
        return route not in self.seen_routes

    def clear(self):
        self.route_changes.clear()
        self.seen_routes.clear()
        self.current_route = ""


class StorageSync:
    """存储状态同步器"""

    STORAGE_SYNC_SCRIPT = """
    (function() {
        if (window.__storageSync) return;
        window.__storageSync = {
            data: {},
            init: function() {
                try {
                    if (localStorage) {
                        for (var key in localStorage) {
                            this.data[key] = localStorage.getItem(key);
                        }
                    }
                    if (sessionStorage) {
                        for (var key in sessionStorage) {
                            this.data['session_' + key] = sessionStorage.getItem(key);
                        }
                    }
                } catch(e) {}
            },
            getData: function() {
                return this.data;
            },
            getHeaders: function() {
                var headers = {};
                for (var key in this.data) {
                    headers['X-Storage-' + key] = this.data[key];
                }
                return headers;
            }
        };
        window.__storageSync.init();
    })();
    """

    def __init__(self):
        self.storage_data: Dict[str, str] = {}

    def get_injection_script(self) -> str:
        return self.STORAGE_SYNC_SCRIPT

    def get_storage_data(self) -> Dict[str, str]:
        return self.storage_data

    def get_sync_headers(self) -> Dict[str, str]:
        headers = {}
        for key, value in self.storage_data.items():
            headers[f'X-Storage-{key}'] = value
        return headers


class ResponseCapture:
    """响应捕获器"""

    def __init__(self):
        self.captured_requests: List[Dict] = []

    def get_capture_script(self, capture_xhr: bool = True, capture_fetch: bool = True) -> str:
        scripts = []

        if capture_xhr:
            scripts.append("""
            (function() {
                if (window.__xhrCapture) return;
                window.__xhrCapture = {
                    requests: [],
                    init: function() {
                        var self = this;
                        var originalXHROpen = XMLHttpRequest.prototype.open;
                        var originalXHRSend = XMLHttpRequest.prototype.send;
                        
                        XMLHttpRequest.prototype.open = function(method, url, async) {
                            this._url = url;
                            this._method = method;
                            return originalXHROpen.apply(this, arguments);
                        };
                        
                        XMLHttpRequest.prototype.send = function(data) {
                            var self2 = this;
                            this.addEventListener('load', function() {
                                self2._response = this.responseText;
                                self2._status = this.status;
                                self2._contentType = this.getResponseHeader('content-type');
                                self2._responseURL = this.responseURL;
                                self.requests.push({
                                    url: self2._url,
                                    method: self2._method,
                                    status: self2._status,
                                    contentType: self2._contentType,
                                    responseURL: self2._responseURL,
                                    timestamp: Date.now()
                                });
                            });
                            return originalXHRSend.apply(this, arguments);
                        };
                    }
                };
                window.__xhrCapture.init();
            })();
            """)

        if capture_fetch:
            scripts.append("""
            (function() {
                if (window.__fetchCapture) return;
                window.__fetchCapture = {
                    requests: [],
                    init: function() {
                        var self = this;
                        var originalFetch = window.fetch;
                        window.fetch = function(url, options) {
                            var fetchInfo = {
                                url: typeof url === 'string' ? url : url.url,
                                method: (options && options.method) || 'GET',
                                timestamp: Date.now()
                            };
                            return originalFetch.apply(this, arguments).then(function(response) {
                                fetchInfo.status = response.status;
                                fetchInfo.contentType = response.headers.get('content-type');
                                fetchInfo.responseURL = response.url;
                                self.requests.push(fetchInfo);
                                return response;
                            });
                        };
                    }
                };
                window.__fetchCapture.init();
            })();
            """)

        return ''.join(scripts)

    def add_captured_request(self, request_info: Dict):
        self.captured_requests.append(request_info)

    def get_all_requests(self) -> List[Dict]:
        return self.captured_requests

    def get_api_requests(self) -> List[Dict]:
        api_requests = []
        for req in self.captured_requests:
            url = req.get('url', '')
            if '/api/' in url or '/v' in url or 'json' in req.get('contentType', '').lower():
                api_requests.append(req)
        return api_requests

    def clear(self):
        self.captured_requests.clear()


__all__ = ['RouteTracker', 'RouteChange', 'StorageSync', 'ResponseCapture']
