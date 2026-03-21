"""
OpenAPI Exporter
从扫描结果生成 OpenAPI 3.0 规范
"""

from typing import Dict, List, Any, Optional
import json
from datetime import datetime


class OpenAPIExporter:
    """OpenAPI 规范导出器"""
    
    def __init__(self):
        self.spec: Dict[str, Any] = {
            "openapi": "3.0.0",
            "info": {
                "title": "Discovered API",
                "version": "1.0.0",
                "description": "API discovered by ApiRed"
            },
            "paths": {}
        }
    
    def generate_from_scan_result(self, scan_result) -> Dict:
        """
        从扫描结果生成 OpenAPI 规范
        
        Args:
            scan_result: ScanResult 对象
        
        Returns:
            OpenAPI 规范字典
        """
        self._generate_info(scan_result)
        self._generate_paths(scan_result.api_endpoints)
        self._generate_components()
        return self.spec
    
    def _generate_info(self, scan_result) -> None:
        """生成 info 部分"""
        self.spec["info"]["title"] = f"API for {scan_result.target_url}"
        self.spec["info"]["description"] = f"Discovered by ApiRed at {scan_result.start_time}"
    
    def _generate_paths(self, endpoints: List) -> None:
        """生成 paths 部分"""
        for endpoint in endpoints:
            path = endpoint.path if endpoint.path.startswith('/') else f"/{endpoint.path}"
            
            if path not in self.spec["paths"]:
                self.spec["paths"][path] = {}
            
            method = endpoint.method.lower() if endpoint.method else "get"
            self.spec["paths"][path][method] = self._generate_operation(endpoint)
    
    def _generate_operation(self, endpoint) -> Dict:
        """生成单个操作的 OpenAPI 定义"""
        operation = {
            "summary": endpoint.path,
            "responses": {
                "200": {"description": "Successful response"},
                "401": {"description": "Unauthorized"},
                "403": {"description": "Forbidden"},
                "404": {"description": "Not Found"}
            }
        }
        
        if hasattr(endpoint, 'parameters') and endpoint.parameters:
            operation["parameters"] = endpoint.parameters
        
        if hasattr(endpoint, 'request_body') and endpoint.request_body:
            operation["requestBody"] = endpoint.request_body
        
        return operation
    
    def _generate_components(self) -> None:
        """生成 components 部分（schemas, security schemes）"""
        self.spec["components"] = {
            "schemas": {
                "Error": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "integer"},
                        "message": {"type": "string"}
                    }
                }
            },
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT"
                }
            }
        }
    
    def export_json(self, scan_result, output_path: str) -> None:
        """导出为 JSON 文件"""
        spec = self.generate_from_scan_result(scan_result)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(spec, f, indent=2, ensure_ascii=False)
    
    def export_yaml(self, scan_result, output_path: str) -> None:
        """导出为 YAML 文件"""
        import yaml
        spec = self.generate_from_scan_result(scan_result)
        with open(output_path, 'w', encoding='utf-8') as f:
            yaml.dump(spec, f, default_flow_style=False, allow_unicode=True)
