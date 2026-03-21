import pytest
from core.exporters.openapi_exporter import OpenAPIExporter
from core.models import ScanResult, APIEndpoint, APIStatus


class TestOpenAPIExporter:
    def test_exporter_creation(self):
        exporter = OpenAPIExporter()
        assert exporter is not None
        assert "openapi" in exporter.spec
        assert exporter.spec["openapi"].startswith("3.0")
    
    def test_generate_spec_structure(self):
        exporter = OpenAPIExporter()
        spec = exporter.spec
        assert "openapi" in spec
        assert "info" in spec
        assert "paths" in spec
    
    def test_spec_info_defaults(self):
        exporter = OpenAPIExporter()
        assert exporter.spec["info"]["title"] == "Discovered API"
        assert exporter.spec["info"]["version"] == "1.0.0"
    
    def test_generate_from_scan_result(self, sample_scan_result):
        exporter = OpenAPIExporter()
        spec = exporter.generate_from_scan_result(sample_scan_result)
        assert "openapi" in spec
        assert "paths" in spec
    
    def test_generate_paths_from_endpoints(self, sample_scan_result):
        endpoint = APIEndpoint(
            path="/api/users",
            method="GET",
            full_url="https://example.com/api/users"
        )
        sample_scan_result.api_endpoints.append(endpoint)
        
        exporter = OpenAPIExporter()
        exporter._generate_paths(sample_scan_result.api_endpoints)
        
        assert "/api/users" in exporter.spec["paths"]
        assert "get" in exporter.spec["paths"]["/api/users"]
    
    def test_generate_operation_with_parameters(self):
        endpoint = APIEndpoint(
            path="/api/users",
            method="GET",
            parameters=["id", "page"]
        )
        
        exporter = OpenAPIExporter()
        operation = exporter._generate_operation(endpoint)
        
        assert "summary" in operation
        assert "responses" in operation
        assert operation["parameters"] == ["id", "page"]
    
    def test_generate_components(self):
        exporter = OpenAPIExporter()
        exporter._generate_components()
        
        assert "components" in exporter.spec
        assert "schemas" in exporter.spec["components"]
        assert "securitySchemes" in exporter.spec["components"]
        assert "bearerAuth" in exporter.spec["components"]["securitySchemes"]
