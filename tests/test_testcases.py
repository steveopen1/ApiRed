import pytest
from core.testcases import TestCaseLoader, TestCase, load_default_library


class TestTestCaseLibrary:
    def test_loader_creation(self):
        loader = TestCaseLoader()
        assert loader is not None
    
    def test_load_default_library(self):
        library = load_default_library()
        assert library is not None
        assert library.category in ["owasp_top10", "owasp_api_security"]
        assert library.count() > 0
    
    def test_get_by_vuln_type(self):
        library = load_default_library()
        sql_tests = library.get_by_vuln_type("SQL_INJECTION")
        assert len(sql_tests) > 0
        assert all(tc.vuln_type == "SQL_INJECTION" for tc in sql_tests)
    
    def test_get_by_severity(self):
        library = load_default_library()
        critical_tests = library.get_by_severity("CRITICAL")
        assert len(critical_tests) > 0
        assert all(tc.severity == "CRITICAL" for tc in critical_tests)
    
    def test_get_by_id(self):
        library = load_default_library()
        test = library.get_by_id("OWASP-API-1")
        assert test is not None
        assert test.id == "OWASP-API-1"
    
    def test_get_all_vuln_types(self):
        library = load_default_library()
        vuln_types = library.get_all_vuln_types()
        assert len(vuln_types) > 0
        assert "SQL_INJECTION" in vuln_types
        assert "XSS" in vuln_types
    
    def test_test_case_to_dict(self):
        library = load_default_library()
        test = library.get_by_id("OWASP-API-6")
        assert test is not None
        d = test.to_dict()
        assert d['id'] == "OWASP-API-6"
        assert d['vuln_type'] == "SQL_INJECTION"
        assert len(d['payloads']) > 0
