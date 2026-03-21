import pytest
from core.framework import FrameworkRuleEngine, load_default_fingerprints


class TestFrameworkRuleEngine:
    def test_engine_creation(self):
        engine = FrameworkRuleEngine()
        assert engine is not None
    
    def test_load_vc_framework_fingerprint(self):
        engine = load_default_fingerprints()
        assert 'VC Framework' in engine.list_rules()
    
    def test_detect_vc_framework(self):
        engine = load_default_fingerprints()
        
        target_info = {
            'js_files': 'vcFramework.js, vc-lang.js',
            'api_paths': '/callComponent/login/getSysInfo',
            'response_content': 'VC Framework智慧小区',
            'headers': 'X-Powered-By: VC'
        }
        
        matches = engine.detect(target_info)
        
        assert len(matches) > 0
        assert matches[0].name == 'VC Framework'
        assert matches[0].confidence >= 0.4
    
    def test_generate_vc_endpoints(self):
        engine = load_default_fingerprints()
        
        endpoints = engine.generate_endpoints('VC Framework')
        
        assert len(endpoints) > 0
        assert any('/callComponent/' in ep for ep in endpoints)
        assert any('login' in ep for ep in endpoints)
    
    def test_no_match_for_unknown_target(self):
        engine = load_default_fingerprints()
        
        target_info = {
            'js_files': 'unknown.js',
            'api_paths': '/api/users',
            'response_content': 'some content',
            'headers': ''
        }
        
        matches = engine.detect(target_info)
        
        assert len(matches) == 0 or matches[0].confidence < 0.3
    
    def test_express_framework(self):
        engine = load_default_fingerprints()
        
        target_info = {
            'js_files': 'app.js',
            'api_paths': '/api/users',
            'headers': 'X-Powered-By: Express',
            'response_content': 'Express'
        }
        
        matches = engine.detect(target_info)
        
        assert len(matches) > 0
        express_matches = [m for m in matches if m.name == 'Express.js']
        assert len(express_matches) > 0


class TestFrameworkMatch:
    def test_framework_match_creation(self):
        from core.framework.rule_engine import FrameworkMatch
        
        match = FrameworkMatch(
            name='Test Framework',
            confidence=0.8,
            api_pattern={'base_path': '/api/'}
        )
        
        assert match.name == 'Test Framework'
        assert match.confidence == 0.8
        assert match.api_pattern['base_path'] == '/api/'
