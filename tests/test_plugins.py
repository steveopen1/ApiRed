import pytest
from core.plugins import PluginRegistry, BypassTesterPlugin, CollectorPlugin, TesterPlugin, ExporterPlugin


class TestPluginRegistry:
    def test_register_collector(self):
        class DummyCollector(CollectorPlugin):
            @property
            def name(self):
                return "dummy"
            
            def initialize(self, config):
                pass
            
            async def execute(self, context):
                return {}
            
            async def collect(self, target):
                return []
        
        PluginRegistry.register_collector('dummy', DummyCollector)
        assert PluginRegistry.get_collector('dummy') == DummyCollector
    
    def test_register_tester(self):
        class DummyTester(TesterPlugin):
            @property
            def name(self):
                return "dummy_tester"
            
            def initialize(self, config):
                pass
            
            async def execute(self, context):
                return {}
            
            async def test(self, endpoint):
                return []
        
        PluginRegistry.register_tester('dummy_tester', DummyTester)
        assert PluginRegistry.get_tester('dummy_tester') == DummyTester
    
    def test_list_collectors(self):
        collectors = PluginRegistry.list_collectors()
        assert isinstance(collectors, list)
    
    def test_list_testers(self):
        testers = PluginRegistry.list_testers()
        assert isinstance(testers, list)
    
    def test_get_nonexistent_plugin(self):
        result = PluginRegistry.get_collector('nonexistent_plugin_12345')
        assert result is None


class TestBypassTesterPlugin:
    def test_bypass_plugin_creation(self):
        plugin = BypassTesterPlugin()
        assert plugin.name == "bypass"
    
    def test_bypass_plugin_has_techniques(self):
        plugin = BypassTesterPlugin()
        assert hasattr(plugin, 'techniques')
        assert len(plugin.techniques) > 0
        assert "header_injection" in plugin.techniques
        assert "method_tampering" in plugin.techniques
    
    def test_bypass_plugin_initialize(self):
        plugin = BypassTesterPlugin()
        config = {'techniques': ['custom_technique']}
        plugin.initialize(config)
        assert plugin.techniques == ['custom_technique']
    
    @pytest.mark.asyncio
    async def test_bypass_plugin_execute(self):
        plugin = BypassTesterPlugin()
        result = await plugin.execute({})
        assert 'tested' in result
        assert result['tested'] == len(plugin.techniques)
    
    @pytest.mark.asyncio
    async def test_bypass_plugin_test(self):
        plugin = BypassTesterPlugin()
        results = await plugin.test(None)
        assert isinstance(results, list)
        assert len(results) == len(plugin.techniques)
