import pytest
from core.scanner import ChkApiScanner, ScannerConfig


class TestScanner:
    def test_scanner_config_creation(self):
        config = ScannerConfig(target="https://example.com")
        assert config.target == "https://example.com"
    
    def test_scanner_initialization(self):
        config = ScannerConfig(target="https://example.com")
        scanner = ChkApiScanner(config)
        assert scanner.config == config
        assert not scanner.is_running
    
    def test_scanner_config_defaults(self):
        config = ScannerConfig(target="https://example.com")
        assert config.cookies == ""
        assert config.chrome is True
        assert config.attack_mode == "all"
        assert config.concurrency == 50
        assert config.output_format == "json"
        assert config.resume is False
    
    def test_scanner_config_custom_values(self):
        config = ScannerConfig(
            target="https://example.com",
            cookies="session=abc123",
            chrome=False,
            attack_mode="collect",
            concurrency=100
        )
        assert config.cookies == "session=abc123"
        assert config.chrome is False
        assert config.attack_mode == "collect"
        assert config.concurrency == 100
    
    @pytest.mark.asyncio
    async def test_scanner_initialize(self):
        config = ScannerConfig(target="https://example.com", resume=False)
        scanner = ChkApiScanner(config)
        await scanner.initialize()
        assert scanner.is_running is True
        assert scanner.http_client is not None
        assert scanner.result is not None
        assert scanner.result.target_url == "https://example.com"
    
    @pytest.mark.asyncio
    async def test_scanner_checkpoint_creation(self, tmp_path):
        checkpoint_file = tmp_path / "checkpoint.json"
        config = ScannerConfig(
            target="https://example.com",
            resume=False,
            checkpoint_file=str(checkpoint_file)
        )
        scanner = ChkApiScanner(config)
        await scanner.initialize()
        await scanner._save_checkpoint()
        assert checkpoint_file.exists()


class TestScannerEventCallbacks:
    def test_register_callback(self):
        config = ScannerConfig(target="https://example.com")
        scanner = ChkApiScanner(config)
        
        callback_called = []
        def test_callback(data):
            callback_called.append(data)
        
        scanner.on('stage_start', test_callback)
        assert len(scanner._callbacks['stage_start']) == 1
    
    def test_emit_callback(self):
        config = ScannerConfig(target="https://example.com")
        scanner = ChkApiScanner(config)
        
        callback_called = []
        def test_callback(data):
            callback_called.append(data)
        
        scanner.on('finding', test_callback)
        scanner._emit('finding', {'type': 'test'})
        assert len(callback_called) == 1
        assert callback_called[0]['type'] == 'test'
