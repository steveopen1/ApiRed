"""
Unit tests for Error Handler Module
"""

import pytest
import asyncio
from core.utils.error_handler import (
    ErrorSeverity,
    FuzzingError,
    NetworkError,
    DNSError,
    HTTPError,
    ConfigurationError,
    FatalError,
    ErrorHandler,
    CircuitBreaker,
    handle_error
)


class TestErrorSeverity:
    """Test cases for ErrorSeverity enum"""
    
    def test_error_severity_values(self):
        """Test ErrorSeverity enum values"""
        assert ErrorSeverity.RECOVERABLE.value == "recoverable"
        assert ErrorSeverity.CONFIGURATION.value == "configuration"
        assert ErrorSeverity.FATAL.value == "fatal"


class TestFuzzingError:
    """Test cases for FuzzingError"""
    
    def test_basic_error(self):
        """Test basic FuzzingError creation"""
        error = FuzzingError("Test error")
        
        assert str(error) == "[recoverable] Test error"
        assert error.severity == ErrorSeverity.RECOVERABLE
        assert error.retry_count == 0
        assert error.context == ""
    
    def test_error_with_context(self):
        """Test FuzzingError with context"""
        error = FuzzingError(
            message="Network failed",
            severity=ErrorSeverity.RECOVERABLE,
            retry_count=2,
            context="dns_resolution"
        )
        
        assert error.context == "dns_resolution"
        assert error.retry_count == 2
        assert error.is_recoverable()
        assert not error.is_fatal()
    
    def test_fatal_error(self):
        """Test fatal error"""
        error = FatalError("Critical failure", context="auth")
        
        assert error.severity == ErrorSeverity.FATAL
        assert error.is_fatal()
        assert not error.is_recoverable()
    
    def test_network_error(self):
        """Test NetworkError"""
        error = NetworkError("Connection timeout", retry_count=1, context="api_call")
        
        assert isinstance(error, FuzzingError)
        assert error.severity == ErrorSeverity.RECOVERABLE
        assert error.context == "api_call"
    
    def test_dns_error(self):
        """Test DNSError"""
        error = DNSError("DNS lookup failed", retry_count=0)
        
        assert isinstance(error, FuzzingError)
        assert error.context == "dns"
    
    def test_http_error(self):
        """Test HTTPError with status code"""
        error = HTTPError("404 Not Found", status_code=404, retry_count=2)
        
        assert error.status_code == 404
        assert isinstance(error, FuzzingError)
    
    def test_configuration_error(self):
        """Test ConfigurationError"""
        error = ConfigurationError("Invalid API key", context="api_config")
        
        assert error.severity == ErrorSeverity.CONFIGURATION
        assert error.context == "api_config"


class TestErrorHandler:
    """Test cases for ErrorHandler"""
    
    def test_initialization(self):
        """Test ErrorHandler initialization"""
        handler = ErrorHandler(max_retries=5)
        
        assert handler.max_retries == 5
        assert handler.error_stats == {}
    
    def test_register_handler(self):
        """Test registering custom error handler"""
        handler = ErrorHandler()
        
        def custom_handler(error):
            return False
        
        handler.register_handler(ValueError, custom_handler)
        
        assert ValueError in handler._error_handlers
    
    def test_register_recovery(self):
        """Test registering recovery function"""
        handler = ErrorHandler()
        
        def recovery_func(error):
            pass
        
        handler.register_recovery(NetworkError, recovery_func)
        
        assert NetworkError in handler._recovery_handlers
    
    def test_handle_recoverable_error(self):
        """Test handling recoverable error"""
        handler = ErrorHandler()
        
        error = NetworkError("Timeout")
        result = handler.handle_error(error, "test_context")
        
        assert result is True
        assert "test_context:NetworkError" in handler.error_stats
    
    def test_handle_fatal_error(self):
        """Test handling fatal error"""
        handler = ErrorHandler()
        
        error = FatalError("Critical")
        result = handler.handle_error(error, "test_context")
        
        assert result is False
    
    def test_handle_configuration_error(self):
        """Test handling configuration error"""
        handler = ErrorHandler()
        
        error = ConfigurationError("Invalid config")
        
        with pytest.raises(ConfigurationError):
            handler.handle_error(error, "test_context")
    
    def test_should_retry(self):
        """Test retry decision logic"""
        handler = ErrorHandler(max_retries=3)
        
        recoverable = NetworkError("Timeout", retry_count=2)
        assert handler.should_retry(recoverable, 1) is True
        
        exhausted = NetworkError("Timeout", retry_count=3)
        assert handler.should_retry(exhausted, 1) is False
        
        fatal = FatalError("Critical")
        assert handler.should_retry(fatal, 0) is False


class TestCircuitBreaker:
    """Test cases for CircuitBreaker"""
    
    def test_initialization(self):
        """Test CircuitBreaker initialization"""
        cb = CircuitBreaker(
            failure_threshold=5,
            recovery_timeout=60.0
        )
        
        assert cb.failure_threshold == 5
        assert cb.recovery_timeout == 60.0
        assert cb.is_open is False
    
    def test_record_success(self):
        """Test recording success"""
        cb = CircuitBreaker(failure_threshold=3)
        
        cb.record_success()
        
        assert cb._failure_count == 0
        assert cb.is_open is False
    
    def test_record_failure_opens_circuit(self):
        """Test that failures open the circuit"""
        cb = CircuitBreaker(failure_threshold=3)
        
        for _ in range(3):
            cb.record_failure()
        
        assert cb.is_open is True
    
    def test_circuit_half_open_after_timeout(self):
        """Test circuit transitions to half-open after timeout"""
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=0.1)
        
        cb.record_failure()
        assert cb.is_open is True
        
        import time
        time.sleep(0.2)
        
        assert cb.is_open is False
        assert cb._failure_count == 0
    
    @pytest.mark.asyncio
    async def test_call_success(self):
        """Test successful call through circuit breaker"""
        cb = CircuitBreaker(failure_threshold=3)
        
        async def success_func():
            return "success"
        
        result = await cb.call(success_func)
        
        assert result == "success"
        assert cb._failure_count == 0
    
    @pytest.mark.asyncio
    async def test_call_failure_opens_circuit(self):
        """Test that call failure opens circuit"""
        cb = CircuitBreaker(failure_threshold=2)
        
        async def failing_func():
            raise ValueError("test error")
        
        try:
            await cb.call(failing_func)
        except ValueError:
            pass
        
        assert cb.is_open is True


class TestGlobalHandleError:
    """Test cases for global handle_error function"""
    
    def test_handle_recoverable_error(self):
        """Test global handle_error with recoverable error"""
        error = NetworkError("Timeout")
        result = handle_error(error, "test")
        
        assert result is True
    
    def test_handle_fatal_error(self):
        """Test global handle_error with fatal error"""
        error = FatalError("Critical")
        result = handle_error(error, "test")
        
        assert result is False


class TestErrorRecovery:
    """Test error recovery scenarios"""
    
    def test_recovery_handler_called(self):
        """Test that recovery handler is called"""
        handler = ErrorHandler()
        recovery_called = False
        
        def recovery_func(error):
            nonlocal recovery_called
            recovery_called = True
        
        handler.register_recovery(NetworkError, recovery_func)
        
        error = NetworkError("Timeout")
        handler.handle_error(error)
        
        assert recovery_called is True


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
