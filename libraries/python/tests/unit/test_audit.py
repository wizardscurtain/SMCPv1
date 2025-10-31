"""Unit tests for audit logging and monitoring.

Tests the SMCPAuditLogger and monitoring components.
"""

import pytest
import json
import os
import tempfile
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, mock_open

from smcp_security.audit import (
    SMCPAuditLogger, EventSeverity, EventCategory, AuditConfig
)
from smcp_security.exceptions import SecurityError


class TestEventSeverity:
    """Test event severity enumeration."""
    
    @pytest.mark.unit
    @pytest.mark.audit
    def test_severity_levels(self):
        """Test severity level values."""
        assert EventSeverity.LOW.value == "LOW"
        assert EventSeverity.MEDIUM.value == "MEDIUM"
        assert EventSeverity.HIGH.value == "HIGH"
        assert EventSeverity.CRITICAL.value == "CRITICAL"
    
    @pytest.mark.unit
    @pytest.mark.audit
    def test_severity_ordering(self):
        """Test severity level ordering."""
        severities = [EventSeverity.LOW, EventSeverity.MEDIUM, 
                     EventSeverity.HIGH, EventSeverity.CRITICAL]
        
        # Test that severities can be compared
        assert EventSeverity.LOW < EventSeverity.MEDIUM
        assert EventSeverity.MEDIUM < EventSeverity.HIGH
        assert EventSeverity.HIGH < EventSeverity.CRITICAL


class TestEventCategory:
    """Test event category enumeration."""
    
    @pytest.mark.unit
    @pytest.mark.audit
    def test_category_values(self):
        """Test event category values."""
        assert EventCategory.AUTHENTICATION.value == "AUTHENTICATION"
        assert EventCategory.AUTHORIZATION.value == "AUTHORIZATION"
        assert EventCategory.INPUT_VALIDATION.value == "INPUT_VALIDATION"
        assert EventCategory.RATE_LIMITING.value == "RATE_LIMITING"
        assert EventCategory.CRYPTOGRAPHY.value == "CRYPTOGRAPHY"
        assert EventCategory.SYSTEM.value == "SYSTEM"
        assert EventCategory.SECURITY_VIOLATION.value == "SECURITY_VIOLATION"


class TestAuditConfig:
    """Test audit configuration."""
    
    @pytest.mark.unit
    @pytest.mark.audit
    def test_default_config_creation(self):
        """Test creation of default audit config."""
        config = AuditConfig()
        
        assert config.log_level == "INFO"
        assert config.enable_file_logging is True
        assert config.enable_syslog is False
        assert config.enable_remote_logging is False
        assert config.log_format == "json"
        assert config.max_log_size_mb == 100
        assert config.max_log_files == 10
        assert config.buffer_size == 1000
    
    @pytest.mark.unit
    @pytest.mark.audit
    def test_custom_config_creation(self):
        """Test creation of custom audit config."""
        config = AuditConfig(
            log_level="DEBUG",
            enable_file_logging=False,
            enable_syslog=True,
            log_format="text",
            max_log_size_mb=50,
            buffer_size=500
        )
        
        assert config.log_level == "DEBUG"
        assert config.enable_file_logging is False
        assert config.enable_syslog is True
        assert config.log_format == "text"
        assert config.max_log_size_mb == 50
        assert config.buffer_size == 500


class TestSMCPAuditLogger:
    """Test SMCP audit logger functionality."""
    
    @pytest.fixture
    def temp_log_file(self):
        """Create temporary log file for testing."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
            temp_path = f.name
        yield temp_path
        # Cleanup
        if os.path.exists(temp_path):
            os.unlink(temp_path)
    
    @pytest.fixture
    def audit_logger(self, temp_log_file):
        """Create audit logger with temporary file."""
        config = AuditConfig(
            log_file_path=temp_log_file,
            enable_file_logging=True,
            log_level="DEBUG"
        )
        return SMCPAuditLogger(config)
    
    @pytest.fixture
    def memory_audit_logger(self):
        """Create audit logger that only logs to memory."""
        config = AuditConfig(
            enable_file_logging=False,
            enable_syslog=False,
            log_level="DEBUG"
        )
        return SMCPAuditLogger(config)
    
    @pytest.mark.unit
    @pytest.mark.audit
    def test_audit_logger_initialization(self, audit_logger):
        """Test audit logger initialization."""
        assert audit_logger.config.log_level == "DEBUG"
        assert isinstance(audit_logger.event_buffer, list)
        assert len(audit_logger.event_buffer) == 0
    
    @pytest.mark.unit
    @pytest.mark.audit
    def test_log_event_basic(self, memory_audit_logger):
        """Test basic event logging."""
        event_data = {
            "user_id": "test_user",
            "action": "login_attempt",
            "result": "success"
        }
        
        memory_audit_logger.log_event(
            category=EventCategory.AUTHENTICATION,
            severity=EventSeverity.MEDIUM,
            message="User login successful",
            **event_data
        )
        
        # Check event was logged
        events = memory_audit_logger.get_events(limit=1)
        assert len(events) == 1
        
        event = events[0]
        assert event["category"] == "AUTHENTICATION"
        assert event["severity"] == "MEDIUM"
        assert event["message"] == "User login successful"
        assert event["user_id"] == "test_user"
        assert event["action"] == "login_attempt"
        assert event["result"] == "success"
        assert "timestamp" in event
        assert "event_id" in event
    
    @pytest.mark.unit
    @pytest.mark.audit
    def test_log_security_violation(self, memory_audit_logger):
        """Test logging security violations."""
        memory_audit_logger.log_security_violation(
            user_id="malicious_user",
            violation_type="command_injection",
            details="Attempted command injection in request",
            ip_address="192.168.1.100",
            user_agent="curl/7.68.0"
        )
        
        events = memory_audit_logger.get_events(limit=1)
        event = events[0]
        
        assert event["category"] == "SECURITY_VIOLATION"
        assert event["severity"] == "HIGH"
        assert event["violation_type"] == "command_injection"
        assert event["ip_address"] == "192.168.1.100"
    
    @pytest.mark.unit
    @pytest.mark.audit
    def test_log_authentication_event(self, memory_audit_logger):
        """Test logging authentication events."""
        # Successful login
        memory_audit_logger.log_authentication_event(
            user_id="test_user",
            event_type="login",
            success=True,
            ip_address="192.168.1.100"
        )
        
        # Failed login
        memory_audit_logger.log_authentication_event(
            user_id="test_user",
            event_type="login",
            success=False,
            ip_address="192.168.1.100",
            failure_reason="invalid_password"
        )
        
        events = memory_audit_logger.get_events(limit=2)
        
        # Check successful login
        success_event = events[0]
        assert success_event["category"] == "AUTHENTICATION"
        assert success_event["event_type"] == "login"
        assert success_event["success"] is True
        assert success_event["severity"] == "MEDIUM"
        
        # Check failed login
        failure_event = events[1]
        assert failure_event["success"] is False
        assert failure_event["failure_reason"] == "invalid_password"
        assert failure_event["severity"] == "HIGH"
    
    @pytest.mark.unit
    @pytest.mark.audit
    def test_log_authorization_event(self, memory_audit_logger):
        """Test logging authorization events."""
        memory_audit_logger.log_authorization_event(
            user_id="test_user",
            resource="sensitive_data",
            action="read",
            granted=False,
            reason="insufficient_permissions"
        )
        
        events = memory_audit_logger.get_events(limit=1)
        event = events[0]
        
        assert event["category"] == "AUTHORIZATION"
        assert event["resource"] == "sensitive_data"
        assert event["action"] == "read"
        assert event["granted"] is False
        assert event["reason"] == "insufficient_permissions"
        assert event["severity"] == "MEDIUM"
    
    @pytest.mark.unit
    @pytest.mark.audit
    def test_log_system_event(self, memory_audit_logger):
        """Test logging system events."""
        memory_audit_logger.log_system_event(
            event_type="service_start",
            component="smcp_security",
            details="Security framework initialized"
        )
        
        events = memory_audit_logger.get_events(limit=1)
        event = events[0]
        
        assert event["category"] == "SYSTEM"
        assert event["event_type"] == "service_start"
        assert event["component"] == "smcp_security"
        assert event["details"] == "Security framework initialized"
    
    @pytest.mark.unit
    @pytest.mark.audit
    def test_event_filtering_by_category(self, memory_audit_logger):
        """Test filtering events by category."""
        # Log different types of events
        memory_audit_logger.log_authentication_event(
            user_id="user1", event_type="login", success=True
        )
        memory_audit_logger.log_authorization_event(
            user_id="user1", resource="data", action="read", granted=True
        )
        memory_audit_logger.log_system_event(
            event_type="config_change", component="auth"
        )
        
        # Filter by authentication events
        auth_events = memory_audit_logger.get_events(
            category=EventCategory.AUTHENTICATION
        )
        assert len(auth_events) == 1
        assert auth_events[0]["category"] == "AUTHENTICATION"
        
        # Filter by system events
        system_events = memory_audit_logger.get_events(
            category=EventCategory.SYSTEM
        )
        assert len(system_events) == 1
        assert system_events[0]["category"] == "SYSTEM"
    
    @pytest.mark.unit
    @pytest.mark.audit
    def test_event_filtering_by_severity(self, memory_audit_logger):
        """Test filtering events by severity."""
        # Log events with different severities
        memory_audit_logger.log_event(
            category=EventCategory.SYSTEM,
            severity=EventSeverity.LOW,
            message="Low severity event"
        )
        memory_audit_logger.log_event(
            category=EventCategory.SYSTEM,
            severity=EventSeverity.HIGH,
            message="High severity event"
        )
        memory_audit_logger.log_event(
            category=EventCategory.SYSTEM,
            severity=EventSeverity.CRITICAL,
            message="Critical severity event"
        )
        
        # Filter by high severity and above
        high_severity_events = memory_audit_logger.get_events(
            min_severity=EventSeverity.HIGH
        )
        assert len(high_severity_events) == 2
        
        # Filter by critical severity only
        critical_events = memory_audit_logger.get_events(
            min_severity=EventSeverity.CRITICAL
        )
        assert len(critical_events) == 1
        assert critical_events[0]["severity"] == "CRITICAL"
    
    @pytest.mark.unit
    @pytest.mark.audit
    def test_event_filtering_by_time_range(self, memory_audit_logger):
        """Test filtering events by time range."""
        now = datetime.utcnow()
        
        with patch('smcp_security.audit.datetime') as mock_datetime:
            # Log event 2 hours ago
            mock_datetime.utcnow.return_value = now - timedelta(hours=2)
            memory_audit_logger.log_event(
                category=EventCategory.SYSTEM,
                severity=EventSeverity.MEDIUM,
                message="Old event"
            )
            
            # Log event 1 hour ago
            mock_datetime.utcnow.return_value = now - timedelta(hours=1)
            memory_audit_logger.log_event(
                category=EventCategory.SYSTEM,
                severity=EventSeverity.MEDIUM,
                message="Recent event"
            )
            
            # Log current event
            mock_datetime.utcnow.return_value = now
            memory_audit_logger.log_event(
                category=EventCategory.SYSTEM,
                severity=EventSeverity.MEDIUM,
                message="Current event"
            )
        
        # Filter events from last 90 minutes
        recent_events = memory_audit_logger.get_events(
            start_time=now - timedelta(minutes=90)
        )
        assert len(recent_events) == 2
        
        # Filter events from last 30 minutes
        very_recent_events = memory_audit_logger.get_events(
            start_time=now - timedelta(minutes=30)
        )
        assert len(very_recent_events) == 1
        assert very_recent_events[0]["message"] == "Current event"
    
    @pytest.mark.unit
    @pytest.mark.audit
    def test_event_filtering_by_user(self, memory_audit_logger):
        """Test filtering events by user ID."""
        # Log events for different users
        memory_audit_logger.log_authentication_event(
            user_id="user1", event_type="login", success=True
        )
        memory_audit_logger.log_authentication_event(
            user_id="user2", event_type="login", success=True
        )
        memory_audit_logger.log_authentication_event(
            user_id="user1", event_type="logout", success=True
        )
        
        # Filter events for user1
        user1_events = memory_audit_logger.get_events(user_id="user1")
        assert len(user1_events) == 2
        for event in user1_events:
            assert event["user_id"] == "user1"
        
        # Filter events for user2
        user2_events = memory_audit_logger.get_events(user_id="user2")
        assert len(user2_events) == 1
        assert user2_events[0]["user_id"] == "user2"
    
    @pytest.mark.unit
    @pytest.mark.audit
    def test_event_buffer_management(self, memory_audit_logger):
        """Test event buffer size management."""
        # Set small buffer size for testing
        memory_audit_logger.config.buffer_size = 5
        
        # Log more events than buffer size
        for i in range(10):
            memory_audit_logger.log_event(
                category=EventCategory.SYSTEM,
                severity=EventSeverity.LOW,
                message=f"Event {i}"
            )
        
        # Should only keep the most recent events
        events = memory_audit_logger.get_events()
        assert len(events) <= 5
        
        # Should have the most recent events
        assert "Event 9" in events[0]["message"]
    
    @pytest.mark.unit
    @pytest.mark.audit
    def test_file_logging(self, audit_logger, temp_log_file):
        """Test logging to file."""
        audit_logger.log_event(
            category=EventCategory.SYSTEM,
            severity=EventSeverity.MEDIUM,
            message="Test file logging",
            test_data="file_test"
        )
        
        # Flush to ensure write
        audit_logger.flush()
        
        # Check file contents
        assert os.path.exists(temp_log_file)
        with open(temp_log_file, 'r') as f:
            content = f.read()
            assert "Test file logging" in content
            assert "file_test" in content
    
    @pytest.mark.unit
    @pytest.mark.audit
    def test_json_log_format(self, audit_logger, temp_log_file):
        """Test JSON log format."""
        audit_logger.log_event(
            category=EventCategory.AUTHENTICATION,
            severity=EventSeverity.HIGH,
            message="JSON format test",
            user_id="test_user"
        )
        
        audit_logger.flush()
        
        # Read and parse JSON
        with open(temp_log_file, 'r') as f:
            line = f.readline().strip()
            log_entry = json.loads(line)
            
            assert log_entry["category"] == "AUTHENTICATION"
            assert log_entry["severity"] == "HIGH"
            assert log_entry["message"] == "JSON format test"
            assert log_entry["user_id"] == "test_user"
            assert "timestamp" in log_entry
            assert "event_id" in log_entry
    
    @pytest.mark.unit
    @pytest.mark.audit
    def test_log_rotation(self, audit_logger):
        """Test log file rotation."""
        # Mock file size check to trigger rotation
        with patch('os.path.getsize') as mock_getsize:
            mock_getsize.return_value = 100 * 1024 * 1024 + 1  # Exceed max size
            
            with patch.object(audit_logger, '_rotate_log_file') as mock_rotate:
                audit_logger.log_event(
                    category=EventCategory.SYSTEM,
                    severity=EventSeverity.LOW,
                    message="Rotation test"
                )
                
                # Should trigger rotation
                mock_rotate.assert_called_once()
    
    @pytest.mark.unit
    @pytest.mark.audit
    def test_get_statistics(self, memory_audit_logger):
        """Test getting audit statistics."""
        # Log various events
        memory_audit_logger.log_authentication_event(
            user_id="user1", event_type="login", success=True
        )
        memory_audit_logger.log_authentication_event(
            user_id="user2", event_type="login", success=False
        )
        memory_audit_logger.log_security_violation(
            user_id="user3", violation_type="injection", details="Test"
        )
        memory_audit_logger.log_system_event(
            event_type="startup", component="auth"
        )
        
        stats = memory_audit_logger.get_statistics()
        
        assert "total_events" in stats
        assert "events_by_category" in stats
        assert "events_by_severity" in stats
        assert "events_by_hour" in stats
        
        assert stats["total_events"] == 4
        assert stats["events_by_category"]["AUTHENTICATION"] == 2
        assert stats["events_by_category"]["SECURITY_VIOLATION"] == 1
        assert stats["events_by_category"]["SYSTEM"] == 1
    
    @pytest.mark.unit
    @pytest.mark.audit
    def test_export_events(self, memory_audit_logger, temp_log_file):
        """Test exporting events to file."""
        # Log some events
        for i in range(3):
            memory_audit_logger.log_event(
                category=EventCategory.SYSTEM,
                severity=EventSeverity.MEDIUM,
                message=f"Export test event {i}"
            )
        
        # Export to file
        memory_audit_logger.export_events(temp_log_file, format="json")
        
        # Verify export
        assert os.path.exists(temp_log_file)
        with open(temp_log_file, 'r') as f:
            content = f.read()
            assert "Export test event 0" in content
            assert "Export test event 1" in content
            assert "Export test event 2" in content
    
    @pytest.mark.unit
    @pytest.mark.audit
    def test_clear_events(self, memory_audit_logger):
        """Test clearing events from buffer."""
        # Log some events
        for i in range(5):
            memory_audit_logger.log_event(
                category=EventCategory.SYSTEM,
                severity=EventSeverity.LOW,
                message=f"Clear test event {i}"
            )
        
        # Verify events exist
        events = memory_audit_logger.get_events()
        assert len(events) == 5
        
        # Clear events
        memory_audit_logger.clear_events()
        
        # Verify events are cleared
        events = memory_audit_logger.get_events()
        assert len(events) == 0
    
    @pytest.mark.unit
    @pytest.mark.audit
    def test_context_manager(self, memory_audit_logger):
        """Test using audit logger as context manager."""
        with memory_audit_logger as logger:
            logger.log_event(
                category=EventCategory.SYSTEM,
                severity=EventSeverity.MEDIUM,
                message="Context manager test"
            )
        
        # Event should be logged and flushed
        events = memory_audit_logger.get_events()
        assert len(events) == 1
        assert events[0]["message"] == "Context manager test"
    
    @pytest.mark.unit
    @pytest.mark.audit
    def test_thread_safety(self, memory_audit_logger):
        """Test thread safety of audit logger."""
        import threading
        import time
        
        def log_events(thread_id):
            for i in range(10):
                memory_audit_logger.log_event(
                    category=EventCategory.SYSTEM,
                    severity=EventSeverity.LOW,
                    message=f"Thread {thread_id} event {i}",
                    thread_id=thread_id
                )
                time.sleep(0.001)  # Small delay
        
        # Start multiple threads
        threads = []
        for i in range(3):
            thread = threading.Thread(target=log_events, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Should have all events from all threads
        events = memory_audit_logger.get_events()
        assert len(events) == 30  # 3 threads * 10 events each
        
        # Verify events from each thread
        for thread_id in range(3):
            thread_events = [e for e in events if e.get("thread_id") == thread_id]
            assert len(thread_events) == 10
    
    @pytest.mark.unit
    @pytest.mark.audit
    @pytest.mark.performance
    def test_logging_performance(self, memory_audit_logger, benchmark):
        """Test audit logging performance."""
        def log_batch_events():
            for i in range(100):
                memory_audit_logger.log_event(
                    category=EventCategory.SYSTEM,
                    severity=EventSeverity.MEDIUM,
                    message=f"Performance test event {i}",
                    event_number=i
                )
        
        # Benchmark logging performance
        result = benchmark(log_batch_events)
        
        # Verify all events were logged
        events = memory_audit_logger.get_events()
        assert len(events) >= 100
