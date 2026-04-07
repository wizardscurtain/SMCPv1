"""Audit and Monitoring Layer

Provides logging, monitoring, and forensic capabilities
for SMCP security events.
"""

import json
import logging
import os
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
import threading
from collections import defaultdict, deque
import hashlib

from .exceptions import SecurityError


@dataclass
class AuditConfig:
    """Configuration for audit logging"""
    log_level: str = "INFO"
    max_events_memory: int = 10000
    buffer_size: int = 1000
    enable_file_logging: bool = True
    log_file_path: str = "smcp_audit.log"
    enable_syslog: bool = False
    enable_remote_logging: bool = False
    log_format: str = "json"
    max_log_size_mb: int = 100
    max_log_files: int = 10
    enable_correlation: bool = True
    incident_threshold: int = 5
    cleanup_interval_hours: int = 24


class EventSeverity(Enum):
    """Security event severity levels with ordering support"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    # Map values to integers for ordering
    _order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

    def __lt__(self, other):
        if self.__class__ is other.__class__:
            order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            return order[self.value] < order[other.value]
        return NotImplemented

    def __le__(self, other):
        if self.__class__ is other.__class__:
            return self == other or self < other
        return NotImplemented

    def __gt__(self, other):
        if self.__class__ is other.__class__:
            return other < self
        return NotImplemented

    def __ge__(self, other):
        if self.__class__ is other.__class__:
            return self == other or self > other
        return NotImplemented


class EventCategory(Enum):
    """Security event categories"""
    AUTHENTICATION = "AUTHENTICATION"
    AUTHORIZATION = "AUTHORIZATION"
    INPUT_VALIDATION = "INPUT_VALIDATION"
    RATE_LIMITING = "RATE_LIMITING"
    CRYPTOGRAPHY = "CRYPTOGRAPHY"
    ANOMALY_DETECTION = "ANOMALY_DETECTION"
    SYSTEM = "SYSTEM"
    AUDIT = "AUDIT"
    SECURITY_VIOLATION = "SECURITY_VIOLATION"


class SMCPAuditLogger:
    """Main audit logging system for SMCP"""

    def __init__(self, config: Optional[AuditConfig] = None,
                 log_level: str = "INFO",
                 max_events_memory: int = 10000,
                 enable_file_logging: bool = True,
                 log_file_path: str = "smcp_audit.log"):

        if config is not None:
            self.config = config
        else:
            self.config = AuditConfig(
                log_level=log_level,
                max_events_memory=max_events_memory,
                enable_file_logging=enable_file_logging,
                log_file_path=log_file_path
            )

        # In-memory event storage
        # event_buffer is the canonical in-memory list (used by tests)
        self.event_buffer: List[Dict[str, Any]] = []

        # Thread safety
        self._lock = threading.RLock()

        # Setup file logging
        self._file_handler = None
        if self.config.enable_file_logging:
            self._setup_file_logging(self.config.log_file_path)

        # Setup Python logger (console)
        self._logger = logging.getLogger(f'smcp_audit_{id(self)}')
        self._logger.setLevel(getattr(logging, self.config.log_level.upper(), logging.INFO))
        if not self._logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter(
                '%(asctime)s - SMCP-AUDIT - %(levelname)s - %(message)s'
            ))
            self._logger.addHandler(handler)

        # Metrics
        self._metrics: Dict[str, Any] = {
            "total_events": 0,
            "events_by_severity": defaultdict(int),
            "events_by_category": defaultdict(int),
            "events_by_hour": defaultdict(int),
            "start_time": datetime.utcnow(),
        }

    def _setup_file_logging(self, log_file_path: str):
        """Setup file handler for JSON logging"""
        try:
            self._file_handler = open(log_file_path, 'a', buffering=1)
        except Exception:
            self._file_handler = None

    def _generate_event_id(self) -> str:
        """Generate unique event ID"""
        return str(uuid.uuid4()).replace('-', '')[:16]

    def _severity_order(self, severity: EventSeverity) -> int:
        order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        return order.get(severity.value, 0)

    def log_event(self, category: EventCategory, severity: EventSeverity,
                  message: str, **kwargs) -> str:
        """Log a generic event with arbitrary extra fields.

        Returns event ID.
        """
        event_id = self._generate_event_id()
        timestamp = datetime.utcnow()

        event: Dict[str, Any] = {
            "event_id": event_id,
            "timestamp": timestamp.isoformat(),
            "category": category.value,
            "severity": severity.value,
            "message": message,
        }
        event.update(kwargs)

        with self._lock:
            # Enforce buffer_size limit — keep most recent events
            self.event_buffer.append(event)
            buf = self.config.buffer_size
            if len(self.event_buffer) > buf:
                # Trim oldest
                self.event_buffer = self.event_buffer[-buf:]

            # Update metrics
            self._metrics["total_events"] += 1
            self._metrics["events_by_severity"][severity.value] += 1
            self._metrics["events_by_category"][category.value] += 1
            hour_key = timestamp.strftime("%Y-%m-%dT%H")
            self._metrics["events_by_hour"][hour_key] += 1

        # Write to file if enabled
        if self.config.enable_file_logging and self._file_handler:
            try:
                # Check for rotation
                if hasattr(self, '_check_rotation'):
                    self._check_rotation()
                else:
                    self._maybe_rotate()
                self._file_handler.write(json.dumps(event) + "\n")
                self._file_handler.flush()
            except Exception:
                pass

        return event_id

    def _maybe_rotate(self):
        """Check if log file needs rotation and rotate if necessary."""
        if not self.config.enable_file_logging or not self._file_handler:
            return
        try:
            file_path = self.config.log_file_path
            size = os.path.getsize(file_path)
            max_bytes = self.config.max_log_size_mb * 1024 * 1024
            if size > max_bytes:
                self._rotate_log_file()
        except Exception:
            pass

    def _rotate_log_file(self):
        """Rotate the log file."""
        try:
            if self._file_handler:
                self._file_handler.close()
            log_path = self.config.log_file_path
            rotated_path = log_path + f".{int(time.time())}"
            if os.path.exists(log_path):
                os.rename(log_path, rotated_path)
            self._file_handler = open(log_path, 'a', buffering=1)
        except Exception:
            pass

    def log_security_event(self, event_type: str,
                           user_id: Optional[str] = None,
                           details: Optional[Dict[str, Any]] = None,
                           severity: Union[str, EventSeverity] = EventSeverity.MEDIUM,
                           category: Union[str, EventCategory] = EventCategory.SYSTEM,
                           ip_address: Optional[str] = None,
                           user_agent: Optional[str] = None,
                           session_id: Optional[str] = None,
                           request_id: Optional[str] = None) -> str:
        """Log a security event"""
        if isinstance(severity, str):
            # Map old-style names if needed
            sev_map = {
                "DEBUG": "LOW", "INFO": "LOW", "WARNING": "MEDIUM",
                "ERROR": "HIGH"
            }
            sev_val = sev_map.get(severity.upper(), severity.upper())
            try:
                severity = EventSeverity(sev_val)
            except ValueError:
                severity = EventSeverity.MEDIUM

        if isinstance(category, str):
            try:
                category = EventCategory(category.upper())
            except ValueError:
                category = EventCategory.SYSTEM

        extra: Dict[str, Any] = {"event_type": event_type}
        if user_id is not None:
            extra["user_id"] = user_id
        if ip_address is not None:
            extra["ip_address"] = ip_address
        if user_agent is not None:
            extra["user_agent"] = user_agent
        if session_id is not None:
            extra["session_id"] = session_id
        if request_id is not None:
            extra["request_id"] = request_id
        if details:
            extra.update(details)

        return self.log_event(category=category, severity=severity,
                              message=event_type, **extra)

    def log_security_violation(self, user_id: str = None,
                                violation_type: str = "",
                                details: str = "",
                                ip_address: Optional[str] = None,
                                user_agent: Optional[str] = None,
                                **kwargs) -> str:
        """Log a security violation"""
        extra: Dict[str, Any] = {
            "user_id": user_id,
            "violation_type": violation_type,
            "details": details,
        }
        if ip_address is not None:
            extra["ip_address"] = ip_address
        if user_agent is not None:
            extra["user_agent"] = user_agent
        extra.update(kwargs)

        return self.log_event(
            category=EventCategory.SECURITY_VIOLATION,
            severity=EventSeverity.HIGH,
            message=f"Security violation: {violation_type}",
            **extra
        )

    def log_authentication_event(self, user_id: str,
                                  event_type: str,
                                  success: bool,
                                  ip_address: Optional[str] = None,
                                  failure_reason: Optional[str] = None,
                                  **kwargs) -> str:
        """Log authentication event"""
        severity = EventSeverity.MEDIUM if success else EventSeverity.HIGH

        extra: Dict[str, Any] = {
            "user_id": user_id,
            "event_type": event_type,
            "success": success,
        }
        if ip_address is not None:
            extra["ip_address"] = ip_address
        if failure_reason is not None:
            extra["failure_reason"] = failure_reason
        extra.update(kwargs)

        return self.log_event(
            category=EventCategory.AUTHENTICATION,
            severity=severity,
            message=f"Authentication {event_type}: {'success' if success else 'failure'}",
            **extra
        )

    def log_authorization_event(self, user_id: str,
                                 resource: str,
                                 action: str,
                                 granted: bool,
                                 reason: Optional[str] = None,
                                 ip_address: Optional[str] = None,
                                 **kwargs) -> str:
        """Log authorization event"""
        severity = EventSeverity.LOW if granted else EventSeverity.MEDIUM

        extra: Dict[str, Any] = {
            "user_id": user_id,
            "resource": resource,
            "action": action,
            "granted": granted,
        }
        if reason is not None:
            extra["reason"] = reason
        if ip_address is not None:
            extra["ip_address"] = ip_address
        extra.update(kwargs)

        return self.log_event(
            category=EventCategory.AUTHORIZATION,
            severity=severity,
            message=f"Authorization {'granted' if granted else 'denied'} for {resource}",
            **extra
        )

    def log_system_event(self, event_type: str,
                          component: str = None,
                          details: Any = None,
                          severity: EventSeverity = EventSeverity.LOW,
                          **kwargs) -> str:
        """Log a system event"""
        extra: Dict[str, Any] = {"event_type": event_type}
        if component is not None:
            extra["component"] = component
        if details is not None:
            extra["details"] = details
        extra.update(kwargs)

        return self.log_event(
            category=EventCategory.SYSTEM,
            severity=severity,
            message=f"System event: {event_type}",
            **extra
        )

    def get_events(self, limit: int = None,
                   category: Optional[EventCategory] = None,
                   min_severity: Optional[EventSeverity] = None,
                   severity: Optional[EventSeverity] = None,
                   user_id: Optional[str] = None,
                   start_time: Optional[datetime] = None,
                   end_time: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Get events with filtering.

        When limit is provided: return the oldest `limit` matching events
        in ascending (oldest-first) order.
        When limit is not provided: return all matching events in
        descending (newest-first) order.
        """
        with self._lock:
            events = list(self.event_buffer)

        # Filter by category (accept string or EventCategory enum)
        if category is not None:
            category_val = category if isinstance(category, str) else category.value
            events = [e for e in events if e.get("category") == category_val]

        # Filter by exact severity
        if severity is not None:
            events = [e for e in events if e.get("severity") == severity.value]

        # Filter by min_severity
        if min_severity is not None:
            sev_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            min_ord = sev_order.get(min_severity.value, 0)
            events = [e for e in events
                      if sev_order.get(e.get("severity", "LOW"), 0) >= min_ord]

        # Filter by user_id
        if user_id is not None:
            events = [e for e in events if e.get("user_id") == user_id]

        # Filter by start_time
        if start_time is not None:
            events = [e for e in events
                      if datetime.fromisoformat(e["timestamp"]) >= start_time]

        # Filter by end_time
        if end_time is not None:
            events = [e for e in events
                      if datetime.fromisoformat(e["timestamp"]) <= end_time]

        if limit is not None:
            # Return the oldest `limit` events (ascending order)
            events = events[:limit]
        else:
            # No limit: return all, newest-first
            events = list(reversed(events))

        return events

    def get_statistics(self) -> Dict[str, Any]:
        """Return metrics summary"""
        with self._lock:
            return {
                "total_events": self._metrics["total_events"],
                "events_by_category": dict(self._metrics["events_by_category"]),
                "events_by_severity": dict(self._metrics["events_by_severity"]),
                "events_by_hour": dict(self._metrics["events_by_hour"]),
            }

    def clear_events(self):
        """Clear all events from memory"""
        with self._lock:
            self.event_buffer.clear()

    def flush(self):
        """Flush any pending log entries"""
        if self._file_handler:
            try:
                self._file_handler.flush()
            except Exception:
                pass

    def export_events(self, file_path: str, format: str = "json"):
        """Export events to a file"""
        with self._lock:
            events = list(self.event_buffer)

        if format.lower() == "json":
            with open(file_path, 'w') as f:
                f.write(json.dumps(events, default=str))
        elif format.lower() == "csv":
            import csv
            import io
            output = io.StringIO()
            if events:
                writer = csv.DictWriter(output, fieldnames=list(events[0].keys()))
                writer.writeheader()
                writer.writerows(events)
            with open(file_path, 'w') as f:
                f.write(output.getvalue())
        else:
            raise ValueError(f"Unsupported export format: {format}")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.flush()
        return False

    def close(self):
        """Close file handler"""
        if self._file_handler:
            try:
                self._file_handler.close()
            except Exception:
                pass
            self._file_handler = None
