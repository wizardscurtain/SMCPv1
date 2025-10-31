"""Audit and Monitoring Layer

Provides logging, monitoring, and forensic capabilities
for SMCP security events.
"""

import json
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass, asdict
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
    enable_file_logging: bool = True
    log_file_path: str = "smcp_audit.log"
    enable_correlation: bool = True
    incident_threshold: int = 5
    cleanup_interval_hours: int = 24


class EventSeverity(Enum):
    """Security event severity levels"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class EventCategory(Enum):
    """Security event categories"""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    INPUT_VALIDATION = "input_validation"
    RATE_LIMITING = "rate_limiting"
    CRYPTOGRAPHY = "cryptography"
    ANOMALY_DETECTION = "anomaly_detection"
    SYSTEM = "system"
    AUDIT = "audit"


@dataclass
class SecurityEvent:
    """Represents a security event"""
    timestamp: datetime
    event_id: str
    category: EventCategory
    severity: EventSeverity
    user_id: Optional[str]
    ip_address: Optional[str]
    user_agent: Optional[str]
    event_type: str
    description: str
    details: Dict[str, Any]
    source_component: str
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary"""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        data['category'] = self.category.value
        data['severity'] = self.severity.value
        return data
    
    def to_json(self) -> str:
        """Convert event to JSON string"""
        return json.dumps(self.to_dict())


class SMCPAuditLogger:
    """Main audit logging system for SMCP"""
    
    def __init__(self, config: Optional[AuditConfig] = None, 
                 log_level: str = "INFO", 
                 max_events_memory: int = 10000,
                 enable_file_logging: bool = True,
                 log_file_path: str = "smcp_audit.log"):
        
        if config is not None:
            self.config = config
            self.log_level = getattr(logging, config.log_level.upper())
            self.max_events_memory = config.max_events_memory
            self.enable_file_logging = config.enable_file_logging
            log_file_path = config.log_file_path
        else:
            self.config = AuditConfig(log_level=log_level, max_events_memory=max_events_memory,
                                    enable_file_logging=enable_file_logging, log_file_path=log_file_path)
            self.log_level = getattr(logging, log_level.upper())
            self.max_events_memory = max_events_memory
            self.enable_file_logging = enable_file_logging
        
        # In-memory event storage for real-time analysis
        self.recent_events: deque = deque(maxlen=max_events_memory)
        self.event_counts = defaultdict(int)
        self.user_activity = defaultdict(list)
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Setup logging
        self._setup_logging(log_file_path)
        
        # Event correlation
        self.correlation_rules = []
        self.active_incidents = {}
        
        # Metrics
        self.metrics = {
            "total_events": 0,
            "events_by_severity": defaultdict(int),
            "events_by_category": defaultdict(int),
            "start_time": datetime.utcnow()
        }
    
    def _setup_logging(self, log_file_path: str):
        """Setup Python logging configuration"""
        self.logger = logging.getLogger('smcp_audit')
        self.logger.setLevel(self.log_level)
        
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_formatter = logging.Formatter(
            '%(asctime)s - SMCP-AUDIT - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
        
        # File handler (if enabled)
        if self.enable_file_logging:
            try:
                file_handler = logging.FileHandler(log_file_path)
                file_formatter = logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                )
                file_handler.setFormatter(file_formatter)
                self.logger.addHandler(file_handler)
            except Exception as e:
                self.logger.warning(f"Could not setup file logging: {e}")
    
    def log_security_event(self, event_type: str, user_id: Optional[str],
                          details: Dict[str, Any], 
                          severity: Union[str, EventSeverity] = EventSeverity.INFO,
                          category: Union[str, EventCategory] = EventCategory.SYSTEM,
                          ip_address: Optional[str] = None,
                          user_agent: Optional[str] = None,
                          session_id: Optional[str] = None,
                          request_id: Optional[str] = None) -> str:
        """Log a security event
        
        Args:
            event_type: Type of event
            user_id: User ID associated with event
            details: Event details dictionary
            severity: Event severity
            category: Event category
            ip_address: Client IP address
            user_agent: Client user agent
            session_id: Session identifier
            request_id: Request identifier
            
        Returns:
            Event ID
        """
        # Convert string enums to enum objects
        if isinstance(severity, str):
            severity = EventSeverity(severity.upper())
        if isinstance(category, str):
            category = EventCategory(category.lower())
        
        # Generate event ID
        event_id = self._generate_event_id()
        
        # Create event
        event = SecurityEvent(
            timestamp=datetime.utcnow(),
            event_id=event_id,
            category=category,
            severity=severity,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            event_type=event_type,
            description=self._generate_description(event_type, details),
            details=details,
            source_component="smcp_security",
            session_id=session_id,
            request_id=request_id
        )
        
        # Store and process event
        with self._lock:
            self._store_event(event)
            self._update_metrics(event)
            self._check_correlation_rules(event)
        
        # Log to Python logger
        log_message = f"[{event_id}] {event.description} | User: {user_id} | Details: {json.dumps(details)}"
        
        if severity == EventSeverity.CRITICAL:
            self.logger.critical(log_message)
        elif severity == EventSeverity.ERROR:
            self.logger.error(log_message)
        elif severity == EventSeverity.WARNING:
            self.logger.warning(log_message)
        elif severity == EventSeverity.DEBUG:
            self.logger.debug(log_message)
        else:
            self.logger.info(log_message)
        
        return event_id
    
    def _generate_event_id(self) -> str:
        """Generate unique event ID"""
        timestamp = str(time.time()).encode()
        random_data = str(time.time_ns()).encode()
        return hashlib.sha256(timestamp + random_data).hexdigest()[:16]
    
    def _generate_description(self, event_type: str, details: Dict[str, Any]) -> str:
        """Generate human-readable event description"""
        descriptions = {
            "authentication_success": "User successfully authenticated",
            "authentication_failure": "Authentication attempt failed",
            "authorization_granted": "Authorization granted for resource access",
            "authorization_denied": "Authorization denied for resource access",
            "input_validation_failed": "Input validation failed",
            "rate_limit_exceeded": "Rate limit exceeded",
            "anomaly_detected": "Anomalous behavior detected",
            "encryption_operation": "Cryptographic operation performed",
            "key_rotation": "Cryptographic key rotated",
            "mcp_request": "MCP request processed",
            "security_violation": "Security violation detected",
            "system_startup": "SMCP security system started",
            "system_shutdown": "SMCP security system shutdown"
        }
        
        base_description = descriptions.get(event_type, f"Security event: {event_type}")
        
        # Add context from details
        if "error" in details:
            base_description += f" (Error: {details['error']})"
        elif "status" in details:
            base_description += f" (Status: {details['status']})"
        
        return base_description
    
    def _store_event(self, event: SecurityEvent):
        """Store event in memory and update indices"""
        self.recent_events.append(event)
        
        # Update event counts
        self.event_counts[event.event_type] += 1
        
        # Update user activity
        if event.user_id:
            self.user_activity[event.user_id].append({
                "timestamp": event.timestamp,
                "event_type": event.event_type,
                "severity": event.severity,
                "event_id": event.event_id
            })
            
            # Limit user activity history
            if len(self.user_activity[event.user_id]) > 1000:
                self.user_activity[event.user_id] = self.user_activity[event.user_id][-1000:]
    
    def _update_metrics(self, event: SecurityEvent):
        """Update audit metrics"""
        self.metrics["total_events"] += 1
        self.metrics["events_by_severity"][event.severity.value] += 1
        self.metrics["events_by_category"][event.category.value] += 1
    
    def _check_correlation_rules(self, event: SecurityEvent):
        """Check event against correlation rules for incident detection"""
        # Example correlation rules
        
        # Multiple failed authentication attempts
        if event.event_type == "authentication_failure" and event.user_id:
            recent_failures = self._get_recent_events_for_user(
                event.user_id, "authentication_failure", minutes=5
            )
            
            if len(recent_failures) >= 5:
                self._create_incident(
                    "multiple_auth_failures",
                    f"Multiple authentication failures for user {event.user_id}",
                    EventSeverity.WARNING,
                    related_events=[e.event_id for e in recent_failures]
                )
        
        # Rapid rate limit violations
        if event.event_type == "rate_limit_exceeded":
            recent_violations = self._get_recent_events(
                "rate_limit_exceeded", minutes=1
            )
            
            if len(recent_violations) >= 10:
                self._create_incident(
                    "dos_attack_suspected",
                    "Possible DoS attack detected - multiple rate limit violations",
                    EventSeverity.CRITICAL,
                    related_events=[e.event_id for e in recent_violations]
                )
    
    def _get_recent_events_for_user(self, user_id: str, event_type: str, 
                                   minutes: int) -> List[SecurityEvent]:
        """Get recent events for a specific user"""
        cutoff_time = datetime.utcnow() - timedelta(minutes=minutes)
        
        return [
            event for event in self.recent_events
            if (event.user_id == user_id and 
                event.event_type == event_type and
                event.timestamp >= cutoff_time)
        ]
    
    def _get_recent_events(self, event_type: str, minutes: int) -> List[SecurityEvent]:
        """Get recent events of a specific type"""
        cutoff_time = datetime.utcnow() - timedelta(minutes=minutes)
        
        return [
            event for event in self.recent_events
            if (event.event_type == event_type and
                event.timestamp >= cutoff_time)
        ]
    
    def _create_incident(self, incident_type: str, description: str,
                        severity: EventSeverity, related_events: List[str]):
        """Create a security incident"""
        incident_id = self._generate_event_id()
        
        incident = {
            "incident_id": incident_id,
            "incident_type": incident_type,
            "description": description,
            "severity": severity,
            "created_at": datetime.utcnow(),
            "related_events": related_events,
            "status": "active"
        }
        
        self.active_incidents[incident_id] = incident
        
        # Log the incident
        self.log_security_event(
            "security_incident",
            None,
            {
                "incident_id": incident_id,
                "incident_type": incident_type,
                "related_events_count": len(related_events)
            },
            severity=severity,
            category=EventCategory.AUDIT
        )
    
    def log_authentication_event(self, user_id: str, success: bool, 
                               method: str, ip_address: Optional[str] = None,
                               user_agent: Optional[str] = None,
                               session_id: Optional[str] = None,
                               additional_details: Dict[str, Any] = None) -> str:
        """Log authentication event
        
        Args:
            user_id: User ID
            success: Whether authentication succeeded
            method: Authentication method used
            ip_address: Client IP address
            user_agent: Client user agent
            session_id: Session ID
            additional_details: Additional event details
            
        Returns:
            Event ID
        """
        details = {
            "method": method,
            "success": success,
            **(additional_details or {})
        }
        
        event_type = "authentication_success" if success else "authentication_failure"
        severity = EventSeverity.INFO if success else EventSeverity.WARNING
        
        return self.log_security_event(
            event_type, user_id, details, severity,
            EventCategory.AUTHENTICATION, ip_address, user_agent, session_id
        )
    
    def log_authorization_event(self, user_id: str, resource: str, 
                              permission: str, granted: bool,
                              ip_address: Optional[str] = None,
                              session_id: Optional[str] = None) -> str:
        """Log authorization event
        
        Args:
            user_id: User ID
            resource: Resource being accessed
            permission: Permission being checked
            granted: Whether access was granted
            ip_address: Client IP address
            session_id: Session ID
            
        Returns:
            Event ID
        """
        details = {
            "resource": resource,
            "permission": permission,
            "granted": granted
        }
        
        event_type = "authorization_granted" if granted else "authorization_denied"
        severity = EventSeverity.INFO if granted else EventSeverity.WARNING
        
        return self.log_security_event(
            event_type, user_id, details, severity,
            EventCategory.AUTHORIZATION, ip_address, None, session_id
        )
    
    def get_events(self, limit: int = 100, 
                  severity: Optional[EventSeverity] = None,
                  category: Optional[EventCategory] = None,
                  user_id: Optional[str] = None,
                  since: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Get events with filtering
        
        Args:
            limit: Maximum number of events to return
            severity: Filter by severity
            category: Filter by category
            user_id: Filter by user ID
            since: Filter events since this timestamp
            
        Returns:
            List of event dictionaries
        """
        with self._lock:
            events = list(self.recent_events)
        
        # Apply filters
        if severity:
            events = [e for e in events if e.severity == severity]
        
        if category:
            events = [e for e in events if e.category == category]
        
        if user_id:
            events = [e for e in events if e.user_id == user_id]
        
        if since:
            events = [e for e in events if e.timestamp >= since]
        
        # Sort by timestamp (newest first) and limit
        events.sort(key=lambda e: e.timestamp, reverse=True)
        events = events[:limit]
        
        return [event.to_dict() for event in events]
    
    def get_user_activity(self, user_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Get activity history for a user
        
        Args:
            user_id: User ID
            limit: Maximum number of activities to return
            
        Returns:
            List of user activities
        """
        with self._lock:
            activities = self.user_activity.get(user_id, [])
        
        # Sort by timestamp (newest first) and limit
        activities = sorted(activities, key=lambda a: a["timestamp"], reverse=True)
        return activities[:limit]
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get audit system metrics
        
        Returns:
            Dictionary with metrics
        """
        with self._lock:
            uptime = datetime.utcnow() - self.metrics["start_time"]
            
            return {
                "total_events": self.metrics["total_events"],
                "events_by_severity": dict(self.metrics["events_by_severity"]),
                "events_by_category": dict(self.metrics["events_by_category"]),
                "uptime_seconds": uptime.total_seconds(),
                "events_in_memory": len(self.recent_events),
                "active_incidents": len(self.active_incidents),
                "unique_users": len(self.user_activity),
                "events_per_second": self.metrics["total_events"] / max(1, uptime.total_seconds())
            }
    
    def get_incidents(self, status: str = "active") -> List[Dict[str, Any]]:
        """Get security incidents
        
        Args:
            status: Filter by incident status
            
        Returns:
            List of incidents
        """
        with self._lock:
            incidents = [
                incident for incident in self.active_incidents.values()
                if incident["status"] == status
            ]
        
        # Convert datetime objects to ISO strings
        for incident in incidents:
            incident["created_at"] = incident["created_at"].isoformat()
        
        return incidents
    
    def resolve_incident(self, incident_id: str, resolution_notes: str = ""):
        """Resolve a security incident
        
        Args:
            incident_id: Incident ID to resolve
            resolution_notes: Notes about the resolution
        """
        with self._lock:
            if incident_id in self.active_incidents:
                self.active_incidents[incident_id]["status"] = "resolved"
                self.active_incidents[incident_id]["resolved_at"] = datetime.utcnow()
                self.active_incidents[incident_id]["resolution_notes"] = resolution_notes
                
                # Log resolution
                self.log_security_event(
                    "incident_resolved",
                    None,
                    {
                        "incident_id": incident_id,
                        "resolution_notes": resolution_notes
                    },
                    EventSeverity.INFO,
                    EventCategory.AUDIT
                )
    
    def export_events(self, format: str = "json", 
                     since: Optional[datetime] = None,
                     until: Optional[datetime] = None) -> str:
        """Export events for external analysis
        
        Args:
            format: Export format (json, csv)
            since: Export events since this timestamp
            until: Export events until this timestamp
            
        Returns:
            Exported data as string
        """
        with self._lock:
            events = list(self.recent_events)
        
        # Apply time filters
        if since:
            events = [e for e in events if e.timestamp >= since]
        
        if until:
            events = [e for e in events if e.timestamp <= until]
        
        if format.lower() == "json":
            return json.dumps([event.to_dict() for event in events], indent=2)
        elif format.lower() == "csv":
            # Simple CSV export
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Header
            writer.writerow([
                "timestamp", "event_id", "category", "severity", 
                "user_id", "event_type", "description", "ip_address"
            ])
            
            # Data
            for event in events:
                writer.writerow([
                    event.timestamp.isoformat(),
                    event.event_id,
                    event.category.value,
                    event.severity.value,
                    event.user_id or "",
                    event.event_type,
                    event.description,
                    event.ip_address or ""
                ])
            
            return output.getvalue()
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    def clear_old_events(self, older_than_hours: int = 24):
        """Clear events older than specified hours
        
        Args:
            older_than_hours: Remove events older than this many hours
        """
        cutoff_time = datetime.utcnow() - timedelta(hours=older_than_hours)
        
        with self._lock:
            # Filter recent events
            self.recent_events = deque(
                [e for e in self.recent_events if e.timestamp >= cutoff_time],
                maxlen=self.max_events_memory
            )
            
            # Clean user activity
            for user_id in list(self.user_activity.keys()):
                self.user_activity[user_id] = [
                    activity for activity in self.user_activity[user_id]
                    if activity["timestamp"] >= cutoff_time
                ]
                
                # Remove empty user activity lists
                if not self.user_activity[user_id]:
                    del self.user_activity[user_id]
    
    def flush(self):
        """Flush any pending log entries"""
        # Force flush all handlers
        for handler in self.logger.handlers:
            handler.flush()
    
    def log_security_violation(self, violation_type: str, user_id: str, 
                             details: Dict[str, Any], severity: str = "WARNING"):
        """Log a security violation (alias for log_security_event)"""
        return self.log_security_event(
            violation_type, user_id, details, 
            EventSeverity(severity.upper()), EventCategory.SYSTEM
        )