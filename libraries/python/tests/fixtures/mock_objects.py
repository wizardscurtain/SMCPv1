"""Mock objects and test doubles for SMCP v1 testing.

This module provides mock implementations of external dependencies
and complex components for isolated testing.
"""

import time
import random
from typing import Dict, Any, List, Optional, Union
from unittest.mock import Mock, MagicMock
from dataclasses import dataclass
import numpy as np


class MockMLModel:
    """Mock machine learning model for testing AI immune system."""
    
    def __init__(self, contamination: float = 0.1, random_state: int = 42):
        self.contamination = contamination
        self.random_state = random_state
        self.is_fitted = False
        self.training_data = None
        random.seed(random_state)
    
    def fit(self, X):
        """Mock fit method."""
        self.training_data = X
        self.is_fitted = True
        return self
    
    def predict(self, X):
        """Mock predict method - returns mostly normal (1) with some anomalies (-1)."""
        if not self.is_fitted:
            raise ValueError("Model must be fitted before prediction")
        
        n_samples = len(X) if hasattr(X, '__len__') else 1
        predictions = []
        
        for _ in range(n_samples):
            # Simulate anomaly detection with contamination rate
            if random.random() < self.contamination:
                predictions.append(-1)  # Anomaly
            else:
                predictions.append(1)   # Normal
        
        return np.array(predictions) if hasattr(X, '__len__') else predictions[0]
    
    def decision_function(self, X):
        """Mock decision function - returns anomaly scores."""
        if not self.is_fitted:
            raise ValueError("Model must be fitted before prediction")
        
        n_samples = len(X) if hasattr(X, '__len__') else 1
        scores = []
        
        for _ in range(n_samples):
            # Generate random scores between -1 and 1
            # Negative scores indicate anomalies
            score = random.uniform(-1, 1)
            scores.append(score)
        
        return np.array(scores) if hasattr(X, '__len__') else scores[0]


class MockStandardScaler:
    """Mock StandardScaler for testing."""
    
    def __init__(self):
        self.mean_ = None
        self.scale_ = None
        self.is_fitted = False
    
    def fit(self, X):
        """Mock fit method."""
        self.mean_ = np.mean(X, axis=0) if hasattr(X, 'shape') else 0
        self.scale_ = np.std(X, axis=0) if hasattr(X, 'shape') else 1
        self.is_fitted = True
        return self
    
    def transform(self, X):
        """Mock transform method."""
        if not self.is_fitted:
            raise ValueError("Scaler must be fitted before transform")
        
        # Simple normalization
        if hasattr(X, 'shape'):
            return (X - self.mean_) / (self.scale_ + 1e-8)
        else:
            return X  # Return as-is for simple cases
    
    def fit_transform(self, X):
        """Mock fit_transform method."""
        return self.fit(X).transform(X)


class MockCryptoProvider:
    """Mock cryptographic provider for testing."""
    
    def __init__(self):
        self.keys = {}
        self.encrypted_data = {}
    
    def generate_key(self) -> bytes:
        """Generate a mock key."""
        return b'mock_key_32_bytes_long_for_test'
    
    def encrypt(self, key: bytes, plaintext: bytes, nonce: bytes = None) -> Dict[str, bytes]:
        """Mock encryption."""
        if nonce is None:
            nonce = b'mock_nonce_12'
        
        # Simple XOR "encryption" for testing
        key_byte = key[0] if key else 0
        ciphertext = bytes(b ^ key_byte for b in plaintext)
        
        return {
            'ciphertext': ciphertext,
            'nonce': nonce
        }
    
    def decrypt(self, key: bytes, ciphertext: bytes, nonce: bytes) -> bytes:
        """Mock decryption."""
        # Reverse the XOR "encryption"
        key_byte = key[0] if key else 0
        plaintext = bytes(b ^ key_byte for b in ciphertext)
        return plaintext
    
    def hash_password(self, password: str) -> str:
        """Mock password hashing."""
        return f"mock_hash_{hash(password)}"
    
    def verify_password(self, password: str, hash_string: str) -> bool:
        """Mock password verification."""
        expected_hash = f"mock_hash_{hash(password)}"
        return hash_string == expected_hash


class MockNetworkService:
    """Mock network service for testing external communications."""
    
    def __init__(self):
        self.requests_log = []
        self.responses = {}
        self.default_response = {"status": "ok", "data": "mock_response"}
    
    def set_response(self, url: str, response: Dict[str, Any]):
        """Set mock response for a URL."""
        self.responses[url] = response
    
    def get(self, url: str, **kwargs) -> Dict[str, Any]:
        """Mock GET request."""
        self.requests_log.append({
            "method": "GET",
            "url": url,
            "kwargs": kwargs,
            "timestamp": time.time()
        })
        
        return self.responses.get(url, self.default_response)
    
    def post(self, url: str, data: Any = None, **kwargs) -> Dict[str, Any]:
        """Mock POST request."""
        self.requests_log.append({
            "method": "POST",
            "url": url,
            "data": data,
            "kwargs": kwargs,
            "timestamp": time.time()
        })
        
        return self.responses.get(url, self.default_response)
    
    def get_request_log(self) -> List[Dict[str, Any]]:
        """Get log of all requests made."""
        return self.requests_log.copy()
    
    def clear_log(self):
        """Clear request log."""
        self.requests_log.clear()


class MockDatabase:
    """Mock database for testing data operations."""
    
    def __init__(self):
        self.data = {}
        self.query_log = []
        self.connected = False
    
    def connect(self):
        """Mock database connection."""
        self.connected = True
    
    def disconnect(self):
        """Mock database disconnection."""
        self.connected = False
    
    def execute(self, query: str, params: tuple = None) -> List[Dict[str, Any]]:
        """Mock query execution."""
        if not self.connected:
            raise Exception("Database not connected")
        
        self.query_log.append({
            "query": query,
            "params": params,
            "timestamp": time.time()
        })
        
        # Simple mock responses based on query type
        query_lower = query.lower().strip()
        
        if query_lower.startswith("select"):
            return [{"id": 1, "name": "mock_record", "value": "test_data"}]
        elif query_lower.startswith("insert"):
            return [{"affected_rows": 1, "last_insert_id": random.randint(1, 1000)}]
        elif query_lower.startswith("update"):
            return [{"affected_rows": 1}]
        elif query_lower.startswith("delete"):
            return [{"affected_rows": 1}]
        else:
            return [{"status": "executed"}]
    
    def get_query_log(self) -> List[Dict[str, Any]]:
        """Get log of all queries executed."""
        return self.query_log.copy()
    
    def clear_log(self):
        """Clear query log."""
        self.query_log.clear()


class MockSMSProvider:
    """Mock SMS provider for testing MFA."""
    
    def __init__(self):
        self.sent_messages = []
        self.delivery_success_rate = 0.95
    
    def send_sms(self, phone_number: str, message: str) -> bool:
        """Mock SMS sending."""
        success = random.random() < self.delivery_success_rate
        
        self.sent_messages.append({
            "phone_number": phone_number,
            "message": message,
            "success": success,
            "timestamp": time.time()
        })
        
        return success
    
    def get_sent_messages(self) -> List[Dict[str, Any]]:
        """Get log of sent messages."""
        return self.sent_messages.copy()
    
    def clear_log(self):
        """Clear message log."""
        self.sent_messages.clear()


class MockEmailProvider:
    """Mock email provider for testing MFA."""
    
    def __init__(self):
        self.sent_emails = []
        self.delivery_success_rate = 0.98
    
    def send_email(self, to_email: str, subject: str, body: str) -> bool:
        """Mock email sending."""
        success = random.random() < self.delivery_success_rate
        
        self.sent_emails.append({
            "to_email": to_email,
            "subject": subject,
            "body": body,
            "success": success,
            "timestamp": time.time()
        })
        
        return success
    
    def get_sent_emails(self) -> List[Dict[str, Any]]:
        """Get log of sent emails."""
        return self.sent_emails.copy()
    
    def clear_log(self):
        """Clear email log."""
        self.sent_emails.clear()


class MockFileSystem:
    """Mock file system for testing file operations."""
    
    def __init__(self):
        self.files = {}
        self.directories = set(["/"])
        self.access_log = []
    
    def read_file(self, path: str) -> str:
        """Mock file reading."""
        self.access_log.append({
            "operation": "read",
            "path": path,
            "timestamp": time.time()
        })
        
        if path in self.files:
            return self.files[path]
        else:
            raise FileNotFoundError(f"File not found: {path}")
    
    def write_file(self, path: str, content: str):
        """Mock file writing."""
        self.access_log.append({
            "operation": "write",
            "path": path,
            "size": len(content),
            "timestamp": time.time()
        })
        
        self.files[path] = content
    
    def delete_file(self, path: str):
        """Mock file deletion."""
        self.access_log.append({
            "operation": "delete",
            "path": path,
            "timestamp": time.time()
        })
        
        if path in self.files:
            del self.files[path]
        else:
            raise FileNotFoundError(f"File not found: {path}")
    
    def list_directory(self, path: str) -> List[str]:
        """Mock directory listing."""
        self.access_log.append({
            "operation": "list",
            "path": path,
            "timestamp": time.time()
        })
        
        # Return files in the directory
        files_in_dir = []
        for file_path in self.files.keys():
            if file_path.startswith(path) and file_path != path:
                relative_path = file_path[len(path):].lstrip("/")
                if "/" not in relative_path:  # Direct child
                    files_in_dir.append(relative_path)
        
        return files_in_dir
    
    def get_access_log(self) -> List[Dict[str, Any]]:
        """Get file access log."""
        return self.access_log.copy()
    
    def clear_log(self):
        """Clear access log."""
        self.access_log.clear()


class MockRedisCache:
    """Mock Redis cache for testing caching operations."""
    
    def __init__(self):
        self.cache = {}
        self.expiry_times = {}
        self.operations_log = []
    
    def get(self, key: str) -> Optional[str]:
        """Mock cache get operation."""
        self.operations_log.append({
            "operation": "get",
            "key": key,
            "timestamp": time.time()
        })
        
        # Check if key exists and hasn't expired
        if key in self.cache:
            if key in self.expiry_times:
                if time.time() > self.expiry_times[key]:
                    # Key has expired
                    del self.cache[key]
                    del self.expiry_times[key]
                    return None
            return self.cache[key]
        
        return None
    
    def set(self, key: str, value: str, ex: Optional[int] = None):
        """Mock cache set operation."""
        self.operations_log.append({
            "operation": "set",
            "key": key,
            "value_size": len(value),
            "expiry": ex,
            "timestamp": time.time()
        })
        
        self.cache[key] = value
        
        if ex is not None:
            self.expiry_times[key] = time.time() + ex
    
    def delete(self, key: str) -> bool:
        """Mock cache delete operation."""
        self.operations_log.append({
            "operation": "delete",
            "key": key,
            "timestamp": time.time()
        })
        
        if key in self.cache:
            del self.cache[key]
            if key in self.expiry_times:
                del self.expiry_times[key]
            return True
        
        return False
    
    def exists(self, key: str) -> bool:
        """Mock cache exists check."""
        return self.get(key) is not None
    
    def flushall(self):
        """Mock cache flush operation."""
        self.operations_log.append({
            "operation": "flushall",
            "timestamp": time.time()
        })
        
        self.cache.clear()
        self.expiry_times.clear()
    
    def get_operations_log(self) -> List[Dict[str, Any]]:
        """Get cache operations log."""
        return self.operations_log.copy()
    
    def clear_log(self):
        """Clear operations log."""
        self.operations_log.clear()


@dataclass
class MockMetrics:
    """Mock metrics collection for testing monitoring."""
    
    def __init__(self):
        self.counters = {}
        self.gauges = {}
        self.histograms = {}
        self.timers = {}
    
    def increment_counter(self, name: str, value: int = 1, tags: Dict[str, str] = None):
        """Mock counter increment."""
        if name not in self.counters:
            self.counters[name] = 0
        self.counters[name] += value
    
    def set_gauge(self, name: str, value: float, tags: Dict[str, str] = None):
        """Mock gauge set."""
        self.gauges[name] = value
    
    def record_histogram(self, name: str, value: float, tags: Dict[str, str] = None):
        """Mock histogram recording."""
        if name not in self.histograms:
            self.histograms[name] = []
        self.histograms[name].append(value)
    
    def start_timer(self, name: str) -> 'MockTimer':
        """Mock timer start."""
        return MockTimer(name, self)
    
    def get_counter(self, name: str) -> int:
        """Get counter value."""
        return self.counters.get(name, 0)
    
    def get_gauge(self, name: str) -> float:
        """Get gauge value."""
        return self.gauges.get(name, 0.0)
    
    def get_histogram_stats(self, name: str) -> Dict[str, float]:
        """Get histogram statistics."""
        values = self.histograms.get(name, [])
        if not values:
            return {"count": 0, "min": 0, "max": 0, "avg": 0}
        
        return {
            "count": len(values),
            "min": min(values),
            "max": max(values),
            "avg": sum(values) / len(values)
        }


class MockTimer:
    """Mock timer for testing timing operations."""
    
    def __init__(self, name: str, metrics: MockMetrics):
        self.name = name
        self.metrics = metrics
        self.start_time = None
    
    def __enter__(self):
        self.start_time = time.time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.start_time is not None:
            duration = time.time() - self.start_time
            if self.name not in self.metrics.timers:
                self.metrics.timers[self.name] = []
            self.metrics.timers[self.name].append(duration)


def create_mock_security_framework():
    """Create a mock security framework for testing."""
    framework = Mock()
    
    # Mock methods
    framework.process_request = Mock(return_value={
        "request": {"jsonrpc": "2.0", "method": "test"},
        "context": {"user_id": "test_user"},
        "security_metadata": {
            "processing_time_ms": 5.0,
            "security_level": "LOW_RISK",
            "threat_score": 0.1
        }
    })
    
    framework.get_security_metrics = Mock(return_value={
        "requests_processed": 100,
        "attacks_blocked": 5,
        "success_rate": 0.95,
        "avg_processing_time_ms": 4.2
    })
    
    return framework


def patch_ml_dependencies():
    """Create patches for ML dependencies when not available."""
    from unittest.mock import patch
    
    patches = {
        'sklearn.ensemble.IsolationForest': MockMLModel,
        'sklearn.preprocessing.StandardScaler': MockStandardScaler,
        'sklearn.cluster.DBSCAN': Mock,
        'joblib.dump': Mock(),
        'joblib.load': Mock(return_value=MockMLModel())
    }
    
    return patches
