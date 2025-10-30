"""AI Immune System Implementation

Provides machine learning-based anomaly detection and threat classification
for SMCP security monitoring.
"""

import numpy as np
import time
import json
import re
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from collections import defaultdict, deque
import hashlib
import statistics

# ML imports (with fallbacks for environments without ML libraries)
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    from sklearn.cluster import DBSCAN
    import joblib
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

from .exceptions import AnomalyDetectionError


@dataclass
class AnomalyResult:
    """Result of anomaly detection"""
    is_anomaly: bool
    anomaly_score: float
    confidence: float
    features: List[float]
    detection_method: str
    timestamp: datetime
    

@dataclass
class ThreatInfo:
    """Information about detected threat"""
    threat_type: str
    severity: str
    confidence: float
    indicators: List[str]
    mitigation_suggestions: List[str]
    

class FeatureExtractor:
    """Extracts features from MCP requests for ML analysis"""
    
    def __init__(self):
        self.feature_names = [
            "request_size",
            "parameter_count", 
            "method_length",
            "has_file_operations",
            "has_network_operations",
            "has_database_operations",
            "entropy",
            "special_char_ratio",
            "numeric_ratio",
            "uppercase_ratio",
            "time_of_day",
            "day_of_week",
            "request_depth",
            "string_length_variance",
            "suspicious_keywords_count"
        ]
        
        self.suspicious_keywords = [
            "admin", "root", "password", "secret", "token", "key",
            "exec", "eval", "system", "shell", "cmd", "command",
            "script", "inject", "payload", "exploit", "hack",
            "bypass", "override", "escalate", "privilege"
        ]
    
    def extract_features(self, request_data: Dict[str, Any]) -> np.ndarray:
        """Extract numerical features from MCP request
        
        Args:
            request_data: MCP request dictionary
            
        Returns:
            Feature vector as numpy array
        """
        request_str = json.dumps(request_data)
        params = request_data.get("params", {})
        method = request_data.get("method", "")
        
        features = [
            len(request_str),  # request_size
            len(params),  # parameter_count
            len(method),  # method_length
            self._has_file_operations(request_data),  # has_file_operations
            self._has_network_operations(request_data),  # has_network_operations
            self._has_database_operations(request_data),  # has_database_operations
            self._calculate_entropy(request_str),  # entropy
            self._calculate_special_char_ratio(request_str),  # special_char_ratio
            self._calculate_numeric_ratio(request_str),  # numeric_ratio
            self._calculate_uppercase_ratio(request_str),  # uppercase_ratio
            datetime.now().hour,  # time_of_day
            datetime.now().weekday(),  # day_of_week
            self._calculate_depth(request_data),  # request_depth
            self._calculate_string_length_variance(params),  # string_length_variance
            self._count_suspicious_keywords(request_str)  # suspicious_keywords_count
        ]
        
        return np.array(features, dtype=float)
    
    def _has_file_operations(self, request_data: Dict[str, Any]) -> float:
        """Check if request contains file operations"""
        request_str = json.dumps(request_data).lower()
        file_indicators = ["file", "path", "directory", "folder", "read", "write", "delete"]
        return float(any(indicator in request_str for indicator in file_indicators))
    
    def _has_network_operations(self, request_data: Dict[str, Any]) -> float:
        """Check if request contains network operations"""
        request_str = json.dumps(request_data).lower()
        network_indicators = ["http", "url", "api", "request", "fetch", "download"]
        return float(any(indicator in request_str for indicator in network_indicators))
    
    def _has_database_operations(self, request_data: Dict[str, Any]) -> float:
        """Check if request contains database operations"""
        request_str = json.dumps(request_data).lower()
        db_indicators = ["sql", "query", "database", "table", "select", "insert", "update"]
        return float(any(indicator in request_str for indicator in db_indicators))
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0.0
        
        # Count character frequencies
        char_counts = defaultdict(int)
        for char in text:
            char_counts[char] += 1
        
        # Calculate entropy
        entropy = 0.0
        text_length = len(text)
        
        for count in char_counts.values():
            probability = count / text_length
            if probability > 0:
                entropy -= probability * np.log2(probability)
        
        return entropy
    
    def _calculate_special_char_ratio(self, text: str) -> float:
        """Calculate ratio of special characters"""
        if not text:
            return 0.0
        
        special_chars = sum(1 for char in text if not char.isalnum() and not char.isspace())
        return special_chars / len(text)
    
    def _calculate_numeric_ratio(self, text: str) -> float:
        """Calculate ratio of numeric characters"""
        if not text:
            return 0.0
        
        numeric_chars = sum(1 for char in text if char.isdigit())
        return numeric_chars / len(text)
    
    def _calculate_uppercase_ratio(self, text: str) -> float:
        """Calculate ratio of uppercase characters"""
        if not text:
            return 0.0
        
        alpha_chars = sum(1 for char in text if char.isalpha())
        if alpha_chars == 0:
            return 0.0
        
        uppercase_chars = sum(1 for char in text if char.isupper())
        return uppercase_chars / alpha_chars
    
    def _calculate_depth(self, obj: Any, current_depth: int = 0) -> float:
        """Calculate maximum nesting depth of object"""
        if isinstance(obj, dict):
            if not obj:
                return current_depth
            return max(self._calculate_depth(value, current_depth + 1) 
                      for value in obj.values())
        elif isinstance(obj, list):
            if not obj:
                return current_depth
            return max(self._calculate_depth(item, current_depth + 1) 
                      for item in obj)
        else:
            return current_depth
    
    def _calculate_string_length_variance(self, params: Dict[str, Any]) -> float:
        """Calculate variance in string lengths within parameters"""
        string_lengths = []
        
        def collect_strings(obj):
            if isinstance(obj, str):
                string_lengths.append(len(obj))
            elif isinstance(obj, dict):
                for value in obj.values():
                    collect_strings(value)
            elif isinstance(obj, list):
                for item in obj:
                    collect_strings(item)
        
        collect_strings(params)
        
        if len(string_lengths) < 2:
            return 0.0
        
        return float(np.var(string_lengths))
    
    def _count_suspicious_keywords(self, text: str) -> float:
        """Count suspicious keywords in text"""
        text_lower = text.lower()
        count = sum(1 for keyword in self.suspicious_keywords 
                   if keyword in text_lower)
        return float(count)


class AIImmuneSystem:
    """AI-based immune system for anomaly detection"""
    
    def __init__(self, threshold: float = 0.8, learning_mode: bool = False):
        self.threshold = threshold
        self.learning_mode = learning_mode
        self.feature_extractor = FeatureExtractor()
        
        # ML models (if available)
        if ML_AVAILABLE:
            self.anomaly_detector = IsolationForest(
                contamination=0.1,  # Expected proportion of anomalies
                random_state=42,
                n_estimators=100
            )
            self.scaler = StandardScaler()
            self.clustering_model = DBSCAN(eps=0.5, min_samples=5)
        else:
            self.anomaly_detector = None
            self.scaler = None
            self.clustering_model = None
        
        self.is_trained = False
        self.training_data = []
        
        # Pattern-based detection (fallback)
        self.pattern_detector = PatternBasedDetector()
        
        # Behavioral analysis
        self.user_profiles = defaultdict(lambda: {
            "request_history": deque(maxlen=1000),
            "feature_history": deque(maxlen=1000),
            "baseline_established": False,
            "baseline_features": None
        })
        
        # Metrics
        self.detection_metrics = {
            "total_requests": 0,
            "anomalies_detected": 0,
            "false_positives": 0,
            "true_positives": 0,
            "detection_accuracy": 0.0
        }
    
    def train(self, normal_requests: List[Dict[str, Any]]):
        """Train the anomaly detection model on normal requests
        
        Args:
            normal_requests: List of normal MCP requests for training
        """
        if not ML_AVAILABLE:
            # Use pattern-based training
            self.pattern_detector.train(normal_requests)
            self.is_trained = True
            return
        
        # Extract features from training data
        features_list = []
        for request in normal_requests:
            features = self.feature_extractor.extract_features(request)
            features_list.append(features)
            self.training_data.append(request)
        
        if not features_list:
            raise AnomalyDetectionError("No training data provided")
        
        X = np.array(features_list)
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train anomaly detector
        self.anomaly_detector.fit(X_scaled)
        
        # Train clustering model for pattern analysis
        self.clustering_model.fit(X_scaled)
        
        self.is_trained = True
    
    def detect_anomaly(self, request_data: Dict[str, Any], 
                      user_id: Optional[str] = None) -> AnomalyResult:
        """Detect if a request is anomalous
        
        Args:
            request_data: MCP request to analyze
            user_id: User ID for behavioral analysis
            
        Returns:
            AnomalyResult with detection information
        """
        self.detection_metrics["total_requests"] += 1
        
        # Extract features
        features = self.feature_extractor.extract_features(request_data)
        
        # Update user profile if provided
        if user_id:
            self._update_user_profile(user_id, request_data, features)
        
        # Perform detection
        if ML_AVAILABLE and self.is_trained:
            result = self._ml_based_detection(features, user_id)
        else:
            result = self._pattern_based_detection(request_data, features)
        
        # Update metrics
        if result.is_anomaly:
            self.detection_metrics["anomalies_detected"] += 1
        
        return result
    
    def _ml_based_detection(self, features: np.ndarray, 
                           user_id: Optional[str] = None) -> AnomalyResult:
        """ML-based anomaly detection"""
        features_scaled = self.scaler.transform(features.reshape(1, -1))
        
        # Get anomaly score
        anomaly_score = self.anomaly_detector.decision_function(features_scaled)[0]
        is_anomaly = self.anomaly_detector.predict(features_scaled)[0] == -1
        
        # Calculate confidence based on distance from decision boundary
        confidence = min(1.0, abs(anomaly_score) / 0.5)
        
        # Behavioral analysis if user provided
        if user_id and self.user_profiles[user_id]["baseline_established"]:
            behavioral_anomaly = self._detect_behavioral_anomaly(user_id, features)
            if behavioral_anomaly:
                is_anomaly = True
                confidence = max(confidence, 0.8)
        
        return AnomalyResult(
            is_anomaly=is_anomaly,
            anomaly_score=float(anomaly_score),
            confidence=confidence,
            features=features.tolist(),
            detection_method="ml_isolation_forest",
            timestamp=datetime.utcnow()
        )
    
    def _pattern_based_detection(self, request_data: Dict[str, Any], 
                               features: np.ndarray) -> AnomalyResult:
        """Pattern-based anomaly detection (fallback)"""
        result = self.pattern_detector.detect_anomaly(request_data)
        
        return AnomalyResult(
            is_anomaly=result["is_anomaly"],
            anomaly_score=result["score"],
            confidence=result["confidence"],
            features=features.tolist(),
            detection_method="pattern_based",
            timestamp=datetime.utcnow()
        )
    
    def _update_user_profile(self, user_id: str, request_data: Dict[str, Any], 
                           features: np.ndarray):
        """Update user behavioral profile"""
        profile = self.user_profiles[user_id]
        
        # Add to history
        profile["request_history"].append({
            "timestamp": datetime.utcnow(),
            "request": request_data
        })
        profile["feature_history"].append(features)
        
        # Establish baseline if enough data
        if (len(profile["feature_history"]) >= 50 and 
            not profile["baseline_established"]):
            
            feature_matrix = np.array(list(profile["feature_history"]))
            profile["baseline_features"] = {
                "mean": np.mean(feature_matrix, axis=0),
                "std": np.std(feature_matrix, axis=0),
                "min": np.min(feature_matrix, axis=0),
                "max": np.max(feature_matrix, axis=0)
            }
            profile["baseline_established"] = True
    
    def _detect_behavioral_anomaly(self, user_id: str, 
                                 features: np.ndarray) -> bool:
        """Detect behavioral anomalies for a specific user"""
        profile = self.user_profiles[user_id]
        baseline = profile["baseline_features"]
        
        if not baseline:
            return False
        
        # Calculate z-scores for each feature
        z_scores = np.abs((features - baseline["mean"]) / (baseline["std"] + 1e-8))
        
        # Check if any feature is more than 3 standard deviations away
        if np.any(z_scores > 3.0):
            return True
        
        # Check if multiple features are moderately anomalous
        if np.sum(z_scores > 2.0) >= 3:
            return True
        
        return False
    
    def get_user_profile(self, user_id: str) -> Dict[str, Any]:
        """Get user behavioral profile
        
        Args:
            user_id: User ID
            
        Returns:
            User profile information
        """
        profile = self.user_profiles[user_id]
        
        return {
            "user_id": user_id,
            "request_count": len(profile["request_history"]),
            "baseline_established": profile["baseline_established"],
            "last_activity": profile["request_history"][-1]["timestamp"] if profile["request_history"] else None,
            "feature_statistics": profile["baseline_features"] if profile["baseline_established"] else None
        }
    
    def get_detection_metrics(self) -> Dict[str, Any]:
        """Get detection performance metrics"""
        total = self.detection_metrics["total_requests"]
        if total > 0:
            self.detection_metrics["detection_rate"] = self.detection_metrics["anomalies_detected"] / total
        
        return dict(self.detection_metrics)
    
    def update_feedback(self, request_id: str, is_true_positive: bool):
        """Update model with feedback on detection accuracy
        
        Args:
            request_id: Request identifier
            is_true_positive: Whether the detection was correct
        """
        if is_true_positive:
            self.detection_metrics["true_positives"] += 1
        else:
            self.detection_metrics["false_positives"] += 1
        
        # Update accuracy
        total_feedback = (self.detection_metrics["true_positives"] + 
                         self.detection_metrics["false_positives"])
        if total_feedback > 0:
            self.detection_metrics["detection_accuracy"] = (
                self.detection_metrics["true_positives"] / total_feedback
            )


class PatternBasedDetector:
    """Pattern-based anomaly detection (fallback when ML is not available)"""
    
    def __init__(self):
        self.suspicious_patterns = [
            r'[;&|`$()]',  # Shell metacharacters
            r'\b(rm|del|format|shutdown)\b',  # Dangerous commands
            r'\.\.[\/\\]',  # Path traversal
            r'(union|select|insert|update|delete)\s+',  # SQL injection
            r'<script[^>]*>.*?</script>',  # XSS
            r'javascript:',  # JavaScript injection
            r'\b(eval|exec|system)\s*\(',  # Code execution
        ]
        
        self.normal_patterns = set()
        self.request_sizes = []
        self.parameter_counts = []
    
    def train(self, normal_requests: List[Dict[str, Any]]):
        """Train on normal request patterns"""
        for request in normal_requests:
            request_str = json.dumps(request)
            self.normal_patterns.add(hashlib.md5(request_str.encode()).hexdigest())
            self.request_sizes.append(len(request_str))
            self.parameter_counts.append(len(request.get("params", {})))
    
    def detect_anomaly(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect anomalies using pattern matching"""
        request_str = json.dumps(request_data)
        score = 0.0
        indicators = []
        
        # Check for suspicious patterns
        for pattern in self.suspicious_patterns:
            if re.search(pattern, request_str, re.IGNORECASE):
                score += 0.3
                indicators.append(f"Suspicious pattern: {pattern}")
        
        # Check request size anomaly
        if self.request_sizes:
            mean_size = statistics.mean(self.request_sizes)
            std_size = statistics.stdev(self.request_sizes) if len(self.request_sizes) > 1 else 0
            
            if abs(len(request_str) - mean_size) > 3 * std_size:
                score += 0.2
                indicators.append("Unusual request size")
        
        # Check parameter count anomaly
        param_count = len(request_data.get("params", {}))
        if self.parameter_counts:
            mean_params = statistics.mean(self.parameter_counts)
            std_params = statistics.stdev(self.parameter_counts) if len(self.parameter_counts) > 1 else 0
            
            if abs(param_count - mean_params) > 3 * std_params:
                score += 0.2
                indicators.append("Unusual parameter count")
        
        # Check if request is completely new
        request_hash = hashlib.md5(request_str.encode()).hexdigest()
        if request_hash not in self.normal_patterns:
            score += 0.1
        
        is_anomaly = score > 0.5
        confidence = min(1.0, score)
        
        return {
            "is_anomaly": is_anomaly,
            "score": score,
            "confidence": confidence,
            "indicators": indicators
        }


class ThreatClassifier:
    """Classifies detected anomalies into threat categories"""
    
    def __init__(self):
        self.threat_categories = {
            "command_injection": {
                "patterns": [r'[;&|`$()]', r'\b(rm|del|format|shutdown)\b'],
                "severity": "HIGH",
                "description": "Command injection attempt detected",
                "mitigation": ["Block request", "Review input validation", "Check system logs"]
            },
            "sql_injection": {
                "patterns": [r'(union|select|insert|update|delete)\s+', r"'\s*or\s*'1'\s*=\s*'1"],
                "severity": "HIGH",
                "description": "SQL injection attempt detected",
                "mitigation": ["Block request", "Review database queries", "Use parameterized queries"]
            },
            "xss_attack": {
                "patterns": [r'<script[^>]*>.*?</script>', r'javascript:', r'on\w+\s*='],
                "severity": "MEDIUM",
                "description": "Cross-site scripting attempt detected",
                "mitigation": ["Block request", "Sanitize input", "Implement CSP headers"]
            },
            "path_traversal": {
                "patterns": [r'\.\.[\/\\]', r'%2e%2e%2f', r'%2e%2e\\'],
                "severity": "HIGH",
                "description": "Path traversal attempt detected",
                "mitigation": ["Block request", "Validate file paths", "Use chroot jail"]
            },
            "code_execution": {
                "patterns": [r'\b(eval|exec|system|shell_exec)\s*\('],
                "severity": "CRITICAL",
                "description": "Code execution attempt detected",
                "mitigation": ["Block request immediately", "Isolate system", "Investigate breach"]
            },
            "data_exfiltration": {
                "patterns": [r'cat.*passwd', r'dump.*database', r'export.*data'],
                "severity": "CRITICAL",
                "description": "Data exfiltration attempt detected",
                "mitigation": ["Block request", "Monitor data access", "Review permissions"]
            },
            "privilege_escalation": {
                "patterns": [r'\b(sudo|su|admin|root)\b', r'privilege.*escalat'],
                "severity": "HIGH",
                "description": "Privilege escalation attempt detected",
                "mitigation": ["Block request", "Review user permissions", "Audit system access"]
            }
        }
    
    def classify_threat(self, request_data: Dict[str, Any], 
                      anomaly_result: AnomalyResult) -> ThreatInfo:
        """Classify the type of threat detected
        
        Args:
            request_data: Original request data
            anomaly_result: Anomaly detection result
            
        Returns:
            ThreatInfo with classification details
        """
        if not anomaly_result.is_anomaly:
            return ThreatInfo(
                threat_type="none",
                severity="LOW",
                confidence=0.0,
                indicators=[],
                mitigation_suggestions=[]
            )
        
        request_text = json.dumps(request_data).lower()
        detected_threats = []
        all_indicators = []
        
        # Check each threat category
        for threat_type, config in self.threat_categories.items():
            indicators = []
            for pattern in config["patterns"]:
                if re.search(pattern, request_text, re.IGNORECASE):
                    indicators.append(f"Pattern match: {pattern}")
            
            if indicators:
                detected_threats.append({
                    "type": threat_type,
                    "severity": config["severity"],
                    "description": config["description"],
                    "indicators": indicators,
                    "mitigation": config["mitigation"]
                })
                all_indicators.extend(indicators)
        
        if detected_threats:
            # Return highest severity threat
            severity_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            highest_threat = max(detected_threats, 
                               key=lambda x: severity_order[x["severity"]])
            
            return ThreatInfo(
                threat_type=highest_threat["type"],
                severity=highest_threat["severity"],
                confidence=min(1.0, anomaly_result.confidence + 0.2),
                indicators=all_indicators,
                mitigation_suggestions=highest_threat["mitigation"]
            )
        
        # Unknown anomaly
        return ThreatInfo(
            threat_type="unknown_anomaly",
            severity="MEDIUM",
            confidence=anomaly_result.confidence,
            indicators=[f"Anomaly score: {anomaly_result.anomaly_score:.3f}"],
            mitigation_suggestions=[
                "Monitor request patterns",
                "Review request details",
                "Consider additional validation"
            ]
        )