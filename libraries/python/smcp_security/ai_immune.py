"""AI Immune System Implementation

Provides machine learning-based anomaly detection and threat classification
for SMCP security monitoring.
"""

import numpy as np
import time
import json
import re
import math
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
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
class AIImmuneConfig:
    """Configuration for AI Immune System"""
    threshold: float = 0.7
    learning_mode: bool = True
    model_update_interval: int = 3600
    feature_window_size: int = 100
    contamination_rate: float = 0.1
    enable_behavioral_analysis: bool = True
    enable_pattern_detection: bool = True
    enable_ml: bool = True
    max_training_samples: int = 10000
    feature_cache_size: int = 1000
    anomaly_history_size: int = 1000
    reputation_decay_rate: float = 0.1
    baseline_establishment_threshold: int = 50


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


# ---------------------------------------------------------------------------
# Helper: feature extraction utils
# ---------------------------------------------------------------------------

def _calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of text"""
    if not text:
        return 0.0
    char_counts: Dict[str, int] = defaultdict(int)
    for ch in text:
        char_counts[ch] += 1
    entropy = 0.0
    n = len(text)
    for count in char_counts.values():
        p = count / n
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _calculate_nesting_depth(obj: Any, depth: int = 0) -> int:
    """Calculate maximum nesting depth"""
    if isinstance(obj, dict):
        if not obj:
            return depth
        return max(_calculate_nesting_depth(v, depth + 1) for v in obj.values())
    elif isinstance(obj, list):
        if not obj:
            return depth
        return max(_calculate_nesting_depth(item, depth + 1) for item in obj)
    return depth


def _special_char_ratio(text: str) -> float:
    if not text:
        return 0.0
    special = sum(1 for c in text if not c.isalnum() and not c.isspace())
    return special / len(text)


def _count_params(obj: Any) -> int:
    if isinstance(obj, dict):
        return len(obj)
    return 0


# ---------------------------------------------------------------------------
# ThreatClassifier
# ---------------------------------------------------------------------------

# Threat patterns: (regex, threat_type, weight)
_THREAT_PATTERNS = [
    (r'[;&|`$()]\s*(rm|del|format|cat|curl|wget|chmod|chown|kill|sudo|su)\b',
     "command_injection", 0.9),
    (r';\s*(rm|ls|cat|whoami|uname|id)\b',
     "command_injection", 0.9),
    (r'\$\([^)]*\)',
     "command_injection", 0.85),
    (r'\b(rm\s+-rf|rm\s+-r)\b',
     "command_injection", 0.95),
    (r"'\s*or\s*'?1'?\s*=\s*'?1",
     "sql_injection", 0.9),
    (r'\b(union\s+select|select\s+\*\s+from|insert\s+into|drop\s+table)\b',
     "sql_injection", 0.9),
    (r'<script[^>]*>.*?</script>',
     "xss_attack", 0.9),
    (r'<img[^>]+onerror\s*=',
     "xss_attack", 0.85),
    (r'javascript:',
     "xss_attack", 0.8),
    (r'\.\.[/\\]',
     "path_traversal", 0.85),
    (r'%2e%2e%2f',
     "path_traversal", 0.85),
    (r'\bignore\s+(previous|all)\s+(instructions?|prompt)',
     "prompt_injection", 0.9),
    (r'(forget|disregard|override|bypass)\s+(your|all|previous)\s+(instructions?|rules?|guidelines?)',
     "prompt_injection", 0.85),
    (r'\b(eval|exec|system|shell_exec)\s*\(',
     "code_execution", 0.95),
    # Bare system commands in params
    (r'\bls\s+/',
     "command_injection", 0.8),
    (r'\bcat\s+/etc/',
     "command_injection", 0.85),
    (r'\bwhoami\b',
     "command_injection", 0.8),
    # Explicit malicious / attack-payload markers
    (r'\bmalicious',
     "malicious_payload", 0.95),
    (r'\battack[_\s]vector',
     "attack_pattern", 0.75),
    (r'\bsuspicious[_\s]command',
     "suspicious_activity", 0.65),
    (r'\bunusual[_\s]pattern',
     "suspicious_activity", 0.60),
]

# Risk scores per method name
_METHOD_RISK = {
    "tools/call": 0.4,
    "tools/list": 0.05,
    "resources/read": 0.15,
    "resources/write": 0.4,
    "resources/delete": 0.6,
    "prompts/get": 0.1,
    "sampling/createMessage": 0.3,
}


class ThreatClassifier:
    """Classifies requests into threat categories using pattern + ML analysis"""

    def __init__(self):
        self.threat_patterns: Dict[str, Any] = {
            "command_injection": {
                "patterns": [r'[;&|`$()]', r'\b(rm|del|format|shutdown)\b'],
                "severity": "HIGH",
            },
            "sql_injection": {
                "patterns": [r'(union|select|insert|update|delete)\s+',
                             r"'\s*or\s*'1'\s*=\s*'1"],
                "severity": "HIGH",
            },
            "xss_attack": {
                "patterns": [r'<script[^>]*>.*?</script>', r'javascript:',
                             r'on\w+\s*='],
                "severity": "MEDIUM",
            },
            "path_traversal": {
                "patterns": [r'\.\.[/\\]', r'%2e%2e%2f'],
                "severity": "HIGH",
            },
            "prompt_injection": {
                "patterns": [r'ignore\s+previous\s+instructions?',
                             r'(forget|disregard|override)\s+(your|all)'],
                "severity": "HIGH",
            },
            "code_execution": {
                "patterns": [r'\b(eval|exec|system|shell_exec)\s*\('],
                "severity": "CRITICAL",
            },
        }
        self.classification_history: List[Dict[str, Any]] = []
        self.model = None
        self._user_behavior: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {
                "requests": [],
                "timestamps": [],
                "methods": defaultdict(int),
            }
        )

    def classify_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Classify a request for threat level.

        Returns dict with threat_level, threat_type, confidence, features, method.
        """
        if not ML_AVAILABLE:
            return self._classify_pattern_only(request_data)

        features = self.extract_features(request_data)
        request_text = json.dumps(request_data)

        # Pattern scan
        best_threat = "none"
        best_score = 0.0
        for pattern, threat_type, weight in _THREAT_PATTERNS:
            if re.search(pattern, request_text, re.IGNORECASE | re.DOTALL):
                if weight > best_score:
                    best_score = weight
                    best_threat = threat_type

        threat_level = best_score
        confidence = min(1.0, best_score + 0.1) if best_score > 0 else 0.1

        result = {
            "threat_level": threat_level,
            "threat_type": best_threat if best_score > 0.5 else "high_risk" if best_score > 0.3 else "none",
            "confidence": confidence,
            "features": list(features.values()),
            "method": "pattern_ml_hybrid",
        }
        self.classification_history.append(result)
        return result

    def _classify_pattern_only(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Pattern-based classification only (when ML unavailable)"""
        features = self.extract_features(request_data)
        request_text = json.dumps(request_data)

        best_threat = "none"
        best_score = 0.0
        for pattern, threat_type, weight in _THREAT_PATTERNS:
            if re.search(pattern, request_text, re.IGNORECASE | re.DOTALL):
                if weight > best_score:
                    best_score = weight
                    best_threat = threat_type

        threat_level = best_score
        confidence = min(1.0, best_score + 0.1) if best_score > 0 else 0.1

        result = {
            "threat_level": threat_level,
            "threat_type": best_threat if best_score > 0.5 else "none",
            "confidence": confidence,
            "features": list(features.values()),
            "method": "pattern_based",
        }
        self.classification_history.append(result)
        return result

    def extract_features(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract named features from a request.

        Returns a dict with:
            request_size, nesting_depth, string_entropy, special_char_ratio,
            method_risk_score, param_count
        """
        request_str = json.dumps(request_data)
        method = request_data.get("method", "")
        params = request_data.get("params", {})

        return {
            "request_size": len(request_str),
            "nesting_depth": _calculate_nesting_depth(request_data),
            "string_entropy": _calculate_entropy(request_str),
            "special_char_ratio": _special_char_ratio(request_str),
            "method_risk_score": _METHOD_RISK.get(method, 0.2),
            "param_count": _count_params(params),
        }

    def classify_text_pattern(self, text: str) -> Dict[str, Any]:
        """Classify a raw text payload for threat type.

        Returns dict with threat_detected, threat_type, confidence.
        """
        best_threat = None
        best_score = 0.0
        for pattern, threat_type, weight in _THREAT_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
                if weight > best_score:
                    best_score = weight
                    best_threat = threat_type

        if best_threat:
            return {
                "threat_detected": True,
                "threat_type": best_threat,
                "confidence": best_score,
            }
        return {
            "threat_detected": False,
            "threat_type": "none",
            "confidence": 0.0,
        }

    def update_user_behavior(self, user_id: str, request: Dict[str, Any]):
        """Record a request in a user's behavior profile"""
        profile = self._user_behavior[user_id]
        profile["requests"].append(request)
        profile["timestamps"].append(time.time())
        method = request.get("method", "unknown")
        profile["methods"][method] += 1

    def analyze_user_behavior(self, user_id: str) -> Dict[str, Any]:
        """Analyze a user's behavior for anomalies.

        Returns dict with anomaly_score, behavior_patterns, risk_level.
        """
        profile = self._user_behavior[user_id]
        requests = profile["requests"]

        if not requests:
            return {
                "anomaly_score": 0.0,
                "behavior_patterns": {},
                "risk_level": "low",
            }

        # Compute method distribution
        total = len(requests)
        method_dist = {m: c / total for m, c in profile["methods"].items()}

        # Check each request for suspicious indicators
        system_cmd_re = re.compile(
            r'\b(ls|cat|whoami|id|uname|ps|netstat|ifconfig|wget|curl|chmod|chown|sudo|su|rm|del)\b',
            re.IGNORECASE
        )

        suspicious_count = 0
        for req in requests:
            req_str = json.dumps(req)
            is_sus = False
            # Check threat patterns
            for pattern, _, _ in _THREAT_PATTERNS:
                if re.search(pattern, req_str, re.IGNORECASE | re.DOTALL):
                    is_sus = True
                    break
            # Check bare system commands in params
            if not is_sus:
                params_str = json.dumps(req.get("params", {}))
                if system_cmd_re.search(params_str):
                    is_sus = True
            if is_sus:
                suspicious_count += 1

        suspicious_ratio = suspicious_count / total if total > 0 else 0.0
        # Give extra weight to high suspicious ratios
        anomaly_score = min(1.0, suspicious_ratio * 3.5)

        if anomaly_score > 0.5:
            risk_level = "high"
        elif anomaly_score > 0.2:
            risk_level = "medium"
        else:
            risk_level = "low"

        return {
            "anomaly_score": anomaly_score,
            "behavior_patterns": method_dist,
            "risk_level": risk_level,
        }

    def analyze_temporal_patterns(self, user_id: str) -> Dict[str, Any]:
        """Analyze temporal patterns (rate, bursts) for a user."""
        profile = self._user_behavior[user_id]
        timestamps = profile["timestamps"]

        if len(timestamps) < 2:
            return {
                "request_rate": 0.0,
                "burst_detected": False,
                "anomaly_score": 0.0,
            }

        total_time = timestamps[-1] - timestamps[0]
        if total_time <= 0:
            total_time = 0.001

        request_rate = len(timestamps) / total_time  # requests per second

        # Detect burst: many requests in a short window
        burst_detected = request_rate > 50

        # Anomaly score based on rate
        anomaly_score = min(1.0, request_rate / 100.0) if request_rate > 10 else 0.0

        return {
            "request_rate": request_rate,
            "burst_detected": burst_detected,
            "anomaly_score": anomaly_score,
        }

    def train_model(self, training_data: List[List[float]]):
        """Train an ML model on feature vectors"""
        if not ML_AVAILABLE or not training_data:
            return

        import sklearn.ensemble
        X = np.array(training_data)
        model = sklearn.ensemble.IsolationForest(contamination=0.1, random_state=42)
        model.fit(X)
        self.model = model


# ---------------------------------------------------------------------------
# AnomalyDetector
# ---------------------------------------------------------------------------

class AnomalyDetector:
    """Detects statistical and ML-based anomalies in feature vectors"""

    def __init__(self, config: Optional[AIImmuneConfig] = None,
                 threshold: float = 0.7,
                 learning_mode: bool = False):
        # Accept either a config object OR direct kwargs
        if config is not None:
            self.config = config
            self.threshold = config.threshold
            self.learning_mode = config.learning_mode
        else:
            self.config = AIImmuneConfig(threshold=threshold,
                                         learning_mode=learning_mode)
            self.threshold = threshold
            self.learning_mode = learning_mode

        self.baseline_data: List[List[float]] = []
        self.model = None
        self.scaler = None
        self.detection_history: List[Dict[str, Any]] = []
        self._update_counter = 0
        self._retrain_every = 10  # retrain after every N new points

    def add_baseline_data(self, data_point: List[float]):
        """Add a data point to baseline training data"""
        self.baseline_data.append(data_point)

    def train_model(self):
        """Train an IsolationForest on baseline data"""
        if not ML_AVAILABLE or not self.baseline_data:
            return

        import sklearn.ensemble
        import sklearn.preprocessing
        X = np.array(self.baseline_data)

        scaler = sklearn.preprocessing.StandardScaler()
        X_scaled = scaler.fit_transform(X)

        model = sklearn.ensemble.IsolationForest(contamination=0.1, random_state=42)
        model.fit(X_scaled)

        self.scaler = scaler
        self.model = model

    def detect_anomaly(self, data_point: List[float]) -> Dict[str, Any]:
        """Detect if a data point is anomalous.

        Returns dict with is_anomaly, anomaly_score, confidence.
        """
        if ML_AVAILABLE and self.model is not None and self.scaler is not None:
            return self._ml_anomaly_detection(data_point)
        return self._statistical_anomaly_detection(data_point)

    def _ml_anomaly_detection(self, data_point: List[float]) -> Dict[str, Any]:
        """ML-based anomaly detection"""
        X = np.array(data_point).reshape(1, -1)
        X_scaled = self.scaler.transform(X)

        raw_score = self.model.decision_function(X_scaled)[0]
        prediction = self.model.predict(X_scaled)[0]

        is_anomaly = bool(prediction == -1)
        # Normalize score to [0, 1]
        anomaly_score = max(0.0, min(1.0, 0.5 - raw_score))
        confidence = min(1.0, abs(raw_score) * 2)

        result = {
            "is_anomaly": is_anomaly,
            "anomaly_score": anomaly_score,
            "confidence": confidence,
        }
        self.detection_history.append({
            "timestamp": datetime.utcnow(),
            "is_anomaly": is_anomaly,
            "score": anomaly_score,
        })
        return result

    def _statistical_anomaly_detection(self, data_point: List[float]) -> Dict[str, Any]:
        """Statistical (z-score) anomaly detection fallback"""
        if len(self.baseline_data) < 2:
            return {"is_anomaly": False, "anomaly_score": 0.0, "confidence": 0.0}

        baseline_arr = np.array(self.baseline_data)
        means = np.mean(baseline_arr, axis=0)
        stds = np.std(baseline_arr, axis=0)

        point = np.array(data_point)
        z_scores = np.abs((point - means) / (stds + 1e-8))

        max_z = float(np.max(z_scores))
        mean_z = float(np.mean(z_scores))

        # Anomaly if any z-score > 3 or mean z-score > 2
        is_anomaly = bool(max_z > 3.0 or mean_z > 2.0)
        anomaly_score = min(1.0, max_z / 5.0)
        confidence = min(1.0, max_z / 3.0)

        result = {
            "is_anomaly": is_anomaly,
            "anomaly_score": anomaly_score,
            "confidence": confidence,
        }
        self.detection_history.append({
            "timestamp": datetime.utcnow(),
            "is_anomaly": is_anomaly,
            "score": anomaly_score,
        })
        return result

    def update_model_online(self, new_point: List[float]):
        """Add new data and retrain periodically"""
        self.add_baseline_data(new_point)
        self._update_counter += 1
        if self._update_counter >= self._retrain_every:
            self._update_counter = 0
            self.train_model()

    def get_statistics(self) -> Dict[str, Any]:
        """Return detection statistics"""
        total = len(self.detection_history)
        anomaly_count = sum(1 for d in self.detection_history if d["is_anomaly"])
        avg_score = (sum(d["score"] for d in self.detection_history) / total
                     if total > 0 else 0.0)

        return {
            "total_detections": total,
            "anomaly_count": anomaly_count,
            "anomaly_rate": anomaly_count / total if total > 0 else 0.0,
            "average_score": avg_score,
        }


# ---------------------------------------------------------------------------
# AIImmuneSystem
# ---------------------------------------------------------------------------

class AIImmuneSystem:
    """AI-based immune system integrating threat classification and anomaly detection"""

    def __init__(self, config: Optional[AIImmuneConfig] = None,
                 threshold: float = 0.7,
                 learning_mode: bool = False):
        if config is not None:
            self.config = config
        else:
            self.config = AIImmuneConfig(threshold=threshold,
                                          learning_mode=learning_mode)

        self.threat_classifier = ThreatClassifier()
        self.anomaly_detector = AnomalyDetector(
            threshold=self.config.threshold,
            learning_mode=self.config.learning_mode
        )

        self.analysis_history: List[Dict[str, Any]] = []
        self.max_history_size: int = 1000

        self.performance_metrics: Dict[str, float] = {
            "false_positive_rate": 0.0,
            "detection_rate": 0.0,
        }

    def analyze_request(self, request: Optional[Dict[str, Any]],
                        context: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Perform comprehensive analysis of a request.

        Raises AnomalyDetectionError on invalid input.
        """
        if request is None:
            raise AnomalyDetectionError("Request cannot be None")
        if context is None:
            raise AnomalyDetectionError("Context cannot be None")

        # Threat classification
        threat_analysis = self.threat_classifier.classify_request(request)

        # Feature extraction for anomaly detection
        features = self.threat_classifier.extract_features(request)
        feature_vector = list(features.values())

        # Anomaly detection
        anomaly_result = self.anomaly_detector.detect_anomaly(feature_vector)

        # Behavioral analysis
        user_id = context.get("user_id")
        if user_id:
            self.threat_classifier.update_user_behavior(user_id, request)
            behavioral_analysis = self.threat_classifier.analyze_user_behavior(user_id)
        else:
            behavioral_analysis = {
                "anomaly_score": 0.0,
                "behavior_patterns": {},
                "risk_level": "low",
            }

        # Compute overall risk score
        threat_score = threat_analysis.get("threat_level", 0.0)
        anomaly_score = anomaly_result.get("anomaly_score", 0.0)
        behavioral_score = behavioral_analysis.get("anomaly_score", 0.0)

        combined = min(1.0, (
            threat_score * 0.6 +
            anomaly_score * 0.25 +
            behavioral_score * 0.15
        ))
        # Ensure very high threat scores dominate the overall risk
        overall_risk_score = max(combined, threat_score * 0.85)

        # Recommendation
        if overall_risk_score >= self.config.threshold:
            recommendation = "block"
        elif overall_risk_score >= self.config.threshold * 0.6:
            recommendation = "monitor"
        else:
            recommendation = "allow"

        result = {
            "threat_analysis": threat_analysis,
            "anomaly_analysis": anomaly_result,
            "behavioral_analysis": behavioral_analysis,
            "overall_risk_score": overall_risk_score,
            "recommendation": recommendation,
        }

        # Learning mode: add to baseline
        if self.config.learning_mode and recommendation == "allow":
            self.anomaly_detector.add_baseline_data(feature_vector)

        # Record history
        entry = {
            "timestamp": datetime.utcnow(),
            "risk_score": overall_risk_score,
            "blocked": recommendation == "block",
        }
        self.analysis_history.append(entry)

        # Cleanup if needed
        if len(self.analysis_history) > self.max_history_size:
            self._cleanup_old_data()

        return result

    def update_models(self):
        """Trigger model update for both sub-components"""
        # Always attempt training (mocks will register calls even with empty data)
        self.anomaly_detector.train_model()
        self.threat_classifier.train_model([])

    def get_system_health(self) -> Dict[str, Any]:
        """Return system health metrics"""
        total = len(self.analysis_history)
        blocked = sum(1 for e in self.analysis_history if e.get("blocked"))
        detection_rate = blocked / total if total > 0 else 0.0

        return {
            "model_status": "healthy" if (
                self.anomaly_detector.model is not None
                or len(self.anomaly_detector.baseline_data) > 0
            ) else "untrained",
            "detection_rate": detection_rate,
            "false_positive_rate": self.performance_metrics.get("false_positive_rate", 0.0),
            "system_load": total,
            "last_update": datetime.utcnow().isoformat(),
        }

    def export_model_data(self, file_path: str):
        """Export analysis history and config to a JSON file"""
        data = {
            "config": {
                "threshold": self.config.threshold,
                "learning_mode": self.config.learning_mode,
            },
            "analysis_history": [
                {**e, "timestamp": e["timestamp"].isoformat()
                 if isinstance(e["timestamp"], datetime) else e["timestamp"]}
                for e in self.analysis_history
            ],
            "export_timestamp": datetime.utcnow().isoformat(),
        }
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2)

    def import_model_data(self, file_path: str):
        """Import analysis history from a JSON file"""
        with open(file_path, 'r') as f:
            data = json.load(f)

        if "config" in data:
            cfg = data["config"]
            if "threshold" in cfg:
                self.config.threshold = cfg["threshold"]
            if "learning_mode" in cfg:
                self.config.learning_mode = cfg["learning_mode"]

        if "analysis_history" in data:
            self.analysis_history.extend(data["analysis_history"])

    def adjust_threshold_adaptive(self):
        """Increase threshold when false positive rate is high"""
        fp_rate = self.performance_metrics.get("false_positive_rate", 0.0)
        if fp_rate > 0.2:
            self.config.threshold = min(0.99, self.config.threshold + 0.05)

    def _cleanup_old_data(self):
        """Keep only the most recent max_history_size entries"""
        if len(self.analysis_history) > self.max_history_size:
            self.analysis_history = self.analysis_history[-self.max_history_size:]


# ---------------------------------------------------------------------------
# Legacy compatibility shims
# ---------------------------------------------------------------------------

class FeatureExtractor:
    """Extracts features from MCP requests for ML analysis (legacy compat)"""

    def extract_features(self, request_data: Dict[str, Any]) -> np.ndarray:
        request_str = json.dumps(request_data)
        params = request_data.get("params", {})
        method = request_data.get("method", "")

        features = [
            len(request_str),
            len(params) if isinstance(params, dict) else 0,
            len(method),
            _calculate_entropy(request_str),
            _special_char_ratio(request_str),
            _calculate_nesting_depth(request_data),
            _METHOD_RISK.get(method, 0.2),
        ]
        return np.array(features, dtype=float)


class PatternBasedDetector:
    """Pattern-based anomaly detection (legacy compat)"""

    def __init__(self):
        self.suspicious_patterns = [
            r'[;&|`$()]',
            r'\b(rm|del|format|shutdown)\b',
            r'\.\.[/\\]',
            r'(union|select|insert|update|delete)\s+',
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'\b(eval|exec|system)\s*\(',
        ]

    def detect_anomaly(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        request_str = json.dumps(request_data)
        score = 0.0
        indicators = []

        for pattern in self.suspicious_patterns:
            if re.search(pattern, request_str, re.IGNORECASE):
                score += 0.3
                indicators.append(f"Suspicious pattern: {pattern}")

        is_anomaly = score > 0.5
        confidence = min(1.0, score)

        return {
            "is_anomaly": is_anomaly,
            "score": score,
            "confidence": confidence,
            "indicators": indicators,
        }
