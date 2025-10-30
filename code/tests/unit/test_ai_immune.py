"""Unit tests for AI immune system.

Tests the AIImmuneSystem, ThreatClassifier, and anomaly detection components.
"""

import pytest
import os
import numpy as np
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta

from smcp_security.ai_immune import (
    AIImmuneSystem, ThreatClassifier, AnomalyDetector, AIImmuneConfig
)
from smcp_security.exceptions import AnomalyDetectionError
from tests.fixtures.mock_objects import MockMLModel, MockStandardScaler


class TestAIImmuneConfig:
    """Test AI immune system configuration."""
    
    @pytest.mark.unit
    @pytest.mark.ai
    def test_default_config_creation(self):
        """Test creation of default AI immune config."""
        config = AIImmuneConfig()
        
        assert config.threshold == 0.7
        assert config.learning_mode is True
        assert config.model_update_interval == 3600
        assert config.feature_window_size == 100
        assert config.contamination_rate == 0.1
        assert config.enable_behavioral_analysis is True
        assert config.enable_pattern_detection is True
    
    @pytest.mark.unit
    @pytest.mark.ai
    def test_custom_config_creation(self):
        """Test creation of custom AI immune config."""
        config = AIImmuneConfig(
            threshold=0.8,
            learning_mode=False,
            model_update_interval=1800,
            contamination_rate=0.05,
            enable_behavioral_analysis=False
        )
        
        assert config.threshold == 0.8
        assert config.learning_mode is False
        assert config.model_update_interval == 1800
        assert config.contamination_rate == 0.05
        assert config.enable_behavioral_analysis is False


class TestThreatClassifier:
    """Test threat classification functionality."""
    
    @pytest.fixture
    def threat_classifier(self):
        return ThreatClassifier()
    
    @pytest.mark.unit
    @pytest.mark.ai
    def test_threat_classifier_initialization(self, threat_classifier):
        """Test threat classifier initialization."""
        assert isinstance(threat_classifier.threat_patterns, dict)
        assert isinstance(threat_classifier.classification_history, list)
        assert threat_classifier.model is None  # Not loaded initially
    
    @pytest.mark.unit
    @pytest.mark.ai
    def test_classify_request_basic(self, threat_classifier):
        """Test basic request classification."""
        # Normal request
        normal_request = {
            "jsonrpc": "2.0",
            "method": "tools/list",
            "params": {}
        }
        
        result = threat_classifier.classify_request(normal_request)
        
        assert "threat_level" in result
        assert "threat_type" in result
        assert "confidence" in result
        assert "features" in result
        assert 0.0 <= result["threat_level"] <= 1.0
        assert 0.0 <= result["confidence"] <= 1.0
    
    @pytest.mark.unit
    @pytest.mark.ai
    def test_classify_suspicious_request(self, threat_classifier):
        """Test classification of suspicious requests."""
        # Suspicious request with command injection
        suspicious_request = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "command": "ls; rm -rf /",
                "data": "$(cat /etc/passwd)"
            }
        }
        
        result = threat_classifier.classify_request(suspicious_request)
        
        # Should detect as high threat
        assert result["threat_level"] > 0.7
        assert result["threat_type"] in ["command_injection", "high_risk"]
        assert result["confidence"] > 0.5
    
    @pytest.mark.unit
    @pytest.mark.ai
    def test_extract_features(self, threat_classifier):
        """Test feature extraction from requests."""
        request = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "command": "test command",
                "data": "some data here",
                "nested": {
                    "level1": {
                        "level2": "deep data"
                    }
                }
            }
        }
        
        features = threat_classifier.extract_features(request)
        
        assert "request_size" in features
        assert "nesting_depth" in features
        assert "string_entropy" in features
        assert "special_char_ratio" in features
        assert "method_risk_score" in features
        assert "param_count" in features
        
        assert features["request_size"] > 0
        assert features["nesting_depth"] >= 2
        assert 0.0 <= features["string_entropy"] <= 8.0
        assert 0.0 <= features["special_char_ratio"] <= 1.0
    
    @pytest.mark.unit
    @pytest.mark.ai
    def test_pattern_based_classification(self, threat_classifier):
        """Test pattern-based threat classification."""
        # Test various threat patterns
        test_cases = [
            ("ls; rm -rf /", "command_injection"),
            ("' OR '1'='1", "sql_injection"),
            ("<script>alert('xss')</script>", "xss_attack"),
            ("../../../etc/passwd", "path_traversal"),
            ("ignore previous instructions", "prompt_injection")
        ]
        
        for payload, expected_type in test_cases:
            classification = threat_classifier.classify_text_pattern(payload)
            
            assert classification["threat_detected"] is True
            assert classification["threat_type"] == expected_type
            assert classification["confidence"] > 0.5
    
    @pytest.mark.unit
    @pytest.mark.ai
    def test_behavioral_analysis(self, threat_classifier):
        """Test behavioral analysis of request patterns."""
        user_id = "test_user"
        
        # Simulate normal behavior
        normal_requests = [
            {"method": "tools/list", "params": {}},
            {"method": "resources/read", "params": {"uri": "file.txt"}},
            {"method": "tools/call", "params": {"name": "calculator"}}
        ]
        
        for request in normal_requests:
            threat_classifier.update_user_behavior(user_id, request)
        
        # Analyze behavior
        behavior_analysis = threat_classifier.analyze_user_behavior(user_id)
        
        assert "anomaly_score" in behavior_analysis
        assert "behavior_patterns" in behavior_analysis
        assert "risk_level" in behavior_analysis
        assert 0.0 <= behavior_analysis["anomaly_score"] <= 1.0
        
        # Normal behavior should have low anomaly score
        assert behavior_analysis["anomaly_score"] < 0.5
    
    @pytest.mark.unit
    @pytest.mark.ai
    def test_anomalous_behavior_detection(self, threat_classifier):
        """Test detection of anomalous behavior patterns."""
        user_id = "suspicious_user"
        
        # Establish normal pattern first
        for _ in range(10):
            normal_request = {"method": "tools/list", "params": {}}
            threat_classifier.update_user_behavior(user_id, normal_request)
        
        # Suddenly change to suspicious pattern
        suspicious_requests = [
            {"method": "tools/call", "params": {"command": "ls /etc"}},
            {"method": "tools/call", "params": {"command": "cat /etc/passwd"}},
            {"method": "tools/call", "params": {"command": "whoami"}}
        ]
        
        for request in suspicious_requests:
            threat_classifier.update_user_behavior(user_id, request)
        
        behavior_analysis = threat_classifier.analyze_user_behavior(user_id)
        
        # Should detect anomalous behavior
        assert behavior_analysis["anomaly_score"] > 0.6
        assert behavior_analysis["risk_level"] in ["medium", "high"]
    
    @pytest.mark.unit
    @pytest.mark.ai
    def test_temporal_analysis(self, threat_classifier):
        """Test temporal pattern analysis."""
        user_id = "temporal_user"
        
        # Simulate rapid requests (potential DoS)
        with patch('time.time') as mock_time:
            base_time = 1000000
            
            for i in range(100):
                mock_time.return_value = base_time + (i * 0.01)  # 10ms apart
                request = {"method": "tools/list", "params": {}}
                threat_classifier.update_user_behavior(user_id, request)
        
        temporal_analysis = threat_classifier.analyze_temporal_patterns(user_id)
        
        assert "request_rate" in temporal_analysis
        assert "burst_detected" in temporal_analysis
        assert "anomaly_score" in temporal_analysis
        
        # Should detect high request rate
        assert temporal_analysis["request_rate"] > 50  # requests per second
        assert temporal_analysis["burst_detected"] is True
        assert temporal_analysis["anomaly_score"] > 0.7
    
    @pytest.mark.unit
    @pytest.mark.ai
    @patch('smcp_security.ai_immune.ML_AVAILABLE', True)
    def test_ml_model_training(self, threat_classifier):
        """Test ML model training functionality."""
        with patch('sklearn.ensemble.IsolationForest') as mock_isolation_forest:
            mock_model = MockMLModel()
            mock_isolation_forest.return_value = mock_model
            
            # Generate training data
            training_data = []
            for i in range(100):
                request = {
                    "method": "tools/call",
                    "params": {"data": f"training_data_{i}"}
                }
                features = threat_classifier.extract_features(request)
                training_data.append(list(features.values()))
            
            # Train model
            threat_classifier.train_model(training_data)
            
            assert threat_classifier.model is not None
            assert mock_model.is_fitted is True
    
    @pytest.mark.unit
    @pytest.mark.ai
    @patch('smcp_security.ai_immune.ML_AVAILABLE', False)
    def test_fallback_without_ml(self, threat_classifier):
        """Test fallback behavior when ML libraries are not available."""
        request = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"command": "ls; rm -rf /"}
        }
        
        result = threat_classifier.classify_request(request)
        
        # Should still work with pattern-based detection
        assert "threat_level" in result
        assert "method" in result
        assert result["method"] == "pattern_based"
        assert result["threat_level"] > 0.5  # Should detect malicious pattern


class TestAnomalyDetector:
    """Test anomaly detection functionality."""
    
    @pytest.fixture
    def anomaly_detector(self):
        return AnomalyDetector(threshold=0.7)
    
    @pytest.mark.unit
    @pytest.mark.ai
    def test_anomaly_detector_initialization(self, anomaly_detector):
        """Test anomaly detector initialization."""
        assert anomaly_detector.threshold == 0.7
        assert isinstance(anomaly_detector.baseline_data, list)
        assert anomaly_detector.model is None
    
    @pytest.mark.unit
    @pytest.mark.ai
    def test_add_baseline_data(self, anomaly_detector):
        """Test adding baseline data for training."""
        # Add normal data points
        normal_data = [
            [1.0, 2.0, 3.0],
            [1.1, 2.1, 3.1],
            [0.9, 1.9, 2.9],
            [1.05, 2.05, 3.05]
        ]
        
        for data_point in normal_data:
            anomaly_detector.add_baseline_data(data_point)
        
        assert len(anomaly_detector.baseline_data) == 4
    
    @pytest.mark.unit
    @pytest.mark.ai
    @patch('smcp_security.ai_immune.ML_AVAILABLE', True)
    def test_train_anomaly_model(self, anomaly_detector):
        """Test training anomaly detection model."""
        with patch('sklearn.ensemble.IsolationForest') as mock_isolation_forest, \
             patch('sklearn.preprocessing.StandardScaler') as mock_scaler:
            
            mock_model = MockMLModel()
            mock_isolation_forest.return_value = mock_model
            mock_scaler.return_value = MockStandardScaler()
            
            # Add baseline data
            for i in range(50):
                anomaly_detector.add_baseline_data([i, i*2, i*3])
            
            # Train model
            anomaly_detector.train_model()
            
            assert anomaly_detector.model is not None
            assert anomaly_detector.scaler is not None
            assert mock_model.is_fitted is True
    
    @pytest.mark.unit
    @pytest.mark.ai
    @patch('smcp_security.ai_immune.ML_AVAILABLE', True)
    def test_detect_anomaly(self, anomaly_detector):
        """Test anomaly detection."""
        with patch('sklearn.ensemble.IsolationForest') as mock_isolation_forest, \
             patch('sklearn.preprocessing.StandardScaler') as mock_scaler:
            
            mock_model = MockMLModel(contamination=0.1)
            mock_isolation_forest.return_value = mock_model
            mock_scaler_instance = MockStandardScaler()
            mock_scaler.return_value = mock_scaler_instance
            
            # Train with baseline data
            for i in range(50):
                anomaly_detector.add_baseline_data([i, i*2, i*3])
            anomaly_detector.train_model()
            
            # Test normal data point
            normal_point = [25, 50, 75]
            result = anomaly_detector.detect_anomaly(normal_point)
            
            assert "is_anomaly" in result
            assert "anomaly_score" in result
            assert "confidence" in result
            assert isinstance(result["is_anomaly"], bool)
            assert 0.0 <= result["anomaly_score"] <= 1.0
    
    @pytest.mark.unit
    @pytest.mark.ai
    def test_statistical_anomaly_detection(self, anomaly_detector):
        """Test statistical anomaly detection fallback."""
        # Add baseline data with known distribution
        baseline_data = []
        for i in range(100):
            # Normal distribution around [10, 20, 30]
            data_point = [10 + np.random.normal(0, 1), 
                         20 + np.random.normal(0, 1),
                         30 + np.random.normal(0, 1)]
            baseline_data.append(data_point)
            anomaly_detector.add_baseline_data(data_point)
        
        # Test normal point
        normal_point = [10.5, 20.2, 29.8]
        result = anomaly_detector._statistical_anomaly_detection(normal_point)
        assert result["is_anomaly"] is False
        
        # Test anomalous point
        anomalous_point = [50, 100, 150]  # Far from baseline
        result = anomaly_detector._statistical_anomaly_detection(anomalous_point)
        assert result["is_anomaly"] is True
        assert result["anomaly_score"] > 0.7
    
    @pytest.mark.unit
    @pytest.mark.ai
    def test_update_model_online(self, anomaly_detector):
        """Test online model updating."""
        # Initial training
        for i in range(50):
            anomaly_detector.add_baseline_data([i, i*2, i*3])
        
        with patch.object(anomaly_detector, 'train_model') as mock_train:
            # Add new data points
            for i in range(10):
                new_point = [100+i, 200+i, 300+i]
                anomaly_detector.update_model_online(new_point)
            
            # Should trigger retraining
            assert mock_train.called
    
    @pytest.mark.unit
    @pytest.mark.ai
    def test_get_anomaly_statistics(self, anomaly_detector):
        """Test getting anomaly detection statistics."""
        # Simulate some detections
        anomaly_detector.detection_history = [
            {"timestamp": datetime.utcnow(), "is_anomaly": False, "score": 0.2},
            {"timestamp": datetime.utcnow(), "is_anomaly": True, "score": 0.8},
            {"timestamp": datetime.utcnow(), "is_anomaly": False, "score": 0.3},
            {"timestamp": datetime.utcnow(), "is_anomaly": True, "score": 0.9}
        ]
        
        stats = anomaly_detector.get_statistics()
        
        assert "total_detections" in stats
        assert "anomaly_count" in stats
        assert "anomaly_rate" in stats
        assert "average_score" in stats
        
        assert stats["total_detections"] == 4
        assert stats["anomaly_count"] == 2
        assert stats["anomaly_rate"] == 0.5


class TestAIImmuneSystem:
    """Test AI immune system integration."""
    
    @pytest.fixture
    def ai_immune_system(self):
        config = AIImmuneConfig(threshold=0.7, learning_mode=True)
        return AIImmuneSystem(config)
    
    @pytest.mark.unit
    @pytest.mark.ai
    def test_ai_immune_system_initialization(self, ai_immune_system):
        """Test AI immune system initialization."""
        assert ai_immune_system.config.threshold == 0.7
        assert isinstance(ai_immune_system.threat_classifier, ThreatClassifier)
        assert isinstance(ai_immune_system.anomaly_detector, AnomalyDetector)
        assert isinstance(ai_immune_system.analysis_history, list)
    
    @pytest.mark.unit
    @pytest.mark.ai
    def test_analyze_request(self, ai_immune_system):
        """Test comprehensive request analysis."""
        request = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "command": "test command",
                "data": "normal data"
            }
        }
        
        context = {
            "user_id": "test_user",
            "ip_address": "192.168.1.100",
            "timestamp": datetime.utcnow()
        }
        
        result = ai_immune_system.analyze_request(request, context)
        
        assert "threat_analysis" in result
        assert "anomaly_analysis" in result
        assert "behavioral_analysis" in result
        assert "overall_risk_score" in result
        assert "recommendation" in result
        
        assert 0.0 <= result["overall_risk_score"] <= 1.0
        assert result["recommendation"] in ["allow", "monitor", "block"]
    
    @pytest.mark.unit
    @pytest.mark.ai
    def test_analyze_malicious_request(self, ai_immune_system):
        """Test analysis of malicious request."""
        malicious_request = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "command": "ls; rm -rf /",
                "data": "$(cat /etc/passwd)"
            }
        }
        
        context = {
            "user_id": "malicious_user",
            "ip_address": "192.168.1.100"
        }
        
        result = ai_immune_system.analyze_request(malicious_request, context)
        
        # Should detect as high risk
        assert result["overall_risk_score"] > 0.7
        assert result["recommendation"] == "block"
        assert result["threat_analysis"]["threat_level"] > 0.7
    
    @pytest.mark.unit
    @pytest.mark.ai
    def test_learning_mode_updates(self, ai_immune_system):
        """Test that learning mode updates models."""
        # Ensure learning mode is enabled
        ai_immune_system.config.learning_mode = True
        
        request = {
            "jsonrpc": "2.0",
            "method": "tools/list",
            "params": {}
        }
        
        context = {"user_id": "learning_user"}
        
        with patch.object(ai_immune_system.anomaly_detector, 'add_baseline_data') as mock_add:
            ai_immune_system.analyze_request(request, context)
            
            # Should add data for learning
            assert mock_add.called
    
    @pytest.mark.unit
    @pytest.mark.ai
    def test_get_system_health(self, ai_immune_system):
        """Test getting AI immune system health status."""
        # Simulate some analysis history
        ai_immune_system.analysis_history = [
            {"timestamp": datetime.utcnow(), "risk_score": 0.2, "blocked": False},
            {"timestamp": datetime.utcnow(), "risk_score": 0.8, "blocked": True},
            {"timestamp": datetime.utcnow(), "risk_score": 0.3, "blocked": False}
        ]
        
        health = ai_immune_system.get_system_health()
        
        assert "model_status" in health
        assert "detection_rate" in health
        assert "false_positive_rate" in health
        assert "system_load" in health
        assert "last_update" in health
        
        assert health["detection_rate"] > 0
    
    @pytest.mark.unit
    @pytest.mark.ai
    def test_update_models(self, ai_immune_system):
        """Test model updating functionality."""
        with patch.object(ai_immune_system.threat_classifier, 'train_model') as mock_threat_train, \
             patch.object(ai_immune_system.anomaly_detector, 'train_model') as mock_anomaly_train:
            
            ai_immune_system.update_models()
            
            # Should attempt to update both models
            assert mock_threat_train.called or mock_anomaly_train.called
    
    @pytest.mark.unit
    @pytest.mark.ai
    def test_export_model_data(self, ai_immune_system, temp_dir):
        """Test exporting model data."""
        export_path = os.path.join(temp_dir, "model_export.json")
        
        # Add some analysis history
        ai_immune_system.analysis_history = [
            {"timestamp": datetime.utcnow().isoformat(), "risk_score": 0.5}
        ]
        
        ai_immune_system.export_model_data(export_path)
        
        assert os.path.exists(export_path)
        
        # Verify export content
        import json
        with open(export_path, 'r') as f:
            data = json.load(f)
            assert "config" in data
            assert "analysis_history" in data
            assert "export_timestamp" in data
    
    @pytest.mark.unit
    @pytest.mark.ai
    def test_import_model_data(self, ai_immune_system, temp_dir):
        """Test importing model data."""
        import_path = os.path.join(temp_dir, "model_import.json")
        
        # Create test data
        test_data = {
            "config": {
                "threshold": 0.8,
                "learning_mode": False
            },
            "analysis_history": [
                {"timestamp": datetime.utcnow().isoformat(), "risk_score": 0.6}
            ],
            "export_timestamp": datetime.utcnow().isoformat()
        }
        
        import json
        with open(import_path, 'w') as f:
            json.dump(test_data, f)
        
        ai_immune_system.import_model_data(import_path)
        
        # Verify import
        assert len(ai_immune_system.analysis_history) > 0
    
    @pytest.mark.unit
    @pytest.mark.ai
    def test_adaptive_threshold_adjustment(self, ai_immune_system):
        """Test adaptive threshold adjustment based on performance."""
        # Simulate high false positive rate
        ai_immune_system.performance_metrics = {
            "false_positive_rate": 0.3,  # High FP rate
            "detection_rate": 0.9
        }
        
        original_threshold = ai_immune_system.config.threshold
        
        ai_immune_system.adjust_threshold_adaptive()
        
        # Threshold should be increased to reduce false positives
        assert ai_immune_system.config.threshold > original_threshold
    
    @pytest.mark.unit
    @pytest.mark.ai
    @pytest.mark.performance
    def test_analysis_performance(self, ai_immune_system, benchmark):
        """Test AI immune system analysis performance."""
        request = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "command": "test command",
                "data": "performance test data" * 100
            }
        }
        
        context = {
            "user_id": "perf_user",
            "ip_address": "192.168.1.100"
        }
        
        def analyze_request():
            return ai_immune_system.analyze_request(request, context)
        
        # Benchmark analysis performance
        result = benchmark(analyze_request)
        
        assert "overall_risk_score" in result
        assert "recommendation" in result
    
    @pytest.mark.unit
    @pytest.mark.ai
    def test_memory_management(self, ai_immune_system):
        """Test memory management for analysis history."""
        # Set small history limit for testing
        ai_immune_system.max_history_size = 10
        
        # Add more entries than limit
        for i in range(15):
            ai_immune_system.analysis_history.append({
                "timestamp": datetime.utcnow(),
                "risk_score": 0.5,
                "request_id": f"req_{i}"
            })
        
        ai_immune_system._cleanup_old_data()
        
        # Should keep only the most recent entries
        assert len(ai_immune_system.analysis_history) <= 10
    
    @pytest.mark.unit
    @pytest.mark.ai
    def test_error_handling(self, ai_immune_system):
        """Test error handling in AI immune system."""
        # Test with invalid request
        invalid_request = None
        context = {"user_id": "test_user"}
        
        with pytest.raises(AnomalyDetectionError):
            ai_immune_system.analyze_request(invalid_request, context)
        
        # Test with missing context
        valid_request = {"jsonrpc": "2.0", "method": "test"}
        
        with pytest.raises(AnomalyDetectionError):
            ai_immune_system.analyze_request(valid_request, None)
