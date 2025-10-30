"""Unit tests for rate limiting and DoS protection.

Tests the AdaptiveRateLimiter and DoSProtection components.
"""

import pytest
import time
from unittest.mock import Mock, patch
from datetime import datetime, timedelta

from smcp_security.rate_limiting import (
    AdaptiveRateLimiter, DoSProtection, RateLimitConfig
)
from smcp_security.exceptions import RateLimitError


class TestRateLimitConfig:
    """Test rate limit configuration."""
    
    @pytest.mark.unit
    @pytest.mark.ratelimit
    def test_default_config_creation(self):
        """Test creation of default rate limit config."""
        config = RateLimitConfig()
        
        assert config.default_limit == 100
        assert config.window_seconds == 60
        assert config.burst_limit == 150
        assert config.adaptive is True
        assert config.lockout_threshold == 1000
        assert config.lockout_duration_seconds == 300
    
    @pytest.mark.unit
    @pytest.mark.ratelimit
    def test_custom_config_creation(self):
        """Test creation of custom rate limit config."""
        config = RateLimitConfig(
            default_limit=50,
            window_seconds=30,
            burst_limit=75,
            adaptive=False,
            lockout_threshold=500,
            lockout_duration_seconds=600
        )
        
        assert config.default_limit == 50
        assert config.window_seconds == 30
        assert config.burst_limit == 75
        assert config.adaptive is False
        assert config.lockout_threshold == 500
        assert config.lockout_duration_seconds == 600


class TestAdaptiveRateLimiter:
    """Test adaptive rate limiting functionality."""
    
    @pytest.fixture
    def rate_limiter(self):
        return AdaptiveRateLimiter(default_limit=10, window_seconds=60)
    
    @pytest.fixture
    def strict_rate_limiter(self):
        return AdaptiveRateLimiter(default_limit=5, window_seconds=30, adaptive=False)
    
    @pytest.mark.unit
    @pytest.mark.ratelimit
    def test_rate_limit_initialization(self, rate_limiter):
        """Test rate limiter initialization."""
        assert rate_limiter.config.default_limit == 10
        assert rate_limiter.config.window_seconds == 60
        assert isinstance(rate_limiter.request_counts, dict)
        assert isinstance(rate_limiter.user_limits, dict)
    
    @pytest.mark.unit
    @pytest.mark.ratelimit
    def test_check_rate_limit_within_limit(self, rate_limiter):
        """Test rate limit check when within limits."""
        user_id = "test_user"
        
        # Should pass for requests within limit
        for i in range(5):
            result = rate_limiter.check_rate_limit(user_id)
            assert result is True
    
    @pytest.mark.unit
    @pytest.mark.ratelimit
    def test_check_rate_limit_exceeds_limit(self, rate_limiter):
        """Test rate limit check when exceeding limits."""
        user_id = "test_user"
        
        # Make requests up to the limit
        for i in range(10):
            rate_limiter.check_rate_limit(user_id)
        
        # Next request should be rate limited
        with pytest.raises(RateLimitError, match="Rate limit exceeded"):
            rate_limiter.check_rate_limit(user_id)
    
    @pytest.mark.unit
    @pytest.mark.ratelimit
    def test_rate_limit_window_reset(self, rate_limiter):
        """Test that rate limits reset after window expires."""
        user_id = "test_user"
        
        # Fill up the rate limit
        for i in range(10):
            rate_limiter.check_rate_limit(user_id)
        
        # Should be rate limited
        with pytest.raises(RateLimitError):
            rate_limiter.check_rate_limit(user_id)
        
        # Simulate time passing (mock time)
        with patch('time.time') as mock_time:
            # Set time to 61 seconds later (past window)
            mock_time.return_value = time.time() + 61
            
            # Should now be allowed again
            result = rate_limiter.check_rate_limit(user_id)
            assert result is True
    
    @pytest.mark.unit
    @pytest.mark.ratelimit
    def test_per_user_rate_limits(self, rate_limiter):
        """Test that rate limits are tracked per user."""
        user1 = "user1"
        user2 = "user2"
        
        # Fill up rate limit for user1
        for i in range(10):
            rate_limiter.check_rate_limit(user1)
        
        # user1 should be rate limited
        with pytest.raises(RateLimitError):
            rate_limiter.check_rate_limit(user1)
        
        # user2 should still be allowed
        result = rate_limiter.check_rate_limit(user2)
        assert result is True
    
    @pytest.mark.unit
    @pytest.mark.ratelimit
    def test_custom_user_limits(self, rate_limiter):
        """Test setting custom limits for specific users."""
        user_id = "premium_user"
        
        # Set higher limit for premium user
        rate_limiter.set_user_limit(user_id, 20)
        
        # Should be able to make 20 requests
        for i in range(20):
            result = rate_limiter.check_rate_limit(user_id)
            assert result is True
        
        # 21st request should be rate limited
        with pytest.raises(RateLimitError):
            rate_limiter.check_rate_limit(user_id)
    
    @pytest.mark.unit
    @pytest.mark.ratelimit
    def test_adaptive_rate_limiting(self, rate_limiter):
        """Test adaptive rate limiting based on system load."""
        user_id = "test_user"
        
        # Simulate high system load
        with patch.object(rate_limiter, '_get_system_load', return_value=0.9):
            # Adaptive limiter should reduce limits under high load
            effective_limit = rate_limiter._get_effective_limit(user_id)
            assert effective_limit < rate_limiter.config.default_limit
        
        # Simulate low system load
        with patch.object(rate_limiter, '_get_system_load', return_value=0.1):
            # Should allow higher limits under low load
            effective_limit = rate_limiter._get_effective_limit(user_id)
            assert effective_limit >= rate_limiter.config.default_limit
    
    @pytest.mark.unit
    @pytest.mark.ratelimit
    def test_burst_handling(self, rate_limiter):
        """Test burst request handling."""
        user_id = "burst_user"
        
        # Should allow burst up to burst_limit
        burst_limit = rate_limiter.config.burst_limit or 15
        
        # Make burst requests
        for i in range(burst_limit):
            result = rate_limiter.check_rate_limit(user_id, allow_burst=True)
            assert result is True
        
        # Beyond burst limit should be rejected
        with pytest.raises(RateLimitError):
            rate_limiter.check_rate_limit(user_id, allow_burst=True)
    
    @pytest.mark.unit
    @pytest.mark.ratelimit
    def test_get_rate_limit_status(self, rate_limiter):
        """Test getting rate limit status for a user."""
        user_id = "status_user"
        
        # Make some requests
        for i in range(3):
            rate_limiter.check_rate_limit(user_id)
        
        status = rate_limiter.get_rate_limit_status(user_id)
        
        assert "requests_made" in status
        assert "limit" in status
        assert "remaining" in status
        assert "reset_time" in status
        assert "window_seconds" in status
        
        assert status["requests_made"] == 3
        assert status["remaining"] == 7  # 10 - 3
        assert status["limit"] == 10
    
    @pytest.mark.unit
    @pytest.mark.ratelimit
    def test_clear_user_limits(self, rate_limiter):
        """Test clearing rate limit data for a user."""
        user_id = "clear_user"
        
        # Make some requests
        for i in range(5):
            rate_limiter.check_rate_limit(user_id)
        
        # Verify requests are tracked
        status = rate_limiter.get_rate_limit_status(user_id)
        assert status["requests_made"] == 5
        
        # Clear user data
        rate_limiter.clear_user_data(user_id)
        
        # Status should be reset
        status = rate_limiter.get_rate_limit_status(user_id)
        assert status["requests_made"] == 0
    
    @pytest.mark.unit
    @pytest.mark.ratelimit
    def test_ip_based_rate_limiting(self, rate_limiter):
        """Test IP-based rate limiting."""
        ip_address = "192.168.1.100"
        
        # Make requests from IP
        for i in range(10):
            result = rate_limiter.check_rate_limit_by_ip(ip_address)
            assert result is True
        
        # Should be rate limited
        with pytest.raises(RateLimitError):
            rate_limiter.check_rate_limit_by_ip(ip_address)
    
    @pytest.mark.unit
    @pytest.mark.ratelimit
    def test_sliding_window_implementation(self, rate_limiter):
        """Test sliding window rate limiting implementation."""
        user_id = "sliding_user"
        
        with patch('time.time') as mock_time:
            start_time = 1000000
            mock_time.return_value = start_time
            
            # Make requests at different times within window
            for i in range(5):
                mock_time.return_value = start_time + (i * 10)  # Every 10 seconds
                rate_limiter.check_rate_limit(user_id)
            
            # Move to middle of window and make more requests
            mock_time.return_value = start_time + 30
            for i in range(5):
                rate_limiter.check_rate_limit(user_id)
            
            # Should now be at limit
            with pytest.raises(RateLimitError):
                rate_limiter.check_rate_limit(user_id)
    
    @pytest.mark.unit
    @pytest.mark.ratelimit
    def test_rate_limit_headers(self, rate_limiter):
        """Test rate limit header generation."""
        user_id = "header_user"
        
        # Make some requests
        for i in range(3):
            rate_limiter.check_rate_limit(user_id)
        
        headers = rate_limiter.get_rate_limit_headers(user_id)
        
        assert "X-RateLimit-Limit" in headers
        assert "X-RateLimit-Remaining" in headers
        assert "X-RateLimit-Reset" in headers
        assert "X-RateLimit-Window" in headers
        
        assert headers["X-RateLimit-Limit"] == "10"
        assert headers["X-RateLimit-Remaining"] == "7"
        assert headers["X-RateLimit-Window"] == "60"


class TestDoSProtection:
    """Test DoS protection functionality."""
    
    @pytest.fixture
    def dos_protection(self):
        return DoSProtection()
    
    @pytest.mark.unit
    @pytest.mark.ratelimit
    @pytest.mark.security
    def test_dos_protection_initialization(self, dos_protection):
        """Test DoS protection initialization."""
        assert isinstance(dos_protection.suspicious_ips, set)
        assert isinstance(dos_protection.blocked_ips, dict)
        assert isinstance(dos_protection.request_patterns, dict)
    
    @pytest.mark.unit
    @pytest.mark.ratelimit
    @pytest.mark.security
    def test_rapid_request_detection(self, dos_protection):
        """Test detection of rapid requests from same IP."""
        ip_address = "192.168.1.100"
        
        # Simulate rapid requests
        with patch('time.time') as mock_time:
            base_time = 1000000
            
            for i in range(100):
                mock_time.return_value = base_time + (i * 0.01)  # 10ms apart
                dos_protection.analyze_request(ip_address, "test_user")
        
        # IP should be flagged as suspicious
        assert ip_address in dos_protection.suspicious_ips
    
    @pytest.mark.unit
    @pytest.mark.ratelimit
    @pytest.mark.security
    def test_distributed_attack_detection(self, dos_protection):
        """Test detection of distributed attacks."""
        # Simulate requests from many IPs in short time
        with patch('time.time') as mock_time:
            base_time = 1000000
            mock_time.return_value = base_time
            
            # 100 different IPs making requests
            for i in range(100):
                ip = f"192.168.1.{i}"
                dos_protection.analyze_request(ip, f"user_{i}")
        
        # Should detect as potential DDoS
        threat_level = dos_protection.get_threat_level()
        assert threat_level > 0.5  # Should be elevated
    
    @pytest.mark.unit
    @pytest.mark.ratelimit
    @pytest.mark.security
    def test_ip_blocking(self, dos_protection):
        """Test IP blocking functionality."""
        ip_address = "192.168.1.100"
        
        # Block IP
        dos_protection.block_ip(ip_address, duration_seconds=300, reason="Testing")
        
        # IP should be blocked
        assert dos_protection.is_ip_blocked(ip_address)
        
        # Get block info
        block_info = dos_protection.get_block_info(ip_address)
        assert block_info["reason"] == "Testing"
        assert block_info["duration_seconds"] == 300
    
    @pytest.mark.unit
    @pytest.mark.ratelimit
    @pytest.mark.security
    def test_ip_unblocking(self, dos_protection):
        """Test IP unblocking functionality."""
        ip_address = "192.168.1.100"
        
        # Block then unblock IP
        dos_protection.block_ip(ip_address, duration_seconds=300)
        assert dos_protection.is_ip_blocked(ip_address)
        
        dos_protection.unblock_ip(ip_address)
        assert not dos_protection.is_ip_blocked(ip_address)
    
    @pytest.mark.unit
    @pytest.mark.ratelimit
    @pytest.mark.security
    def test_automatic_ip_unblocking(self, dos_protection):
        """Test automatic IP unblocking after timeout."""
        ip_address = "192.168.1.100"
        
        with patch('time.time') as mock_time:
            start_time = 1000000
            mock_time.return_value = start_time
            
            # Block IP for 60 seconds
            dos_protection.block_ip(ip_address, duration_seconds=60)
            assert dos_protection.is_ip_blocked(ip_address)
            
            # Move time forward past block duration
            mock_time.return_value = start_time + 61
            
            # Should no longer be blocked
            assert not dos_protection.is_ip_blocked(ip_address)
    
    @pytest.mark.unit
    @pytest.mark.ratelimit
    @pytest.mark.security
    def test_request_pattern_analysis(self, dos_protection):
        """Test request pattern analysis."""
        ip_address = "192.168.1.100"
        
        # Simulate suspicious patterns
        patterns = [
            "/admin/login",
            "/admin/config", 
            "/admin/users",
            "/admin/system"
        ]
        
        for pattern in patterns * 10:  # Repeat patterns
            dos_protection.analyze_request(
                ip_address, "test_user", request_path=pattern
            )
        
        # Should detect suspicious pattern
        analysis = dos_protection.analyze_patterns(ip_address)
        assert analysis["suspicious"] is True
        assert analysis["pattern_score"] > 0.7
    
    @pytest.mark.unit
    @pytest.mark.ratelimit
    @pytest.mark.security
    def test_user_agent_analysis(self, dos_protection):
        """Test user agent analysis for bot detection."""
        suspicious_agents = [
            "curl/7.68.0",
            "python-requests/2.25.1",
            "Wget/1.20.3",
            "bot/1.0",
            ""
        ]
        
        for agent in suspicious_agents:
            result = dos_protection.analyze_user_agent(agent)
            assert result["suspicious"] is True
            assert result["bot_score"] > 0.5
        
        # Normal browser should not be suspicious
        normal_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        result = dos_protection.analyze_user_agent(normal_agent)
        assert result["suspicious"] is False
    
    @pytest.mark.unit
    @pytest.mark.ratelimit
    @pytest.mark.security
    def test_geolocation_analysis(self, dos_protection):
        """Test geolocation-based analysis."""
        # Mock geolocation data
        with patch.object(dos_protection, '_get_ip_geolocation') as mock_geo:
            mock_geo.return_value = {
                "country": "CN",
                "region": "Beijing",
                "city": "Beijing",
                "is_tor": False,
                "is_proxy": True
            }
            
            analysis = dos_protection.analyze_geolocation("1.2.3.4")
            
            # Proxy should increase suspicion
            assert analysis["risk_score"] > 0.5
            assert analysis["factors"]["is_proxy"] is True
    
    @pytest.mark.unit
    @pytest.mark.ratelimit
    @pytest.mark.security
    def test_threat_level_calculation(self, dos_protection):
        """Test overall threat level calculation."""
        # Simulate various threat indicators
        dos_protection.suspicious_ips.add("192.168.1.100")
        dos_protection.suspicious_ips.add("192.168.1.101")
        dos_protection.block_ip("10.0.0.1", 300, "Automated attack")
        
        threat_level = dos_protection.get_threat_level()
        
        assert 0.0 <= threat_level <= 1.0
        assert threat_level > 0.0  # Should be elevated due to suspicious activity
    
    @pytest.mark.unit
    @pytest.mark.ratelimit
    @pytest.mark.security
    def test_whitelist_functionality(self, dos_protection):
        """Test IP whitelist functionality."""
        trusted_ip = "192.168.1.100"
        
        # Add to whitelist
        dos_protection.add_to_whitelist(trusted_ip)
        
        # Should not be blocked even with suspicious activity
        for i in range(1000):
            dos_protection.analyze_request(trusted_ip, "trusted_user")
        
        assert not dos_protection.is_ip_blocked(trusted_ip)
        assert trusted_ip not in dos_protection.suspicious_ips
    
    @pytest.mark.unit
    @pytest.mark.ratelimit
    @pytest.mark.security
    def test_challenge_response(self, dos_protection):
        """Test challenge-response mechanism."""
        ip_address = "192.168.1.100"
        
        # Generate challenge
        challenge = dos_protection.generate_challenge(ip_address)
        
        assert "challenge_id" in challenge
        assert "challenge_data" in challenge
        assert "expires_at" in challenge
        
        # Verify correct response
        challenge_id = challenge["challenge_id"]
        correct_response = dos_protection._calculate_challenge_response(
            challenge["challenge_data"]
        )
        
        result = dos_protection.verify_challenge_response(
            challenge_id, correct_response
        )
        assert result is True
        
        # Verify incorrect response
        result = dos_protection.verify_challenge_response(
            challenge_id, "wrong_response"
        )
        assert result is False
    
    @pytest.mark.unit
    @pytest.mark.ratelimit
    @pytest.mark.security
    def test_adaptive_thresholds(self, dos_protection):
        """Test adaptive threshold adjustment."""
        # Simulate high attack volume
        for i in range(1000):
            ip = f"10.0.{i // 256}.{i % 256}"
            dos_protection.analyze_request(ip, f"user_{i}")
        
        # Thresholds should be lowered
        new_threshold = dos_protection.get_current_threshold()
        default_threshold = dos_protection.config.default_threshold
        
        assert new_threshold < default_threshold
    
    @pytest.mark.unit
    @pytest.mark.ratelimit
    @pytest.mark.security
    def test_cleanup_expired_data(self, dos_protection):
        """Test cleanup of expired tracking data."""
        ip_address = "192.168.1.100"
        
        with patch('time.time') as mock_time:
            start_time = 1000000
            mock_time.return_value = start_time
            
            # Add some data
            dos_protection.analyze_request(ip_address, "test_user")
            dos_protection.block_ip(ip_address, 60)
            
            # Move time forward significantly
            mock_time.return_value = start_time + 3600  # 1 hour later
            
            # Run cleanup
            dos_protection.cleanup_expired_data()
            
            # Old data should be cleaned up
            assert not dos_protection.is_ip_blocked(ip_address)
    
    @pytest.mark.unit
    @pytest.mark.ratelimit
    @pytest.mark.performance
    def test_performance_under_load(self, dos_protection, benchmark):
        """Test DoS protection performance under load."""
        def simulate_requests():
            for i in range(100):
                ip = f"192.168.1.{i % 10}"
                dos_protection.analyze_request(ip, f"user_{i}")
        
        # Benchmark the performance
        result = benchmark(simulate_requests)
        
        # Should complete within reasonable time
        assert result is None  # Function doesn't return anything
