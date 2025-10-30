"""Rate Limiting and DoS Protection Layer

Provides adaptive rate limiting, DoS protection, and traffic analysis
for SMCP requests.
"""

import time
import asyncio
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import statistics
import hashlib

from .exceptions import RateLimitError, SecurityError


class RateLimitType(Enum):
    """Types of rate limits"""
    REQUESTS_PER_SECOND = "rps"
    REQUESTS_PER_MINUTE = "rpm"
    REQUESTS_PER_HOUR = "rph"
    BANDWIDTH_PER_SECOND = "bps"
    CONCURRENT_CONNECTIONS = "concurrent"


@dataclass
class RateLimit:
    """Rate limit configuration"""
    limit_type: RateLimitType
    limit: int
    window_seconds: int
    burst_allowance: int = 0  # Allow bursts up to this amount
    

@dataclass
class UserMetrics:
    """Metrics for a specific user"""
    request_times: deque = field(default_factory=lambda: deque(maxlen=1000))
    request_sizes: deque = field(default_factory=lambda: deque(maxlen=100))
    error_count: int = 0
    last_request_time: float = 0
    reputation_score: float = 0.5  # 0.0 = bad, 1.0 = excellent
    is_suspicious: bool = False
    total_requests: int = 0
    

class AdaptiveRateLimiter:
    """Adaptive rate limiter that adjusts limits based on user behavior"""
    
    def __init__(self, default_limit: int = 100, adaptive: bool = True):
        self.default_limit = default_limit
        self.adaptive = adaptive
        
        # Rate limit configurations
        self.rate_limits = {
            RateLimitType.REQUESTS_PER_SECOND: RateLimit(
                RateLimitType.REQUESTS_PER_SECOND, 10, 1, burst_allowance=5
            ),
            RateLimitType.REQUESTS_PER_MINUTE: RateLimit(
                RateLimitType.REQUESTS_PER_MINUTE, default_limit, 60, burst_allowance=20
            ),
            RateLimitType.REQUESTS_PER_HOUR: RateLimit(
                RateLimitType.REQUESTS_PER_HOUR, default_limit * 10, 3600, burst_allowance=100
            ),
        }
        
        # User-specific data
        self.user_metrics: Dict[str, UserMetrics] = defaultdict(UserMetrics)
        self.user_limits: Dict[str, Dict[RateLimitType, int]] = defaultdict(dict)
        
        # Global metrics
        self.global_request_count = 0
        self.global_request_times = deque(maxlen=10000)
        
        # Whitelist/Blacklist
        self.whitelisted_users = set()
        self.blacklisted_users = set()
        
    def check_rate_limit(self, user_id: str, endpoint: str = "default", 
                        request_size: int = 0) -> bool:
        """Check if request is within rate limits
        
        Args:
            user_id: User identifier
            endpoint: Endpoint being accessed
            request_size: Size of request in bytes
            
        Returns:
            True if within limits, False otherwise
            
        Raises:
            RateLimitError: If rate limit is exceeded
        """
        current_time = time.time()
        
        # Check blacklist
        if user_id in self.blacklisted_users:
            raise RateLimitError(f"User {user_id} is blacklisted")
        
        # Skip checks for whitelisted users
        if user_id in self.whitelisted_users:
            self._record_request(user_id, current_time, request_size, True)
            return True
        
        user_metrics = self.user_metrics[user_id]
        
        # Check each rate limit type
        for limit_type, rate_limit in self.rate_limits.items():
            if not self._check_specific_limit(user_id, limit_type, rate_limit, current_time):
                self._record_request(user_id, current_time, request_size, False)
                raise RateLimitError(
                    f"Rate limit exceeded for {limit_type.value}: {rate_limit.limit} per {rate_limit.window_seconds}s"
                )
        
        # Check for suspicious patterns
        if self._is_suspicious_pattern(user_id, current_time):
            user_metrics.is_suspicious = True
            raise RateLimitError(f"Suspicious request pattern detected for user {user_id}")
        
        # Record successful request
        self._record_request(user_id, current_time, request_size, True)
        
        # Update reputation and adaptive limits
        if self.adaptive:
            self._update_reputation(user_id)
            self._adjust_limits(user_id)
        
        return True
    
    def _check_specific_limit(self, user_id: str, limit_type: RateLimitType, 
                            rate_limit: RateLimit, current_time: float) -> bool:
        """Check a specific rate limit type"""
        user_metrics = self.user_metrics[user_id]
        
        # Get effective limit (may be adjusted for this user)
        effective_limit = self.user_limits[user_id].get(
            limit_type, rate_limit.limit
        )
        
        # Count requests in the time window
        window_start = current_time - rate_limit.window_seconds
        
        # Clean old requests
        while (user_metrics.request_times and 
               user_metrics.request_times[0] < window_start):
            user_metrics.request_times.popleft()
        
        request_count = len(user_metrics.request_times)
        
        # Check base limit
        if request_count >= effective_limit:
            # Check if burst allowance can be used
            if request_count >= effective_limit + rate_limit.burst_allowance:
                return False
            
            # Allow burst if user has good reputation
            if user_metrics.reputation_score < 0.7:
                return False
        
        return True
    
    def _is_suspicious_pattern(self, user_id: str, current_time: float) -> bool:
        """Detect suspicious request patterns"""
        user_metrics = self.user_metrics[user_id]
        
        if len(user_metrics.request_times) < 5:
            return False
        
        recent_requests = list(user_metrics.request_times)[-10:]
        
        # Check for very regular intervals (bot-like behavior)
        if len(recent_requests) >= 5:
            intervals = [recent_requests[i] - recent_requests[i-1] 
                        for i in range(1, len(recent_requests))]
            
            # If all intervals are very similar, it might be a bot
            if len(set(round(interval, 1) for interval in intervals)) <= 2:
                return True
        
        # Check for rapid-fire requests
        if len(recent_requests) >= 3:
            last_three = recent_requests[-3:]
            if last_three[-1] - last_three[0] < 0.1:  # 3 requests in 100ms
                return True
        
        # Check error rate
        if user_metrics.total_requests > 10:
            error_rate = user_metrics.error_count / user_metrics.total_requests
            if error_rate > 0.5:  # More than 50% errors
                return True
        
        return False
    
    def _record_request(self, user_id: str, timestamp: float, 
                       request_size: int, success: bool):
        """Record request metrics"""
        user_metrics = self.user_metrics[user_id]
        
        user_metrics.request_times.append(timestamp)
        user_metrics.last_request_time = timestamp
        user_metrics.total_requests += 1
        
        if request_size > 0:
            user_metrics.request_sizes.append(request_size)
        
        if not success:
            user_metrics.error_count += 1
        
        # Global metrics
        self.global_request_count += 1
        self.global_request_times.append(timestamp)
    
    def _update_reputation(self, user_id: str):
        """Update user reputation score based on behavior"""
        user_metrics = self.user_metrics[user_id]
        
        if user_metrics.total_requests < 10:
            return  # Not enough data
        
        # Calculate error rate
        error_rate = user_metrics.error_count / user_metrics.total_requests
        
        # Calculate request pattern regularity
        regularity_score = self._calculate_regularity_score(user_id)
        
        # Calculate size consistency
        size_consistency = self._calculate_size_consistency(user_id)
        
        # Update reputation (weighted average)
        new_score = (
            (1 - error_rate) * 0.4 +  # Lower error rate = better
            (1 - regularity_score) * 0.3 +  # Less regular = more human-like
            size_consistency * 0.3  # Consistent sizes = normal usage
        )
        
        # Smooth the reputation change
        user_metrics.reputation_score = (
            user_metrics.reputation_score * 0.8 + new_score * 0.2
        )
        
        # Clamp to valid range
        user_metrics.reputation_score = max(0.0, min(1.0, user_metrics.reputation_score))
    
    def _calculate_regularity_score(self, user_id: str) -> float:
        """Calculate how regular/bot-like the request pattern is"""
        user_metrics = self.user_metrics[user_id]
        
        if len(user_metrics.request_times) < 5:
            return 0.5
        
        recent_requests = list(user_metrics.request_times)[-20:]
        intervals = [recent_requests[i] - recent_requests[i-1] 
                    for i in range(1, len(recent_requests))]
        
        if len(intervals) < 2:
            return 0.5
        
        # Calculate coefficient of variation
        mean_interval = statistics.mean(intervals)
        if mean_interval == 0:
            return 1.0  # Very regular
        
        std_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0
        cv = std_interval / mean_interval
        
        # Higher CV = less regular = more human-like
        return min(1.0, cv)
    
    def _calculate_size_consistency(self, user_id: str) -> float:
        """Calculate request size consistency"""
        user_metrics = self.user_metrics[user_id]
        
        if len(user_metrics.request_sizes) < 3:
            return 0.5
        
        sizes = list(user_metrics.request_sizes)
        
        # Calculate coefficient of variation for sizes
        mean_size = statistics.mean(sizes)
        if mean_size == 0:
            return 1.0
        
        std_size = statistics.stdev(sizes) if len(sizes) > 1 else 0
        cv = std_size / mean_size
        
        # Moderate variation is normal
        if 0.1 <= cv <= 0.5:
            return 1.0
        elif cv < 0.1:
            return 0.5  # Too consistent
        else:
            return max(0.0, 1.0 - (cv - 0.5))  # Too variable
    
    def _adjust_limits(self, user_id: str):
        """Adjust rate limits based on user reputation"""
        user_metrics = self.user_metrics[user_id]
        reputation = user_metrics.reputation_score
        
        # Adjust limits based on reputation
        for limit_type, base_limit in self.rate_limits.items():
            if reputation > 0.8:
                # High reputation users get higher limits
                multiplier = 1.5
            elif reputation > 0.6:
                # Good users get slightly higher limits
                multiplier = 1.2
            elif reputation < 0.3:
                # Low reputation users get lower limits
                multiplier = 0.5
            elif reputation < 0.5:
                # Suspicious users get reduced limits
                multiplier = 0.7
            else:
                # Normal users keep default limits
                multiplier = 1.0
            
            adjusted_limit = int(base_limit.limit * multiplier)
            self.user_limits[user_id][limit_type] = adjusted_limit
    
    def add_to_whitelist(self, user_id: str):
        """Add user to whitelist (bypass rate limits)"""
        self.whitelisted_users.add(user_id)
        if user_id in self.blacklisted_users:
            self.blacklisted_users.remove(user_id)
    
    def add_to_blacklist(self, user_id: str):
        """Add user to blacklist (block all requests)"""
        self.blacklisted_users.add(user_id)
        if user_id in self.whitelisted_users:
            self.whitelisted_users.remove(user_id)
    
    def remove_from_whitelist(self, user_id: str):
        """Remove user from whitelist"""
        self.whitelisted_users.discard(user_id)
    
    def remove_from_blacklist(self, user_id: str):
        """Remove user from blacklist"""
        self.blacklisted_users.discard(user_id)
    
    def get_user_status(self, user_id: str) -> Dict[str, Any]:
        """Get current status and metrics for user"""
        user_metrics = self.user_metrics[user_id]
        
        current_time = time.time()
        
        # Calculate current request rates
        rates = {}
        for limit_type, rate_limit in self.rate_limits.items():
            window_start = current_time - rate_limit.window_seconds
            recent_requests = [
                t for t in user_metrics.request_times 
                if t >= window_start
            ]
            rates[limit_type.value] = len(recent_requests)
        
        return {
            "user_id": user_id,
            "reputation_score": user_metrics.reputation_score,
            "is_suspicious": user_metrics.is_suspicious,
            "total_requests": user_metrics.total_requests,
            "error_count": user_metrics.error_count,
            "error_rate": user_metrics.error_count / max(1, user_metrics.total_requests),
            "current_rates": rates,
            "effective_limits": dict(self.user_limits[user_id]),
            "is_whitelisted": user_id in self.whitelisted_users,
            "is_blacklisted": user_id in self.blacklisted_users,
            "last_request_time": user_metrics.last_request_time
        }


class DoSProtection:
    """Denial of Service protection system"""
    
    def __init__(self):
        self.connection_tracker = defaultdict(list)
        self.request_patterns = defaultdict(dict)
        self.global_metrics = {
            "total_requests": 0,
            "blocked_requests": 0,
            "start_time": time.time()
        }
        
        # DoS detection thresholds
        self.thresholds = {
            "max_connections_per_ip": 100,
            "max_request_rate_global": 10000,  # requests per minute
            "max_request_size": 10 * 1024 * 1024,  # 10MB
            "max_concurrent_requests": 1000,
            "suspicious_pattern_threshold": 0.8
        }
        
        self.active_connections = set()
        self.blocked_ips = {}
        
    def analyze_request_pattern(self, user_id: str, request_data: Dict[str, Any]) -> bool:
        """Analyze request for DoS patterns
        
        Args:
            user_id: User identifier
            request_data: Request data to analyze
            
        Returns:
            True if request is allowed, False if blocked
        """
        current_time = time.time()
        
        # Update global metrics
        self.global_metrics["total_requests"] += 1
        
        # Check global rate limit
        if not self._check_global_rate_limit():
            self.global_metrics["blocked_requests"] += 1
            return False
        
        # Analyze request size
        request_size = len(str(request_data))
        if request_size > self.thresholds["max_request_size"]:
            return False
        
        # Track request pattern
        pattern_key = f"{user_id}"
        
        if pattern_key not in self.request_patterns:
            self.request_patterns[pattern_key] = {
                "count": 0,
                "first_seen": current_time,
                "last_seen": current_time,
                "sizes": deque(maxlen=100),
                "methods": deque(maxlen=100),
                "intervals": deque(maxlen=50)
            }
        
        pattern = self.request_patterns[pattern_key]
        
        # Update pattern data
        if pattern["last_seen"] > 0:
            interval = current_time - pattern["last_seen"]
            pattern["intervals"].append(interval)
        
        pattern["count"] += 1
        pattern["last_seen"] = current_time
        pattern["sizes"].append(request_size)
        pattern["methods"].append(request_data.get("method", "unknown"))
        
        # Analyze for suspicious patterns
        if self._is_dos_pattern(pattern):
            return False
        
        return True
    
    def _check_global_rate_limit(self) -> bool:
        """Check global system rate limit"""
        current_time = time.time()
        
        # This is a simplified check - in production, use a proper sliding window
        recent_rate = self.global_metrics["total_requests"] / max(1, current_time - self.global_metrics["start_time"]) * 60
        
        return recent_rate <= self.thresholds["max_request_rate_global"]
    
    def _is_dos_pattern(self, pattern: Dict[str, Any]) -> bool:
        """Detect DoS attack patterns"""
        current_time = time.time()
        
        # High frequency requests
        time_window = current_time - pattern["first_seen"]
        if time_window > 0:
            request_rate = pattern["count"] / time_window
            if request_rate > 100:  # More than 100 requests per second
                return True
        
        # Very large requests
        if pattern["sizes"] and max(pattern["sizes"]) > self.thresholds["max_request_size"]:
            return True
        
        # Consistent timing (bot-like behavior)
        if len(pattern["intervals"]) >= 10:
            intervals = list(pattern["intervals"])[-10:]
            if len(set(round(interval, 2) for interval in intervals)) <= 2:
                return True
        
        # Repeated identical requests
        if len(pattern["methods"]) >= 20:
            recent_methods = list(pattern["methods"])[-20:]
            if len(set(recent_methods)) == 1:  # All same method
                return True
        
        return False
    
    def block_ip(self, ip_address: str, duration_seconds: int = 3600):
        """Block an IP address
        
        Args:
            ip_address: IP address to block
            duration_seconds: Block duration in seconds
        """
        self.blocked_ips[ip_address] = time.time() + duration_seconds
    
    def is_ip_blocked(self, ip_address: str) -> bool:
        """Check if IP address is blocked
        
        Args:
            ip_address: IP address to check
            
        Returns:
            True if blocked, False otherwise
        """
        if ip_address not in self.blocked_ips:
            return False
        
        # Check if block has expired
        if time.time() > self.blocked_ips[ip_address]:
            del self.blocked_ips[ip_address]
            return False
        
        return True
    
    def unblock_ip(self, ip_address: str):
        """Unblock an IP address
        
        Args:
            ip_address: IP address to unblock
        """
        if ip_address in self.blocked_ips:
            del self.blocked_ips[ip_address]
    
    def get_protection_status(self) -> Dict[str, Any]:
        """Get current DoS protection status"""
        current_time = time.time()
        uptime = current_time - self.global_metrics["start_time"]
        
        # Clean expired blocks
        expired_blocks = [
            ip for ip, expiry in self.blocked_ips.items()
            if current_time > expiry
        ]
        for ip in expired_blocks:
            del self.blocked_ips[ip]
        
        return {
            "total_requests": self.global_metrics["total_requests"],
            "blocked_requests": self.global_metrics["blocked_requests"],
            "block_rate": self.global_metrics["blocked_requests"] / max(1, self.global_metrics["total_requests"]),
            "uptime_seconds": uptime,
            "requests_per_second": self.global_metrics["total_requests"] / max(1, uptime),
            "active_patterns": len(self.request_patterns),
            "blocked_ips": len(self.blocked_ips),
            "thresholds": self.thresholds
        }
    
    def reset_metrics(self):
        """Reset all metrics and patterns"""
        self.global_metrics = {
            "total_requests": 0,
            "blocked_requests": 0,
            "start_time": time.time()
        }
        self.request_patterns.clear()
        self.connection_tracker.clear()
    
    def update_thresholds(self, new_thresholds: Dict[str, Any]):
        """Update DoS protection thresholds
        
        Args:
            new_thresholds: Dictionary of new threshold values
        """
        for key, value in new_thresholds.items():
            if key in self.thresholds:
                self.thresholds[key] = value