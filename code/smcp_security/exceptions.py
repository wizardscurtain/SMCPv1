"""Custom exceptions for SMCP Security Framework"""

class SMCPSecurityError(Exception):
    """Base exception for all SMCP security errors"""
    pass

class SecurityError(SMCPSecurityError):
    """General security error"""
    pass

class ValidationError(SMCPSecurityError):
    """Input validation error"""
    pass

class AuthenticationError(SMCPSecurityError):
    """Authentication failure"""
    pass

class AuthorizationError(SMCPSecurityError):
    """Authorization failure"""
    pass

class RateLimitError(SMCPSecurityError):
    """Rate limit exceeded"""
    pass

class CryptographicError(SMCPSecurityError):
    """Cryptographic operation error"""
    pass

class AnomalyDetectionError(SMCPSecurityError):
    """Anomaly detection error"""
    pass