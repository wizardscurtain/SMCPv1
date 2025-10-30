"""Secure Model Context Protocol (SMCP) v1 Security Framework

A comprehensive security framework for Model Context Protocol implementations
that provides multi-layered defense against various attack vectors including
command injection, prompt manipulation, authentication bypass, and more.
"""

__version__ = "1.0.0"
__author__ = "Secure AI Systems Laboratory"
__email__ = "security@smcp.org"

from .core import SMCPSecurityFramework, SecurityConfig
from .input_validation import InputValidator, CommandInjectionPrevention
from .authentication import JWTAuthenticator, MFAManager
from .authorization import RBACManager
from .rate_limiting import AdaptiveRateLimiter, DoSProtection
from .cryptography import SMCPCrypto, Argon2KeyDerivation
from .audit import SMCPAuditLogger
from .ai_immune import AIImmuneSystem, ThreatClassifier

__all__ = [
    'SMCPSecurityFramework',
    'SecurityConfig',
    'InputValidator',
    'CommandInjectionPrevention', 
    'JWTAuthenticator',
    'MFAManager',
    'RBACManager',
    'AdaptiveRateLimiter',
    'DoSProtection',
    'SMCPCrypto',
    'Argon2KeyDerivation',
    'SMCPAuditLogger',
    'AIImmuneSystem',
    'ThreatClassifier'
]