"""Secure Model Context Protocol (SMCP) v1 - "HTTPS for MCP"

A security framework for Model Context Protocol implementations
that provides multi-layered defense against various attack vectors including
command injection, prompt manipulation, authentication bypass, and more.

## Quick Start

### Option 1: Decorator Style (Recommended)
```python
from smcp_security import protect

@server.call_tool()
@protect
async def execute_command(arguments):
    return execute(arguments)  # Now protected!
```

### Option 2: One-Liner Style
```python
from smcp_security import secure_mcp

server = Server("my-tools")
server = secure_mcp(server)  # All tools now protected!
```

### Option 3: Middleware Style
```python
from smcp_security import SMCPMiddleware

app.add_middleware(SMCPMiddleware)
```
"""

__version__ = "1.0.0-beta1"
__author__ = "SMCP Security Team"
__email__ = "security@smcp.dev"

# Simple integration (recommended for most users)
from .simple import (
    protect,
    secure_mcp,
    SMCPMiddleware,
    get_default_security,
)

# Core framework (for advanced users)
from .core import SMCPSecurityFramework, SecurityConfig
from .input_validation import InputValidator, CommandInjectionPrevention
from .authentication import JWTAuthenticator, MFAManager
from .authorization import RBACManager
from .rate_limiting import AdaptiveRateLimiter, DoSProtection
from .cryptography import SMCPCrypto, Argon2KeyDerivation
from .audit import SMCPAuditLogger
from .ai_immune import AIImmuneSystem, ThreatClassifier

__all__ = [
    # Simple integration (most users start here)
    'protect',
    'secure_mcp',
    'SMCPMiddleware',
    'get_default_security',
    # Core framework
    'SMCPSecurityFramework',
    'SecurityConfig',
    # Advanced components
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