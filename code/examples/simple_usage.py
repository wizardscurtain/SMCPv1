"""Simple SMCP Usage Example - "HTTPS for MCP"

This example shows how easy it is to add security to an MCP server.
Just like adding 'https' to 'http', you can add SMCP protection in 1-2 lines.
"""

import asyncio
from smcp_security import protect, secure_mcp, SecurityConfig


# ==============================================================================
# Example 1: Decorator Style (Recommended)
# ==============================================================================

print("=" * 70)
print("Example 1: @protect Decorator - Add security to individual tools")
print("=" * 70)


# Simulated MCP tool (vulnerable without protection)
async def execute_command_unsafe(arguments: dict) -> str:
    """Execute a shell command - DANGEROUS without protection!"""
    command = arguments.get("command", "")
    print(f"\n🚨 UNSAFE: Would execute: {command}")
    return f"Would execute: {command}"


# Same tool, but protected with @protect decorator
@protect
async def execute_command_safe(arguments: dict) -> str:
    """Execute a shell command - NOW PROTECTED by SMCP!"""
    command = arguments.get("command", "")
    print(f"\n✅ SAFE: Validated command: {command}")
    return f"Safely executed: {command}"


async def demo_decorator():
    """Demonstrate @protect decorator blocking attacks."""

    print("\n--- Testing legitimate request ---")
    try:
        result = await execute_command_safe({"command": "ls -la"})
        print(f"✅ Success: {result}")
    except Exception as e:
        print(f"❌ Blocked: {e}")

    print("\n--- Testing command injection attack ---")
    try:
        # Attempt command injection
        result = await execute_command_safe({
            "command": "ls; rm -rf / #"  # Malicious!
        })
        print(f"✅ Success: {result}")
    except Exception as e:
        print(f"✅ BLOCKED ATTACK: {e}")

    print("\n--- Testing path traversal attack ---")
    try:
        # Attempt path traversal
        result = await execute_command_safe({
            "command": "cat ../../../../etc/passwd"  # Malicious!
        })
        print(f"✅ Success: {result}")
    except Exception as e:
        print(f"✅ BLOCKED ATTACK: {e}")


# ==============================================================================
# Example 2: One-Liner Style (Simplest)
# ==============================================================================

print("\n\n" + "=" * 70)
print("Example 2: secure_mcp() - Protect entire server in one line")
print("=" * 70)


class FakeMCPServer:
    """Simulated MCP server for demonstration."""

    def __init__(self, name: str):
        self.name = name
        self.tools = []

    def call_tool(self):
        """Decorator for registering tools."""
        def decorator(func):
            self.tools.append(func)
            return func
        return decorator


def demo_secure_mcp():
    """Demonstrate secure_mcp() one-liner."""

    print("\n--- Creating MCP server ---")
    server = FakeMCPServer("my-vulnerable-server")

    print("✅ Server created")

    print("\n--- Adding SMCP security (ONE LINE) ---")
    server = secure_mcp(server)  # ← That's it! Now protected!

    print("✅ Server now protected by SMCP")
    print(f"   - Input validation: ENABLED")
    print(f"   - Rate limiting: ENABLED (100 req/min)")
    print(f"   - Prompt injection detection: ENABLED")
    print(f"   - Audit logging: ENABLED")

    # All tools registered after this point are automatically protected
    @server.call_tool()
    async def dangerous_tool(args):
        return "This tool is now protected!"


# ==============================================================================
# Example 3: Custom Configuration
# ==============================================================================

print("\n\n" + "=" * 70)
print("Example 3: Custom Config - Fine-tune security settings")
print("=" * 70)


def demo_custom_config():
    """Demonstrate custom security configuration."""

    print("\n--- Creating custom security config ---")

    config = SecurityConfig(
        # Input validation
        enable_input_validation=True,
        validation_strictness="maximum",  # Strictest mode

        # Rate limiting
        enable_rate_limiting=True,
        default_rate_limit=200,  # 200 requests per minute

        # AI threat detection
        enable_ai_immune=True,
        anomaly_threshold=0.9,  # Higher threshold = stricter

        # Audit logging
        enable_audit_logging=True,
        log_level="DEBUG",  # Detailed logs

        # Optional features
        enable_mfa=True,  # Enable MFA
        enable_rbac=True,  # Enable role-based access control
    )

    print("✅ Custom config created:")
    print(f"   - Strictness: {config.validation_strictness}")
    print(f"   - Rate limit: {config.default_rate_limit} req/min")
    print(f"   - Anomaly threshold: {config.anomaly_threshold}")
    print(f"   - MFA: {config.enable_mfa}")
    print(f"   - RBAC: {config.enable_rbac}")

    server = FakeMCPServer("my-server")
    server = secure_mcp(server, config)  # Use custom config

    print("\n✅ Server protected with custom configuration")


# ==============================================================================
# Example 4: Real-World Scenario
# ==============================================================================

print("\n\n" + "=" * 70)
print("Example 4: Real-World - File access tool with SMCP protection")
print("=" * 70)


@protect
async def read_file(arguments: dict) -> str:
    """Read a file - protected against path traversal."""
    filepath = arguments.get("path", "")

    # SMCP already validated the path before we get here
    # No path traversal, no command injection possible

    print(f"\n✅ Reading file: {filepath}")
    return f"Contents of {filepath}..."


async def demo_real_world():
    """Demonstrate real-world file access protection."""

    print("\n--- Legitimate file access ---")
    try:
        result = await read_file({"path": "/home/user/document.txt"})
        print(f"✅ Success: {result}")
    except Exception as e:
        print(f"❌ Blocked: {e}")

    print("\n--- Attempting path traversal attack ---")
    try:
        # Hacker tries to read /etc/passwd
        result = await read_file({"path": "../../../../etc/passwd"})
        print(f"❌ SECURITY BREACH: {result}")  # Should never reach here
    except Exception as e:
        print(f"✅ ATTACK BLOCKED: Path traversal detected and prevented")

    print("\n--- Attempting command injection via filename ---")
    try:
        # Hacker tries to inject commands
        result = await read_file({"path": "file.txt; cat /etc/passwd #"})
        print(f"❌ SECURITY BREACH: {result}")  # Should never reach here
    except Exception as e:
        print(f"✅ ATTACK BLOCKED: Command injection detected and prevented")


# ==============================================================================
# Run All Examples
# ==============================================================================

async def main():
    """Run all examples."""

    # Example 1: Decorator style
    await demo_decorator()

    # Example 2: One-liner style
    demo_secure_mcp()

    # Example 3: Custom configuration
    demo_custom_config()

    # Example 4: Real-world scenario
    await demo_real_world()

    print("\n\n" + "=" * 70)
    print("Summary: SMCP - 'HTTPS for MCP'")
    print("=" * 70)
    print("\n✅ Three ways to add security:")
    print("   1. @protect decorator - per-tool protection")
    print("   2. secure_mcp(server) - one-line server protection")
    print("   3. SMCPMiddleware - framework middleware")
    print("\n✅ What you get:")
    print("   - Command injection protection")
    print("   - Prompt injection detection")
    print("   - Path traversal prevention")
    print("   - XSS & SQL injection blocking")
    print("   - Rate limiting & DoS protection")
    print("   - Audit logging & monitoring")
    print("\n✅ Just like HTTPS made HTTP secure,")
    print("   SMCP makes MCP secure - in 1-2 lines of code!")
    print("=" * 70)


if __name__ == "__main__":
    print("\n🔒 SMCP Security Framework - Simple Usage Examples\n")
    asyncio.run(main())
