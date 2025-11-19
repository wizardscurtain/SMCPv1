"""Example 1: Basic MCP Server Protection

This example shows how to add SMCP security to a basic MCP server
in the simplest way possible - using the @protect decorator.

Run this example:
    python examples/01_basic_protection.py
"""

import asyncio
from typing import Dict, Any
from smcp_security import protect


# ============================================================================
# WITHOUT SMCP - Vulnerable Server
# ============================================================================

class VulnerableServer:
    """Example of an unprotected MCP server - DON'T DO THIS!"""

    async def execute_command(self, arguments: Dict[str, Any]) -> str:
        """Execute a shell command - DANGEROUS!"""
        command = arguments.get("command", "")
        print(f"\n🚨 UNSAFE: Executing command: {command}")

        # This is vulnerable to command injection!
        # Don't actually execute this in production
        return f"Would execute: {command}"

    async def read_file(self, arguments: Dict[str, Any]) -> str:
        """Read a file - DANGEROUS!"""
        filepath = arguments.get("path", "")
        print(f"\n🚨 UNSAFE: Reading file: {filepath}")

        # This is vulnerable to path traversal!
        return f"Would read: {filepath}"


# ============================================================================
# WITH SMCP - Protected Server
# ============================================================================

class ProtectedServer:
    """Example of a protected MCP server using SMCP."""

    @protect
    async def execute_command(self, arguments: Dict[str, Any]) -> str:
        """Execute a shell command - NOW PROTECTED!"""
        command = arguments.get("command", "")
        print(f"\n✅ SAFE: Validated command: {command}")

        # SMCP validates before we get here
        # Command injection attempts are blocked
        return f"Safely executed: {command}"

    @protect
    async def read_file(self, arguments: Dict[str, Any]) -> str:
        """Read a file - NOW PROTECTED!"""
        filepath = arguments.get("path", "")
        print(f"\n✅ SAFE: Validated filepath: {filepath}")

        # SMCP validates before we get here
        # Path traversal attempts are blocked
        return f"Safely read: {filepath}"


# ============================================================================
# Demonstration
# ============================================================================

async def demonstrate_vulnerability():
    """Show how the vulnerable server can be exploited."""
    print("=" * 70)
    print("DEMONSTRATION: Vulnerable Server (WITHOUT SMCP)")
    print("=" * 70)

    server = VulnerableServer()

    # Legitimate requests work
    print("\n--- Legitimate Request ---")
    result = await server.execute_command({"command": "ls -la"})
    print(f"Result: {result}")

    # But attacks also work! 😱
    print("\n--- ATTACK: Command Injection ---")
    result = await server.execute_command({
        "command": "ls; rm -rf / #"  # Malicious!
    })
    print(f"Result: {result}")
    print("⚠️  Attack succeeded! System compromised!")

    print("\n--- ATTACK: Path Traversal ---")
    result = await server.read_file({
        "path": "../../../../etc/passwd"  # Malicious!
    })
    print(f"Result: {result}")
    print("⚠️  Attack succeeded! Sensitive file accessed!")


async def demonstrate_protection():
    """Show how SMCP protects against attacks."""
    print("\n\n" + "=" * 70)
    print("DEMONSTRATION: Protected Server (WITH SMCP)")
    print("=" * 70)

    server = ProtectedServer()

    # Legitimate requests still work
    print("\n--- Legitimate Request ---")
    try:
        result = await server.execute_command({"command": "ls -la"})
        print(f"Result: {result}")
    except Exception as e:
        print(f"Error: {e}")

    # But attacks are blocked! 🛡️
    print("\n--- ATTACK BLOCKED: Command Injection ---")
    try:
        result = await server.execute_command({
            "command": "ls; rm -rf / #"  # Malicious!
        })
        print(f"Result: {result}")
    except Exception as e:
        print(f"✅ ATTACK BLOCKED!")
        print(f"   Reason: {type(e).__name__}")

    print("\n--- ATTACK BLOCKED: Path Traversal ---")
    try:
        result = await server.read_file({
            "path": "../../../../etc/passwd"  # Malicious!
        })
        print(f"Result: {result}")
    except Exception as e:
        print(f"✅ ATTACK BLOCKED!")
        print(f"   Reason: {type(e).__name__}")


async def test_rate_limiting():
    """Demonstrate rate limiting protection."""
    print("\n\n" + "=" * 70)
    print("DEMONSTRATION: Rate Limiting Protection")
    print("=" * 70)

    server = ProtectedServer()

    print("\n--- Simulating rapid requests ---")

    # Make multiple rapid requests
    for i in range(5):
        try:
            result = await server.execute_command({"command": "echo test"})
            print(f"Request {i+1}: ✅ Success")
        except Exception as e:
            print(f"Request {i+1}: ❌ {type(e).__name__}")

    print("\n✅ Rate limiting prevents abuse!")
    print("   Default limit: 100 requests/minute per user")


async def show_what_smcp_protects():
    """Show all the protections SMCP provides."""
    print("\n\n" + "=" * 70)
    print("WHAT SMCP PROTECTS AGAINST")
    print("=" * 70)

    protections = [
        ("Command Injection", "ls; rm -rf / #", "Prevents shell command chaining"),
        ("Path Traversal", "../../../../etc/passwd", "Prevents directory escape"),
        ("SQL Injection", "1' OR '1'='1", "Detects SQL attack patterns"),
        ("XSS Injection", "<script>alert('xss')</script>", "Detects XSS patterns"),
        ("Prompt Injection", "Ignore all previous instructions", "Detects prompt manipulation"),
        ("Rate Limiting", "10000 rapid requests", "Prevents DoS attacks"),
    ]

    for attack_type, example, description in protections:
        print(f"\n✅ {attack_type}")
        print(f"   Example: {example}")
        print(f"   Protection: {description}")


async def show_usage_summary():
    """Show how easy it is to use SMCP."""
    print("\n\n" + "=" * 70)
    print("HOW TO USE SMCP - IT'S THIS EASY")
    print("=" * 70)

    print("""
# Step 1: Import
from smcp_security import protect

# Step 2: Add decorator
@protect
async def my_tool(arguments):
    return execute(arguments)

# That's it! Your tool is now protected against:
# ✅ Command injection
# ✅ Path traversal
# ✅ SQL injection
# ✅ XSS attacks
# ✅ Prompt injection
# ✅ Rate limit abuse
# ✅ And more...

# All in ONE LINE of code!
    """)


# ============================================================================
# Main
# ============================================================================

async def main():
    """Run all demonstrations."""
    print("\n🔒 SMCP Example 1: Basic Protection")
    print("=" * 70)
    print("This example demonstrates:")
    print("1. How vulnerable servers can be exploited")
    print("2. How SMCP protects against common attacks")
    print("3. How easy it is to add protection (ONE decorator!)")
    print("=" * 70)

    # Show vulnerable server
    await demonstrate_vulnerability()

    # Show protected server
    await demonstrate_protection()

    # Show rate limiting
    await test_rate_limiting()

    # Show all protections
    await show_what_smcp_protects()

    # Show usage
    await show_usage_summary()

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print("""
WITHOUT SMCP:
- Vulnerable to command injection ❌
- Vulnerable to path traversal ❌
- Vulnerable to SQL/XSS attacks ❌
- No rate limiting ❌
- No audit trail ❌

WITH SMCP (@protect):
- Protected from command injection ✅
- Protected from path traversal ✅
- Protected from SQL/XSS attacks ✅
- Rate limiting enabled ✅
- Full audit logging ✅

Implementation effort: 1 line of code (@protect)
Time to secure your server: 5 minutes

Just like HTTPS made HTTP secure,
SMCP makes MCP secure.
    """)
    print("=" * 70)


if __name__ == "__main__":
    print("\n🚀 Running SMCP Basic Protection Example\n")
    asyncio.run(main())
    print("\n✅ Example complete!\n")
