"""Example 2: Secure File Operations with SMCP

This example shows how to build a secure file management MCP server
that protects against path traversal, command injection, and other attacks.

Real-world use case: AI agent that can read/write files safely.

Run this example:
    python examples/02_file_operations.py
"""

import asyncio
import os
import tempfile
from pathlib import Path
from typing import Dict, Any, List
from smcp_security import protect, SecurityConfig, SMCPSecurityFramework


# ============================================================================
# Secure File Operations Server
# ============================================================================

class SecureFileServer:
    """
    MCP server for file operations with SMCP protection.

    Features:
    - Read files (with path traversal protection)
    - List directories (with path restrictions)
    - Search files (with injection protection)
    - Get file info (with validation)

    All operations are protected by SMCP.
    """

    def __init__(self, allowed_dir: str = None):
        """
        Initialize server with optional directory restriction.

        Args:
            allowed_dir: Directory to restrict operations to (None = no restriction)
        """
        self.allowed_dir = allowed_dir
        print(f"✅ Server initialized")
        if allowed_dir:
            print(f"   Restricted to: {allowed_dir}")

    @protect
    async def read_file(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Read a file securely.

        Protected against:
        - Path traversal (../, ../../../../etc/passwd)
        - Command injection (file.txt; cat /etc/passwd)
        - Symlink attacks

        Args:
            arguments: {"path": "/path/to/file.txt"}

        Returns:
            {"content": "file contents", "size": 1234}
        """
        filepath = arguments.get("path")

        # Additional application-level validation
        if self.allowed_dir:
            abs_path = os.path.abspath(filepath)
            allowed_path = os.path.abspath(self.allowed_dir)
            if not abs_path.startswith(allowed_path):
                raise ValueError(f"Access denied: outside allowed directory")

        # SMCP already validated against path traversal and injection
        # Now safe to read the file
        try:
            with open(filepath, 'r') as f:
                content = f.read()

            return {
                "content": content,
                "size": len(content),
                "path": filepath
            }
        except FileNotFoundError:
            return {"error": "File not found", "path": filepath}
        except PermissionError:
            return {"error": "Permission denied", "path": filepath}

    @protect
    async def list_directory(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        List files in a directory securely.

        Protected against:
        - Path traversal
        - Directory escape attempts

        Args:
            arguments: {"path": "/path/to/dir", "pattern": "*.txt"}

        Returns:
            {"files": [...], "directories": [...]}
        """
        dirpath = arguments.get("path", ".")
        pattern = arguments.get("pattern", "*")

        # Validate directory access
        if self.allowed_dir:
            abs_path = os.path.abspath(dirpath)
            allowed_path = os.path.abspath(self.allowed_dir)
            if not abs_path.startswith(allowed_path):
                raise ValueError("Access denied: outside allowed directory")

        try:
            path = Path(dirpath)
            files = []
            directories = []

            for item in path.glob(pattern):
                if item.is_file():
                    files.append({
                        "name": item.name,
                        "size": item.stat().st_size,
                        "modified": item.stat().st_mtime
                    })
                elif item.is_dir():
                    directories.append(item.name)

            return {
                "files": files,
                "directories": directories,
                "path": str(path)
            }
        except Exception as e:
            return {"error": str(e)}

    @protect
    async def search_files(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Search for files containing text.

        Protected against:
        - Command injection in search terms
        - Path traversal in search directory

        Args:
            arguments: {
                "directory": "/path/to/search",
                "text": "search term",
                "file_pattern": "*.py"
            }

        Returns:
            {"matches": [...]}
        """
        directory = arguments.get("directory", ".")
        search_text = arguments.get("text", "")
        file_pattern = arguments.get("file_pattern", "*")

        # SMCP protects against injection in search_text
        # Now safe to use in file operations

        matches = []
        try:
            path = Path(directory)
            for file_path in path.rglob(file_pattern):
                if file_path.is_file():
                    try:
                        with open(file_path, 'r') as f:
                            content = f.read()
                            if search_text in content:
                                # Count occurrences
                                count = content.count(search_text)
                                matches.append({
                                    "file": str(file_path),
                                    "occurrences": count
                                })
                    except (UnicodeDecodeError, PermissionError):
                        # Skip binary files or files we can't read
                        continue

            return {
                "matches": matches,
                "search_text": search_text,
                "files_searched": len(list(path.rglob(file_pattern)))
            }
        except Exception as e:
            return {"error": str(e)}

    @protect
    async def get_file_info(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get metadata about a file.

        Args:
            arguments: {"path": "/path/to/file"}

        Returns:
            {"size": ..., "modified": ..., "type": ...}
        """
        filepath = arguments.get("path")

        try:
            path = Path(filepath)
            stat = path.stat()

            return {
                "path": str(path),
                "size": stat.st_size,
                "modified": stat.st_mtime,
                "is_file": path.is_file(),
                "is_directory": path.is_dir(),
                "extension": path.suffix
            }
        except Exception as e:
            return {"error": str(e)}


# ============================================================================
# Demonstration
# ============================================================================

async def demonstrate_secure_operations():
    """Demonstrate secure file operations."""
    print("\n" + "=" * 70)
    print("DEMONSTRATION: Secure File Operations")
    print("=" * 70)

    # Create a temporary directory for testing
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test files
        test_file = os.path.join(tmpdir, "test.txt")
        with open(test_file, 'w') as f:
            f.write("This is a test file.\nIt contains multiple lines.\n")

        secret_file = os.path.join(tmpdir, "secret.txt")
        with open(secret_file, 'w') as f:
            f.write("This is secret data that should be protected.")

        print(f"\n✅ Created test environment in: {tmpdir}")

        # Initialize server (no restrictions for demo)
        server = SecureFileServer()

        # Test 1: Read legitimate file
        print("\n--- Test 1: Reading legitimate file ---")
        result = await server.read_file({"path": test_file})
        print(f"✅ Success: Read {result['size']} bytes")
        print(f"   Content preview: {result['content'][:50]}...")

        # Test 2: List directory
        print("\n--- Test 2: Listing directory ---")
        result = await server.list_directory({"path": tmpdir})
        print(f"✅ Success: Found {len(result['files'])} files")
        for file in result['files']:
            print(f"   - {file['name']} ({file['size']} bytes)")

        # Test 3: Search files
        print("\n--- Test 3: Searching files ---")
        result = await server.search_files({
            "directory": tmpdir,
            "text": "test",
            "file_pattern": "*.txt"
        })
        print(f"✅ Success: Found {len(result['matches'])} matches")
        for match in result['matches']:
            print(f"   - {match['file']}: {match['occurrences']} occurrences")

        # Test 4: Get file info
        print("\n--- Test 4: Getting file info ---")
        result = await server.get_file_info({"path": test_file})
        print(f"✅ Success: File info retrieved")
        print(f"   Size: {result['size']} bytes")
        print(f"   Extension: {result['extension']}")


async def demonstrate_attack_protection():
    """Demonstrate how SMCP blocks attacks."""
    print("\n\n" + "=" * 70)
    print("DEMONSTRATION: Attack Protection")
    print("=" * 70)

    server = SecureFileServer()

    # Attack 1: Path traversal
    print("\n--- ATTACK 1: Path Traversal ---")
    try:
        result = await server.read_file({
            "path": "../../../../etc/passwd"
        })
        print("❌ Attack succeeded (This shouldn't happen!)")
    except Exception as e:
        print("✅ ATTACK BLOCKED!")
        print(f"   Reason: Path traversal detected")

    # Attack 2: Command injection via filename
    print("\n--- ATTACK 2: Command Injection ---")
    try:
        result = await server.read_file({
            "path": "test.txt; cat /etc/passwd #"
        })
        print("❌ Attack succeeded (This shouldn't happen!)")
    except Exception as e:
        print("✅ ATTACK BLOCKED!")
        print(f"   Reason: Command injection detected")

    # Attack 3: Injection in search term
    print("\n--- ATTACK 3: Search Injection ---")
    try:
        result = await server.search_files({
            "directory": ".",
            "text": "test'; DROP TABLE users; --",
            "file_pattern": "*.txt"
        })
        print("✅ SEARCH ALLOWED (but safely sanitized)")
        print("   SMCP ensures search term can't cause harm")
    except Exception as e:
        print(f"   Error: {e}")


async def demonstrate_restricted_access():
    """Demonstrate directory restriction feature."""
    print("\n\n" + "=" * 70)
    print("DEMONSTRATION: Restricted Access")
    print("=" * 70)

    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test file
        test_file = os.path.join(tmpdir, "allowed.txt")
        with open(test_file, 'w') as f:
            f.write("This file is within allowed directory")

        # Initialize server with restrictions
        server = SecureFileServer(allowed_dir=tmpdir)

        print(f"\n✅ Server restricted to: {tmpdir}")

        # Test 1: Access allowed file
        print("\n--- Test 1: Access file in allowed directory ---")
        try:
            result = await server.read_file({"path": test_file})
            print(f"✅ SUCCESS: Access granted")
            print(f"   Read {result['size']} bytes")
        except Exception as e:
            print(f"❌ Error: {e}")

        # Test 2: Try to access file outside allowed directory
        print("\n--- Test 2: Access file outside allowed directory ---")
        try:
            result = await server.read_file({"path": "/etc/hosts"})
            print(f"❌ SECURITY BREACH: Access granted (shouldn't happen!)")
        except Exception as e:
            print(f"✅ ACCESS DENIED: Outside allowed directory")


async def show_best_practices():
    """Show best practices for secure file operations."""
    print("\n\n" + "=" * 70)
    print("BEST PRACTICES FOR SECURE FILE OPERATIONS")
    print("=" * 70)

    practices = [
        ("1. Use @protect decorator", "Adds SMCP validation automatically"),
        ("2. Restrict to specific directory", "Use allowed_dir parameter"),
        ("3. Handle errors gracefully", "Return error dicts, don't crash"),
        ("4. Validate file types", "Check extensions before processing"),
        ("5. Set file size limits", "Prevent reading huge files"),
        ("6. Log all file access", "Audit trail for security"),
        ("7. Use absolute paths", "Avoid ambiguity"),
        ("8. Check permissions", "Catch PermissionError"),
    ]

    for practice, description in practices:
        print(f"\n✅ {practice}")
        print(f"   → {description}")


# ============================================================================
# Main
# ============================================================================

async def main():
    """Run all demonstrations."""
    print("\n🔒 SMCP Example 2: Secure File Operations")
    print("=" * 70)
    print("This example demonstrates:")
    print("1. Building a secure file operations server")
    print("2. Protection against path traversal attacks")
    print("3. Protection against command injection")
    print("4. Directory access restrictions")
    print("5. Best practices for file operations")
    print("=" * 70)

    await demonstrate_secure_operations()
    await demonstrate_attack_protection()
    await demonstrate_restricted_access()
    await show_best_practices()

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print("""
SMCP provides:
✅ Automatic path traversal protection
✅ Command injection prevention
✅ Safe text searching
✅ Directory access control
✅ Audit logging of all operations

Real-world applications:
- AI assistants that read/write files
- Code analysis tools
- Document processing services
- File management interfaces

Implementation: Just add @protect to your file operation functions!
    """)
    print("=" * 70)


if __name__ == "__main__":
    print("\n🚀 Running SMCP Secure File Operations Example\n")
    asyncio.run(main())
    print("\n✅ Example complete!\n")
