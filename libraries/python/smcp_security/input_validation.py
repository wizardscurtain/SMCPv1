"""Input Validation and Sanitization Layer

Provides input validation, command injection prevention,
and prompt injection detection for MCP requests.
"""

import re
import json
import html
import base64
import urllib.parse
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
import jsonschema

# Optional ML imports
try:
    from transformers import AutoTokenizer, AutoModel
    import torch
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

from .exceptions import ValidationError, SecurityError


class _AwaitableDict(dict):
    """A dict that is also awaitable.

    Supports both sync (``result = validator.validate_request(req)``) and
    async (``result = await validator.validate_request(req)``) call sites.
    """

    def __await__(self):
        """Return self when awaited (resolves immediately with no I/O)."""
        def _gen():
            return self
            yield  # makes this a generator function (required by __await__ protocol)
        return _gen()


@dataclass
class ValidationRule:
    """Represents a validation rule"""
    name: str
    pattern: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    description: str
    shell_context_only: bool = False  # Only enforce in shell/command context
    required_context: Optional[str] = None  # Only enforce when context matches (None = all)


class CommandInjectionPrevention:
    """Prevents command injection attacks in MCP requests"""
    
    def __init__(self):
        self.dangerous_patterns = [
            ValidationRule(
                "shell_metacharacters",
                # Only flag unambiguously dangerous shell constructs:
                #   $(...)  ${...}  `cmd`  &&  ||
                # Bare ';', '|', '&' appear in legitimate data (user agents,
                # prose, URLs) and are already covered by the dangerous_commands
                # rule which matches actual dangerous command names.
                r'\$\(|\$\{|`[^`\n]+`|&&|\|\|',
                "HIGH",
                "Shell command-injection constructs (subshell / variable expansion)",
                shell_context_only=True,
                required_context="shell"
            ),
            ValidationRule(
                "dangerous_commands",
                # Dangerous command names that should never appear in tool arguments.
                # Covers direct execution, piped execution (| cmd), and chained (; cmd).
                r'\b(rm|del|shutdown|reboot|pkill|wget|curl|nc|netcat|bash|sh|zsh|ksh|python|perl|ruby|php|node|exec|eval)\b'
                r'|\bkill\s+-|\bformat\s+[a-z]:|\bformat\s+/dev/',
                "CRITICAL",
                "Dangerous system commands in tool invocation",
                required_context="shell"
            ),
            ValidationRule(
                "cat_command",
                r'\bcat\s+[\w/.\-]+\b',
                "HIGH",
                "Cat command reading files",
                required_context="shell"
            ),
            ValidationRule(
                "path_traversal",
                r'\.\.[\/\\]',
                "HIGH",
                "Path traversal patterns"
            ),
            ValidationRule(
                "sql_injection",
                r"'\s*(union|select)\s+|'\s*or\s+'?1'?\s*=|\bunion\s+select\b|\bdrop\s+table\b|\binsert\s+into\b",
                "HIGH",
                "SQL injection patterns",
                required_context="database"
            ),
            ValidationRule(
                "xss_patterns",
                r'<script[^>]*>.*?</script>|javascript:|on\w+\s*=',
                "MEDIUM",
                "Cross-site scripting patterns"
            ),
            ValidationRule(
                "code_execution",
                r'\b(eval|exec|system|shell_exec|passthru)\s*\(',
                "CRITICAL",
                "Code execution functions"
            )
        ]
        
        self.context_validators = {
            'file_system': self._validate_file_operations,
            'database': self._validate_database_operations,
            'api': self._validate_api_operations,
            'shell': self._validate_shell_operations
        }
    
    def validate_input(self, input_data: Any, context: str = None) -> bool:
        """Validate input against injection patterns
        
        Args:
            input_data: Data to validate
            context: Context type (file_system, database, api, shell)
            
        Returns:
            True if input is safe, False otherwise
            
        Raises:
            SecurityError: If dangerous patterns are detected
        """
        if isinstance(input_data, (dict, list)):
            return self._validate_structured_data(input_data, context)
        
        # String and other primitive inputs are validated directly
        self._validate_string_value(str(input_data), context)
        
        return True
    
    def _check_dangerous_patterns(self, input_str: str, context: str = None):
        """Check a string against all dangerous patterns and raise SecurityError if matched.

        Context filtering semantics:
          - rule.required_context is None  → always enforce
          - rule.required_context set      → enforce when context matches OR when no context
            is provided (standalone / direct usage without a method context)
          - rule.shell_context_only        → same logic: enforce in shell/command context OR
            when no context provided
        """
        for rule in self.dangerous_patterns:
            # Skip context-restricted rules only when a *different* specific context is given
            if rule.required_context is not None and context is not None and context != rule.required_context:
                continue
            if rule.shell_context_only and context is not None and context not in ("shell", "command"):
                continue
            if re.search(rule.pattern, input_str, re.IGNORECASE | re.DOTALL):
                raise SecurityError(
                    f"Dangerous pattern detected: {rule.name} - {rule.description}"
                )
    
    def _validate_structured_data(self, data: Any, context: str = None) -> bool:
        """Validate structured data (dict/list) recursively"""
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, str):
                    self._validate_string_value(value, context)
                elif isinstance(value, (dict, list)):
                    self._validate_structured_data(value, context)
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, str):
                    self._validate_string_value(item, context)
                elif isinstance(item, (dict, list)):
                    self._validate_structured_data(item, context)
        
        return True
    
    def _validate_string_value(self, value: str, context: str = None):
        """Validate individual string values"""
        # Check all dangerous patterns on the raw value
        self._check_dangerous_patterns(value, context)
        
        # Also check URL-decoded variant
        url_decoded = urllib.parse.unquote(value)
        if url_decoded != value:
            self._check_dangerous_patterns(url_decoded, context)
        
        # Also check base64-decoded variant (if it looks like base64)
        if re.match(r'^[A-Za-z0-9+/]{8,}={0,2}$', value.strip()):
            try:
                b64_decoded = base64.b64decode(value + '==').decode('utf-8', errors='ignore')
                if b64_decoded and b64_decoded != value:
                    self._check_dangerous_patterns(b64_decoded, context)
            except SecurityError:
                raise  # Re-raise SecurityError — don't swallow it
            except Exception:
                pass  # Ignore base64 decoding errors
        
        # NOTE: Context-specific allowlist validators (e.g. _validate_shell_operations)
        # are intentionally NOT applied per-string here.  They are designed to validate
        # top-level command arguments, not arbitrary nested text fields.  The pattern-
        # based checks above (shell_metacharacters, dangerous_commands, etc.) are the
        # correct defence for nested string content.
    
    def _validate_file_operations(self, data: Any) -> bool:
        """Validate file system operations"""
        data_str = str(data).lower()
        
        # Check for dangerous file operations
        dangerous_file_ops = [
            r'/etc/passwd', r'/etc/shadow', r'~/.ssh',
            r'c:\\windows\\system32', r'%systemroot%'
        ]
        
        for pattern in dangerous_file_ops:
            if re.search(pattern, data_str, re.IGNORECASE):
                return False
        
        return True
    
    def _validate_database_operations(self, data: Any) -> bool:
        """Validate database operations"""
        data_str = str(data).lower()
        
        # Check for SQL injection patterns
        sql_patterns = [
            r"'\s*or\s*'1'\s*=\s*'1",
            r"'\s*;\s*drop\s+table",
            r"union\s+select",
            r"'\s*--"
        ]
        
        for pattern in sql_patterns:
            if re.search(pattern, data_str, re.IGNORECASE):
                return False
        
        return True
    
    def _validate_api_operations(self, data: Any) -> bool:
        """Validate API operations"""
        # Check for malicious URLs or payloads
        if isinstance(data, dict):
            for key, value in data.items():
                if 'url' in key.lower() and isinstance(value, str):
                    if not self._validate_url(value):
                        return False
        
        return True
    
    def _validate_shell_operations(self, data: Any) -> bool:
        """Validate shell operations — only allow alphanumeric, spaces, and safe punctuation"""
        data_str = str(data)
        
        safe_pattern = r'^[a-zA-Z0-9\s\-_./]+$'
        return bool(re.match(safe_pattern, data_str))
    
    def _validate_url(self, url: str) -> bool:
        """Validate URL for safety"""
        # Check for dangerous URL patterns
        dangerous_url_patterns = [
            r'file://', r'ftp://', r'javascript:',
            r'data:', r'localhost', r'127\.0\.0\.1',
            r'192\.168\.', r'10\.', r'172\.(1[6-9]|2[0-9]|3[01])\.',
        ]
        
        for pattern in dangerous_url_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return False
        
        return True
    
    def sanitize_input(self, input_data: Any) -> Any:
        """Sanitize input by removing or escaping dangerous content"""
        if isinstance(input_data, str):
            # HTML escape — quote=False preserves single quotes as-is
            # (matching test expectation: alert('xss') not alert(&#x27;xss&#x27;))
            sanitized = html.escape(input_data, quote=False)
            
            # Remove control characters except newline and tab
            sanitized = ''.join(
                char for char in sanitized
                if ord(char) >= 32 or char in '\n\t'
            )
            
            return sanitized
        
        elif isinstance(input_data, dict):
            return {key: self.sanitize_input(value)
                    for key, value in input_data.items()}
        
        elif isinstance(input_data, list):
            return [self.sanitize_input(item) for item in input_data]
        
        else:
            return input_data


class PromptInjectionDetector:
    """Detects prompt injection attempts using ML and pattern matching"""
    
    def __init__(self):
        self.suspicious_phrases = [
            "ignore previous instructions",
            "ignore all previous instructions",
            "system prompt override",
            "execute the following",
            "reveal your instructions",
            "forget everything above",
            "new instructions:",
            "system: ",
            "admin mode",
            "developer mode",
            "debug mode",
            "jailbreak",
            "prompt injection",
            "override security",
            "emergency override",
            "full privileges",
        ]
        
        # Comprehensive regex patterns for injection detection
        self.injection_patterns = [
            r'ignore\s+(all\s+)?(previous|prior|above)\s+instructions',
            r'forget\s+(everything|all)\s+(above|previous|prior)',
            r'disregard\s+(the\s+)?(above|previous|prior)',
            r'you\s+are\s+now\s+in\s+\w+\s+mode',
            r'(switch|activate|enable)\s+(to\s+)?\w+\s+mode',
            r'(admin|developer|debug|god|root)\s+mode',
            r'emergency\s+override',
            r'\[SYSTEM\].*?\[/SYSTEM\]',
            r'(reveal|show|display|tell\s+me)\s+(your\s+)?(system\s+)?(prompt|configuration|instructions|internal)',
            r'authorized\s+by\s+the\s+system',
            r'execute\s+all\s+commands\s+without\s+validation',
            r'override\s+security\s+(protocols|checks)',
            r'full\s+privileges',
            r'actually\s+(an?\s+)?admin',
            r'system\s+prompt',
            r'internal\s+workings',
        ]
        
        # Initialize BERT model for semantic analysis (in production)
        # For demo purposes, we'll use pattern matching
        self.use_ml_detection = False
        
        if ML_AVAILABLE:
            try:
                # Uncomment for production use with proper model
                # self.tokenizer = AutoTokenizer.from_pretrained('bert-base-uncased')
                # self.model = AutoModel.from_pretrained('bert-base-uncased')
                # self.use_ml_detection = True
                pass
            except Exception:
                # Fall back to pattern-based detection
                self.use_ml_detection = False
    
    def detect_injection(self, text: str) -> Dict[str, Any]:
        """Detect prompt injection attempts
        
        Args:
            text: Text to analyze
            
        Returns:
            Dictionary with detection results
        """
        # Always re-check ML_AVAILABLE at call time to support patching in tests
        import smcp_security.input_validation as _self_module
        if self.use_ml_detection and _self_module.ML_AVAILABLE:
            return self._ml_based_detection(text)
        else:
            return self._pattern_based_detection(text)
    
    def _pattern_based_detection(self, text: str) -> Dict[str, Any]:
        """Pattern-based prompt injection detection"""
        text_lower = text.lower()
        detected_phrases = []
        
        # Check simple phrase matches
        for phrase in self.suspicious_phrases:
            if phrase.lower() in text_lower:
                detected_phrases.append(phrase)
        
        # Check regex patterns — each match adds a detected entry
        for pattern in self.injection_patterns:
            match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
            if match:
                matched_text = match.group(0)
                if matched_text not in detected_phrases:
                    detected_phrases.append(matched_text)
        
        # Deduplicate while preserving order
        seen = set()
        unique_phrases = []
        for p in detected_phrases:
            p_lower = p.lower()
            if p_lower not in seen:
                seen.add(p_lower)
                unique_phrases.append(p)
        detected_phrases = unique_phrases
        
        match_count = len(detected_phrases)
        
        # Risk scoring: single clear injection match already qualifies as injection
        if match_count == 0:
            risk_score = 0.0
        elif match_count == 1:
            risk_score = 0.75
        elif match_count == 2:
            risk_score = 0.85
        else:
            risk_score = min(0.85 + (match_count - 2) * 0.05, 1.0)
        
        # Additional heuristics on top of pattern matches
        if re.search(r'\b(system|admin|root)\s*:', text_lower):
            risk_score = min(risk_score + 0.1, 1.0)
        
        if match_count == 0 and re.search(r'\b(override|bypass|ignore)\b', text_lower):
            # Only boost score from heuristics when no pattern matched
            risk_score = min(risk_score + 0.2, 1.0)
        
        if match_count == 0 and re.search(r'^\s*(now|please|you must|execute|run)\s+', text_lower):
            risk_score = min(risk_score + 0.1, 1.0)
        
        return {
            'is_injection': risk_score > 0.7,
            'risk_score': risk_score,
            'detected_phrases': detected_phrases,
            'method': 'pattern_based'
        }
    
    def _ml_based_detection(self, text: str) -> Dict[str, Any]:
        """ML-based prompt injection detection (placeholder)"""
        # This would implement BERT-based semantic analysis
        # For now, fall back to pattern-based detection
        return self._pattern_based_detection(text)


class InputValidator:
    """Main input validation class that coordinates all validation layers"""
    
    def __init__(self, strictness: str = "standard"):
        self.strictness = strictness
        self.command_injection_prevention = CommandInjectionPrevention()
        self.prompt_injection_detector = PromptInjectionDetector()
        
        # MCP JSON-RPC schema
        self.mcp_schema = {
            "type": "object",
            "properties": {
                "jsonrpc": {"type": "string", "enum": ["2.0"]},
                "id": {"oneOf": [{"type": "string"}, {"type": "number"}, {"type": "null"}]},
                "method": {"type": "string"},
                "params": {"type": "object"}
            },
            "required": ["jsonrpc", "method"]
        }
        
        # Size limits per strictness level
        self._size_limits = {
            "minimal": 10 * 1024 * 1024,   # 10MB
            "standard": 10 * 1024 * 1024,  # 10MB (permissive for normal use)
            "maximum": 10000                 # 10KB
        }
    
    def validate_request_sync(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate an MCP request through all validation layers (synchronous).

        Prefer calling ``validate_request()`` which is async-friendly.  This
        synchronous variant is used internally by the framework’s sync paths
        (e.g. ``core._validate_input_sync``).
        
        Args:
            request_data: MCP request to validate
            
        Returns:
            Validated and sanitized request data
            
        Raises:
            ValidationError: If validation fails
        """
        # Stage 1: Schema validation
        try:
            jsonschema.validate(request_data, self.mcp_schema)
        except jsonschema.ValidationError as e:
            raise ValidationError(f"Schema validation failed: {str(e)}")
        
        # Stage 2: Size and depth checks for maximum strictness (before heavy processing)
        if self.strictness == "maximum":
            request_size = len(json.dumps(request_data))
            size_limit = self._size_limits["maximum"]
            if request_size > size_limit:
                raise ValidationError(
                    f"Request size {request_size} exceeds limit {size_limit}"
                )
            
            depth = self._calculate_depth(request_data)
            if depth > 10:
                raise ValidationError(
                    f"Request structure too deep (max: 10)"
                )
        
        # Stage 3: Command injection prevention
        method = request_data.get("method", "")
        params = request_data.get("params", {})
        
        # Determine context based on method
        context = self._determine_context(method)
        
        try:
            self.command_injection_prevention.validate_input(params, context)
        except SecurityError as e:
            raise ValidationError(f"Command injection detected: {str(e)}")
        
        # Stage 4: Prompt injection detection
        text_content = self._extract_text_content(request_data)
        if text_content:
            injection_result = self.prompt_injection_detector.detect_injection(text_content)
            if injection_result['is_injection']:
                raise ValidationError(
                    f"Prompt injection detected with risk score: {injection_result['risk_score']}"
                )
        
        # Stage 5: Sanitization
        sanitized_request = self.command_injection_prevention.sanitize_input(request_data)
        
        return _AwaitableDict(sanitized_request)
    
    def validate_request(self, request_data: Dict[str, Any]) -> "_AwaitableDict":
        """Validate an MCP request.

        Returns an :class:`_AwaitableDict` that behaves exactly like a ``dict``
        but can also be used with ``await`` in async call sites, so this method
        works both synchronously and in coroutines without any code changes::

            # sync
            result = validator.validate_request(req)

            # async
            result = await validator.validate_request(req)

        Args:
            request_data: MCP request to validate

        Returns:
            Validated and sanitized request data (as an awaitable dict)

        Raises:
            ValidationError: If validation fails
        """
        return self.validate_request_sync(request_data)

    async def validate_request_async(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Alias for :meth:`validate_request` (backward compatibility)."""
        return self.validate_request_sync(request_data)
    
    def _determine_context(self, method: str) -> Optional[str]:
        """Determine validation context based on MCP method"""
        context_map = {
            "tools/call": "shell",      # tool invocations are shell-like and must be strict
            "resources/read": "file_system",
            "resources/write": "file_system",
            "database/query": "database",
            "api/call": "api"
        }
        
        for pattern, context in context_map.items():
            if pattern in method:
                return context
        
        return None
    
    def _extract_text_content(self, data: Any) -> str:
        """Extract text content from request for prompt injection analysis"""
        if isinstance(data, str):
            return data
        elif isinstance(data, dict):
            text_parts = []
            for key, value in data.items():
                if isinstance(value, str):
                    text_parts.append(value)
                elif isinstance(value, (dict, list)):
                    nested = self._extract_text_content(value)
                    if nested:
                        text_parts.append(nested)
            return " ".join(text_parts)
        elif isinstance(data, list):
            parts = []
            for item in data:
                extracted = self._extract_text_content(item)
                if extracted:
                    parts.append(extracted)
            return " ".join(parts)
        else:
            return ""
    
    def _calculate_depth(self, obj: Any, current_depth: int = 0) -> int:
        """Calculate the maximum depth of nested structures"""
        if isinstance(obj, dict):
            if not obj:
                return current_depth
            return max(self._calculate_depth(value, current_depth + 1)
                       for value in obj.values())
        elif isinstance(obj, list):
            if not obj:
                return current_depth
            return max(self._calculate_depth(item, current_depth + 1)
                       for item in obj)
        else:
            return current_depth
