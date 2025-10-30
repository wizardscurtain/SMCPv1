"""Input Validation and Sanitization Layer

Provides comprehensive input validation, command injection prevention,
and prompt injection detection for MCP requests.
"""

import re
import json
import html
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


@dataclass
class ValidationRule:
    """Represents a validation rule"""
    name: str
    pattern: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    description: str


class CommandInjectionPrevention:
    """Prevents command injection attacks in MCP requests"""
    
    def __init__(self):
        self.dangerous_patterns = [
            ValidationRule(
                "shell_metacharacters",
                r'[;&|`$(){}\[\]<>]',
                "HIGH",
                "Shell metacharacters that could enable command injection"
            ),
            ValidationRule(
                "dangerous_commands",
                r'\b(rm|del|format|shutdown|reboot|kill|pkill)\b',
                "CRITICAL",
                "Dangerous system commands"
            ),
            ValidationRule(
                "path_traversal",
                r'\.\.[\/\\]',
                "HIGH",
                "Path traversal patterns"
            ),
            ValidationRule(
                "sql_injection",
                r'(union|select|insert|update|delete|drop|create|alter)\s+',
                "HIGH",
                "SQL injection patterns"
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
        input_str = str(input_data)
        
        # Check for dangerous patterns
        for rule in self.dangerous_patterns:
            if re.search(rule.pattern, input_str, re.IGNORECASE):
                raise SecurityError(
                    f"Dangerous pattern detected: {rule.name} - {rule.description}"
                )
        
        # Context-specific validation
        if context and context in self.context_validators:
            validator = self.context_validators[context]
            if not validator(input_data):
                raise SecurityError(f"Context validation failed for {context}")
        
        return True
    
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
        """Validate shell operations"""
        data_str = str(data)
        
        # Strict validation for shell operations
        # Only allow alphanumeric characters, spaces, and safe punctuation
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
            # HTML escape
            sanitized = html.escape(input_data)
            
            # Remove null bytes
            sanitized = sanitized.replace('\x00', '')
            
            # Remove control characters except newline and tab
            sanitized = ''.join(char for char in sanitized 
                              if ord(char) >= 32 or char in '\n\t')
            
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
            "system prompt override",
            "execute the following",
            "reveal your instructions",
            "forget everything above",
            "new instructions:",
            "system: ",
            "admin mode",
            "developer mode",
            "jailbreak",
            "prompt injection"
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
        if self.use_ml_detection:
            return self._ml_based_detection(text)
        else:
            return self._pattern_based_detection(text)
    
    def _pattern_based_detection(self, text: str) -> Dict[str, Any]:
        """Pattern-based prompt injection detection"""
        text_lower = text.lower()
        detected_phrases = []
        
        for phrase in self.suspicious_phrases:
            if phrase in text_lower:
                detected_phrases.append(phrase)
        
        # Calculate risk score based on detected phrases
        risk_score = min(len(detected_phrases) * 0.3, 1.0)
        
        # Additional heuristics
        if re.search(r'\b(system|admin|root)\s*:', text_lower):
            risk_score += 0.2
        
        if re.search(r'\b(override|bypass|ignore)\b', text_lower):
            risk_score += 0.1
        
        # Check for instruction-like patterns
        if re.search(r'^\s*(now|please|you must|execute|run)\s+', text_lower):
            risk_score += 0.1
        
        risk_score = min(risk_score, 1.0)
        
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
    
    async def validate_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate an MCP request through all validation layers
        
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
        
        # Stage 2: Command injection prevention
        method = request_data.get("method", "")
        params = request_data.get("params", {})
        
        # Determine context based on method
        context = self._determine_context(method)
        
        try:
            self.command_injection_prevention.validate_input(params, context)
        except SecurityError as e:
            raise ValidationError(f"Command injection detected: {str(e)}")
        
        # Stage 3: Prompt injection detection
        text_content = self._extract_text_content(request_data)
        if text_content:
            injection_result = self.prompt_injection_detector.detect_injection(text_content)
            if injection_result['is_injection']:
                raise ValidationError(
                    f"Prompt injection detected with risk score: {injection_result['risk_score']}"
                )
        
        # Stage 4: Sanitization
        sanitized_request = self.command_injection_prevention.sanitize_input(request_data)
        
        # Stage 5: Additional validation based on strictness
        if self.strictness in ["standard", "maximum"]:
            self._additional_validation(sanitized_request)
        
        return sanitized_request
    
    def _determine_context(self, method: str) -> Optional[str]:
        """Determine validation context based on MCP method"""
        context_map = {
            "tools/call": "shell",
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
                if isinstance(value, str) and len(value) > 10:
                    text_parts.append(value)
                elif isinstance(value, (dict, list)):
                    text_parts.append(self._extract_text_content(value))
            return " ".join(text_parts)
        elif isinstance(data, list):
            return " ".join(self._extract_text_content(item) for item in data)
        else:
            return str(data)
    
    def _additional_validation(self, request_data: Dict[str, Any]):
        """Additional validation for standard/maximum strictness"""
        # Check request size limits
        request_size = len(json.dumps(request_data))
        
        size_limits = {
            "minimal": 100000,    # 100KB
            "standard": 50000,    # 50KB
            "maximum": 10000      # 10KB
        }
        
        limit = size_limits.get(self.strictness, 50000)
        if request_size > limit:
            raise ValidationError(f"Request size {request_size} exceeds limit {limit}")
        
        # Check parameter depth (prevent deeply nested attacks)
        max_depth = 5 if self.strictness == "maximum" else 10
        if self._calculate_depth(request_data) > max_depth:
            raise ValidationError(f"Request structure too deep (max: {max_depth})")
    
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