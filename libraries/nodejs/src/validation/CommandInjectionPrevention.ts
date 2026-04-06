/**
 * Command Injection Prevention
 * Prevents command injection attacks in MCP requests.
 */

import { SecurityError } from '../exceptions';

interface ValidationRule {
  name: string;
  pattern: RegExp;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
  shellContextOnly?: boolean;
  requiredContext?: string;
}

export class CommandInjectionPrevention {
  private readonly dangerousPatterns: ValidationRule[];

  constructor() {
    this.dangerousPatterns = [
      {
        name: 'shell_metacharacters',
        pattern: /\$\(|\$\{|`[^`\n]+`|&&|\|\|/i,
        severity: 'HIGH',
        description: 'Shell command-injection constructs (subshell / variable expansion)',
        shellContextOnly: true,
        requiredContext: 'shell',
      },
      {
        name: 'dangerous_commands',
        pattern: /\b(rm|del|shutdown|reboot|pkill|wget|curl|nc|netcat|bash|sh|zsh|ksh|python|perl|ruby|php|node|exec|eval)\b|\bkill\s+-|\bformat\s+[a-z]:|\bformat\s+\/dev\//i,
        severity: 'CRITICAL',
        description: 'Dangerous system commands in tool invocation',
        requiredContext: 'shell',
      },
      {
        name: 'cat_command',
        pattern: /\bcat\s+[\w/.\-]+\b/i,
        severity: 'HIGH',
        description: 'Cat command reading files',
        requiredContext: 'shell',
      },
      {
        name: 'path_traversal',
        pattern: /\.\.[\\/\\]/,
        severity: 'HIGH',
        description: 'Path traversal patterns',
      },
      {
        name: 'sql_injection',
        pattern: /'\s*(union|select)\s+|'\s*or\s+'?1'?\s*=|\bunion\s+select\b|\bdrop\s+table\b|\binsert\s+into\b/i,
        severity: 'HIGH',
        description: 'SQL injection patterns',
        requiredContext: 'database',
      },
      {
        name: 'xss_patterns',
        pattern: /<script[^>]*>.*?<\/script>|javascript:|on\w+\s*=/i,
        severity: 'MEDIUM',
        description: 'Cross-site scripting patterns',
      },
      {
        name: 'code_execution',
        pattern: /\b(eval|exec|system|shell_exec|passthru)\s*\(/i,
        severity: 'CRITICAL',
        description: 'Code execution functions',
      },
    ];
  }

  validateInput(inputData: unknown, context?: string): boolean {
    if (Array.isArray(inputData) || (inputData !== null && typeof inputData === 'object')) {
      return this._validateStructuredData(inputData, context);
    }
    this._validateStringValue(String(inputData), context);
    return true;
  }

  sanitizeInput<T>(inputData: T): T {
    if (typeof inputData === 'string') {
      // HTML escape (without escaping single quotes, matching Python's html.escape(quote=False))
      let sanitized = (inputData as unknown as string)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');

      // Remove control characters below 0x20 except \n and \t
      sanitized = sanitized
        .split('')
        .filter((c) => c === '\n' || c === '\t' || c.charCodeAt(0) >= 32)
        .join('');

      return sanitized as unknown as T;
    }

    if (Array.isArray(inputData)) {
      return (inputData as unknown[]).map((item) => this.sanitizeInput(item)) as unknown as T;
    }

    if (inputData !== null && typeof inputData === 'object') {
      const result: Record<string, unknown> = {};
      for (const [key, value] of Object.entries(inputData as Record<string, unknown>)) {
        result[key] = this.sanitizeInput(value);
      }
      return result as unknown as T;
    }

    return inputData;
  }

  private _checkDangerousPatterns(str: string, context?: string): void {
    for (const rule of this.dangerousPatterns) {
      // Skip context-restricted rules when a different context is given
      if (rule.requiredContext !== undefined && context !== undefined && context !== rule.requiredContext) {
        continue;
      }
      if (rule.shellContextOnly && context !== undefined && context !== 'shell' && context !== 'command') {
        continue;
      }
      if (rule.pattern.test(str)) {
        throw new SecurityError(
          `Dangerous pattern detected: ${rule.name} - ${rule.description}`
        );
      }
    }
  }

  private _validateStringValue(value: string, context?: string): void {
    // Check raw value
    this._checkDangerousPatterns(value, context);

    // Check URL-decoded variant
    try {
      const urlDecoded = decodeURIComponent(value);
      if (urlDecoded !== value) {
        this._checkDangerousPatterns(urlDecoded, context);
      }
    } catch {
      // Ignore malformed URI sequences
    }

    // Check base64-decoded variant
    if (/^[A-Za-z0-9+/]{8,}={0,2}$/.test(value.trim())) {
      try {
        const b64Decoded = Buffer.from(value.trim(), 'base64').toString('utf-8');
        if (b64Decoded && b64Decoded !== value) {
          this._checkDangerousPatterns(b64Decoded, context);
        }
      } catch {
        // Ignore base64 decoding errors
      }
    }
  }

  private _validateStructuredData(data: unknown, context?: string): boolean {
    if (Array.isArray(data)) {
      for (const item of data) {
        if (typeof item === 'string') {
          this._validateStringValue(item, context);
        } else if (item !== null && typeof item === 'object') {
          this._validateStructuredData(item, context);
        }
      }
    } else if (data !== null && typeof data === 'object') {
      for (const value of Object.values(data as Record<string, unknown>)) {
        if (typeof value === 'string') {
          this._validateStringValue(value, context);
        } else if (value !== null && typeof value === 'object') {
          this._validateStructuredData(value, context);
        }
      }
    }
    return true;
  }
}
