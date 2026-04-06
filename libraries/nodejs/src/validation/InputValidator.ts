/**
 * Input Validator
 * Main input validation class coordinating all validation layers.
 */

import Joi from 'joi';
import { CommandInjectionPrevention } from './CommandInjectionPrevention';
import { PromptInjectionDetector } from './PromptInjectionDetector';
import { ValidationError } from '../exceptions';

export type ValidationStrictness = 'minimal' | 'standard' | 'maximum';

export interface ValidatedRequest extends Record<string, unknown> {}

const SIZE_LIMITS: Record<ValidationStrictness, number> = {
  minimal: 10 * 1024 * 1024,   // 10MB
  standard: 10 * 1024 * 1024,  // 10MB
  maximum: 10000,               // 10KB
};

const MCP_SCHEMA = Joi.object({
  jsonrpc: Joi.string().valid('2.0').required(),
  method: Joi.string().required(),
  id: Joi.alternatives().try(Joi.string(), Joi.number(), Joi.allow(null)).optional(),
  params: Joi.object().optional(),
}).unknown(false);

const CONTEXT_MAP: Record<string, string> = {
  'tools/call': 'shell',
  'resources/read': 'file_system',
  'resources/write': 'file_system',
  'database/query': 'database',
  'api/call': 'api',
};

export class InputValidator {
  private readonly strictness: ValidationStrictness;
  private readonly commandInjection: CommandInjectionPrevention;
  private readonly promptInjection: PromptInjectionDetector;

  constructor(options: { strictness?: ValidationStrictness } = {}) {
    this.strictness = options.strictness ?? 'standard';
    this.commandInjection = new CommandInjectionPrevention();
    this.promptInjection = new PromptInjectionDetector();
  }

  validateRequest(requestData: unknown): ValidatedRequest {
    // Stage 1: Schema validation
    const { error, value } = MCP_SCHEMA.validate(requestData, { abortEarly: true });
    if (error) {
      throw new ValidationError(`Schema validation failed: ${error.message}`);
    }
    const typed = value as Record<string, unknown>;

    // Stage 2: Size and depth checks for maximum strictness
    if (this.strictness === 'maximum') {
      const requestSize = JSON.stringify(typed).length;
      const sizeLimit = SIZE_LIMITS.maximum;
      if (requestSize > sizeLimit) {
        throw new ValidationError(
          `Request size ${requestSize} exceeds limit ${sizeLimit}`
        );
      }

      const depth = this._calculateDepth(typed);
      if (depth > 10) {
        throw new ValidationError('Request structure too deep (max: 10)');
      }
    }

    // Stage 3: Command injection prevention
    const method = (typed.method as string) || '';
    const params = typed.params as Record<string, unknown> | undefined;
    const context = this._determineContext(method);

    try {
      this.commandInjection.validateInput(params ?? {}, context ?? undefined);
    } catch (e) {
      throw new ValidationError(`Command injection detected: ${(e as Error).message}`);
    }

    // Stage 4: Prompt injection detection
    const textContent = this._extractTextContent(typed);
    if (textContent) {
      const injectionResult = this.promptInjection.detectInjection(textContent);
      if (injectionResult.isInjection) {
        throw new ValidationError(
          `Prompt injection detected with risk score: ${injectionResult.riskScore}`
        );
      }
      // Also check base64-decoded variants of each token.
      // Attackers may encode injection payloads as base64 to bypass string matching.
      for (const token of textContent.split(/\s+/)) {
        if (/^[A-Za-z0-9+/]{8,}={0,2}$/.test(token.trim())) {
          try {
            const decoded = Buffer.from(token.trim(), 'base64').toString('utf-8');
            if (decoded && decoded !== token) {
              const decodedResult = this.promptInjection.detectInjection(decoded);
              if (decodedResult.isInjection) {
                throw new ValidationError(
                  `Prompt injection detected in base64-encoded content with risk score: ${decodedResult.riskScore}`
                );
              }
            }
          } catch (e) {
            if (e instanceof ValidationError) throw e; // Re-raise
            // Ignore decoding errors
          }
        }
      }
    }

    // Stage 5: Sanitization
    const sanitized = this.commandInjection.sanitizeInput(typed);
    return sanitized as ValidatedRequest;
  }

  async validateRequestAsync(requestData: unknown): Promise<ValidatedRequest> {
    return this.validateRequest(requestData);
  }

  private _determineContext(method: string): string | null {
    for (const [pattern, ctx] of Object.entries(CONTEXT_MAP)) {
      if (method.includes(pattern)) {
        return ctx;
      }
    }
    return null;
  }

  private _extractTextContent(data: unknown): string {
    if (typeof data === 'string') {
      return data;
    }
    if (Array.isArray(data)) {
      return data.map((item) => this._extractTextContent(item)).filter(Boolean).join(' ');
    }
    if (data !== null && typeof data === 'object') {
      const parts: string[] = [];
      for (const value of Object.values(data as Record<string, unknown>)) {
        if (typeof value === 'string') {
          parts.push(value);
        } else if (value !== null && typeof value === 'object') {
          const nested = this._extractTextContent(value);
          if (nested) parts.push(nested);
        }
      }
      return parts.join(' ');
    }
    return '';
  }

  private _calculateDepth(obj: unknown, currentDepth = 0): number {
    if (Array.isArray(obj)) {
      if (obj.length === 0) return currentDepth;
      return Math.max(...obj.map((item) => this._calculateDepth(item, currentDepth + 1)));
    }
    if (obj !== null && typeof obj === 'object') {
      const values = Object.values(obj as Record<string, unknown>);
      if (values.length === 0) return currentDepth;
      return Math.max(...values.map((v) => this._calculateDepth(v, currentDepth + 1)));
    }
    return currentDepth;
  }
}
