/**
 * SMCP Audit Logger
 * Structured event logging using winston.
 */

import * as winston from 'winston';
import * as crypto from 'crypto';

export const enum EventCategory {
  INPUT_VALIDATION = 'INPUT_VALIDATION',
  AUTHENTICATION = 'AUTHENTICATION',
  AUTHORIZATION = 'AUTHORIZATION',
  RATE_LIMITING = 'RATE_LIMITING',
  CRYPTOGRAPHY = 'CRYPTOGRAPHY',
  AI_IMMUNE = 'AI_IMMUNE',
  AUDIT = 'AUDIT',
  SECURITY_VIOLATION = 'SECURITY_VIOLATION',
}

export const enum EventSeverity {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL',
}

export interface AuditEvent {
  id: string;
  timestamp: string;
  userId?: string;
  category: string;
  severity: string;
  message: string;
  metadata: Record<string, unknown>;
}

export interface AuditEventFilters {
  category?: string;
  severity?: string;
  userId?: string;
  startTime?: string;
  endTime?: string;
}

type LogLevelString = 'DEBUG' | 'INFO' | 'WARNING' | 'ERROR' | 'CRITICAL';

const LOG_LEVEL_MAP: Record<LogLevelString, string> = {
  DEBUG: 'debug',
  INFO: 'info',
  WARNING: 'warn',
  ERROR: 'error',
  CRITICAL: 'error',
};

export class SMCPAuditLogger {
  private readonly logger: winston.Logger;
  private readonly events: AuditEvent[] = [];

  constructor(options: { logLevel?: LogLevelString } = {}) {
    const level = LOG_LEVEL_MAP[options.logLevel ?? 'INFO'];

    this.logger = winston.createLogger({
      level,
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      ),
      transports: [
        new winston.transports.Console({ silent: process.env.NODE_ENV === 'test' }),
      ],
    });
  }

  logEvent(
    category: string,
    severity: string,
    message: string,
    context: Record<string, unknown> = {}
  ): void {
    const event: AuditEvent = {
      id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      userId: context.userId as string | undefined,
      category,
      severity,
      message,
      metadata: context,
    };

    this.events.push(event);

    const winstonLevel = severity === 'CRITICAL' || severity === 'HIGH' ? 'error' :
                         severity === 'MEDIUM' ? 'warn' : 'info';
    this.logger.log(winstonLevel, message, { category, severity, ...context });
  }

  logAuthenticationEvent(
    userId: string,
    eventType: string,
    success: boolean,
    ipAddress?: string
  ): void {
    this.logEvent(
      EventCategory.AUTHENTICATION,
      success ? EventSeverity.LOW : EventSeverity.HIGH,
      `Authentication ${eventType}: ${success ? 'success' : 'failure'} for user ${userId}`,
      { userId, eventType, success, ipAddress }
    );
  }

  logAuthorizationEvent(
    userId: string,
    resource: string,
    action: string,
    granted: boolean,
    ipAddress?: string
  ): void {
    this.logEvent(
      EventCategory.AUTHORIZATION,
      granted ? EventSeverity.LOW : EventSeverity.MEDIUM,
      `Authorization ${granted ? 'granted' : 'denied'} for user ${userId} on ${resource}:${action}`,
      { userId, resource, action, granted, ipAddress }
    );
  }

  logSecurityEvent(
    eventType: string,
    userId: string,
    details: Record<string, unknown>,
    level: string = EventSeverity.HIGH
  ): void {
    this.logEvent(
      EventCategory.SECURITY_VIOLATION,
      level,
      `Security event: ${eventType} for user ${userId}`,
      { userId, eventType, ...details }
    );
  }

  /** Stub methods for backward compat with old framework calls */
  logThreat(details: Record<string, unknown>): void {
    this.logEvent(EventCategory.SECURITY_VIOLATION, EventSeverity.CRITICAL, 'Threat detected', details);
  }

  logError(details: Record<string, unknown>): void {
    this.logEvent(EventCategory.AUDIT, EventSeverity.HIGH, 'Error occurred', details);
  }

  logAuthentication(details: Record<string, unknown>): void {
    const userId = (details.userId as string) ?? 'unknown';
    const success = (details.success as boolean) ?? false;
    this.logAuthenticationEvent(userId, 'login', success);
  }

  logAuthorization(details: Record<string, unknown>): void {
    const userId = (details.userId as string) ?? 'unknown';
    const action = (details.action as string) ?? '';
    const granted = (details.granted as boolean) ?? false;
    this.logAuthorizationEvent(userId, '*', action, granted);
  }

  logRequest(details: Record<string, unknown>): void {
    this.logEvent(EventCategory.AUDIT, EventSeverity.LOW, 'Request processed', details);
  }

  getEvents(filters?: AuditEventFilters): AuditEvent[] {
    if (!filters) return [...this.events];

    return this.events.filter((event) => {
      if (filters.category && event.category !== filters.category) return false;
      if (filters.severity && event.severity !== filters.severity) return false;
      if (filters.userId && event.userId !== filters.userId) return false;
      if (filters.startTime && event.timestamp < filters.startTime) return false;
      if (filters.endTime && event.timestamp > filters.endTime) return false;
      return true;
    });
  }
}
