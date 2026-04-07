/**
 * Audit logger tests
 */

import { SMCPAuditLogger, EventCategory, EventSeverity } from '../src/audit/SMCPAuditLogger';

describe('SMCPAuditLogger', () => {
  let logger: SMCPAuditLogger;

  beforeEach(() => {
    logger = new SMCPAuditLogger({ logLevel: 'ERROR' });
  });

  it('logEvent stores event in memory', () => {
    logger.logEvent(EventCategory.AUDIT, EventSeverity.LOW, 'test message', {});
    const events = logger.getEvents();
    expect(events.length).toBe(1);
    expect(events[0].message).toBe('test message');
  });

  it('getEvents retrieves by category', () => {
    logger.logEvent(EventCategory.AUTHENTICATION, EventSeverity.LOW, 'auth event', {});
    logger.logEvent(EventCategory.AUDIT, EventSeverity.LOW, 'audit event', {});

    const authEvents = logger.getEvents({ category: EventCategory.AUTHENTICATION });
    expect(authEvents.length).toBe(1);
    expect(authEvents[0].category).toBe(EventCategory.AUTHENTICATION);
  });

  it('getEvents retrieves by severity', () => {
    logger.logEvent(EventCategory.AUDIT, EventSeverity.LOW, 'low event', {});
    logger.logEvent(EventCategory.AUDIT, EventSeverity.HIGH, 'high event', {});

    const highEvents = logger.getEvents({ severity: EventSeverity.HIGH });
    expect(highEvents.length).toBe(1);
    expect(highEvents[0].severity).toBe(EventSeverity.HIGH);
  });

  it('getEvents retrieves by userId', () => {
    logger.logEvent(EventCategory.AUDIT, EventSeverity.LOW, 'user1 event', { userId: 'user1' });
    logger.logEvent(EventCategory.AUDIT, EventSeverity.LOW, 'user2 event', { userId: 'user2' });

    const user1Events = logger.getEvents({ userId: 'user1' });
    expect(user1Events.length).toBe(1);
    expect(user1Events[0].userId).toBe('user1');
  });

  it('logAuthenticationEvent creates AUTHENTICATION category event', () => {
    logger.logAuthenticationEvent('user1', 'login', true, '127.0.0.1');
    const events = logger.getEvents({ category: EventCategory.AUTHENTICATION });
    expect(events.length).toBe(1);
    expect(events[0].category).toBe(EventCategory.AUTHENTICATION);
  });

  it('logAuthenticationEvent for failure uses HIGH severity', () => {
    logger.logAuthenticationEvent('user1', 'login', false);
    const events = logger.getEvents({ severity: EventSeverity.HIGH });
    expect(events.length).toBeGreaterThanOrEqual(1);
  });

  it('logAuthorizationEvent creates AUTHORIZATION category event', () => {
    logger.logAuthorizationEvent('user1', 'tools', 'read', true);
    const events = logger.getEvents({ category: EventCategory.AUTHORIZATION });
    expect(events.length).toBe(1);
  });

  it('logSecurityEvent creates SECURITY_VIOLATION category event', () => {
    logger.logSecurityEvent('injection_attempt', 'user1', { endpoint: '/api' });
    const events = logger.getEvents({ category: EventCategory.SECURITY_VIOLATION });
    expect(events.length).toBe(1);
  });

  it('event has id, timestamp, category, severity, message, metadata', () => {
    logger.logEvent(EventCategory.AUDIT, EventSeverity.MEDIUM, 'test', { key: 'val' });
    const event = logger.getEvents()[0];
    expect(event.id).toBeTruthy();
    expect(event.timestamp).toBeTruthy();
    expect(event.category).toBe(EventCategory.AUDIT);
    expect(event.severity).toBe(EventSeverity.MEDIUM);
    expect(event.message).toBe('test');
    expect(event.metadata).toBeDefined();
  });

  it('getEvents with no filter returns all events', () => {
    logger.logEvent(EventCategory.AUDIT, EventSeverity.LOW, 'event1', {});
    logger.logEvent(EventCategory.AUDIT, EventSeverity.LOW, 'event2', {});
    logger.logEvent(EventCategory.AUTHENTICATION, EventSeverity.LOW, 'event3', {});

    const all = logger.getEvents();
    expect(all.length).toBe(3);
  });

  it('multiple logEvent calls accumulate events', () => {
    for (let i = 0; i < 5; i++) {
      logger.logEvent(EventCategory.AUDIT, EventSeverity.LOW, `event ${i}`, {});
    }
    expect(logger.getEvents().length).toBe(5);
  });
});
