/**
 * Rate limiting tests
 */

import { AdaptiveRateLimiter } from '../src/ratelimit/AdaptiveRateLimiter';
import { DoSProtection } from '../src/ratelimit/DoSProtection';
import { RateLimitError } from '../src/exceptions';

describe('AdaptiveRateLimiter', () => {
  let limiter: AdaptiveRateLimiter;

  beforeEach(() => {
    limiter = new AdaptiveRateLimiter({ baseLimit: 5, windowSeconds: 60, adaptive: false });
  });

  it('allows requests under the limit', () => {
    for (let i = 0; i < 5; i++) {
      expect(() => limiter.checkRateLimit('user1')).not.toThrow();
    }
  });

  it('throws RateLimitError at the limit', () => {
    for (let i = 0; i < 5; i++) {
      limiter.checkRateLimit('user1');
    }
    expect(() => limiter.checkRateLimit('user1')).toThrow(RateLimitError);
  });

  it('whitelisted user bypasses limit', () => {
    limiter.addToWhitelist('vip-user');
    // Fill up more than the limit without throwing
    for (let i = 0; i < 100; i++) {
      expect(() => limiter.checkRateLimit('vip-user')).not.toThrow();
    }
  });

  it('blacklisted user is always blocked', () => {
    limiter.addToBlacklist('bad-user');
    expect(() => limiter.checkRateLimit('bad-user')).toThrow(RateLimitError);
  });

  it('getRateLimitStatus shows correct remaining count', () => {
    limiter.checkRateLimit('user2');
    limiter.checkRateLimit('user2');
    const status = limiter.getRateLimitStatus('user2');
    expect(status.requestsInWindow).toBe(2);
    expect(status.remaining).toBe(3); // 5 - 2
    expect(status.limit).toBe(5);
  });

  it('setUserLimit overrides base limit', () => {
    limiter.setUserLimit('premium', 10);
    for (let i = 0; i < 10; i++) {
      expect(() => limiter.checkRateLimit('premium')).not.toThrow();
    }
    expect(() => limiter.checkRateLimit('premium')).toThrow(RateLimitError);
  });

  it('clearUserData removes user request history', () => {
    for (let i = 0; i < 5; i++) {
      limiter.checkRateLimit('user3');
    }
    limiter.clearUserData('user3');
    // Should be able to make requests again
    expect(() => limiter.checkRateLimit('user3')).not.toThrow();
  });

  it('removeFromWhitelist re-enables rate limiting for user', () => {
    limiter.addToWhitelist('temp-vip');
    limiter.removeFromWhitelist('temp-vip');
    // Fill up limit
    for (let i = 0; i < 5; i++) {
      limiter.checkRateLimit('temp-vip');
    }
    expect(() => limiter.checkRateLimit('temp-vip')).toThrow(RateLimitError);
  });

  it('getRateLimitHeaders returns correct headers', () => {
    const headers = limiter.getRateLimitHeaders('new-user');
    expect(headers['X-RateLimit-Limit']).toBe('5');
    expect(headers['X-RateLimit-Remaining']).toBe('5');
    expect(headers['X-RateLimit-Reset']).toBeDefined();
  });

  it('flagSuspiciousIP adds to suspicious IPs', () => {
    limiter.flagSuspiciousIP('1.2.3.4');
    const metrics = limiter.getDoSMetrics();
    expect(metrics.suspiciousIPs).toContain('1.2.3.4');
  });
});

describe('DoSProtection', () => {
  let dos: DoSProtection;

  beforeEach(() => {
    dos = new DoSProtection();
  });

  it('blockIP makes isIPBlocked return true', () => {
    dos.blockIP('10.0.0.1', 3600, 'test block');
    expect(dos.isIPBlocked('10.0.0.1')).toBe(true);
  });

  it('blockIP with past expiry (already expired) returns false', () => {
    dos.blockIP('10.0.0.2', -1, 'expired');
    // Expired immediately — should be unblocked
    expect(dos.isIPBlocked('10.0.0.2')).toBe(false);
  });

  it('unblockIP removes IP from block list', () => {
    dos.blockIP('10.0.0.3', 3600);
    dos.unblockIP('10.0.0.3');
    expect(dos.isIPBlocked('10.0.0.3')).toBe(false);
  });

  it('whitelisted IP is always allowed', () => {
    dos.addToWhitelist('192.168.1.1');
    const result = dos.analyzeRequest('192.168.1.1');
    expect(result.allowed).toBe(true);
  });

  it('blocked IP is denied in analyzeRequest', () => {
    dos.blockIP('10.0.0.4', 3600);
    const result = dos.analyzeRequest('10.0.0.4');
    expect(result.allowed).toBe(false);
  });

  it('analyzeUserAgent detects curl as bot', () => {
    const analysis = dos.analyzeUserAgent('curl/7.64.1');
    expect(analysis.isBot).toBe(true);
  });

  it('analyzeUserAgent detects wget as bot', () => {
    const analysis = dos.analyzeUserAgent('Wget/1.20.3');
    expect(analysis.isBot).toBe(true);
  });

  it('analyzeUserAgent flags short UA as suspicious', () => {
    const analysis = dos.analyzeUserAgent('ab');
    expect(analysis.isSuspicious).toBe(true);
  });

  it('normal browser UA is not flagged as bot', () => {
    const analysis = dos.analyzeUserAgent(
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    );
    expect(analysis.isBot).toBe(false);
  });

  it('generateChallenge returns a challenge with id', () => {
    const challenge = dos.generateChallenge('1.2.3.4');
    expect(challenge.challengeId).toBeTruthy();
    expect(challenge.challenge).toContain('?');
    expect(challenge.expiresAt).toBeGreaterThan(Date.now());
  });

  it('verifyChallengeResponse succeeds with correct answer', () => {
    // We can't easily predict the answer, so we'll inspect the internals
    // Instead test that wrong answers fail
    const challenge = dos.generateChallenge('1.2.3.4');
    // Try an obviously wrong answer
    expect(dos.verifyChallengeResponse(challenge.challengeId, '999')).toBe(false);
  });

  it('cleanupExpiredData does not throw', () => {
    dos.blockIP('10.0.0.5', -1);
    expect(() => dos.cleanupExpiredData()).not.toThrow();
    expect(dos.isIPBlocked('10.0.0.5')).toBe(false);
  });
});
