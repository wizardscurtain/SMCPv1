/**
 * Adaptive Rate Limiter
 * Sliding-window rate limiting with adaptive scaling.
 */

import * as os from 'os';
import { RateLimitError } from '../exceptions';

export interface RateLimitStatus {
  userId: string;
  requestsInWindow: number;
  limit: number;
  remaining: number;
  resetTime: number;
  isThrottled: boolean;
}

export interface DoSMetrics {
  totalRequests: number;
  blockedRequests: number;
  suspiciousIPs: string[];
  blacklistedUsers: string[];
}

interface AdaptiveRateLimiterOptions {
  baseLimit?: number;
  windowSeconds?: number;
  adaptive?: boolean;
  burstLimit?: number;
}

export class AdaptiveRateLimiter {
  private readonly baseLimit: number;
  private readonly windowSeconds: number;
  private readonly adaptive: boolean;
  private readonly burstLimit: number;

  /** userId/ip → array of request timestamps (ms) */
  readonly requestCounts: Map<string, number[]> = new Map();
  private readonly userLimits: Map<string, number> = new Map();
  private readonly whitelist: Set<string> = new Set();
  private readonly blacklist: Set<string> = new Set();
  private readonly suspiciousIPs: Set<string> = new Set();

  private totalRequests = 0;
  private blockedRequests = 0;

  constructor(options: AdaptiveRateLimiterOptions = {}) {
    this.baseLimit = options.baseLimit ?? 100;
    this.windowSeconds = options.windowSeconds ?? 60;
    this.adaptive = options.adaptive ?? true;
    this.burstLimit = options.burstLimit ?? Math.floor((options.baseLimit ?? 100) * 1.5);
  }

  checkRateLimit(
    userId: string,
    _endpoint?: string,
    _requestSize?: number,
    allowBurst = false
  ): boolean {
    this.totalRequests++;

    // Whitelist bypass
    if (this.whitelist.has(userId)) return true;

    // Blacklist block
    if (this.blacklist.has(userId)) {
      this.blockedRequests++;
      throw new RateLimitError('User is blacklisted');
    }

    const now = Date.now();
    const windowMs = this.windowSeconds * 1000;

    // Prune old entries
    const timestamps = this._getAndPruneTimestamps(userId, now, windowMs);

    // Determine effective limit
    let limit = this.userLimits.get(userId) ?? this.baseLimit;

    if (this.adaptive) {
      const loadFactor = this._getSystemLoad();
      if (loadFactor > 0.8) {
        limit = Math.floor(limit * 0.5);
      } else if (loadFactor > 0.6) {
        limit = Math.floor(limit * 0.75);
      }
    }

    const effectiveLimit = allowBurst ? this.burstLimit : limit;

    if (timestamps.length >= effectiveLimit) {
      this.blockedRequests++;
      throw new RateLimitError(
        `Rate limit exceeded: ${timestamps.length}/${effectiveLimit} requests in window`
      );
    }

    timestamps.push(now);
    this.requestCounts.set(userId, timestamps);
    return true;
  }

  checkRateLimitByIP(ip: string): boolean {
    return this.checkRateLimit(ip);
  }

  setUserLimit(userId: string, limit: number): void {
    this.userLimits.set(userId, limit);
  }

  clearUserData(userId?: string): void {
    if (userId !== undefined) {
      this.requestCounts.delete(userId);
      this.userLimits.delete(userId);
    } else {
      this.requestCounts.clear();
      this.userLimits.clear();
    }
  }

  addToWhitelist(userId: string): void {
    this.whitelist.add(userId);
    this.blacklist.delete(userId);
  }

  removeFromWhitelist(userId: string): void {
    this.whitelist.delete(userId);
  }

  addToBlacklist(userId: string): void {
    this.blacklist.add(userId);
    this.whitelist.delete(userId);
  }

  removeFromBlacklist(userId: string): void {
    this.blacklist.delete(userId);
  }

  flagSuspiciousIP(ip: string): void {
    this.suspiciousIPs.add(ip);
  }

  getRateLimitStatus(userId: string): RateLimitStatus {
    const now = Date.now();
    const windowMs = this.windowSeconds * 1000;
    const timestamps = this._getAndPruneTimestamps(userId, now, windowMs);
    const limit = this.userLimits.get(userId) ?? this.baseLimit;
    const remaining = Math.max(0, limit - timestamps.length);
    const resetTime = timestamps.length > 0 ? timestamps[0] + windowMs : now + windowMs;

    return {
      userId,
      requestsInWindow: timestamps.length,
      limit,
      remaining,
      resetTime,
      isThrottled: timestamps.length >= limit,
    };
  }

  getRateLimitHeaders(userId: string): Record<string, string> {
    const status = this.getRateLimitStatus(userId);
    return {
      'X-RateLimit-Limit': String(status.limit),
      'X-RateLimit-Remaining': String(status.remaining),
      'X-RateLimit-Reset': String(Math.floor(status.resetTime / 1000)),
    };
  }

  getDoSMetrics(): DoSMetrics {
    return {
      totalRequests: this.totalRequests,
      blockedRequests: this.blockedRequests,
      suspiciousIPs: Array.from(this.suspiciousIPs),
      blacklistedUsers: Array.from(this.blacklist),
    };
  }

  private _getAndPruneTimestamps(userId: string, now: number, windowMs: number): number[] {
    const timestamps = (this.requestCounts.get(userId) ?? []).filter(
      (ts) => now - ts < windowMs
    );
    this.requestCounts.set(userId, timestamps);
    return timestamps;
  }

  private _getSystemLoad(): number {
    try {
      const loads = os.loadavg();
      const cpuCount = os.cpus().length;
      return loads[0] / cpuCount; // Normalize to 0–1 range (roughly)
    } catch {
      return 0.5;
    }
  }
}
