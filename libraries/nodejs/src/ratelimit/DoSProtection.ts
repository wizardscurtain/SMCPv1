/**
 * DoS Protection
 * Threat analysis, IP blocking, and challenge generation.
 */

import * as crypto from 'crypto';

export interface AnalyzeRequestResult {
  allowed: boolean;
  threatLevel: number;
  reason: string;
}

export interface ChallengeResult {
  challengeId: string;
  challenge: string;
  expiresAt: number;
}

export interface UserAgentAnalysis {
  isBot: boolean;
  isSuspicious: boolean;
  userAgent: string;
  signals: string[];
}

export interface PatternAnalysis {
  hasRepeatedPatterns: boolean;
  requestRate: number;
  suspiciousPatterns: string[];
}

interface BlockedIP {
  ip: string;
  blockedUntil: number;
  reason: string;
}

interface PendingChallenge {
  ip: string;
  challenge: string;
  answer: string;
  expiresAt: number;
}

export class DoSProtection {
  private readonly blockedIPs: Map<string, BlockedIP> = new Map();
  private readonly whitelist: Set<string> = new Set();
  private readonly requestHistory: Map<string, number[]> = new Map();
  private readonly pendingChallenges: Map<string, PendingChallenge> = new Map();
  private readonly threatScores: Map<string, number> = new Map();

  analyzeRequest(
    ip: string,
    _userId?: string,
    _requestPath?: string,
    _requestData?: unknown
  ): AnalyzeRequestResult {
    // Whitelist bypass
    if (this.whitelist.has(ip)) {
      return { allowed: true, threatLevel: 0, reason: 'whitelisted' };
    }

    // Check if blocked
    if (this.isIPBlocked(ip)) {
      return { allowed: false, threatLevel: 1.0, reason: 'ip_blocked' };
    }

    // Track request
    const now = Date.now();
    const history = this.requestHistory.get(ip) ?? [];
    const recentHistory = history.filter((ts) => now - ts < 60000); // last minute
    recentHistory.push(now);
    this.requestHistory.set(ip, recentHistory);

    // Calculate threat level
    const threatLevel = this.getThreatLevel(ip);

    if (threatLevel >= 0.8) {
      return { allowed: false, threatLevel, reason: 'high_threat_level' };
    }

    return { allowed: true, threatLevel, reason: 'normal' };
  }

  blockIP(ip: string, durationSeconds: number, reason = 'manual_block'): void {
    this.blockedIPs.set(ip, {
      ip,
      blockedUntil: Date.now() + durationSeconds * 1000,
      reason,
    });
  }

  unblockIP(ip: string): void {
    this.blockedIPs.delete(ip);
  }

  isIPBlocked(ip: string): boolean {
    const block = this.blockedIPs.get(ip);
    if (!block) return false;

    if (Date.now() > block.blockedUntil) {
      this.blockedIPs.delete(ip);
      return false;
    }

    return true;
  }

  addToWhitelist(ip: string): void {
    this.whitelist.add(ip);
  }

  removeFromWhitelist(ip: string): void {
    this.whitelist.delete(ip);
  }

  getThreatLevel(ip?: string): number {
    if (!ip) {
      // Return average threat level
      if (this.threatScores.size === 0) return 0;
      const sum = Array.from(this.threatScores.values()).reduce((a, b) => a + b, 0);
      return sum / this.threatScores.size;
    }

    const score = this.threatScores.get(ip);
    if (score !== undefined) return score;

    // Calculate from history
    const history = this.requestHistory.get(ip) ?? [];
    const now = Date.now();
    const recentRequests = history.filter((ts) => now - ts < 60000).length;

    // Simple scoring: 100+ requests/min is suspicious
    if (recentRequests > 200) return 0.9;
    if (recentRequests > 100) return 0.7;
    if (recentRequests > 50) return 0.4;
    return 0.1;
  }

  generateChallenge(ip: string): ChallengeResult {
    const challengeId = crypto.randomBytes(16).toString('hex');
    const a = Math.floor(Math.random() * 10) + 1;
    const b = Math.floor(Math.random() * 10) + 1;
    const challenge = `What is ${a} + ${b}?`;
    const answer = String(a + b);
    const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes

    this.pendingChallenges.set(challengeId, { ip, challenge, answer, expiresAt });

    return { challengeId, challenge, expiresAt };
  }

  verifyChallengeResponse(challengeId: string, response: string): boolean {
    const pending = this.pendingChallenges.get(challengeId);
    if (!pending) return false;

    if (Date.now() > pending.expiresAt) {
      this.pendingChallenges.delete(challengeId);
      return false;
    }

    const isCorrect = pending.answer === response.trim();
    this.pendingChallenges.delete(challengeId);
    return isCorrect;
  }

  analyzeUserAgent(userAgent: string): UserAgentAnalysis {
    const signals: string[] = [];
    let isBot = false;
    let isSuspicious = false;

    const botPatterns = [
      /\bcurl\b/i,
      /\bwget\b/i,
      /\bpython-requests\b/i,
      /\bhttpclient\b/i,
      /\bgo-http-client\b/i,
      /\bscrapy\b/i,
      /\bbot\b/i,
      /\bspider\b/i,
      /\bcrawler\b/i,
    ];

    for (const pattern of botPatterns) {
      if (pattern.test(userAgent)) {
        isBot = true;
        signals.push(`bot_pattern:${pattern.source}`);
      }
    }

    if (!userAgent || userAgent.length < 10) {
      isSuspicious = true;
      signals.push('suspicious:short_ua');
    }

    return { isBot, isSuspicious, userAgent, signals };
  }

  analyzePatterns(ip: string): PatternAnalysis {
    const history = this.requestHistory.get(ip) ?? [];
    const now = Date.now();
    const recentHistory = history.filter((ts) => now - ts < 60000);
    const requestRate = recentHistory.length / 60; // per second
    const suspiciousPatterns: string[] = [];

    if (requestRate > 10) suspiciousPatterns.push('high_request_rate');
    if (recentHistory.length > 100) suspiciousPatterns.push('flood_attempt');

    // Check for repeated patterns (uniform intervals)
    if (recentHistory.length >= 5) {
      const intervals = recentHistory.slice(1).map((ts, i) => ts - recentHistory[i]);
      const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
      const variance = intervals.reduce((acc, v) => acc + Math.pow(v - avgInterval, 2), 0) / intervals.length;
      if (variance < 100 && recentHistory.length > 10) {
        suspiciousPatterns.push('automated_pattern');
      }
    }

    return {
      hasRepeatedPatterns: suspiciousPatterns.length > 0,
      requestRate,
      suspiciousPatterns,
    };
  }

  cleanupExpiredData(): void {
    const now = Date.now();

    // Clean expired blocks
    for (const [ip, block] of this.blockedIPs.entries()) {
      if (now > block.blockedUntil) {
        this.blockedIPs.delete(ip);
      }
    }

    // Clean expired challenges
    for (const [id, challenge] of this.pendingChallenges.entries()) {
      if (now > challenge.expiresAt) {
        this.pendingChallenges.delete(id);
      }
    }

    // Trim request history older than 5 minutes
    for (const [ip, history] of this.requestHistory.entries()) {
      const pruned = history.filter((ts) => now - ts < 5 * 60 * 1000);
      if (pruned.length === 0) {
        this.requestHistory.delete(ip);
      } else {
        this.requestHistory.set(ip, pruned);
      }
    }
  }
}
