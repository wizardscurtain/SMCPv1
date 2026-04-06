/**
 * AI Immune System
 * Anomaly detection and threat scoring for MCP requests.
 */

import { ThreatClassifier } from './ThreatClassifier';
import { SecurityError } from '../exceptions';

export interface AnalysisResult {
  overallRiskScore: number;
  recommendation: 'allow' | 'monitor' | 'block';
  threatIndicators: string[];
  anomalyScores: Record<string, number>;
}

export interface AIStats {
  requestsAnalyzed: number;
  anomaliesDetected: number;
  threatsBlocked: number;
  threshold: number;
  learningMode: boolean;
}

interface AIImmuneOptions {
  threshold?: number;
  learningMode?: boolean;
  anomalyThreshold?: number; // alias used by SecurityConfig
}

export class AIImmuneSystem {
  private readonly threshold: number;
  private readonly learningMode: boolean;
  private readonly threatClassifier: ThreatClassifier;
  private readonly recentRequests: unknown[] = [];
  private readonly maxHistory = 100;

  private requestsAnalyzed = 0;
  private anomaliesDetected = 0;
  private threatsBlocked = 0;

  constructor(options: AIImmuneOptions = {}) {
    this.threshold = options.threshold ?? options.anomalyThreshold ?? 0.7;
    this.learningMode = options.learningMode ?? false;
    this.threatClassifier = new ThreatClassifier();
  }

  analyzeRequest(
    requestData: unknown,
    _authContext: unknown
  ): AnalysisResult {
    this.requestsAnalyzed++;

    const classification = this.threatClassifier.classifyThreat(requestData);
    const anomalyScores: Record<string, number> = {};

    // Base score from threat classification
    let riskScore = classification.confidence;
    anomalyScores.threat_classification = riskScore;

    // Score based on method
    const method = this._extractMethod(requestData);
    if (method) {
      const methodScore = this._scoreMethod(method);
      anomalyScores.method_score = methodScore;
      riskScore = Math.max(riskScore, methodScore * 0.5);
    }

    // Score based on params content
    const paramsScore = this._scoreParams(requestData);
    anomalyScores.params_score = paramsScore;
    riskScore = Math.max(riskScore, paramsScore);

    // Track request for pattern detection
    this.recentRequests.push(requestData);
    if (this.recentRequests.length > this.maxHistory) {
      this.recentRequests.shift();
    }

    // Pattern repetition scoring
    const repetitionScore = this._scoreRepetition(requestData);
    anomalyScores.repetition_score = repetitionScore;
    riskScore = Math.max(riskScore, repetitionScore);

    const overallRiskScore = Math.min(riskScore, 1.0);

    let recommendation: 'allow' | 'monitor' | 'block';
    if (overallRiskScore > this.threshold) {
      this.anomaliesDetected++;
      recommendation = overallRiskScore > 0.85 ? 'block' : 'monitor';
    } else {
      recommendation = 'allow';
    }

    if (overallRiskScore > 0.9 || recommendation === 'block') {
      this.threatsBlocked++;
      throw new SecurityError(
        `AI Immune System blocked request with risk score ${overallRiskScore.toFixed(2)}`
      );
    }

    return {
      overallRiskScore,
      recommendation,
      threatIndicators: classification.indicators,
      anomalyScores,
    };
  }

  train(normalRequests: unknown[]): void {
    // Learning mode: ingest normal request patterns
    for (const req of normalRequests) {
      this.recentRequests.push(req);
    }
    // Trim to max history
    while (this.recentRequests.length > this.maxHistory) {
      this.recentRequests.shift();
    }
  }

  getStats(): AIStats {
    return {
      requestsAnalyzed: this.requestsAnalyzed,
      anomaliesDetected: this.anomaliesDetected,
      threatsBlocked: this.threatsBlocked,
      threshold: this.threshold,
      learningMode: this.learningMode,
    };
  }

  private _extractMethod(data: unknown): string | null {
    if (data !== null && typeof data === 'object' && !Array.isArray(data)) {
      const obj = data as Record<string, unknown>;
      if (typeof obj.method === 'string') return obj.method;
    }
    return null;
  }

  private _scoreMethod(method: string): number {
    // System/admin methods are higher risk
    if (method.startsWith('system/')) return 0.4;
    if (method.startsWith('security/')) return 0.3;
    if (method === 'tools/call') return 0.1;
    return 0.0;
  }

  private _scoreParams(data: unknown): number {
    const text = JSON.stringify(data).toLowerCase();
    let score = 0;

    if (text.includes('password') || text.includes('secret') || text.includes('credential')) {
      score += 0.3;
    }
    if (text.includes('escalat') || text.includes('privilege') || text.includes('sudo')) {
      score += 0.25;
    }
    if (text.length > 10000) {
      score += 0.2; // Unusually large payload
    }

    return Math.min(score, 1.0);
  }

  private _scoreRepetition(requestData: unknown): number {
    const serialized = JSON.stringify(requestData);
    const matchCount = this.recentRequests.filter(
      (r) => JSON.stringify(r) === serialized
    ).length;

    // More than 5 identical requests is suspicious
    if (matchCount > 10) return 0.7;
    if (matchCount > 5) return 0.4;
    return 0.0;
  }
}
