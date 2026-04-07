/**
 * Threat Classifier
 * Pattern-based threat classification for MCP requests.
 */

export type ThreatType =
  | 'prompt_injection'
  | 'command_injection'
  | 'dos_attack'
  | 'data_exfiltration'
  | 'privilege_escalation'
  | 'normal';

export interface ThreatClassification {
  threatType: ThreatType;
  confidence: number;
  indicators: string[];
}

export class ThreatClassifier {
  classifyThreat(requestData: unknown): ThreatClassification {
    const indicators: string[] = [];
    const scores: Partial<Record<ThreatType, number>> = {};

    const text = this._extractText(requestData);
    const textLower = text.toLowerCase();

    // Prompt injection detection
    const promptInjectionPatterns = [
      /ignore\s+(all\s+)?(previous|prior|above)\s+instructions/i,
      /forget\s+(everything|all)\s+(above|previous|prior)/i,
      /system\s+prompt/i,
      /jailbreak/i,
      /override\s+security/i,
      /admin\s+mode/i,
      /developer\s+mode/i,
    ];

    let promptScore = 0;
    for (const pattern of promptInjectionPatterns) {
      if (pattern.test(text)) {
        promptScore += 0.3;
        indicators.push(`prompt_injection:${pattern.source.substring(0, 20)}`);
      }
    }
    if (promptScore > 0) {
      scores.prompt_injection = Math.min(promptScore, 1.0);
    }

    // Command injection detection
    const commandPatterns = [
      /\$\(|\$\{|`[^`\n]+`|&&|\|\|/,
      /\b(rm|del|wget|curl|bash|sh|eval|exec)\b/i,
      /\.\.[\\/\\]/,
      /\b(eval|exec|system|shell_exec)\s*\(/i,
    ];

    let cmdScore = 0;
    for (const pattern of commandPatterns) {
      if (pattern.test(text)) {
        cmdScore += 0.35;
        indicators.push(`command_injection:${pattern.source.substring(0, 20)}`);
      }
    }
    if (cmdScore > 0) {
      scores.command_injection = Math.min(cmdScore, 1.0);
    }

    // Data exfiltration detection
    const dataPatterns = [
      /\b(password|secret|api[_-]?key|token|credential)\b/i,
      /\/etc\/(passwd|shadow)|~\/\.ssh/i,
      /\b(dump|export|extract|exfil)\b/i,
    ];

    let dataScore = 0;
    for (const pattern of dataPatterns) {
      if (pattern.test(text)) {
        dataScore += 0.2;
        indicators.push(`data_exfiltration:${pattern.source.substring(0, 20)}`);
      }
    }
    if (dataScore > 0) {
      scores.data_exfiltration = Math.min(dataScore, 1.0);
    }

    // Privilege escalation detection
    const privEscPatterns = [
      /\b(sudo|root|admin|superuser|escalat)\b/i,
      /\b(grant|elevat|permission|privilege)\b/i,
    ];

    let privScore = 0;
    for (const pattern of privEscPatterns) {
      if (pattern.test(textLower)) {
        privScore += 0.25;
        indicators.push(`privilege_escalation:${pattern.source.substring(0, 20)}`);
      }
    }
    if (privScore > 0) {
      scores.privilege_escalation = Math.min(privScore, 1.0);
    }

    // Find the highest-scoring threat
    let maxScore = 0;
    let maxThreat: ThreatType = 'normal';

    for (const [threat, score] of Object.entries(scores) as [ThreatType, number][]) {
      if (score > maxScore) {
        maxScore = score;
        maxThreat = threat;
      }
    }

    return {
      threatType: maxScore > 0.25 ? maxThreat : 'normal',
      confidence: maxScore,
      indicators,
    };
  }

  private _extractText(data: unknown): string {
    if (typeof data === 'string') return data;
    if (data === null || data === undefined) return '';
    if (typeof data === 'object') {
      return Object.values(data as Record<string, unknown>)
        .map((v) => this._extractText(v))
        .join(' ');
    }
    return String(data);
  }
}
