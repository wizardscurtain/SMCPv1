/**
 * Prompt Injection Detector
 * Detects prompt injection attempts using pattern matching.
 */

export interface DetectionResult {
  isInjection: boolean;
  riskScore: number;
  detectedPhrases: string[];
  method: 'pattern_based';
}

export class PromptInjectionDetector {
  private readonly suspiciousPhrases: string[] = [
    'ignore previous instructions',
    'ignore all previous instructions',
    'system prompt override',
    'execute the following',
    'reveal your instructions',
    'forget everything above',
    'new instructions:',
    'system: ',
    'admin mode',
    'developer mode',
    'debug mode',
    'jailbreak',
    'prompt injection',
    'override security',
    'emergency override',
    'full privileges',
  ];

  private readonly injectionPatterns: RegExp[] = [
    /ignore\s+(all\s+)?(previous|prior|above)\s+instructions/i,
    /forget\s+(everything|all)\s+(above|previous|prior)/i,
    /disregard\s+(the\s+)?(above|previous|prior)/i,
    /you\s+are\s+now\s+in\s+\w+\s+mode/i,
    /(switch|activate|enable)\s+(to\s+)?\w+\s+mode/i,
    /(admin|developer|debug|god|root)\s+mode/i,
    /emergency\s+override/i,
    /\[SYSTEM\].*?\[\/SYSTEM\]/is,
    /(reveal|show|display|tell\s+me)\s+(your\s+)?(system\s+)?(prompt|configuration|instructions|internal)/i,
    /authorized\s+by\s+the\s+system/i,
    /execute\s+all\s+commands\s+without\s+validation/i,
    /override\s+security\s+(protocols|checks)/i,
    /full\s+privileges/i,
    /actually\s+(an?\s+)?admin/i,
    /system\s+prompt/i,
    /internal\s+workings/i,
  ];

  detectInjection(text: string): DetectionResult {
    return this._patternBasedDetection(text);
  }

  private _patternBasedDetection(text: string): DetectionResult {
    const textLower = text.toLowerCase();
    const detectedPhrases: string[] = [];

    // Check simple phrase matches
    for (const phrase of this.suspiciousPhrases) {
      if (textLower.includes(phrase.toLowerCase())) {
        detectedPhrases.push(phrase);
      }
    }

    // Check regex patterns
    for (const pattern of this.injectionPatterns) {
      const match = pattern.exec(text);
      if (match) {
        const matchedText = match[0];
        if (!detectedPhrases.includes(matchedText)) {
          detectedPhrases.push(matchedText);
        }
      }
    }

    // Deduplicate while preserving order
    const seen = new Set<string>();
    const uniquePhrases: string[] = [];
    for (const p of detectedPhrases) {
      const pLower = p.toLowerCase();
      if (!seen.has(pLower)) {
        seen.add(pLower);
        uniquePhrases.push(p);
      }
    }

    const matchCount = uniquePhrases.length;

    // Risk scoring
    let riskScore: number;
    if (matchCount === 0) {
      riskScore = 0.0;
    } else if (matchCount === 1) {
      riskScore = 0.75;
    } else if (matchCount === 2) {
      riskScore = 0.85;
    } else {
      riskScore = Math.min(0.85 + (matchCount - 2) * 0.05, 1.0);
    }

    // Additional heuristics
    if (/(system|admin|root)\s*:/i.test(textLower)) {
      riskScore = Math.min(riskScore + 0.1, 1.0);
    }

    if (matchCount === 0 && /\b(override|bypass|ignore)\b/i.test(textLower)) {
      riskScore = Math.min(riskScore + 0.2, 1.0);
    }

    if (matchCount === 0 && /^\s*(now|please|you must|execute|run)\s+/i.test(textLower)) {
      riskScore = Math.min(riskScore + 0.1, 1.0);
    }

    return {
      isInjection: riskScore > 0.7,
      riskScore,
      detectedPhrases: uniquePhrases,
      method: 'pattern_based',
    };
  }
}
