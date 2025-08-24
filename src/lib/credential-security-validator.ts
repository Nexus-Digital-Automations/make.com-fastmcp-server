/**
 * Comprehensive credential security validation framework
 * Implements advanced validation, strength assessment, and security scoring
 */

import * as crypto from 'crypto';
import logger from './logger.js';

export interface CredentialValidationResult {
  isValid: boolean;
  score: number; // 0-100 security score
  errors: string[];
  warnings: string[];
  strengths: string[];
  weaknesses: string[];
  recommendations: string[];
}

export interface SecurityAssessment {
  score: number;
  grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  weaknesses: string[];
  strengths: string[];
  recommendations: string[];
}

export interface ExposureRiskAssessment {
  riskLevel: 'critical' | 'high' | 'medium' | 'low';
  risks: string[];
  mitigations: string[];
}

/**
 * Advanced credential security validator
 */
export class CredentialSecurityValidator {
  private static readonly MIN_API_KEY_LENGTH = 32;
  private static readonly MIN_SECRET_LENGTH = 64;
  private static readonly MIN_TOKEN_LENGTH = 20;
  
  private readonly componentLogger: ReturnType<typeof logger.child>;
  
  // Known weak patterns that should be avoided
  private static readonly WEAK_PATTERNS = [
    /^(test|demo|example|sample)_/i,
    /^(dev|development|staging)_/i,
    /password|secret|key/i,
    /123456|qwerty|admin/i,
    /^[a-zA-Z]+$/, // Only letters
    /^[0-9]+$/, // Only numbers
    /(.)\1{3,}/ // Repeated characters (4 or more)
  ];

  // Entropy calculation patterns
  private static readonly ENTROPY_PATTERNS = {
    lowercase: /[a-z]/g,
    uppercase: /[A-Z]/g,
    digits: /[0-9]/g,
    special: /[!@#$%^&*()_+\-=[\]{}|;:,.<>?]/g,
    space: /\s/g
  };

  constructor() {
    try {
      this.componentLogger = logger.child({ component: 'CredentialSecurityValidator' });
    } catch {
      // Fallback for test environments
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      this.componentLogger = logger as any;
    }
  }

  /**
   * Validate Make.com API key with comprehensive checks
   */
  public validateMakeApiKey(apiKey: string): CredentialValidationResult {
    const result: CredentialValidationResult = {
      isValid: true,
      score: 100,
      errors: [],
      warnings: [],
      strengths: [],
      weaknesses: [],
      recommendations: []
    };

    // Basic format validation
    if (!apiKey || typeof apiKey !== 'string') {
      result.errors.push('API key must be a non-empty string');
      result.isValid = false;
      result.score = 0;
      return result;
    }

    const trimmedKey = apiKey.trim();

    // Length validation
    if (trimmedKey.length < 10) {
      result.errors.push('API key is too short (minimum 10 characters)');
      result.score -= 40;
    } else if (trimmedKey.length < CredentialSecurityValidator.MIN_API_KEY_LENGTH) {
      result.warnings.push(`API key shorter than recommended (${CredentialSecurityValidator.MIN_API_KEY_LENGTH} characters)`);
      result.score -= 15;
    } else {
      result.strengths.push('Adequate key length');
    }

    // Character composition analysis
    const composition = this.analyzeCharacterComposition(trimmedKey);
    if (composition.entropy < 3.0) {
      result.weaknesses.push('Low entropy - predictable character patterns');
      result.score -= 20;
    } else if (composition.entropy >= 4.0) {
      result.strengths.push('High entropy - good character diversity');
    }

    // Check for weak patterns
    const weakPatterns = this.checkWeakPatterns(trimmedKey);
    if (weakPatterns.length > 0) {
      result.warnings.push(`Contains potentially weak patterns: ${weakPatterns.join(', ')}`);
      result.score -= (weakPatterns.length * 10);
    }

    // Check for common vulnerabilities
    const vulnerabilities = this.checkCommonVulnerabilities(trimmedKey);
    if (vulnerabilities.length > 0) {
      result.weaknesses.push(...vulnerabilities);
      result.score -= (vulnerabilities.length * 15);
    }

    // Format validation (Make.com API keys typically have specific patterns)
    if (!this.validateMakeApiKeyFormat(trimmedKey)) {
      result.warnings.push('API key format may not match expected Make.com patterns');
      result.score -= 5;
    }

    // Check for credential exposure risks
    const exposureRisks = this.checkCredentialExposure(trimmedKey);
    if (exposureRisks.length > 0) {
      result.warnings.push(`Potential exposure risks: ${exposureRisks.join(', ')}`);
      result.score -= (exposureRisks.length * 8);
    }

    // Ensure score doesn't go below 0
    result.score = Math.max(0, result.score);
    
    // Set validity based on score and critical errors
    result.isValid = result.errors.length === 0 && result.score >= 40;

    // Add recommendations based on findings
    this.addRecommendations(result);

    this.componentLogger.debug('API key validation completed', {
      score: result.score,
      isValid: result.isValid,
      errorCount: result.errors.length,
      warningCount: result.warnings.length
    });

    return result;
  }

  /**
   * Assess overall security strength of a credential
   */
  public assessSecurityStrength(credential: string): SecurityAssessment {
    const validation = this.validateMakeApiKey(credential);
    
    let grade: SecurityAssessment['grade'];
    if (validation.score >= 90) {grade = 'A+';}
    else if (validation.score >= 80) {grade = 'A';}
    else if (validation.score >= 70) {grade = 'B';}
    else if (validation.score >= 60) {grade = 'C';}
    else if (validation.score >= 40) {grade = 'D';}
    else {grade = 'F';}

    return {
      score: validation.score,
      grade,
      weaknesses: validation.weaknesses,
      strengths: validation.strengths,
      recommendations: validation.recommendations
    };
  }

  /**
   * Check for weak patterns in credentials
   */
  public checkWeakPatterns(credential: string): string[] {
    const weakPatterns: string[] = [];

    for (const [index, pattern] of CredentialSecurityValidator.WEAK_PATTERNS.entries()) {
      if (pattern.test(credential)) {
        switch (index) {
          case 0: {
            weakPatterns.push('test/demo prefix');
            break;
          }
          case 1: {
            weakPatterns.push('development environment prefix');
            break;
          }
          case 2: {
            weakPatterns.push('contains common words');
            break;
          }
          case 3: {
            weakPatterns.push('common weak sequences');
            break;
          }
          case 4: {
            weakPatterns.push('only alphabetic characters');
            break;
          }
          case 5: {
            weakPatterns.push('only numeric characters');
            break;
          }
          case 6: {
            weakPatterns.push('repeated character sequences');
            break;
          }
        }
      }
    }

    return weakPatterns;
  }

  /**
   * Check for credential exposure risks
   */
  public checkCredentialExposure(credential: string): string[] {
    const risks: string[] = [];

    // Check for common base64 patterns (often exposed in configs)
    if (/^[A-Za-z0-9+/]+=*$/.test(credential) && credential.length % 4 === 0) {
      risks.push('base64-like pattern (commonly exposed in configs)');
    }

    // Check for hex patterns
    if (/^[a-fA-F0-9]+$/.test(credential) && credential.length >= 32) {
      risks.push('hexadecimal pattern (may be hash-based)');
    }

    // Check for sequential patterns
    if (this.hasSequentialPattern(credential)) {
      risks.push('sequential character patterns');
    }

    // Check for dictionary words
    if (this.containsDictionaryWords(credential)) {
      risks.push('contains dictionary words');
    }

    return risks;
  }

  /**
   * Analyze character composition and calculate entropy
   */
  private analyzeCharacterComposition(text: string): {
    entropy: number;
    charSets: number;
    composition: Record<string, number>;
  } {
    const composition: Record<string, number> = {
      lowercase: 0,
      uppercase: 0,
      digits: 0,
      special: 0,
      space: 0
    };

    // Count character types
    for (const [type, pattern] of Object.entries(CredentialSecurityValidator.ENTROPY_PATTERNS)) {
      const matches = text.match(pattern);
      composition[type] = matches ? matches.length : 0;
    }

    // Calculate number of character sets used
    const charSets = Object.values(composition).filter(count => count > 0).length;

    // Calculate Shannon entropy
    const charFreq: Record<string, number> = {};
    for (const char of text) {
      charFreq[char] = (charFreq[char] || 0) + 1;
    }

    let entropy = 0;
    const length = text.length;
    for (const freq of Object.values(charFreq)) {
      const probability = freq / length;
      entropy -= probability * Math.log2(probability);
    }

    return {
      entropy,
      charSets,
      composition
    };
  }

  /**
   * Check for common credential vulnerabilities
   */
  private checkCommonVulnerabilities(credential: string): string[] {
    const vulnerabilities: string[] = [];

    // Check for timestamp patterns (often indicates test keys)
    if (/\d{10,13}/.test(credential)) {
      vulnerabilities.push('contains timestamp-like sequences');
    }

    // Check for UUID patterns (v4 UUIDs are more secure than v1)
    const uuidPattern = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;
    if (uuidPattern.test(credential)) {
      vulnerabilities.push('contains UUID pattern (check if v4 for better security)');
    }

    // Check for short repeating segments
    if (this.hasRepeatingSegments(credential)) {
      vulnerabilities.push('contains repeating segments');
    }

    return vulnerabilities;
  }

  /**
   * Validate Make.com specific API key format
   */
  private validateMakeApiKeyFormat(apiKey: string): boolean {
    // Make.com API keys often follow specific patterns
    // This is a simplified check - in production, validate against known formats
    
    // Check for reasonable length and character composition
    if (apiKey.length < 20 || apiKey.length > 200) {
      return false;
    }

    // Should not be purely numeric or alphabetic
    const hasLetters = /[a-zA-Z]/.test(apiKey);
    const hasNumbers = /[0-9]/.test(apiKey);
    const hasSpecialChars = /[^a-zA-Z0-9]/.test(apiKey);

    return hasLetters && (hasNumbers || hasSpecialChars);
  }

  /**
   * Check for sequential patterns
   */
  private hasSequentialPattern(text: string): boolean {
    let sequentialCount = 0;
    for (let i = 1; i < text.length; i++) {
      const current = text.charCodeAt(i);
      const previous = text.charCodeAt(i - 1);
      if (Math.abs(current - previous) === 1) {
        sequentialCount++;
        if (sequentialCount >= 3) {
          return true;
        }
      } else {
        sequentialCount = 0;
      }
    }
    return false;
  }

  /**
   * Check for repeating segments
   */
  private hasRepeatingSegments(text: string): boolean {
    for (let segmentLength = 2; segmentLength <= Math.floor(text.length / 2); segmentLength++) {
      for (let i = 0; i <= text.length - segmentLength * 2; i++) {
        const segment = text.substring(i, i + segmentLength);
        const nextSegment = text.substring(i + segmentLength, i + segmentLength * 2);
        if (segment === nextSegment) {
          return true;
        }
      }
    }
    return false;
  }

  /**
   * Check for dictionary words (simplified implementation)
   */
  private containsDictionaryWords(text: string): boolean {
    const commonWords = [
      'password', 'secret', 'key', 'token', 'admin', 'test', 'demo',
      'user', 'account', 'login', 'auth', 'api', 'access', 'private'
    ];

    const lowerText = text.toLowerCase();
    return commonWords.some(word => lowerText.includes(word));
  }

  /**
   * Add recommendations based on validation results
   */
  private addRecommendations(result: CredentialValidationResult): void {
    if (result.score < 60) {
      result.recommendations.push('Consider regenerating the API key with higher entropy');
    }

    if (result.weaknesses.some(w => w.includes('entropy'))) {
      result.recommendations.push('Use a cryptographically secure random generator');
    }

    if (result.warnings.some(w => w.includes('weak patterns'))) {
      result.recommendations.push('Avoid predictable patterns and common words');
    }

    if (result.warnings.some(w => w.includes('exposure'))) {
      result.recommendations.push('Ensure proper credential storage and avoid logging');
    }

    if (result.score >= 80) {
      result.recommendations.push('Implement automatic rotation every 90 days');
    }

    if (result.errors.length === 0 && result.score >= 70) {
      result.recommendations.push('Enable credential monitoring and anomaly detection');
    }
  }

  /**
   * Generate a secure credential based on type and requirements
   */
  public generateSecureCredential(type: 'api_key' | 'secret' | 'token', options: {
    length?: number;
    prefix?: string;
    includeTimestamp?: boolean;
  } = {}): string {
    const length = options.length || (type === 'secret' ? 64 : 32);
    
    let result = options.prefix || '';
    
    if (options.includeTimestamp) {
      result += `${Date.now().toString(36)}_`;
    }

    // Generate cryptographically secure random string
    const randomBytes = crypto.randomBytes(Math.ceil(length / 1.33)); // Base64 encoding inflates size
    const randomPart = randomBytes.toString('base64url').slice(0, length - result.length);
    
    result += randomPart;

    this.componentLogger.info('Secure credential generated', {
      type,
      length: result.length,
      hasPrefix: !!options.prefix,
      hasTimestamp: !!options.includeTimestamp
    });

    return result;
  }

  /**
   * Validate credential rotation requirements
   */
  public validateRotationRequirements(credential: string, createdAt: Date, policy: {
    maxAge: number; // milliseconds
    warnBefore: number; // milliseconds
  }): {
    needsRotation: boolean;
    isExpired: boolean;
    warningTime: boolean;
    daysUntilExpiry: number;
    recommendation: string;
  } {
    const now = new Date();
    const age = now.getTime() - createdAt.getTime();
    const daysUntilExpiry = Math.ceil((policy.maxAge - age) / (24 * 60 * 60 * 1000));
    
    const isExpired = age >= policy.maxAge;
    const warningTime = age >= (policy.maxAge - policy.warnBefore);
    const needsRotation = isExpired || warningTime;

    let recommendation = '';
    if (isExpired) {
      recommendation = 'Credential has expired and must be rotated immediately';
    } else if (warningTime) {
      recommendation = `Credential should be rotated soon (${daysUntilExpiry} days remaining)`;
    } else {
      recommendation = `Credential is current (${daysUntilExpiry} days until rotation)`;
    }

    return {
      needsRotation,
      isExpired,
      warningTime,
      daysUntilExpiry,
      recommendation
    };
  }
}

/**
 * Factory function to create credential validator with default settings
 */
export function createCredentialValidator(): CredentialSecurityValidator {
  return new CredentialSecurityValidator();
}

// Export lazy-initialized singleton instance
let _credentialSecurityValidator: CredentialSecurityValidator | null = null;

export const credentialSecurityValidator = (): CredentialSecurityValidator => {
  if (!_credentialSecurityValidator) {
    _credentialSecurityValidator = new CredentialSecurityValidator();
  }
  return _credentialSecurityValidator;
};

export default credentialSecurityValidator;