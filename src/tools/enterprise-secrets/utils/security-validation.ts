/**
 * @fileoverview Security Validation Utility Module
 * Centralized security validation utilities for enterprise secrets management
 */

import { SecurityPolicySchema } from '../schemas/index.js';

/**
 * Security validation results interface
 */
export interface SecurityValidationResult {
  isValid: boolean;
  violations: string[];
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  recommendations: string[];
}

/**
 * Password policy validation result
 */
export interface PasswordPolicyResult {
  isValid: boolean;
  violations: string[];
  strength: 'weak' | 'fair' | 'good' | 'strong' | 'very-strong';
}

/**
 * Security validation utilities
 */
export class SecurityValidator {
  /**
   * Validate security policy configuration
   */
  public static validateSecurityPolicy(config: unknown): SecurityValidationResult {
    const violations: string[] = [];
    let riskLevel: SecurityValidationResult['riskLevel'] = 'low';
    const recommendations: string[] = [];

    try {
      SecurityPolicySchema.parse(config);
    } catch (error) {
      violations.push('Invalid security policy configuration');
      riskLevel = 'high';
      recommendations.push('Review and correct security policy configuration');
    }

    return {
      isValid: violations.length === 0,
      violations,
      riskLevel,
      recommendations
    };
  }

  /**
   * Validate password strength and policies
   */
  public static validatePassword(password: string, policy?: {
    minLength?: number;
    requireUppercase?: boolean;
    requireLowercase?: boolean;
    requireNumbers?: boolean;
    requireSpecialChars?: boolean;
    maxAge?: number;
  }): PasswordPolicyResult {
    const violations: string[] = [];
    const defaultPolicy = {
      minLength: 12,
      requireUppercase: true,
      requireLowercase: true,
      requireNumbers: true,
      requireSpecialChars: true,
      ...policy
    };

    // Check minimum length
    if (password.length < defaultPolicy.minLength) {
      violations.push(`Password must be at least ${defaultPolicy.minLength} characters long`);
    }

    // Check uppercase requirement
    if (defaultPolicy.requireUppercase && !/[A-Z]/.test(password)) {
      violations.push('Password must contain at least one uppercase letter');
    }

    // Check lowercase requirement
    if (defaultPolicy.requireLowercase && !/[a-z]/.test(password)) {
      violations.push('Password must contain at least one lowercase letter');
    }

    // Check numbers requirement
    if (defaultPolicy.requireNumbers && !/\d/.test(password)) {
      violations.push('Password must contain at least one number');
    }

    // Check special characters requirement
    if (defaultPolicy.requireSpecialChars && !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
      violations.push('Password must contain at least one special character');
    }

    // Determine strength
    const strength = this.calculatePasswordStrength(password);

    return {
      isValid: violations.length === 0,
      violations,
      strength
    };
  }

  /**
   * Calculate password strength score
   */
  private static calculatePasswordStrength(password: string): PasswordPolicyResult['strength'] {
    let score = 0;

    // Length scoring
    if (password.length >= 8) score += 1;
    if (password.length >= 12) score += 1;
    if (password.length >= 16) score += 1;

    // Character variety scoring
    if (/[a-z]/.test(password)) score += 1;
    if (/[A-Z]/.test(password)) score += 1;
    if (/\d/.test(password)) score += 1;
    if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) score += 1;

    // Complexity scoring
    if (/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])/.test(password)) score += 1;

    // Return strength based on score
    if (score <= 2) return 'weak';
    if (score <= 4) return 'fair';
    if (score <= 6) return 'good';
    if (score <= 7) return 'strong';
    return 'very-strong';
  }

  /**
   * Validate API key format and strength
   */
  public static validateApiKey(apiKey: string): SecurityValidationResult {
    const violations: string[] = [];
    let riskLevel: SecurityValidationResult['riskLevel'] = 'low';
    const recommendations: string[] = [];

    // Check minimum length (API keys should be at least 32 characters)
    if (apiKey.length < 32) {
      violations.push('API key should be at least 32 characters long');
      riskLevel = 'high';
      recommendations.push('Generate a longer API key for better security');
    }

    // Check for weak patterns
    if (/^[0-9]+$/.test(apiKey)) {
      violations.push('API key should not contain only numbers');
      riskLevel = 'high';
      recommendations.push('Use alphanumeric characters in API keys');
    }

    if (/^[a-zA-Z]+$/.test(apiKey)) {
      violations.push('API key should not contain only letters');
      riskLevel = 'medium';
      recommendations.push('Include numbers in API keys for better entropy');
    }

    // Check for common weak patterns
    if (/(.)\1{3,}/.test(apiKey)) {
      violations.push('API key contains repeated character patterns');
      riskLevel = 'medium';
      recommendations.push('Avoid repeating character patterns in API keys');
    }

    return {
      isValid: violations.length === 0,
      violations,
      riskLevel,
      recommendations
    };
  }

  /**
   * Validate encryption configuration
   */
  public static validateEncryptionConfig(config: {
    algorithm?: string;
    keySize?: number;
    mode?: string;
  }): SecurityValidationResult {
    const violations: string[] = [];
    let riskLevel: SecurityValidationResult['riskLevel'] = 'low';
    const recommendations: string[] = [];

    // Validate algorithm
    const approvedAlgorithms = ['AES', 'ChaCha20', 'RSA'];
    if (config.algorithm && !approvedAlgorithms.includes(config.algorithm)) {
      violations.push(`Encryption algorithm '${config.algorithm}' is not approved`);
      riskLevel = 'high';
      recommendations.push(`Use approved algorithms: ${approvedAlgorithms.join(', ')}`);
    }

    // Validate key size
    if (config.keySize) {
      const minKeySizes = { 'AES': 256, 'RSA': 2048, 'ChaCha20': 256 };
      const minSize = minKeySizes[config.algorithm as keyof typeof minKeySizes];
      
      if (minSize && config.keySize < minSize) {
        violations.push(`Key size ${config.keySize} is below minimum ${minSize} for ${config.algorithm}`);
        riskLevel = 'high';
        recommendations.push(`Use minimum key size of ${minSize} bits for ${config.algorithm}`);
      }
    }

    // Validate mode for AES
    if (config.algorithm === 'AES' && config.mode) {
      const approvedModes = ['GCM', 'CBC', 'CTR'];
      if (!approvedModes.includes(config.mode)) {
        violations.push(`AES mode '${config.mode}' is not recommended`);
        riskLevel = 'medium';
        recommendations.push(`Use approved AES modes: ${approvedModes.join(', ')}`);
      }
    }

    return {
      isValid: violations.length === 0,
      violations,
      riskLevel,
      recommendations
    };
  }

  /**
   * Validate network security configuration
   */
  public static validateNetworkConfig(config: {
    tlsVersion?: string;
    cipherSuites?: string[];
    certificateValidation?: boolean;
  }): SecurityValidationResult {
    const violations: string[] = [];
    let riskLevel: SecurityValidationResult['riskLevel'] = 'low';
    const recommendations: string[] = [];

    // Validate TLS version
    if (config.tlsVersion) {
      const approvedVersions = ['1.2', '1.3'];
      if (!approvedVersions.includes(config.tlsVersion)) {
        violations.push(`TLS version ${config.tlsVersion} is not secure`);
        riskLevel = 'high';
        recommendations.push('Use TLS 1.2 or 1.3');
      }
    }

    // Validate cipher suites
    if (config.cipherSuites) {
      const weakCiphers = ['RC4', 'DES', '3DES', 'MD5'];
      const foundWeakCiphers = config.cipherSuites.filter(cipher => 
        weakCiphers.some(weak => cipher.includes(weak))
      );
      
      if (foundWeakCiphers.length > 0) {
        violations.push(`Weak cipher suites detected: ${foundWeakCiphers.join(', ')}`);
        riskLevel = 'high';
        recommendations.push('Remove weak cipher suites from configuration');
      }
    }

    // Validate certificate validation
    if (config.certificateValidation === false) {
      violations.push('Certificate validation is disabled');
      riskLevel = 'critical';
      recommendations.push('Enable certificate validation for secure connections');
    }

    return {
      isValid: violations.length === 0,
      violations,
      riskLevel,
      recommendations
    };
  }

  /**
   * Generate security score based on multiple validation results
   */
  public static calculateSecurityScore(validationResults: SecurityValidationResult[]): {
    score: number;
    grade: 'A' | 'B' | 'C' | 'D' | 'F';
    overallRiskLevel: SecurityValidationResult['riskLevel'];
  } {
    let totalViolations = 0;
    let highestRiskLevel: SecurityValidationResult['riskLevel'] = 'low';
    
    for (const result of validationResults) {
      totalViolations += result.violations.length;
      
      // Determine highest risk level
      const riskLevels = { low: 0, medium: 1, high: 2, critical: 3 };
      if (riskLevels[result.riskLevel] > riskLevels[highestRiskLevel]) {
        highestRiskLevel = result.riskLevel;
      }
    }

    // Calculate score (100 - violations penalty)
    const violationPenalty = Math.min(totalViolations * 10, 90);
    const score = Math.max(100 - violationPenalty, 0);

    // Assign grade
    let grade: 'A' | 'B' | 'C' | 'D' | 'F';
    if (score >= 90) grade = 'A';
    else if (score >= 80) grade = 'B';
    else if (score >= 70) grade = 'C';
    else if (score >= 60) grade = 'D';
    else grade = 'F';

    return {
      score,
      grade,
      overallRiskLevel: highestRiskLevel
    };
  }
}