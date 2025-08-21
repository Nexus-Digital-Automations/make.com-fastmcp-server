/**
 * @fileoverview Enterprise Secrets Utils Index
 * Aggregates all utility modules for enterprise secrets management
 */

// Vault operations utilities
export {
  VaultServerManager,
  VaultOperations,
  vaultManager
} from './vault-operations.js';

// HSM integration utilities
export {
  HSMIntegrationManager,
  HSMOperations,
  hsmManager
} from './hsm-integration.js';

// Security validation utilities
export {
  SecurityValidator,
  type SecurityValidationResult,
  type PasswordPolicyResult
} from './security-validation.js';

// Audit logging utilities
export {
  EnterpriseAuditLogger,
  AuditUtils,
  enterpriseAuditLogger,
  type EnterpriseSecretsAuditEvent,
  type AuditRiskLevel,
  type ComplianceFramework,
  type EnterpriseAuditEventDetails
} from './audit-logging.js';

// Import classes for factory
import { VaultServerManager as VaultServerManagerClass } from './vault-operations.js';
import { HSMIntegrationManager as HSMIntegrationManagerClass } from './hsm-integration.js';
import { EnterpriseAuditLogger as EnterpriseAuditLoggerClass } from './audit-logging.js';

/**
 * Utility factory for creating configured utility instances
 */
export class EnterpriseUtilityFactory {
  /**
   * Create a configured vault manager instance
   */
  public static createVaultManager(): VaultServerManagerClass {
    return VaultServerManagerClass.getInstance();
  }

  /**
   * Create a configured HSM manager instance
   */
  public static createHSMManager(): HSMIntegrationManagerClass {
    return HSMIntegrationManagerClass.getInstance();
  }

  /**
   * Create a configured audit logger instance
   */
  public static createAuditLogger(): EnterpriseAuditLoggerClass {
    return EnterpriseAuditLoggerClass.getInstance();
  }
}

/**
 * Common utility functions used across enterprise secrets tools
 */
export const CommonUtils = {
  /**
   * Generate secure random identifier
   */
  generateSecureId(prefix: string = '', length: number = 16): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = prefix ? `${prefix}-` : '';
    
    for (let i = 0; i < length; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    
    return result;
  },

  /**
   * Sanitize input for logging (remove sensitive data)
   */
  sanitizeForLogging(input: unknown): unknown {
    if (typeof input !== 'object' || input === null) {
      return input;
    }

    const sensitiveKeys = [
      'password', 'secret', 'key', 'token', 'credential',
      'privateKey', 'apiKey', 'passphrase', 'pin'
    ];

    const sanitized: Record<string, unknown> = {};
    
    for (const [key, value] of Object.entries(input as Record<string, unknown>)) {
      if (sensitiveKeys.some(sensitive => key.toLowerCase().includes(sensitive))) {
        sanitized[key] = '[REDACTED]';
      } else if (typeof value === 'object') {
        sanitized[key] = this.sanitizeForLogging(value);
      } else {
        sanitized[key] = value;
      }
    }

    return sanitized;
  },

  /**
   * Format error for consistent reporting
   */
  formatError(error: unknown): { message: string; stack?: string; type: string } {
    if (error instanceof Error) {
      return {
        message: error.message,
        stack: error.stack,
        type: error.constructor.name
      };
    }

    return {
      message: String(error),
      type: 'Unknown'
    };
  },

  /**
   * Create timeout promise for operations
   */
  createTimeoutPromise<T>(
    promise: Promise<T>,
    timeoutMs: number,
    timeoutMessage: string = 'Operation timed out'
  ): Promise<T> {
    return Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        setTimeout(() => reject(new Error(timeoutMessage)), timeoutMs);
      })
    ]);
  },

  /**
   * Validate required environment variables
   */
  validateRequiredEnvVars(requiredVars: string[]): { missing: string[]; present: string[] } {
    const missing: string[] = [];
    const present: string[] = [];

    for (const varName of requiredVars) {
      if (process.env[varName]) {
        present.push(varName);
      } else {
        missing.push(varName);
      }
    }

    return { missing, present };
  }
};

/**
 * Version information for utility modules
 */
export const ENTERPRISE_UTILS_VERSION = {
  version: '2.0.0',
  apiVersion: 'v2',
  compatibilityLevel: 'enterprise-grade',
  lastUpdated: '2024-12-21'
};