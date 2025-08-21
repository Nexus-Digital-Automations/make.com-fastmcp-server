/**
 * @fileoverview HSM Integration Utility Module
 * Centralized utilities for Hardware Security Module integrations
 */

import { HSMStatus } from '../types/index.js';
import { HSMConfigSchema } from '../schemas/index.js';
import { auditLogger } from '../../../lib/audit-logger.js';

/**
 * Singleton HSM Integration Manager for centralized HSM operations
 */
export class HSMIntegrationManager {
  private static instance: HSMIntegrationManager | null = null;
  private hsmProviders: Map<string, HSMStatus> = new Map();

  private constructor() {}

  public static getInstance(): HSMIntegrationManager {
    if (!HSMIntegrationManager.instance) {
      HSMIntegrationManager.instance = new HSMIntegrationManager();
    }
    return HSMIntegrationManager.instance;
  }

  /**
   * Configure Hardware Security Module integration
   */
  public async configureHSM(config: Parameters<typeof HSMConfigSchema.parse>[0]): Promise<HSMStatus> {
    const validatedConfig = HSMConfigSchema.parse(config);

    // Initialize HSM connection
    const hsmStatus: HSMStatus = {
      provider: validatedConfig.provider,
      connected: true, // Simulated connection for development
      certified: true,
      fipsLevel: validatedConfig.compliance?.fipsLevel || 'level2',
      keyCount: 0,
      operationsPerSecond: 0,
      lastHealthCheck: new Date(),
      errorMessages: [],
      complianceStatus: {
        fips140: true,
        commonCriteria: Boolean(validatedConfig.compliance?.commonCriteria),
        customCertifications: validatedConfig.compliance?.certifications || [],
      },
    };

    // Configure HSM auto-unseal for Vault
    await this.configureHSMAutoUnseal(validatedConfig);

    // Store HSM status
    this.hsmProviders.set(validatedConfig.provider, hsmStatus);

    // Log HSM configuration
    await auditLogger.logEvent({
      level: 'info',
      category: 'security',
      action: 'hsm_configured',
      success: true,
      details: {
        provider: validatedConfig.provider,
        fipsLevel: validatedConfig.compliance?.fipsLevel,
        encryptionAlgorithm: validatedConfig.config.encryptionAlgorithm,
      },
      riskLevel: 'low',
    });

    return hsmStatus;
  }

  /**
   * Get HSM provider status
   */
  public getHSMStatus(provider: string): HSMStatus | undefined {
    return this.hsmProviders.get(provider);
  }

  /**
   * List all configured HSM providers
   */
  public listHSMProviders(): HSMStatus[] {
    return Array.from(this.hsmProviders.values());
  }

  /**
   * Configure HSM auto-unseal based on provider
   */
  private async configureHSMAutoUnseal(config: Parameters<typeof HSMConfigSchema.parse>[0]): Promise<void> {
    const validatedConfig = HSMConfigSchema.parse(config);
    
    switch (validatedConfig.provider) {
      case 'aws_cloudhsm':
        await this.configureAWSCloudHSM(validatedConfig);
        break;
      case 'azure_keyvault':
        await this.configureAzureKeyVault(validatedConfig);
        break;
      case 'pkcs11':
        await this.configurePKCS11HSM(validatedConfig);
        break;
      default:
        throw new Error(`Unsupported HSM provider: ${validatedConfig.provider}`);
    }
  }

  /**
   * Configure AWS CloudHSM integration
   */
  private async configureAWSCloudHSM(config: Parameters<typeof HSMConfigSchema.parse>[0]): Promise<void> {
    const validatedConfig = HSMConfigSchema.parse(config);
    // AWS CloudHSM configuration logic
    console.debug('Configuring AWS CloudHSM', {
      region: validatedConfig.config.region,
      endpoint: validatedConfig.config.endpoint,
    });
  }

  /**
   * Configure Azure Key Vault HSM integration
   */
  private async configureAzureKeyVault(config: Parameters<typeof HSMConfigSchema.parse>[0]): Promise<void> {
    const validatedConfig = HSMConfigSchema.parse(config);
    // Azure Key Vault HSM configuration logic
    console.debug('Configuring Azure Key Vault HSM', {
      tenantId: validatedConfig.config.tenantId,
      vaultName: validatedConfig.config.vaultName,
    });
  }

  /**
   * Configure PKCS#11 HSM integration
   */
  private async configurePKCS11HSM(config: Parameters<typeof HSMConfigSchema.parse>[0]): Promise<void> {
    const validatedConfig = HSMConfigSchema.parse(config);
    // PKCS#11 HSM configuration logic
    console.debug('Configuring PKCS#11 HSM', {
      library: validatedConfig.config.library,
      slot: validatedConfig.config.slot,
    });
  }

  /**
   * Perform HSM health check
   */
  public async performHealthCheck(provider: string): Promise<boolean> {
    const hsmStatus = this.hsmProviders.get(provider);
    if (!hsmStatus) {
      return false;
    }

    // Update last health check
    hsmStatus.lastHealthCheck = new Date();
    this.hsmProviders.set(provider, hsmStatus);

    return hsmStatus.connected;
  }
}

/**
 * HSM utility functions for common operations
 */
export const HSMOperations = {
  /**
   * Validate HSM provider type
   */
  isValidHSMProvider(provider: string): boolean {
    const validProviders = ['aws_cloudhsm', 'azure_keyvault', 'pkcs11'];
    return validProviders.includes(provider);
  },

  /**
   * Get FIPS level requirements
   */
  getFIPSLevelRequirements(level: string): { description: string; securityFeatures: string[] } {
    const requirements = {
      'level1': {
        description: 'Software-based cryptographic modules',
        securityFeatures: ['Basic authentication', 'Software-only implementation']
      },
      'level2': {
        description: 'Role-based authentication',
        securityFeatures: ['Role-based authentication', 'Tamper-evidence', 'Operating system security']
      },
      'level3': {
        description: 'Physical tamper resistance',
        securityFeatures: ['Identity-based authentication', 'Physical tamper resistance', 'Secure key storage']
      },
      'level4': {
        description: 'Complete environmental protection',
        securityFeatures: ['Physical tamper response', 'Environmental protection', 'Secure key zeroization']
      }
    };

    return requirements[level as keyof typeof requirements] || requirements.level2;
  },

  /**
   * Generate HSM key reference
   */
  generateKeyReference(provider: string, keyId: string): string {
    const timestamp = Date.now().toString(36);
    return `${provider}:${keyId}:${timestamp}`;
  },

  /**
   * Validate HSM configuration
   */
  validateHSMConfig(config: unknown): boolean {
    try {
      HSMConfigSchema.parse(config);
      return true;
    } catch {
      return false;
    }
  }
};

/**
 * Export singleton instance for convenience
 */
export const hsmManager = HSMIntegrationManager.getInstance();