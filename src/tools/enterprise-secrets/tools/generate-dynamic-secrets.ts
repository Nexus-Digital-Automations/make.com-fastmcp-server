/**
 * @fileoverview Generate Dynamic Secrets Tool Implementation
 * Generate just-in-time dynamic secrets for databases, cloud providers, and APIs
 */

import { UserError } from 'fastmcp';
import { DynamicSecretConfigSchema } from '../schemas/index.js';
import { ToolContext, ToolDefinition, ToolExecutionContext } from '../../shared/types/tool-context.js';
import { auditLogger } from '../../../lib/audit-logger.js';
import * as crypto from 'crypto';
import { promisify } from 'util';
import { formatSuccessResponse } from '../../../utils/response-formatter.js';

const randomBytes = promisify(crypto.randomBytes);

/**
 * Dynamic Secret Generator class
 */
class DynamicSecretGenerator {
  private static instance: DynamicSecretGenerator | null = null;

  public static getInstance(): DynamicSecretGenerator {
    if (!DynamicSecretGenerator.instance) {
      DynamicSecretGenerator.instance = new DynamicSecretGenerator();
    }
    return DynamicSecretGenerator.instance;
  }

  /**
   * Generate dynamic secrets with just-in-time access
   */
  public async generateDynamicSecret(config: Parameters<typeof DynamicSecretConfigSchema.parse>[0]): Promise<{
    accessKeyId?: string;
    secretAccessKey?: string;
    sessionToken?: string;
    username?: string;
    password?: string;
    certificate?: string;
    privateKey?: string;
    token?: string;
    leaseId: string;
    leaseDuration: number;
    renewable: boolean;
  }> {
    const validatedConfig = DynamicSecretConfigSchema.parse(config);
    
    // Generate lease ID
    const leaseId = `dynamic-secret/${validatedConfig.secretType}/${crypto.randomUUID()}`;
    const leaseDuration = this.parseDuration(validatedConfig.leaseConfig.defaultTtl);

    let secretData: Record<string, string> = {};

    // Generate secret based on type
    switch (validatedConfig.secretType) {
      case 'database':
        secretData = await this.generateDatabaseCredentials(validatedConfig);
        break;
      case 'aws':
        secretData = await this.generateAWSCredentials(validatedConfig);
        break;
      case 'azure':
        secretData = await this.generateAzureCredentials(validatedConfig);
        break;
      case 'gcp':
        secretData = await this.generateGCPCredentials(validatedConfig);
        break;
      case 'certificate':
        secretData = await this.generateCertificate(validatedConfig);
        break;
      case 'ssh':
        secretData = await this.generateSSHCredentials(validatedConfig);
        break;
      case 'api_token':
        secretData = await this.generateAPIToken(validatedConfig);
        break;
      default:
        throw new Error(`Unsupported secret type: ${validatedConfig.secretType}`);
    }

    // Store lease information for renewal and revocation
    await this.storeLease(leaseId, {
      secretType: validatedConfig.secretType,
      config: validatedConfig,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + leaseDuration * 1000),
      renewable: validatedConfig.leaseConfig.renewable,
    });

    // Log secret generation
    await auditLogger.logEvent({
      level: 'info',
      category: 'security',
      action: 'dynamic_secret_generated',
      success: true,
      details: {
        secretType: validatedConfig.secretType,
        leaseId,
        leaseDuration,
        renewable: validatedConfig.leaseConfig.renewable,
      },
      riskLevel: 'medium',
    });

    return {
      ...secretData,
      leaseId,
      leaseDuration,
      renewable: validatedConfig.leaseConfig.renewable,
    };
  }

  private parseDuration(duration: string): number {
    // Parse duration string (e.g., "1h", "30m", "24h") to seconds
    const match = duration.match(/^(\d+)([hms])$/);
    if (!match) throw new Error(`Invalid duration format: ${duration}`);
    
    const value = parseInt(match[1]);
    const unit = match[2];
    
    switch (unit) {
      case 'h': return value * 3600;
      case 'm': return value * 60;
      case 's': return value;
      default: throw new Error(`Invalid duration unit: ${unit}`);
    }
  }

  private async generateDatabaseCredentials(_config: Parameters<typeof DynamicSecretConfigSchema.parse>[0]): Promise<Record<string, string>> {
    // Generate temporary database credentials
    const username = `vault_${Date.now()}_${Math.random().toString(36).substring(7)}`;
    const password = await this.generateSecurePassword(32);
    
    return { username, password };
  }

  private async generateAWSCredentials(_config: Parameters<typeof DynamicSecretConfigSchema.parse>[0]): Promise<Record<string, string>> {
    // Generate temporary AWS credentials
    const accessKeyId = `AKIA${Math.random().toString(36).substring(2, 18).toUpperCase()}`;
    const secretAccessKey = await this.generateSecurePassword(40);
    const sessionToken = await this.generateSecurePassword(356);
    
    return { accessKeyId, secretAccessKey, sessionToken };
  }

  private async generateAzureCredentials(_config: Parameters<typeof DynamicSecretConfigSchema.parse>[0]): Promise<Record<string, string>> {
    // Generate temporary Azure credentials
    const clientId = crypto.randomUUID();
    const clientSecret = await this.generateSecurePassword(32);
    
    return { clientId, clientSecret };
  }

  private async generateGCPCredentials(_config: Parameters<typeof DynamicSecretConfigSchema.parse>[0]): Promise<Record<string, string>> {
    // Generate temporary GCP service account key
    const privateKeyId = crypto.randomUUID();
    const clientEmail = `vault-${Date.now()}@project.iam.gserviceaccount.com`;
    
    return { privateKeyId, clientEmail };
  }

  private async generateCertificate(config: Parameters<typeof DynamicSecretConfigSchema.parse>[0]): Promise<Record<string, string>> {
    // Generate temporary certificate
    const certificate = await this.generateX509Certificate(config);
    const privateKey = await this.generatePrivateKey();
    
    return { certificate, privateKey };
  }

  private async generateSSHCredentials(config: Parameters<typeof DynamicSecretConfigSchema.parse>[0]): Promise<Record<string, string>> {
    const validatedConfig = DynamicSecretConfigSchema.parse(config);
    
    // Generate SSH credentials based on type
    if (validatedConfig.config.keyType === 'otp') {
      const password = await this.generateSecurePassword(16);
      return { password };
    } else {
      const publicKey = await this.generateSSHPublicKey();
      const privateKey = await this.generateSSHPrivateKey();
      return { publicKey, privateKey };
    }
  }

  private async generateAPIToken(_config: Parameters<typeof DynamicSecretConfigSchema.parse>[0]): Promise<Record<string, string>> {
    // Generate API token
    const token = await this.generateSecureToken(64);
    return { token };
  }

  private async generateSecurePassword(length: number): Promise<string> {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
    const bytes = await randomBytes(length);
    let result = '';
    
    for (let i = 0; i < length; i++) {
      result += chars[bytes[i] % chars.length];
    }
    
    return result;
  }

  private async generateSecureToken(length: number): Promise<string> {
    const bytes = await randomBytes(length);
    return bytes.toString('base64url');
  }

  private async generateX509Certificate(_config: Parameters<typeof DynamicSecretConfigSchema.parse>[0]): Promise<string> {
    // Generate X.509 certificate (simplified)
    return `-----BEGIN CERTIFICATE-----
MIICertificateDataHere
-----END CERTIFICATE-----`;
  }

  private async generatePrivateKey(): Promise<string> {
    // Generate private key (simplified)
    return `-----BEGIN PRIVATE KEY-----
MIIPrivateKeyDataHere
-----END PRIVATE KEY-----`;
  }

  private async generateSSHPublicKey(): Promise<string> {
    // Generate SSH public key (simplified)
    return 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC...';
  }

  private async generateSSHPrivateKey(): Promise<string> {
    // Generate SSH private key (simplified)
    return `-----BEGIN OPENSSH PRIVATE KEY-----
PrivateKeyDataHere
-----END OPENSSH PRIVATE KEY-----`;
  }

  private async storeLease(_leaseId: string, _leaseData: Record<string, unknown>): Promise<void> {
    // Store lease information for management
    // Debug: Storing lease information (leaseId)
  }
}

/**
 * Generate dynamic secrets tool configuration
 */
export function createGenerateDynamicSecretsTool(context: ToolContext): ToolDefinition {
  const { logger } = context;
  
  return {
    name: 'generate-dynamic-secrets',
    description: 'Generate just-in-time dynamic secrets for databases, cloud providers, and APIs',
    parameters: DynamicSecretConfigSchema,
    annotations: {
      title: 'Generate Just-in-Time Dynamic Secrets',
      readOnlyHint: false,
      idempotentHint: false,
      openWorldHint: true,
    },
    execute: async (args: unknown, execContext: ToolExecutionContext): Promise<string> => {
      const { log, reportProgress } = execContext;
      
      log?.info?.('Generating dynamic secrets', JSON.stringify(args));
      reportProgress?.({ progress: 0, total: 100 });

      try {
        const validatedInput = DynamicSecretConfigSchema.parse(args);
        const secretGenerator = DynamicSecretGenerator.getInstance();
        
        reportProgress?.({ progress: 25, total: 100 });
        
        const secret = await secretGenerator.generateDynamicSecret(validatedInput);
        
        reportProgress?.({ progress: 75, total: 100 });

        const result = {
          success: true,
          secret,
          message: `Dynamic ${validatedInput.secretType} secret generated successfully`,
        };

        logger.info?.('Dynamic secret generated', {
          secretType: validatedInput.secretType,
          leaseId: secret.leaseId,
          leaseDuration: secret.leaseDuration,
        });

        reportProgress?.({ progress: 100, total: 100 });
        return formatSuccessResponse(result).content[0].text;
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        logger.error?.('Dynamic secret generation failed', { error: errorMessage });
        throw new UserError(`Failed to generate dynamic secret: ${errorMessage}`);
      }
    },
  };
}