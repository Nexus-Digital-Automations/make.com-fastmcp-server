/**
 * Encryption utilities for secure credential management
 * Provides encryption at rest, key derivation, and secure storage capabilities
 */

import * as crypto from 'crypto';
import { promisify } from 'util';
import logger from '../lib/logger.js';

const scrypt = promisify(crypto.scrypt);
const randomBytes = promisify(crypto.randomBytes);

export interface EncryptedData {
  data: string;
  iv: string;
  salt: string;
  algorithm: string;
  keyLength: number;
}

export interface KeyRotationInfo {
  keyId: string;
  createdAt: Date;
  rotatedAt?: Date;
  expiresAt?: Date;
  status: 'active' | 'rotating' | 'deprecated' | 'revoked';
}

export interface CredentialMetadata {
  id: string;
  type: 'api_key' | 'secret' | 'token' | 'certificate';
  service: string;
  createdAt: Date;
  lastUsed?: Date;
  rotationInfo: KeyRotationInfo;
  encrypted: boolean;
}

export class CryptographicError extends Error {
  constructor(message: string, public readonly operation: string) {
    super(message);
    this.name = 'CryptographicError';
  }
}

/**
 * Secure encryption service for credentials and sensitive data
 */
export class EncryptionService {
  private static readonly ALGORITHM = 'aes-256-gcm';
  private static readonly KEY_LENGTH = 32;
  private static readonly IV_LENGTH = 16;
  private static readonly TAG_LENGTH = 16;
  private static readonly SALT_LENGTH = 32;
  
  private componentLogger: ReturnType<typeof logger.child>;

  constructor() {
    this.componentLogger = logger.child({ component: 'EncryptionService' });
  }

  /**
   * Derive a key from a password using PBKDF2
   */
  private async deriveKey(password: string, salt: Buffer): Promise<Buffer> {
    try {
      const key = await scrypt(password, salt, EncryptionService.KEY_LENGTH) as Buffer;
      return key;
    } catch (error) {
      throw new CryptographicError(
        `Key derivation failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'deriveKey'
      );
    }
  }

  /**
   * Generate a cryptographically secure random password/secret
   */
  public generateSecureSecret(length: number = 64): string {
    try {
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}|;:,.<>?';
      const bytes = crypto.randomBytes(length);
      let result = '';
      
      for (let i = 0; i < length; i++) {
        result += chars[bytes[i] % chars.length];
      }
      
      return result;
    } catch (error) {
      throw new CryptographicError(
        `Secret generation failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'generateSecureSecret'
      );
    }
  }

  /**
   * Generate a secure API key with specific format
   */
  public generateApiKey(prefix: string = 'mcp', length: number = 32): string {
    try {
      const timestamp = Date.now().toString(36);
      const randomPart = crypto.randomBytes(length).toString('base64url').slice(0, length);
      return `${prefix}_${timestamp}_${randomPart}`;
    } catch (error) {
      throw new CryptographicError(
        `API key generation failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'generateApiKey'
      );
    }
  }

  /**
   * Encrypt sensitive data with AES-256-GCM
   */
  public async encrypt(plaintext: string, masterPassword: string): Promise<EncryptedData> {
    try {
      // Generate random salt and IV
      const salt = await randomBytes(EncryptionService.SALT_LENGTH);
      const iv = await randomBytes(EncryptionService.IV_LENGTH);
      
      // Derive key from master password
      const key = await this.deriveKey(masterPassword, salt);
      
      // Create cipher with IV
      const cipher = crypto.createCipheriv(EncryptionService.ALGORITHM, key, iv);
      
      // Encrypt data
      let encrypted = cipher.update(plaintext, 'utf8', 'base64');
      encrypted += cipher.final('base64');
      
      // Get authentication tag
      const tag = cipher.getAuthTag();
      
      // Combine encrypted data and tag
      const encryptedWithTag = encrypted + ':' + tag.toString('base64');
      
      this.componentLogger.debug('Data encrypted successfully', {
        algorithm: EncryptionService.ALGORITHM,
        keyLength: EncryptionService.KEY_LENGTH,
        dataLength: plaintext.length
      });

      return {
        data: encryptedWithTag,
        iv: iv.toString('base64'),
        salt: salt.toString('base64'),
        algorithm: EncryptionService.ALGORITHM,
        keyLength: EncryptionService.KEY_LENGTH
      };
    } catch (error) {
      this.componentLogger.error('Encryption failed', { error: error instanceof Error ? error.message : 'Unknown error' });
      throw new CryptographicError(
        `Encryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'encrypt'
      );
    }
  }

  /**
   * Decrypt data encrypted with encrypt method
   */
  public async decrypt(encryptedData: EncryptedData, masterPassword: string): Promise<string> {
    try {
      // Parse salt and IV
      const salt = Buffer.from(encryptedData.salt, 'base64');
      const iv = Buffer.from(encryptedData.iv, 'base64');
      
      // Derive key from master password
      const key = await this.deriveKey(masterPassword, salt);
      
      // Parse encrypted data and authentication tag
      const [encryptedText, tagB64] = encryptedData.data.split(':');
      const tag = Buffer.from(tagB64, 'base64');
      
      // Create decipher with IV
      const decipher = crypto.createDecipheriv(encryptedData.algorithm, key, iv) as crypto.DecipherGCM;
      decipher.setAuthTag(tag);
      
      // Decrypt data
      let decrypted = decipher.update(encryptedText, 'base64', 'utf8');
      decrypted += decipher.final('utf8');
      
      this.componentLogger.debug('Data decrypted successfully', {
        algorithm: encryptedData.algorithm,
        dataLength: decrypted.length
      });

      return decrypted;
    } catch (error) {
      this.componentLogger.error('Decryption failed', { error: error instanceof Error ? error.message : 'Unknown error' });
      throw new CryptographicError(
        `Decryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'decrypt'
      );
    }
  }

  /**
   * Hash data using SHA-256 (for integrity checks, not encryption)
   */
  public hash(data: string): string {
    try {
      return crypto.createHash('sha256').update(data).digest('hex');
    } catch (error) {
      throw new CryptographicError(
        `Hashing failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'hash'
      );
    }
  }

  /**
   * Verify data integrity using hash comparison
   */
  public verifyHash(data: string, expectedHash: string): boolean {
    try {
      const actualHash = this.hash(data);
      return crypto.timingSafeEqual(Buffer.from(actualHash), Buffer.from(expectedHash));
    } catch (error) {
      this.componentLogger.warn('Hash verification failed', { error: error instanceof Error ? error.message : 'Unknown error' });
      return false;
    }
  }

  /**
   * Generate a secure random token for temporary credentials
   */
  public generateToken(length: number = 32): string {
    try {
      return crypto.randomBytes(length).toString('base64url');
    } catch (error) {
      throw new CryptographicError(
        `Token generation failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'generateToken'
      );
    }
  }
}

/**
 * Credential management service with rotation and audit capabilities
 */
export class CredentialManager {
  private encryptionService: EncryptionService;
  private credentials: Map<string, CredentialMetadata> = new Map();
  private componentLogger: ReturnType<typeof logger.child>;
  private auditLog: Array<{
    timestamp: Date;
    operation: string;
    credentialId: string;
    userId?: string;
    success: boolean;
    details?: Record<string, unknown>;
  }> = [];

  constructor() {
    this.encryptionService = new EncryptionService();
    this.componentLogger = logger.child({ component: 'CredentialManager' });
  }

  /**
   * Store encrypted credential with metadata
   */
  public async storeCredential(
    credential: string,
    type: CredentialMetadata['type'],
    service: string,
    masterPassword: string,
    options: {
      id?: string;
      expiresIn?: number; // milliseconds
      userId?: string;
    } = {}
  ): Promise<string> {
    try {
      const credentialId = options.id || crypto.randomUUID();
      const now = new Date();
      
      // Encrypt the credential
      const encryptedData = await this.encryptionService.encrypt(credential, masterPassword);
      
      // Create metadata
      const metadata: CredentialMetadata = {
        id: credentialId,
        type,
        service,
        createdAt: now,
        rotationInfo: {
          keyId: crypto.randomUUID(),
          createdAt: now,
          expiresAt: options.expiresIn ? new Date(now.getTime() + options.expiresIn) : undefined,
          status: 'active'
        },
        encrypted: true
      };

      // Store metadata and encrypted data (in real implementation, use secure storage)
      this.credentials.set(credentialId, metadata);
      
      // Store encrypted data (placeholder - in production, use secure database/vault)
      process.env[`ENCRYPTED_CREDENTIAL_${credentialId}`] = JSON.stringify(encryptedData);
      
      // Audit log
      this.logAuditEvent('store_credential', credentialId, options.userId, true, {
        type,
        service,
        encrypted: true
      });

      this.componentLogger.info('Credential stored successfully', {
        credentialId,
        type,
        service,
        encrypted: true
      });

      return credentialId;
    } catch (error) {
      this.logAuditEvent('store_credential', 'unknown', options.userId, false, {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Retrieve and decrypt credential
   */
  public async retrieveCredential(
    credentialId: string,
    masterPassword: string,
    userId?: string
  ): Promise<string> {
    try {
      const metadata = this.credentials.get(credentialId);
      if (!metadata) {
        throw new Error(`Credential ${credentialId} not found`);
      }

      // Check if credential is expired
      if (metadata.rotationInfo.expiresAt && metadata.rotationInfo.expiresAt < new Date()) {
        throw new Error(`Credential ${credentialId} has expired`);
      }

      // Check credential status
      if (metadata.rotationInfo.status === 'revoked') {
        throw new Error(`Credential ${credentialId} has been revoked`);
      }

      // Get encrypted data
      const encryptedDataStr = process.env[`ENCRYPTED_CREDENTIAL_${credentialId}`];
      if (!encryptedDataStr) {
        throw new Error(`Encrypted data for credential ${credentialId} not found`);
      }

      const encryptedData = JSON.parse(encryptedDataStr) as EncryptedData;
      
      // Decrypt credential
      const credential = await this.encryptionService.decrypt(encryptedData, masterPassword);
      
      // Update last used timestamp
      metadata.lastUsed = new Date();
      
      // Audit log
      this.logAuditEvent('retrieve_credential', credentialId, userId, true, {
        type: metadata.type,
        service: metadata.service
      });

      this.componentLogger.debug('Credential retrieved successfully', {
        credentialId,
        type: metadata.type,
        service: metadata.service
      });

      return credential;
    } catch (error) {
      this.logAuditEvent('retrieve_credential', credentialId, userId, false, {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Rotate a credential (generate new value and mark old as deprecated)
   */
  public async rotateCredential(
    credentialId: string,
    masterPassword: string,
    options: {
      newCredential?: string;
      userId?: string;
      gracePeriod?: number; // milliseconds to keep old credential
    } = {}
  ): Promise<string> {
    try {
      const metadata = this.credentials.get(credentialId);
      if (!metadata) {
        throw new Error(`Credential ${credentialId} not found`);
      }

      // Generate new credential if not provided
      const newCredential = options.newCredential || 
        (metadata.type === 'api_key' ? this.encryptionService.generateApiKey() : 
         this.encryptionService.generateSecureSecret());

      // Mark current credential as rotating
      metadata.rotationInfo.status = 'rotating';
      metadata.rotationInfo.rotatedAt = new Date();

      // Store new credential with new ID
      const newCredentialId = await this.storeCredential(
        newCredential,
        metadata.type,
        metadata.service,
        masterPassword,
        {
          userId: options.userId,
          expiresIn: options.gracePeriod
        }
      );

      // Set grace period for old credential
      if (options.gracePeriod) {
        metadata.rotationInfo.expiresAt = new Date(Date.now() + options.gracePeriod);
        metadata.rotationInfo.status = 'deprecated';
      } else {
        metadata.rotationInfo.status = 'revoked';
      }

      // Audit log
      this.logAuditEvent('rotate_credential', credentialId, options.userId, true, {
        newCredentialId,
        gracePeriod: options.gracePeriod,
        service: metadata.service
      });

      this.componentLogger.info('Credential rotated successfully', {
        oldCredentialId: credentialId,
        newCredentialId,
        service: metadata.service,
        gracePeriod: options.gracePeriod
      });

      return newCredentialId;
    } catch (error) {
      this.logAuditEvent('rotate_credential', credentialId, options.userId, false, {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Revoke a credential immediately
   */
  public async revokeCredential(credentialId: string, userId?: string): Promise<void> {
    try {
      const metadata = this.credentials.get(credentialId);
      if (!metadata) {
        throw new Error(`Credential ${credentialId} not found`);
      }

      // Mark as revoked
      metadata.rotationInfo.status = 'revoked';
      metadata.rotationInfo.rotatedAt = new Date();

      // Remove encrypted data
      delete process.env[`ENCRYPTED_CREDENTIAL_${credentialId}`];

      // Audit log
      this.logAuditEvent('revoke_credential', credentialId, userId, true, {
        service: metadata.service,
        type: metadata.type
      });

      this.componentLogger.info('Credential revoked successfully', {
        credentialId,
        service: metadata.service,
        type: metadata.type
      });
    } catch (error) {
      this.logAuditEvent('revoke_credential', credentialId, userId, false, {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Get credential metadata without decrypting
   */
  public getCredentialMetadata(credentialId: string): CredentialMetadata | undefined {
    return this.credentials.get(credentialId);
  }

  /**
   * List all credentials with their metadata
   */
  public listCredentials(filter?: {
    service?: string;
    type?: CredentialMetadata['type'];
    status?: KeyRotationInfo['status'];
  }): CredentialMetadata[] {
    const credentials = Array.from(this.credentials.values());
    
    if (!filter) {
      return credentials;
    }

    return credentials.filter(cred => {
      if (filter.service && cred.service !== filter.service) return false;
      if (filter.type && cred.type !== filter.type) return false;
      if (filter.status && cred.rotationInfo.status !== filter.status) return false;
      return true;
    });
  }

  /**
   * Get audit log for credential operations
   */
  public getAuditLog(filter?: {
    credentialId?: string;
    userId?: string;
    operation?: string;
    startDate?: Date;
    endDate?: Date;
  }): Array<{
    timestamp: Date;
    operation: string;
    credentialId: string;
    userId?: string;
    success: boolean;
    details?: Record<string, unknown>;
  }> {
    let log = [...this.auditLog];

    if (filter) {
      log = log.filter(entry => {
        if (filter.credentialId && entry.credentialId !== filter.credentialId) return false;
        if (filter.userId && entry.userId !== filter.userId) return false;
        if (filter.operation && entry.operation !== filter.operation) return false;
        if (filter.startDate && entry.timestamp < filter.startDate) return false;
        if (filter.endDate && entry.timestamp > filter.endDate) return false;
        return true;
      });
    }

    return log.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
  }

  /**
   * Clean up expired credentials
   */
  public cleanupExpiredCredentials(): number {
    const now = new Date();
    let cleanedCount = 0;

    for (const [credentialId, metadata] of this.credentials.entries()) {
      if (metadata.rotationInfo.expiresAt && metadata.rotationInfo.expiresAt < now) {
        // Remove expired credential
        this.credentials.delete(credentialId);
        delete process.env[`ENCRYPTED_CREDENTIAL_${credentialId}`];
        cleanedCount++;

        this.logAuditEvent('cleanup_expired', credentialId, 'system', true, {
          expiredAt: metadata.rotationInfo.expiresAt,
          service: metadata.service
        });
      }
    }

    if (cleanedCount > 0) {
      this.componentLogger.info('Cleaned up expired credentials', { count: cleanedCount });
    }

    return cleanedCount;
  }

  /**
   * Log audit event
   */
  private logAuditEvent(
    operation: string,
    credentialId: string,
    userId: string | undefined,
    success: boolean,
    details?: Record<string, unknown>
  ): void {
    const auditEntry = {
      timestamp: new Date(),
      operation,
      credentialId,
      userId,
      success,
      details
    };

    this.auditLog.push(auditEntry);

    // Keep only last 10000 audit entries to prevent memory issues
    if (this.auditLog.length > 10000) {
      this.auditLog = this.auditLog.slice(-10000);
    }

    this.componentLogger.debug('Audit event logged', auditEntry);
  }
}

// Export singleton instances
export const encryptionService = new EncryptionService();
export const credentialManager = new CredentialManager();

export default {
  EncryptionService,
  CredentialManager,
  encryptionService,
  credentialManager,
  CryptographicError
};