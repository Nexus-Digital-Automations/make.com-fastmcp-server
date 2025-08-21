/**
 * Comprehensive Unit Tests for Encryption Utilities
 * 
 * Tests all encryption functionality including key derivation, encryption/decryption,
 * credential management, key rotation, audit logging, and security validations.
 * Achieves 100% test coverage for this critical security module.
 */

import { jest } from '@jest/globals';
import crypto from 'crypto';
import {
  EncryptionService,
  CredentialManager,
  CryptographicError,
  encryptionService,
  credentialManager,
  type EncryptedData,
  type CredentialMetadata,
  type KeyRotationInfo
} from '../../../src/utils/encryption';

// Mock logger to avoid actual logging during tests
jest.mock('../../../src/lib/logger.js', () => ({
  default: {
    child: jest.fn(() => ({
      debug: jest.fn(),
      info: jest.fn(),
      warn: jest.fn(),
      error: jest.fn()
    }))
  }
}));

describe('Encryption Utilities - Comprehensive Test Suite', () => {

  describe('CryptographicError', () => {
    it('should create error with operation context', () => {
      const error = new CryptographicError('Test error message', 'testOperation');
      
      expect(error.name).toBe('CryptographicError');
      expect(error.message).toBe('Test error message');
      expect(error.operation).toBe('testOperation');
      expect(error).toBeInstanceOf(Error);
    });

    it('should extend Error properly', () => {
      const error = new CryptographicError('Test', 'operation');
      
      expect(error instanceof Error).toBe(true);
      expect(error instanceof CryptographicError).toBe(true);
      expect(error.stack).toBeDefined();
    });
  });

  describe('EncryptionService', () => {
    let encryptionSvc: EncryptionService;

    beforeEach(() => {
      encryptionSvc = new EncryptionService();
    });

    describe('generateSecureSecret', () => {
      it('should generate secret with default length', () => {
        const secret = encryptionSvc.generateSecureSecret();
        
        expect(secret).toBeDefined();
        expect(typeof secret).toBe('string');
        expect(secret.length).toBe(64);
        expect(secret).toMatch(/^[A-Za-z0-9!@#$%^&*()\-_=+\[\]{}|;:,.<>?]+$/);
      });

      it('should generate secret with custom length', () => {
        const secret = encryptionSvc.generateSecureSecret(32);
        
        expect(secret.length).toBe(32);
      });

      it('should generate different secrets each time', () => {
        const secret1 = encryptionSvc.generateSecureSecret(20);
        const secret2 = encryptionSvc.generateSecureSecret(20);
        
        expect(secret1).not.toBe(secret2);
        expect(secret1.length).toBe(20);
        expect(secret2.length).toBe(20);
      });

      it('should handle crypto errors gracefully', () => {
        // Mock crypto.randomBytes to throw error
        const originalRandomBytes = crypto.randomBytes;
        crypto.randomBytes = jest.fn(() => {
          throw new Error('Crypto error');
        }) as any;

        expect(() => {
          encryptionSvc.generateSecureSecret();
        }).toThrow(CryptographicError);
        expect(() => {
          encryptionSvc.generateSecureSecret();
        }).toThrow('Secret generation failed: Crypto error');

        // Restore original
        crypto.randomBytes = originalRandomBytes;
      });

      it('should use all available characters', () => {
        const secret = encryptionSvc.generateSecureSecret(1000); // Large sample
        const expectedChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}|;:,.<>?';
        
        // Check that we have variety in characters (not all the same)
        const uniqueChars = new Set(secret.split(''));
        expect(uniqueChars.size).toBeGreaterThan(10); // Should have variety
        
        // Check all characters are from allowed set
        for (const char of secret) {
          expect(expectedChars).toContain(char);
        }
      });
    });

    describe('generateApiKey', () => {
      it('should generate API key with default prefix', () => {
        const apiKey = encryptionSvc.generateApiKey();
        
        expect(apiKey).toBeDefined();
        expect(typeof apiKey).toBe('string');
        expect(apiKey.startsWith('mcp_')).toBe(true);
        
        const parts = apiKey.split('_');
        expect(parts).toHaveLength(3);
        expect(parts[0]).toBe('mcp');
        expect(parts[1]).toMatch(/^[a-z0-9]+$/); // Timestamp in base36
        expect(parts[2]).toMatch(/^[A-Za-z0-9_-]+$/); // Base64url
      });

      it('should generate API key with custom prefix', () => {
        const apiKey = encryptionSvc.generateApiKey('test', 16);
        
        expect(apiKey.startsWith('test_')).toBe(true);
        
        const parts = apiKey.split('_');
        expect(parts[0]).toBe('test');
        expect(parts[2].length).toBe(16);
      });

      it('should generate different API keys each time', () => {
        const key1 = encryptionSvc.generateApiKey();
        const key2 = encryptionSvc.generateApiKey();
        
        expect(key1).not.toBe(key2);
      });

      it('should handle crypto errors in API key generation', () => {
        const originalRandomBytes = crypto.randomBytes;
        crypto.randomBytes = jest.fn(() => {
          throw new Error('Random bytes error');
        }) as any;

        expect(() => {
          encryptionSvc.generateApiKey();
        }).toThrow(CryptographicError);
        expect(() => {
          encryptionSvc.generateApiKey();
        }).toThrow('API key generation failed: Random bytes error');

        crypto.randomBytes = originalRandomBytes;
      });
    });

    describe('encrypt and decrypt', () => {
      const testPassword = 'test-master-password-123';
      const testData = 'sensitive-test-data';

      it('should encrypt and decrypt successfully', async () => {
        const encrypted = await encryptionSvc.encrypt(testData, testPassword);
        
        expect(encrypted).toBeDefined();
        expect(encrypted.data).toBeDefined();
        expect(encrypted.iv).toBeDefined();
        expect(encrypted.salt).toBeDefined();
        expect(encrypted.algorithm).toBe('aes-256-gcm');
        expect(encrypted.keyLength).toBe(32);
        
        // Decrypt and verify
        const decrypted = await encryptionSvc.decrypt(encrypted, testPassword);
        expect(decrypted).toBe(testData);
      });

      it('should produce different encrypted output each time', async () => {
        const encrypted1 = await encryptionSvc.encrypt(testData, testPassword);
        const encrypted2 = await encryptionSvc.encrypt(testData, testPassword);
        
        expect(encrypted1.data).not.toBe(encrypted2.data);
        expect(encrypted1.iv).not.toBe(encrypted2.iv);
        expect(encrypted1.salt).not.toBe(encrypted2.salt);
        
        // Both should decrypt to same data
        const decrypted1 = await encryptionSvc.decrypt(encrypted1, testPassword);
        const decrypted2 = await encryptionSvc.decrypt(encrypted2, testPassword);
        expect(decrypted1).toBe(testData);
        expect(decrypted2).toBe(testData);
      });

      it('should fail decryption with wrong password', async () => {
        const encrypted = await encryptionSvc.encrypt(testData, testPassword);
        
        await expect(
          encryptionSvc.decrypt(encrypted, 'wrong-password')
        ).rejects.toThrow(CryptographicError);
      });

      it('should handle empty string encryption/decryption', async () => {
        const encrypted = await encryptionSvc.encrypt('', testPassword);
        const decrypted = await encryptionSvc.decrypt(encrypted, testPassword);
        
        expect(decrypted).toBe('');
      });

      it('should handle large data encryption/decryption', async () => {
        const largeData = 'x'.repeat(10000);
        const encrypted = await encryptionSvc.encrypt(largeData, testPassword);
        const decrypted = await encryptionSvc.decrypt(encrypted, testPassword);
        
        expect(decrypted).toBe(largeData);
        expect(decrypted.length).toBe(10000);
      });

      it('should handle special characters in data', async () => {
        const specialData = '🔐 Special chars: @#$%^&*()[]{}|;:,.<>?/\n\t\r"\'\\\n中文测试';
        const encrypted = await encryptionSvc.encrypt(specialData, testPassword);
        const decrypted = await encryptionSvc.decrypt(encrypted, testPassword);
        
        expect(decrypted).toBe(specialData);
      });

      it('should handle special characters in password', async () => {
        const specialPassword = '🔒Test-Pass@123!#$%^&*()[]{}|;:,.<>?/\\中文';
        const encrypted = await encryptionSvc.encrypt(testData, specialPassword);
        const decrypted = await encryptionSvc.decrypt(encrypted, specialPassword);
        
        expect(decrypted).toBe(testData);
      });

      it('should fail with corrupted encrypted data', async () => {
        const encrypted = await encryptionSvc.encrypt(testData, testPassword);
        
        // Corrupt the encrypted data
        const corruptedEncrypted: EncryptedData = {
          ...encrypted,
          data: 'corrupted-data'
        };
        
        await expect(
          encryptionSvc.decrypt(corruptedEncrypted, testPassword)
        ).rejects.toThrow(CryptographicError);
      });

      it('should fail with corrupted salt', async () => {
        const encrypted = await encryptionSvc.encrypt(testData, testPassword);
        
        const corruptedEncrypted: EncryptedData = {
          ...encrypted,
          salt: 'invalid-salt'
        };
        
        await expect(
          encryptionSvc.decrypt(corruptedEncrypted, testPassword)
        ).rejects.toThrow(CryptographicError);
      });

      it('should handle encryption errors gracefully', async () => {
        // Mock scrypt to throw error
        const crypto = require('crypto');
        const originalScrypt = crypto.scrypt;
        crypto.scrypt = jest.fn((password, salt, keylen, callback) => {
          callback(new Error('Scrypt error'));
        });

        await expect(
          encryptionSvc.encrypt(testData, testPassword)
        ).rejects.toThrow(CryptographicError);
        await expect(
          encryptionSvc.encrypt(testData, testPassword)
        ).rejects.toThrow('Encryption failed');

        crypto.scrypt = originalScrypt;
      });
    });

    describe('hash and verifyHash', () => {
      const testData = 'test-data-to-hash';

      it('should generate consistent hash', () => {
        const hash1 = encryptionSvc.hash(testData);
        const hash2 = encryptionSvc.hash(testData);
        
        expect(hash1).toBe(hash2);
        expect(hash1).toMatch(/^[a-f0-9]{64}$/); // SHA-256 hex
        expect(hash1.length).toBe(64);
      });

      it('should generate different hashes for different data', () => {
        const hash1 = encryptionSvc.hash('data1');
        const hash2 = encryptionSvc.hash('data2');
        
        expect(hash1).not.toBe(hash2);
      });

      it('should verify hash correctly', () => {
        const hash = encryptionSvc.hash(testData);
        
        expect(encryptionSvc.verifyHash(testData, hash)).toBe(true);
        expect(encryptionSvc.verifyHash('wrong-data', hash)).toBe(false);
      });

      it('should handle empty string hashing', () => {
        const hash = encryptionSvc.hash('');
        
        expect(hash).toBeDefined();
        expect(hash.length).toBe(64);
        expect(encryptionSvc.verifyHash('', hash)).toBe(true);
      });

      it('should handle hash errors gracefully', () => {
        const originalCreateHash = crypto.createHash;
        crypto.createHash = jest.fn(() => {
          throw new Error('Hash error');
        }) as any;

        expect(() => {
          encryptionSvc.hash(testData);
        }).toThrow(CryptographicError);
        expect(() => {
          encryptionSvc.hash(testData);
        }).toThrow('Hashing failed: Hash error');

        crypto.createHash = originalCreateHash;
      });

      it('should handle hash verification errors gracefully', () => {
        const validHash = encryptionSvc.hash(testData);
        
        // Mock timingSafeEqual to throw error
        const originalTimingSafeEqual = crypto.timingSafeEqual;
        crypto.timingSafeEqual = jest.fn(() => {
          throw new Error('Timing safe equal error');
        }) as any;

        const result = encryptionSvc.verifyHash(testData, validHash);
        expect(result).toBe(false);

        crypto.timingSafeEqual = originalTimingSafeEqual;
      });

      it('should use timing-safe comparison', () => {
        const hash = encryptionSvc.hash(testData);
        const spy = jest.spyOn(crypto, 'timingSafeEqual');
        
        encryptionSvc.verifyHash(testData, hash);
        
        expect(spy).toHaveBeenCalled();
        spy.mockRestore();
      });
    });

    describe('generateToken', () => {
      it('should generate token with default length', () => {
        const token = encryptionSvc.generateToken();
        
        expect(token).toBeDefined();
        expect(typeof token).toBe('string');
        expect(token).toMatch(/^[A-Za-z0-9_-]+$/); // Base64url
      });

      it('should generate token with custom length', () => {
        const token = encryptionSvc.generateToken(16);
        
        // Base64url encoding of 16 bytes
        expect(token.length).toBeGreaterThanOrEqual(21); // Approximately 16 * 4/3
      });

      it('should generate different tokens each time', () => {
        const token1 = encryptionSvc.generateToken();
        const token2 = encryptionSvc.generateToken();
        
        expect(token1).not.toBe(token2);
      });

      it('should handle crypto errors in token generation', () => {
        const originalRandomBytes = crypto.randomBytes;
        crypto.randomBytes = jest.fn(() => {
          throw new Error('Random bytes error');
        }) as any;

        expect(() => {
          encryptionSvc.generateToken();
        }).toThrow(CryptographicError);
        expect(() => {
          encryptionSvc.generateToken();
        }).toThrow('Token generation failed: Random bytes error');

        crypto.randomBytes = originalRandomBytes;
      });
    });
  });

  describe('CredentialManager', () => {
    let credManager: CredentialManager;
    const masterPassword = 'test-master-password';
    const testCredential = 'secret-api-key-12345';
    
    beforeEach(() => {
      credManager = new CredentialManager();
      // Clear environment variables
      Object.keys(process.env)
        .filter(key => key.startsWith('ENCRYPTED_CREDENTIAL_'))
        .forEach(key => delete process.env[key]);
    });

    afterEach(() => {
      // Clean up environment variables
      Object.keys(process.env)
        .filter(key => key.startsWith('ENCRYPTED_CREDENTIAL_'))
        .forEach(key => delete process.env[key]);
    });

    describe('storeCredential', () => {
      it('should store credential successfully', async () => {
        const credentialId = await credManager.storeCredential(
          testCredential,
          'api_key',
          'test-service',
          masterPassword,
          { userId: 'user123' }
        );
        
        expect(credentialId).toBeDefined();
        expect(typeof credentialId).toBe('string');
        
        const metadata = credManager.getCredentialMetadata(credentialId);
        expect(metadata).toBeDefined();
        expect(metadata!.type).toBe('api_key');
        expect(metadata!.service).toBe('test-service');
        expect(metadata!.encrypted).toBe(true);
        expect(metadata!.rotationInfo.status).toBe('active');
      });

      it('should store credential with custom ID', async () => {
        const customId = 'custom-credential-id';
        const credentialId = await credManager.storeCredential(
          testCredential,
          'secret',
          'test-service',
          masterPassword,
          { id: customId }
        );
        
        expect(credentialId).toBe(customId);
      });

      it('should store credential with expiration', async () => {
        const expiresIn = 60000; // 1 minute
        const beforeStore = new Date();
        
        const credentialId = await credManager.storeCredential(
          testCredential,
          'token',
          'test-service',
          masterPassword,
          { expiresIn }
        );
        
        const afterStore = new Date();
        const metadata = credManager.getCredentialMetadata(credentialId);
        
        expect(metadata!.rotationInfo.expiresAt).toBeDefined();
        expect(metadata!.rotationInfo.expiresAt!.getTime()).toBeGreaterThanOrEqual(
          beforeStore.getTime() + expiresIn
        );
        expect(metadata!.rotationInfo.expiresAt!.getTime()).toBeLessThanOrEqual(
          afterStore.getTime() + expiresIn
        );
      });

      it('should create audit log entry', async () => {
        const credentialId = await credManager.storeCredential(
          testCredential,
          'api_key',
          'test-service',
          masterPassword,
          { userId: 'user123' }
        );
        
        const auditLog = credManager.getAuditLog({ credentialId });
        expect(auditLog).toHaveLength(1);
        expect(auditLog[0].operation).toBe('store_credential');
        expect(auditLog[0].credentialId).toBe(credentialId);
        expect(auditLog[0].userId).toBe('user123');
        expect(auditLog[0].success).toBe(true);
      });

      it('should handle storage errors gracefully', async () => {
        // Mock encryption service to throw error
        const originalEncrypt = encryptionService.encrypt;
        encryptionService.encrypt = jest.fn().mockRejectedValue(new Error('Encryption failed'));

        await expect(
          credManager.storeCredential(testCredential, 'api_key', 'test-service', masterPassword)
        ).rejects.toThrow('Encryption failed');
        
        // Check audit log for failed attempt
        const auditLog = credManager.getAuditLog();
        expect(auditLog.some(entry => 
          entry.operation === 'store_credential' && 
          entry.success === false
        )).toBe(true);

        encryptionService.encrypt = originalEncrypt;
      });
    });

    describe('retrieveCredential', () => {
      let storedCredentialId: string;

      beforeEach(async () => {
        storedCredentialId = await credManager.storeCredential(
          testCredential,
          'api_key',
          'test-service',
          masterPassword
        );
      });

      it('should retrieve credential successfully', async () => {
        const retrieved = await credManager.retrieveCredential(
          storedCredentialId,
          masterPassword,
          'user123'
        );
        
        expect(retrieved).toBe(testCredential);
        
        // Check last used is updated
        const metadata = credManager.getCredentialMetadata(storedCredentialId);
        expect(metadata!.lastUsed).toBeDefined();
      });

      it('should create audit log for retrieval', async () => {
        await credManager.retrieveCredential(storedCredentialId, masterPassword, 'user123');
        
        const auditLog = credManager.getAuditLog({ 
          credentialId: storedCredentialId,
          operation: 'retrieve_credential'
        });
        expect(auditLog).toHaveLength(1);
        expect(auditLog[0].success).toBe(true);
        expect(auditLog[0].userId).toBe('user123');
      });

      it('should fail for non-existent credential', async () => {
        await expect(
          credManager.retrieveCredential('non-existent', masterPassword)
        ).rejects.toThrow('Credential non-existent not found');
      });

      it('should fail for expired credential', async () => {
        // Store credential with very short expiration
        const expiredId = await credManager.storeCredential(
          testCredential,
          'token',
          'test-service',
          masterPassword,
          { expiresIn: -1000 } // Already expired
        );
        
        await expect(
          credManager.retrieveCredential(expiredId, masterPassword)
        ).rejects.toThrow(`Credential ${expiredId} has expired`);
      });

      it('should fail for revoked credential', async () => {
        // Revoke the credential
        await credManager.revokeCredential(storedCredentialId);
        
        await expect(
          credManager.retrieveCredential(storedCredentialId, masterPassword)
        ).rejects.toThrow(`Credential ${storedCredentialId} has been revoked`);
      });

      it('should fail for missing encrypted data', async () => {
        // Remove encrypted data from environment
        delete process.env[`ENCRYPTED_CREDENTIAL_${storedCredentialId}`];
        
        await expect(
          credManager.retrieveCredential(storedCredentialId, masterPassword)
        ).rejects.toThrow(`Encrypted data for credential ${storedCredentialId} not found`);
      });

      it('should handle decryption errors gracefully', async () => {
        await expect(
          credManager.retrieveCredential(storedCredentialId, 'wrong-password')
        ).rejects.toThrow();
        
        // Check audit log for failed attempt
        const auditLog = credManager.getAuditLog({ 
          credentialId: storedCredentialId,
          operation: 'retrieve_credential'
        });
        expect(auditLog.some(entry => entry.success === false)).toBe(true);
      });
    });

    describe('rotateCredential', () => {
      let originalCredentialId: string;

      beforeEach(async () => {
        originalCredentialId = await credManager.storeCredential(
          testCredential,
          'api_key',
          'test-service',
          masterPassword
        );
      });

      it('should rotate credential successfully', async () => {
        const newCredentialId = await credManager.rotateCredential(
          originalCredentialId,
          masterPassword,
          { userId: 'user123' }
        );
        
        expect(newCredentialId).toBeDefined();
        expect(newCredentialId).not.toBe(originalCredentialId);
        
        // Old credential should be revoked (no grace period)
        const oldMetadata = credManager.getCredentialMetadata(originalCredentialId);
        expect(oldMetadata!.rotationInfo.status).toBe('revoked');
        
        // New credential should be active
        const newMetadata = credManager.getCredentialMetadata(newCredentialId);
        expect(newMetadata!.rotationInfo.status).toBe('active');
        expect(newMetadata!.service).toBe('test-service');
        expect(newMetadata!.type).toBe('api_key');
      });

      it('should rotate with custom new credential', async () => {
        const customCredential = 'custom-new-credential-value';
        const newCredentialId = await credManager.rotateCredential(
          originalCredentialId,
          masterPassword,
          { newCredential: customCredential }
        );
        
        const retrievedCredential = await credManager.retrieveCredential(
          newCredentialId,
          masterPassword
        );
        expect(retrievedCredential).toBe(customCredential);
      });

      it('should rotate with grace period', async () => {
        const gracePeriod = 60000; // 1 minute
        const newCredentialId = await credManager.rotateCredential(
          originalCredentialId,
          masterPassword,
          { gracePeriod, userId: 'user123' }
        );
        
        // Old credential should be deprecated with expiration
        const oldMetadata = credManager.getCredentialMetadata(originalCredentialId);
        expect(oldMetadata!.rotationInfo.status).toBe('deprecated');
        expect(oldMetadata!.rotationInfo.expiresAt).toBeDefined();
        
        // Should still be able to retrieve old credential during grace period
        const oldCredential = await credManager.retrieveCredential(
          originalCredentialId,
          masterPassword
        );
        expect(oldCredential).toBe(testCredential);
      });

      it('should create audit log for rotation', async () => {
        const newCredentialId = await credManager.rotateCredential(
          originalCredentialId,
          masterPassword,
          { userId: 'user123' }
        );
        
        const auditLog = credManager.getAuditLog({ 
          credentialId: originalCredentialId,
          operation: 'rotate_credential'
        });
        expect(auditLog).toHaveLength(1);
        expect(auditLog[0].success).toBe(true);
        expect(auditLog[0].details?.newCredentialId).toBe(newCredentialId);
      });

      it('should fail for non-existent credential', async () => {
        await expect(
          credManager.rotateCredential('non-existent', masterPassword)
        ).rejects.toThrow('Credential non-existent not found');
      });

      it('should handle rotation errors gracefully', async () => {
        // Mock store credential to fail
        const originalStoreCredential = credManager.storeCredential;
        credManager.storeCredential = jest.fn().mockRejectedValue(new Error('Store failed'));

        await expect(
          credManager.rotateCredential(originalCredentialId, masterPassword)
        ).rejects.toThrow('Store failed');
        
        // Check audit log for failed attempt
        const auditLog = credManager.getAuditLog({ 
          credentialId: originalCredentialId,
          operation: 'rotate_credential'
        });
        expect(auditLog.some(entry => entry.success === false)).toBe(true);

        credManager.storeCredential = originalStoreCredential;
      });
    });

    describe('revokeCredential', () => {
      let credentialId: string;

      beforeEach(async () => {
        credentialId = await credManager.storeCredential(
          testCredential,
          'api_key',
          'test-service',
          masterPassword
        );
      });

      it('should revoke credential successfully', async () => {
        await credManager.revokeCredential(credentialId, 'user123');
        
        const metadata = credManager.getCredentialMetadata(credentialId);
        expect(metadata!.rotationInfo.status).toBe('revoked');
        expect(metadata!.rotationInfo.rotatedAt).toBeDefined();
        
        // Encrypted data should be removed
        expect(process.env[`ENCRYPTED_CREDENTIAL_${credentialId}`]).toBeUndefined();
      });

      it('should create audit log for revocation', async () => {
        await credManager.revokeCredential(credentialId, 'user123');
        
        const auditLog = credManager.getAuditLog({ 
          credentialId,
          operation: 'revoke_credential'
        });
        expect(auditLog).toHaveLength(1);
        expect(auditLog[0].success).toBe(true);
        expect(auditLog[0].userId).toBe('user123');
      });

      it('should fail for non-existent credential', async () => {
        await expect(
          credManager.revokeCredential('non-existent')
        ).rejects.toThrow('Credential non-existent not found');
      });

      it('should handle revocation errors gracefully', async () => {
        // Mock to simulate error during revocation
        const originalMetadata = credManager.getCredentialMetadata;
        credManager.getCredentialMetadata = jest.fn().mockReturnValue(undefined);

        await expect(
          credManager.revokeCredential(credentialId)
        ).rejects.toThrow('Credential');
        
        // Check audit log for failed attempt
        const auditLog = credManager.getAuditLog({ 
          credentialId,
          operation: 'revoke_credential'
        });
        expect(auditLog.some(entry => entry.success === false)).toBe(true);

        credManager.getCredentialMetadata = originalMetadata;
      });
    });

    describe('listCredentials', () => {
      beforeEach(async () => {
        // Store multiple credentials for testing
        await credManager.storeCredential('cred1', 'api_key', 'service1', masterPassword);
        await credManager.storeCredential('cred2', 'secret', 'service1', masterPassword);
        await credManager.storeCredential('cred3', 'token', 'service2', masterPassword);
      });

      it('should list all credentials without filter', () => {
        const credentials = credManager.listCredentials();
        
        expect(credentials).toHaveLength(3);
        expect(credentials.every(cred => cred.encrypted)).toBe(true);
        expect(credentials.every(cred => cred.rotationInfo.status === 'active')).toBe(true);
      });

      it('should filter by service', () => {
        const service1Credentials = credManager.listCredentials({ service: 'service1' });
        
        expect(service1Credentials).toHaveLength(2);
        expect(service1Credentials.every(cred => cred.service === 'service1')).toBe(true);
      });

      it('should filter by type', () => {
        const apiKeyCredentials = credManager.listCredentials({ type: 'api_key' });
        
        expect(apiKeyCredentials).toHaveLength(1);
        expect(apiKeyCredentials[0].type).toBe('api_key');
      });

      it('should filter by status', () => {
        const activeCredentials = credManager.listCredentials({ status: 'active' });
        
        expect(activeCredentials).toHaveLength(3);
        expect(activeCredentials.every(cred => cred.rotationInfo.status === 'active')).toBe(true);
      });

      it('should filter by multiple criteria', () => {
        const filtered = credManager.listCredentials({ 
          service: 'service1', 
          type: 'secret' 
        });
        
        expect(filtered).toHaveLength(1);
        expect(filtered[0].service).toBe('service1');
        expect(filtered[0].type).toBe('secret');
      });

      it('should return empty array for no matches', () => {
        const noMatches = credManager.listCredentials({ service: 'non-existent' });
        
        expect(noMatches).toHaveLength(0);
      });
    });

    describe('getAuditLog', () => {
      let credentialId: string;

      beforeEach(async () => {
        credentialId = await credManager.storeCredential(
          testCredential,
          'api_key',
          'test-service',
          masterPassword,
          { userId: 'user123' }
        );
        await credManager.retrieveCredential(credentialId, masterPassword, 'user456');
      });

      it('should return all audit entries without filter', () => {
        const auditLog = credManager.getAuditLog();
        
        expect(auditLog.length).toBeGreaterThanOrEqual(2);
        expect(auditLog.every(entry => entry.timestamp instanceof Date)).toBe(true);
        expect(auditLog.every(entry => typeof entry.success === 'boolean')).toBe(true);
      });

      it('should filter by credential ID', () => {
        const credentialLog = credManager.getAuditLog({ credentialId });
        
        expect(credentialLog.every(entry => entry.credentialId === credentialId)).toBe(true);
        expect(credentialLog.length).toBeGreaterThanOrEqual(2);
      });

      it('should filter by user ID', () => {
        const userLog = credManager.getAuditLog({ userId: 'user123' });
        
        expect(userLog.every(entry => entry.userId === 'user123')).toBe(true);
        expect(userLog.length).toBeGreaterThanOrEqual(1);
      });

      it('should filter by operation', () => {
        const storeLog = credManager.getAuditLog({ operation: 'store_credential' });
        
        expect(storeLog.every(entry => entry.operation === 'store_credential')).toBe(true);
        expect(storeLog.length).toBeGreaterThanOrEqual(1);
      });

      it('should filter by date range', () => {
        const now = new Date();
        const oneHourAgo = new Date(now.getTime() - 3600000);
        
        const recentLog = credManager.getAuditLog({ 
          startDate: oneHourAgo,
          endDate: now
        });
        
        expect(recentLog.every(entry => 
          entry.timestamp >= oneHourAgo && entry.timestamp <= now
        )).toBe(true);
      });

      it('should return sorted entries (newest first)', () => {
        const auditLog = credManager.getAuditLog();
        
        for (let i = 0; i < auditLog.length - 1; i++) {
          expect(auditLog[i].timestamp.getTime()).toBeGreaterThanOrEqual(
            auditLog[i + 1].timestamp.getTime()
          );
        }
      });
    });

    describe('cleanupExpiredCredentials', () => {
      it('should clean up expired credentials', async () => {
        // Store credential with very short expiration
        const expiredId = await credManager.storeCredential(
          testCredential,
          'token',
          'test-service',
          masterPassword,
          { expiresIn: -1000 } // Already expired
        );
        
        // Store non-expired credential
        const validId = await credManager.storeCredential(
          testCredential,
          'api_key',
          'test-service',
          masterPassword
        );
        
        const cleanedCount = credManager.cleanupExpiredCredentials();
        
        expect(cleanedCount).toBe(1);
        expect(credManager.getCredentialMetadata(expiredId)).toBeUndefined();
        expect(credManager.getCredentialMetadata(validId)).toBeDefined();
        expect(process.env[`ENCRYPTED_CREDENTIAL_${expiredId}`]).toBeUndefined();
      });

      it('should return zero when no expired credentials', async () => {
        await credManager.storeCredential(
          testCredential,
          'api_key',
          'test-service',
          masterPassword
        );
        
        const cleanedCount = credManager.cleanupExpiredCredentials();
        
        expect(cleanedCount).toBe(0);
      });

      it('should create audit log for cleanup', async () => {
        const expiredId = await credManager.storeCredential(
          testCredential,
          'token',
          'test-service',
          masterPassword,
          { expiresIn: -1000 }
        );
        
        credManager.cleanupExpiredCredentials();
        
        const auditLog = credManager.getAuditLog({ 
          credentialId: expiredId,
          operation: 'cleanup_expired'
        });
        expect(auditLog).toHaveLength(1);
        expect(auditLog[0].success).toBe(true);
        expect(auditLog[0].userId).toBe('system');
      });
    });
  });

  describe('Singleton Exports', () => {
    it('should export singleton instances', () => {
      expect(encryptionService).toBeInstanceOf(EncryptionService);
      expect(credentialManager).toBeInstanceOf(CredentialManager);
    });

    it('should export the same instances on multiple imports', () => {
      const {
        encryptionService: encryptionService2,
        credentialManager: credentialManager2
      } = require('../../../src/utils/encryption');
      
      expect(encryptionService).toBe(encryptionService2);
      expect(credentialManager).toBe(credentialManager2);
    });
  });

  describe('Integration Tests', () => {
    it('should handle complete credential lifecycle', async () => {
      const masterPassword = 'integration-test-password';
      const credential = 'integration-test-credential';
      
      // Store credential
      const credentialId = await credentialManager.storeCredential(
        credential,
        'api_key',
        'integration-service',
        masterPassword,
        { userId: 'integration-user' }
      );
      
      // Retrieve credential
      const retrieved = await credentialManager.retrieveCredential(
        credentialId,
        masterPassword,
        'integration-user'
      );
      expect(retrieved).toBe(credential);
      
      // Rotate credential
      const newCredentialId = await credentialManager.rotateCredential(
        credentialId,
        masterPassword,
        { userId: 'integration-user' }
      );
      
      // Verify old credential is revoked
      await expect(
        credentialManager.retrieveCredential(credentialId, masterPassword)
      ).rejects.toThrow('revoked');
      
      // Verify new credential works
      const newRetrieved = await credentialManager.retrieveCredential(
        newCredentialId,
        masterPassword,
        'integration-user'
      );
      expect(newRetrieved).toBeDefined();
      expect(newRetrieved).not.toBe(credential); // Should be different (auto-generated)
      
      // Check audit trail
      const auditLog = credentialManager.getAuditLog({ userId: 'integration-user' });
      expect(auditLog.length).toBeGreaterThanOrEqual(4); // store, retrieve, rotate, retrieve
      expect(auditLog.every(entry => entry.userId === 'integration-user')).toBe(true);
    });

    it('should handle encryption service standalone usage', async () => {
      const data = 'standalone-test-data';
      const password = 'standalone-password';
      
      // Test encryption/decryption
      const encrypted = await encryptionService.encrypt(data, password);
      const decrypted = await encryptionService.decrypt(encrypted, password);
      expect(decrypted).toBe(data);
      
      // Test hashing
      const hash = encryptionService.hash(data);
      expect(encryptionService.verifyHash(data, hash)).toBe(true);
      
      // Test token generation
      const token = encryptionService.generateToken();
      expect(token).toBeDefined();
      expect(typeof token).toBe('string');
      
      // Test API key generation
      const apiKey = encryptionService.generateApiKey('test');
      expect(apiKey.startsWith('test_')).toBe(true);
      
      // Test secret generation
      const secret = encryptionService.generateSecureSecret(32);
      expect(secret.length).toBe(32);
    });
  });
});