/**
 * Basic Integration Test for Encryption Components
 * Tests core functionality without TypeScript compilation issues
 */

import { describe, test, expect, beforeEach, afterEach } from '@jest/globals';
import { EncryptionService, CredentialManager } from '../encryption.js';

describe('Encryption Integration Test', () => {
  let encryptionService: EncryptionService;
  let credentialManager: CredentialManager;

  beforeEach(() => {
    encryptionService = new EncryptionService();
    credentialManager = new CredentialManager();
  });

  test('should encrypt and decrypt data successfully', async () => {
    const plaintext = 'This is a test message for encryption';
    const masterPassword = 'test-master-password-123';

    // Encrypt data
    const encrypted = await encryptionService.encrypt(plaintext, masterPassword);
    
    expect(encrypted).toEqual(
      expect.objectContaining({
        data: expect.any(String),
        iv: expect.any(String),
        salt: expect.any(String),
        algorithm: 'aes-256-gcm',
        keyLength: 256
      })
    );

    // Decrypt data
    const decrypted = await encryptionService.decrypt(encrypted, masterPassword);
    expect(decrypted).toBe(plaintext);
  });

  test('should generate secure API keys', () => {
    const apiKey1 = encryptionService.generateApiKey('test', 32);
    const apiKey2 = encryptionService.generateApiKey('test', 32);
    
    expect(apiKey1).toMatch(/^test_[a-z0-9]+_[A-Za-z0-9_-]{32}$/);
    expect(apiKey2).toMatch(/^test_[a-z0-9]+_[A-Za-z0-9_-]{32}$/);
    expect(apiKey1).not.toBe(apiKey2);
  });

  test('should generate secure random secrets', () => {
    const secret1 = encryptionService.generateSecureSecret(64);
    const secret2 = encryptionService.generateSecureSecret(64);
    
    expect(secret1).toHaveLength(64);
    expect(secret2).toHaveLength(64);
    expect(secret1).not.toBe(secret2);
  });

  test('should hash data correctly', () => {
    const data = 'test data for hashing';
    const hash1 = encryptionService.hash(data);
    const hash2 = encryptionService.hash(data);
    const hash3 = encryptionService.hash(data + 'different');
    
    expect(hash1).toBe(hash2);
    expect(hash1).not.toBe(hash3);
    expect(hash1).toHaveLength(64); // SHA-256 hex string
  });

  test('should verify hashes correctly', () => {
    const data = 'test data for hash verification';
    const hash = encryptionService.hash(data);
    
    expect(encryptionService.verifyHash(data, hash)).toBe(true);
    expect(encryptionService.verifyHash(data + 'tampered', hash)).toBe(false);
  });

  test('should generate secure tokens', () => {
    const token1 = encryptionService.generateToken(32);
    const token2 = encryptionService.generateToken(32);
    
    expect(token1).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(token2).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(token1).not.toBe(token2);
  });

  test('should handle invalid decryption gracefully', async () => {
    const plaintext = 'test message';
    const masterPassword = 'correct-password';
    const wrongPassword = 'wrong-password';

    const encrypted = await encryptionService.encrypt(plaintext, masterPassword);
    
    await expect(
      encryptionService.decrypt(encrypted, wrongPassword)
    ).rejects.toThrow();
  });

  test('should handle corrupted data gracefully', async () => {
    const plaintext = 'test message';
    const masterPassword = 'test-password';

    const encrypted = await encryptionService.encrypt(plaintext, masterPassword);
    
    // Corrupt the data
    const corruptedData = {
      ...encrypted,
      data: encrypted.data.slice(0, -5) + 'xxxxx'
    };

    await expect(
      encryptionService.decrypt(corruptedData, masterPassword)
    ).rejects.toThrow();
  });

  test('should store and retrieve credentials', async () => {
    const credential = 'super-secret-api-key-12345';
    const type = 'api_key';
    const service = 'test-service';
    const masterPassword = 'master-key-2024';

    // Store credential
    const credentialId = await credentialManager.storeCredential(
      credential,
      type,
      service,
      masterPassword
    );

    expect(credentialId).toBeDefined();
    expect(typeof credentialId).toBe('string');

    // Retrieve credential
    const retrieved = await credentialManager.retrieveCredential(
      credentialId,
      masterPassword
    );

    expect(retrieved).toBe(credential);

    // Check metadata
    const metadata = credentialManager.getCredentialMetadata(credentialId);
    expect(metadata).toEqual(
      expect.objectContaining({
        id: credentialId,
        type,
        service,
        encrypted: true
      })
    );
  });

  test('should list credentials with filters', async () => {
    const credentials = [
      { value: 'api-key-1', type: 'api_key' as const, service: 'service-1' },
      { value: 'secret-1', type: 'secret' as const, service: 'service-1' },
      { value: 'api-key-2', type: 'api_key' as const, service: 'service-2' }
    ];

    const masterPassword = 'test-password';
    const storedIds: string[] = [];

    // Store all credentials
    for (const cred of credentials) {
      const id = await credentialManager.storeCredential(
        cred.value,
        cred.type,
        cred.service,
        masterPassword
      );
      storedIds.push(id);
    }

    // List all credentials
    const allCredentials = credentialManager.listCredentials();
    expect(allCredentials.length).toBe(3);

    // Filter by service
    const service1Creds = credentialManager.listCredentials({ service: 'service-1' });
    expect(service1Creds.length).toBe(2);

    // Filter by type
    const apiKeyCreds = credentialManager.listCredentials({ type: 'api_key' });
    expect(apiKeyCreds.length).toBe(2);

    // Filter by service and type
    const service1ApiKeys = credentialManager.listCredentials({ 
      service: 'service-1', 
      type: 'api_key' 
    });
    expect(service1ApiKeys.length).toBe(1);
  });
});

describe('Credential Manager Advanced Features', () => {
  let credentialManager: CredentialManager;

  beforeEach(() => {
    credentialManager = new CredentialManager();
  });

  test('should rotate credentials successfully', async () => {
    const originalCredential = 'original-api-key';
    const masterPassword = 'master-password';

    // Store original credential
    const originalId = await credentialManager.storeCredential(
      originalCredential,
      'api_key',
      'test-service',
      masterPassword
    );

    // Rotate credential
    const newId = await credentialManager.rotateCredential(
      originalId,
      masterPassword,
      {
        newCredential: 'new-api-key-rotated',
        gracePeriod: 60000 // 1 minute
      }
    );

    expect(newId).not.toBe(originalId);

    // New credential should be retrievable
    const newCredential = await credentialManager.retrieveCredential(
      newId,
      masterPassword
    );
    expect(newCredential).toBe('new-api-key-rotated');

    // Original credential should still be accessible during grace period
    const oldCredential = await credentialManager.retrieveCredential(
      originalId,
      masterPassword
    );
    expect(oldCredential).toBe(originalCredential);
  });

  test('should revoke credentials', async () => {
    const credential = 'revokable-credential';
    const masterPassword = 'master-password';

    const credentialId = await credentialManager.storeCredential(
      credential,
      'secret',
      'test-service',
      masterPassword
    );

    // Revoke credential
    await credentialManager.revokeCredential(credentialId);

    // Should not be able to retrieve revoked credential
    await expect(
      credentialManager.retrieveCredential(credentialId, masterPassword)
    ).rejects.toThrow();
  });

  test('should track audit log', async () => {
    const credential = 'audit-test-credential';
    const masterPassword = 'master-password';
    const userId = 'test-user-123';

    // Store credential
    const credentialId = await credentialManager.storeCredential(
      credential,
      'api_key',
      'audit-service',
      masterPassword,
      { userId }
    );

    // Retrieve credential
    await credentialManager.retrieveCredential(credentialId, masterPassword, userId);

    // Check audit log
    const auditLog = credentialManager.getAuditLog({
      credentialId,
      userId
    });

    expect(auditLog.length).toBeGreaterThanOrEqual(2); // Store + retrieve

    const storeEvent = auditLog.find(entry => entry.operation === 'store_credential');
    const retrieveEvent = auditLog.find(entry => entry.operation === 'retrieve_credential');

    expect(storeEvent).toBeDefined();
    expect(retrieveEvent).toBeDefined();
    
    if (storeEvent) {
      expect(storeEvent.success).toBe(true);
      expect(storeEvent.userId).toBe(userId);
      expect(storeEvent.credentialId).toBe(credentialId);
    }

    if (retrieveEvent) {
      expect(retrieveEvent.success).toBe(true);
      expect(retrieveEvent.userId).toBe(userId);
      expect(retrieveEvent.credentialId).toBe(credentialId);
    }
  });
});