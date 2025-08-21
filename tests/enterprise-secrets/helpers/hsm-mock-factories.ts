/**
 * HSM and Vault integration mock factories for enterprise-secrets testing
 * Provides realistic mocks for hardware security modules and vault operations
 */

import { jest } from '@jest/globals';
import { EventEmitter } from 'events';
import type { ToolContext } from '../../../src/tools/shared/types/tool-context.js';
import { MockHSMProvider, MockVaultClient } from './security-test-utils.js';

/**
 * Create enhanced mock API client for security operations
 */
export function createSecurityMockApiClient(): jest.Mocked<any> {
  const mockClient = {
    get: jest.fn(),
    post: jest.fn(),
    put: jest.fn(),
    delete: jest.fn(),
    patch: jest.fn(),
  } as jest.Mocked<any>;

  // Setup security-specific default responses
  mockClient.get.mockImplementation((endpoint: string) => {
    if (endpoint.includes('/vault/health')) {
      return Promise.resolve({
        success: true,
        data: {
          initialized: true,
          sealed: false,
          standby: false,
        },
      });
    }

    if (endpoint.includes('/vault/secrets')) {
      return Promise.resolve({
        success: true,
        data: {
          'secret/database': { username: 'encrypted-user', password: 'encrypted-pass' },
          'secret/api-key': { key: 'encrypted-api-key' },
        },
      });
    }

    if (endpoint.includes('/hsm/status')) {
      return Promise.resolve({
        success: true,
        data: {
          connected: true,
          initialized: true,
          keyCount: 5,
        },
      });
    }

    if (endpoint.includes('/compliance/audit')) {
      return Promise.resolve({
        success: true,
        data: {
          totalEvents: 1000,
          securityEvents: 50,
          lastAudit: new Date().toISOString(),
        },
      });
    }

    return Promise.resolve({ success: true, data: {} });
  });

  mockClient.post.mockImplementation((endpoint: string, data: any) => {
    if (endpoint.includes('/vault/auth')) {
      return Promise.resolve({
        success: true,
        data: {
          clientToken: 'vault-token-12345',
          policies: ['default', 'secrets-policy'],
          leaseDuration: 3600,
        },
      });
    }

    if (endpoint.includes('/hsm/encrypt')) {
      return Promise.resolve({
        success: true,
        data: {
          ciphertext: `hsm:encrypted:${Buffer.from(data.plaintext).toString('base64')}`,
          keyId: data.keyId,
          algorithm: 'AES-256-GCM',
        },
      });
    }

    if (endpoint.includes('/vault/secrets')) {
      return Promise.resolve({
        success: true,
        data: {
          version: 1,
          created: new Date().toISOString(),
        },
      });
    }

    return Promise.resolve({ success: true, data: {} });
  });

  return mockClient;
}

/**
 * Create enhanced tool context for security testing
 */
export function createSecurityToolContext(overrides: Partial<ToolContext> = {}): ToolContext {
  return {
    server: {} as never,
    apiClient: createSecurityMockApiClient(),
    logger: createSecurityMockLogger(),
    ...overrides,
  };
}

/**
 * Create mock logger with security-specific methods
 */
export function createSecurityMockLogger() {
  const logger = {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
    child: jest.fn(),
    audit: jest.fn(), // Security-specific audit logging
    security: jest.fn(), // Security event logging
  };

  logger.child.mockReturnValue(logger);
  return logger;
}

/**
 * Mock PKCS#11 HSM provider
 */
export class MockPKCS11Provider extends EventEmitter {
  private slots: Map<number, any> = new Map();
  private sessions: Map<string, any> = new Map();
  private isInitialized = false;

  async initialize(libraryPath: string): Promise<void> {
    // Simulate PKCS#11 library loading
    await new Promise(resolve => setTimeout(resolve, 100));
    this.isInitialized = true;
    
    // Setup default slots
    this.slots.set(0, {
      slotId: 0,
      description: 'Mock HSM Slot 0',
      tokenPresent: true,
      token: {
        label: 'MOCK_TOKEN',
        serialNumber: '123456789',
        flags: ['TOKEN_INITIALIZED', 'USER_PIN_INITIALIZED'],
      },
    });

    this.emit('initialized', { libraryPath });
  }

  async getSlots(): Promise<Array<{ slotId: number; description: string; tokenPresent: boolean }>> {
    this.ensureInitialized();
    
    return Array.from(this.slots.values()).map(slot => ({
      slotId: slot.slotId,
      description: slot.description,
      tokenPresent: slot.tokenPresent,
    }));
  }

  async openSession(slotId: number, flags: string[]): Promise<string> {
    this.ensureInitialized();
    
    if (!this.slots.has(slotId)) {
      throw new Error(`Slot ${slotId} not found`);
    }

    const sessionId = `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    this.sessions.set(sessionId, {
      slotId,
      flags,
      loggedIn: false,
      created: new Date(),
    });

    this.emit('sessionOpened', { sessionId, slotId });
    return sessionId;
  }

  async login(sessionId: string, userType: 'USER' | 'SO', pin: string): Promise<void> {
    this.ensureInitialized();
    
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error(`Session ${sessionId} not found`);
    }

    // Simulate PIN validation
    if (pin !== 'test-pin-123') {
      throw new Error('Invalid PIN');
    }

    session.loggedIn = true;
    session.userType = userType;
    this.emit('userLoggedIn', { sessionId, userType });
  }

  async generateKeyPair(sessionId: string, keyType: 'RSA' | 'EC', keySize: number): Promise<{
    publicKey: string;
    privateKey: string;
  }> {
    this.ensureSession(sessionId);
    
    const keyId = `key_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const publicKey = `pkcs11:public:${keyType}:${keySize}:${keyId}`;
    const privateKey = `pkcs11:private:${keyType}:${keySize}:${keyId}`;

    this.emit('keyPairGenerated', { sessionId, keyType, keySize, keyId });
    return { publicKey, privateKey };
  }

  async encrypt(sessionId: string, keyHandle: string, data: Buffer): Promise<Buffer> {
    this.ensureSession(sessionId);
    
    // Mock encryption - prepend identifier and base64 encode
    const encrypted = Buffer.concat([
      Buffer.from('PKCS11_ENC:'),
      Buffer.from(keyHandle),
      Buffer.from(':'),
      data,
    ]);

    this.emit('encrypted', { sessionId, keyHandle, dataSize: data.length });
    return encrypted;
  }

  async decrypt(sessionId: string, keyHandle: string, encryptedData: Buffer): Promise<Buffer> {
    this.ensureSession(sessionId);
    
    // Mock decryption - extract original data
    const prefix = 'PKCS11_ENC:';
    const dataString = encryptedData.toString();
    
    if (!dataString.startsWith(prefix)) {
      throw new Error('Invalid encrypted data format');
    }

    const parts = dataString.split(':');
    if (parts.length < 3) {
      throw new Error('Invalid encrypted data format');
    }

    const originalData = Buffer.from(parts.slice(2).join(':'));
    this.emit('decrypted', { sessionId, keyHandle, dataSize: originalData.length });
    return originalData;
  }

  async sign(sessionId: string, keyHandle: string, data: Buffer, algorithm: string = 'RSA_PKCS'): Promise<Buffer> {
    this.ensureSession(sessionId);
    
    // Mock signature generation
    const signature = Buffer.from(`PKCS11_SIG:${keyHandle}:${algorithm}:${data.toString('base64')}`);
    this.emit('signed', { sessionId, keyHandle, algorithm, dataSize: data.length });
    return signature;
  }

  async verify(sessionId: string, keyHandle: string, data: Buffer, signature: Buffer, algorithm: string = 'RSA_PKCS'): Promise<boolean> {
    this.ensureSession(sessionId);
    
    // Mock signature verification
    const expectedSig = `PKCS11_SIG:${keyHandle}:${algorithm}:${data.toString('base64')}`;
    const isValid = signature.toString() === expectedSig;
    
    this.emit('verified', { sessionId, keyHandle, algorithm, isValid });
    return isValid;
  }

  async closeSession(sessionId: string): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (session) {
      this.sessions.delete(sessionId);
      this.emit('sessionClosed', { sessionId });
    }
  }

  async finalize(): Promise<void> {
    this.sessions.clear();
    this.slots.clear();
    this.isInitialized = false;
    this.emit('finalized');
  }

  private ensureInitialized(): void {
    if (!this.isInitialized) {
      throw new Error('PKCS#11 provider not initialized');
    }
  }

  private ensureSession(sessionId: string): void {
    this.ensureInitialized();
    
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error(`Session ${sessionId} not found`);
    }
    
    if (!session.loggedIn) {
      throw new Error('User not logged in to session');
    }
  }

  getSessionCount(): number {
    return this.sessions.size;
  }

  isProviderInitialized(): boolean {
    return this.isInitialized;
  }
}

/**
 * Mock AWS CloudHSM provider
 */
export class MockCloudHSMProvider extends EventEmitter {
  private clusterId: string | null = null;
  private isConnected = false;
  private keys: Map<string, any> = new Map();

  async connect(config: {
    clusterId: string;
    region: string;
    customerCA: string;
  }): Promise<void> {
    // Simulate CloudHSM connection
    await new Promise(resolve => setTimeout(resolve, 200));
    
    this.clusterId = config.clusterId;
    this.isConnected = true;
    
    this.emit('connected', { clusterId: config.clusterId, region: config.region });
  }

  async createUser(username: string, password: string, userType: 'CRYPTO_USER' | 'CRYPTO_OFFICER'): Promise<void> {
    this.ensureConnected();
    
    // Simulate user creation
    await new Promise(resolve => setTimeout(resolve, 100));
    this.emit('userCreated', { username, userType });
  }

  async loginUser(username: string, password: string): Promise<string> {
    this.ensureConnected();
    
    // Simulate user authentication
    await new Promise(resolve => setTimeout(resolve, 50));
    const sessionToken = `cloudhsm_session_${Date.now()}`;
    
    this.emit('userLoggedIn', { username, sessionToken });
    return sessionToken;
  }

  async generateSymmetricKey(sessionToken: string, keySpec: {
    keyType: 'AES';
    keySize: 128 | 192 | 256;
    keyUsage: string[];
  }): Promise<string> {
    this.ensureConnected();
    
    const keyHandle = `cloudhsm_key_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    this.keys.set(keyHandle, {
      type: keySpec.keyType,
      size: keySpec.keySize,
      usage: keySpec.keyUsage,
      created: new Date(),
    });

    this.emit('keyGenerated', { keyHandle, keySpec });
    return keyHandle;
  }

  async encryptData(sessionToken: string, keyHandle: string, plaintext: Buffer): Promise<{
    ciphertext: Buffer;
    iv: Buffer;
  }> {
    this.ensureConnected();
    this.ensureKey(keyHandle);
    
    // Mock encryption with CloudHSM
    const iv = Buffer.from(`cloudhsm_iv_${Date.now()}`);
    const ciphertext = Buffer.concat([
      Buffer.from('CLOUDHSM_ENC:'),
      Buffer.from(keyHandle),
      Buffer.from(':'),
      plaintext,
    ]);

    this.emit('encrypted', { keyHandle, dataSize: plaintext.length });
    return { ciphertext, iv };
  }

  async decryptData(sessionToken: string, keyHandle: string, ciphertext: Buffer, iv: Buffer): Promise<Buffer> {
    this.ensureConnected();
    this.ensureKey(keyHandle);
    
    // Mock decryption
    const dataString = ciphertext.toString();
    const prefix = 'CLOUDHSM_ENC:';
    
    if (!dataString.startsWith(prefix)) {
      throw new Error('Invalid CloudHSM encrypted data format');
    }

    const parts = dataString.split(':');
    const originalData = Buffer.from(parts.slice(2).join(':'));
    
    this.emit('decrypted', { keyHandle, dataSize: originalData.length });
    return originalData;
  }

  async deleteKey(sessionToken: string, keyHandle: string): Promise<void> {
    this.ensureConnected();
    this.ensureKey(keyHandle);
    
    this.keys.delete(keyHandle);
    this.emit('keyDeleted', { keyHandle });
  }

  async getClusterInfo(): Promise<{
    clusterId: string;
    state: string;
    hsmCount: number;
    region: string;
  }> {
    this.ensureConnected();
    
    return {
      clusterId: this.clusterId!,
      state: 'ACTIVE',
      hsmCount: 2,
      region: 'us-west-2',
    };
  }

  async disconnect(): Promise<void> {
    this.isConnected = false;
    this.clusterId = null;
    this.keys.clear();
    this.emit('disconnected');
  }

  private ensureConnected(): void {
    if (!this.isConnected) {
      throw new Error('Not connected to CloudHSM cluster');
    }
  }

  private ensureKey(keyHandle: string): void {
    if (!this.keys.has(keyHandle)) {
      throw new Error(`Key not found: ${keyHandle}`);
    }
  }

  getKeyCount(): number {
    return this.keys.size;
  }

  isClusterConnected(): boolean {
    return this.isConnected;
  }
}

/**
 * Mock Azure Key Vault provider
 */
export class MockAzureKeyVaultProvider extends EventEmitter {
  private vaultUrl: string | null = null;
  private isAuthenticated = false;
  private keys: Map<string, any> = new Map();
  private secrets: Map<string, any> = new Map();
  private certificates: Map<string, any> = new Map();

  async authenticate(credentials: {
    tenantId: string;
    clientId: string;
    clientSecret: string;
  }): Promise<string> {
    // Simulate Azure authentication
    await new Promise(resolve => setTimeout(resolve, 200));
    
    this.isAuthenticated = true;
    const accessToken = `azure_token_${Date.now()}`;
    
    this.emit('authenticated', { tenantId: credentials.tenantId, clientId: credentials.clientId });
    return accessToken;
  }

  async setVaultUrl(vaultUrl: string): Promise<void> {
    this.vaultUrl = vaultUrl;
    this.emit('vaultConfigured', { vaultUrl });
  }

  async createKey(accessToken: string, keyName: string, keyType: 'RSA' | 'EC', keySize?: number): Promise<{
    keyId: string;
    keyUrl: string;
    publicKey: string;
  }> {
    this.ensureAuthenticated();
    
    const keyId = `azure_key_${Date.now()}_${keyName}`;
    const keyUrl = `${this.vaultUrl}/keys/${keyName}`;
    const publicKey = `-----BEGIN PUBLIC KEY-----\nAZURE_${keyType}_${keySize || 256}_PUBLIC_KEY\n-----END PUBLIC KEY-----`;
    
    this.keys.set(keyName, {
      keyId,
      keyUrl,
      keyType,
      keySize: keySize || 256,
      publicKey,
      created: new Date(),
    });

    this.emit('keyCreated', { keyName, keyType, keySize });
    return { keyId, keyUrl, publicKey };
  }

  async encryptWithKey(accessToken: string, keyName: string, plaintext: Buffer, algorithm: string = 'RSA-OAEP-256'): Promise<{
    ciphertext: string;
    keyVersion: string;
  }> {
    this.ensureAuthenticated();
    this.ensureKey(keyName);
    
    const ciphertext = `azure:encrypted:${keyName}:${algorithm}:${plaintext.toString('base64')}`;
    const keyVersion = `v${Date.now()}`;
    
    this.emit('encrypted', { keyName, algorithm, dataSize: plaintext.length });
    return { ciphertext, keyVersion };
  }

  async decryptWithKey(accessToken: string, keyName: string, ciphertext: string): Promise<Buffer> {
    this.ensureAuthenticated();
    this.ensureKey(keyName);
    
    // Parse Azure ciphertext format
    const parts = ciphertext.split(':');
    if (parts.length !== 5 || parts[0] !== 'azure' || parts[1] !== 'encrypted') {
      throw new Error('Invalid Azure encrypted data format');
    }
    
    const originalData = Buffer.from(parts[4], 'base64');
    this.emit('decrypted', { keyName, dataSize: originalData.length });
    return originalData;
  }

  async setSecret(accessToken: string, secretName: string, secretValue: string, contentType?: string): Promise<{
    secretId: string;
    secretUrl: string;
    version: string;
  }> {
    this.ensureAuthenticated();
    
    const secretId = `azure_secret_${Date.now()}_${secretName}`;
    const secretUrl = `${this.vaultUrl}/secrets/${secretName}`;
    const version = `v${Date.now()}`;
    
    this.secrets.set(secretName, {
      secretId,
      secretUrl,
      value: secretValue,
      contentType: contentType || 'text/plain',
      version,
      created: new Date(),
    });

    this.emit('secretCreated', { secretName, contentType });
    return { secretId, secretUrl, version };
  }

  async getSecret(accessToken: string, secretName: string, version?: string): Promise<{
    value: string;
    contentType: string;
    version: string;
  }> {
    this.ensureAuthenticated();
    
    const secret = this.secrets.get(secretName);
    if (!secret) {
      throw new Error(`Secret not found: ${secretName}`);
    }

    this.emit('secretRetrieved', { secretName, version: version || secret.version });
    return {
      value: secret.value,
      contentType: secret.contentType,
      version: secret.version,
    };
  }

  async deleteKey(accessToken: string, keyName: string): Promise<void> {
    this.ensureAuthenticated();
    this.ensureKey(keyName);
    
    this.keys.delete(keyName);
    this.emit('keyDeleted', { keyName });
  }

  async deleteSecret(accessToken: string, secretName: string): Promise<void> {
    this.ensureAuthenticated();
    
    if (!this.secrets.has(secretName)) {
      throw new Error(`Secret not found: ${secretName}`);
    }

    this.secrets.delete(secretName);
    this.emit('secretDeleted', { secretName });
  }

  private ensureAuthenticated(): void {
    if (!this.isAuthenticated) {
      throw new Error('Not authenticated with Azure Key Vault');
    }
  }

  private ensureKey(keyName: string): void {
    if (!this.keys.has(keyName)) {
      throw new Error(`Key not found: ${keyName}`);
    }
  }

  getKeyCount(): number {
    return this.keys.size;
  }

  getSecretCount(): number {
    return this.secrets.size;
  }

  isVaultAuthenticated(): boolean {
    return this.isAuthenticated;
  }
}

/**
 * Security Performance Testing Factory
 */
export const SecurityPerformanceFactory = {
  createEncryptionBenchmark(provider: MockHSMProvider | MockCloudHSMProvider | MockAzureKeyVaultProvider) {
    return {
      name: 'Encryption Performance Benchmark',
      async executeBenchmark(dataSizes: number[] = [1024, 10240, 102400]): Promise<{
        results: Array<{ size: number; avgLatency: number; throughput: number }>;
        summary: { totalOperations: number; avgThroughput: number };
      }> {
        const results: Array<{ size: number; avgLatency: number; throughput: number }> = [];
        let totalOperations = 0;
        
        for (const size of dataSizes) {
          const iterations = 10;
          const measurements: number[] = [];
          
          for (let i = 0; i < iterations; i++) {
            const testData = Buffer.alloc(size, 'test data');
            const startTime = process.hrtime.bigint();
            
            // Perform encryption based on provider type
            if (provider instanceof MockHSMProvider) {
              // HSM encryption test would go here
              await new Promise(resolve => setTimeout(resolve, 10)); // Simulate encryption
            } else if (provider instanceof MockCloudHSMProvider) {
              // CloudHSM encryption test would go here
              await new Promise(resolve => setTimeout(resolve, 15)); // Simulate encryption
            } else if (provider instanceof MockAzureKeyVaultProvider) {
              // Azure Key Vault encryption test would go here
              await new Promise(resolve => setTimeout(resolve, 20)); // Simulate encryption
            }
            
            const endTime = process.hrtime.bigint();
            const latency = Number(endTime - startTime) / 1_000_000; // Convert to ms
            measurements.push(latency);
          }
          
          const avgLatency = measurements.reduce((sum, val) => sum + val, 0) / measurements.length;
          const throughput = size / (avgLatency / 1000); // Bytes per second
          
          results.push({ size, avgLatency, throughput });
          totalOperations += iterations;
        }
        
        const avgThroughput = results.reduce((sum, result) => sum + result.throughput, 0) / results.length;
        
        return {
          results,
          summary: { totalOperations, avgThroughput },
        };
      },
    };
  },

  createConcurrencyTest(provider: MockHSMProvider | MockCloudHSMProvider | MockAzureKeyVaultProvider) {
    return {
      name: 'Concurrency Performance Test',
      async executeConcurrencyTest(concurrency: number = 10, operations: number = 100): Promise<{
        totalOperations: number;
        successfulOperations: number;
        failedOperations: number;
        avgLatency: number;
        operationsPerSecond: number;
      }> {
        const startTime = Date.now();
        let successfulOperations = 0;
        let failedOperations = 0;
        let totalLatency = 0;

        const workers = Array(concurrency).fill(0).map(async () => {
          for (let i = 0; i < operations / concurrency; i++) {
            try {
              const opStart = process.hrtime.bigint();
              
              // Simulate operation based on provider type
              await new Promise(resolve => setTimeout(resolve, Math.random() * 50));
              
              const opEnd = process.hrtime.bigint();
              const latency = Number(opEnd - opStart) / 1_000_000;
              
              successfulOperations++;
              totalLatency += latency;
            } catch (error) {
              failedOperations++;
            }
          }
        });

        await Promise.all(workers);

        const endTime = Date.now();
        const totalTime = (endTime - startTime) / 1000; // Convert to seconds
        const avgLatency = totalLatency / successfulOperations;
        const operationsPerSecond = operations / totalTime;

        return {
          totalOperations: operations,
          successfulOperations,
          failedOperations,
          avgLatency,
          operationsPerSecond,
        };
      },
    };
  },
};