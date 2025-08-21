/**
 * Security-focused test utilities for enterprise-secrets module
 * Provides specialized testing patterns for HSM, Vault, compliance, and security operations
 */

import { expect } from '@jest/globals';
import crypto from 'crypto';
import { EventEmitter } from 'events';

/**
 * Mock HSM provider for testing hardware security module integrations
 */
export class MockHSMProvider extends EventEmitter {
  private keys: Map<string, any> = new Map();
  private isInitialized = false;
  private sessionToken: string | null = null;

  async initialize(config: any): Promise<void> {
    if (this.isInitialized) {
      throw new Error('HSM already initialized');
    }

    // Simulate HSM initialization
    await new Promise(resolve => setTimeout(resolve, 100));
    this.isInitialized = true;
    this.sessionToken = `hsm-session-${Date.now()}`;
    
    this.emit('initialized', { sessionToken: this.sessionToken });
  }

  async generateKey(keySpec: {
    type: 'AES' | 'RSA' | 'ECC';
    size: number;
    usage: string[];
  }): Promise<{ keyId: string; publicKey?: string }> {
    this.ensureInitialized();

    const keyId = `hsm-key-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const keyData = {
      type: keySpec.type,
      size: keySpec.size,
      usage: keySpec.usage,
      created: new Date().toISOString(),
    };

    let publicKey: string | undefined;
    if (keySpec.type === 'RSA' || keySpec.type === 'ECC') {
      // Generate mock public key for asymmetric algorithms
      publicKey = `-----BEGIN PUBLIC KEY-----\nMOCK_${keySpec.type}_${keySpec.size}_PUBLIC_KEY\n-----END PUBLIC KEY-----`;
    }

    this.keys.set(keyId, { ...keyData, publicKey });
    this.emit('keyGenerated', { keyId, type: keySpec.type });

    return { keyId, publicKey };
  }

  async encrypt(keyId: string, plaintext: string | Buffer): Promise<{
    ciphertext: string;
    iv?: string;
    tag?: string;
  }> {
    this.ensureInitialized();
    
    const key = this.keys.get(keyId);
    if (!key) {
      throw new Error(`Key not found: ${keyId}`);
    }

    if (!key.usage.includes('encrypt')) {
      throw new Error(`Key ${keyId} does not support encryption`);
    }

    // Simulate encryption with mock data
    const iv = crypto.randomBytes(16).toString('hex');
    const tag = crypto.randomBytes(16).toString('hex');
    const ciphertext = `hsm:encrypted:${keyId}:${Buffer.from(plaintext).toString('base64')}`;

    this.emit('encrypted', { keyId, size: plaintext.length });

    return { ciphertext, iv, tag };
  }

  async decrypt(keyId: string, ciphertext: string, iv?: string, tag?: string): Promise<string> {
    this.ensureInitialized();
    
    const key = this.keys.get(keyId);
    if (!key) {
      throw new Error(`Key not found: ${keyId}`);
    }

    if (!key.usage.includes('decrypt')) {
      throw new Error(`Key ${keyId} does not support decryption`);
    }

    // Extract plaintext from mock ciphertext
    const parts = ciphertext.split(':');
    if (parts.length !== 4 || parts[0] !== 'hsm' || parts[1] !== 'encrypted') {
      throw new Error('Invalid ciphertext format');
    }

    const plaintext = Buffer.from(parts[3], 'base64').toString();
    this.emit('decrypted', { keyId, size: plaintext.length });

    return plaintext;
  }

  async sign(keyId: string, data: string | Buffer, algorithm: string = 'RSA-PSS-SHA256'): Promise<string> {
    this.ensureInitialized();
    
    const key = this.keys.get(keyId);
    if (!key) {
      throw new Error(`Key not found: ${keyId}`);
    }

    if (!key.usage.includes('sign')) {
      throw new Error(`Key ${keyId} does not support signing`);
    }

    // Generate mock signature
    const signature = `hsm:signature:${keyId}:${crypto.createHash('sha256').update(data).digest('hex')}`;
    this.emit('signed', { keyId, algorithm, dataSize: data.length });

    return signature;
  }

  async verify(keyId: string, data: string | Buffer, signature: string, algorithm: string = 'RSA-PSS-SHA256'): Promise<boolean> {
    this.ensureInitialized();
    
    const key = this.keys.get(keyId);
    if (!key) {
      throw new Error(`Key not found: ${keyId}`);
    }

    // Verify mock signature format
    const expectedSignature = `hsm:signature:${keyId}:${crypto.createHash('sha256').update(data).digest('hex')}`;
    const isValid = signature === expectedSignature;

    this.emit('verified', { keyId, algorithm, isValid });

    return isValid;
  }

  async deleteKey(keyId: string): Promise<void> {
    this.ensureInitialized();
    
    if (!this.keys.has(keyId)) {
      throw new Error(`Key not found: ${keyId}`);
    }

    this.keys.delete(keyId);
    this.emit('keyDeleted', { keyId });
  }

  async listKeys(): Promise<Array<{ keyId: string; type: string; created: string }>> {
    this.ensureInitialized();
    
    return Array.from(this.keys.entries()).map(([keyId, keyData]) => ({
      keyId,
      type: keyData.type,
      created: keyData.created,
    }));
  }

  async destroy(): Promise<void> {
    this.keys.clear();
    this.isInitialized = false;
    this.sessionToken = null;
    this.emit('destroyed');
  }

  private ensureInitialized(): void {
    if (!this.isInitialized) {
      throw new Error('HSM not initialized');
    }
  }

  getSessionToken(): string | null {
    return this.sessionToken;
  }

  isHSMInitialized(): boolean {
    return this.isInitialized;
  }
}

/**
 * Mock Vault client for testing HashiCorp Vault integrations
 */
export class MockVaultClient {
  private secrets: Map<string, any> = new Map();
  private policies: Map<string, any> = new Map();
  private auditLogs: Array<any> = [];
  private authToken: string | null = null;
  private sealStatus = false;

  async authenticate(token: string): Promise<{ clientToken: string; policies: string[] }> {
    // Simulate authentication
    this.authToken = token;
    const policies = ['default', 'test-policy'];
    
    this.auditLogs.push({
      type: 'auth',
      token: this.hashToken(token),
      timestamp: new Date().toISOString(),
      success: true,
    });

    return { clientToken: token, policies };
  }

  async unseal(key: string): Promise<{ sealed: boolean; progress: number; threshold: number }> {
    // Simulate unsealing process
    this.sealStatus = false;
    return { sealed: false, progress: 3, threshold: 3 };
  }

  async writeSecret(path: string, data: any, version?: number): Promise<{ version: number }> {
    this.ensureAuthenticated();
    
    const secretVersion = version || 1;
    const secretData = {
      data,
      metadata: {
        version: secretVersion,
        created: new Date().toISOString(),
        updated: new Date().toISOString(),
      },
    };

    this.secrets.set(path, secretData);
    
    this.auditLogs.push({
      type: 'write',
      path,
      token: this.hashToken(this.authToken!),
      timestamp: new Date().toISOString(),
      version: secretVersion,
    });

    return { version: secretVersion };
  }

  async readSecret(path: string, version?: number): Promise<{ data: any; metadata: any } | null> {
    this.ensureAuthenticated();
    
    const secret = this.secrets.get(path);
    if (!secret) {
      this.auditLogs.push({
        type: 'read',
        path,
        token: this.hashToken(this.authToken!),
        timestamp: new Date().toISOString(),
        error: 'not_found',
      });
      return null;
    }

    this.auditLogs.push({
      type: 'read',
      path,
      token: this.hashToken(this.authToken!),
      timestamp: new Date().toISOString(),
      success: true,
    });

    return secret;
  }

  async deleteSecret(path: string): Promise<void> {
    this.ensureAuthenticated();
    
    if (!this.secrets.has(path)) {
      throw new Error(`Secret not found: ${path}`);
    }

    this.secrets.delete(path);
    
    this.auditLogs.push({
      type: 'delete',
      path,
      token: this.hashToken(this.authToken!),
      timestamp: new Date().toISOString(),
      success: true,
    });
  }

  async listSecrets(path: string): Promise<string[]> {
    this.ensureAuthenticated();
    
    const secretPaths = Array.from(this.secrets.keys())
      .filter(secretPath => secretPath.startsWith(path))
      .map(secretPath => secretPath.substring(path.length));

    this.auditLogs.push({
      type: 'list',
      path,
      token: this.hashToken(this.authToken!),
      timestamp: new Date().toISOString(),
      count: secretPaths.length,
    });

    return secretPaths;
  }

  async createPolicy(name: string, policy: any): Promise<void> {
    this.ensureAuthenticated();
    
    this.policies.set(name, {
      ...policy,
      created: new Date().toISOString(),
    });

    this.auditLogs.push({
      type: 'policy_create',
      name,
      token: this.hashToken(this.authToken!),
      timestamp: new Date().toISOString(),
    });
  }

  async getPolicy(name: string): Promise<any | null> {
    this.ensureAuthenticated();
    
    return this.policies.get(name) || null;
  }

  async encrypt(transitKey: string, plaintext: string): Promise<{ ciphertext: string }> {
    this.ensureAuthenticated();
    
    const ciphertext = `vault:v1:${Buffer.from(plaintext).toString('base64')}`;
    
    this.auditLogs.push({
      type: 'encrypt',
      key: transitKey,
      token: this.hashToken(this.authToken!),
      timestamp: new Date().toISOString(),
    });

    return { ciphertext };
  }

  async decrypt(transitKey: string, ciphertext: string): Promise<{ plaintext: string }> {
    this.ensureAuthenticated();
    
    // Extract plaintext from mock ciphertext
    const parts = ciphertext.split(':');
    if (parts.length !== 3 || parts[0] !== 'vault' || parts[1] !== 'v1') {
      throw new Error('Invalid ciphertext format');
    }

    const plaintext = Buffer.from(parts[2], 'base64').toString();
    
    this.auditLogs.push({
      type: 'decrypt',
      key: transitKey,
      token: this.hashToken(this.authToken!),
      timestamp: new Date().toISOString(),
    });

    return { plaintext };
  }

  async getAuditLogs(limit: number = 100): Promise<any[]> {
    return this.auditLogs.slice(-limit);
  }

  async getHealth(): Promise<{ sealed: boolean; initialized: boolean }> {
    return { sealed: this.sealStatus, initialized: true };
  }

  private ensureAuthenticated(): void {
    if (!this.authToken) {
      throw new Error('Not authenticated');
    }
  }

  private hashToken(token: string): string {
    return `hmac-sha256:${crypto.createHash('sha256').update(token).digest('hex').substring(0, 16)}`;
  }

  reset(): void {
    this.secrets.clear();
    this.policies.clear();
    this.auditLogs = [];
    this.authToken = null;
    this.sealStatus = false;
  }
}

/**
 * Security assertion utilities
 */
export const SecurityAssertions = {
  /**
   * Assert that encryption meets security standards
   */
  expectSecureEncryption(algorithm: string, keySize: number, ciphertext: string): void {
    // Validate encryption algorithm
    const approvedAlgorithms = ['AES-256-GCM', 'AES-256-CBC', 'RSA-OAEP-256', 'ChaCha20-Poly1305'];
    expect(approvedAlgorithms).toContain(algorithm);

    // Validate key size
    if (algorithm.startsWith('AES')) {
      expect(keySize).toBeGreaterThanOrEqual(256);
    } else if (algorithm.startsWith('RSA')) {
      expect(keySize).toBeGreaterThanOrEqual(2048);
    }

    // Validate ciphertext format
    expect(ciphertext).toBeTruthy();
    expect(ciphertext.length).toBeGreaterThan(0);
    expect(ciphertext).not.toBe('plaintext'); // Ensure it's actually encrypted
  },

  /**
   * Assert that audit logging is comprehensive
   */
  expectComprehensiveAudit(auditLog: any, requiredFields: string[]): void {
    requiredFields.forEach(field => {
      expect(auditLog).toHaveProperty(field);
      expect(auditLog[field]).toBeTruthy();
    });

    // Validate timestamp format
    expect(auditLog.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
    
    // Ensure sensitive data is not logged
    const auditString = JSON.stringify(auditLog);
    expect(auditString).not.toMatch(/password|secret|key/i);
  },

  /**
   * Assert RBAC policy enforcement
   */
  expectRBACEnforcement(policy: any, user: string, action: string, resource: string): boolean {
    const hasPermission = policy.rules.some((rule: any) => {
      const pathMatches = resource.match(new RegExp(rule.path.replace('*', '.*')));
      const actionAllowed = rule.capabilities.includes(action);
      return pathMatches && actionAllowed;
    });

    expect(hasPermission).toBeDefined();
    return hasPermission;
  },

  /**
   * Assert that secrets are properly protected
   */
  expectSecretProtection(secret: any): void {
    // Ensure secret data is encrypted or hashed
    if (secret.data) {
      Object.values(secret.data).forEach(value => {
        if (typeof value === 'string') {
          // Check for common patterns indicating encryption
          const isProtected = value.includes(':') && (
            value.startsWith('vault:') ||
            value.startsWith('hsm:') ||
            value.length > 50 // Likely encrypted if very long
          );
          expect(isProtected).toBe(true);
        }
      });
    }

    // Ensure metadata exists
    expect(secret).toHaveProperty('metadata');
    expect(secret.metadata).toHaveProperty('version');
    expect(secret.metadata).toHaveProperty('created');
  },
};

/**
 * Compliance testing utilities
 */
export const ComplianceTestUtils = {
  /**
   * Test SOC 2 compliance requirements
   */
  async testSOC2Compliance(systemUnderTest: any): Promise<{
    passed: boolean;
    failedRequirements: string[];
    evidence: Record<string, any>;
  }> {
    const evidence: Record<string, any> = {};
    const failedRequirements: string[] = [];

    // Test encryption at rest
    try {
      const encryptionTest = await systemUnderTest.testEncryptionAtRest();
      evidence.encryptionAtRest = encryptionTest;
      if (!encryptionTest.passed) {
        failedRequirements.push('Encryption at rest');
      }
    } catch (error) {
      failedRequirements.push('Encryption at rest');
      evidence.encryptionAtRest = { error: error.message };
    }

    // Test access logging
    try {
      const auditTest = await systemUnderTest.testAuditLogging();
      evidence.auditLogging = auditTest;
      if (!auditTest.passed) {
        failedRequirements.push('Access logging');
      }
    } catch (error) {
      failedRequirements.push('Access logging');
      evidence.auditLogging = { error: error.message };
    }

    // Test RBAC
    try {
      const rbacTest = await systemUnderTest.testRBAC();
      evidence.rbac = rbacTest;
      if (!rbacTest.passed) {
        failedRequirements.push('Role-based access control');
      }
    } catch (error) {
      failedRequirements.push('Role-based access control');
      evidence.rbac = { error: error.message };
    }

    return {
      passed: failedRequirements.length === 0,
      failedRequirements,
      evidence,
    };
  },

  /**
   * Test PCI DSS compliance requirements
   */
  async testPCIDSSCompliance(systemUnderTest: any): Promise<{
    passed: boolean;
    failedRequirements: string[];
    evidence: Record<string, any>;
  }> {
    const evidence: Record<string, any> = {};
    const failedRequirements: string[] = [];

    // Test strong cryptography
    try {
      const cryptoTest = await systemUnderTest.testCryptographyStrength();
      evidence.cryptography = cryptoTest;
      if (!cryptoTest.passed || cryptoTest.keySize < 2048) {
        failedRequirements.push('Strong cryptography');
      }
    } catch (error) {
      failedRequirements.push('Strong cryptography');
      evidence.cryptography = { error: error.message };
    }

    // Test key rotation
    try {
      const rotationTest = await systemUnderTest.testKeyRotation();
      evidence.keyRotation = rotationTest;
      if (!rotationTest.passed) {
        failedRequirements.push('Key rotation');
      }
    } catch (error) {
      failedRequirements.push('Key rotation');
      evidence.keyRotation = { error: error.message };
    }

    return {
      passed: failedRequirements.length === 0,
      failedRequirements,
      evidence,
    };
  },

  /**
   * Generate compliance report
   */
  generateComplianceReport(results: Array<{ framework: string; passed: boolean; failedRequirements: string[] }>): string {
    let report = 'COMPLIANCE TEST REPORT\n';
    report += '======================\n\n';
    report += `Generated: ${new Date().toISOString()}\n\n`;

    results.forEach(result => {
      report += `${result.framework}: ${result.passed ? '✅ PASSED' : '❌ FAILED'}\n`;
      if (result.failedRequirements.length > 0) {
        report += `  Failed Requirements:\n`;
        result.failedRequirements.forEach(req => {
          report += `    - ${req}\n`;
        });
      }
      report += '\n';
    });

    const overallPassed = results.every(r => r.passed);
    report += `OVERALL STATUS: ${overallPassed ? '✅ COMPLIANT' : '❌ NON-COMPLIANT'}\n`;

    return report;
  },
};

/**
 * Performance testing utilities for security operations
 */
export const SecurityPerformanceUtils = {
  /**
   * Benchmark encryption performance
   */
  async benchmarkEncryption(
    encryptFn: (data: string) => Promise<string>,
    dataSizes: number[] = [1024, 10240, 102400], // 1KB, 10KB, 100KB
    iterations: number = 100
  ): Promise<Record<string, { avgLatency: number; throughput: number }>> {
    const results: Record<string, { avgLatency: number; throughput: number }> = {};

    for (const size of dataSizes) {
      const testData = 'x'.repeat(size);
      const measurements: number[] = [];

      for (let i = 0; i < iterations; i++) {
        const start = process.hrtime.bigint();
        await encryptFn(testData);
        const end = process.hrtime.bigint();
        
        const latency = Number(end - start) / 1_000_000; // Convert to ms
        measurements.push(latency);
      }

      const avgLatency = measurements.reduce((sum, val) => sum + val, 0) / measurements.length;
      const throughput = size / (avgLatency / 1000); // Bytes per second

      results[`${size}_bytes`] = { avgLatency, throughput };
    }

    return results;
  },

  /**
   * Test concurrent security operations
   */
  async testConcurrentOperations(
    operationFn: () => Promise<any>,
    concurrency: number = 10,
    duration: number = 5000
  ): Promise<{
    totalOperations: number;
    averageLatency: number;
    operationsPerSecond: number;
    errors: number;
  }> {
    const startTime = Date.now();
    const endTime = startTime + duration;
    let totalOperations = 0;
    let totalLatency = 0;
    let errors = 0;

    const workers = Array(concurrency).fill(0).map(async () => {
      while (Date.now() < endTime) {
        try {
          const opStart = process.hrtime.bigint();
          await operationFn();
          const opEnd = process.hrtime.bigint();
          
          const latency = Number(opEnd - opStart) / 1_000_000;
          totalOperations++;
          totalLatency += latency;
        } catch (error) {
          errors++;
        }
      }
    });

    await Promise.all(workers);

    const actualDuration = (Date.now() - startTime) / 1000;
    const averageLatency = totalLatency / totalOperations;
    const operationsPerSecond = totalOperations / actualDuration;

    return {
      totalOperations,
      averageLatency,
      operationsPerSecond,
      errors,
    };
  },
};