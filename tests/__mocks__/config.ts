/**
 * Mock config manager for tests
 * Provides safe defaults that work in test environment
 */

import { ServerConfig, MakeApiConfig, RateLimitConfig } from '../../src/types/index.js';

// Mock configuration data
const mockConfig: ServerConfig = {
  name: 'Test Make.com FastMCP Server',
  version: '1.0.0-test',
  port: 3001,
  logLevel: 'error', // Quiet in tests
  authentication: {
    enabled: false,
    secret: 'test-secret-12345678901234567890123456'
  },
  rateLimit: {
    maxRequests: 1000,
    windowMs: 60000,
    skipSuccessfulRequests: true,
    skipFailedRequests: true
  },
  make: {
    apiKey: 'test_api_key_12345',
    baseUrl: 'https://api.make.com/api/v2',
    teamId: '12345',
    organizationId: '67890',
    timeout: 30000,
    retries: 3
  }
};

// Mock ConfigManager class
class MockConfigManager {
  private static instance: MockConfigManager;
  private config: ServerConfig = mockConfig;

  public static getInstance(): MockConfigManager {
    if (!MockConfigManager.instance) {
      MockConfigManager.instance = new MockConfigManager();
    }
    return MockConfigManager.instance;
  }

  public reinitialize(): void {
    // Mock implementation - no-op in tests
  }

  public getConfig(): ServerConfig {
    return { ...this.config };
  }

  public getMakeConfig(): MakeApiConfig {
    return { ...this.config.make };
  }

  public getLogLevel(): string {
    return this.config.logLevel || 'error';
  }

  public isAuthEnabled(): boolean {
    return this.config.authentication?.enabled || false;
  }

  public getAuthSecret(): string | undefined {
    return this.config.authentication?.secret;
  }

  public getRateLimitConfig(): RateLimitConfig | undefined {
    return this.config.rateLimit ? { ...this.config.rateLimit } : undefined;
  }

  public isDevelopment(): boolean {
    return process.env.NODE_ENV === 'development';
  }

  public isProduction(): boolean {
    return process.env.NODE_ENV === 'production';
  }

  public isTest(): boolean {
    return process.env.NODE_ENV === 'test';
  }

  public validateEnvironment(): { valid: boolean; errors: string[]; warnings: string[] } {
    return { valid: true, errors: [], warnings: [] };
  }

  public getConfigurationReport(): string {
    return JSON.stringify({
      environment: 'test',
      server: {
        name: this.config.name,
        version: this.config.version,
        port: this.config.port,
        logLevel: this.config.logLevel
      },
      make: {
        baseUrl: this.config.make.baseUrl,
        hasApiKey: true,
        apiKeyLength: this.config.make.apiKey.length
      },
      authentication: {
        enabled: false,
        hasSecret: true,
        secretLength: 32
      },
      rateLimit: this.config.rateLimit
    }, null, 2);
  }
}

// Create and export mock instance
const mockConfigManager = MockConfigManager.getInstance();

// ES module exports
export default mockConfigManager;
export { MockConfigManager as ConfigManager };
export const configManager = mockConfigManager;

// CommonJS compatibility
if (typeof module !== 'undefined' && module.exports) {
  module.exports = mockConfigManager;
  module.exports.default = mockConfigManager;
  module.exports.configManager = mockConfigManager;
  module.exports.ConfigManager = MockConfigManager;
}