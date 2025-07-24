/**
 * Configuration management for Make.com FastMCP Server
 * Handles environment variables, validation, and defaults
 */

import { config as dotenvConfig } from 'dotenv';
import { ServerConfig, MakeApiConfig, RateLimitConfig } from '../types/index.js';

// Load environment variables
dotenvConfig();

class ConfigManager {
  private static instance: ConfigManager;
  private config: ServerConfig;

  private constructor() {
    this.config = this.loadConfig();
    this.validateConfig();
  }

  public static getInstance(): ConfigManager {
    if (!ConfigManager.instance) {
      ConfigManager.instance = new ConfigManager();
    }
    return ConfigManager.instance;
  }

  private loadConfig(): ServerConfig {
    const makeConfig: MakeApiConfig = {
      apiKey: this.getRequiredEnv('MAKE_API_KEY'),
      baseUrl: process.env.MAKE_BASE_URL || 'https://eu1.make.com/api/v2',
      teamId: process.env.MAKE_TEAM_ID,
      organizationId: process.env.MAKE_ORGANIZATION_ID,
      timeout: parseInt(process.env.MAKE_TIMEOUT || '30000'),
      retries: parseInt(process.env.MAKE_RETRIES || '3'),
    };

    const rateLimitConfig: RateLimitConfig = {
      maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100'),
      windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000'),
      skipSuccessfulRequests: process.env.RATE_LIMIT_SKIP_SUCCESS === 'true',
      skipFailedRequests: process.env.RATE_LIMIT_SKIP_FAILED === 'true',
    };

    return {
      name: 'Make.com FastMCP Server',
      version: '1.0.0',
      port: parseInt(process.env.PORT || '3000'),
      logLevel: (process.env.LOG_LEVEL as any) || 'info',
      authentication: {
        enabled: process.env.AUTH_ENABLED === 'true',
        secret: process.env.AUTH_SECRET,
      },
      rateLimit: rateLimitConfig,
      make: makeConfig,
    };
  }

  private getRequiredEnv(key: string): string {
    const value = process.env[key];
    if (!value) {
      throw new Error(`Required environment variable ${key} is not set`);
    }
    return value;
  }

  private validateConfig(): void {
    // Validate Make.com API configuration
    if (!this.config.make.apiKey) {
      throw new Error('Make.com API key is required');
    }

    if (!this.isValidUrl(this.config.make.baseUrl)) {
      throw new Error('Invalid Make.com base URL');
    }

    // Validate rate limiting configuration
    if (this.config.rateLimit) {
      if (this.config.rateLimit.maxRequests <= 0) {
        throw new Error('Rate limit max requests must be positive');
      }
      if (this.config.rateLimit.windowMs <= 0) {
        throw new Error('Rate limit window must be positive');
      }
    }

    // Validate authentication if enabled
    if (this.config.authentication?.enabled && !this.config.authentication.secret) {
      throw new Error('Authentication secret is required when authentication is enabled');
    }
  }

  private isValidUrl(url: string): boolean {
    try {
      new URL(url);
      return true;
    } catch {
      return false;
    }
  }

  public getConfig(): ServerConfig {
    return { ...this.config };
  }

  public getMakeConfig(): MakeApiConfig {
    return { ...this.config.make };
  }

  public getLogLevel(): string {
    return this.config.logLevel || 'info';
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
}

export const configManager = ConfigManager.getInstance();
export default configManager;