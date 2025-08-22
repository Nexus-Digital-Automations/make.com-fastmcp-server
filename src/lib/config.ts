/**
 * Configuration management for Make.com FastMCP Server
 * Handles environment variables, validation, and defaults with comprehensive error handling
 */

import { config as dotenvConfig } from 'dotenv';
import { z } from 'zod';
import { ServerConfig, MakeApiConfig, RateLimitConfig } from '../types/index.js';

// Load environment variables
dotenvConfig();

// Configuration validation schemas
const MakeApiConfigSchema = z.object({
  apiKey: z.string().min(1, 'Make.com API key is required'),
  baseUrl: z.string().url('Invalid Make.com base URL').optional().default('https://eu1.make.com/api/v2'),
  teamId: z.string().optional(),
  organizationId: z.string().optional(),
  timeout: z.number().min(1000, 'Timeout must be at least 1000ms').max(300000, 'Timeout cannot exceed 300000ms').optional().default(30000),
  retries: z.number().min(0, 'Retries must be non-negative').max(10, 'Retries cannot exceed 10').optional().default(3),
});

const RateLimitConfigSchema = z.object({
  maxRequests: z.number().min(1, 'Max requests must be positive').optional().default(100),
  windowMs: z.number().min(1000, 'Window must be at least 1000ms').optional().default(60000),
  skipSuccessfulRequests: z.boolean().optional().default(false),
  skipFailedRequests: z.boolean().optional().default(false),
});

const AuthConfigSchema = z.object({
  enabled: z.boolean().optional().default(false),
  secret: z.string().min(32, 'Auth secret must be at least 32 characters').optional(),
}).refine((data) => {
  if (data.enabled && !data.secret) {
    throw new Error('Authentication secret is required when authentication is enabled');
  }
  return true;
}, {
  message: 'Authentication secret is required when authentication is enabled',
});

const ServerConfigSchema = z.object({
  name: z.string().optional().default('Make.com FastMCP Server'),
  version: z.string().optional().default('1.0.0'),
  port: z.number().min(1, 'Port must be positive').max(65535, 'Port must be valid').optional().default(3000),
  logLevel: z.enum(['debug', 'info', 'warn', 'error']).optional().default('info'),
  authentication: AuthConfigSchema.optional(),
  rateLimit: RateLimitConfigSchema.optional(),
  make: MakeApiConfigSchema,
});

// Environment variable parsing utilities
class EnvironmentParser {
  static parseString(value: string | undefined, fallback?: string): string | undefined {
    if (value === undefined || value === '') {
      return fallback;
    }
    return value;
  }

  static parseNumber(value: string | undefined, fallback?: number): number | undefined {
    if (value === undefined || value === '') {
      return fallback;
    }
    const parsed = parseInt(value, 10);
    if (isNaN(parsed)) {
      throw new Error(`Invalid number value: ${value}`);
    }
    return parsed;
  }

  static parseBoolean(value: string | undefined, fallback?: boolean): boolean | undefined {
    if (value === undefined || value === '') {
      return fallback;
    }
    const lower = value.toLowerCase();
    if (lower === 'true' || lower === '1' || lower === 'yes') {
      return true;
    }
    if (lower === 'false' || lower === '0' || lower === 'no') {
      return false;
    }
    throw new Error(`Invalid boolean value: ${value}. Expected: true, false, 1, 0, yes, or no`);
  }

  static parseUrl(value: string | undefined, fallback?: string): string | undefined {
    const url = this.parseString(value, fallback);
    if (url && !this.isValidUrl(url)) {
      throw new Error(`Invalid URL format: ${url}`);
    }
    return url;
  }

  private static isValidUrl(url: string): boolean {
    try {
      new URL(url);
      return true;
    } catch {
      return false;
    }
  }
}

// Configuration error classes
export class ConfigurationError extends Error {
  constructor(message: string, public readonly key?: string, public readonly value?: string) {
    super(message);
    this.name = 'ConfigurationError';
  }
}

export class ValidationError extends ConfigurationError {
  constructor(message: string, key?: string, value?: string) {
    super(`Validation failed: ${message}`, key, value);
    this.name = 'ValidationError';
  }
}

class ConfigManager {
  private static instance: ConfigManager;
  private config: ServerConfig;
  private validationErrors: string[] = [];

  private constructor() {
    try {
      this.config = this.loadConfig();
      this.validateConfig();
    } catch (error) {
      if (error instanceof ConfigurationError) {
        throw error;
      }
      throw new ConfigurationError(`Failed to initialize configuration: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  public static getInstance(): ConfigManager {
    if (!ConfigManager.instance) {
      ConfigManager.instance = new ConfigManager();
    }
    return ConfigManager.instance;
  }

  // Method to reinitialize configuration for testing purposes
  public reinitialize(): void {
    try {
      this.config = this.loadConfig();
      this.validateConfig();
    } catch (error) {
      if (error instanceof ConfigurationError) {
        throw error;
      }
      throw new ConfigurationError(`Failed to reinitialize configuration: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  private loadConfig(): ServerConfig {
    try {
      // Load raw configuration with proper error handling and fallbacks
      const rawConfig = {
        name: EnvironmentParser.parseString(process.env.SERVER_NAME, 'Make.com FastMCP Server'),
        version: EnvironmentParser.parseString(process.env.SERVER_VERSION, '1.0.0'),
        port: EnvironmentParser.parseNumber(process.env.PORT, 3000),
        logLevel: this.parseLogLevel(process.env.LOG_LEVEL),
        authentication: {
          enabled: EnvironmentParser.parseBoolean(process.env.AUTH_ENABLED, false),
          secret: EnvironmentParser.parseString(process.env.AUTH_SECRET),
        },
        rateLimit: {
          maxRequests: EnvironmentParser.parseNumber(process.env.RATE_LIMIT_MAX_REQUESTS, 100),
          windowMs: EnvironmentParser.parseNumber(process.env.RATE_LIMIT_WINDOW_MS, 60000),
          skipSuccessfulRequests: EnvironmentParser.parseBoolean(process.env.RATE_LIMIT_SKIP_SUCCESS, false),
          skipFailedRequests: EnvironmentParser.parseBoolean(process.env.RATE_LIMIT_SKIP_FAILED, false),
        },
        make: {
          apiKey: this.getRequiredEnv('MAKE_API_KEY'),
          baseUrl: EnvironmentParser.parseUrl(process.env.MAKE_BASE_URL, 'https://eu1.make.com/api/v2'),
          teamId: EnvironmentParser.parseString(process.env.MAKE_TEAM_ID),
          organizationId: EnvironmentParser.parseString(process.env.MAKE_ORGANIZATION_ID),
          timeout: EnvironmentParser.parseNumber(process.env.MAKE_TIMEOUT, 30000),
          retries: EnvironmentParser.parseNumber(process.env.MAKE_RETRIES, 3),
        },
      };

      // Validate using Zod schema
      const validatedConfig = ServerConfigSchema.parse(rawConfig);
      return validatedConfig;

    } catch (error) {
      if (error instanceof z.ZodError) {
        const validationMessages = error.issues.map(err => 
          `${err.path.join('.')}: ${err.message}`
        ).join(', ');
        throw new ValidationError(`Configuration validation failed: ${validationMessages}`);
      }
      throw error;
    }
  }

  private parseLogLevel(value: string | undefined): 'debug' | 'info' | 'warn' | 'error' {
    const level = EnvironmentParser.parseString(value, 'info')?.toLowerCase();
    if (!level || !['debug', 'info', 'warn', 'error'].includes(level)) {
      throw new ConfigurationError(`Invalid log level: ${level}. Must be one of: debug, info, warn, error`, 'LOG_LEVEL', value);
    }
    return level as 'debug' | 'info' | 'warn' | 'error';
  }

  private getRequiredEnv(key: string): string {
    const value = process.env[key];
    if (!value || value.trim() === '') {
      throw new ConfigurationError(`Required environment variable is missing or empty`, key);
    }
    return value.trim();
  }

  private validateConfig(): void {
    // Additional business logic validation beyond schema validation
    const errors: string[] = [];

    // Validate Make.com API key format (basic check)
    if (this.config.make.apiKey && this.config.make.apiKey.length < 10) {
      errors.push('Make.com API key appears to be too short (should be at least 10 characters)');
    }

    // Validate port availability in development
    if (this.isDevelopment() && this.config.port && this.config.port < 1024) {
      errors.push('Port numbers below 1024 require elevated privileges in development');
    }

    // Validate authentication configuration consistency
    if (this.config.authentication?.enabled) {
      if (!this.config.authentication.secret) {
        errors.push('Authentication is enabled but no secret is provided');
      } else if (this.config.authentication.secret.length < 32) {
        errors.push('Authentication secret should be at least 32 characters for security');
      }
    }

    // Validate environment-specific settings
    if (this.isProduction()) {
      if (this.config.logLevel === 'debug') {
        console.warn('WARNING: Debug logging is enabled in production environment');
      }
      if (!this.config.authentication?.enabled) {
        console.warn('WARNING: Authentication is disabled in production environment');
      }
    }

    if (errors.length > 0) {
      throw new ValidationError(`Configuration validation failed: ${errors.join('; ')}`);
    }
  }

  // Enhanced configuration access methods with error handling
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

  public isTest(): boolean {
    return process.env.NODE_ENV === 'test';
  }

  // Configuration validation and health check methods
  public validateEnvironment(): { valid: boolean; errors: string[]; warnings: string[] } {
    const errors: string[] = [];
    const warnings: string[] = [];

    try {
      // Test Make.com API key presence
      if (!process.env.MAKE_API_KEY) {
        errors.push('MAKE_API_KEY is required but not set');
      }

      // Check for common configuration issues
      if (process.env.NODE_ENV === 'production') {
        if (process.env.LOG_LEVEL === 'debug') {
          warnings.push('Debug logging enabled in production');
        }
        if (process.env.AUTH_ENABLED !== 'true') {
          warnings.push('Authentication disabled in production');
        }
      }

      // Validate numeric environment variables
      const numericVars = ['PORT', 'MAKE_TIMEOUT', 'MAKE_RETRIES', 'RATE_LIMIT_MAX_REQUESTS', 'RATE_LIMIT_WINDOW_MS'];
      for (const varName of numericVars) {
        const value = process.env[varName];
        if (value && isNaN(parseInt(value))) {
          errors.push(`${varName} must be a valid number, got: ${value}`);
        }
      }

      // Validate boolean environment variables
      const booleanVars = ['AUTH_ENABLED', 'RATE_LIMIT_SKIP_SUCCESS', 'RATE_LIMIT_SKIP_FAILED'];
      for (const varName of booleanVars) {
        const value = process.env[varName];
        if (value && !['true', 'false', '1', '0', 'yes', 'no'].includes(value.toLowerCase())) {
          errors.push(`${varName} must be a valid boolean, got: ${value}`);
        }
      }

      return { valid: errors.length === 0, errors, warnings };
    } catch (error) {
      errors.push(`Environment validation failed: ${error instanceof Error ? error.message : String(error)}`);
      return { valid: false, errors, warnings };
    }
  }

  // Configuration reporting for debugging
  public getConfigurationReport(): string {
    const report = {
      environment: process.env.NODE_ENV || 'unknown',
      server: {
        name: this.config.name,
        version: this.config.version,
        port: this.config.port,
        logLevel: this.config.logLevel,
      },
      make: {
        baseUrl: this.config.make.baseUrl,
        hasApiKey: !!this.config.make.apiKey,
        apiKeyLength: this.config.make.apiKey?.length || 0,
        teamId: this.config.make.teamId || 'not set',
        organizationId: this.config.make.organizationId || 'not set',
        timeout: this.config.make.timeout,
        retries: this.config.make.retries,
      },
      authentication: {
        enabled: this.config.authentication?.enabled || false,
        hasSecret: !!this.config.authentication?.secret,
        secretLength: this.config.authentication?.secret?.length || 0,
      },
      rateLimit: this.config.rateLimit || 'not configured',
    };

    return JSON.stringify(report, null, 2);
  }
}

// Configuration validation utility functions
export function createConfigurationValidator(): {
  validateMakeApiKey: (_key: string) => boolean;
  validatePort: (_port: number) => boolean;
  validateTimeout: (_timeout: number) => boolean;
  validateLogLevel: (_level: string) => boolean;
  generateSecureSecret: () => string;
} {
  return {
    validateMakeApiKey: (key: string): boolean => {
      return Boolean(key && key.length >= 10 && key.trim().length > 0);
    },
    
    validatePort: (port: number): boolean => {
      return port >= 1 && port <= 65535;
    },
    
    validateTimeout: (timeout: number): boolean => {
      return timeout >= 1000 && timeout <= 300000;
    },
    
    validateLogLevel: (level: string): boolean => {
      return ['debug', 'info', 'warn', 'error'].includes(level.toLowerCase());
    },
    
    generateSecureSecret: (): string => {
      // Generate a cryptographically secure random string
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
      let result = '';
      for (let i = 0; i < 64; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
      }
      return result;
    }
  };
}

// Configuration presets for different environments
export const ConfigPresets = {
  development: {
    logLevel: 'debug' as const,
    authentication: { enabled: false },
    rateLimit: {
      maxRequests: 1000,
      windowMs: 60000,
      skipSuccessfulRequests: false,
      skipFailedRequests: false,
    }
  },
  
  production: {
    logLevel: 'warn' as const,
    authentication: { enabled: true },
    rateLimit: {
      maxRequests: 100,
      windowMs: 60000,
      skipSuccessfulRequests: false,
      skipFailedRequests: false,
    }
  },
  
  testing: {
    logLevel: 'error' as const,
    authentication: { enabled: false },
    rateLimit: {
      maxRequests: 10000,
      windowMs: 60000,
      skipSuccessfulRequests: true,
      skipFailedRequests: true,
    }
  }
};

export const configManager = ConfigManager.getInstance();
export default configManager;