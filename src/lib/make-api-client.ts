/**
 * Make.com API Client with rate limiting, retry logic, and error handling
 * Provides robust interface to Make.com API endpoints with secure credential management
 */

import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios';
import Bottleneck from 'bottleneck';
import { MakeApiConfig, ApiResponse, MakeApiError } from '../types/index.js';
import logger from './logger.js';
import { secureConfigManager } from './secure-config.js';
import { credentialSecurityValidator } from './credential-security-validator.js';

export class MakeApiClient {
  private readonly axiosInstance: AxiosInstance;
  private readonly limiter: Bottleneck;
  private config: MakeApiConfig;
  private readonly componentLogger: ReturnType<typeof logger.child>;
  private readonly userId?: string;

  constructor(config: MakeApiConfig, userId?: string) {
    this.config = config;
    this.userId = userId;
    const getComponentLogger = (): ReturnType<typeof logger.child> => {
      try {
        return logger.child({ component: 'MakeApiClient' });
      } catch {
        // Fallback for test environments
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        return logger as any;
      }
    };
    this.componentLogger = getComponentLogger();
    
    // Validate API key security on initialization
    this.validateCredentialSecurity(config.apiKey);
    
    this.axiosInstance = axios.create({
      baseURL: config.baseUrl,
      timeout: config.timeout || 30000,
      headers: {
        'Authorization': `Token ${config.apiKey}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
    });

    // Initialize rate limiter (Make.com allows 10 requests per second)
    this.limiter = new Bottleneck({
      minTime: 100, // 100ms between requests (10 req/sec)
      maxConcurrent: 5,
      reservoir: 600, // 600 requests per minute
      reservoirRefreshAmount: 600,
      reservoirRefreshInterval: 60 * 1000, // 1 minute
    });

    this.setupInterceptors();
  }

  /**
   * Create a MakeApiClient instance with secure credential management
   */
  public static async createSecure(userId?: string): Promise<MakeApiClient> {
    try {
      const secureConfig = await secureConfigManager.getSecureMakeConfig(userId);
      return new MakeApiClient(secureConfig, userId);
    } catch (error) {
      const getComponentLogger = (): ReturnType<typeof logger.child> => {
    try {
      return logger.child({ component: 'MakeApiClient' });
    } catch {
      // Fallback for test environments
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      return logger as any;
    }
  };
  const componentLogger = getComponentLogger();
      componentLogger.error('Failed to create secure API client', {
        error: error instanceof Error ? error.message : 'Unknown error',
        userId
      });
      throw error;
    }
  }

  /**
   * Refresh API credentials (useful after credential rotation)
   */
  public async refreshCredentials(): Promise<void> {
    try {
      const secureConfig = await secureConfigManager.getSecureMakeConfig(this.userId);
      
      // Validate new credentials before using them
      this.validateCredentialSecurity(secureConfig.apiKey);
      
      // Update the authorization header
      this.axiosInstance.defaults.headers.Authorization = `Token ${secureConfig.apiKey}`;
      this.config = secureConfig;
      
      this.componentLogger.info('API credentials refreshed successfully', {
        userId: this.userId,
        credentialValidated: true
      });
    } catch (error) {
      this.componentLogger.error('Failed to refresh API credentials', {
        error: error instanceof Error ? error.message : 'Unknown error',
        userId: this.userId
      });
      throw error;
    }
  }

  /**
   * Validate credential security and log warnings
   */
  private validateCredentialSecurity(apiKey: string): void {
    try {
      const validation = credentialSecurityValidator.validateMakeApiKey(apiKey);
      
      if (!validation.isValid) {
        this.componentLogger.error('API key validation failed', {
          errors: validation.errors,
          score: validation.score
        });
        throw new Error(`API key validation failed: ${validation.errors.join(', ')}`);
      }
      
      if (validation.score < 70) {
        this.componentLogger.warn('API key security score below recommended threshold', {
          score: validation.score,
          warnings: validation.warnings,
          recommendations: validation.recommendations
        });
      }
      
      if (validation.warnings.length > 0) {
        this.componentLogger.warn('API key security warnings detected', {
          warnings: validation.warnings,
          score: validation.score
        });
      }
      
      this.componentLogger.debug('API key validation completed', {
        isValid: validation.isValid,
        score: validation.score,
        strengths: validation.strengths
      });
    } catch (error) {
      this.componentLogger.error('Failed to validate API key security', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Check if credentials need rotation based on age and security policy
   */
  public async checkCredentialRotation(): Promise<{
    needsRotation: boolean;
    recommendation: string;
    daysUntilExpiry?: number;
  }> {
    try {
      // Get credential metadata if available
      const credentialId = process.env.MAKE_API_KEY_CREDENTIAL_ID;
      if (!credentialId) {
        return {
          needsRotation: false,
          recommendation: 'Using non-managed credential - consider migrating to secure storage'
        };
      }
      
      const status = secureConfigManager.getCredentialStatus(credentialId);
      
      if (status.status === 'not_found') {
        return {
          needsRotation: true,
          recommendation: 'Credential not found in secure storage - immediate rotation required'
        };
      }
      
      const needsRotation = ['rotation_due', 'expired'].includes(status.status);
      
      return {
        needsRotation,
        recommendation: this.getRotationRecommendation(status.status, status.daysUntilRotation),
        daysUntilExpiry: status.daysUntilRotation
      };
    } catch (error) {
      this.componentLogger.error('Failed to check credential rotation status', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      return {
        needsRotation: true,
        recommendation: 'Unable to verify credential status - rotation recommended'
      };
    }
  }

  /**
   * Get rotation recommendation based on credential status
   */
  private getRotationRecommendation(status: string, daysUntilRotation?: number): string {
    switch (status) {
      case 'expired':
        return 'Credential has expired - immediate rotation required';
      case 'rotation_due':
        return 'Credential rotation is due - rotate as soon as possible';
      case 'healthy':
        if (daysUntilRotation && daysUntilRotation <= 14) {
          return `Credential rotation due in ${daysUntilRotation} days - plan rotation soon`;
        }
        return 'Credential is healthy - no immediate action required';
      default:
        return 'Unknown credential status - verify configuration';
    }
  }

  private setupInterceptors(): void {
    // Request interceptor for logging
    this.axiosInstance.interceptors.request.use(
      (config) => {
        this.componentLogger.debug('API Request', {
          method: config.method?.toUpperCase(),
          url: config.url,
          params: config.params,
        });
        return config;
      },
      (error) => {
        this.componentLogger.error('Request interceptor error', error);
        return Promise.reject(error);
      }
    );

    // Response interceptor for logging and error handling
    this.axiosInstance.interceptors.response.use(
      (response) => {
        this.componentLogger.debug('API Response', {
          status: response.status,
          url: response.config.url,
          dataSize: JSON.stringify(response.data).length,
        });
        return response;
      },
      (error) => {
        const makeError = this.handleAxiosError(error);
        this.componentLogger.error('API Error', {
          message: makeError.message,
          code: makeError.code,
          status: makeError.status,
          retryable: makeError.retryable,
        });
        return Promise.reject(makeError);
      }
    );
  }

  private handleAxiosError(error: unknown): MakeApiError {
    const makeError = new Error('API client error') as MakeApiError;
    
    // Type guard for axios error
    const axiosError = error as {
      response?: {
        data?: { message?: string };
        statusText?: string;
        status?: number;
      };
      request?: unknown;
      message?: string;
    };
    
    if (axiosError?.response) {
      // Server responded with error status
      makeError.message = axiosError.response.data?.message || axiosError.response.statusText || 'API request failed';
      makeError.status = axiosError.response.status;
      makeError.code = (axiosError.response.data as { code?: string })?.code || `HTTP_${axiosError.response?.status}` || 'HTTP_UNKNOWN';
      makeError.details = axiosError.response.data;
      
      // Determine if error is retryable
      makeError.retryable = (axiosError.response?.status || 0) >= 500 || axiosError.response?.status === 429;
    } else if (axiosError?.request) {
      // Network error
      makeError.message = 'Network error - no response received';
      makeError.code = 'NETWORK_ERROR';
      makeError.retryable = true;
    } else {
      // Request configuration error
      if (error === undefined) {
        makeError.message = 'Unknown API client error';
      } else {
        makeError.message = (error as Error)?.message || String(error) || 'Unknown API client error';
      }
      makeError.code = 'CLIENT_ERROR';
      makeError.retryable = false;
    }
    
    makeError.name = 'MakeApiError';
    return makeError;
  }

  private async executeWithRetry<T>(
    operation: () => Promise<AxiosResponse<T>>,
    operationName: string,
    retries: number = this.config.retries || 3
  ): Promise<ApiResponse<T>> {
    let lastError: MakeApiError | undefined;
    
    for (let attempt = 1; attempt <= retries; attempt++) {
      try {
        this.componentLogger.debug(`Executing ${operationName}`, { attempt, maxRetries: retries });
        
        const response = await this.limiter.schedule(() => operation());
        
        return {
          success: true,
          data: response.data,
          metadata: {
            total: response.headers['x-total-count'] ? parseInt(response.headers['x-total-count']) : undefined,
            page: response.headers['x-page'] ? parseInt(response.headers['x-page']) : undefined,
            limit: response.headers['x-per-page'] ? parseInt(response.headers['x-per-page']) : undefined,
          },
        };
      } catch (error) {
        // Ensure error is properly processed, especially for null/undefined cases
        if (error && typeof error === 'object' && 'name' in error && error.name === 'MakeApiError') {
          lastError = error as MakeApiError;
        } else {
          // Process unknown/null/undefined errors through handleAxiosError
          lastError = this.handleAxiosError(error);
        }
        
        if (!lastError.retryable || attempt === retries) {
          break;
        }
        
        // Exponential backoff with jitter
        const delay = Math.min(1000 * Math.pow(2, attempt - 1) + Math.random() * 1000, 30000);
        this.componentLogger.warn(`Retrying ${operationName} in ${delay}ms`, {
          attempt,
          error: lastError.message,
        });
        
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
    
    return {
      success: false,
      error: {
        message: lastError?.message ?? 'Unknown error',
        code: lastError?.code ?? 'UNKNOWN',
        details: typeof lastError?.details === 'object' ? lastError.details : { message: lastError?.details ?? 'No error details available' },
      },
    };
  }

  // Generic HTTP methods
  public async get<T = unknown>(url: string, config?: AxiosRequestConfig): Promise<ApiResponse<T>> {
    return this.executeWithRetry(
      () => this.axiosInstance.get<T>(url, config),
      `GET ${url}`
    );
  }

  public async post<T = unknown>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<ApiResponse<T>> {
    return this.executeWithRetry(
      () => this.axiosInstance.post<T>(url, data, config),
      `POST ${url}`
    );
  }

  public async put<T = unknown>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<ApiResponse<T>> {
    return this.executeWithRetry(
      () => this.axiosInstance.put<T>(url, data, config),
      `PUT ${url}`
    );
  }

  public async patch<T = unknown>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<ApiResponse<T>> {
    return this.executeWithRetry(
      () => this.axiosInstance.patch<T>(url, data, config),
      `PATCH ${url}`
    );
  }

  public async delete<T = unknown>(url: string, config?: AxiosRequestConfig): Promise<ApiResponse<T>> {
    return this.executeWithRetry(
      () => this.axiosInstance.delete<T>(url, config),
      `DELETE ${url}`
    );
  }

  // Enhanced health check with credential validation
  public async healthCheck(): Promise<{
    healthy: boolean;
    credentialValid: boolean;
    rotationNeeded: boolean;
    securityScore?: number;
    issues: string[];
  }> {
    const issues: string[] = [];
    let healthy = false;
    let credentialValid = true;
    let rotationNeeded = false;
    let securityScore: number | undefined;
    
    try {
      // Check credential security first
      const validation = credentialSecurityValidator.validateMakeApiKey(this.config.apiKey);
      credentialValid = validation.isValid;
      securityScore = validation.score;
      
      if (!credentialValid) {
        issues.push(`Credential validation failed: ${validation.errors.join(', ')}`);
      }
      
      if (validation.score < 60) {
        issues.push(`Low security score: ${validation.score}/100`);
      }
      
      // Check rotation requirements
      const rotationCheck = await this.checkCredentialRotation();
      rotationNeeded = rotationCheck.needsRotation;
      
      if (rotationNeeded) {
        issues.push(rotationCheck.recommendation);
      }
      
      // Test API connectivity
      const response = await this.get('/users/me');
      healthy = response.success;
      
      if (!healthy) {
        issues.push('API connectivity test failed');
      }
      
      return {
        healthy: healthy && credentialValid,
        credentialValid,
        rotationNeeded,
        securityScore,
        issues
      };
    } catch (error) {
      issues.push(`Health check error: ${error instanceof Error ? error.message : 'Unknown error'}`);
      this.componentLogger.error('Enhanced health check failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
        issues
      });
      
      return {
        healthy: false,
        credentialValid: false,
        rotationNeeded: true,
        issues
      };
    }
  }

  // Get rate limiter status
  public getRateLimiterStatus(): {
    running: number;
    queued: number;
  } {
    const running = this.limiter.running();
    const queued = this.limiter.queued();
    return {
      running: typeof running === 'number' ? running : 0,
      queued: typeof queued === 'number' ? queued : 0,
    };
  }

  // Graceful shutdown with credential cleanup
  public async shutdown(): Promise<void> {
    this.componentLogger.info('Shutting down API client');
    
    try {
      // Check and log final credential status
      const rotationCheck = await this.checkCredentialRotation();
      if (rotationCheck.needsRotation) {
        this.componentLogger.warn('Credential rotation needed before next startup', {
          recommendation: rotationCheck.recommendation
        });
      }
      
      await this.limiter.stop({ dropWaitingJobs: false });
      this.componentLogger.info('API client shutdown completed successfully');
    } catch (error) {
      this.componentLogger.error('Error during API client shutdown', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      // Still attempt to stop the limiter
      await this.limiter.stop({ dropWaitingJobs: true });
    }
  }
}

export default MakeApiClient;