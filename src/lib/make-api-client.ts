/**
 * Make.com API Client with rate limiting, retry logic, and error handling
 * Provides robust interface to Make.com API endpoints with secure credential management
 */

import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios';
import Bottleneck from 'bottleneck';
import { MakeApiConfig, ApiResponse, MakeApiError } from '../types/index.js';
import { ComponentLogger } from '../types/logger.js';
import { secureConfigManager } from './secure-config.js';
import { createComponentLogger } from '../utils/logger-factory.js';
import { credentialSecurityValidator } from './credential-security-validator.js';
import { OAuth21Authenticator } from './oauth-authenticator.js';
import { getMakeOAuthConfig } from '../config/make-oauth-config.js';
import { AuthenticationError } from '../utils/errors.js';

/**
 * Type definition for axios-like error structure
 */
interface AxiosErrorLike {
  response?: {
    data?: { message?: string };
    statusText?: string;
    status?: number;
  };
  request?: unknown;
  message?: string;
}

export class MakeApiClient {
  private readonly axiosInstance: AxiosInstance;
  private readonly limiter: Bottleneck;
  private config: MakeApiConfig;
  private readonly componentLogger: ComponentLogger;
  private readonly userId?: string;
  
  // OAuth 2.1 + PKCE support
  private readonly oauthClient?: OAuth21Authenticator;
  private currentAccessToken?: string;
  private tokenExpiry?: Date;
  private readonly useOAuth: boolean;

  constructor(config: MakeApiConfig, userId?: string, accessToken?: string) {
    this.config = config;
    this.userId = userId;
    this.useOAuth = !!accessToken;
    this.currentAccessToken = accessToken;
    
    this.componentLogger = createComponentLogger({
      component: 'MakeApiClient',
      metadata: { userId, useOAuth: this.useOAuth },
    });
    
    // Initialize OAuth client if using OAuth authentication
    if (this.useOAuth) {
      try {
        const oauthConfig = getMakeOAuthConfig();
        this.oauthClient = new OAuth21Authenticator({
          clientId: oauthConfig.clientId,
          clientSecret: oauthConfig.clientSecret,
          redirectUri: oauthConfig.redirectUri,
          scope: oauthConfig.scope,
          tokenEndpoint: oauthConfig.tokenEndpoint,
          authEndpoint: oauthConfig.authEndpoint,
          revokeEndpoint: oauthConfig.revokeEndpoint,
          usePKCE: oauthConfig.usePKCE,
        });
        
        this.componentLogger.info('OAuth authentication mode enabled', {
          clientId: oauthConfig.clientId,
          hasAccessToken: !!accessToken,
        });
      } catch (error) {
        this.componentLogger.warn('OAuth configuration failed, falling back to API key', { error });
        this.useOAuth = false;
      }
    }
    
    // Validate credentials based on authentication method
    if (this.useOAuth) {
      if (!accessToken) {
        throw new AuthenticationError('Access token required for OAuth authentication');
      }
    } else {
      this.validateCredentialSecurity(config.apiKey);
    }
    
    // Create axios instance with appropriate authentication
    const authHeaders = this.useOAuth && accessToken
      ? { 'Authorization': `Bearer ${accessToken}` }
      : { 'Authorization': `Token ${config.apiKey}` };
    
    this.axiosInstance = axios.create({
      baseURL: config.baseUrl,
      timeout: config.timeout || 30000,
      headers: {
        ...authHeaders,
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
      const componentLogger = createComponentLogger({
        component: 'MakeApiClient',
        metadata: { operation: 'createSecure', userId },
      });
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
      const validation = credentialSecurityValidator().validateMakeApiKey(apiKey);
      
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
    
    const axiosError = this.castToAxiosError(error);
    
    if (axiosError?.response) {
      this.handleResponseError(makeError, axiosError.response);
    } else if (axiosError?.request) {
      this.handleNetworkError(makeError);
    } else {
      this.handleClientError(makeError, error);
    }
    
    makeError.name = 'MakeApiError';
    return makeError;
  }

  /**
   * Cast unknown error to axios error structure
   */
  private castToAxiosError(error: unknown): AxiosErrorLike {
    return error as AxiosErrorLike;
  }

  /**
   * Handle HTTP response errors with status codes
   */
  private handleResponseError(makeError: MakeApiError, response: AxiosErrorLike['response']): void {
    if (!response) {return;}
    
    makeError.message = this.extractErrorMessage(response);
    makeError.status = response.status;
    makeError.code = this.generateErrorCode(response);
    makeError.details = response.data;
    makeError.retryable = this.isRetryableStatus(response.status);
  }

  /**
   * Handle network connectivity errors
   */
  private handleNetworkError(makeError: MakeApiError): void {
    makeError.message = 'Network error - no response received';
    makeError.code = 'NETWORK_ERROR';
    makeError.retryable = true;
  }

  /**
   * Handle client configuration errors
   */
  private handleClientError(makeError: MakeApiError, error: unknown): void {
    makeError.message = this.extractClientErrorMessage(error);
    makeError.code = 'CLIENT_ERROR';
    makeError.retryable = false;
  }

  /**
   * Extract error message from response with fallbacks
   */
  private extractErrorMessage(response: AxiosErrorLike['response']): string {
    if (!response) {return 'API request failed';}
    return response.data?.message || response.statusText || 'API request failed';
  }

  /**
   * Generate error code from response data and status
   */
  private generateErrorCode(response: AxiosErrorLike['response']): string {
    if (!response) {return 'HTTP_UNKNOWN';}
    return (response.data as { code?: string })?.code || `HTTP_${response.status}` || 'HTTP_UNKNOWN';
  }

  /**
   * Determine if HTTP status code indicates retryable error
   */
  private isRetryableStatus(status: number | undefined): boolean {
    return (status || 0) >= 500 || status === 429;
  }

  /**
   * Extract error message from client error with fallbacks
   */
  private extractClientErrorMessage(error: unknown): string {
    if (error === undefined) {
      return 'Unknown API client error';
    }
    return (error as Error)?.message || String(error) || 'Unknown API client error';
  }

  private async executeWithRetry<T>(
    operation: () => Promise<AxiosResponse<T>>,
    operationName: string,
    retries: number = this.config.retries || 3
  ): Promise<ApiResponse<T>> {
    let lastError: MakeApiError | undefined;
    
    for (let attempt = 1; attempt <= retries; attempt++) {
      try {
        const response = await this.executeOperation(operation, operationName, attempt, retries);
        return this.createSuccessResponse(response);
      } catch (error) {
        lastError = this.handleRetryError(error);
        
        if (!this.shouldRetry(lastError, attempt, retries)) {
          break;
        }
        
        await this.delayRetry(operationName, attempt, lastError);
      }
    }
    
    return this.createErrorResponse(lastError);
  }

  /**
   * Execute a single operation with logging
   */
  private async executeOperation<T>(
    operation: () => Promise<AxiosResponse<T>>,
    operationName: string,
    attempt: number,
    maxRetries: number
  ): Promise<AxiosResponse<T>> {
    this.componentLogger.debug(`Executing ${operationName}`, { attempt, maxRetries });
    return await this.limiter.schedule(() => operation());
  }

  /**
   * Create a successful API response object
   */
  private createSuccessResponse<T>(response: AxiosResponse<T>): ApiResponse<T> {
    return {
      success: true,
      data: response.data,
      metadata: {
        total: response.headers['x-total-count'] ? parseInt(response.headers['x-total-count']) : undefined,
        page: response.headers['x-page'] ? parseInt(response.headers['x-page']) : undefined,
        limit: response.headers['x-per-page'] ? parseInt(response.headers['x-per-page']) : undefined,
      },
    };
  }

  /**
   * Handle and process retry errors
   */
  private handleRetryError(error: unknown): MakeApiError {
    if (error && typeof error === 'object' && 'name' in error && error.name === 'MakeApiError') {
      return error as MakeApiError;
    } else {
      return this.handleAxiosError(error);
    }
  }

  /**
   * Determine if operation should be retried
   */
  private shouldRetry(error: MakeApiError, attempt: number, maxRetries: number): boolean {
    return error.retryable && attempt < maxRetries;
  }

  /**
   * Handle retry delay with exponential backoff and jitter
   */
  private async delayRetry(
    operationName: string,
    attempt: number,
    error: MakeApiError
  ): Promise<void> {
    const delay = this.calculateRetryDelay(attempt);
    this.componentLogger.warn(`Retrying ${operationName} in ${delay}ms`, {
      attempt,
      error: error.message,
    });
    
    await new Promise(resolve => setTimeout(resolve, delay));
  }

  /**
   * Calculate retry delay with exponential backoff and jitter
   */
  private calculateRetryDelay(attempt: number): number {
    return Math.min(1000 * Math.pow(2, attempt - 1) + Math.random() * 1000, 30000);
  }

  /**
   * Create an error API response object
   */
  private createErrorResponse<T>(lastError?: MakeApiError): ApiResponse<T> {
    return {
      success: false,
      error: {
        message: lastError?.message ?? 'Unknown error',
        code: lastError?.code ?? 'UNKNOWN',
        details: typeof lastError?.details === 'object' 
          ? lastError.details 
          : { message: lastError?.details ?? 'No error details available' },
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
      const validation = credentialSecurityValidator().validateMakeApiKey(this.config.apiKey);
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

  /**
   * Update OAuth access token for authenticated requests
   * @param accessToken New access token
   * @param expiresIn Token expiry time in seconds
   */
  public updateAccessToken(accessToken: string, expiresIn?: number): void {
    if (!this.useOAuth) {
      throw new AuthenticationError('Cannot update access token for non-OAuth client');
    }

    this.currentAccessToken = accessToken;
    this.tokenExpiry = expiresIn 
      ? new Date(Date.now() + expiresIn * 1000)
      : undefined;

    // Update axios headers
    this.axiosInstance.defaults.headers.Authorization = `Bearer ${accessToken}`;

    this.componentLogger.info('Access token updated', {
      hasExpiry: !!this.tokenExpiry,
      expiresAt: this.tokenExpiry?.toISOString(),
    });
  }

  /**
   * Check if current access token is expired or about to expire
   * @param bufferSeconds Buffer time in seconds before expiry (default: 300 = 5 minutes)
   * @returns True if token needs refresh
   */
  public isTokenExpired(bufferSeconds = 300): boolean {
    if (!this.useOAuth || !this.tokenExpiry) {
      return false; // No expiry tracking for API key auth or tokens without expiry
    }

    const now = new Date();
    const expiryWithBuffer = new Date(this.tokenExpiry.getTime() - bufferSeconds * 1000);
    
    return now >= expiryWithBuffer;
  }

  /**
   * Validate current access token with Make.com
   * @returns Token validation result
   */
  public async validateCurrentToken(): Promise<{
    valid: boolean;
    error?: string;
    needsRefresh: boolean;
  }> {
    if (!this.useOAuth || !this.currentAccessToken) {
      return {
        valid: false,
        error: 'No OAuth token available',
        needsRefresh: false,
      };
    }

    try {
      // Check expiry first
      if (this.isTokenExpired()) {
        return {
          valid: false,
          error: 'Token expired',
          needsRefresh: true,
        };
      }

      // Validate with OAuth client if available
      if (this.oauthClient) {
        const validation = await this.oauthClient.validateBearerToken(this.currentAccessToken);
        return {
          valid: validation.valid,
          error: validation.error,
          needsRefresh: !validation.valid,
        };
      }

      // Fallback: Make a test API call to validate token
      try {
        await this.axiosInstance.get('/users/me', {
          timeout: 5000, // Quick validation call
        });
        
        return {
          valid: true,
          needsRefresh: false,
        };
      } catch (error) {
        const isAuthError = axios.isAxiosError(error) && 
          (error.response?.status === 401 || error.response?.status === 403);
        
        return {
          valid: false,
          error: isAuthError ? 'Token authentication failed' : 'Token validation request failed',
          needsRefresh: isAuthError,
        };
      }
    } catch (error) {
      this.componentLogger.error('Token validation failed', { error });
      return {
        valid: false,
        error: 'Token validation error',
        needsRefresh: true,
      };
    }
  }

  /**
   * Get current authentication method information
   * @returns Authentication method details
   */
  public getAuthInfo(): {
    method: 'oauth' | 'apikey';
    hasToken: boolean;
    tokenExpiry?: string;
    isExpired?: boolean;
  } {
    return {
      method: this.useOAuth ? 'oauth' : 'apikey',
      hasToken: this.useOAuth ? !!this.currentAccessToken : !!this.config.apiKey,
      tokenExpiry: this.tokenExpiry?.toISOString(),
      isExpired: this.useOAuth ? this.isTokenExpired() : undefined,
    };
  }

  /**
   * Create a new OAuth-enabled MakeApiClient instance
   * @param config Make.com API configuration
   * @param accessToken OAuth access token
   * @param userId User identifier
   * @returns New MakeApiClient instance with OAuth authentication
   */
  public static createWithOAuth(
    config: MakeApiConfig, 
    accessToken: string, 
    userId?: string
  ): MakeApiClient {
    return new MakeApiClient(config, userId, accessToken);
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