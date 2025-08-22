/**
 * Make.com API Client with rate limiting, retry logic, and error handling
 * Provides robust interface to Make.com API endpoints with secure credential management
 */

import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios';
import Bottleneck from 'bottleneck';
import { MakeApiConfig, ApiResponse, MakeApiError } from '../types/index.js';
import logger from './logger.js';
import { secureConfigManager } from './secure-config.js';

export class MakeApiClient {
  private readonly axiosInstance: AxiosInstance;
  private readonly limiter: Bottleneck;
  private config: MakeApiConfig;
  private readonly componentLogger: ReturnType<typeof logger.child>;
  private readonly userId?: string;

  constructor(config: MakeApiConfig, userId?: string) {
    this.config = config;
    this.userId = userId;
    this.componentLogger = logger.child({ component: 'MakeApiClient' });
    
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
      const componentLogger = logger.child({ component: 'MakeApiClient' });
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
      
      // Update the authorization header
      this.axiosInstance.defaults.headers.Authorization = `Token ${secureConfig.apiKey}`;
      this.config = secureConfig;
      
      this.componentLogger.info('API credentials refreshed successfully', {
        userId: this.userId
      });
    } catch (error) {
      this.componentLogger.error('Failed to refresh API credentials', {
        error: error instanceof Error ? error.message : 'Unknown error',
        userId: this.userId
      });
      throw error;
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
    const makeError = new Error() as MakeApiError;
    
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
      makeError.message = (error as Error)?.message || String(error) || 'Unknown API client error';
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
        lastError = error as MakeApiError;
        
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

  // Health check method
  public async healthCheck(): Promise<boolean> {
    try {
      const response = await this.get('/users/me');
      return response.success;
    } catch (error) {
      this.componentLogger.error('Health check failed', error as Record<string, unknown>);
      return false;
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

  // Graceful shutdown
  public async shutdown(): Promise<void> {
    this.componentLogger.info('Shutting down API client');
    await this.limiter.stop({ dropWaitingJobs: false });
  }
}

export default MakeApiClient;