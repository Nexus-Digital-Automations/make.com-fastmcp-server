/**
 * Make.com API Client with rate limiting, retry logic, and error handling
 * Provides robust interface to Make.com API endpoints
 */

import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios';
import Bottleneck from 'bottleneck';
import { MakeApiConfig, ApiResponse, MakeApiError } from '../types/index.js';
import logger from './logger.js';

export class MakeApiClient {
  private axiosInstance: AxiosInstance;
  private limiter: Bottleneck;
  private config: MakeApiConfig;
  private componentLogger: ReturnType<typeof logger.child>;

  constructor(config: MakeApiConfig) {
    this.config = config;
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

  private handleAxiosError(error: any): MakeApiError {
    const makeError = new Error() as MakeApiError;
    
    if (error.response) {
      // Server responded with error status
      makeError.message = error.response.data?.message || error.response.statusText || 'API request failed';
      makeError.status = error.response.status;
      makeError.code = error.response.data?.code || `HTTP_${error.response.status}`;
      makeError.details = error.response.data;
      
      // Determine if error is retryable
      makeError.retryable = error.response.status >= 500 || error.response.status === 429;
    } else if (error.request) {
      // Network error
      makeError.message = 'Network error - no response received';
      makeError.code = 'NETWORK_ERROR';
      makeError.retryable = true;
    } else {
      // Request configuration error
      makeError.message = error.message || 'Unknown API client error';
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
    let lastError: MakeApiError;
    
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
        message: lastError!.message,
        code: lastError!.code,
        details: lastError!.details,
      },
    };
  }

  // Generic HTTP methods
  public async get<T = any>(url: string, config?: AxiosRequestConfig): Promise<ApiResponse<T>> {
    return this.executeWithRetry(
      () => this.axiosInstance.get<T>(url, config),
      `GET ${url}`
    );
  }

  public async post<T = any>(url: string, data?: any, config?: AxiosRequestConfig): Promise<ApiResponse<T>> {
    return this.executeWithRetry(
      () => this.axiosInstance.post<T>(url, data, config),
      `POST ${url}`
    );
  }

  public async put<T = any>(url: string, data?: any, config?: AxiosRequestConfig): Promise<ApiResponse<T>> {
    return this.executeWithRetry(
      () => this.axiosInstance.put<T>(url, data, config),
      `PUT ${url}`
    );
  }

  public async patch<T = any>(url: string, data?: any, config?: AxiosRequestConfig): Promise<ApiResponse<T>> {
    return this.executeWithRetry(
      () => this.axiosInstance.patch<T>(url, data, config),
      `PATCH ${url}`
    );
  }

  public async delete<T = any>(url: string, config?: AxiosRequestConfig): Promise<ApiResponse<T>> {
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
      this.componentLogger.error('Health check failed', error);
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