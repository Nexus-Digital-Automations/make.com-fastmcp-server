/**
 * Mock implementation of Make.com API client for testing
 * Provides realistic responses and error simulation
 */

import { jest } from '@jest/globals';
import { ApiResponse } from '../../src/types/index.js';

export class MockMakeApiClient {
  private responses: Map<string, any> = new Map();
  private failures: Map<string, Error> = new Map(); 
  private delays: Map<string, number> = new Map();
  private callLog: Array<{ method: string; endpoint: string; data?: any }> = [];

  constructor() {
    this.setupDefaultResponses();
  }

  /**
   * Set up default successful responses for common endpoints
   */
  private setupDefaultResponses(): void {
    // User endpoints
    this.responses.set('GET:/users/me', {
      success: true,
      data: globalThis.testUtils.createMockUser(),
    });

    // Scenario endpoints
    this.responses.set('GET:/scenarios', {
      success: true,
      data: [globalThis.testUtils.createMockScenario()],
      metadata: { total: 1, page: 1, limit: 20 },
    });

    // Connection endpoints
    this.responses.set('GET:/connections', {
      success: true,
      data: [globalThis.testUtils.createMockConnection()],
      metadata: { total: 1, page: 1, limit: 20 },
    });

    // Default success response for any unmatched endpoint
    this.responses.set('DEFAULT', {
      success: true,
      data: { message: 'Mock response' },
    });
  }

  /**
   * Mock a successful response for a specific endpoint
   */
  mockResponse(method: string, endpoint: string, response: any): void {
    const key = `${method.toUpperCase()}:${endpoint}`;
    this.responses.set(key, response);
  }

  /**
   * Alias for mockResponse for backward compatibility
   */
  setMockResponse(method: string, endpoint: string, response: any): void {
    this.mockResponse(method, endpoint, response);
  }

  /**
   * Mock a failure response for a specific endpoint
   */
  mockFailure(method: string, endpoint: string, error: Error): void {
    const key = `${method.toUpperCase()}:${endpoint}`;
    this.failures.set(key, error);
  }

  /**
   * Alias for mockFailure for backward compatibility
   */
  mockError(method: string, endpoint: string, error: Error): void {
    this.mockFailure(method, endpoint, error);
  }

  /**
   * Mock network delay for a specific endpoint
   */
  mockDelay(method: string, endpoint: string, delayMs: number): void {
    const key = `${method.toUpperCase()}:${endpoint}`;
    this.delays.set(key, delayMs);
  }

  /**
   * Get call log for testing purposes
   */
  getCallLog(): Array<{ method: string; endpoint: string; data?: any }> {
    return [...this.callLog];
  }

  /**
   * Clear call log
   */
  clearCallLog(): void {
    this.callLog = [];
  }

  /**
   * Reset all mocks to defaults
   */
  reset(): void {
    this.responses.clear();
    this.failures.clear();
    this.delays.clear();
    this.callLog = [];
    this.setupDefaultResponses();
  }

  /**
   * Simulate API call with mocked response
   */
  private async simulateCall(method: string, endpoint: string, data?: any): Promise<ApiResponse> {
    const key = `${method.toUpperCase()}:${endpoint}`;
    
    // Log the call
    this.callLog.push({ method: method.toUpperCase(), endpoint, data });

    // Simulate delay if configured
    const delay = this.delays.get(key);
    if (delay) {
      await globalThis.testUtils.delay(delay);
    }

    // Check for configured failure
    const failure = this.failures.get(key);
    if (failure) {
      throw failure;
    }

    // Return configured response or default
    const response = this.responses.get(key) || this.responses.get('DEFAULT');
    
    // Ensure the response is properly structured as ApiResponse
    if (!response) {
      return {
        success: false,
        error: {
          message: 'No mock response configured',
          code: 'MOCK_ERROR'
        }
      };
    }

    // Return the response as-is since it should already be properly formatted
    return response;
  }

  // HTTP method implementations (with Jest spy tracking)
  get = jest.fn(async (endpoint: string, options?: any): Promise<ApiResponse> => {
    return this.simulateCall('GET', endpoint, options?.params);
  });

  post = jest.fn(async (endpoint: string, data?: any, options?: any): Promise<ApiResponse> => {
    return this.simulateCall('POST', endpoint, data);
  });

  put = jest.fn(async (endpoint: string, data?: any, options?: any): Promise<ApiResponse> => {
    return this.simulateCall('PUT', endpoint, data);
  });

  patch = jest.fn(async (endpoint: string, data?: any, options?: any): Promise<ApiResponse> => {
    return this.simulateCall('PATCH', endpoint, data);
  });

  delete = jest.fn(async (endpoint: string, options?: any): Promise<ApiResponse> => {
    return this.simulateCall('DELETE', endpoint, options?.params);
  });

  // Health check method
  async healthCheck(): Promise<boolean> {
    try {
      await this.get('/users/me');
      return true;
    } catch {
      return false;
    }
  }

  // Rate limiter status (mock)
  getRateLimiterStatus(): any {
    return {
      remaining: 100,
      resetTime: Date.now() + 60000,
      limit: 100,
    };
  }

  // Shutdown method (mock)
  async shutdown(): Promise<void> {
    // Mock implementation - no actual cleanup needed
  }
}

/**
 * Factory function to create mock API client
 */
export const createMockApiClient = (): MockMakeApiClient => {
  return new MockMakeApiClient();
};

/**
 * Jest mock factory for automatic mocking
 */
export const mockMakeApiClient = jest.fn(() => createMockApiClient());

export default MockMakeApiClient;