/**
 * External service integrations for folders module
 * Generated on 2025-08-22T09:20:06.378Z
 */

import logger from '../../../lib/logger.js';

/**
 * Service client for external integrations
 */
export class FoldersServiceClient {
  private readonly baseUrl: string;
  private readonly headers: Record<string, string>;

  constructor(baseUrl: string, apiKey?: string) {
    this.baseUrl = baseUrl;
    this.headers = {
      'Content-Type': 'application/json',
      'User-Agent': 'Make-FastMCP-Folders/1.0'
    };

    if (apiKey) {
      this.headers.Authorization = `Bearer ${apiKey}`;
    }
  }

  /**
   * Make HTTP request to external service
   */
  async makeRequest(endpoint: string, options: {
    method?: 'GET' | 'POST' | 'PUT' | 'DELETE';
    data?: unknown;
    params?: Record<string, string>;
  } = {}): Promise<unknown> {
    const { method = 'GET', data, params } = options;

    try {
      const url = new URL(endpoint, this.baseUrl);
      
      if (params) {
        Object.entries(params).forEach(([key, value]) => {
          url.searchParams.append(key, value);
        });
      }

      const response = await fetch(url.toString(), {
        method,
        headers: this.headers,
        body: data ? JSON.stringify(data) : undefined
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const result = await response.json();
      
      logger.debug('External service request completed', {
        module: 'folders',
        endpoint,
        method,
        status: response.status
      });

      return result;
    } catch (error) {
      logger.error('External service request failed', {
        module: 'folders',
        endpoint,
        method,
        error: error instanceof Error ? error.message : String(error)
      });
      throw error;
    }
  }

  /**
   * Health check for external service
   */
  async healthCheck(): Promise<boolean> {
    try {
      await this.makeRequest('/health');
      return true;
    } catch (error) {
      logger.warn('External service health check failed', {
        module: 'folders',
        error: error instanceof Error ? error.message : String(error)
      });
      return false;
    }
  }
}

/**
 * Factory function to create service client
 */
export function createFoldersServiceClient(): FoldersServiceClient {
  const baseUrl = process.env.FOLDERS_SERVICE_URL || 'http://localhost:3000';
  const apiKey = process.env.FOLDERS_API_KEY;
  
  return new FoldersServiceClient(baseUrl, apiKey);
}
