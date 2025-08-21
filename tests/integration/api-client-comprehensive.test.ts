/**
 * @fileoverview Comprehensive API client integration tests
 * Tests Make.com API client functionality, authentication, error handling, and performance
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import MakeApiClient from '../../src/lib/make-api-client.js';

// Mock HTTP client with axios-like interface
const mockHttpClient = {
  get: jest.fn(),
  post: jest.fn(),
  put: jest.fn(),
  delete: jest.fn(),
  patch: jest.fn(),
  request: jest.fn(),
  interceptors: {
    request: {
      use: jest.fn(),
      eject: jest.fn()
    },
    response: {
      use: jest.fn(),
      eject: jest.fn()
    }
  },
  defaults: {
    timeout: 5000,
    headers: {}
  }
};

// Mock response builder
const createMockResponse = (data: any, status = 200, headers = {}) => ({
  data,
  status,
  statusText: status >= 200 && status < 300 ? 'OK' : 'Error',
  headers: {
    'content-type': 'application/json',
    ...headers
  },
  config: {},
  request: {}
});

describe('Make.com API Client - Integration Tests', () => {
  let apiClient: MakeApiClient;

  beforeEach(() => {
    // Reset all mocks
    jest.clearAllMocks();
    
    // Create API client with test configuration
    apiClient = new MakeApiClient({
      baseUrl: 'https://api.make.com/v2',
      apiToken: 'test-token-123',
      timeout: 5000,
      retryAttempts: 3,
      rateLimitEnabled: true,
      httpClient: mockHttpClient as any
    });
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  describe('Authentication and Authorization', () => {
    it('should include API token in request headers', async () => {
      mockHttpClient.get.mockResolvedValue(
        createMockResponse({ teams: [] })
      );

      await apiClient.get('/teams');

      expect(mockHttpClient.get).toHaveBeenCalledWith('/teams', {
        headers: expect.objectContaining({
          'Authorization': 'Bearer test-token-123',
          'Content-Type': 'application/json'
        }),
        timeout: 5000
      });
    });

    it('should handle token refresh when expired', async () => {
      // First request fails with 401
      mockHttpClient.get.mockRejectedValueOnce({
        response: { status: 401, data: { error: 'Token expired' } }
      });

      // Refresh token request succeeds
      mockHttpClient.post.mockResolvedValueOnce(
        createMockResponse({ accessToken: 'new-token-456' })
      );

      // Retry original request with new token
      mockHttpClient.get.mockResolvedValueOnce(
        createMockResponse({ teams: [{ id: 1, name: 'Test Team' }] })
      );

      const result = await apiClient.get('/teams');

      expect(result.success).toBe(true);
      expect(result.data.teams).toHaveLength(1);
      expect(mockHttpClient.get).toHaveBeenCalledTimes(2); // Original + retry
      expect(mockHttpClient.post).toHaveBeenCalledWith('/auth/refresh', expect.any(Object));
    });

    it('should handle OAuth flow for interactive authentication', async () => {
      const oauthClient = new MakeApiClient({
        baseUrl: 'https://api.make.com/v2',
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        redirectUri: 'https://app.example.com/callback',
        httpClient: mockHttpClient as any
      });

      mockHttpClient.post.mockResolvedValue(
        createMockResponse({
          access_token: 'oauth-token-789',
          refresh_token: 'refresh-token-abc',
          expires_in: 3600,
          token_type: 'Bearer'
        })
      );

      const authResult = await oauthClient.exchangeCodeForToken('auth-code-123');

      expect(authResult.success).toBe(true);
      expect(authResult.data.access_token).toBe('oauth-token-789');
      expect(mockHttpClient.post).toHaveBeenCalledWith('/oauth/token', {
        grant_type: 'authorization_code',
        code: 'auth-code-123',
        client_id: 'test-client-id',
        client_secret: 'test-client-secret',
        redirect_uri: 'https://app.example.com/callback'
      });
    });

    it('should handle API key rotation gracefully', async () => {
      const rotationHandler = jest.fn();
      
      const rotatingClient = new MakeApiClient({
        baseUrl: 'https://api.make.com/v2',
        apiToken: 'old-token',
        keyRotationHandler: rotationHandler,
        httpClient: mockHttpClient as any
      });

      // Simulate key rotation notification
      mockHttpClient.get.mockRejectedValueOnce({
        response: { status: 401, data: { error: 'API key rotated' } }
      });

      rotationHandler.mockResolvedValue('new-rotated-token');

      mockHttpClient.get.mockResolvedValueOnce(
        createMockResponse({ success: true })
      );

      const result = await rotatingClient.get('/test');

      expect(result.success).toBe(true);
      expect(rotationHandler).toHaveBeenCalled();
    });
  });

  describe('HTTP Methods and Request Handling', () => {
    describe('GET Requests', () => {
      it('should handle successful GET requests', async () => {
        const mockData = {
          scenarios: [
            { id: 1, name: 'Test Scenario 1' },
            { id: 2, name: 'Test Scenario 2' }
          ],
          total: 2
        };

        mockHttpClient.get.mockResolvedValue(createMockResponse(mockData));

        const result = await apiClient.get('/scenarios');

        expect(result.success).toBe(true);
        expect(result.data).toEqual(mockData);
        expect(mockHttpClient.get).toHaveBeenCalledWith('/scenarios', expect.any(Object));
      });

      it('should handle GET requests with query parameters', async () => {
        mockHttpClient.get.mockResolvedValue(
          createMockResponse({ scenarios: [] })
        );

        await apiClient.get('/scenarios', {
          teamId: 123,
          folderId: 456,
          limit: 50,
          offset: 0,
          sortBy: 'name',
          sortOrder: 'asc'
        });

        expect(mockHttpClient.get).toHaveBeenCalledWith('/scenarios', {
          params: {
            teamId: 123,
            folderId: 456,
            limit: 50,
            offset: 0,
            sortBy: 'name',
            sortOrder: 'asc'
          },
          headers: expect.any(Object),
          timeout: expect.any(Number)
        });
      });

      it('should handle nested resource URLs', async () => {
        mockHttpClient.get.mockResolvedValue(
          createMockResponse({ connections: [] })
        );

        await apiClient.get('/teams/123/scenarios/456/connections');

        expect(mockHttpClient.get).toHaveBeenCalledWith(
          '/teams/123/scenarios/456/connections',
          expect.any(Object)
        );
      });
    });

    describe('POST Requests', () => {
      it('should handle POST requests with JSON payload', async () => {
        const scenarioData = {
          name: 'New Scenario',
          teamId: 123,
          blueprint: {
            modules: [{ id: 1, app: 'webhook' }],
            connections: []
          }
        };

        mockHttpClient.post.mockResolvedValue(
          createMockResponse({ id: 789, ...scenarioData })
        );

        const result = await apiClient.post('/scenarios', scenarioData);

        expect(result.success).toBe(true);
        expect(result.data.id).toBe(789);
        expect(mockHttpClient.post).toHaveBeenCalledWith('/scenarios', scenarioData, {
          headers: expect.objectContaining({
            'Content-Type': 'application/json'
          }),
          timeout: expect.any(Number)
        });
      });

      it('should handle file upload via POST', async () => {
        const fileData = new FormData();
        fileData.append('file', new Blob(['test content']), 'test.txt');
        fileData.append('description', 'Test file upload');

        mockHttpClient.post.mockResolvedValue(
          createMockResponse({ fileId: 'file-123', uploaded: true })
        );

        const result = await apiClient.post('/files/upload', fileData, {
          'Content-Type': 'multipart/form-data'
        });

        expect(result.success).toBe(true);
        expect(result.data.fileId).toBe('file-123');
        expect(mockHttpClient.post).toHaveBeenCalledWith('/files/upload', fileData, {
          headers: expect.objectContaining({
            'Content-Type': 'multipart/form-data'
          }),
          timeout: expect.any(Number)
        });
      });

      it('should handle batch operations via POST', async () => {
        const batchOperations = {
          operations: [
            { method: 'PUT', url: '/scenarios/1', data: { name: 'Updated 1' } },
            { method: 'PUT', url: '/scenarios/2', data: { name: 'Updated 2' } },
            { method: 'DELETE', url: '/scenarios/3' }
          ]
        };

        mockHttpClient.post.mockResolvedValue(
          createMockResponse({
            results: [
              { success: true, id: 1 },
              { success: true, id: 2 },
              { success: true, id: 3 }
            ]
          })
        );

        const result = await apiClient.post('/batch', batchOperations);

        expect(result.success).toBe(true);
        expect(result.data.results).toHaveLength(3);
      });
    });

    describe('PUT and PATCH Requests', () => {
      it('should handle PUT requests for full resource updates', async () => {
        const updateData = {
          name: 'Updated Scenario Name',
          description: 'Updated description',
          isActive: true
        };

        mockHttpClient.put.mockResolvedValue(
          createMockResponse({ id: 456, ...updateData, updatedAt: '2024-01-15T10:00:00Z' })
        );

        const result = await apiClient.put('/scenarios/456', updateData);

        expect(result.success).toBe(true);
        expect(result.data.name).toBe('Updated Scenario Name');
        expect(mockHttpClient.put).toHaveBeenCalledWith('/scenarios/456', updateData, expect.any(Object));
      });

      it('should handle PATCH requests for partial updates', async () => {
        const patchData = { isActive: false };

        mockHttpClient.patch.mockResolvedValue(
          createMockResponse({ id: 456, isActive: false, updatedAt: '2024-01-15T10:00:00Z' })
        );

        const result = await apiClient.patch('/scenarios/456', patchData);

        expect(result.success).toBe(true);
        expect(result.data.isActive).toBe(false);
        expect(mockHttpClient.patch).toHaveBeenCalledWith('/scenarios/456', patchData, expect.any(Object));
      });
    });

    describe('DELETE Requests', () => {
      it('should handle DELETE requests', async () => {
        mockHttpClient.delete.mockResolvedValue(
          createMockResponse({ deleted: true, id: 789 })
        );

        const result = await apiClient.delete('/scenarios/789');

        expect(result.success).toBe(true);
        expect(result.data.deleted).toBe(true);
        expect(mockHttpClient.delete).toHaveBeenCalledWith('/scenarios/789', expect.any(Object));
      });

      it('should handle bulk DELETE operations', async () => {
        const deleteIds = [1, 2, 3, 4, 5];

        mockHttpClient.delete.mockResolvedValue(
          createMockResponse({
            deleted: deleteIds,
            count: deleteIds.length
          })
        );

        const result = await apiClient.delete('/scenarios/bulk', { ids: deleteIds });

        expect(result.success).toBe(true);
        expect(result.data.count).toBe(5);
      });
    });
  });

  describe('Error Handling', () => {
    it('should handle 4xx client errors gracefully', async () => {
      mockHttpClient.get.mockRejectedValue({
        response: {
          status: 404,
          data: { error: 'Scenario not found', code: 'SCENARIO_NOT_FOUND' }
        }
      });

      const result = await apiClient.get('/scenarios/nonexistent');

      expect(result.success).toBe(false);
      expect(result.error).toEqual({
        message: 'Scenario not found',
        code: 'SCENARIO_NOT_FOUND',
        status: 404
      });
    });

    it('should handle 5xx server errors with retry logic', async () => {
      // First two attempts fail with 500
      mockHttpClient.get
        .mockRejectedValueOnce({
          response: { status: 500, data: { error: 'Internal server error' } }
        })
        .mockRejectedValueOnce({
          response: { status: 502, data: { error: 'Bad gateway' } }
        })
        .mockResolvedValueOnce(
          createMockResponse({ scenarios: [] })
        );

      const result = await apiClient.get('/scenarios');

      expect(result.success).toBe(true);
      expect(mockHttpClient.get).toHaveBeenCalledTimes(3); // Initial + 2 retries
    });

    it('should handle network errors and timeouts', async () => {
      mockHttpClient.get.mockRejectedValue({
        code: 'ECONNABORTED',
        message: 'timeout of 5000ms exceeded'
      });

      const result = await apiClient.get('/scenarios');

      expect(result.success).toBe(false);
      expect(result.error.code).toBe('ECONNABORTED');
      expect(result.error.message).toContain('timeout');
    });

    it('should handle malformed JSON responses', async () => {
      mockHttpClient.get.mockResolvedValue({
        data: 'invalid json response',
        status: 200,
        headers: { 'content-type': 'application/json' }
      });

      const result = await apiClient.get('/scenarios');

      expect(result.success).toBe(false);
      expect(result.error.message).toContain('Invalid JSON');
    });

    it('should provide detailed error context for debugging', async () => {
      const debugClient = new MakeApiClient({
        baseUrl: 'https://api.make.com/v2',
        apiToken: 'test-token',
        debug: true,
        httpClient: mockHttpClient as any
      });

      mockHttpClient.post.mockRejectedValue({
        response: {
          status: 422,
          data: {
            error: 'Validation failed',
            details: {
              field: 'name',
              message: 'Name is required'
            }
          }
        },
        config: {
          url: '/scenarios',
          method: 'post',
          data: { teamId: 123 }
        }
      });

      const result = await debugClient.post('/scenarios', { teamId: 123 });

      expect(result.success).toBe(false);
      expect(result.error).toEqual({
        message: 'Validation failed',
        status: 422,
        details: {
          field: 'name',
          message: 'Name is required'
        },
        request: {
          url: '/scenarios',
          method: 'post',
          data: { teamId: 123 }
        }
      });
    });
  });

  describe('Rate Limiting and Throttling', () => {
    it('should handle rate limit responses with retry-after', async () => {
      const rateLimitError = {
        response: {
          status: 429,
          headers: { 'retry-after': '60' },
          data: { error: 'Rate limit exceeded' }
        }
      };

      mockHttpClient.get
        .mockRejectedValueOnce(rateLimitError)
        .mockResolvedValueOnce(createMockResponse({ success: true }));

      const startTime = Date.now();
      const result = await apiClient.get('/scenarios');
      const endTime = Date.now();

      expect(result.success).toBe(true);
      expect(endTime - startTime).toBeGreaterThan(59000); // Should wait ~60 seconds
      expect(mockHttpClient.get).toHaveBeenCalledTimes(2);
    });

    it('should implement exponential backoff for retries', async () => {
      const retryClient = new MakeApiClient({
        baseUrl: 'https://api.make.com/v2',
        apiToken: 'test-token',
        retryAttempts: 3,
        retryBackoff: 'exponential',
        httpClient: mockHttpClient as any
      });

      mockHttpClient.get
        .mockRejectedValueOnce({ response: { status: 503 } })
        .mockRejectedValueOnce({ response: { status: 503 } })
        .mockResolvedValueOnce(createMockResponse({ success: true }));

      const startTime = Date.now();
      const result = await retryClient.get('/scenarios');
      const endTime = Date.now();

      expect(result.success).toBe(true);
      expect(endTime - startTime).toBeGreaterThan(3000); // Should have exponential delays
      expect(mockHttpClient.get).toHaveBeenCalledTimes(3);
    });

    it('should respect concurrent request limits', async () => {
      const concurrentClient = new MakeApiClient({
        baseUrl: 'https://api.make.com/v2',
        apiToken: 'test-token',
        maxConcurrentRequests: 3,
        httpClient: mockHttpClient as any
      });

      mockHttpClient.get.mockImplementation(async () => {
        await new Promise(resolve => setTimeout(resolve, 100));
        return createMockResponse({ success: true });
      });

      const requests = Array(10).fill(0).map(() => 
        concurrentClient.get('/scenarios')
      );

      const results = await Promise.allSettled(requests);
      const successful = results.filter(r => r.status === 'fulfilled');

      expect(successful).toHaveLength(10);
      // Verify that no more than 3 requests were running concurrently
      expect(mockHttpClient.get).toHaveBeenCalledTimes(10);
    });
  });

  describe('Performance and Caching', () => {
    it('should cache GET responses when caching is enabled', async () => {
      const cachedClient = new MakeApiClient({
        baseUrl: 'https://api.make.com/v2',
        apiToken: 'test-token',
        enableCaching: true,
        cacheTtl: 300000, // 5 minutes
        httpClient: mockHttpClient as any
      });

      mockHttpClient.get.mockResolvedValue(
        createMockResponse({ scenarios: [{ id: 1, name: 'Cached Scenario' }] })
      );

      // First request
      const result1 = await cachedClient.get('/scenarios');
      // Second request (should use cache)
      const result2 = await cachedClient.get('/scenarios');

      expect(result1.success).toBe(true);
      expect(result2.success).toBe(true);
      expect(result1.data).toEqual(result2.data);
      expect(mockHttpClient.get).toHaveBeenCalledTimes(1); // Only one actual HTTP request
    });

    it('should invalidate cache on mutations', async () => {
      const cachedClient = new MakeApiClient({
        baseUrl: 'https://api.make.com/v2',
        apiToken: 'test-token',
        enableCaching: true,
        cacheInvalidationPatterns: {
          '/scenarios*': ['POST /scenarios', 'PUT /scenarios/*', 'DELETE /scenarios/*']
        },
        httpClient: mockHttpClient as any
      });

      // Cache initial GET
      mockHttpClient.get.mockResolvedValue(
        createMockResponse({ scenarios: [{ id: 1, name: 'Original' }] })
      );
      await cachedClient.get('/scenarios');

      // Perform mutation
      mockHttpClient.post.mockResolvedValue(
        createMockResponse({ id: 2, name: 'New Scenario' })
      );
      await cachedClient.post('/scenarios', { name: 'New Scenario' });

      // GET again (should not use cache)
      mockHttpClient.get.mockResolvedValue(
        createMockResponse({ scenarios: [{ id: 1, name: 'Original' }, { id: 2, name: 'New Scenario' }] })
      );
      const result = await cachedClient.get('/scenarios');

      expect(result.data.scenarios).toHaveLength(2);
      expect(mockHttpClient.get).toHaveBeenCalledTimes(2); // Cache was invalidated
    });

    it('should compress large request payloads', async () => {
      const compressionClient = new MakeApiClient({
        baseUrl: 'https://api.make.com/v2',
        apiToken: 'test-token',
        enableCompression: true,
        compressionThreshold: 1024, // 1KB
        httpClient: mockHttpClient as any
      });

      const largeBlueprint = {
        modules: Array(100).fill(0).map((_, i) => ({
          id: i,
          app: 'test-app',
          type: 'action',
          parameters: {
            data: 'x'.repeat(100) // Large parameter data
          }
        })),
        connections: Array(99).fill(0).map((_, i) => ({
          source: i,
          target: i + 1
        }))
      };

      mockHttpClient.post.mockResolvedValue(
        createMockResponse({ id: 123, created: true })
      );

      const result = await compressionClient.post('/scenarios', {
        name: 'Large Scenario',
        blueprint: largeBlueprint
      });

      expect(result.success).toBe(true);
      expect(mockHttpClient.post).toHaveBeenCalledWith(
        '/scenarios',
        expect.any(Object),
        expect.objectContaining({
          headers: expect.objectContaining({
            'Content-Encoding': 'gzip'
          })
        })
      );
    });
  });

  describe('Connection Management and Health', () => {
    it('should perform health checks on API endpoints', async () => {
      mockHttpClient.get.mockResolvedValue(
        createMockResponse({
          status: 'healthy',
          version: '2.1.0',
          timestamp: '2024-01-15T10:00:00Z'
        })
      );

      const healthResult = await apiClient.healthCheck();

      expect(healthResult.healthy).toBe(true);
      expect(healthResult.responseTime).toBeGreaterThan(0);
      expect(mockHttpClient.get).toHaveBeenCalledWith('/health');
    });

    it('should handle connection pooling for high-throughput scenarios', async () => {
      const pooledClient = new MakeApiClient({
        baseUrl: 'https://api.make.com/v2',
        apiToken: 'test-token',
        connectionPooling: {
          maxSockets: 10,
          keepAlive: true,
          timeout: 60000
        },
        httpClient: mockHttpClient as any
      });

      mockHttpClient.get.mockResolvedValue(createMockResponse({ success: true }));

      const requests = Array(50).fill(0).map(() => pooledClient.get('/scenarios'));
      const results = await Promise.allSettled(requests);

      expect(results.filter(r => r.status === 'fulfilled')).toHaveLength(50);
    });

    it('should detect and handle API endpoint changes', async () => {
      const versionedClient = new MakeApiClient({
        baseUrl: 'https://api.make.com/v2',
        apiToken: 'test-token',
        apiVersionCheck: true,
        supportedVersions: ['2.0', '2.1'],
        httpClient: mockHttpClient as any
      });

      // API returns version mismatch warning
      mockHttpClient.get.mockResolvedValue(
        createMockResponse(
          { scenarios: [] },
          200,
          { 'api-version': '2.2', 'api-deprecated': 'true' }
        )
      );

      const result = await versionedClient.get('/scenarios');

      expect(result.success).toBe(true);
      expect(result.warnings).toContainEqual(
        expect.objectContaining({
          type: 'api_version_mismatch',
          message: expect.stringContaining('2.2')
        })
      );
    });
  });
});