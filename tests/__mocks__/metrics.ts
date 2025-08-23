/**
 * Mock implementation of metrics module for testing
 * Provides all methods expected by the monitoring middleware
 */

// Create the mock as a direct object with jest.fn() calls
const mockMetricsInstance = {
  // Core metrics methods
  setActiveConnections: jest.fn(),
  recordRequest: jest.fn(),
  createTimer: jest.fn().mockReturnValue(() => 1.5), // Returns a function that returns 1.5 seconds
  recordToolExecution: jest.fn(),
  recordError: jest.fn(),
  recordAuthAttempt: jest.fn(),
  recordAuthDuration: jest.fn(),
  recordMakeApiCall: jest.fn(),
  healthCheck: jest.fn().mockResolvedValue({ 
    healthy: true, 
    metricsCount: 100 
  }),
  
  // Cache metrics methods
  recordCacheHit: jest.fn(),
  recordCacheMiss: jest.fn(),
  recordCacheInvalidation: jest.fn(),
  recordCacheDuration: jest.fn(),
  updateCacheSize: jest.fn(),
  updateCacheHitRate: jest.fn(),
  updateRateLimiterState: jest.fn(),
  
  // Registry methods
  getMetrics: jest.fn().mockResolvedValue('# Mock metrics data'),
  getRegistry: jest.fn(),
  shutdown: jest.fn(),
};

// Create a mock MetricsCollector class
const MockMetricsCollector = jest.fn().mockImplementation(() => mockMetricsInstance);
MockMetricsCollector.getInstance = jest.fn().mockReturnValue(mockMetricsInstance);
MockMetricsCollector.resetInstance = jest.fn();

// Export both named and default exports to match the real metrics module
export const metrics = mockMetricsInstance;
export const MetricsCollector = MockMetricsCollector;
export default mockMetricsInstance;