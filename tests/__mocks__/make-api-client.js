/**
 * Mock implementation of MakeApiClient for Jest tests
 * Provides the same interface as the real MakeApiClient class
 */

// Mock constructor function that returns an instance with all the needed methods
function MockMakeApiClient(config) {
  return {
    get: jest.fn(() => Promise.resolve({ success: true, data: {} })),
    post: jest.fn(() => Promise.resolve({ success: true, data: {} })),
    put: jest.fn(() => Promise.resolve({ success: true, data: {} })),
    patch: jest.fn(() => Promise.resolve({ success: true, data: {} })),
    delete: jest.fn(() => Promise.resolve({ success: true, data: {} })),
    
    // Health check method
    healthCheck: jest.fn(() => Promise.resolve(true)),
    
    // Rate limiter status method
    getRateLimiterStatus: jest.fn(() => ({
      running: 0,
      queued: 0
    })),
    
    // Shutdown method
    shutdown: jest.fn(() => Promise.resolve()),
    
    // Refresh credentials method
    refreshCredentials: jest.fn(() => Promise.resolve()),
    
    // Additional mock methods that might be needed
    setAuthToken: jest.fn(),
    setBaseURL: jest.fn(),
    setRateLimit: jest.fn(),
    clearCache: jest.fn(),
  };
}

// Add static methods if needed
MockMakeApiClient.createSecure = jest.fn(() => Promise.resolve(new MockMakeApiClient()));

// Export for ES modules
export default MockMakeApiClient;

// Export for CommonJS
module.exports = MockMakeApiClient;
module.exports.default = MockMakeApiClient;