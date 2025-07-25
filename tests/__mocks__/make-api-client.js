/**
 * Mock implementation of MakeApiClient for Jest tests
 * Provides the same interface as the real MakeApiClient
 */

const mockMakeApiClient = {
  get: jest.fn(() => Promise.resolve({ success: true, data: {} })),
  post: jest.fn(() => Promise.resolve({ success: true, data: {} })),
  put: jest.fn(() => Promise.resolve({ success: true, data: {} })),
  patch: jest.fn(() => Promise.resolve({ success: true, data: {} })),
  delete: jest.fn(() => Promise.resolve({ success: true, data: {} })),
  head: jest.fn(() => Promise.resolve({ success: true, data: {} })),
  options: jest.fn(() => Promise.resolve({ success: true, data: {} })),
  
  // Additional mock methods that might be needed
  setAuthToken: jest.fn(),
  setBaseURL: jest.fn(),
  setRateLimit: jest.fn(),
  clearCache: jest.fn(),
};

// Export for ES modules
export default mockMakeApiClient;

// Export for CommonJS
module.exports = mockMakeApiClient;
module.exports.default = mockMakeApiClient;