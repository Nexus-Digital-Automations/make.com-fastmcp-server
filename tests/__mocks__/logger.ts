import { jest } from '@jest/globals';

const createMockLogger = () => ({
  info: jest.fn(),
  debug: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  child: jest.fn(() => createMockLogger()),
});

// Manual mock for logger with ES module compatibility
const mockLogger = createMockLogger();

// Ensure ES module default export works correctly
Object.defineProperty(mockLogger, '__esModule', { value: true });

export default mockLogger;
export const logger = mockLogger;

// For CommonJS compatibility
module.exports = mockLogger;
module.exports.default = mockLogger;
module.exports.logger = mockLogger;