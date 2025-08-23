// Enhanced mock logger that works with all test scenarios
const createMockLogger = () => ({
  info: (...args: any[]) => {},
  debug: (...args: any[]) => {},
  warn: (...args: any[]) => {},
  error: (...args: any[]) => {},
  child: (options?: any) => createMockLogger(),
  logWithCorrelation: (...args: any[]) => 'mock_correlation_id',
  logDuration: (...args: any[]) => {},
  generateCorrelationId: () => 'mock_correlation_id',
  generateTraceId: () => 'mock_trace_id',
  generateSpanId: () => 'mock_span_id',
  generateRequestId: () => 'mock_request_id',
  setLogLevel: (...args: any[]) => {},
  getLogLevel: () => 'info' as const,
  trace: (...args: any[]) => {},
  fatal: (...args: any[]) => {},
  level: 'info' as const,
});

// Create mock logger instance
const mockLogger = createMockLogger();

// ES module exports with explicit __esModule flag for better compatibility
export default mockLogger;
export const logger = mockLogger;

// Enhanced CommonJS/ESM compatibility for Jest's module resolution
const moduleExports = {
  __esModule: true,
  default: mockLogger,
  logger: mockLogger,
};

// CommonJS compatibility
if (typeof module !== 'undefined' && module.exports) {
  module.exports = moduleExports;
}