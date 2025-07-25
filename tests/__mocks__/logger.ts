// Simple mock logger that doesn't depend on Jest globals
const createMockLogger = () => ({
  info: (...args: any[]) => {},
  debug: (...args: any[]) => {},
  warn: (...args: any[]) => {},
  error: (...args: any[]) => {},
  child: () => createMockLogger(),
  logWithCorrelation: (...args: any[]) => 'mock_correlation_id',
  logDuration: (...args: any[]) => {},
  generateCorrelationId: () => 'mock_correlation_id',
  generateTraceId: () => 'mock_trace_id',
  generateSpanId: () => 'mock_span_id',
  generateRequestId: () => 'mock_request_id',
  setLogLevel: (...args: any[]) => {},
  getLogLevel: () => 'info',
});

// Create mock logger instance
const mockLogger = createMockLogger();

// ES module exports
export default mockLogger;
export const logger = mockLogger;

// CommonJS compatibility
if (typeof module !== 'undefined' && module.exports) {
  module.exports = mockLogger;
  module.exports.default = mockLogger;
  module.exports.logger = mockLogger;
}