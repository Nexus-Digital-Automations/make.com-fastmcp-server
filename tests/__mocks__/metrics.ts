/**
 * Manual Mock for metrics module
 * This file will be automatically used by Jest when metrics.js is imported
 * CRITICAL: This file must export the exact same structure as the real metrics module
 */

// Create jest mock functions with deterministic names
const createSetActiveConnections = () => jest.fn().mockName('setActiveConnections');
const createRecordRequest = () => jest.fn().mockName('recordRequest');
const createCreateTimer = () => jest.fn().mockName('createTimer').mockReturnValue(() => 1.5);
const createRecordToolExecution = () => jest.fn().mockName('recordToolExecution');
const createRecordError = () => jest.fn().mockName('recordError');
const createRecordAuthAttempt = () => jest.fn().mockName('recordAuthAttempt');
const createRecordAuthDuration = () => jest.fn().mockName('recordAuthDuration');
const createRecordMakeApiCall = () => jest.fn().mockName('recordMakeApiCall');
const createHealthCheck = () => jest.fn().mockName('healthCheck').mockResolvedValue({ 
  healthy: true, 
  metricsCount: 100 
});
const createRecordCacheHit = () => jest.fn().mockName('recordCacheHit');
const createRecordCacheMiss = () => jest.fn().mockName('recordCacheMiss');
const createRecordCacheInvalidation = () => jest.fn().mockName('recordCacheInvalidation');
const createRecordCacheDuration = () => jest.fn().mockName('recordCacheDuration');
const createUpdateCacheSize = () => jest.fn().mockName('updateCacheSize');
const createUpdateCacheHitRate = () => jest.fn().mockName('updateCacheHitRate');
const createUpdateRateLimiterState = () => jest.fn().mockName('updateRateLimiterState');
const createGetMetrics = () => jest.fn().mockName('getMetrics').mockResolvedValue('# Mock metrics data');
const createGetRegistry = () => jest.fn().mockName('getRegistry');
const createShutdown = () => jest.fn().mockName('shutdown');

// Create the mock metrics instance object
const mockMetricsInstance = {
  setActiveConnections: createSetActiveConnections(),
  recordRequest: createRecordRequest(),
  createTimer: createCreateTimer(),
  recordToolExecution: createRecordToolExecution(),
  recordError: createRecordError(),
  recordAuthAttempt: createRecordAuthAttempt(),
  recordAuthDuration: createRecordAuthDuration(),
  recordMakeApiCall: createRecordMakeApiCall(),
  healthCheck: createHealthCheck(),
  recordCacheHit: createRecordCacheHit(),
  recordCacheMiss: createRecordCacheMiss(),
  recordCacheInvalidation: createRecordCacheInvalidation(),
  recordCacheDuration: createRecordCacheDuration(),
  updateCacheSize: createUpdateCacheSize(),
  updateCacheHitRate: createUpdateCacheHitRate(),
  updateRateLimiterState: createUpdateRateLimiterState(),
  getMetrics: createGetMetrics(),
  getRegistry: createGetRegistry(),
  shutdown: createShutdown(),
};

// Create mock MetricsCollector class constructor
const MockMetricsCollector = jest.fn().mockImplementation(() => mockMetricsInstance);
MockMetricsCollector.getInstance = jest.fn().mockReturnValue(mockMetricsInstance);
MockMetricsCollector.resetInstance = jest.fn();

// CRITICAL: Export in all the ways Jest might expect
const metricsExport = mockMetricsInstance;

// CommonJS exports (for require())
module.exports = metricsExport;
module.exports.default = metricsExport;
module.exports.metrics = metricsExport;
module.exports.MetricsCollector = MockMetricsCollector;

// Mark as ES module for proper Jest handling
module.exports.__esModule = true;

// ES6 exports (for import)
export default metricsExport;
export const metrics = metricsExport;
export { MockMetricsCollector as MetricsCollector };