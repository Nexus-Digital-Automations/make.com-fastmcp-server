/**
 * Test fixture data for log-streaming module
 * Provides realistic streaming data patterns for comprehensive testing
 */

import { MakeLogEntry } from '../../../src/tools/log-streaming/types/streaming.js';

/**
 * Sample execution data for streaming tests
 */
export const SAMPLE_EXECUTION_DATA = {
  executionId: 'exec_1234567890',
  scenarioId: 12345,
  startTime: '2025-08-21T18:00:00.000Z',
  status: 'running',
  progress: 45,
};

/**
 * Sample log entries with various scenarios
 */
export const SAMPLE_LOG_ENTRIES: MakeLogEntry[] = [
  {
    id: 'log_001',
    timestamp: '2025-08-21T18:00:01.000Z',
    level: 'info',
    message: 'Module execution started',
    module: { id: 'module_1', name: 'HTTP Module' },
    executionId: 'exec_1234567890',
    data: { url: 'https://api.example.com/data' },
    metrics: { processingTime: 120, operations: 1, dataSize: 1024 },
  },
  {
    id: 'log_002',
    timestamp: '2025-08-21T18:00:02.500Z',
    level: 'warn',
    message: 'Rate limit approaching',
    module: { id: 'module_1', name: 'HTTP Module' },
    executionId: 'exec_1234567890',
    data: { remaining: 5, limit: 100 },
    metrics: { processingTime: 89, operations: 1, dataSize: 512 },
  },
  {
    id: 'log_003',
    timestamp: '2025-08-21T18:00:03.200Z',
    level: 'error',
    message: 'Network timeout occurred',
    module: { id: 'module_2', name: 'Database Module' },
    executionId: 'exec_1234567890',
    error: { message: 'Connection timeout after 30s', code: 'TIMEOUT' },
    metrics: { processingTime: 30000, operations: 0, dataSize: 0 },
  },
  {
    id: 'log_004',
    timestamp: '2025-08-21T18:00:04.100Z',
    level: 'info',
    message: 'Data transformation completed',
    module: { id: 'module_3', name: 'Transform Module' },
    executionId: 'exec_1234567890',
    data: { recordsProcessed: 150, transformations: 3 },
    metrics: { processingTime: 245, operations: 150, dataSize: 15360 },
  },
];

/**
 * Sample streaming configuration for tests
 */
export const SAMPLE_STREAM_CONFIG = {
  scenarioId: 12345,
  monitoring: {
    updateIntervalMs: 1000,
    maxDuration: 300,
    includePerformanceMetrics: true,
    includeModuleDetails: true,
    trackProgress: true,
  },
  alerts: {
    enabled: true,
    errorThreshold: 3,
    performanceThreshold: 5000,
    moduleFailureAlert: true,
    executionTimeAlert: true,
    customThresholds: {
      memoryUsage: 1024,
      cpuUsage: 80,
    },
  },
  output: {
    format: 'json' as const,
    includeVisualization: true,
    realTimeUpdate: true,
  },
};

/**
 * Mock external system responses
 */
export const MOCK_API_RESPONSES = {
  getExecution: {
    success: true,
    data: {
      id: 'exec_1234567890',
      scenarioId: 12345,
      status: 'running',
      progress: 65,
      startTime: '2025-08-21T18:00:00.000Z',
      modules: ['module_1', 'module_2', 'module_3'],
    },
  },
  getExecutions: {
    success: true,
    data: [
      {
        id: 'exec_1234567890',
        status: 'running',
        startTime: '2025-08-21T18:00:00.000Z',
      },
    ],
  },
  getLogs: {
    success: true,
    data: SAMPLE_LOG_ENTRIES,
  },
  getModules: {
    success: true,
    data: [
      { id: 'module_1', name: 'HTTP Module', status: 'completed', processingTime: 120 },
      { id: 'module_2', name: 'Database Module', status: 'error', processingTime: 30000 },
      { id: 'module_3', name: 'Transform Module', status: 'running', processingTime: 245 },
    ],
  },
};

/**
 * Test scenarios for different export formats
 */
export const EXPORT_FORMAT_TEST_DATA = {
  json: {
    format: 'json' as const,
    expectedMimeType: 'application/json',
    sampleOutput: {
      logs: SAMPLE_LOG_ENTRIES,
      metadata: { count: 4, exported: '2025-08-21T18:00:00.000Z' },
    },
  },
  csv: {
    format: 'csv' as const,
    expectedMimeType: 'text/csv',
    expectedHeaders: ['timestamp', 'level', 'module', 'message', 'processingTime'],
  },
  parquet: {
    format: 'parquet' as const,
    expectedMimeType: 'application/octet-stream',
    schema: {
      timestamp: 'timestamp',
      level: 'string',
      module: 'string',
      message: 'string',
      processingTime: 'int64',
    },
  },
};

/**
 * Performance benchmark data
 */
export const PERFORMANCE_BENCHMARKS = {
  streaming: {
    expectedLatency: 100, // ms
    expectedThroughput: 1000, // logs/second
    maxMemoryUsage: 50 * 1024 * 1024, // 50MB
  },
  export: {
    smallDataset: { logs: 100, expectedTime: 500 }, // 100 logs in 500ms
    mediumDataset: { logs: 10000, expectedTime: 5000 }, // 10k logs in 5s
    largeDataset: { logs: 100000, expectedTime: 30000 }, // 100k logs in 30s
  },
};

/**
 * Error scenarios for testing
 */
export const ERROR_SCENARIOS = [
  {
    name: 'Network timeout',
    mockError: { code: 'ECONNRESET', message: 'socket hang up' },
    expectedBehavior: 'graceful degradation',
  },
  {
    name: 'Rate limit exceeded',
    mockError: { code: 'RATE_LIMIT', message: 'Too many requests' },
    expectedBehavior: 'retry with exponential backoff',
  },
  {
    name: 'Invalid execution ID',
    mockError: { code: 'NOT_FOUND', message: 'Execution not found' },
    expectedBehavior: 'user error with clear message',
  },
  {
    name: 'Authentication failed',
    mockError: { code: 'UNAUTHORIZED', message: 'Invalid credentials' },
    expectedBehavior: 'authentication error handling',
  },
];

/**
 * Real-time streaming test patterns
 */
export const STREAMING_TEST_PATTERNS = {
  continuousStream: {
    duration: 5000, // 5 seconds
    updateInterval: 100, // 100ms updates
    expectedUpdates: 50,
  },
  burstyStream: {
    burstSize: 10,
    burstInterval: 1000,
    totalBursts: 3,
  },
  errorProneStream: {
    errorRate: 0.1, // 10% error rate
    totalEvents: 100,
  },
};