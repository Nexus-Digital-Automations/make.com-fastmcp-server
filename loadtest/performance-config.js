// Performance optimization configuration based on research report recommendations
// This file contains production-ready performance settings for the FastMCP OAuth server

export const performanceConfig = {
  // Redis session store optimization
  redis: {
    connectionPooling: {
      min: 10,
      max: 50,
      acquireTimeoutMillis: 3000,
      idleTimeoutMillis: 30000,
    },
    sessionCaching: {
      localCache: true, // L1 cache for frequent sessions
      cacheTTL: 300, // 5 minutes L1 cache
      compressionThreshold: 1024, // Compress sessions > 1KB
    },
    encryption: {
      batchEncryption: true, // Batch encrypt multiple sessions
      keyRotation: "daily", // Rotate encryption keys daily
    },
  },

  // FastMCP server optimizations
  fastmcpServer: {
    httpServer: {
      keepAliveTimeout: 5000,
      headersTimeout: 60000,
      maxHeaderSize: 16384,
      bodyParser: { limit: "1mb" },
    },
    rateLimiting: {
      windowMs: 60000, // 1 minute window
      max: 1000, // 1000 requests per window per IP
      standardHeaders: true,
      legacyHeaders: false,
    },
    middleware: {
      compression: true,
      etag: true,
      responseCache: {
        ttl: 300, // 5 minute cache for cacheable responses
      },
    },
  },

  // Make.com API client optimizations
  makeApiClient: {
    rateLimiter: {
      reservoir: 600, // Match Make.com rate limits
      reservoirRefreshAmount: 600,
      reservoirRefreshInterval: 60000, // 1 minute
      maxConcurrent: 10, // Limit concurrent requests
    },
    retryPolicy: {
      retries: 3,
      retryDelay: "exponential", // Exponential backoff
      maxRetryDelay: 30000, // Max 30 second delay
    },
    connectionPool: {
      maxConnections: 20,
      keepAlive: true,
      keepAliveMsecs: 1000,
    },
  },

  // Load testing scenarios configuration
  loadTesting: {
    oauth: {
      authorizationFlow: {
        pattern: "constant-arrival-rate",
        rate: 50, // 50 new auth flows per second
        duration: "5m",
        preAllocatedVUs: 100,
      },
      tokenRefresh: {
        pattern: "ramping-rate",
        stages: [
          { duration: "2m", rate: 100 }, // Ramp up to 100/sec
          { duration: "5m", rate: 500 }, // Sustain 500/sec
          { duration: "2m", rate: 0 }, // Ramp down
        ],
      },
      sessionValidation: {
        pattern: "per-vu-iterations",
        vus: 1000, // 1000 concurrent users
        iterations: 10, // Each user validates 10 times
      },
    },

    fastmcp: {
      toolExecution: {
        pattern: "ramping-vus",
        stages: [
          { duration: "2m", target: 50 },
          { duration: "5m", target: 100 },
          { duration: "2m", target: 200 },
          { duration: "5m", target: 200 },
          { duration: "2m", target: 0 },
        ],
      },
      webSocketStress: {
        pattern: "constant-vus",
        vus: 500,
        duration: "10m",
      },
      concurrentAPI: {
        pattern: "per-vu-iterations",
        vus: 100,
        iterations: 50,
        maxDuration: "15m",
      },
    },
  },

  // Performance targets from research analysis
  performanceTargets: {
    oauth: {
      authorizationFlow: 200, // < 200ms per request at 50 req/sec
      tokenRefresh: 100, // < 100ms per request at 500 req/sec
      sessionValidation: 50, // < 50ms per request with 1000 concurrent users
      redisOperations: 10, // < 10ms per operation under load
    },

    fastmcp: {
      toolExecution: 500, // < 500ms per tool under concurrent load
      webSocketConnections: 1000, // Support 1000+ concurrent connections
      memoryUsage: {
        normal: 536870912, // < 512MB under normal load
        stress: 1073741824, // < 1GB under stress
      },
      cpuUsage: {
        normal: 70, // < 70% under normal load
        stress: 90, // < 90% under stress
      },
    },

    general: {
      httpResponseTime: {
        p95: 500, // 95% of requests under 500ms
        p99: 1000, // 99% of requests under 1s
      },
      errorRate: 0.01, // Less than 1% failures
      successRate: 0.99, // 99% success rate
    },
  },

  // Monitoring and alerting configuration
  monitoring: {
    prometheus: {
      scrapeInterval: "5s",
      evaluationInterval: "15s",
      retentionTime: "7d",
      retentionSize: "2GB",
    },

    grafana: {
      refreshInterval: "5s",
      dashboards: [
        "oauth-load-test-dashboard",
        "fastmcp-performance-dashboard",
        "system-resource-dashboard",
      ],
    },

    alerts: {
      responseTimeThreshold: 1000, // Alert if response time > 1s
      errorRateThreshold: 0.05, // Alert if error rate > 5%
      memoryUsageThreshold: 0.85, // Alert if memory usage > 85%
      cpuUsageThreshold: 0.8, // Alert if CPU usage > 80%
    },
  },

  // CI/CD integration settings
  cicd: {
    performanceGates: {
      maxResponseTime: 500, // Fail if P95 response time > 500ms
      maxErrorRate: 0.02, // Fail if error rate > 2%
      minThroughput: 100, // Fail if throughput < 100 req/sec
    },

    regressionDetection: {
      enabled: true,
      thresholdIncrease: 0.2, // 20% performance degradation triggers failure
      baselineWindow: "7d", // Use 7 days of data for baseline
    },

    testSchedule: {
      quickTest: {
        duration: "5m",
        schedule: "on_pull_request",
      },
      fullTest: {
        duration: "30m",
        schedule: "nightly",
      },
      sustainedTest: {
        duration: "24h",
        schedule: "weekly",
      },
    },
  },
};

// Export individual configuration sections for modular usage
export const {
  redis,
  fastmcpServer,
  makeApiClient,
  loadTesting,
  performanceTargets,
  monitoring,
  cicd,
} = performanceConfig;

export default performanceConfig;
