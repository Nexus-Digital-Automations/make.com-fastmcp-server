/**
 * Integration Worker Thread
 * Handles concurrent API operations, health checks, and service coordination
 */

const { parentPort, workerData } = require('worker_threads');
const https = require('https');
const http = require('http');
const { URL } = require('url');
const { performance } = require('perf_hooks');

/**
 * Worker configuration
 */
const config = workerData?.config || {
  logging: { level: 'info' },
  timeouts: { defaultMs: 30000 }
};
const workerId = workerData?.workerId || 0;

/**
 * Simple logger for worker thread
 */
const logger = {
  info: (message, data = {}) => {
    if (config.logging.level === 'debug' || config.logging.level === 'info') {
      console.log(`[Worker-${workerId}] INFO: ${message}`, data);
    }
  },
  warn: (message, data = {}) => {
    console.warn(`[Worker-${workerId}] WARN: ${message}`, data);
  },
  error: (message, data = {}) => {
    console.error(`[Worker-${workerId}] ERROR: ${message}`, data);
  },
  debug: (message, data = {}) => {
    if (config.logging.level === 'debug') {
      console.log(`[Worker-${workerId}] DEBUG: ${message}`, data);
    }
  }
};

/**
 * HTTP client with timeout and retry capabilities
 */
class HttpClient {
  constructor() {
    this.agents = {
      http: new http.Agent({
        keepAlive: true,
        maxSockets: 10,
        maxFreeSockets: 5,
        timeout: 60000
      }),
      https: new https.Agent({
        keepAlive: true,
        maxSockets: 10,
        maxFreeSockets: 5,
        timeout: 60000,
        rejectUnauthorized: true
      })
    };
  }

  async request(options) {
    return new Promise((resolve, reject) => {
      const url = new URL(options.url);
      const isHttps = url.protocol === 'https:';
      const client = isHttps ? https : http;
      
      const requestOptions = {
        hostname: url.hostname,
        port: url.port || (isHttps ? 443 : 80),
        path: url.pathname + url.search,
        method: options.method || 'GET',
        headers: {
          'User-Agent': 'Make-FastMCP-Integration-Agent/1.0',
          ...options.headers
        },
        timeout: options.timeout || 30000,
        agent: this.agents[isHttps ? 'https' : 'http']
      };

      const req = client.request(requestOptions, (res) => {
        let data = '';
        
        res.on('data', (chunk) => {
          data += chunk;
        });
        
        res.on('end', () => {
          try {
            const response = {
              status: res.statusCode,
              statusText: res.statusMessage,
              headers: res.headers,
              data: this.parseResponseData(data, res.headers['content-type'])
            };
            resolve(response);
          } catch (error) {
            reject(error);
          }
        });
      });

      req.on('error', (error) => {
        reject(error);
      });

      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Request timeout'));
      });

      // Send request body if provided
      if (options.data) {
        if (typeof options.data === 'object') {
          req.write(JSON.stringify(options.data));
        } else {
          req.write(options.data);
        }
      }

      req.end();
    });
  }

  parseResponseData(data, contentType) {
    if (!data) return null;
    
    if (contentType && contentType.includes('application/json')) {
      try {
        return JSON.parse(data);
      } catch (error) {
        logger.warn('Failed to parse JSON response', { error: error.message });
        return data;
      }
    }
    
    return data;
  }
}

/**
 * Circuit breaker implementation for worker
 */
class CircuitBreaker {
  constructor(config = {}) {
    this.failureThreshold = config.failureThreshold || 5;
    this.successThreshold = config.successThreshold || 3;
    this.openTimeout = config.openTimeoutMs || 60000;
    this.state = 'closed'; // closed, open, half_open
    this.failureCount = 0;
    this.successCount = 0;
    this.lastFailure = null;
  }

  canExecute() {
    if (this.state === 'closed') {
      return true;
    }
    
    if (this.state === 'open') {
      const now = Date.now();
      if (this.lastFailure && (now - this.lastFailure) > this.openTimeout) {
        this.state = 'half_open';
        this.successCount = 0;
        return true;
      }
      return false;
    }
    
    // half_open state
    return true;
  }

  onSuccess() {
    this.failureCount = 0;
    
    if (this.state === 'half_open') {
      this.successCount++;
      if (this.successCount >= this.successThreshold) {
        this.state = 'closed';
        this.successCount = 0;
      }
    } else {
      this.state = 'closed';
    }
  }

  onFailure() {
    this.failureCount++;
    this.lastFailure = Date.now();
    
    if (this.failureCount >= this.failureThreshold) {
      this.state = 'open';
      this.successCount = 0;
    }
  }
}

/**
 * Integration worker implementation
 */
class IntegrationWorker {
  constructor() {
    this.httpClient = new HttpClient();
    this.circuitBreakers = new Map();
    
    logger.info('Integration worker initialized', { workerId });
  }

  /**
   * Process incoming messages from main thread
   */
  async processMessage(message) {
    const startTime = performance.now();
    
    try {
      logger.debug('Processing message', { 
        type: message.type,
        id: message.id 
      });

      let result;
      switch (message.type) {
        case 'api_request':
          result = await this.handleApiRequest(message.data);
          break;
        case 'health_check':
          result = await this.handleHealthCheck(message.data);
          break;
        case 'batch_operation':
          result = await this.handleBatchOperation(message.data);
          break;
        case 'credential_sync':
          result = await this.handleCredentialSync(message.data);
          break;
        default:
          throw new Error(`Unknown message type: ${message.type}`);
      }

      const duration = performance.now() - startTime;
      
      parentPort.postMessage({
        type: message.type,
        data: result,
        id: message.id,
        workerId,
        duration
      });

    } catch (error) {
      const duration = performance.now() - startTime;
      
      logger.error('Message processing failed', {
        messageType: message.type,
        messageId: message.id,
        error: error.message,
        duration
      });

      parentPort.postMessage({
        type: message.type,
        data: null,
        id: message.id,
        workerId,
        duration,
        error: {
          code: error.code || 'WORKER_ERROR',
          message: error.message,
          details: error.details || {}
        }
      });
    }
  }

  /**
   * Handle API request with circuit breaker
   */
  async handleApiRequest(data) {
    const { context, requestData, serviceConfig } = data;
    const serviceId = context.serviceId;
    
    // Get or create circuit breaker
    let circuitBreaker = this.circuitBreakers.get(serviceId);
    if (!circuitBreaker && serviceConfig.circuitBreaker.enabled) {
      circuitBreaker = new CircuitBreaker(serviceConfig.circuitBreaker);
      this.circuitBreakers.set(serviceId, circuitBreaker);
    }
    
    // Check circuit breaker
    if (circuitBreaker && !circuitBreaker.canExecute()) {
      throw new Error(`Circuit breaker is open for service ${serviceId}`);
    }
    
    const startTime = performance.now();
    
    try {
      // Find endpoint
      const endpoint = serviceConfig.endpoints.find(ep => 
        ep.id === context.endpointId || ep.active
      );
      if (!endpoint) {
        throw new Error(`No active endpoint found for service ${serviceId}`);
      }
      
      // Prepare request options
      const requestOptions = {
        url: endpoint.url,
        method: endpoint.method,
        timeout: context.timeout,
        headers: {
          'Content-Type': 'application/json',
          ...this.buildAuthHeaders(serviceConfig.authentication)
        }
      };
      
      if (requestData && (endpoint.method === 'POST' || endpoint.method === 'PUT' || endpoint.method === 'PATCH')) {
        requestOptions.data = requestData;
      }
      
      // Execute request with retry logic
      const response = await this.executeWithRetry(
        () => this.httpClient.request(requestOptions),
        serviceConfig.retry
      );
      
      const endTime = performance.now();
      const responseTime = endTime - startTime;
      
      // Update circuit breaker on success
      if (circuitBreaker) {
        circuitBreaker.onSuccess();
      }
      
      return {
        request: context,
        response: {
          success: response.status >= 200 && response.status < 300,
          data: response.data,
          metadata: {
            statusCode: response.status,
            headers: response.headers
          }
        },
        timestamp: new Date(),
        responseTime,
        cached: false
      };
      
    } catch (error) {
      const endTime = performance.now();
      const responseTime = endTime - startTime;
      
      // Update circuit breaker on failure
      if (circuitBreaker) {
        circuitBreaker.onFailure();
      }
      
      // Determine if error is retryable
      const isRetryable = this.isRetryableError(error, serviceConfig.retry);
      
      return {
        request: context,
        response: {
          success: false,
          error: {
            message: error.message,
            code: error.code || 'API_ERROR'
          }
        },
        timestamp: new Date(),
        responseTime,
        cached: false,
        error: {
          code: error.code || 'API_ERROR',
          message: error.message,
          retryable: isRetryable
        }
      };
    }
  }

  /**
   * Handle health check
   */
  async handleHealthCheck(data) {
    const { serviceId, serviceConfig } = data;
    const healthConfig = serviceConfig.healthCheck;
    
    const startTime = performance.now();
    let status = 'healthy';
    let responseTime = 0;
    let details = {};
    
    try {
      // Find health check endpoint or use first active endpoint
      const endpoint = serviceConfig.endpoints.find(ep => 
        ep.healthCheckPath || ep.active
      );
      
      if (!endpoint) {
        throw new Error('No endpoint available for health check');
      }
      
      const healthUrl = endpoint.healthCheckPath ? 
        `${endpoint.url}${endpoint.healthCheckPath}` : 
        endpoint.url;
      
      const requestOptions = {
        url: healthUrl,
        method: healthConfig.method || 'GET',
        timeout: healthConfig.timeoutMs,
        headers: {
          ...healthConfig.headers,
          ...this.buildAuthHeaders(serviceConfig.authentication)
        }
      };
      
      const response = await this.httpClient.request(requestOptions);
      const endTime = performance.now();
      responseTime = endTime - startTime;
      
      // Check if status code is expected
      const isHealthy = healthConfig.expectedStatusCodes.includes(response.status);
      status = isHealthy ? 'healthy' : 'degraded';
      
      details = {
        statusCode: response.status,
        message: response.statusText || 'Health check completed',
        metrics: {
          responseTime,
          contentLength: response.headers['content-length'] || 0
        }
      };
      
    } catch (error) {
      const endTime = performance.now();
      responseTime = endTime - startTime;
      status = 'unhealthy';
      
      details = {
        message: error.message,
        error: error.code || 'HEALTH_CHECK_FAILED'
      };
    }
    
    return {
      serviceId,
      status,
      score: this.calculateHealthScore(status, responseTime),
      lastChecked: new Date(),
      responseTime,
      details,
      trend: 'stable',
      consecutiveFailures: status === 'unhealthy' ? 1 : 0,
      consecutiveSuccesses: status === 'healthy' ? 1 : 0,
      history: []
    };
  }

  /**
   * Handle batch operation
   */
  async handleBatchOperation(batch) {
    const { id, requests, strategy, maxConcurrency, failureStrategy } = batch;
    
    logger.info('Processing batch operation', {
      batchId: id,
      requestCount: requests.length,
      strategy
    });
    
    let results = [];
    
    switch (strategy) {
      case 'parallel':
        results = await this.executeBatchParallel(requests, maxConcurrency);
        break;
      case 'sequential':
        results = await this.executeBatchSequential(requests);
        break;
      case 'pipeline':
        results = await this.executeBatchPipeline(requests);
        break;
      default:
        throw new Error(`Unknown batch strategy: ${strategy}`);
    }
    
    // Handle failure strategy
    if (failureStrategy === 'fail_fast') {
      const hasFailure = results.some(r => !r.response.success);
      if (hasFailure) {
        throw new Error('Batch operation failed (fail_fast strategy)');
      }
    }
    
    return results;
  }

  /**
   * Handle credential synchronization
   */
  async handleCredentialSync(data) {
    const { credentialId, serviceIds, services } = data;
    
    logger.info('Processing credential synchronization', {
      credentialId,
      serviceCount: serviceIds.length
    });
    
    // Simulate credential synchronization
    // In a real implementation, this would update credentials across services
    const results = [];
    
    for (const service of services) {
      try {
        // Simulate credential update
        await new Promise(resolve => setTimeout(resolve, 100));
        
        results.push({
          serviceId: service.id,
          success: true,
          timestamp: new Date()
        });
        
      } catch (error) {
        results.push({
          serviceId: service.id,
          success: false,
          error: error.message,
          timestamp: new Date()
        });
      }
    }
    
    return {
      credentialId,
      results,
      totalServices: services.length,
      successCount: results.filter(r => r.success).length,
      failureCount: results.filter(r => !r.success).length
    };
  }

  /**
   * Execute requests in parallel with concurrency limit
   */
  async executeBatchParallel(requests, maxConcurrency) {
    const results = [];
    const executing = [];
    
    for (const request of requests) {
      // Wait if we've hit the concurrency limit
      if (executing.length >= maxConcurrency) {
        await Promise.race(executing);
      }
      
      const promise = this.handleApiRequest({
        context: request,
        serviceConfig: { /* service config would be looked up */ }
      }).then(result => {
        const index = executing.indexOf(promise);
        if (index > -1) {
          executing.splice(index, 1);
        }
        return result;
      }).catch(error => {
        const index = executing.indexOf(promise);
        if (index > -1) {
          executing.splice(index, 1);
        }
        throw error;
      });
      
      executing.push(promise);
      results.push(promise);
    }
    
    return await Promise.allSettled(results);
  }

  /**
   * Execute requests sequentially
   */
  async executeBatchSequential(requests) {
    const results = [];
    
    for (const request of requests) {
      try {
        const result = await this.handleApiRequest({
          context: request,
          serviceConfig: { /* service config would be looked up */ }
        });
        results.push(result);
      } catch (error) {
        results.push({
          request,
          response: { success: false, error: { message: error.message } },
          timestamp: new Date(),
          responseTime: 0,
          cached: false
        });
      }
    }
    
    return results;
  }

  /**
   * Execute requests in pipeline mode
   */
  async executeBatchPipeline(requests) {
    // Pipeline implementation would chain requests
    // For now, fall back to sequential
    return await this.executeBatchSequential(requests);
  }

  /**
   * Execute operation with retry logic
   */
  async executeWithRetry(operation, retryConfig) {
    if (!retryConfig || !retryConfig.enabled) {
      return await operation();
    }
    
    let lastError;
    
    for (let attempt = 0; attempt <= retryConfig.maxAttempts; attempt++) {
      try {
        return await operation();
      } catch (error) {
        lastError = error;
        
        if (attempt === retryConfig.maxAttempts) {
          break;
        }
        
        if (!this.isRetryableError(error, retryConfig)) {
          break;
        }
        
        // Calculate delay
        let delay = retryConfig.baseDelayMs;
        
        if (retryConfig.strategy === 'exponential') {
          delay = Math.min(
            retryConfig.baseDelayMs * Math.pow(2, attempt),
            retryConfig.maxDelayMs
          );
        } else if (retryConfig.strategy === 'linear') {
          delay = Math.min(
            retryConfig.baseDelayMs * (attempt + 1),
            retryConfig.maxDelayMs
          );
        }
        
        // Add jitter if enabled
        if (retryConfig.jitter && retryConfig.jitter.enabled) {
          const jitter = Math.random() * retryConfig.jitter.maxMs;
          delay += jitter;
        }
        
        logger.debug('Retrying operation', { 
          attempt: attempt + 1,
          delay,
          error: error.message 
        });
        
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
    
    throw lastError;
  }

  /**
   * Check if error is retryable
   */
  isRetryableError(error, retryConfig) {
    if (!retryConfig || !retryConfig.retryableErrors) {
      return false;
    }
    
    const errorCode = error.code || error.name || '';
    const errorMessage = error.message || '';
    
    return retryConfig.retryableErrors.some(pattern => 
      errorCode.includes(pattern) || errorMessage.includes(pattern)
    );
  }

  /**
   * Build authentication headers
   */
  buildAuthHeaders(authConfig) {
    const headers = {};
    
    switch (authConfig.type) {
      case 'api_key':
        if (authConfig.config.keyLocation === 'header') {
          const prefix = authConfig.config.keyPrefix || '';
          headers[authConfig.config.keyName] = `${prefix}${process.env.MAKE_API_KEY || ''}`;
        }
        break;
      case 'basic':
        const credentials = Buffer.from(`${authConfig.config.username}:${authConfig.config.password}`).toString('base64');
        headers['Authorization'] = `Basic ${credentials}`;
        break;
      case 'jwt':
        headers['Authorization'] = `Bearer ${authConfig.config.token}`;
        break;
    }
    
    return headers;
  }

  /**
   * Calculate health score based on status and response time
   */
  calculateHealthScore(status, responseTime) {
    let baseScore = 0;
    
    switch (status) {
      case 'healthy':
        baseScore = 100;
        break;
      case 'degraded':
        baseScore = 60;
        break;
      case 'unhealthy':
        baseScore = 0;
        break;
      default:
        baseScore = 50;
    }
    
    // Adjust score based on response time
    if (responseTime > 10000) { // 10 seconds
      baseScore = Math.max(0, baseScore - 40);
    } else if (responseTime > 5000) { // 5 seconds
      baseScore = Math.max(0, baseScore - 20);
    } else if (responseTime > 2000) { // 2 seconds
      baseScore = Math.max(0, baseScore - 10);
    }
    
    return Math.max(0, Math.min(100, baseScore));
  }
}

// Initialize worker
const worker = new IntegrationWorker();

// Listen for messages from main thread
if (parentPort) {
  parentPort.on('message', async (message) => {
    await worker.processMessage(message);
  });
  
  // Notify main thread that worker is ready
  parentPort.postMessage({
    type: 'worker_ready',
    workerId,
    timestamp: new Date().toISOString()
  });
}

// Handle uncaught errors
process.on('uncaughtException', (error) => {
  logger.error('Uncaught exception in worker', {
    error: error.message,
    stack: error.stack
  });
  
  if (parentPort) {
    parentPort.postMessage({
      type: 'worker_error',
      workerId,
      error: {
        message: error.message,
        stack: error.stack
      }
    });
  }
});

process.on('unhandledRejection', (reason) => {
  logger.error('Unhandled rejection in worker', {
    reason: reason instanceof Error ? reason.message : String(reason)
  });
  
  if (parentPort) {
    parentPort.postMessage({
      type: 'worker_error',
      workerId,
      error: {
        message: reason instanceof Error ? reason.message : String(reason)
      }
    });
  }
});

logger.info('Integration worker ready', { workerId });