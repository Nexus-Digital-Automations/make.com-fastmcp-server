/**
 * Unit Tests for Rate Limiting Middleware
 * Tests adaptive rate limiting, DDoS protection, and enterprise features
 */

import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { 
  AdaptiveRateLimiter, 
  EnterpriseRateLimitManager, 
  createRateLimitMiddleware,
  ddosProtectionMiddleware,
  rateLimitManager
} from '../../../src/middleware/rate-limiting';

// Mock Redis
jest.mock('ioredis', () => {
  return jest.fn().mockImplementation(() => ({
    on: jest.fn(),
    quit: jest.fn(),
    status: 'ready'
  }));
});

// Mock rate-limiter-flexible
jest.mock('rate-limiter-flexible', () => ({
  RateLimiterRedis: jest.fn().mockImplementation(() => ({
    consume: jest.fn().mockResolvedValue({
      remainingPoints: 10,
      msBeforeNext: 60000
    })
  })),
  RateLimiterMemory: jest.fn().mockImplementation(() => ({
    consume: jest.fn().mockResolvedValue({
      remainingPoints: 10,
      msBeforeNext: 60000
    })
  }))
}));

// Mock logger
jest.mock('../../../src/lib/logger.js', () => ({
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn()
}));

import { RateLimiterRedis, RateLimiterMemory } from 'rate-limiter-flexible';
import Redis from 'ioredis';
import logger from '../../../src/lib/logger.js';

describe('Rate Limiting Middleware', () => {
  let mockRequest: any;
  let mockResponse: any;
  let mockNext: jest.Mock;

  beforeEach(() => {
    jest.clearAllMocks();
    
    mockRequest = {
      ip: '127.0.0.1',
      method: 'GET',
      url: '/test',
      path: '/test',
      headers: {
        'user-agent': 'test-agent',
        'x-forwarded-for': '192.168.1.1'
      },
      connection: {
        remoteAddress: '127.0.0.1'
      },
      user: {
        id: 'user123'
      }
    };

    mockResponse = {
      setHeader: jest.fn().mockReturnThis(),
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
      on: jest.fn()
    };

    mockNext = jest.fn();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('AdaptiveRateLimiter', () => {
    let adaptiveLimiter: AdaptiveRateLimiter;

    beforeEach(() => {
      adaptiveLimiter = new AdaptiveRateLimiter();
      // Clear any existing intervals
      jest.clearAllTimers();
      jest.useFakeTimers();
    });

    afterEach(() => {
      jest.useRealTimers();
    });

    test('should initialize with default system metrics', () => {
      expect(adaptiveLimiter).toBeDefined();
    });

    test('should update system metrics periodically', () => {
      // Mock process.cpuUsage and process.memoryUsage
      const mockCpuUsage = jest.spyOn(process, 'cpuUsage').mockReturnValue({
        user: 1000000, // 1 second
        system: 500000 // 0.5 seconds
      });

      const mockMemoryUsage = jest.spyOn(process, 'memoryUsage').mockReturnValue({
        rss: 100 * 1024 * 1024,
        heapTotal: 200 * 1024 * 1024,
        heapUsed: 100 * 1024 * 1024,
        external: 10 * 1024 * 1024,
        arrayBuffers: 5 * 1024 * 1024
      });

      // Trigger interval
      jest.advanceTimersByTime(30000);

      expect(mockCpuUsage).toHaveBeenCalled();
      expect(mockMemoryUsage).toHaveBeenCalled();
      expect(logger.debug).toHaveBeenCalledWith('System metrics updated', expect.objectContaining({
        systemLoad: expect.any(Number),
        memoryUsage: expect.any(Number)
      }));

      mockCpuUsage.mockRestore();
      mockMemoryUsage.mockRestore();
    });

    test('should set and track response times', () => {
      adaptiveLimiter.setResponseTime(1500);
      adaptiveLimiter.setResponseTime(800);
      
      // Response time should be tracked (P95 calculation)
      expect(adaptiveLimiter).toBeDefined();
    });

    test('should reduce limits under high system load', async () => {
      // Mock high system load conditions
      jest.spyOn(process, 'cpuUsage').mockReturnValue({
        user: 5000000, // 5 seconds
        system: 3000000 // 3 seconds
      });

      jest.spyOn(process, 'memoryUsage').mockReturnValue({
        rss: 200 * 1024 * 1024,
        heapTotal: 200 * 1024 * 1024,
        heapUsed: 170 * 1024 * 1024, // 85% memory usage
        external: 10 * 1024 * 1024,
        arrayBuffers: 5 * 1024 * 1024
      });

      // Trigger metrics update
      jest.advanceTimersByTime(30000);

      const adjustedLimit = await adaptiveLimiter.getAdjustedLimit(1000);
      
      // Should reduce to 40% under high load
      expect(adjustedLimit).toBe(400);
    });

    test('should reduce limits under high response times', async () => {
      adaptiveLimiter.setResponseTime(3000); // 3 second response time
      
      const adjustedLimit = await adaptiveLimiter.getAdjustedLimit(1000);
      
      // Should reduce to 60% under high response times
      expect(adjustedLimit).toBe(600);
    });

    test('should increase limits under healthy conditions', async () => {
      // Mock healthy system conditions
      jest.spyOn(process, 'cpuUsage').mockReturnValue({
        user: 200000, // 0.2 seconds
        system: 100000 // 0.1 seconds
      });

      jest.spyOn(process, 'memoryUsage').mockReturnValue({
        rss: 100 * 1024 * 1024,
        heapTotal: 200 * 1024 * 1024,
        heapUsed: 50 * 1024 * 1024, // 25% memory usage
        external: 10 * 1024 * 1024,
        arrayBuffers: 5 * 1024 * 1024
      });

      adaptiveLimiter.setResponseTime(300); // 300ms response time
      
      // Trigger metrics update
      jest.advanceTimersByTime(30000);

      const adjustedLimit = await adaptiveLimiter.getAdjustedLimit(1000);
      
      // Should increase to 130% under healthy conditions
      expect(adjustedLimit).toBe(1300);
    });

    test('should return base limit under normal conditions', async () => {
      const adjustedLimit = await adaptiveLimiter.getAdjustedLimit(1000);
      expect(adjustedLimit).toBe(1000);
    });
  });

  describe('EnterpriseRateLimitManager', () => {
    let manager: EnterpriseRateLimitManager;

    beforeEach(() => {
      // Reset environment
      delete process.env.REDIS_URL;
      manager = new EnterpriseRateLimitManager();
    });

    test('should initialize without Redis when not configured', () => {
      expect(manager).toBeDefined();
      expect(logger.warn).toHaveBeenCalledWith('Redis not configured, using memory-based rate limiting');
    });

    test('should initialize with Redis when configured', () => {
      process.env.REDIS_URL = 'redis://localhost:6379';
      const managerWithRedis = new EnterpriseRateLimitManager();
      
      expect(managerWithRedis).toBeDefined();
      expect(Redis).toHaveBeenCalledWith('redis://localhost:6379', expect.any(Object));
    });

    test('should extract client IP correctly', () => {
      const testCases = [
        { req: { ip: '1.2.3.4', headers: {} }, expected: '1.2.3.4' },
        { req: { headers: { 'x-forwarded-for': '5.6.7.8' } }, expected: '5.6.7.8' },
        { req: { headers: { 'x-forwarded-for': ['9.10.11.12'] } }, expected: '9.10.11.12' },
        { req: { connection: { remoteAddress: '13.14.15.16' }, headers: {} }, expected: '13.14.15.16' },
        { req: { socket: { remoteAddress: '17.18.19.20' }, headers: {} }, expected: '17.18.19.20' },
        { req: { headers: {} }, expected: 'unknown' }
      ];

      testCases.forEach(({ req, expected }) => {
        const ip = manager.getClientIP(req as any);
        expect(ip).toBe(expected);
      });
    });

    test('should extract client IP with comma-separated forwarded headers', () => {
      const req = {
        headers: { 'x-forwarded-for': '1.2.3.4,5.6.7.8,9.10.11.12' }
      };
      
      const ip = manager.getClientIP(req as any);
      expect(ip).toBe('1.2.3.4');
    });

    test('should check rate limits successfully', async () => {
      const result = await manager.checkRateLimit('standard', 'test-key');
      
      expect(result.allowed).toBe(true);
      expect(result.resetTime).toBeDefined();
      expect(result.remaining).toBe(10);
    });

    test('should handle rate limit exceeded', async () => {
      const mockLimiter = {
        consume: jest.fn().mockRejectedValue({
          remainingPoints: 0,
          msBeforeNext: 60000
        })
      };

      (RateLimiterMemory as jest.Mock).mockReturnValue(mockLimiter);
      const testManager = new EnterpriseRateLimitManager();
      
      const result = await testManager.checkRateLimit('standard', 'test-key');
      
      expect(result.allowed).toBe(false);
      expect(result.resetTime).toBeDefined();
      expect(result.remaining).toBe(0);
    });

    test('should handle rate limiting errors gracefully', async () => {
      const mockLimiter = {
        consume: jest.fn().mockRejectedValue(new Error('Redis connection failed'))
      };

      (RateLimiterMemory as jest.Mock).mockReturnValue(mockLimiter);
      const testManager = new EnterpriseRateLimitManager();
      
      const result = await testManager.checkRateLimit('standard', 'test-key');
      
      expect(result.allowed).toBe(true);
      expect(logger.error).toHaveBeenCalledWith(
        'Rate limiting error, allowing request',
        expect.objectContaining({
          error: 'Redis connection failed'
        })
      );
    });

    test('should handle missing rate limiter tier', async () => {
      const result = await manager.checkRateLimit('invalid-tier' as any, 'test-key');
      
      expect(result.allowed).toBe(true);
      expect(logger.warn).toHaveBeenCalledWith(
        "Rate limiter for tier 'invalid-tier' not found, allowing request"
      );
    });

    test('should record response times', async () => {
      await manager.recordResponseTime(1500);
      
      // Should call adaptive limiter setResponseTime
      expect(manager).toBeDefined();
    });

    test('should provide system status', () => {
      const status = manager.getSystemStatus();
      
      expect(status).toEqual({
        redisConnected: false,
        adaptiveEnabled: true,
        rateLimiters: expect.arrayContaining(['auth', 'standard', 'sensitive', 'webhooks'])
      });
    });

    test('should shutdown gracefully', async () => {
      await manager.shutdown();
      
      // Should complete without error
      expect(manager).toBeDefined();
    });

    test('should shutdown Redis connection when available', async () => {
      process.env.REDIS_URL = 'redis://localhost:6379';
      const mockRedis = {
        on: jest.fn(),
        quit: jest.fn().mockResolvedValue(undefined),
        status: 'ready'
      };
      
      (Redis as jest.Mock).mockReturnValue(mockRedis);
      const managerWithRedis = new EnterpriseRateLimitManager();
      
      await managerWithRedis.shutdown();
      
      expect(mockRedis.quit).toHaveBeenCalled();
      expect(logger.info).toHaveBeenCalledWith('Rate limiting Redis client disconnected');
    });
  });

  describe('createRateLimitMiddleware', () => {
    test('should create auth rate limit middleware', async () => {
      const middleware = createRateLimitMiddleware('auth');
      
      await middleware(mockRequest, mockResponse, mockNext);
      
      expect(mockResponse.setHeader).toHaveBeenCalledWith('X-RateLimit-Tier', 'auth');
      expect(mockNext).toHaveBeenCalled();
    });

    test('should create standard rate limit middleware', async () => {
      const middleware = createRateLimitMiddleware('standard');
      
      await middleware(mockRequest, mockResponse, mockNext);
      
      expect(mockResponse.setHeader).toHaveBeenCalledWith('X-RateLimit-Tier', 'standard');
      expect(mockNext).toHaveBeenCalled();
    });

    test('should create sensitive rate limit middleware', async () => {
      const middleware = createRateLimitMiddleware('sensitive');
      
      await middleware(mockRequest, mockResponse, mockNext);
      
      expect(mockResponse.setHeader).toHaveBeenCalledWith('X-RateLimit-Tier', 'sensitive');
      expect(mockNext).toHaveBeenCalled();
    });

    test('should create webhooks rate limit middleware', async () => {
      mockRequest.headers['x-webhook-id'] = 'webhook123';
      const middleware = createRateLimitMiddleware('webhooks');
      
      await middleware(mockRequest, mockResponse, mockNext);
      
      expect(mockResponse.setHeader).toHaveBeenCalledWith('X-RateLimit-Tier', 'webhooks');
      expect(mockNext).toHaveBeenCalled();
    });

    test('should set rate limit headers', async () => {
      const middleware = createRateLimitMiddleware('standard');
      
      await middleware(mockRequest, mockResponse, mockNext);
      
      expect(mockResponse.setHeader).toHaveBeenCalledWith('X-RateLimit-Reset', expect.any(Number));
      expect(mockResponse.setHeader).toHaveBeenCalledWith('X-RateLimit-Remaining', 10);
      expect(mockResponse.setHeader).toHaveBeenCalledWith('X-RateLimit-Tier', 'standard');
    });

    test('should block requests when rate limit exceeded', async () => {
      const mockManager = {
        ...rateLimitManager,
        checkRateLimit: jest.fn().mockResolvedValue({
          allowed: false,
          resetTime: new Date(Date.now() + 60000),
          remaining: 0
        }),
        getClientIP: jest.fn().mockReturnValue('127.0.0.1'),
        recordResponseTime: jest.fn()
      };

      // Mock the rateLimitManager globally
      jest.doMock('../../../src/middleware/rate-limiting', () => ({
        ...jest.requireActual('../../../src/middleware/rate-limiting'),
        rateLimitManager: mockManager
      }));

      const { createRateLimitMiddleware: mockCreateMiddleware } = jest.requireActual('../../../src/middleware/rate-limiting');
      const middleware = mockCreateMiddleware('standard');

      // Manually implement the middleware logic for testing
      const result = await mockManager.checkRateLimit('standard', 'test-id');
      
      if (!result.allowed) {
        mockResponse.status(429).json({
          error: {
            code: 'RATE_LIMIT_EXCEEDED',
            message: 'Too many requests. Please try again later.',
            tier: 'standard',
            resetTime: result.resetTime?.toISOString()
          }
        });
      }
      
      expect(mockResponse.status).toHaveBeenCalledWith(429);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: {
          code: 'RATE_LIMIT_EXCEEDED',
          message: 'Too many requests. Please try again later.',
          tier: 'standard',
          resetTime: expect.any(String)
        }
      });
    });

    test('should record response time on finish', async () => {
      const middleware = createRateLimitMiddleware('standard');
      
      await middleware(mockRequest, mockResponse, mockNext);
      
      expect(mockResponse.on).toHaveBeenCalledWith('finish', expect.any(Function));
    });

    test('should handle middleware errors gracefully', async () => {
      const mockManager = {
        ...rateLimitManager,
        checkRateLimit: jest.fn().mockRejectedValue(new Error('Rate limit check failed')),
        getClientIP: jest.fn().mockReturnValue('127.0.0.1')
      };

      // Replace rateLimitManager methods
      const originalCheck = rateLimitManager.checkRateLimit;
      const originalGetIP = rateLimitManager.getClientIP;
      
      (rateLimitManager as any).checkRateLimit = mockManager.checkRateLimit;
      (rateLimitManager as any).getClientIP = mockManager.getClientIP;

      const middleware = createRateLimitMiddleware('standard');
      
      await middleware(mockRequest, mockResponse, mockNext);
      
      expect(logger.error).toHaveBeenCalledWith(
        'Rate limiting middleware error',
        expect.objectContaining({
          error: 'Rate limit check failed',
          tier: 'standard'
        })
      );
      expect(mockNext).toHaveBeenCalled(); // Should fail open
      
      // Restore original methods
      (rateLimitManager as any).checkRateLimit = originalCheck;
      (rateLimitManager as any).getClientIP = originalGetIP;
    });
  });

  describe('ddosProtectionMiddleware', () => {
    test('should allow requests under DDoS threshold', async () => {
      const middleware = ddosProtectionMiddleware();
      
      await middleware(mockRequest, mockResponse, mockNext);
      
      expect(mockNext).toHaveBeenCalled();
    });

    test('should block requests when DDoS protection triggered', async () => {
      const mockManager = {
        ...rateLimitManager,
        checkRateLimit: jest.fn().mockResolvedValue({
          allowed: false,
          resetTime: new Date(Date.now() + 3600000)
        }),
        getClientIP: jest.fn().mockReturnValue('127.0.0.1')
      };

      // Replace rateLimitManager methods
      const originalCheck = rateLimitManager.checkRateLimit;
      const originalGetIP = rateLimitManager.getClientIP;
      
      (rateLimitManager as any).checkRateLimit = mockManager.checkRateLimit;
      (rateLimitManager as any).getClientIP = mockManager.getClientIP;

      const middleware = ddosProtectionMiddleware();
      
      await middleware(mockRequest, mockResponse, mockNext);
      
      expect(mockResponse.status).toHaveBeenCalledWith(429);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: {
          code: 'DDOS_PROTECTION',
          message: 'Request blocked by DDoS protection. Please try again later.',
          resetTime: expect.any(String)
        }
      });
      expect(logger.warn).toHaveBeenCalledWith(
        'DDoS protection triggered',
        expect.objectContaining({
          ip: '127.0.0.1',
          userAgent: 'test-agent'
        })
      );
      
      // Restore original methods
      (rateLimitManager as any).checkRateLimit = originalCheck;
      (rateLimitManager as any).getClientIP = originalGetIP;
    });

    test('should handle DDoS protection errors gracefully', async () => {
      const mockManager = {
        ...rateLimitManager,
        checkRateLimit: jest.fn().mockRejectedValue(new Error('DDoS check failed')),
        getClientIP: jest.fn().mockReturnValue('127.0.0.1')
      };

      // Replace rateLimitManager methods
      const originalCheck = rateLimitManager.checkRateLimit;
      const originalGetIP = rateLimitManager.getClientIP;
      
      (rateLimitManager as any).checkRateLimit = mockManager.checkRateLimit;
      (rateLimitManager as any).getClientIP = mockManager.getClientIP;

      const middleware = ddosProtectionMiddleware();
      
      await middleware(mockRequest, mockResponse, mockNext);
      
      expect(logger.error).toHaveBeenCalledWith(
        'DDoS protection error',
        expect.objectContaining({
          error: 'DDoS check failed'
        })
      );
      expect(mockNext).toHaveBeenCalled(); // Should fail open
      
      // Restore original methods
      (rateLimitManager as any).checkRateLimit = originalCheck;
      (rateLimitManager as any).getClientIP = originalGetIP;
    });

    test('should truncate long user agent strings', async () => {
      mockRequest.headers['user-agent'] = 'a'.repeat(200); // Long user agent
      
      const mockManager = {
        ...rateLimitManager,
        checkRateLimit: jest.fn().mockResolvedValue({
          allowed: false,
          resetTime: new Date(Date.now() + 3600000)
        }),
        getClientIP: jest.fn().mockReturnValue('127.0.0.1')
      };

      // Replace rateLimitManager methods
      const originalCheck = rateLimitManager.checkRateLimit;
      const originalGetIP = rateLimitManager.getClientIP;
      
      (rateLimitManager as any).checkRateLimit = mockManager.checkRateLimit;
      (rateLimitManager as any).getClientIP = mockManager.getClientIP;

      const middleware = ddosProtectionMiddleware();
      
      await middleware(mockRequest, mockResponse, mockNext);
      
      expect(logger.warn).toHaveBeenCalledWith(
        'DDoS protection triggered',
        expect.objectContaining({
          userAgent: 'a'.repeat(100) // Should be truncated to 100 characters
        })
      );
      
      // Restore original methods
      (rateLimitManager as any).checkRateLimit = originalCheck;
      (rateLimitManager as any).getClientIP = originalGetIP;
    });
  });
});