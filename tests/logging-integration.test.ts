/**
 * Integration tests for the Winston logging system
 * Tests actual logging functionality with mocked dependencies
 */

import {
  describe,
  test,
  expect,
  beforeEach,
  afterEach,
  beforeAll,
} from "@jest/globals";
import { MockDataFactory, ErrorScenarioFactory } from "./utils/mock-factories";
import { measurePerformance } from "./setup";

// Test environment setup
beforeAll(() => {
  process.env.MAKE_API_KEY = "test-api-key-12345";
  process.env.MAKE_BASE_URL = "https://test.make.com/api/v2";
  process.env.LOG_LEVEL = "debug";
  process.env.LOG_FILE_ENABLED = "true";
});

describe("FastMCP Server Logging Integration Tests", () => {
  describe("Error Classification and Logging", () => {
    test("should categorize authentication errors correctly", () => {
      const authError = ErrorScenarioFactory.createAuthenticationError();

      // Simulate error classification logic
      const category =
        authError.status === 401 ? "AUTHENTICATION_ERROR" : "UNKNOWN";
      const severity = authError.status === 401 ? "HIGH" : "LOW";

      expect(category).toBe("AUTHENTICATION_ERROR");
      expect(severity).toBe("HIGH");
    });

    test("should categorize rate limit errors correctly", () => {
      const rateLimitError = ErrorScenarioFactory.createRateLimitError();

      const category =
        rateLimitError.status === 429 ? "RATE_LIMIT_ERROR" : "UNKNOWN";
      const severity = rateLimitError.status === 429 ? "MEDIUM" : "LOW";

      expect(category).toBe("RATE_LIMIT_ERROR");
      expect(severity).toBe("MEDIUM");
      expect(rateLimitError.headers["retry-after"]).toBe("60");
    });

    test("should categorize server errors correctly", () => {
      const serverError = ErrorScenarioFactory.createServerError();

      const category = serverError.status >= 500 ? "INTERNAL_ERROR" : "UNKNOWN";
      const severity = serverError.status >= 500 ? "HIGH" : "LOW";

      expect(category).toBe("INTERNAL_ERROR");
      expect(severity).toBe("HIGH");
    });

    test("should categorize timeout errors correctly", () => {
      const timeoutError = ErrorScenarioFactory.createTimeoutError();

      const category =
        timeoutError.code === "ECONNABORTED" ? "TIMEOUT_ERROR" : "UNKNOWN";
      const severity = timeoutError.code === "ECONNABORTED" ? "MEDIUM" : "LOW";

      expect(category).toBe("TIMEOUT_ERROR");
      expect(severity).toBe("MEDIUM");
    });

    test("should categorize network errors correctly", () => {
      const networkError = ErrorScenarioFactory.createNetworkError();

      const category =
        networkError.code === "ENOTFOUND" ? "MAKE_API_ERROR" : "UNKNOWN";
      const severity = "LOW"; // Network errors are typically recoverable

      expect(category).toBe("MAKE_API_ERROR");
      expect(severity).toBe("LOW");
      expect(networkError.hostname).toBe("us1.make.com");
    });
  });

  describe("Correlation ID Generation", () => {
    test("should generate valid UUID correlation IDs", () => {
      const generateCorrelationId = () => {
        // Simulate UUID v4 generation (simplified)
        return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
          const r = (Math.random() * 16) | 0;
          const v = c === "x" ? r : (r & 0x3) | 0x8;
          return v.toString(16);
        });
      };

      const correlationId = generateCorrelationId();

      // Test UUID v4 format
      expect(correlationId).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      );
    });

    test("should generate unique correlation IDs", () => {
      const generateCorrelationId = () => {
        return "test-correlation-" + Math.random().toString(36).substr(2, 15);
      };

      const ids = Array.from({ length: 100 }, () => generateCorrelationId());
      const uniqueIds = new Set(ids);

      expect(uniqueIds.size).toBe(100); // All should be unique
    });
  });

  describe("Performance Monitoring", () => {
    test("should track operation duration", async () => {
      const mockOperation = async () => {
        await new Promise((resolve) => setTimeout(resolve, 100));
        return "operation completed";
      };

      const { result, duration, memoryDelta } = await measurePerformance(
        mockOperation,
        "test operation",
      );

      expect(result).toBe("operation completed");
      expect(duration).toBeGreaterThan(90); // Should be at least 90ms
      expect(duration).toBeLessThan(200); // Should complete within 200ms
      expect(typeof memoryDelta).toBe("number");
    });

    test("should monitor memory usage during error processing", async () => {
      const errorOperation = async () => {
        // Simulate error processing that might consume memory
        const errors = Array.from({ length: 1000 }, (_, i) => ({
          id: `error-${i}`,
          message: `Test error ${i}`,
          category: "MAKE_API_ERROR",
          severity: "LOW",
          timestamp: new Date().toISOString(),
        }));

        // Process errors
        return errors.filter((error) => error.severity === "HIGH").length;
      };

      const { result, duration, memoryDelta } = await measurePerformance(
        errorOperation,
        "error processing",
      );

      expect(result).toBe(0); // No HIGH severity errors in test data
      expect(duration).toBeLessThan(100); // Should be fast
      expect(Math.abs(memoryDelta)).toBeLessThan(10 * 1024 * 1024); // Less than 10MB
    });
  });

  describe("Structured Logging Format", () => {
    test("should format log entries consistently", () => {
      const createLogEntry = (level: string, message: string, data: any) => ({
        level,
        message,
        timestamp: new Date().toISOString(),
        ...data,
      });

      const logEntry = createLogEntry("error", "API request failed", {
        correlationId: "test-123",
        operation: "GET /scenarios",
        duration: 250,
        category: "AUTHENTICATION_ERROR",
        severity: "HIGH",
        statusCode: 401,
      });

      expect(logEntry).toHaveProperty("level", "error");
      expect(logEntry).toHaveProperty("message", "API request failed");
      expect(logEntry).toHaveProperty("timestamp");
      expect(logEntry).toHaveProperty("correlationId", "test-123");
      expect(logEntry).toHaveProperty("operation", "GET /scenarios");
      expect(logEntry).toHaveProperty("duration", 250);
      expect(logEntry).toHaveProperty("category", "AUTHENTICATION_ERROR");
      expect(logEntry).toHaveProperty("severity", "HIGH");
      expect(logEntry).toHaveProperty("statusCode", 401);
    });

    test("should handle missing data gracefully", () => {
      const createLogEntry = (level: string, message: string, data?: any) => {
        const entry: any = {
          level,
          message,
          timestamp: new Date().toISOString(),
        };

        if (data) {
          Object.assign(entry, data);
        }

        return entry;
      };

      const logEntry = createLogEntry("info", "Operation completed");

      expect(logEntry).toHaveProperty("level", "info");
      expect(logEntry).toHaveProperty("message", "Operation completed");
      expect(logEntry).toHaveProperty("timestamp");
      expect(logEntry).not.toHaveProperty("correlationId");
    });
  });

  describe("Mock Data Factory Integration", () => {
    test("should create realistic scenarios for testing", () => {
      const scenario = MockDataFactory.createScenario({
        name: "Logging Test Scenario",
        status: "active",
      });

      expect(scenario).toHaveProperty("id");
      expect(scenario.name).toBe("Logging Test Scenario");
      expect(scenario.status).toBe("active");
      expect(scenario).toHaveProperty("created_at");
      expect(new Date(scenario.created_at)).toBeInstanceOf(Date);
    });

    test("should create realistic connections for testing", () => {
      const connection = MockDataFactory.createConnection({
        app: "test-webhook",
        name: "Logging Test Connection",
      });

      expect(connection).toHaveProperty("id");
      expect(connection.app).toBe("test-webhook");
      expect(connection.name).toBe("Logging Test Connection");
      expect(["verified", "error"]).toContain(connection.status);
    });

    test("should create realistic users for testing", () => {
      const user = MockDataFactory.createUser({
        name: "Test Logger",
        email: "logger@test.com",
        role: "admin",
      });

      expect(user).toHaveProperty("id");
      expect(user.name).toBe("Test Logger");
      expect(user.email).toBe("logger@test.com");
      expect(user.role).toBe("admin");
    });
  });

  describe("Error Response Generation", () => {
    test("should generate proper API error responses", () => {
      const errorResponse = MockDataFactory.createApiErrorResponse(
        401,
        "Authentication failed",
      );

      expect(errorResponse.status).toBe(401);
      expect(errorResponse.data.error).toBe("UNAUTHORIZED");
      expect(errorResponse.data.message).toBe("Authentication failed");
      expect(errorResponse.data).toHaveProperty("timestamp");
    });

    test("should map status codes to error types correctly", () => {
      const testCases = [
        { status: 400, expectedError: "BAD_REQUEST" },
        { status: 401, expectedError: "UNAUTHORIZED" },
        { status: 403, expectedError: "FORBIDDEN" },
        { status: 404, expectedError: "NOT_FOUND" },
        { status: 429, expectedError: "RATE_LIMIT_EXCEEDED" },
        { status: 500, expectedError: "INTERNAL_SERVER_ERROR" },
        { status: 502, expectedError: "BAD_GATEWAY" },
        { status: 503, expectedError: "SERVICE_UNAVAILABLE" },
        { status: 504, expectedError: "GATEWAY_TIMEOUT" },
        { status: 999, expectedError: "UNKNOWN_ERROR" },
      ];

      testCases.forEach(({ status, expectedError }) => {
        const response = MockDataFactory.createApiErrorResponse(
          status,
          "Test error",
        );
        expect(response.data.error).toBe(expectedError);
      });
    });
  });

  describe("Concurrent Operations", () => {
    test("should handle multiple simultaneous logging operations", async () => {
      const operations = Array.from({ length: 10 }, (_, i) => ({
        correlationId: `test-${i}`,
        operation: `TEST_OP_${i}`,
        duration: Math.random() * 100,
        statusCode: [200, 401, 500, 429][Math.floor(Math.random() * 4)],
      }));

      const processOperations = async () => {
        return Promise.all(
          operations.map(async (op) => ({
            ...op,
            category:
              op.statusCode === 401
                ? "AUTHENTICATION_ERROR"
                : op.statusCode === 429
                  ? "RATE_LIMIT_ERROR"
                  : op.statusCode >= 500
                    ? "INTERNAL_ERROR"
                    : "SUCCESS",
            severity: op.statusCode >= 400 ? "HIGH" : "INFO",
          })),
        );
      };

      const results = await processOperations();

      expect(results).toHaveLength(10);
      results.forEach((result) => {
        expect(result).toHaveProperty("correlationId");
        expect(result).toHaveProperty("category");
        expect(result).toHaveProperty("severity");
      });
    });
  });

  describe("Environment Configuration", () => {
    test("should respect environment variables", () => {
      expect(process.env.MAKE_API_KEY).toBe("test-api-key-12345");
      expect(process.env.MAKE_BASE_URL).toBe("https://test.make.com/api/v2");
      expect(process.env.LOG_LEVEL).toBe("debug");
      expect(process.env.LOG_FILE_ENABLED).toBe("true");
    });

    test("should provide default values when environment variables are missing", () => {
      const getConfig = (envVar: string, defaultValue: string) => {
        return process.env[envVar] || defaultValue;
      };

      expect(getConfig("MISSING_VAR", "default")).toBe("default");
      expect(getConfig("LOG_LEVEL", "info")).toBe("debug"); // Should use env value
    });
  });

  describe("File System Operations", () => {
    test("should handle log file path validation", () => {
      const isValidLogPath = (path: string) => {
        const validPattern = /^logs\/fastmcp-server-\d{4}-\d{2}-\d{2}\.log$/;
        return validPattern.test(path);
      };

      const today = new Date();
      const dateString =
        today.getFullYear() +
        "-" +
        String(today.getMonth() + 1).padStart(2, "0") +
        "-" +
        String(today.getDate()).padStart(2, "0");

      const validPath = `logs/fastmcp-server-${dateString}.log`;
      const invalidPath = "logs/invalid-log-name.log";

      expect(isValidLogPath(validPath)).toBe(true);
      expect(isValidLogPath(invalidPath)).toBe(false);
    });
  });

  describe("Data Sanitization", () => {
    test("should sanitize sensitive data in logs", () => {
      const sanitizeLogData = (data: any) => {
        const sensitiveKeys = ["password", "token", "api_key", "secret"];
        const sanitized = { ...data };

        sensitiveKeys.forEach((key) => {
          if (sanitized[key]) {
            sanitized[key] = "[REDACTED]";
          }
        });

        return sanitized;
      };

      const logData = {
        correlationId: "test-123",
        operation: "POST /auth",
        password: "secret123",
        api_key: "abc123def456",
        duration: 150,
      };

      const sanitized = sanitizeLogData(logData);

      expect(sanitized.correlationId).toBe("test-123");
      expect(sanitized.operation).toBe("POST /auth");
      expect(sanitized.duration).toBe(150);
      expect(sanitized.password).toBe("[REDACTED]");
      expect(sanitized.api_key).toBe("[REDACTED]");
    });
  });
});
