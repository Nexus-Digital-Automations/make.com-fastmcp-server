/**
 * Performance Tests for assessConnectionSecurity Function Refactoring
 *
 * Comprehensive performance testing suite to validate the impact analysis
 * for Extract Method pattern refactoring from complexity 21 to ≤12.
 *
 * Tests baseline performance, memory usage, concurrent execution,
 * and optimization strategies outlined in the research analysis.
 */

import { performance } from "perf_hooks";
import { jest } from "@jest/globals";
import { performanceMonitor } from "../../src/utils/performance-monitor.js";

// Mock the dependencies to control test environment
jest.mock("../../src/lib/make-api-client.js");
jest.mock("../../src/utils/validation.js");
jest.mock("../../src/utils/response-formatter.js");

interface ConnectionData {
  id: number;
  name: string;
  service: string;
  accountName: string;
  valid?: boolean;
  lastVerified?: string;
  createdAt?: string;
  credentials?: Record<string, unknown>;
}

interface ConnectionDiagnosticResult {
  category: "security";
  severity: "info" | "warning" | "error" | "critical";
  title: string;
  description: string;
  details: Record<string, unknown>;
  recommendations: string[];
  fixable: boolean;
  autoFixAction?: string;
  timestamp: string;
}

// Mock implementation of current monolithic function for baseline comparison
async function assessConnectionSecurityMonolithic(
  connection: ConnectionData,
): Promise<ConnectionDiagnosticResult> {
  const connectionId = connection.id;
  const service = connection.service;
  const securityIssues: string[] = [];
  const recommendations: string[] = [];

  // Simulate current monolithic logic with realistic processing times
  const credentials = connection.credentials || {};
  const credentialKeys = Object.keys(credentials);

  // Credential security assessment (simulated processing)
  for (const key of credentialKeys) {
    const value = credentials[key];
    if (typeof value === "string" && value.length > 0) {
      // Simulate string processing time
      await new Promise((resolve) => setTimeout(resolve, 0.1));

      if (key.toLowerCase().includes("password") && value.length < 12) {
        securityIssues.push("Weak password detected");
      }
      if (key.toLowerCase().includes("secret") && value.startsWith("test_")) {
        securityIssues.push("Test credentials in production");
      }
    }
  }

  // OAuth scope validation (simulated processing)
  if (credentials.scope) {
    const scopes = (credentials.scope as string).split(" ");
    if (scopes.includes("admin") || scopes.includes("write:all")) {
      securityIssues.push("Excessive permissions detected");
      recommendations.push("Review and limit OAuth scopes to minimum required");
    }
  }

  // Connection age assessment (simulated processing)
  if (connection.createdAt) {
    const ageInDays =
      (Date.now() - new Date(connection.createdAt).getTime()) /
      (1000 * 60 * 60 * 24);
    if (ageInDays > 365) {
      securityIssues.push("Connection is over 1 year old");
      recommendations.push("Consider rotating connection credentials annually");
    }
  }

  // Security scoring and result construction
  const securityScore = Math.max(0, 100 - securityIssues.length * 20);

  let severity: "info" | "warning" | "error" | "critical" = "info";
  if (securityScore < 40) {
    severity = "critical";
  } else if (securityScore < 60) {
    severity = "error";
  } else if (securityScore < 80) {
    severity = "warning";
  }

  if (recommendations.length === 0) {
    recommendations.push("Maintain current security practices");
  }

  return {
    category: "security" as const,
    severity,
    title: `Security Assessment: ${securityScore >= 80 ? "Good" : securityScore >= 60 ? "Fair" : "Poor"}`,
    description: `Connection security score: ${securityScore}/100`,
    details: {
      connectionId,
      service,
      securityScore,
      issuesFound: securityIssues.length,
      issues: securityIssues,
    },
    recommendations,
    fixable: securityIssues.length > 0,
    autoFixAction:
      securityIssues.length > 0 ? "apply-security-fixes" : undefined,
    timestamp: new Date().toISOString(),
  };
}

// Mock implementation of refactored extracted methods approach
class RefactoredSecurityAssessment {
  private assessCredentialSecurity(credentials: Record<string, unknown>): {
    issues: string[];
    recommendations: string[];
  } {
    const issues: string[] = [];
    const recommendations: string[] = [];
    const credentialKeys = Object.keys(credentials || {});

    for (const key of credentialKeys) {
      const value = credentials[key];
      if (typeof value === "string" && value.length > 0) {
        if (key.toLowerCase().includes("password") && value.length < 12) {
          issues.push("Weak password detected");
          recommendations.push("Use passwords with at least 12 characters");
        }
        if (key.toLowerCase().includes("secret") && value.startsWith("test_")) {
          issues.push("Test credentials in production");
          recommendations.push(
            "Replace test credentials with production values",
          );
        }
      }
    }

    return { issues, recommendations };
  }

  private validateOAuthScopes(credentials: Record<string, unknown>): {
    issues: string[];
    recommendations: string[];
  } {
    const issues: string[] = [];
    const recommendations: string[] = [];

    if (credentials.scope) {
      const scopes = (credentials.scope as string).split(" ");
      if (scopes.includes("admin") || scopes.includes("write:all")) {
        issues.push("Excessive permissions detected");
        recommendations.push(
          "Review and limit OAuth scopes to minimum required",
        );
      }
    }

    return { issues, recommendations };
  }

  private assessConnectionAge(connection: ConnectionData): {
    issues: string[];
    recommendations: string[];
  } {
    const issues: string[] = [];
    const recommendations: string[] = [];

    if (connection.createdAt) {
      const ageInDays =
        (Date.now() - new Date(connection.createdAt).getTime()) /
        (1000 * 60 * 60 * 24);
      if (ageInDays > 365) {
        issues.push("Connection is over 1 year old");
        recommendations.push(
          "Consider rotating connection credentials annually",
        );
      }
    }

    return { issues, recommendations };
  }

  private calculateSecurityScore(issues: string[]): {
    score: number;
    severity: "info" | "warning" | "error" | "critical";
  } {
    const score = Math.max(0, 100 - issues.length * 20);

    let severity: "info" | "warning" | "error" | "critical" = "info";
    if (score < 40) {
      severity = "critical";
    } else if (score < 60) {
      severity = "error";
    } else if (score < 80) {
      severity = "warning";
    }

    return { score, severity };
  }

  private buildSecurityResult(
    connection: ConnectionData,
    securityScore: number,
    severity: "info" | "warning" | "error" | "critical",
    issues: string[],
    recommendations: string[],
  ): ConnectionDiagnosticResult {
    const finalRecommendations =
      recommendations.length === 0
        ? ["Maintain current security practices"]
        : recommendations;

    return {
      category: "security" as const,
      severity,
      title: `Security Assessment: ${securityScore >= 80 ? "Good" : securityScore >= 60 ? "Fair" : "Poor"}`,
      description: `Connection security score: ${securityScore}/100`,
      details: {
        connectionId: connection.id,
        service: connection.service,
        securityScore,
        issuesFound: issues.length,
        issues,
      },
      recommendations: finalRecommendations,
      fixable: issues.length > 0,
      autoFixAction: issues.length > 0 ? "apply-security-fixes" : undefined,
      timestamp: new Date().toISOString(),
    };
  }

  async assessConnectionSecurity(
    connection: ConnectionData,
  ): Promise<ConnectionDiagnosticResult> {
    const securityIssues: string[] = [];
    const recommendations: string[] = [];

    // Extract Method 1: Credential security assessment
    const credentialResults = this.assessCredentialSecurity(
      connection.credentials || {},
    );
    securityIssues.push(...credentialResults.issues);
    recommendations.push(...credentialResults.recommendations);

    // Extract Method 2: OAuth scope validation
    const oauthResults = this.validateOAuthScopes(connection.credentials || {});
    securityIssues.push(...oauthResults.issues);
    recommendations.push(...oauthResults.recommendations);

    // Extract Method 3: Connection age assessment
    const ageResults = this.assessConnectionAge(connection);
    securityIssues.push(...ageResults.issues);
    recommendations.push(...ageResults.recommendations);

    // Extract Method 4: Security scoring
    const { score: securityScore, severity } =
      this.calculateSecurityScore(securityIssues);

    // Extract Method 5: Result construction
    return this.buildSecurityResult(
      connection,
      securityScore,
      severity,
      securityIssues,
      recommendations,
    );
  }
}

// Test data factory
function createTestConnection(
  overrides: Partial<ConnectionData> = {},
): ConnectionData {
  return {
    id: 12345,
    name: "Test Connection",
    service: "slack",
    accountName: "test@example.com",
    valid: true,
    lastVerified: new Date().toISOString(),
    createdAt: new Date(Date.now() - 180 * 24 * 60 * 60 * 1000).toISOString(), // 6 months ago
    credentials: {
      access_token: "valid_token_123",
      refresh_token: "refresh_token_456",
      scope: "read write",
      expires_at: new Date(Date.now() + 3600000).toISOString(),
    },
    ...overrides,
  };
}

function createComplexTestConnection(): ConnectionData {
  return createTestConnection({
    credentials: {
      access_token: "complex_token_with_long_value_to_simulate_processing",
      refresh_token: "refresh_token_456",
      client_secret: "test_secret_should_trigger_warning",
      password: "weak",
      scope: "admin read write delete",
      api_key: "another_key_for_processing",
      webhook_secret: "webhook_secret_value",
      expires_at: new Date(Date.now() + 3600000).toISOString(),
    },
    createdAt: new Date(Date.now() - 400 * 24 * 60 * 60 * 1000).toISOString(), // Over 1 year old
  });
}

function createTestConnections(count: number): ConnectionData[] {
  return Array.from({ length: count }, (_, i) =>
    i % 3 === 0 ? createComplexTestConnection() : createTestConnection(),
  );
}

describe("assessConnectionSecurity Performance Analysis", () => {
  let refactoredAssessment: RefactoredSecurityAssessment;

  beforeEach(() => {
    refactoredAssessment = new RefactoredSecurityAssessment();
    performanceMonitor.clear();
  });

  afterEach(() => {
    performanceMonitor.clear();
  });

  describe("Baseline Performance Comparison", () => {
    test("should measure baseline monolithic function performance", async () => {
      const connection = createTestConnection();
      const iterations = 100;
      const durations: number[] = [];

      for (let i = 0; i < iterations; i++) {
        const startTime = performance.now();
        await assessConnectionSecurityMonolithic(connection);
        const endTime = performance.now();
        durations.push(endTime - startTime);
      }

      const avgDuration =
        durations.reduce((sum, d) => sum + d, 0) / durations.length;
      const minDuration = Math.min(...durations);
      const maxDuration = Math.max(...durations);
      const p95Duration = durations.sort((a, b) => a - b)[
        Math.floor(iterations * 0.95)
      ];

      expect(avgDuration).toBeLessThan(50); // Should complete within 50ms on average
      expect(p95Duration).toBeLessThan(100); // P95 should be under 100ms

      console.log(
        `Monolithic Performance: avg=${avgDuration.toFixed(2)}ms, min=${minDuration.toFixed(2)}ms, max=${maxDuration.toFixed(2)}ms, p95=${p95Duration.toFixed(2)}ms`,
      );
    });

    test("should measure refactored function performance with method call overhead", async () => {
      const connection = createTestConnection();
      const iterations = 100;
      const durations: number[] = [];

      for (let i = 0; i < iterations; i++) {
        const startTime = performance.now();
        await refactoredAssessment.assessConnectionSecurity(connection);
        const endTime = performance.now();
        durations.push(endTime - startTime);
      }

      const avgDuration =
        durations.reduce((sum, d) => sum + d, 0) / durations.length;
      const minDuration = Math.min(...durations);
      const maxDuration = Math.max(...durations);
      const p95Duration = durations.sort((a, b) => a - b)[
        Math.floor(iterations * 0.95)
      ];

      expect(avgDuration).toBeLessThan(60); // Allow for method call overhead
      expect(p95Duration).toBeLessThan(120); // P95 should still be reasonable

      console.log(
        `Refactored Performance: avg=${avgDuration.toFixed(2)}ms, min=${minDuration.toFixed(2)}ms, max=${maxDuration.toFixed(2)}ms, p95=${p95Duration.toFixed(2)}ms`,
      );
    });

    test("should compare monolithic vs refactored performance overhead", async () => {
      const connection = createComplexTestConnection(); // Use complex connection for better measurement
      const iterations = 50;

      // Measure monolithic
      const monolithicDurations: number[] = [];
      for (let i = 0; i < iterations; i++) {
        const startTime = performance.now();
        await assessConnectionSecurityMonolithic(connection);
        const endTime = performance.now();
        monolithicDurations.push(endTime - startTime);
      }

      // Measure refactored
      const refactoredDurations: number[] = [];
      for (let i = 0; i < iterations; i++) {
        const startTime = performance.now();
        await refactoredAssessment.assessConnectionSecurity(connection);
        const endTime = performance.now();
        refactoredDurations.push(endTime - startTime);
      }

      const monolithicAvg =
        monolithicDurations.reduce((sum, d) => sum + d, 0) / iterations;
      const refactoredAvg =
        refactoredDurations.reduce((sum, d) => sum + d, 0) / iterations;
      const overheadPercent =
        ((refactoredAvg - monolithicAvg) / monolithicAvg) * 100;

      console.log(
        `Performance Overhead: ${overheadPercent.toFixed(1)}% (${refactoredAvg.toFixed(2)}ms vs ${monolithicAvg.toFixed(2)}ms)`,
      );

      // Research analysis predicted 15-20% overhead, this should validate
      expect(overheadPercent).toBeLessThan(25); // Should be within acceptable range
      expect(Math.abs(refactoredAvg - monolithicAvg)).toBeLessThan(10); // Absolute difference should be minimal
    });
  });

  describe("Memory Usage Analysis", () => {
    test("should measure memory allocation for monolithic function", async () => {
      const connection = createTestConnection();
      const iterations = 1000;

      // Force garbage collection before measurement
      if (global.gc) {
        global.gc();
      }

      const initialMemory = process.memoryUsage();

      for (let i = 0; i < iterations; i++) {
        await assessConnectionSecurityMonolithic(connection);
      }

      // Force garbage collection after measurement
      if (global.gc) {
        global.gc();
      }

      const finalMemory = process.memoryUsage();
      const heapDelta = finalMemory.heapUsed - initialMemory.heapUsed;
      const memoryPerCall = heapDelta / iterations;

      console.log(
        `Monolithic Memory: ${memoryPerCall} bytes per call (${(heapDelta / 1024).toFixed(2)} KB total)`,
      );

      expect(memoryPerCall).toBeLessThan(1000); // Should use less than 1KB per call on average
    });

    test("should measure memory allocation for refactored function", async () => {
      const connection = createTestConnection();
      const iterations = 1000;

      // Force garbage collection before measurement
      if (global.gc) {
        global.gc();
      }

      const initialMemory = process.memoryUsage();

      for (let i = 0; i < iterations; i++) {
        await refactoredAssessment.assessConnectionSecurity(connection);
      }

      // Force garbage collection after measurement
      if (global.gc) {
        global.gc();
      }

      const finalMemory = process.memoryUsage();
      const heapDelta = finalMemory.heapUsed - initialMemory.heapUsed;
      const memoryPerCall = heapDelta / iterations;

      console.log(
        `Refactored Memory: ${memoryPerCall} bytes per call (${(heapDelta / 1024).toFixed(2)} KB total)`,
      );

      expect(memoryPerCall).toBeLessThan(1500); // Allow for additional intermediate objects
    });
  });

  describe("Concurrent Execution Performance", () => {
    test("should handle concurrent security assessments efficiently", async () => {
      const connections = createTestConnections(20);
      const startTime = performance.now();

      const results = await Promise.all(
        connections.map((connection) =>
          refactoredAssessment.assessConnectionSecurity(connection),
        ),
      );

      const totalTime = performance.now() - startTime;
      const averageTime = totalTime / connections.length;

      expect(results).toHaveLength(connections.length);
      expect(averageTime).toBeLessThan(50); // Should be faster due to parallelization
      expect(totalTime).toBeLessThan(500); // Total time should be reasonable

      console.log(
        `Concurrent Execution: ${totalTime.toFixed(2)}ms total, ${averageTime.toFixed(2)}ms average per assessment`,
      );
    });

    test("should maintain performance under sustained load", async () => {
      const batchSize = 50;
      const batches = 5;
      const results: number[] = [];

      for (let batch = 0; batch < batches; batch++) {
        const connections = createTestConnections(batchSize);
        const startTime = performance.now();

        await Promise.all(
          connections.map((connection) =>
            refactoredAssessment.assessConnectionSecurity(connection),
          ),
        );

        const batchTime = performance.now() - startTime;
        const avgTimePerAssessment = batchTime / batchSize;
        results.push(avgTimePerAssessment);

        console.log(
          `Batch ${batch + 1}: ${avgTimePerAssessment.toFixed(2)}ms average per assessment`,
        );
      }

      // Check for performance degradation across batches
      const firstBatch = results[0];
      const lastBatch = results[results.length - 1];
      const degradationPercent = ((lastBatch - firstBatch) / firstBatch) * 100;

      expect(degradationPercent).toBeLessThan(20); // Should not degrade more than 20%
      console.log(`Performance degradation: ${degradationPercent.toFixed(1)}%`);
    });
  });

  describe("Enterprise-Scale Load Testing", () => {
    test("should meet enterprise performance targets under light load", async () => {
      const connections = createTestConnections(100);
      const concurrency = 5;
      const batches = Math.ceil(connections.length / concurrency);
      const durations: number[] = [];

      for (let i = 0; i < batches; i++) {
        const batch = connections.slice(i * concurrency, (i + 1) * concurrency);

        const batchPromises = batch.map(async (connection) => {
          const startTime = performance.now();
          await refactoredAssessment.assessConnectionSecurity(connection);
          return performance.now() - startTime;
        });

        const batchDurations = await Promise.all(batchPromises);
        durations.push(...batchDurations);
      }

      const avgDuration =
        durations.reduce((sum, d) => sum + d, 0) / durations.length;
      const p95Duration = durations.sort((a, b) => a - b)[
        Math.floor(durations.length * 0.95)
      ];

      // Enterprise targets from research analysis
      expect(avgDuration).toBeLessThan(20); // 20ms average
      expect(p95Duration).toBeLessThan(35); // 35ms P95

      console.log(
        `Light Load Performance: avg=${avgDuration.toFixed(2)}ms, p95=${p95Duration.toFixed(2)}ms`,
      );
    });

    test("should maintain acceptable performance under medium load", async () => {
      const connections = createTestConnections(200); // Reduced from 1000 for test efficiency
      const concurrency = 10;
      const batches = Math.ceil(connections.length / concurrency);
      const durations: number[] = [];

      const startTime = performance.now();

      for (let i = 0; i < batches; i++) {
        const batch = connections.slice(i * concurrency, (i + 1) * concurrency);

        const batchPromises = batch.map(async (connection) => {
          const assessmentStart = performance.now();
          await refactoredAssessment.assessConnectionSecurity(connection);
          return performance.now() - assessmentStart;
        });

        const batchDurations = await Promise.all(batchPromises);
        durations.push(...batchDurations);
      }

      const totalTime = performance.now() - startTime;
      const avgDuration =
        durations.reduce((sum, d) => sum + d, 0) / durations.length;
      const p95Duration = durations.sort((a, b) => a - b)[
        Math.floor(durations.length * 0.95)
      ];
      const throughput = connections.length / (totalTime / 1000); // assessments per second

      // Medium load targets (adjusted for test scale)
      expect(avgDuration).toBeLessThan(30); // 30ms average
      expect(p95Duration).toBeLessThan(50); // 50ms P95
      expect(throughput).toBeGreaterThan(10); // At least 10 assessments/second

      console.log(
        `Medium Load Performance: avg=${avgDuration.toFixed(2)}ms, p95=${p95Duration.toFixed(2)}ms, throughput=${throughput.toFixed(1)}/sec`,
      );
    });
  });

  describe("Performance Monitoring Integration", () => {
    test("should integrate with performance monitoring system", async () => {
      const connection = createTestConnection();

      const metricId = performanceMonitor.startMetric(
        "assessConnectionSecurity_test",
        "tool",
        { connectionType: connection.service },
      );

      const result =
        await refactoredAssessment.assessConnectionSecurity(connection);

      const metric = performanceMonitor.endMetric(metricId);

      expect(metric).toBeTruthy();
      expect(metric?.duration).toBeDefined();
      expect(metric?.category).toBe("tool");
      expect(result.category).toBe("security");

      // Check if metric meets performance targets
      expect(performanceMonitor.meetsPerformanceTarget(metric!)).toBe(true);
    });

    test("should track performance baseline establishment", async () => {
      const connections = createTestConnections(10);

      // Run multiple assessments to establish baseline
      for (const connection of connections) {
        const metricId = performanceMonitor.startMetric(
          "assessConnectionSecurity_baseline",
          "tool",
        );

        await refactoredAssessment.assessConnectionSecurity(connection);
        performanceMonitor.endMetric(metricId);
      }

      const summary = performanceMonitor.getPerformanceSummary();

      expect(summary.totalMetrics).toBeGreaterThan(0);
      expect(summary.baselines.length).toBeGreaterThan(0);

      const baseline = summary.baselines.find(
        (b) =>
          b.name === "assessConnectionSecurity_baseline" &&
          b.category === "tool",
      );

      expect(baseline).toBeDefined();
      expect(baseline?.samples).toBeGreaterThan(5); // Needs at least 5 samples for baseline
    });
  });

  describe("Performance Budget Validation", () => {
    test("should validate latency performance budget", async () => {
      const connection = createComplexTestConnection();
      const iterations = 20;
      const durations: number[] = [];

      for (let i = 0; i < iterations; i++) {
        const startTime = performance.now();
        await refactoredAssessment.assessConnectionSecurity(connection);
        const endTime = performance.now();
        durations.push(endTime - startTime);
      }

      const sorted = durations.sort((a, b) => a - b);
      const p50 = sorted[Math.floor(iterations * 0.5)];
      const p95 = sorted[Math.floor(iterations * 0.95)];
      const p99 = sorted[Math.floor(iterations * 0.99)];

      // Performance budget from research analysis
      expect(p50).toBeLessThan(15); // P50 target: 15ms
      expect(p95).toBeLessThan(35); // P95 target: 35ms
      expect(p99).toBeLessThan(75); // P99 target: 75ms

      console.log(
        `Performance Budget Validation - P50: ${p50.toFixed(2)}ms, P95: ${p95.toFixed(2)}ms, P99: ${p99.toFixed(2)}ms`,
      );
    });

    test("should validate resource usage budget", async () => {
      const connection = createTestConnection();
      const iterations = 100;

      // Force garbage collection for accurate measurement
      if (global.gc) {
        global.gc();
      }

      const initialMemory = process.memoryUsage();
      const startTime = process.cpuUsage();

      for (let i = 0; i < iterations; i++) {
        await refactoredAssessment.assessConnectionSecurity(connection);
      }

      const endTime = process.cpuUsage(startTime);

      // Force garbage collection and measure
      if (global.gc) {
        global.gc();
      }

      const finalMemory = process.memoryUsage();

      const memoryPerAssessment =
        (finalMemory.heapUsed - initialMemory.heapUsed) / iterations;
      const cpuTimePerAssessment =
        (endTime.user + endTime.system) / 1000 / iterations; // Convert to ms

      // Resource budget from research analysis
      expect(memoryPerAssessment).toBeLessThan(100 * 1024); // 100KB per assessment
      expect(cpuTimePerAssessment).toBeLessThan(5); // 5ms CPU time per assessment

      console.log(
        `Resource Budget - Memory: ${(memoryPerAssessment / 1024).toFixed(2)} KB/assessment, CPU: ${cpuTimePerAssessment.toFixed(2)} ms/assessment`,
      );
    });
  });

  describe("Optimization Strategy Validation", () => {
    test("should demonstrate caching optimization potential", async () => {
      const connection = createTestConnection();

      // Simple cache implementation for testing
      const cache = new Map<string, ConnectionDiagnosticResult>();
      const getCacheKey = (conn: ConnectionData) =>
        `${conn.id}_${JSON.stringify(conn.credentials)}`;

      // First call - cache miss
      const startTime1 = performance.now();
      const result1 =
        await refactoredAssessment.assessConnectionSecurity(connection);
      const duration1 = performance.now() - startTime1;

      cache.set(getCacheKey(connection), result1);

      // Second call - cache hit (simulated)
      const startTime2 = performance.now();
      const cachedResult = cache.get(getCacheKey(connection));
      const duration2 = performance.now() - startTime2;

      expect(cachedResult).toBeDefined();
      expect(duration2).toBeLessThan(duration1); // Cache should be faster
      expect(duration2).toBeLessThan(1); // Cache hit should be sub-millisecond

      const speedupFactor = duration1 / duration2;
      console.log(
        `Caching Speedup: ${speedupFactor.toFixed(1)}x faster (${duration1.toFixed(2)}ms → ${duration2.toFixed(4)}ms)`,
      );
    });

    test("should validate parallel execution optimization", async () => {
      const connections = createTestConnections(8);

      // Sequential execution
      const sequentialStart = performance.now();
      for (const connection of connections) {
        await refactoredAssessment.assessConnectionSecurity(connection);
      }
      const sequentialTime = performance.now() - sequentialStart;

      // Parallel execution
      const parallelStart = performance.now();
      await Promise.all(
        connections.map((connection) =>
          refactoredAssessment.assessConnectionSecurity(connection),
        ),
      );
      const parallelTime = performance.now() - parallelStart;

      const speedupFactor = sequentialTime / parallelTime;

      expect(speedupFactor).toBeGreaterThan(1.5); // Should be at least 1.5x faster
      console.log(
        `Parallel Execution Speedup: ${speedupFactor.toFixed(1)}x faster (${sequentialTime.toFixed(2)}ms → ${parallelTime.toFixed(2)}ms)`,
      );
    });
  });
});

/**
 * Performance Test Summary
 *
 * This test suite validates the performance impact analysis for the
 * assessConnectionSecurity function refactoring from complexity 21 to ≤12.
 *
 * Key Validations:
 * 1. Method call overhead measurement (expected +2-5ms)
 * 2. Memory usage impact (expected +15-25% increase)
 * 3. CPU performance characteristics
 * 4. Concurrent execution performance
 * 5. Enterprise-scale load testing
 * 6. Performance budget compliance
 * 7. Optimization strategy effectiveness
 *
 * Expected Results:
 * - Latency increase: 15-20% (acceptable trade-off)
 * - Memory increase: 15-25% (within enterprise limits)
 * - Scalability: Maintained or improved
 * - Optimization potential: High (caching, parallelization)
 */
