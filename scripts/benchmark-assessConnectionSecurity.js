#!/usr/bin/env node

/**
 * Benchmark Script for assessConnectionSecurity Function Performance Analysis
 *
 * Comprehensive benchmarking tool to validate the performance impact analysis
 * for Extract Method pattern refactoring. Provides detailed performance metrics,
 * memory usage analysis, and optimization recommendations.
 *
 * Usage:
 *   node scripts/benchmark-assessConnectionSecurity.js [options]
 *
 * Options:
 *   --iterations <n>     Number of test iterations (default: 1000)
 *   --connections <n>    Number of test connections (default: 100)
 *   --warmup <n>         Warmup iterations (default: 50)
 *   --output <format>    Output format: console|json|csv (default: console)
 *   --profile           Enable V8 profiling
 *   --gc                Force garbage collection between tests
 *   --concurrent <n>     Test concurrent execution with n connections
 */

import { performance } from "perf_hooks";
import { writeFileSync } from "fs";
import { join } from "path";

// Simulated connection data for benchmarking
const CONNECTION_TYPES = {
  simple: {
    id: 1001,
    name: "Simple Connection",
    service: "slack",
    accountName: "user@example.com",
    valid: true,
    lastVerified: new Date().toISOString(),
    createdAt: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString(), // 3 months ago
    credentials: {
      access_token: "simple_token_123",
      refresh_token: "refresh_456",
      scope: "read",
    },
  },

  complex: {
    id: 1002,
    name: "Complex OAuth Connection",
    service: "google",
    accountName: "admin@enterprise.com",
    valid: true,
    lastVerified: new Date().toISOString(),
    createdAt: new Date(Date.now() - 400 * 24 * 60 * 60 * 1000).toISOString(), // Over 1 year old
    credentials: {
      access_token:
        "complex_oauth_token_with_long_value_for_processing_overhead_simulation",
      refresh_token: "refresh_token_complex_value_456",
      client_secret: "test_client_secret_should_trigger_security_warning",
      password: "weak123",
      scope: "admin read write delete manage:users manage:system",
      api_key: "api_key_for_additional_processing",
      webhook_secret: "webhook_secret_value_for_validation",
      custom_field_1: "additional_credential_field_1",
      custom_field_2: "additional_credential_field_2",
      expires_at: new Date(Date.now() + 3600000).toISOString(),
    },
  },

  problematic: {
    id: 1003,
    name: "Problematic Connection",
    service: "legacy-api",
    accountName: "legacy@oldservice.com",
    valid: false,
    lastVerified: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(), // 30 days ago
    createdAt: new Date(Date.now() - 800 * 24 * 60 * 60 * 1000).toISOString(), // Over 2 years old
    credentials: {
      access_token: "expired_token_value",
      client_secret: "test_secret_in_production_environment",
      password: "123", // Very weak password
      scope: "admin write:all delete:all manage:everything",
      api_key: "hardcoded_api_key_value",
      webhook_url: "http://insecure.endpoint.com/webhook", // Insecure protocol
      custom_header: "custom_header_value_for_processing",
      expires_at: new Date(Date.now() - 86400000).toISOString(), // Expired 1 day ago
    },
  },
};

// Monolithic implementation for baseline comparison
async function assessConnectionSecurityMonolithic(connection) {
  const connectionId = connection.id;
  const service = connection.service;
  const securityIssues = [];
  const recommendations = [];

  // Simulate processing overhead
  await new Promise((resolve) => setTimeout(resolve, Math.random() * 0.5));

  const credentials = connection.credentials || {};
  const credentialKeys = Object.keys(credentials);

  // Credential security assessment with processing simulation
  for (const key of credentialKeys) {
    const value = credentials[key];
    if (typeof value === "string" && value.length > 0) {
      // Simulate string processing
      if (key.toLowerCase().includes("password") && value.length < 12) {
        securityIssues.push("Weak password detected");
      }
      if (key.toLowerCase().includes("secret") && value.startsWith("test_")) {
        securityIssues.push("Test credentials in production");
      }
      if (value.includes("hardcoded") || value.includes("insecure")) {
        securityIssues.push("Hardcoded or insecure credential detected");
      }
    }
  }

  // OAuth scope validation
  if (credentials.scope) {
    const scopes = credentials.scope.split(" ");
    if (scopes.includes("admin") || scopes.includes("write:all")) {
      securityIssues.push("Excessive permissions detected");
      recommendations.push("Review and limit OAuth scopes to minimum required");
    }
  }

  // Connection age assessment
  if (connection.createdAt) {
    const ageInDays =
      (Date.now() - new Date(connection.createdAt).getTime()) /
      (1000 * 60 * 60 * 24);
    if (ageInDays > 365) {
      securityIssues.push("Connection is over 1 year old");
      recommendations.push("Consider rotating connection credentials annually");
    }
  }

  // Validity check
  if (connection.valid === false) {
    securityIssues.push("Connection marked as invalid");
    recommendations.push("Verify and update connection credentials");
  }

  // Security scoring
  const securityScore = Math.max(0, 100 - securityIssues.length * 15);

  let severity = "info";
  if (securityScore < 40) severity = "critical";
  else if (securityScore < 60) severity = "error";
  else if (securityScore < 80) severity = "warning";

  if (recommendations.length === 0) {
    recommendations.push("Maintain current security practices");
  }

  return {
    category: "security",
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

// Refactored implementation with extracted methods
class RefactoredSecurityAssessment {
  assessCredentialSecurity(credentials) {
    const issues = [];
    const recommendations = [];
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
        if (value.includes("hardcoded") || value.includes("insecure")) {
          issues.push("Hardcoded or insecure credential detected");
          recommendations.push(
            "Remove hardcoded credentials and use secure storage",
          );
        }
      }
    }

    return { issues, recommendations };
  }

  validateOAuthScopes(credentials) {
    const issues = [];
    const recommendations = [];

    if (credentials.scope) {
      const scopes = credentials.scope.split(" ");
      if (scopes.includes("admin") || scopes.includes("write:all")) {
        issues.push("Excessive permissions detected");
        recommendations.push(
          "Review and limit OAuth scopes to minimum required",
        );
      }
    }

    return { issues, recommendations };
  }

  assessConnectionAge(connection) {
    const issues = [];
    const recommendations = [];

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

  validateConnectionStatus(connection) {
    const issues = [];
    const recommendations = [];

    if (connection.valid === false) {
      issues.push("Connection marked as invalid");
      recommendations.push("Verify and update connection credentials");
    }

    return { issues, recommendations };
  }

  calculateSecurityScore(issues) {
    const score = Math.max(0, 100 - issues.length * 15);

    let severity = "info";
    if (score < 40) severity = "critical";
    else if (score < 60) severity = "error";
    else if (score < 80) severity = "warning";

    return { score, severity };
  }

  buildSecurityResult(
    connection,
    securityScore,
    severity,
    issues,
    recommendations,
  ) {
    const finalRecommendations =
      recommendations.length === 0
        ? ["Maintain current security practices"]
        : recommendations;

    return {
      category: "security",
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

  async assessConnectionSecurity(connection) {
    // Simulate same processing overhead as monolithic
    await new Promise((resolve) => setTimeout(resolve, Math.random() * 0.5));

    const securityIssues = [];
    const recommendations = [];

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

    // Extract Method 4: Connection status validation
    const statusResults = this.validateConnectionStatus(connection);
    securityIssues.push(...statusResults.issues);
    recommendations.push(...statusResults.recommendations);

    // Extract Method 5: Security scoring
    const { score: securityScore, severity } =
      this.calculateSecurityScore(securityIssues);

    // Extract Method 6: Result construction
    return this.buildSecurityResult(
      connection,
      securityScore,
      severity,
      securityIssues,
      recommendations,
    );
  }
}

// Benchmark utilities
class BenchmarkRunner {
  constructor(options = {}) {
    this.iterations = options.iterations || 1000;
    this.warmupIterations = options.warmup || 50;
    this.enableGC = options.gc || false;
    this.enableProfiling = options.profile || false;
    this.outputFormat = options.output || "console";
    this.concurrentConnections = options.concurrent || 0;

    this.refactoredAssessment = new RefactoredSecurityAssessment();
    this.results = {
      monolithic: [],
      refactored: [],
      concurrent: [],
      memory: {
        before: {},
        after: {},
        peak: {},
      },
    };
  }

  forceGarbageCollection() {
    if (this.enableGC && global.gc) {
      global.gc();
      global.gc(); // Run twice to ensure cleanup
    }
  }

  async warmup() {
    console.log(`Warming up with ${this.warmupIterations} iterations...`);

    const warmupConnection = CONNECTION_TYPES.simple;

    for (let i = 0; i < this.warmupIterations; i++) {
      await assessConnectionSecurityMonolithic(warmupConnection);
      await this.refactoredAssessment.assessConnectionSecurity(
        warmupConnection,
      );
    }

    this.forceGarbageCollection();
    console.log("Warmup completed.");
  }

  async benchmarkSingleExecution() {
    console.log(
      `Running single execution benchmark with ${this.iterations} iterations...`,
    );

    const connections = [
      CONNECTION_TYPES.simple,
      CONNECTION_TYPES.complex,
      CONNECTION_TYPES.problematic,
    ];

    for (const [type, connection] of Object.entries(CONNECTION_TYPES)) {
      console.log(`\nBenchmarking ${type} connection type...`);

      // Benchmark monolithic implementation
      const monolithicDurations = [];
      this.forceGarbageCollection();

      for (let i = 0; i < this.iterations; i++) {
        const start = performance.now();
        await assessConnectionSecurityMonolithic(connection);
        const end = performance.now();
        monolithicDurations.push(end - start);
      }

      // Benchmark refactored implementation
      const refactoredDurations = [];
      this.forceGarbageCollection();

      for (let i = 0; i < this.iterations; i++) {
        const start = performance.now();
        await this.refactoredAssessment.assessConnectionSecurity(connection);
        const end = performance.now();
        refactoredDurations.push(end - start);
      }

      this.results.monolithic.push({
        type,
        durations: monolithicDurations,
        stats: this.calculateStats(monolithicDurations),
      });

      this.results.refactored.push({
        type,
        durations: refactoredDurations,
        stats: this.calculateStats(refactoredDurations),
      });
    }
  }

  async benchmarkConcurrentExecution() {
    if (this.concurrentConnections === 0) return;

    console.log(
      `\\nRunning concurrent execution benchmark with ${this.concurrentConnections} connections...`,
    );

    const connections = Array.from(
      { length: this.concurrentConnections },
      (_, i) => {
        const types = Object.values(CONNECTION_TYPES);
        return { ...types[i % types.length], id: 2000 + i };
      },
    );

    // Concurrent refactored execution
    const start = performance.now();
    const results = await Promise.all(
      connections.map((connection) =>
        this.refactoredAssessment.assessConnectionSecurity(connection),
      ),
    );
    const end = performance.now();

    const totalTime = end - start;
    const averageTime = totalTime / connections.length;
    const throughput = connections.length / (totalTime / 1000);

    this.results.concurrent.push({
      connections: this.concurrentConnections,
      totalTime,
      averageTime,
      throughput,
      results: results.length,
    });
  }

  async benchmarkMemoryUsage() {
    console.log("\\nRunning memory usage benchmark...");

    this.forceGarbageCollection();
    this.results.memory.before = process.memoryUsage();

    const connection = CONNECTION_TYPES.complex;
    const iterations = Math.min(this.iterations, 500); // Limit for memory testing

    // Test monolithic memory usage
    for (let i = 0; i < iterations; i++) {
      await assessConnectionSecurityMonolithic(connection);
    }

    this.forceGarbageCollection();
    const midMemory = process.memoryUsage();

    // Test refactored memory usage
    for (let i = 0; i < iterations; i++) {
      await this.refactoredAssessment.assessConnectionSecurity(connection);
    }

    this.forceGarbageCollection();
    this.results.memory.after = process.memoryUsage();

    this.results.memory.monolithic = {
      heapDelta: midMemory.heapUsed - this.results.memory.before.heapUsed,
      perCall:
        (midMemory.heapUsed - this.results.memory.before.heapUsed) / iterations,
    };

    this.results.memory.refactored = {
      heapDelta: this.results.memory.after.heapUsed - midMemory.heapUsed,
      perCall:
        (this.results.memory.after.heapUsed - midMemory.heapUsed) / iterations,
    };
  }

  calculateStats(durations) {
    const sorted = [...durations].sort((a, b) => a - b);
    const sum = sorted.reduce((a, b) => a + b, 0);
    const mean = sum / sorted.length;

    const variance =
      sorted.reduce((acc, val) => acc + Math.pow(val - mean, 2), 0) /
      sorted.length;
    const stdDev = Math.sqrt(variance);

    return {
      count: sorted.length,
      min: sorted[0],
      max: sorted[sorted.length - 1],
      mean,
      median: sorted[Math.floor(sorted.length / 2)],
      stdDev,
      p95: sorted[Math.floor(sorted.length * 0.95)],
      p99: sorted[Math.floor(sorted.length * 0.99)],
    };
  }

  async run() {
    console.log("Starting assessConnectionSecurity Performance Benchmark");
    console.log("=".repeat(60));

    const benchmarkStart = performance.now();

    await this.warmup();
    await this.benchmarkSingleExecution();
    await this.benchmarkConcurrentExecution();
    await this.benchmarkMemoryUsage();

    const benchmarkEnd = performance.now();
    console.log(
      `\\nBenchmark completed in ${(benchmarkEnd - benchmarkStart).toFixed(2)}ms`,
    );

    this.outputResults();
  }

  outputResults() {
    if (this.outputFormat === "json") {
      this.outputJSON();
    } else if (this.outputFormat === "csv") {
      this.outputCSV();
    } else {
      this.outputConsole();
    }
  }

  outputConsole() {
    console.log("\\n" + "=".repeat(80));
    console.log("PERFORMANCE BENCHMARK RESULTS");
    console.log("=".repeat(80));

    // Single execution results
    console.log("\\nSINGLE EXECUTION PERFORMANCE:");
    console.log("-".repeat(50));

    for (let i = 0; i < this.results.monolithic.length; i++) {
      const mono = this.results.monolithic[i];
      const refact = this.results.refactored[i];

      console.log(`\\n${mono.type.toUpperCase()} Connection Type:`);
      console.log(
        `  Monolithic - Mean: ${mono.stats.mean.toFixed(2)}ms, P95: ${mono.stats.p95.toFixed(2)}ms, StdDev: ${mono.stats.stdDev.toFixed(2)}ms`,
      );
      console.log(
        `  Refactored - Mean: ${refact.stats.mean.toFixed(2)}ms, P95: ${refact.stats.p95.toFixed(2)}ms, StdDev: ${refact.stats.stdDev.toFixed(2)}ms`,
      );

      const overheadPercent =
        ((refact.stats.mean - mono.stats.mean) / mono.stats.mean) * 100;
      const overheadMs = refact.stats.mean - mono.stats.mean;

      console.log(
        `  Overhead: ${overheadPercent.toFixed(1)}% (+${overheadMs.toFixed(2)}ms)`,
      );

      // Performance analysis
      if (overheadPercent < 10) {
        console.log(`  ✅ Low overhead - within acceptable range`);
      } else if (overheadPercent < 25) {
        console.log(
          `  ⚠️  Moderate overhead - acceptable for maintainability gains`,
        );
      } else {
        console.log(`  ❌ High overhead - optimization needed`);
      }
    }

    // Concurrent execution results
    if (this.results.concurrent.length > 0) {
      console.log("\\nCONCURRENT EXECUTION PERFORMANCE:");
      console.log("-".repeat(50));

      const concurrent = this.results.concurrent[0];
      console.log(`  Connections: ${concurrent.connections}`);
      console.log(`  Total Time: ${concurrent.totalTime.toFixed(2)}ms`);
      console.log(
        `  Average Time per Connection: ${concurrent.averageTime.toFixed(2)}ms`,
      );
      console.log(
        `  Throughput: ${concurrent.throughput.toFixed(1)} assessments/second`,
      );

      if (concurrent.throughput >= 20) {
        console.log(`  ✅ High throughput - excellent for enterprise scale`);
      } else if (concurrent.throughput >= 10) {
        console.log(
          `  ⚠️  Moderate throughput - acceptable for most use cases`,
        );
      } else {
        console.log(`  ❌ Low throughput - optimization required`);
      }
    }

    // Memory usage results
    if (this.results.memory.monolithic) {
      console.log("\\nMEMORY USAGE ANALYSIS:");
      console.log("-".repeat(50));

      const monoMem = this.results.memory.monolithic;
      const refactMem = this.results.memory.refactored;

      console.log(
        `  Monolithic - Total: ${(monoMem.heapDelta / 1024).toFixed(2)} KB, Per Call: ${monoMem.perCall.toFixed(0)} bytes`,
      );
      console.log(
        `  Refactored - Total: ${(refactMem.heapDelta / 1024).toFixed(2)} KB, Per Call: ${refactMem.perCall.toFixed(0)} bytes`,
      );

      const memoryOverhead = refactMem.perCall - monoMem.perCall;
      const memoryOverheadPercent = (memoryOverhead / monoMem.perCall) * 100;

      console.log(
        `  Memory Overhead: ${memoryOverheadPercent.toFixed(1)}% (+${memoryOverhead.toFixed(0)} bytes per call)`,
      );

      if (memoryOverheadPercent < 20) {
        console.log(`  ✅ Low memory overhead - within acceptable range`);
      } else if (memoryOverheadPercent < 40) {
        console.log(
          `  ⚠️  Moderate memory overhead - monitor for large-scale usage`,
        );
      } else {
        console.log(`  ❌ High memory overhead - optimization required`);
      }
    }

    // Overall assessment
    console.log("\\nOVERALL ASSESSMENT:");
    console.log("-".repeat(50));

    const avgOverhead =
      this.results.refactored.reduce((sum, result, i) => {
        const mono = this.results.monolithic[i];
        return (
          sum + ((result.stats.mean - mono.stats.mean) / mono.stats.mean) * 100
        );
      }, 0) / this.results.refactored.length;

    console.log(`  Average Performance Overhead: ${avgOverhead.toFixed(1)}%`);

    if (avgOverhead < 15) {
      console.log(
        `  ✅ RECOMMENDED: Performance impact is acceptable for complexity reduction benefits`,
      );
    } else if (avgOverhead < 25) {
      console.log(
        `  ⚠️  CONDITIONAL: Consider optimization strategies outlined in research analysis`,
      );
    } else {
      console.log(
        `  ❌ NOT RECOMMENDED: Performance impact too high, revisit refactoring approach`,
      );
    }

    // Recommendations
    console.log("\\nOPTIMIZATION RECOMMENDATIONS:");
    console.log("-".repeat(50));
    console.log("  1. Implement result caching for repeated assessments");
    console.log("  2. Use object pooling for intermediate result objects");
    console.log("  3. Consider parallel execution for independent checks");
    console.log("  4. Implement method-level caching for expensive operations");
    console.log("  5. Monitor performance in production with instrumentation");
  }

  outputJSON() {
    const jsonOutput = {
      benchmark: {
        timestamp: new Date().toISOString(),
        iterations: this.iterations,
        warmupIterations: this.warmupIterations,
        concurrentConnections: this.concurrentConnections,
      },
      results: this.results,
    };

    const filename = join(process.cwd(), "benchmark-results.json");
    writeFileSync(filename, JSON.stringify(jsonOutput, null, 2));
    console.log(`Results written to ${filename}`);
  }

  outputCSV() {
    const csvData = [];
    csvData.push("Type,Implementation,Mean,Median,P95,P99,StdDev,Min,Max");

    for (let i = 0; i < this.results.monolithic.length; i++) {
      const mono = this.results.monolithic[i];
      const refact = this.results.refactored[i];

      csvData.push(
        [
          mono.type,
          "monolithic",
          mono.stats.mean.toFixed(4),
          mono.stats.median.toFixed(4),
          mono.stats.p95.toFixed(4),
          mono.stats.p99.toFixed(4),
          mono.stats.stdDev.toFixed(4),
          mono.stats.min.toFixed(4),
          mono.stats.max.toFixed(4),
        ].join(","),
      );

      csvData.push(
        [
          refact.type,
          "refactored",
          refact.stats.mean.toFixed(4),
          refact.stats.median.toFixed(4),
          refact.stats.p95.toFixed(4),
          refact.stats.p99.toFixed(4),
          refact.stats.stdDev.toFixed(4),
          refact.stats.min.toFixed(4),
          refact.stats.max.toFixed(4),
        ].join(","),
      );
    }

    const filename = join(process.cwd(), "benchmark-results.csv");
    writeFileSync(filename, csvData.join("\\n"));
    console.log(`Results written to ${filename}`);
  }
}

// CLI argument parsing
function parseArgs() {
  const args = process.argv.slice(2);
  const options = {};

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    switch (arg) {
      case "--iterations":
        options.iterations = parseInt(args[++i]) || 1000;
        break;
      case "--connections":
        options.connections = parseInt(args[++i]) || 100;
        break;
      case "--warmup":
        options.warmup = parseInt(args[++i]) || 50;
        break;
      case "--output":
        options.output = args[++i] || "console";
        break;
      case "--profile":
        options.profile = true;
        break;
      case "--gc":
        options.gc = true;
        break;
      case "--concurrent":
        options.concurrent = parseInt(args[++i]) || 10;
        break;
      case "--help":
        console.log(`
Assessment Security Function Benchmark Tool

Usage: node scripts/benchmark-assessConnectionSecurity.js [options]

Options:
  --iterations <n>     Number of test iterations (default: 1000)
  --connections <n>    Number of test connections (default: 100)
  --warmup <n>         Warmup iterations (default: 50)
  --output <format>    Output format: console|json|csv (default: console)
  --profile            Enable V8 profiling
  --gc                 Force garbage collection between tests
  --concurrent <n>     Test concurrent execution with n connections
  --help               Show this help message

Examples:
  node scripts/benchmark-assessConnectionSecurity.js
  node scripts/benchmark-assessConnectionSecurity.js --iterations 2000 --output json
  node scripts/benchmark-assessConnectionSecurity.js --concurrent 20 --gc
        `);
        process.exit(0);
        break;
    }
  }

  return options;
}

// Main execution
async function main() {
  const options = parseArgs();
  const benchmark = new BenchmarkRunner(options);

  try {
    await benchmark.run();
  } catch (error) {
    console.error("Benchmark failed:", error);
    process.exit(1);
  }
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}

export {
  BenchmarkRunner,
  CONNECTION_TYPES,
  assessConnectionSecurityMonolithic,
  RefactoredSecurityAssessment,
};
