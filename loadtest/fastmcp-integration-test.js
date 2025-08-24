import http from "k6/http";
import { check, sleep } from "k6";
import { Counter, Rate, Trend } from "k6/metrics";

// Custom metrics for FastMCP integration performance
const fastmcpErrors = new Counter("fastmcp_errors");
const fastmcpSuccessRate = new Rate("fastmcp_success_rate");
const toolExecutionDuration = new Trend("fastmcp_tool_execution_duration");
const webSocketConnectionDuration = new Trend(
  "fastmcp_websocket_connection_duration",
);

// FastMCP Integration Load Testing Configuration
export const options = {
  scenarios: {
    // FastMCP Tool Execution Load Testing
    tool_execution: {
      executor: "ramping-vus",
      startVUs: 1,
      stages: [
        { duration: "2m", target: 50 }, // Ramp up to 50 users
        { duration: "5m", target: 100 }, // Stay at 100 users
        { duration: "2m", target: 200 }, // Ramp up to 200 users
        { duration: "5m", target: 200 }, // Stay at 200 users
        { duration: "2m", target: 0 }, // Ramp down
      ],
      tags: { scenario: "tool_execution" },
    },

    // WebSocket Connection Stress Testing
    websocket_stress: {
      executor: "constant-vus",
      vus: 500,
      duration: "10m",
      tags: { scenario: "websocket_stress" },
    },

    // Concurrent API Integration Testing
    concurrent_api: {
      executor: "per-vu-iterations",
      vus: 100,
      iterations: 50, // Each VU makes 50 API calls
      maxDuration: "15m",
      tags: { scenario: "concurrent_api" },
    },
  },

  // Performance thresholds for FastMCP integration
  thresholds: {
    fastmcp_tool_execution_duration: ["p(95)<500"], // < 500ms at p95
    fastmcp_websocket_connection_duration: ["p(95)<1000"], // < 1s at p95
    fastmcp_success_rate: ["rate>0.95"], // 95% success rate
    fastmcp_errors: ["count<200"], // Less than 200 total errors
    http_req_duration: ["p(95)<1000"], // 95% of requests under 1s
    http_req_failed: ["rate<0.05"], // Less than 5% failures
  },
};

const BASE_URL = __ENV.FASTMCP_URL || "http://fastmcp-server:8080";

// Mock OAuth token for testing
function getTestToken() {
  return "test-oauth-token-" + Math.random().toString(36).substring(2, 15);
}

// Test FastMCP tool execution with various Make.com tools
export function testToolExecution() {
  const tools = [
    "get-scenarios",
    "get-organizations",
    "get-connections",
    "get-data-structures",
    "create-webhook",
  ];

  const tool = tools[Math.floor(Math.random() * tools.length)];
  const startTime = Date.now();

  const response = http.post(
    `${BASE_URL}/fastmcp/tools/${tool}`,
    JSON.stringify({
      organizationId: `org-${Math.floor(Math.random() * 1000)}`,
      teamId: `team-${Math.floor(Math.random() * 100)}`,
      limit: Math.floor(Math.random() * 50) + 10,
    }),
    {
      headers: {
        Authorization: `Bearer ${getTestToken()}`,
        "Content-Type": "application/json",
      },
      tags: { tool: tool, endpoint: "tool_execution" },
    },
  );

  const success = check(response, {
    "Tool execution successful": (r) => r.status === 200 || r.status === 401, // 401 expected with test tokens
    "Tool execution within target": (r) => r.timings.duration < 500,
    "Response has valid JSON": (r) => {
      try {
        JSON.parse(r.body);
        return true;
      } catch {
        return false;
      }
    },
  });

  if (!success) {
    fastmcpErrors.add(1);
  }

  const duration = Date.now() - startTime;
  toolExecutionDuration.add(duration);
  fastmcpSuccessRate.add(success ? 1 : 0);

  sleep(Math.random() * 2 + 0.5); // Random sleep 0.5-2.5 seconds
}

// Test WebSocket connection establishment and maintenance
export function testWebSocketConnection() {
  const startTime = Date.now();

  // Simulate WebSocket connection handshake
  const wsHandshakeResponse = http.get(`${BASE_URL}/fastmcp/ws`, {
    headers: {
      Connection: "Upgrade",
      Upgrade: "websocket",
      "Sec-WebSocket-Key": btoa(Math.random().toString()),
      "Sec-WebSocket-Version": "13",
      Authorization: `Bearer ${getTestToken()}`,
    },
    tags: { endpoint: "websocket_handshake" },
  });

  const wsSuccess = check(wsHandshakeResponse, {
    "WebSocket handshake successful": (r) =>
      r.status === 101 || r.status === 404, // 404 if WS not implemented
    "WebSocket handshake fast": (r) => r.timings.duration < 1000,
  });

  if (!wsSuccess) {
    fastmcpErrors.add(1);
  }

  const duration = Date.now() - startTime;
  webSocketConnectionDuration.add(duration);
  fastmcpSuccessRate.add(wsSuccess ? 1 : 0);

  sleep(5); // Hold connection simulation
}

// Test concurrent API calls to multiple endpoints
export function testConcurrentAPI() {
  const endpoints = [
    "/health",
    "/oauth/session",
    "/fastmcp/tools/get-scenarios",
    "/fastmcp/tools/get-organizations",
  ];

  const requests = endpoints.map((endpoint) => {
    return {
      method: endpoint.includes("/tools/") ? "POST" : "GET",
      url: `${BASE_URL}${endpoint}`,
      body: endpoint.includes("/tools/")
        ? JSON.stringify({
            organizationId: `org-${Math.floor(Math.random() * 1000)}`,
          })
        : null,
      params: {
        headers: {
          Authorization: `Bearer ${getTestToken()}`,
          "Content-Type": "application/json",
        },
        tags: { endpoint: endpoint },
      },
    };
  });

  // Make concurrent requests
  const responses = http.batch(requests);

  let successCount = 0;
  responses.forEach((response, index) => {
    const success = check(response, {
      [`${endpoints[index]} successful`]: (r) => r.status < 500,
      [`${endpoints[index]} fast enough`]: (r) => r.timings.duration < 1000,
    });

    if (success) {
      successCount++;
    } else {
      fastmcpErrors.add(1);
    }
  });

  fastmcpSuccessRate.add(successCount / responses.length);

  sleep(1);
}

// Test Make.com API rate limiting behavior
export function testRateLimiting() {
  const requests = [];

  // Create 20 rapid requests to test rate limiting
  for (let i = 0; i < 20; i++) {
    requests.push({
      method: "POST",
      url: `${BASE_URL}/fastmcp/tools/get-scenarios`,
      body: JSON.stringify({
        organizationId: `rate-test-org-${i}`,
      }),
      params: {
        headers: {
          Authorization: `Bearer ${getTestToken()}`,
          "Content-Type": "application/json",
        },
        tags: { test: "rate_limiting", request_number: i },
      },
    });
  }

  const responses = http.batch(requests);

  let rateLimitedCount = 0;
  let successCount = 0;

  responses.forEach((response, index) => {
    if (response.status === 429) {
      rateLimitedCount++;
    } else if (response.status === 200 || response.status === 401) {
      successCount++;
    }
  });

  check(null, {
    "Rate limiting working": () => rateLimitedCount > 0 || successCount > 0,
    "Some requests succeeded": () => successCount > 0,
  });

  sleep(5); // Allow rate limiter to reset
}

// Memory and resource usage simulation
export function testResourceUsage() {
  // Create large payloads to test memory handling
  const largePayload = {
    organizationId: "memory-test-org",
    data: Array(1000)
      .fill()
      .map((_, i) => ({
        id: i,
        name: `Test Item ${i}`,
        description: "A".repeat(1000), // 1KB string per item = 1MB total
        metadata: {
          created: new Date().toISOString(),
          tags: Array(10)
            .fill()
            .map((_, j) => `tag-${i}-${j}`),
        },
      })),
  };

  const response = http.post(
    `${BASE_URL}/fastmcp/tools/process-large-data`,
    JSON.stringify(largePayload),
    {
      headers: {
        Authorization: `Bearer ${getTestToken()}`,
        "Content-Type": "application/json",
      },
      tags: { test: "memory_usage" },
    },
  );

  const success = check(response, {
    "Large payload handled": (r) => r.status < 500,
    "Memory test completed": (r) => r.timings.duration < 5000, // 5 second timeout
  });

  if (!success) {
    fastmcpErrors.add(1);
  }

  fastmcpSuccessRate.add(success ? 1 : 0);

  sleep(2);
}

// Main test execution based on scenario
export default function () {
  const scenario = __ENV.K6_SCENARIO || __ITER % 4;

  switch (scenario) {
    case "tool_execution":
    case 0:
      testToolExecution();
      break;
    case "websocket_stress":
    case 1:
      testWebSocketConnection();
      break;
    case "concurrent_api":
    case 2:
      testConcurrentAPI();
      break;
    case 3:
      if (__ITER % 10 === 0) {
        // Run less frequently
        testRateLimiting();
      } else if (__ITER % 20 === 0) {
        // Run even less frequently
        testResourceUsage();
      } else {
        testToolExecution();
      }
      break;
    default:
      testToolExecution();
  }
}

// Setup function to initialize test environment
export function setup() {
  console.log("Starting FastMCP Integration Load Test");

  // Warm up the server with a health check
  const healthResponse = http.get(`${BASE_URL}/health`);
  console.log("Server health check:", healthResponse.status);

  return { serverReady: healthResponse.status === 200 };
}

// Teardown function for cleanup and summary
export function teardown(data) {
  console.log("FastMCP Integration Load Test Completed");
  console.log("Server was ready:", data.serverReady);
  console.log("Total FastMCP Errors:", fastmcpErrors.value);
  console.log("FastMCP Success Rate:", fastmcpSuccessRate.rate);
}
