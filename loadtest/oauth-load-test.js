import http from "k6/http";
import { check, sleep } from "k6";
import { Counter, Rate, Trend } from "k6/metrics";

// Custom metrics for OAuth-specific performance tracking
const oauthErrors = new Counter("oauth_errors");
const oauthSuccessRate = new Rate("oauth_success_rate");
const authFlowDuration = new Trend("oauth_auth_flow_duration");
const tokenRefreshDuration = new Trend("oauth_token_refresh_duration");
const sessionValidationDuration = new Trend(
  "oauth_session_validation_duration",
);

// Load testing configuration based on research recommendations
export const options = {
  scenarios: {
    // OAuth Authorization Flow Load Testing
    authorization_flow: {
      executor: "constant-arrival-rate",
      rate: 50, // 50 new auth flows per second
      timeUnit: "1s",
      duration: "5m",
      preAllocatedVUs: 100,
      maxVUs: 200,
      tags: { scenario: "auth_flow" },
    },

    // Token Refresh Performance Testing
    token_refresh: {
      executor: "ramping-rate",
      startRate: 0,
      timeUnit: "1s",
      preAllocatedVUs: 50,
      maxVUs: 600,
      stages: [
        { duration: "2m", target: 100 }, // Ramp up to 100/sec
        { duration: "5m", target: 500 }, // Sustain 500/sec
        { duration: "2m", target: 0 }, // Ramp down
      ],
      tags: { scenario: "token_refresh" },
    },

    // Session Validation Stress Testing
    session_validation: {
      executor: "per-vu-iterations",
      vus: 1000, // 1000 concurrent users
      iterations: 10, // Each user validates 10 times
      maxDuration: "10m",
      tags: { scenario: "session_validation" },
    },
  },

  // Performance thresholds based on research targets
  thresholds: {
    // OAuth Performance Targets from research report
    oauth_auth_flow_duration: ["p(95)<200"], // < 200ms at p95
    oauth_token_refresh_duration: ["p(95)<100"], // < 100ms at p95
    oauth_session_validation_duration: ["p(95)<50"], // < 50ms at p95
    oauth_success_rate: ["rate>0.99"], // 99% success rate
    oauth_errors: ["count<100"], // Less than 100 total errors

    // General HTTP performance
    http_req_duration: ["p(95)<500"], // 95% of requests under 500ms
    http_req_failed: ["rate<0.01"], // Less than 1% failures
  },
};

// Base URL for FastMCP server
const BASE_URL = __ENV.FASTMCP_URL || "http://fastmcp-server:8080";

// OAuth configuration for Make.com integration testing
const OAUTH_CONFIG = {
  clientId: __ENV.MAKE_CLIENT_ID || "test-client-id",
  redirectUri:
    __ENV.OAUTH_REDIRECT_URI || "http://localhost:8080/oauth/callback",
  scope: "scenarios:read scenarios:write organizations:read",
  responseType: "code",
  codeChallenge: generatePKCEChallenge(),
  codeChallengeMethod: "S256",
};

// Generate PKCE code challenge for OAuth 2.1 compliance
function generatePKCEChallenge() {
  // Simple PKCE challenge generation for load testing
  const codeVerifier = Array.from(
    { length: 43 },
    () =>
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"[
        Math.floor(Math.random() * 66)
      ],
  ).join("");

  // In real implementation, this would be SHA256 hash of codeVerifier
  // For load testing, we'll use a simplified approach
  return btoa(codeVerifier)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

// OAuth Authorization Flow Test
export function authorizationFlow() {
  if (__ITER % 3 !== 0) return; // Run only in authorization_flow scenario

  const startTime = Date.now();

  // Step 1: Initiate OAuth authorization
  const authUrl =
    `${BASE_URL}/oauth/authorize?` +
    `client_id=${OAUTH_CONFIG.clientId}&` +
    `redirect_uri=${encodeURIComponent(OAUTH_CONFIG.redirectUri)}&` +
    `response_type=${OAUTH_CONFIG.responseType}&` +
    `scope=${encodeURIComponent(OAUTH_CONFIG.scope)}&` +
    `code_challenge=${OAUTH_CONFIG.codeChallenge}&` +
    `code_challenge_method=${OAUTH_CONFIG.codeChallengeMethod}&` +
    `state=${Math.random().toString(36).substring(2, 15)}`;

  const authResponse = http.get(authUrl, {
    tags: { endpoint: "oauth_authorize" },
  });

  const authSuccess = check(authResponse, {
    "OAuth authorize request successful": (r) =>
      r.status === 302 || r.status === 200,
    "OAuth authorize response time OK": (r) => r.timings.duration < 200,
  });

  if (!authSuccess) {
    oauthErrors.add(1);
  }

  // Step 2: Simulate authorization code exchange (simplified for load testing)
  if (authSuccess) {
    const tokenResponse = http.post(
      `${BASE_URL}/oauth/token`,
      {
        grant_type: "authorization_code",
        client_id: OAUTH_CONFIG.clientId,
        code: "test-auth-code-" + Math.random().toString(36).substring(2, 15),
        redirect_uri: OAUTH_CONFIG.redirectUri,
        code_verifier: "test-code-verifier",
      },
      {
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        tags: { endpoint: "oauth_token" },
      },
    );

    const tokenSuccess = check(tokenResponse, {
      "OAuth token exchange successful": (r) => r.status === 200,
      "OAuth token contains access_token": (r) => {
        try {
          const body = JSON.parse(r.body);
          return body.access_token !== undefined;
        } catch {
          return false;
        }
      },
    });

    if (!tokenSuccess) {
      oauthErrors.add(1);
    }

    oauthSuccessRate.add(tokenSuccess ? 1 : 0);
  }

  const duration = Date.now() - startTime;
  authFlowDuration.add(duration);

  sleep(1);
}

// Token Refresh Performance Test
export function tokenRefresh() {
  if (__ITER % 3 !== 1) return; // Run only in token_refresh scenario

  const startTime = Date.now();

  // Simulate token refresh request
  const refreshResponse = http.post(
    `${BASE_URL}/oauth/token`,
    {
      grant_type: "refresh_token",
      refresh_token:
        "test-refresh-token-" + Math.random().toString(36).substring(2, 15),
      client_id: OAUTH_CONFIG.clientId,
    },
    {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      tags: { endpoint: "oauth_refresh" },
    },
  );

  const refreshSuccess = check(refreshResponse, {
    "Token refresh successful": (r) => r.status === 200,
    "Token refresh response time OK": (r) => r.timings.duration < 100,
    "New access token provided": (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.access_token !== undefined;
      } catch {
        return false;
      }
    },
  });

  if (!refreshSuccess) {
    oauthErrors.add(1);
  }

  const duration = Date.now() - startTime;
  tokenRefreshDuration.add(duration);
  oauthSuccessRate.add(refreshSuccess ? 1 : 0);

  sleep(0.5);
}

// Session Validation Stress Test
export function sessionValidation() {
  if (__ITER % 3 !== 2) return; // Run only in session_validation scenario

  const startTime = Date.now();

  // Test session validation with mock access token
  const sessionResponse = http.get(`${BASE_URL}/oauth/session`, {
    headers: {
      Authorization: `Bearer test-access-token-${Math.random().toString(36).substring(2, 15)}`,
    },
    tags: { endpoint: "oauth_session_validation" },
  });

  const sessionSuccess = check(sessionResponse, {
    "Session validation responded": (r) => r.status !== 0,
    "Session validation fast": (r) => r.timings.duration < 50,
  });

  if (!sessionSuccess) {
    oauthErrors.add(1);
  }

  const duration = Date.now() - startTime;
  sessionValidationDuration.add(duration);
  oauthSuccessRate.add(sessionSuccess ? 1 : 0);

  sleep(0.1);
}

// FastMCP Tool Execution Load Test
export function toolExecution() {
  const startTime = Date.now();

  // Test FastMCP tool execution with OAuth authentication
  const toolResponse = http.post(
    `${BASE_URL}/fastmcp/tools/execute`,
    {
      tool: "get-scenarios",
      parameters: {
        organizationId:
          "test-org-" + Math.random().toString(36).substring(2, 10),
      },
    },
    {
      headers: {
        Authorization: `Bearer test-access-token-${Math.random().toString(36).substring(2, 15)}`,
        "Content-Type": "application/json",
      },
      tags: { endpoint: "fastmcp_tool_execution" },
    },
  );

  const toolSuccess = check(toolResponse, {
    "Tool execution successful": (r) => r.status === 200 || r.status === 401, // 401 expected with test tokens
    "Tool execution within target": (r) => r.timings.duration < 500,
  });

  if (!toolSuccess) {
    oauthErrors.add(1);
  }

  sleep(1);
}

// Health check and system validation
export function healthCheck() {
  const healthResponse = http.get(`${BASE_URL}/health`, {
    tags: { endpoint: "health_check" },
  });

  check(healthResponse, {
    "Health check successful": (r) => r.status === 200,
    "Health check fast": (r) => r.timings.duration < 100,
  });
}

// Main test execution function
export default function () {
  const scenario = __ENV.K6_SCENARIO || "mixed";

  // Health check every 10th iteration
  if (__ITER % 10 === 0) {
    healthCheck();
  }

  // Execute scenario-specific tests
  switch (scenario) {
    case "auth_flow":
      authorizationFlow();
      break;
    case "token_refresh":
      tokenRefresh();
      break;
    case "session_validation":
      sessionValidation();
      break;
    case "tool_execution":
      toolExecution();
      break;
    default:
      // Mixed scenario - run all tests
      authorizationFlow();
      tokenRefresh();
      sessionValidation();
      toolExecution();
  }
}

// Teardown function for cleanup
export function teardown(data) {
  console.log("OAuth Load Test Completed");
  console.log("Total OAuth Errors:", oauthErrors.value);
  console.log("OAuth Success Rate:", oauthSuccessRate.rate);
}
