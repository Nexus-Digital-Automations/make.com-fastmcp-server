import type { LogPattern } from "./log-pattern-analyzer";

// Critical Error Patterns - High priority patterns for immediate attention
export const CRITICAL_PATTERNS: LogPattern[] = [
  {
    id: "auth-failure-spike",
    name: "Authentication Failure Spike",
    pattern: /API request failed.*AUTHENTICATION_ERROR/,
    severity: "critical",
    action: "Verify API credentials and check for credential expiration",
    threshold: 5,
    timeWindowMs: 300000, // 5 minutes
    suppressionMs: 900000, // 15 minutes
    description: "Multiple authentication failures detected - possible credential issue",
  },
  {
    id: "rate-limit-hit",
    name: "Rate Limit Exceeded",
    pattern: /API request failed.*RATE_LIMIT_ERROR/,
    severity: "warning",
    action: "Implement request throttling and review API usage patterns",
    threshold: 10,
    timeWindowMs: 600000, // 10 minutes
    suppressionMs: 1800000, // 30 minutes
    description: "Rate limit threshold exceeded - implement backoff strategy",
  },
  {
    id: "server-error-cluster",
    name: "Server Error Cluster",
    pattern: /API request failed.*statusCode":(5\d\d)/,
    severity: "critical",
    action: "Investigate Make.com API service health and implement retry logic",
    threshold: 3,
    timeWindowMs: 180000, // 3 minutes
    suppressionMs: 600000, // 10 minutes
    description: "Multiple server errors indicate potential service degradation",
  },
  {
    id: "slow-operation-trend",
    name: "Performance Degradation Trend",
    pattern: /Slow operation detected.*duration.*(\d+)/,
    severity: "warning",
    action: "Investigate performance bottlenecks and optimize slow operations",
    threshold: 15,
    timeWindowMs: 1800000, // 30 minutes
    suppressionMs: 3600000, // 1 hour
    description: "Increasing frequency of slow operations detected",
  },
  {
    id: "memory-pressure",
    name: "Memory Pressure Alert",
    pattern: /Memory usage.*exceeds threshold/,
    severity: "critical",
    action: "Investigate memory leaks and optimize memory usage",
    threshold: 1,
    timeWindowMs: 60000, // 1 minute
    suppressionMs: 1800000, // 30 minutes
    description: "System memory usage exceeding configured thresholds",
  },
  {
    id: "fatal-error",
    name: "Fatal Application Error",
    pattern: /FATAL|Fatal|fatal.*error/,
    severity: "critical",
    action: "Immediate investigation required - application may be unstable",
    threshold: 1,
    timeWindowMs: 60000, // 1 minute
    suppressionMs: 300000, // 5 minutes
    description: "Fatal error detected - immediate attention required",
  },
  {
    id: "connection-failure-cluster",
    name: "Connection Failure Cluster",
    pattern: /CONNECTION_ERROR|ECONNREFUSED|ETIMEDOUT|ENOTFOUND/,
    severity: "critical",
    action: "Check network connectivity and service availability",
    threshold: 5,
    timeWindowMs: 300000, // 5 minutes
    suppressionMs: 900000, // 15 minutes
    description: "Multiple connection failures indicate network or service issues",
  },
  {
    id: "webhook-failure-cluster",
    name: "Webhook Delivery Failures",
    pattern: /Webhook.*failed|Failed to deliver webhook/,
    severity: "warning",
    action: "Investigate webhook endpoint availability and implement retry logic",
    threshold: 10,
    timeWindowMs: 900000, // 15 minutes
    suppressionMs: 1800000, // 30 minutes
    description: "Multiple webhook delivery failures detected",
  },
];

// Performance Monitoring Patterns - System performance and capacity monitoring
export const PERFORMANCE_PATTERNS: LogPattern[] = [
  {
    id: "concurrent-request-overload",
    name: "Concurrent Request Overload",
    pattern: /concurrentRequests.*(\d+)/,
    severity: "warning",
    action: "Monitor system capacity and implement request queuing",
    threshold: 20,
    timeWindowMs: 900000, // 15 minutes
    suppressionMs: 1800000, // 30 minutes
    description: "High concurrent request levels detected",
  },
  {
    id: "health-check-failure",
    name: "Health Check Failure",
    pattern: /Health check failed.*status.*unhealthy/,
    severity: "critical",
    action: "Investigate system health and address failing checks",
    threshold: 1,
    timeWindowMs: 300000, // 5 minutes
    suppressionMs: 900000, // 15 minutes
    description: "System health checks failing - immediate attention required",
  },
  {
    id: "dependency-health-degraded",
    name: "Dependency Health Degraded",
    pattern: /Dependency.*health.*degraded|Dependencies.*failing/,
    severity: "warning",
    action: "Review dependency status and update affected packages",
    threshold: 3,
    timeWindowMs: 1800000, // 30 minutes
    suppressionMs: 3600000, // 1 hour
    description: "Dependency health issues detected",
  },
  {
    id: "high-response-time",
    name: "High Response Time Pattern",
    pattern: /duration.*([5-9]\d{3,}|[1-9]\d{4,})/,
    severity: "warning",
    action: "Investigate slow operations and optimize performance bottlenecks",
    threshold: 25,
    timeWindowMs: 1800000, // 30 minutes
    suppressionMs: 3600000, // 1 hour
    description: "Consistently high response times detected (>5000ms)",
  },
  {
    id: "memory-leak-indicator",
    name: "Memory Leak Indicator",
    pattern: /Memory usage.*increasing|memoryDelta.*[1-9]\d{6,}/,
    severity: "warning",
    action: "Monitor memory trends and investigate potential memory leaks",
    threshold: 10,
    timeWindowMs: 3600000, // 1 hour
    suppressionMs: 7200000, // 2 hours
    description: "Potential memory leak pattern detected",
  },
  {
    id: "api-timeout-trend",
    name: "API Timeout Trend",
    pattern: /TIMEOUT_ERROR|Request timeout|Operation timed out/,
    severity: "warning",
    action: "Investigate external API performance and adjust timeout settings",
    threshold: 8,
    timeWindowMs: 1800000, // 30 minutes
    suppressionMs: 3600000, // 1 hour
    description: "Increasing frequency of API timeouts detected",
  },
];

// Make.com Specific Patterns - Patterns specific to Make.com API interactions
export const MAKE_API_PATTERNS: LogPattern[] = [
  {
    id: "make-quota-exceeded",
    name: "Make.com API Quota Exceeded",
    pattern: /Make\.com.*quota.*exceeded|Quota limit reached/i,
    severity: "critical",
    action: "Review Make.com usage and consider upgrading plan or throttling requests",
    threshold: 1,
    timeWindowMs: 300000, // 5 minutes
    suppressionMs: 1800000, // 30 minutes
    description: "Make.com API quota limit reached",
  },
  {
    id: "make-scenario-errors",
    name: "Make.com Scenario Execution Errors",
    pattern: /Scenario.*error|Failed to execute scenario/i,
    severity: "warning",
    action: "Review scenario configuration and check for data mapping issues",
    threshold: 5,
    timeWindowMs: 600000, // 10 minutes
    suppressionMs: 1800000, // 30 minutes
    description: "Multiple scenario execution errors detected",
  },
  {
    id: "make-webhook-registration-failed",
    name: "Make.com Webhook Registration Failed",
    pattern: /Failed to register webhook|Webhook registration.*failed/i,
    severity: "warning",
    action: "Check webhook configuration and Make.com service availability",
    threshold: 3,
    timeWindowMs: 900000, // 15 minutes
    suppressionMs: 1800000, // 30 minutes
    description: "Webhook registration failures with Make.com",
  },
  {
    id: "make-connection-unauthorized",
    name: "Make.com Connection Unauthorized",
    pattern: /Make\.com.*unauthorized|Connection.*not authorized/i,
    severity: "critical",
    action: "Verify Make.com connection credentials and reauthorize if needed",
    threshold: 2,
    timeWindowMs: 300000, // 5 minutes
    suppressionMs: 900000, // 15 minutes
    description: "Make.com connection authorization issues",
  },
];

// Security Patterns - Security-related log patterns
export const SECURITY_PATTERNS: LogPattern[] = [
  {
    id: "multiple-failed-auth",
    name: "Multiple Failed Authentication Attempts",
    pattern: /Authentication.*failed|Unauthorized.*access.*attempt/i,
    severity: "warning",
    action: "Review authentication logs and consider implementing rate limiting",
    threshold: 10,
    timeWindowMs: 600000, // 10 minutes
    suppressionMs: 1800000, // 30 minutes
    description: "Multiple authentication failures may indicate attack",
  },
  {
    id: "suspicious-requests",
    name: "Suspicious Request Pattern",
    pattern: /SQL injection|XSS attempt|Path traversal|Malicious payload/i,
    severity: "critical",
    action: "Investigate potential security attack and review request filtering",
    threshold: 1,
    timeWindowMs: 60000, // 1 minute
    suppressionMs: 300000, // 5 minutes
    description: "Potential security attack detected in requests",
  },
  {
    id: "unusual-traffic-pattern",
    name: "Unusual Traffic Pattern",
    pattern: /Unusual.*traffic|Traffic.*anomaly|Suspicious.*requests/i,
    severity: "warning",
    action: "Analyze traffic patterns and consider implementing traffic filtering",
    threshold: 5,
    timeWindowMs: 900000, // 15 minutes
    suppressionMs: 1800000, // 30 minutes
    description: "Unusual traffic patterns detected",
  },
];

// System Patterns - General system and operational patterns
export const SYSTEM_PATTERNS: LogPattern[] = [
  {
    id: "startup-errors",
    name: "Application Startup Errors",
    pattern: /Startup.*failed|Failed to start|Initialization.*error/i,
    severity: "critical",
    action: "Review startup configuration and dependencies",
    threshold: 1,
    timeWindowMs: 60000, // 1 minute
    suppressionMs: 300000, // 5 minutes
    description: "Application startup failures detected",
  },
  {
    id: "configuration-errors",
    name: "Configuration Errors",
    pattern: /Configuration.*error|Invalid.*config|Config.*missing/i,
    severity: "warning",
    action: "Review application configuration and environment variables",
    threshold: 3,
    timeWindowMs: 300000, // 5 minutes
    suppressionMs: 900000, // 15 minutes
    description: "Configuration-related errors detected",
  },
  {
    id: "dependency-load-failures",
    name: "Dependency Load Failures",
    pattern: /Failed to load.*dependency|Module.*not found|Import.*error/i,
    severity: "critical",
    action: "Check dependency installation and module paths",
    threshold: 1,
    timeWindowMs: 60000, // 1 minute
    suppressionMs: 300000, // 5 minutes
    description: "Dependency loading failures detected",
  },
  {
    id: "disk-space-warnings",
    name: "Disk Space Warnings",
    pattern: /Disk.*space.*low|Storage.*full|No space left/i,
    severity: "warning",
    action: "Monitor disk usage and clean up unnecessary files",
    threshold: 3,
    timeWindowMs: 1800000, // 30 minutes
    suppressionMs: 3600000, // 1 hour
    description: "Disk space issues detected",
  },
];

// Combine all pattern libraries
export const ALL_PATTERNS: LogPattern[] = [
  ...CRITICAL_PATTERNS,
  ...PERFORMANCE_PATTERNS,
  ...MAKE_API_PATTERNS,
  ...SECURITY_PATTERNS,
  ...SYSTEM_PATTERNS,
];

// Pattern categories for filtering and organization
export const PATTERN_CATEGORIES = {
  CRITICAL: CRITICAL_PATTERNS,
  PERFORMANCE: PERFORMANCE_PATTERNS,
  MAKE_API: MAKE_API_PATTERNS,
  SECURITY: SECURITY_PATTERNS,
  SYSTEM: SYSTEM_PATTERNS,
} as const;

export type PatternCategory = keyof typeof PATTERN_CATEGORIES;

// Helper function to get patterns by category
export function getPatternsByCategory(category: PatternCategory): LogPattern[] {
  return PATTERN_CATEGORIES[category] || [];
}

// Helper function to get patterns by severity
export function getPatternsBySeverity(severity: "info" | "warning" | "critical"): LogPattern[] {
  return ALL_PATTERNS.filter(pattern => pattern.severity === severity);
}

// Helper function to validate pattern configuration
export function validatePattern(pattern: LogPattern): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  if (!pattern.id || pattern.id.trim() === '') {
    errors.push('Pattern ID is required');
  }

  if (!pattern.name || pattern.name.trim() === '') {
    errors.push('Pattern name is required');
  }

  if (!pattern.pattern) {
    errors.push('Pattern RegExp is required');
  }

  if (!['info', 'warning', 'critical'].includes(pattern.severity)) {
    errors.push('Pattern severity must be info, warning, or critical');
  }

  if (!pattern.action || pattern.action.trim() === '') {
    errors.push('Pattern action is required');
  }

  if (!pattern.description || pattern.description.trim() === '') {
    errors.push('Pattern description is required');
  }

  if (pattern.threshold !== undefined && pattern.threshold < 1) {
    errors.push('Pattern threshold must be at least 1');
  }

  if (pattern.timeWindowMs !== undefined && pattern.timeWindowMs < 1000) {
    errors.push('Pattern time window must be at least 1000ms');
  }

  return {
    valid: errors.length === 0,
    errors
  };
}