/**
 * Path resolution utility that works in both runtime and test environments
 */
import path from 'path';

/**
 * Get the project root directory - works for both runtime and testing
 */
export function getProjectRoot(): string {
  // In test environment, use process.cwd() which Jest sets correctly
  if (process.env.NODE_ENV === 'test' || process.env.JEST_WORKER_ID) {
    return process.cwd();
  }
  
  // For runtime, we'll also use process.cwd() for now
  // This works correctly when the server is started from the project directory
  return process.cwd();
}

/**
 * Get logs directory path
 */
export function getLogsDirectory(): string {
  return path.join(getProjectRoot(), 'logs');
}

/**
 * Get audit logs directory path
 */
export function getAuditLogsDirectory(): string {
  return path.join(getProjectRoot(), 'logs', 'audit');
}