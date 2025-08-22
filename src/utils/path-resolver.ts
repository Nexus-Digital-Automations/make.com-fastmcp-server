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
  
  // For MCP server runtime, look for package.json to find project root
  // Start from current directory and walk up the directory tree
  let currentDir = process.cwd();
  
  // If we're likely running from a different directory, try some heuristics
  try {
    const fs = require('fs');
    
    // First, try current working directory
    if (fs.existsSync(path.join(currentDir, 'package.json'))) {
      return currentDir;
    }
    
    // If not found, try looking for package.json in parent directories
    let searchDir = currentDir;
    for (let i = 0; i < 10; i++) { // Limit search to prevent infinite loops
      if (fs.existsSync(path.join(searchDir, 'package.json'))) {
        return searchDir;
      }
      const parentDir = path.dirname(searchDir);
      if (parentDir === searchDir) break; // Reached root
      searchDir = parentDir;
    }
    
    // Fallback: check some common locations
    const possibleRoots = [
      '/Users/jeremyparker/Desktop/Claude Coding Projects/make.com-fastmcp-server',
      path.resolve(process.cwd(), '..'),
      process.cwd()
    ];
    
    for (const rootPath of possibleRoots) {
      if (fs.existsSync(path.join(rootPath, 'package.json'))) {
        return rootPath;
      }
    }
  } catch (error) {
    // Ignore errors and use fallback
  }
  
  // Final fallback
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