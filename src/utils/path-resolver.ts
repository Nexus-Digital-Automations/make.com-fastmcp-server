/**
 * Path resolution utility that works in both runtime and test environments
 */
import path from 'path';
import fs from 'fs';

/**
 * Get the project root directory - works for both runtime and testing
 */
export function getProjectRoot(): string {
  // In test environment, use process.cwd() which Jest sets correctly
  if (process.env.NODE_ENV === 'test' || process.env.JEST_WORKER_ID) {
    return process.cwd();
  }
  
  // CRITICAL: For MCP server runtime from Claude Desktop
  // First check if we can resolve based on the script location
  try {
    
    // Get the directory where this script is located - use process.cwd() for Jest compatibility
    const scriptDir = process.cwd();
    
    // If we're in dist/utils, go up two levels to get project root
    if (scriptDir.includes('/dist/utils') || scriptDir.includes('\\dist\\utils')) {
      const projectRoot = path.resolve(scriptDir, '../../');
      if (fs.existsSync(path.join(projectRoot, 'package.json'))) {
        return projectRoot;
      }
    }
    
    // If we're in dist/, go up one level
    if (scriptDir.includes('/dist') || scriptDir.includes('\\dist')) {
      const projectRoot = path.resolve(scriptDir, '../');
      if (fs.existsSync(path.join(projectRoot, 'package.json'))) {
        return projectRoot;
      }
    }
    
    // Try current working directory
    const currentDir = process.cwd();
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
    
    // ABSOLUTE FALLBACK: Use known project location
    const knownProjectPath = '/Users/jeremyparker/Desktop/Claude Coding Projects/make.com-fastmcp-server';
    if (fs.existsSync(path.join(knownProjectPath, 'package.json'))) {
      return knownProjectPath;
    }
    
    // If all else fails, try relative to script location
    const fallbackPaths = [
      path.resolve(scriptDir, '../../'),  // from dist/utils
      path.resolve(scriptDir, '../'),     // from dist
      scriptDir,                          // current script dir
      currentDir,                         // current working dir
    ];
    
    for (const rootPath of fallbackPaths) {
      if (fs.existsSync(path.join(rootPath, 'package.json'))) {
        return rootPath;
      }
    }
  } catch (error) {
    // Emergency fallback
    const emergencyPath = '/Users/jeremyparker/Desktop/Claude Coding Projects/make.com-fastmcp-server';
    if (fs.existsSync(emergencyPath)) {
      return emergencyPath;
    }
  }
  
  // Absolute final fallback
  return '/Users/jeremyparker/Desktop/Claude Coding Projects/make.com-fastmcp-server';
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