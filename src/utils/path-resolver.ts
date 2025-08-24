/**
 * Path resolution utility that works in both runtime and test environments
 */
import * as path from "path";
import * as fs from "fs";

/**
 * Get the project root directory - works for both runtime and testing
 */
/**
 * Check if running in test environment
 */
function isTestEnvironment(): boolean {
  return process.env.NODE_ENV === "test" || !!process.env.JEST_WORKER_ID;
}

/**
 * Check if package.json exists in given directory
 */
function hasPackageJson(dirPath: string): boolean {
  return fs.existsSync(path.join(dirPath, "package.json"));
}

/**
 * Resolve script directory based paths (dist/utils, dist)
 */
function resolveScriptDirectoryPaths(): string | null {
  const scriptDir = process.cwd();

  // If we're in dist/utils, go up two levels to get project root
  if (
    scriptDir.includes("/dist/utils") ||
    scriptDir.includes("\\dist\\utils")
  ) {
    const projectRoot = path.resolve(scriptDir, "../../");
    if (hasPackageJson(projectRoot)) {
      return projectRoot;
    }
  }

  // If we're in dist/, go up one level
  if (scriptDir.includes("/dist") || scriptDir.includes("\\dist")) {
    const projectRoot = path.resolve(scriptDir, "../");
    if (hasPackageJson(projectRoot)) {
      return projectRoot;
    }
  }

  return null;
}

/**
 * Search parent directories for package.json
 */
function searchParentDirectories(startDir: string): string | null {
  let searchDir = startDir;

  for (let i = 0; i < 10; i++) {
    // Limit search to prevent infinite loops
    if (hasPackageJson(searchDir)) {
      return searchDir;
    }
    const parentDir = path.dirname(searchDir);
    if (parentDir === searchDir) {
      break;
    } // Reached root
    searchDir = parentDir;
  }

  return null;
}

/**
 * Try fallback paths for project root resolution
 */
function resolveFallbackPaths(): string | null {
  const scriptDir = process.cwd();
  const currentDir = process.cwd();

  // ABSOLUTE FALLBACK: Use known project location
  const knownProjectPath =
    "/Users/jeremyparker/Desktop/Claude Coding Projects/make.com-fastmcp-server";
  if (hasPackageJson(knownProjectPath)) {
    return knownProjectPath;
  }

  // Try relative to script location
  const fallbackPaths = [
    path.resolve(scriptDir, "../../"), // from dist/utils
    path.resolve(scriptDir, "../"), // from dist
    scriptDir, // current script dir
    currentDir, // current working dir
  ];

  for (const rootPath of fallbackPaths) {
    if (hasPackageJson(rootPath)) {
      return rootPath;
    }
  }

  return null;
}

/**
 * Handle emergency fallback when all else fails
 */
function getEmergencyFallback(): string {
  const emergencyPath =
    "/Users/jeremyparker/Desktop/Claude Coding Projects/make.com-fastmcp-server";
  if (fs.existsSync(emergencyPath)) {
    return emergencyPath;
  }
  return "/Users/jeremyparker/Desktop/Claude Coding Projects/make.com-fastmcp-server";
}

export function getProjectRoot(): string {
  // In test environment, use process.cwd() which Jest sets correctly
  if (isTestEnvironment()) {
    return process.cwd();
  }

  // CRITICAL: For MCP server runtime from Claude Desktop
  try {
    // Try script directory based resolution first
    const scriptDirPath = resolveScriptDirectoryPaths();
    if (scriptDirPath) {
      return scriptDirPath;
    }

    // Try current working directory
    const currentDir = process.cwd();
    if (hasPackageJson(currentDir)) {
      return currentDir;
    }

    // Search parent directories
    const parentDirPath = searchParentDirectories(currentDir);
    if (parentDirPath) {
      return parentDirPath;
    }

    // Try fallback paths
    const fallbackPath = resolveFallbackPaths();
    if (fallbackPath) {
      return fallbackPath;
    }
  } catch {
    return getEmergencyFallback();
  }

  // Absolute final fallback
  return "/Users/jeremyparker/Desktop/Claude Coding Projects/make.com-fastmcp-server";
}

/**
 * Get logs directory path
 */
export function getLogsDirectory(): string {
  return path.join(getProjectRoot(), "logs");
}

/**
 * Get audit logs directory path
 */
export function getAuditLogsDirectory(): string {
  return path.join(getProjectRoot(), "logs", "audit");
}
