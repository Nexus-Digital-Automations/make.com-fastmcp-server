/**
 * CI/CD Integration Tools for FastMCP Server
 * Enterprise-grade developer workflow automation tools
 */

import { FastMCP } from 'fastmcp';
import { z } from 'zod';
import { spawn } from 'child_process';
import { existsSync, readFileSync } from 'fs';
import { resolve } from 'path';
import logger from '../lib/logger.js';
import MakeApiClient from '../lib/make-api-client.js';
import { extractCorrelationId } from '../utils/error-response.js';
import { formatSuccessResponse } from '../utils/response-formatter.js';

// ==================== SCHEMAS ====================

const TestSuiteSchema = z.object({
  category: z.enum(['unit', 'integration', 'e2e', 'browser', 'security', 'performance', 'chaos', 'all']).describe('Test category to run'),
  includeWatch: z.boolean().default(false).describe('Enable watch mode for continuous testing'),
  includeVerbose: z.boolean().default(false).describe('Enable verbose output'),
  specificFiles: z.array(z.string()).optional().describe('Run specific test files only'),
  testTimeout: z.number().min(1000).max(300000).default(30000).describe('Test timeout in milliseconds'),
  parallel: z.boolean().default(true).describe('Run tests in parallel'),
  maxWorkers: z.number().min(1).max(16).default(4).describe('Maximum number of worker processes'),
}).strict();

const CoverageReportSchema = z.object({
  testCategory: z.enum(['unit', 'integration', 'e2e', 'all']).describe('Test category for coverage analysis'),
  format: z.enum(['html', 'json', 'lcov', 'text', 'summary']).default('summary').describe('Coverage report format'),
  threshold: z.number().min(0).max(100).default(80).describe('Minimum coverage threshold percentage'),
  includeUncoveredFiles: z.boolean().default(true).describe('Include uncovered files in report'),
  outputPath: z.string().optional().describe('Custom output path for coverage reports'),
}).strict();

const DeploymentReadinessSchema = z.object({
  environment: z.enum(['development', 'staging', 'production']).describe('Target deployment environment'),
  includeLinting: z.boolean().default(true).describe('Include linting checks'),
  includeTypeCheck: z.boolean().default(true).describe('Include TypeScript type checking'),
  includeTests: z.boolean().default(true).describe('Include test execution'),
  includeBuild: z.boolean().default(true).describe('Include build verification'),
  includeSecurityChecks: z.boolean().default(true).describe('Include security vulnerability scanning'),
  includeDependencyCheck: z.boolean().default(true).describe('Include dependency vulnerability check'),
  strictMode: z.boolean().default(false).describe('Enable strict mode (fail on warnings)'),
}).strict();

const BuildReportSchema = z.object({
  includeMetrics: z.boolean().default(true).describe('Include build performance metrics'),
  includeQualityScores: z.boolean().default(true).describe('Include code quality scores'),
  includeDependencyAnalysis: z.boolean().default(true).describe('Include dependency analysis'),
  includeSecurityScan: z.boolean().default(true).describe('Include security vulnerability scan'),
  includeSizeAnalysis: z.boolean().default(true).describe('Include bundle size analysis'),
  outputFormat: z.enum(['json', 'html', 'text', 'markdown']).default('json').describe('Output format for build report'),
}).strict();

// ==================== TYPES ====================

interface TestResult {
  category: string;
  passed: number;
  failed: number;
  skipped: number;
  duration: number;
  coverage?: {
    lines: number;
    functions: number;
    branches: number;
    statements: number;
  };
  errors: string[];
  warnings: string[];
}

interface CoverageReport {
  overall: {
    lines: number;
    functions: number;
    branches: number;
    statements: number;
  };
  files: Array<{
    path: string;
    lines: number;
    functions: number;
    branches: number;
    statements: number;
  }>;
  threshold: {
    met: boolean;
    required: number;
    actual: number;
  };
  uncoveredFiles: string[];
}

interface DeploymentCheck {
  passed: boolean;
  checks: Array<{
    name: string;
    status: 'passed' | 'failed' | 'warning' | 'skipped';
    message: string;
    duration?: number;
    details?: Record<string, unknown>;
  }>;
  summary: {
    totalChecks: number;
    passedChecks: number;
    failedChecks: number;
    warningChecks: number;
    overallScore: number;
  };
  recommendations: string[];
}

interface BuildReport {
  buildInfo: {
    timestamp: string;
    environment: string;
    version: string;
    duration: number;
    status: 'success' | 'failed' | 'warning';
  };
  metrics: {
    buildTime: number;
    bundleSize: number;
    dependencies: number;
    devDependencies: number;
    linesOfCode: number;
    files: number;
  };
  quality: {
    lintScore: number;
    typeScore: number;
    testCoverage: number;
    complexityScore: number;
    maintainabilityIndex: number;
  };
  security: {
    vulnerabilities: {
      critical: number;
      high: number;
      medium: number;
      low: number;
    };
    dependencyIssues: string[];
    securityScore: number;
  };
  recommendations: Array<{
    category: string;
    priority: 'critical' | 'high' | 'medium' | 'low';
    message: string;
    action: string;
  }>;
}

// Additional interfaces for CI/CD integration
interface PackageJsonData {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  name?: string;
  version?: string;
  scripts?: Record<string, string>;
}

interface AuditVulnerability {
  severity: 'critical' | 'high' | 'medium' | 'low';
  title?: string;
  url?: string;
  range?: string;
  path?: string[];
}

interface CoverageFileData {
  lines?: { pct: number; total: number; covered: number };
  functions?: { pct: number; total: number; covered: number };
  statements?: { pct: number; total: number; covered: number };
  branches?: { pct: number; total: number; covered: number };
}

// ==================== HELPER FUNCTIONS ====================

function runCommand(command: string, args: string[], options: Record<string, unknown> = {}): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  return new Promise((resolve) => {
    const child = spawn(command, args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      shell: true,
      ...options,
    });

    let stdout = '';
    let stderr = '';

    child.stdout?.on('data', (data) => {
      stdout += data.toString();
    });

    child.stderr?.on('data', (data) => {
      stderr += data.toString();
    });

    child.on('close', (exitCode) => {
      resolve({ stdout, stderr, exitCode: exitCode || 0 });
    });

    child.on('error', (error) => {
      resolve({ stdout, stderr: error.message, exitCode: 1 });
    });
  });
}

// Helper functions for test suite execution
function buildTestCommand(category: string, specificFiles?: string[]): string[] {
  let testCommand = ['run', `test:${category === 'all' ? '' : category}`];
  if (category === 'all') {
    testCommand = ['run', 'test'];
  }
  
  if (specificFiles && specificFiles.length > 0) {
    testCommand.push(...specificFiles);
  }
  
  return testCommand;
}

function buildTestArgs(testCommand: string[], options: {
  includeWatch: boolean;
  includeVerbose: boolean;
  parallel: boolean;
  maxWorkers: number;
}): string[] {
  const testArgs = [...testCommand];
  if (options.includeWatch) { testArgs.push('--watch'); }
  if (options.includeVerbose) { testArgs.push('--verbose'); }
  if (!options.parallel) { testArgs.push('--runInBand'); }
  if (options.maxWorkers !== 4) { testArgs.push(`--maxWorkers=${options.maxWorkers}`); }
  
  return testArgs;
}

function parseTestResults(stdout: string, stderr: string, category: string, duration: number): TestResult {
  const passedMatch = stdout.match(/(\d+) passing/);
  const failedMatch = stdout.match(/(\d+) failing/);
  const skippedMatch = stdout.match(/(\d+) pending/);
  
  return {
    category,
    passed: passedMatch ? parseInt(passedMatch[1]) : 0,
    failed: failedMatch ? parseInt(failedMatch[1]) : 0,
    skipped: skippedMatch ? parseInt(skippedMatch[1]) : 0,
    duration,
    errors: stderr ? stderr.split('\n').filter(line => line.trim().length > 0) : [],
    warnings: stdout.split('\n').filter(line => line.includes('WARN')),
  };
}

function extractCoverageFromOutput(stdout: string, testResult: TestResult): TestResult {
  if (stdout.includes('% Stmts') || stdout.includes('% Lines')) {
    const coverageMatch = stdout.match(/All files\s+\|\s+(\d+\.?\d*)\s+\|\s+(\d+\.?\d*)\s+\|\s+(\d+\.?\d*)\s+\|\s+(\d+\.?\d*)/);
    if (coverageMatch) {
      testResult.coverage = {
        statements: parseFloat(coverageMatch[1]),
        branches: parseFloat(coverageMatch[2]),
        functions: parseFloat(coverageMatch[3]),
        lines: parseFloat(coverageMatch[4]),
      };
    }
  }
  return testResult;
}

// Helper functions for coverage reporting
function buildCoverageCommand(testCategory: string): string[] {
  const coverageCmd = ['run', 'test:coverage'];
  if (testCategory !== 'all') {
    coverageCmd[1] = `test:${testCategory}`;
  }
  return coverageCmd;
}

function processCoverageSummary(coverageSummaryPath: string, threshold: number): CoverageReport {
  const coverageData: CoverageReport = {
    overall: { lines: 0, functions: 0, branches: 0, statements: 0 },
    files: [],
    threshold: { met: false, required: threshold, actual: 0 },
    uncoveredFiles: [],
  };
  
  try {
    const summaryData = JSON.parse(readFileSync(coverageSummaryPath, 'utf8'));
    
    if (summaryData.total) {
      coverageData.overall = {
        lines: summaryData.total.lines.pct || 0,
        functions: summaryData.total.functions.pct || 0,
        branches: summaryData.total.branches.pct || 0,
        statements: summaryData.total.statements.pct || 0,
      };
      
      coverageData.threshold.actual = coverageData.overall.lines;
      coverageData.threshold.met = coverageData.overall.lines >= threshold;
    }
    
    // Extract file-level coverage
    for (const [filePath, fileData] of Object.entries(summaryData)) {
      if (filePath !== 'total' && typeof fileData === 'object' && fileData !== null) {
        const data = fileData as CoverageFileData;
        coverageData.files.push({
          path: filePath,
          lines: data.lines?.pct || 0,
          functions: data.functions?.pct || 0,
          branches: data.branches?.pct || 0,
          statements: data.statements?.pct || 0,
        });
      }
    }
  } catch {
    // Handle parse error silently
  }
  
  return coverageData;
}

async function findUncoveredFiles(coverageData: CoverageReport): Promise<string[]> {
  const { stdout: findFiles } = await runCommand('find', ['src', '-name', '*.ts', '-not', '-path', '*/test*']);
  const sourceFiles = findFiles.split('\n').filter(f => f.trim().length > 0);
  const coveredFiles = coverageData.files.map(f => f.path);
  return sourceFiles.filter(f => !coveredFiles.some(cf => cf.includes(f)));
}

function generateCoverageAnalysis(coverageData: CoverageReport): {
  grade: string;
  recommendations: string[];
} {
  const grade = coverageData.overall.lines >= 90 ? 'A' : 
                coverageData.overall.lines >= 80 ? 'B' :
                coverageData.overall.lines >= 70 ? 'C' :
                coverageData.overall.lines >= 60 ? 'D' : 'F';
                
  const recommendations: string[] = [];
  
  if (coverageData.overall.lines < coverageData.threshold.required) {
    recommendations.push(`Increase line coverage to meet ${coverageData.threshold.required}% threshold`);
  }
  if (coverageData.uncoveredFiles.length > 0) {
    recommendations.push(`Add tests for ${coverageData.uncoveredFiles.length} uncovered files`);
  }
  if (coverageData.files.filter(f => f.lines < 50).length > 0) {
    recommendations.push('Focus on files with less than 50% coverage');
  }
  
  return { grade, recommendations };
}

// Helper functions for deployment readiness validation
async function performLintingCheck(strictMode: boolean): Promise<DeploymentCheck['checks'][0]> {
  const startTime = Date.now();
  const lintResult = await runLintCheck();
  const duration = Date.now() - startTime;
  
  return {
    name: 'Linting',
    status: lintResult.passed ? 'passed' : (strictMode ? 'failed' : 'warning'),
    message: lintResult.passed ? 'All linting checks passed' : `Found ${lintResult.issues} linting issues`,
    duration,
    details: { score: lintResult.score, issues: lintResult.issues },
  };
}

async function performTypeCheck(): Promise<DeploymentCheck['checks'][0]> {
  const startTime = Date.now();
  const typeResult = await runTypeCheck();
  const duration = Date.now() - startTime;
  
  return {
    name: 'Type Checking',
    status: typeResult.passed ? 'passed' : 'failed',
    message: typeResult.passed ? 'All type checks passed' : `Found ${typeResult.errors} type errors`,
    duration,
    details: { score: typeResult.score, errors: typeResult.errors },
  };
}

async function performTestExecution(): Promise<DeploymentCheck['checks'][0]> {
  const startTime = Date.now();
  const { stdout, exitCode } = await runCommand('npm', ['run', 'test']);
  const duration = Date.now() - startTime;
  
  return {
    name: 'Test Execution',
    status: exitCode === 0 ? 'passed' : 'failed',
    message: exitCode === 0 ? 'All tests passed' : 'Some tests failed',
    duration,
    details: { exitCode, hasOutput: stdout.length > 0 },
  };
}

async function performBuildVerification(): Promise<DeploymentCheck['checks'][0]> {
  const startTime = Date.now();
  const { stderr, exitCode } = await runCommand('npm', ['run', 'build']);
  const duration = Date.now() - startTime;
  
  return {
    name: 'Build Verification',
    status: exitCode === 0 ? 'passed' : 'failed',
    message: exitCode === 0 ? 'Build completed successfully' : 'Build failed',
    duration,
    details: { exitCode, hasErrors: stderr.length > 0 },
  };
}

async function performSecurityCheck(strictMode: boolean): Promise<DeploymentCheck['checks'][0]> {
  const startTime = Date.now();
  const securityResult = await runSecurityScan();
  const duration = Date.now() - startTime;
  
  const totalVulns = Object.values(securityResult.vulnerabilities).reduce((sum, count) => sum + count, 0);
  const criticalIssues = securityResult.vulnerabilities.critical + securityResult.vulnerabilities.high;
  
  return {
    name: 'Security Scan',
    status: criticalIssues === 0 ? 'passed' : (strictMode ? 'failed' : 'warning'),
    message: totalVulns === 0 ? 'No security vulnerabilities found' : `Found ${totalVulns} vulnerabilities`,
    duration,
    details: { vulnerabilities: securityResult.vulnerabilities, score: securityResult.score },
  };
}

async function performDependencyCheck(): Promise<DeploymentCheck['checks'][0]> {
  const startTime = Date.now();
  const { stdout } = await runCommand('npm', ['outdated', '--json']);
  const duration = Date.now() - startTime;
  
  let outdatedPackages = 0;
  try {
    const outdated = JSON.parse(stdout);
    outdatedPackages = Object.keys(outdated).length;
  } catch {
    // Handle JSON parse error
  }
  
  return {
    name: 'Dependency Check',
    status: outdatedPackages === 0 ? 'passed' : 'warning',
    message: outdatedPackages === 0 ? 'All dependencies up to date' : `${outdatedPackages} outdated packages`,
    duration,
    details: { outdatedPackages },
  };
}

function calculateDeploymentSummary(checks: DeploymentCheck['checks'], strictMode: boolean): {
  passedChecks: number;
  failedChecks: number;
  warningChecks: number;
  overallPassed: boolean;
  overallScore: number;
} {
  const passedChecks = checks.filter(c => c.status === 'passed').length;
  const failedChecks = checks.filter(c => c.status === 'failed').length;
  const warningChecks = checks.filter(c => c.status === 'warning').length;
  const overallPassed = failedChecks === 0 && (strictMode ? warningChecks === 0 : true);
  const overallScore = Math.round((passedChecks / checks.length) * 100);
  
  return { passedChecks, failedChecks, warningChecks, overallPassed, overallScore };
}

function generateDeploymentRecommendations(summary: {
  failedChecks: number;
  warningChecks: number;
}, strictMode: boolean, environment: string): string[] {
  const recommendations: string[] = [];
  
  if (summary.failedChecks > 0) {
    recommendations.push(`Fix ${summary.failedChecks} failing checks before deployment`);
  }
  if (summary.warningChecks > 0 && strictMode) {
    recommendations.push(`Address ${summary.warningChecks} warnings (strict mode enabled)`);
  }
  if (environment === 'production') {
    recommendations.push('Ensure backup and rollback procedures are in place');
    recommendations.push('Verify monitoring and alerting systems are configured');
  }
  
  return recommendations;
}

// Helper functions for build report generation
async function initializeBuildReport(): Promise<BuildReport> {
  return {
    buildInfo: {
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV || 'development',
      version: '1.0.0', // From package.json
      duration: 0,
      status: 'success',
    },
    metrics: {
      buildTime: 0,
      bundleSize: 0,
      dependencies: 0,
      devDependencies: 0,
      linesOfCode: 0,
      files: 0,
    },
    quality: {
      lintScore: 0,
      typeScore: 0,
      testCoverage: 0,
      complexityScore: 85, // Mock complexity score
      maintainabilityIndex: 78, // Mock maintainability index
    },
    security: {
      vulnerabilities: { critical: 0, high: 0, medium: 0, low: 0 },
      dependencyIssues: [],
      securityScore: 0,
    },
    recommendations: [],
  };
}

async function collectBuildMetrics(buildReport: BuildReport): Promise<BuildReport> {
  const metrics = await getProjectMetrics();
  buildReport.metrics = { ...buildReport.metrics, ...metrics };
  
  // Run build and measure time
  const buildStartTime = Date.now();
  const { exitCode } = await runCommand('npm', ['run', 'build']);
  const buildTime = Date.now() - buildStartTime;
  
  buildReport.metrics.buildTime = buildTime;
  buildReport.buildInfo.status = exitCode === 0 ? 'success' : 'failed';
  
  // Analyze bundle size if dist exists
  if (await checkFileExists('dist')) {
    try {
      const { stdout: sizeOutput } = await runCommand('du', ['-sh', 'dist']);
      const sizeMatch = sizeOutput.match(/^(\d+\.?\d*)([KMGT]?)/);
      if (sizeMatch) {
        const size = parseFloat(sizeMatch[1]);
        const unit = sizeMatch[2];
        buildReport.metrics.bundleSize = unit === 'K' ? size : unit === 'M' ? size * 1024 : size;
      }
    } catch {
      // Handle size calculation error
    }
  }
  
  return buildReport;
}

async function collectQualityScores(buildReport: BuildReport): Promise<BuildReport> {
  const [lintResult, typeResult] = await Promise.all([
    runLintCheck(),
    runTypeCheck(),
  ]);
  
  buildReport.quality.lintScore = lintResult.score;
  buildReport.quality.typeScore = typeResult.score;
  
  // Get test coverage
  try {
    const coveragePath = resolve('coverage/coverage-summary.json');
    if (await checkFileExists(coveragePath)) {
      const coverageData = JSON.parse(readFileSync(coveragePath, 'utf8'));
      buildReport.quality.testCoverage = coverageData.total?.lines?.pct || 0;
    }
  } catch {
    // Handle coverage read error
  }
  
  return buildReport;
}

async function collectSecurityData(buildReport: BuildReport): Promise<BuildReport> {
  const securityResult = await runSecurityScan();
  buildReport.security.vulnerabilities = securityResult.vulnerabilities;
  buildReport.security.securityScore = securityResult.score;
  
  return buildReport;
}

async function collectDependencyAnalysis(buildReport: BuildReport): Promise<BuildReport> {
  try {
    const { stdout } = await runCommand('npm', ['outdated', '--json']);
    const outdated = JSON.parse(stdout);
    buildReport.security.dependencyIssues = Object.keys(outdated).map(pkg => 
      `${pkg}: ${outdated[pkg].current} → ${outdated[pkg].latest}`
    );
  } catch {
    // Handle outdated check error
  }
  
  return buildReport;
}

function generateBuildRecommendations(buildReport: BuildReport): BuildReport['recommendations'] {
  const recommendations: BuildReport['recommendations'] = [];
  
  if (buildReport.quality.lintScore < 90) {
    recommendations.push({
      category: 'Code Quality',
      priority: buildReport.quality.lintScore < 70 ? 'high' : 'medium',
      message: 'Improve code linting score',
      action: 'Fix ESLint errors and warnings',
    });
  }
  
  if (buildReport.quality.typeScore < 90) {
    recommendations.push({
      category: 'Type Safety',
      priority: buildReport.quality.typeScore < 70 ? 'high' : 'medium',
      message: 'Address TypeScript errors',
      action: 'Fix type checking issues',
    });
  }
  
  if (buildReport.quality.testCoverage < 80) {
    recommendations.push({
      category: 'Testing',
      priority: 'medium',
      message: 'Increase test coverage',
      action: 'Add more unit and integration tests',
    });
  }
  
  const totalVulns = Object.values(buildReport.security.vulnerabilities).reduce((sum, count) => sum + count, 0);
  if (totalVulns > 0) {
    recommendations.push({
      category: 'Security',
      priority: buildReport.security.vulnerabilities.critical > 0 ? 'critical' : 'high',
      message: `Address ${totalVulns} security vulnerabilities`,
      action: 'Update dependencies and fix security issues',
    });
  }
  
  if (buildReport.metrics.bundleSize > 10240) { // > 10MB
    recommendations.push({
      category: 'Performance',
      priority: 'medium',
      message: 'Large bundle size detected',
      action: 'Consider code splitting and dependency optimization',
    });
  }
  
  return recommendations;
}

function generateBuildSummary(buildReport: BuildReport): {
  overallGrade: string;
  keyMetrics: Record<string, string | number>;
  actionItems: number;
} {
  const overallGrade = calculateOverallGrade(buildReport);
  const keyMetrics = {
    buildTime: `${Math.round(buildReport.metrics.buildTime / 1000)}s`,
    bundleSize: `${Math.round(buildReport.metrics.bundleSize)}KB`,
    qualityScore: Math.round((buildReport.quality.lintScore + buildReport.quality.typeScore + buildReport.quality.testCoverage) / 3),
    securityScore: buildReport.security.securityScore,
  };
  const actionItems = buildReport.recommendations.filter(r => r.priority === 'critical' || r.priority === 'high').length;
  
  return { overallGrade, keyMetrics, actionItems };
}

async function checkFileExists(path: string): Promise<boolean> {
  try {
    return existsSync(resolve(path));
  } catch {
    return false;
  }
}

async function getProjectMetrics(): Promise<Record<string, number>> {
  const packagePath = resolve('package.json');
  let packageJson = {};
  
  if (await checkFileExists(packagePath)) {
    try {
      packageJson = JSON.parse(readFileSync(packagePath, 'utf8'));
    } catch {
      // Handle JSON parse error
    }
  }

  // Count TypeScript/JavaScript files
  const { stdout: fileCount } = await runCommand('find', ['src', '-name', '*.ts', '-o', '-name', '*.js', '|', 'wc', '-l']);
  
  // Count lines of code
  const { stdout: locCount } = await runCommand('find', ['src', '-name', '*.ts', '-o', '-name', '*.js', '-exec', 'wc', '-l', '{}', '+', '|', 'tail', '-1']);
  
  const dependencies = Object.keys((packageJson as PackageJsonData)?.dependencies || {}).length;
  const devDependencies = Object.keys((packageJson as PackageJsonData)?.devDependencies || {}).length;

  return {
    files: parseInt(fileCount.trim()) || 0,
    linesOfCode: parseInt(locCount.trim().split(/\s+/)[0]) || 0,
    dependencies,
    devDependencies,
  };
}

async function runLintCheck(): Promise<{ passed: boolean; score: number; issues: number }> {
  const { stderr, exitCode } = await runCommand('npm', ['run', 'lint']);
  
  // Parse ESLint output for warnings and errors
  const errorRegex = /(\d+) error/;
  const warningRegex = /(\d+) warning/;
  
  const errorMatch = errorRegex.exec(stderr);
  const warningMatch = warningRegex.exec(stderr);
  const errors = errorMatch?.[1] ? parseInt(errorMatch[1]) : 0;
  const warnings = warningMatch?.[1] ? parseInt(warningMatch[1]) : 0;
  
  const totalIssues = errors + warnings;
  const score = Math.max(0, 100 - (errors * 10 + warnings * 2));
  
  return {
    passed: exitCode === 0,
    score,
    issues: totalIssues,
  };
}

async function runTypeCheck(): Promise<{ passed: boolean; score: number; errors: number }> {
  const { stderr, exitCode } = await runCommand('npm', ['run', 'typecheck']);
  
  // Count TypeScript errors
  const errorLines = stderr.split('\n').filter(line => line.includes('error TS'));
  const errors = errorLines.length;
  
  const score = Math.max(0, 100 - (errors * 5));
  
  return {
    passed: exitCode === 0,
    score,
    errors,
  };
}

async function runSecurityScan(): Promise<{ vulnerabilities: { critical: number; high: number; medium: number; low: number }; score: number }> {
  // Simulate security scan (in real implementation, use npm audit or snyk)
  const { stdout } = await runCommand('npm', ['audit', '--json']);
  
  const vulnerabilities = { critical: 0, high: 0, medium: 0, low: 0 };
  
  try {
    const auditResult = JSON.parse(stdout);
    if (auditResult.vulnerabilities) {
      for (const [, vuln] of Object.entries(auditResult.vulnerabilities)) {
        const severity = (vuln as AuditVulnerability).severity;
        if (vulnerabilities[severity] !== undefined) {
          vulnerabilities[severity]++;
        }
      }
    }
  } catch {
    // Handle JSON parse error or missing audit data
  }
  
  const score = Math.max(0, 100 - (vulnerabilities.critical * 25 + vulnerabilities.high * 15 + vulnerabilities.medium * 8 + vulnerabilities.low * 2));
  
  return { vulnerabilities, score };
}

// ==================== TOOL IMPLEMENTATIONS ====================

function addRunTestSuiteTool(server: FastMCP, componentLogger: typeof logger): void {
  /**
   * Run Test Suite Tool
   * Execute specific test categories with comprehensive configuration options
   * 
   * @param category - Test category (unit, integration, e2e, browser, security, performance, chaos, all)
   * @param includeWatch - Enable watch mode for continuous testing
   * @param includeVerbose - Enable verbose output
   * @param specificFiles - Run specific test files only
   * @param testTimeout - Test timeout in milliseconds
   * @param parallel - Run tests in parallel
   * @param maxWorkers - Maximum number of worker processes
   * @returns {object} Test execution results with coverage and performance metrics
   * 
   * @example
   * ```bash
   * # Run unit tests with coverage
   * mcp-client run-test-suite \
   *   --category unit \
   *   --includeVerbose true \
   *   --parallel true \
   *   --maxWorkers 4
   * ```
   */
  server.addTool({
    name: 'run-test-suite',
    description: 'Execute specific test categories with comprehensive configuration and real-time monitoring',
    parameters: TestSuiteSchema,
    annotations: {
      title: 'Run Test Suite',
    },
    execute: async (args, { log, reportProgress }) => {
      const { category, includeWatch, includeVerbose, specificFiles, testTimeout, parallel, maxWorkers } = args;
      const correlationId = extractCorrelationId({});
      
      componentLogger.info('Running test suite', { 
        category,
        includeWatch,
        includeVerbose,
        specificFiles: specificFiles?.length || 0,
        correlationId 
      });
      
      log?.info?.('Running test suite', { category, correlationId });
      
      try {
        reportProgress({ progress: 0, total: 100 });

        const startTime = Date.now();
        
        // Build test command and arguments using helper functions
        const testCommand = buildTestCommand(category, specificFiles);
        const testArgs = buildTestArgs(testCommand, { includeWatch, includeVerbose, parallel, maxWorkers });
        
        reportProgress({ progress: 20, total: 100 });
        
        componentLogger.info('Executing test command', { command: 'npm', args: testArgs, correlationId });
        
        // Execute tests
        const { stdout, stderr, exitCode } = await runCommand('npm', testArgs);
        
        reportProgress({ progress: 70, total: 100 });
        
        // Parse test results using helper function
        const duration = Date.now() - startTime;
        let testResult = parseTestResults(stdout, stderr, category, duration);
        
        // Extract coverage information using helper function
        testResult = extractCoverageFromOutput(stdout, testResult);
        
        reportProgress({ progress: 100, total: 100 });
        
        componentLogger.info('Test suite completed', { 
          category,
          passed: testResult.passed,
          failed: testResult.failed,
          duration: testResult.duration,
          correlationId 
        });
        
        return formatSuccessResponse({
          status: exitCode === 0 ? 'passed' : 'failed',
          summary: {
            category,
            totalTests: testResult.passed + testResult.failed + testResult.skipped,
            passed: testResult.passed,
            failed: testResult.failed,
            skipped: testResult.skipped,
            successRate: testResult.passed + testResult.failed > 0 ? 
              Math.round((testResult.passed / (testResult.passed + testResult.failed)) * 100) : 0,
            duration: `${Math.round(testResult.duration / 1000)}s`,
          },
          results: testResult,
          configuration: {
            category,
            watch: includeWatch,
            verbose: includeVerbose,
            parallel,
            maxWorkers,
            timeout: testTimeout,
          },
          output: {
            stdout: stdout.slice(0, 2000), // Truncate for readability
            stderr: stderr.slice(0, 1000),
          },
        });
        
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        componentLogger.error('Test suite execution failed', { 
          category,
          error: errorMessage,
          correlationId 
        });
        
        throw new Error(`Test suite execution failed: ${errorMessage}`);
      }
    },
  });
}

function addGetTestCoverageTool(server: FastMCP, componentLogger: typeof logger): void {
  /**
   * Get Test Coverage Tool
   * Retrieve comprehensive test coverage reports with threshold analysis
   * 
   * @param testCategory - Test category for coverage analysis
   * @param format - Coverage report format (html, json, lcov, text, summary)
   * @param threshold - Minimum coverage threshold percentage
   * @param includeUncoveredFiles - Include uncovered files in report
   * @param outputPath - Custom output path for coverage reports
   * @returns {object} Coverage analysis with file-level details and recommendations
   * 
   * @example
   * ```bash
   * # Get coverage report with 90% threshold
   * mcp-client get-test-coverage \
   *   --testCategory all \
   *   --format summary \
   *   --threshold 90 \
   *   --includeUncoveredFiles true
   * ```
   */
  server.addTool({
    name: 'get-test-coverage',
    description: 'Retrieve comprehensive test coverage reports with threshold analysis and file-level details',
    parameters: CoverageReportSchema,
    annotations: {
      title: 'Get Test Coverage',
      readOnlyHint: true,
    },
    execute: async (args, { log, reportProgress }) => {
      const { testCategory, format, threshold, includeUncoveredFiles, outputPath } = args;
      const correlationId = extractCorrelationId({});
      
      componentLogger.info('Retrieving test coverage', { 
        testCategory,
        format,
        threshold,
        correlationId 
      });
      
      log?.info?.('Retrieving test coverage', { testCategory, format, correlationId });
      
      try {
        reportProgress({ progress: 0, total: 100 });

        // Build and run coverage command using helper function
        const coverageCmd = buildCoverageCommand(testCategory);
        
        reportProgress({ progress: 30, total: 100 });
        
        const { exitCode: _exitCode } = await runCommand('npm', coverageCmd);
        
        reportProgress({ progress: 60, total: 100 });
        
        // Process coverage summary using helper function
        const coverageSummaryPath = resolve('coverage/coverage-summary.json');
        let coverageData = {
          overall: { lines: 0, functions: 0, branches: 0, statements: 0 },
          files: [],
          threshold: { met: false, required: threshold, actual: 0 },
          uncoveredFiles: [],
        } as CoverageReport;
        
        if (await checkFileExists(coverageSummaryPath)) {
          coverageData = processCoverageSummary(coverageSummaryPath, threshold);
        }
        
        // Find uncovered files if requested using helper function
        if (includeUncoveredFiles) {
          coverageData.uncoveredFiles = await findUncoveredFiles(coverageData);
        }
        
        reportProgress({ progress: 100, total: 100 });
        
        componentLogger.info('Coverage analysis completed', { 
          testCategory,
          overallCoverage: coverageData.overall.lines,
          thresholdMet: coverageData.threshold.met,
          correlationId 
        });
        
        // Generate analysis using helper function
        const analysis = generateCoverageAnalysis(coverageData);
        
        return formatSuccessResponse({
          status: coverageData.threshold.met ? 'passed' : 'failed',
          coverage: coverageData,
          analysis,
          configuration: {
            testCategory,
            format,
            threshold,
            includeUncoveredFiles,
            outputPath,
          },
        });
        
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        componentLogger.error('Coverage analysis failed', { 
          testCategory,
          error: errorMessage,
          correlationId 
        });
        
        throw new Error(`Coverage analysis failed: ${errorMessage}`);
      }
    },
  });
}

function addValidateDeploymentReadinessTool(server: FastMCP, componentLogger: typeof logger): void {
  /**
   * Validate Deployment Readiness Tool
   * Comprehensive pre-deployment validation with environment-specific checks
   * 
   * @param environment - Target deployment environment
   * @param includeLinting - Include linting checks
   * @param includeTypeCheck - Include TypeScript type checking
   * @param includeTests - Include test execution
   * @param includeBuild - Include build verification
   * @param includeSecurityChecks - Include security vulnerability scanning
   * @param includeDependencyCheck - Include dependency vulnerability check
   * @param strictMode - Enable strict mode (fail on warnings)
   * @returns {object} Deployment readiness assessment with actionable recommendations
   * 
   * @example
   * ```bash
   * # Validate production deployment readiness
   * mcp-client validate-deployment-readiness \
   *   --environment production \
   *   --strictMode true \
   *   --includeSecurityChecks true
   * ```
   */
  server.addTool({
    name: 'validate-deployment-readiness',
    description: 'Comprehensive pre-deployment validation with environment-specific checks and security scanning',
    parameters: DeploymentReadinessSchema,
    annotations: {
      title: 'Validate Deployment Readiness',
    },
    execute: async (args, { log, reportProgress }) => {
      const { environment, includeLinting, includeTypeCheck, includeTests, includeBuild, includeSecurityChecks, includeDependencyCheck, strictMode } = args;
      const correlationId = extractCorrelationId({});
      
      componentLogger.info('Validating deployment readiness', { 
        environment,
        strictMode,
        correlationId 
      });
      
      log?.info?.('Validating deployment readiness', { environment, correlationId });
      
      try {
        reportProgress({ progress: 0, total: 100 });

        const checks: DeploymentCheck['checks'] = [];
        let currentProgress = 0;
        const totalChecks = [includeLinting, includeTypeCheck, includeTests, includeBuild, includeSecurityChecks, includeDependencyCheck].filter(Boolean).length;
        const progressIncrement = 90 / totalChecks;
        
        // Execute checks using helper functions
        if (includeLinting) {
          checks.push(await performLintingCheck(strictMode));
          currentProgress += progressIncrement;
          reportProgress({ progress: currentProgress, total: 100 });
        }
        
        if (includeTypeCheck) {
          checks.push(await performTypeCheck());
          currentProgress += progressIncrement;
          reportProgress({ progress: currentProgress, total: 100 });
        }
        
        if (includeTests) {
          checks.push(await performTestExecution());
          currentProgress += progressIncrement;
          reportProgress({ progress: currentProgress, total: 100 });
        }
        
        if (includeBuild) {
          checks.push(await performBuildVerification());
          currentProgress += progressIncrement;
          reportProgress({ progress: currentProgress, total: 100 });
        }
        
        if (includeSecurityChecks) {
          checks.push(await performSecurityCheck(strictMode));
          currentProgress += progressIncrement;
          reportProgress({ progress: currentProgress, total: 100 });
        }
        
        if (includeDependencyCheck) {
          checks.push(await performDependencyCheck());
          currentProgress += progressIncrement;
          reportProgress({ progress: currentProgress, total: 100 });
        }
        
        // Calculate summary using helper function
        const summary = calculateDeploymentSummary(checks, strictMode);
        
        // Generate recommendations using helper function
        const recommendations = generateDeploymentRecommendations(summary, strictMode, environment);
        
        const deploymentCheck: DeploymentCheck = {
          passed: summary.overallPassed,
          checks,
          summary: {
            totalChecks: checks.length,
            passedChecks: summary.passedChecks,
            failedChecks: summary.failedChecks,
            warningChecks: summary.warningChecks,
            overallScore: summary.overallScore,
          },
          recommendations,
        };
        
        reportProgress({ progress: 100, total: 100 });
        
        componentLogger.info('Deployment readiness validation completed', { 
          environment,
          passed: summary.overallPassed,
          score: summary.overallScore,
          correlationId 
        });
        
        return formatSuccessResponse({
          status: summary.overallPassed ? 'ready' : 'not_ready',
          environment,
          readiness: deploymentCheck,
          configuration: {
            environment,
            strictMode,
            enabledChecks: {
              linting: includeLinting,
              typeCheck: includeTypeCheck,
              tests: includeTests,
              build: includeBuild,
              security: includeSecurityChecks,
              dependencies: includeDependencyCheck,
            },
          },
        }).content[0].text;
        
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        componentLogger.error('Deployment readiness validation failed', { 
          environment,
          error: errorMessage,
          correlationId 
        });
        
        throw new Error(`Deployment readiness validation failed: ${errorMessage}`);
      }
    },
  });
}

function addGenerateBuildReportTool(server: FastMCP, componentLogger: typeof logger): void {
  /**
   * Generate Build Report Tool
   * Comprehensive build analysis with quality metrics and security assessment
   * 
   * @param includeMetrics - Include build performance metrics
   * @param includeQualityScores - Include code quality scores
   * @param includeDependencyAnalysis - Include dependency analysis
   * @param includeSecurityScan - Include security vulnerability scan
   * @param includeSizeAnalysis - Include bundle size analysis
   * @param outputFormat - Output format for build report
   * @returns {object} Comprehensive build report with recommendations and quality scores
   * 
   * @example
   * ```bash
   * # Generate comprehensive build report
   * mcp-client generate-build-report \
   *   --includeMetrics true \
   *   --includeQualityScores true \
   *   --includeSecurityScan true \
   *   --outputFormat json
   * ```
   */
  server.addTool({
    name: 'generate-build-report',
    description: 'Generate comprehensive build analysis with quality metrics, security assessment, and performance insights',
    parameters: BuildReportSchema,
    annotations: {
      title: 'Generate Build Report',
    },
    execute: async (args, { log, reportProgress }) => {
      const { includeMetrics, includeQualityScores, includeDependencyAnalysis, includeSecurityScan, includeSizeAnalysis, outputFormat } = args;
      const correlationId = extractCorrelationId({});
      
      componentLogger.info('Generating build report', { 
        includeMetrics,
        includeQualityScores,
        includeSecurityScan,
        outputFormat,
        correlationId 
      });
      
      log?.info?.('Generating build report', { outputFormat, correlationId });
      
      try {
        reportProgress({ progress: 0, total: 100 });

        const startTime = Date.now();
        
        // Initialize build report using helper function
        let buildReport = await initializeBuildReport();
        
        // Collect metrics using helper function
        if (includeMetrics) {
          reportProgress({ progress: 20, total: 100 });
          buildReport = await collectBuildMetrics(buildReport);
        }
        
        // Collect quality scores using helper function
        if (includeQualityScores) {
          reportProgress({ progress: 50, total: 100 });
          buildReport = await collectQualityScores(buildReport);
        }
        
        // Collect security data using helper function
        if (includeSecurityScan) {
          reportProgress({ progress: 70, total: 100 });
          buildReport = await collectSecurityData(buildReport);
        }
        
        // Collect dependency analysis using helper function
        if (includeDependencyAnalysis) {
          reportProgress({ progress: 85, total: 100 });
          buildReport = await collectDependencyAnalysis(buildReport);
        }
        
        // Generate recommendations using helper function
        buildReport.recommendations = generateBuildRecommendations(buildReport);
        buildReport.buildInfo.duration = Date.now() - startTime;
        
        reportProgress({ progress: 100, total: 100 });
        
        componentLogger.info('Build report generated', { 
          buildStatus: buildReport.buildInfo.status,
          duration: buildReport.buildInfo.duration,
          recommendations: buildReport.recommendations.length,
          correlationId 
        });
        
        // Generate summary using helper function
        const summary = generateBuildSummary(buildReport);
        
        return formatSuccessResponse({
          report: buildReport,
          summary,
          configuration: {
            includeMetrics,
            includeQualityScores,
            includeDependencyAnalysis,
            includeSecurityScan,
            includeSizeAnalysis,
            outputFormat,
          },
        });
        
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        componentLogger.error('Build report generation failed', { 
          error: errorMessage,
          correlationId 
        });
        
        throw new Error(`Build report generation failed: ${errorMessage}`);
      }
    },
  });
}

export function addCICDIntegrationTools(server: FastMCP, _apiClient: MakeApiClient): void {
  const getComponentLogger = () => {
    try {
      return logger.child({ component: 'CICDIntegration' });
    } catch (error) {
      // Fallback for test environments
      return logger as any;
    }
  };
  const componentLogger = getComponentLogger();

  // Add all CI/CD integration tools
  addRunTestSuiteTool(server, componentLogger);
  addGetTestCoverageTool(server, componentLogger);
  addValidateDeploymentReadinessTool(server, componentLogger);
  addGenerateBuildReportTool(server, componentLogger);

  componentLogger.info('CI/CD integration tools added successfully');
}

function calculateOverallGrade(report: BuildReport): string {
  const qualityAvg = (report.quality.lintScore + report.quality.typeScore + report.quality.testCoverage) / 3;
  const securityScore = report.security.securityScore;
  const overallScore = (qualityAvg + securityScore) / 2;
  
  if (overallScore >= 90) {return 'A';}
  if (overallScore >= 80) {return 'B';}
  if (overallScore >= 70) {return 'C';}
  if (overallScore >= 60) {return 'D';}
  return 'F';
}