#!/usr/bin/env node

/**
 * @fileoverview Master Validation Runner for Scenarios Module Refactoring
 * 
 * This script coordinates all validation tests for the refactored scenarios module,
 * including compatibility tests, regression tests, and performance benchmarks.
 * 
 * Usage:
 *   npm run validate:scenarios              # Run all validations
 *   npm run validate:scenarios -- --quick   # Skip performance tests
 *   npm run validate:scenarios -- --verbose # Detailed output
 *   npm run validate:scenarios -- --help    # Show help
 */

import { performance } from 'perf_hooks';
import { spawn } from 'child_process';
import { promises as fs } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Configuration
const config = {
  verbose: process.argv.includes('--verbose'),
  quick: process.argv.includes('--quick'),
  help: process.argv.includes('--help'),
  outputDir: path.join(__dirname, '../../validation-reports'),
  timestamp: new Date().toISOString().replace(/[:.]/g, '-')
};

// Console colors
const colors = {
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  bold: '\x1b[1m',
  reset: '\x1b[0m'
};

function log(message, color = 'white') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

function showHelp() {
  log('\n📖 Scenarios Module Validation Suite', 'cyan');
  log('=====================================', 'cyan');
  log('\nThis validation suite ensures that the refactored scenarios module');
  log('maintains 100% functional compatibility with the original implementation.\n');
  
  log('Usage:', 'yellow');
  log('  npm run validate:scenarios              # Run all validations');
  log('  npm run validate:scenarios -- --quick   # Skip performance tests');
  log('  npm run validate:scenarios -- --verbose # Detailed output');
  log('  npm run validate:scenarios -- --help    # Show this help\n');
  
  log('Test Categories:', 'yellow');
  log('  🔧 Compatibility Tests     - Tool registration, schema validation');
  log('  🧪 Regression Tests        - Output comparison with original');
  log('  📊 Performance Benchmarks  - Performance regression detection');
  log('  🔍 Integration Tests       - Full workflow validation\n');
  
  log('Output:', 'yellow');
  log('  Validation reports are saved to: ./validation-reports/');
  log('  Exit codes: 0 = success, 1 = validation failed, 2 = critical error\n');
}

async function runCommand(command, args = [], options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      stdio: config.verbose ? 'inherit' : 'pipe',
      shell: true,
      ...options
    });
    
    let stdout = '';
    let stderr = '';
    
    if (!config.verbose) {
      child.stdout?.on('data', (data) => {
        stdout += data.toString();
      });
      
      child.stderr?.on('data', (data) => {
        stderr += data.toString();
      });
    }
    
    child.on('close', (code) => {
      resolve({
        code,
        stdout,
        stderr,
        success: code === 0
      });
    });
    
    child.on('error', (error) => {
      reject(error);
    });
  });
}

async function ensureOutputDirectory() {
  try {
    await fs.mkdir(config.outputDir, { recursive: true });
  } catch (error) {
    if (error.code !== 'EEXIST') {
      throw error;
    }
  }
}

async function runCompatibilityTests() {
  log('\n🔧 Running Compatibility Tests...', 'blue');
  
  const startTime = performance.now();
  
  try {
    const result = await runCommand('node', [
      path.join(__dirname, 'validate-scenarios-refactoring.js'),
      ...(config.verbose ? ['--verbose'] : [])
    ]);
    
    const endTime = performance.now();
    const duration = endTime - startTime;
    
    if (result.success) {
      log(`✅ Compatibility tests PASSED (${duration.toFixed(0)}ms)`, 'green');
    } else {
      log(`❌ Compatibility tests FAILED (${duration.toFixed(0)}ms)`, 'red');
      if (!config.verbose && result.stdout) {
        log('Output:', 'yellow');
        log(result.stdout);
      }
    }
    
    // Save results
    await fs.writeFile(
      path.join(config.outputDir, `compatibility-test-${config.timestamp}.log`),
      `Compatibility Test Results\n${'='.repeat(50)}\n\n` +
      `Start Time: ${new Date().toISOString()}\n` +
      `Duration: ${duration.toFixed(2)}ms\n` +
      `Exit Code: ${result.code}\n` +
      `Success: ${result.success}\n\n` +
      `STDOUT:\n${result.stdout}\n\n` +
      `STDERR:\n${result.stderr}\n`
    );
    
    return { success: result.success, duration, output: result.stdout };
    
  } catch (error) {
    log(`💥 Compatibility tests crashed: ${error.message}`, 'red');
    return { success: false, duration: 0, error: error.message };
  }
}

async function runRegressionTests() {
  log('\n🧪 Running Regression Tests...', 'blue');
  
  const startTime = performance.now();
  
  try {
    const result = await runCommand('node', [
      path.join(__dirname, 'regression-test.js'),
      ...(config.verbose ? ['--verbose'] : []),
      '--performance'
    ]);
    
    const endTime = performance.now();
    const duration = endTime - startTime;
    
    if (result.success) {
      log(`✅ Regression tests PASSED (${duration.toFixed(0)}ms)`, 'green');
    } else {
      log(`❌ Regression tests FAILED (${duration.toFixed(0)}ms)`, 'red');
      if (!config.verbose && result.stdout) {
        log('Output:', 'yellow');
        log(result.stdout);
      }
    }
    
    // Save results
    await fs.writeFile(
      path.join(config.outputDir, `regression-test-${config.timestamp}.log`),
      `Regression Test Results\n${'='.repeat(50)}\n\n` +
      `Start Time: ${new Date().toISOString()}\n` +
      `Duration: ${duration.toFixed(2)}ms\n` +
      `Exit Code: ${result.code}\n` +
      `Success: ${result.success}\n\n` +
      `STDOUT:\n${result.stdout}\n\n` +
      `STDERR:\n${result.stderr}\n`
    );
    
    return { success: result.success, duration, output: result.stdout };
    
  } catch (error) {
    log(`💥 Regression tests crashed: ${error.message}`, 'red');
    return { success: false, duration: 0, error: error.message };
  }
}

async function runPerformanceBenchmarks() {
  if (config.quick) {
    log('\n📊 Skipping Performance Benchmarks (--quick mode)', 'yellow');
    return { success: true, duration: 0, skipped: true };
  }
  
  log('\n📊 Running Performance Benchmarks...', 'blue');
  
  const startTime = performance.now();
  
  try {
    // Run Jest performance tests
    const result = await runCommand('npm', ['run', 'test:performance'], {
      cwd: path.join(__dirname, '../..')
    });
    
    const endTime = performance.now();
    const duration = endTime - startTime;
    
    if (result.success) {
      log(`✅ Performance benchmarks PASSED (${duration.toFixed(0)}ms)`, 'green');
    } else {
      log(`❌ Performance benchmarks FAILED (${duration.toFixed(0)}ms)`, 'red');
      if (!config.verbose && result.stdout) {
        log('Output:', 'yellow');
        log(result.stdout);
      }
    }
    
    // Save results
    await fs.writeFile(
      path.join(config.outputDir, `performance-benchmark-${config.timestamp}.log`),
      `Performance Benchmark Results\n${'='.repeat(50)}\n\n` +
      `Start Time: ${new Date().toISOString()}\n` +
      `Duration: ${duration.toFixed(2)}ms\n` +
      `Exit Code: ${result.code}\n` +
      `Success: ${result.success}\n\n` +
      `STDOUT:\n${result.stdout}\n\n` +
      `STDERR:\n${result.stderr}\n`
    );
    
    return { success: result.success, duration, output: result.stdout };
    
  } catch (error) {
    log(`💥 Performance benchmarks crashed: ${error.message}`, 'red');
    return { success: false, duration: 0, error: error.message };
  }
}

async function runIntegrationTests() {
  log('\n🔍 Running Integration Tests...', 'blue');
  
  const startTime = performance.now();
  
  try {
    // Run Jest integration tests for scenarios
    const result = await runCommand('npm', ['test', '--', '--testPathPattern=scenarios.*integration'], {
      cwd: path.join(__dirname, '../..')
    });
    
    const endTime = performance.now();
    const duration = endTime - startTime;
    
    if (result.success) {
      log(`✅ Integration tests PASSED (${duration.toFixed(0)}ms)`, 'green');
    } else {
      log(`❌ Integration tests FAILED (${duration.toFixed(0)}ms)`, 'red');
      if (!config.verbose && result.stdout) {
        log('Output:', 'yellow');
        log(result.stdout);
      }
    }
    
    // Save results
    await fs.writeFile(
      path.join(config.outputDir, `integration-test-${config.timestamp}.log`),
      `Integration Test Results\n${'='.repeat(50)}\n\n` +
      `Start Time: ${new Date().toISOString()}\n` +
      `Duration: ${duration.toFixed(2)}ms\n` +
      `Exit Code: ${result.code}\n` +
      `Success: ${result.success}\n\n` +
      `STDOUT:\n${result.stdout}\n\n` +
      `STDERR:\n${result.stderr}\n`
    );
    
    return { success: result.success, duration, output: result.stdout };
    
  } catch (error) {
    log(`💥 Integration tests crashed: ${error.message}`, 'red');
    return { success: false, duration: 0, error: error.message };
  }
}

async function generateSummaryReport(results) {
  const reportPath = path.join(config.outputDir, `validation-summary-${config.timestamp}.json`);
  const markdownPath = path.join(config.outputDir, `validation-summary-${config.timestamp}.md`);
  
  const summary = {
    timestamp: new Date().toISOString(),
    configuration: config,
    results: results,
    overall: {
      success: results.every(r => r.success),
      totalDuration: results.reduce((sum, r) => sum + r.duration, 0),
      testsRun: results.filter(r => !r.skipped).length,
      testsSkipped: results.filter(r => r.skipped).length
    }
  };
  
  // JSON report
  await fs.writeFile(reportPath, JSON.stringify(summary, null, 2));
  
  // Markdown report
  const markdown = generateMarkdownReport(summary);
  await fs.writeFile(markdownPath, markdown);
  
  return { reportPath, markdownPath, summary };
}

function generateMarkdownReport(summary) {
  const { results, overall } = summary;
  
  return `# Scenarios Module Validation Report

**Generated:** ${summary.timestamp}  
**Overall Result:** ${overall.success ? '✅ PASSED' : '❌ FAILED'}  
**Total Duration:** ${overall.totalDuration.toFixed(2)}ms  
**Tests Run:** ${overall.testsRun}  
**Tests Skipped:** ${overall.testsSkipped}

## Test Results

${results.map(result => `
### ${result.name}

- **Status:** ${result.success ? '✅ PASSED' : '❌ FAILED'}
- **Duration:** ${result.duration.toFixed(2)}ms
${result.skipped ? '- **Note:** Skipped' : ''}
${result.error ? `- **Error:** ${result.error}` : ''}

`).join('')}

## Configuration

- **Verbose Mode:** ${summary.configuration.verbose}
- **Quick Mode:** ${summary.configuration.quick}
- **Output Directory:** ${summary.configuration.outputDir}

## Summary

${overall.success ? 
  '✅ **All validations passed!** The refactored scenarios module maintains full compatibility with the original implementation.' :
  '❌ **Some validations failed.** Please review the failed tests and address the issues before deploying the refactored module.'
}

---
*Generated by Scenarios Module Validation Suite*
`;
}

async function main() {
  if (config.help) {
    showHelp();
    process.exit(0);
  }
  
  log('\n🚀 Starting Scenarios Module Validation Suite', 'cyan');
  log(`${'='.repeat(60)}`, 'cyan');
  log(`Configuration: ${config.verbose ? 'verbose' : 'normal'}, ${config.quick ? 'quick' : 'full'} mode`, 'blue');
  log(`Output directory: ${config.outputDir}`, 'blue');
  
  const overallStartTime = performance.now();
  
  try {
    // Ensure output directory exists
    await ensureOutputDirectory();
    
    // Run all validation categories
    const testResults = [];
    
    // 1. Compatibility Tests
    const compatibilityResult = await runCompatibilityTests();
    testResults.push({ 
      name: 'Compatibility Tests',
      ...compatibilityResult
    });
    
    // 2. Regression Tests
    const regressionResult = await runRegressionTests();
    testResults.push({
      name: 'Regression Tests', 
      ...regressionResult
    });
    
    // 3. Performance Benchmarks
    const performanceResult = await runPerformanceBenchmarks();
    testResults.push({
      name: 'Performance Benchmarks',
      ...performanceResult
    });
    
    // 4. Integration Tests
    const integrationResult = await runIntegrationTests();
    testResults.push({
      name: 'Integration Tests',
      ...integrationResult
    });
    
    // Generate summary report
    const { reportPath, markdownPath, summary } = await generateSummaryReport(testResults);
    
    const overallEndTime = performance.now();
    const totalDuration = overallEndTime - overallStartTime;
    
    // Final summary
    log(`\n${'='.repeat(60)}`, 'cyan');
    log('VALIDATION SUITE SUMMARY', 'cyan');
    log(`${'='.repeat(60)}`, 'cyan');
    
    log(`\nTest Categories:`, 'white');
    testResults.forEach(result => {
      const status = result.success ? '✅' : result.skipped ? '⏭️' : '❌';
      const color = result.success ? 'green' : result.skipped ? 'yellow' : 'red';
      log(`  ${status} ${result.name} (${result.duration.toFixed(0)}ms)`, color);
    });
    
    const overallSuccess = summary.overall.success;
    const passedCount = testResults.filter(r => r.success).length;
    const skippedCount = testResults.filter(r => r.skipped).length;
    const failedCount = testResults.filter(r => !r.success && !r.skipped).length;
    
    log(`\nOverall Results:`, 'white');
    log(`  Total Duration: ${totalDuration.toFixed(0)}ms`, 'blue');
    log(`  Passed: ${passedCount}`, 'green');
    log(`  Failed: ${failedCount}`, failedCount > 0 ? 'red' : 'green');
    log(`  Skipped: ${skippedCount}`, skippedCount > 0 ? 'yellow' : 'green');
    
    log(`\nReports Generated:`, 'white');
    log(`  JSON Report: ${reportPath}`, 'blue');
    log(`  Markdown Report: ${markdownPath}`, 'blue');
    
    log(`\n${'='.repeat(60)}`, overallSuccess ? 'green' : 'red');
    log(`VALIDATION ${overallSuccess ? 'PASSED' : 'FAILED'}`, overallSuccess ? 'green' : 'red');
    log(`${'='.repeat(60)}`, overallSuccess ? 'green' : 'red');
    
    if (overallSuccess) {
      log(`\n🎉 All validations passed! The refactored scenarios module is ready for deployment.`, 'green');
    } else {
      log(`\n⚠️  Some validations failed. Please review the issues and re-run validation.`, 'red');
    }
    
    process.exit(overallSuccess ? 0 : 1);
    
  } catch (error) {
    log(`\n💥 VALIDATION SUITE CRASHED:`, 'red');
    log(`${error.message}`, 'red');
    if (config.verbose && error.stack) {
      log(`${error.stack}`, 'red');
    }
    
    process.exit(2);
  }
}

// Run validation suite if this script is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}

export { main, config };