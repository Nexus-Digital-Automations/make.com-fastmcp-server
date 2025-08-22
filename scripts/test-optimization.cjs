#!/usr/bin/env node

/**
 * Test Infrastructure Optimization Script
 * 
 * Implements systematic test improvements as outlined in research analysis.
 * Focuses on fixing timeout issues, improving coverage, and establishing baselines.
 * 
 * Research Priority: Phase 1 Foundation - Test Infrastructure Optimization
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

console.log('🧪 Test Infrastructure Optimization');
console.log('==================================');

// Test categories and their expected performance characteristics
const testCategories = {
  unit: { timeout: 5000, maxDuration: 100 },
  integration: { timeout: 15000, maxDuration: 1000 },
  e2e: { timeout: 30000, maxDuration: 5000 },
};

/**
 * Analyze test failures and categorize issues
 */
function analyzeTestFailures() {
  console.log('\n📊 Analyzing Test Failures...');
  
  try {
    // Run tests with JSON output to capture detailed results
    const testOutput = execSync('npm test -- --json --outputFile=test-results.json --silent', { 
      encoding: 'utf8',
      timeout: 120000, // 2 minutes max
    });
    
    const results = JSON.parse(fs.readFileSync('test-results.json', 'utf8'));
    
    const analysis = {
      total: results.numTotalTests,
      passed: results.numPassedTests,
      failed: results.numFailedTests,
      skipped: results.numPendingTests,
      timeouts: 0,
      loggerErrors: 0,
      validationErrors: 0,
      other: 0,
    };
    
    // Categorize failures by error type
    if (results.testResults) {
      results.testResults.forEach(suite => {
        if (suite.assertionResults) {
          suite.assertionResults.forEach(test => {
            if (test.status === 'failed' && test.failureMessages) {
              test.failureMessages.forEach(message => {
                if (message.includes('timeout') || message.includes('Timeout')) {
                  analysis.timeouts++;
                } else if (message.includes('logger') || message.includes('child is not a function')) {
                  analysis.loggerErrors++;
                } else if (message.includes('validation') || message.includes('expect')) {
                  analysis.validationErrors++;
                } else {
                  analysis.other++;
                }
              });
            }
          });
        }
      });
    }
    
    console.log('Test Failure Analysis:');
    console.log(`  Total Tests: ${analysis.total}`);
    console.log(`  Passed: ${analysis.passed} (${((analysis.passed / analysis.total) * 100).toFixed(1)}%)`);
    console.log(`  Failed: ${analysis.failed}`);
    console.log(`    - Timeouts: ${analysis.timeouts}`);
    console.log(`    - Logger Errors: ${analysis.loggerErrors}`);
    console.log(`    - Validation Errors: ${analysis.validationErrors}`);
    console.log(`    - Other: ${analysis.other}`);
    console.log(`  Skipped: ${analysis.skipped}`);
    
    return analysis;
    
  } catch (error) {
    console.log('⚠️  Could not complete full test analysis:', error.message);
    return null;
  }
}

/**
 * Check test coverage and identify gaps
 */
function checkTestCoverage() {
  console.log('\n📈 Checking Test Coverage...');
  
  try {
    // Run coverage analysis
    const coverageOutput = execSync('npm run test:coverage -- --silent', { 
      encoding: 'utf8',
      timeout: 60000,
    });
    
    // Parse coverage from output
    const coverageLines = coverageOutput.split('\n');
    const summaryLine = coverageLines.find(line => line.includes('All files'));
    
    if (summaryLine) {
      const match = summaryLine.match(/(\d+\.?\d*)\s*\|\s*(\d+\.?\d*)\s*\|\s*(\d+\.?\d*)\s*\|\s*(\d+\.?\d*)/);
      if (match) {
        const [, statements, branches, functions, lines] = match;
        console.log(`Current Coverage:`);
        console.log(`  Statements: ${statements}%`);
        console.log(`  Branches: ${branches}%`);
        console.log(`  Functions: ${functions}%`);
        console.log(`  Lines: ${lines}%`);
        
        // Check against research targets
        const targets = { statements: 75, branches: 70, functions: 80, lines: 75 };
        const gaps = {
          statements: Math.max(0, targets.statements - parseFloat(statements)),
          branches: Math.max(0, targets.branches - parseFloat(branches)),
          functions: Math.max(0, targets.functions - parseFloat(functions)),
          lines: Math.max(0, targets.lines - parseFloat(lines)),
        };
        
        console.log('\nCoverage Gaps (vs Research Targets):');
        Object.entries(gaps).forEach(([metric, gap]) => {
          if (gap > 0) {
            console.log(`  ${metric}: ${gap.toFixed(1)}% below target`);
          } else {
            console.log(`  ${metric}: ✅ Target met`);
          }
        });
        
        return { current: { statements, branches, functions, lines }, gaps };
      }
    }
    
  } catch (error) {
    console.log('⚠️  Could not analyze coverage:', error.message);
  }
  
  return null;
}

/**
 * Generate test improvement recommendations
 */
function generateRecommendations(analysis, coverage) {
  console.log('\n💡 Test Improvement Recommendations');
  console.log('===================================');
  
  const recommendations = [];
  
  if (analysis) {
    // Timeout recommendations
    if (analysis.timeouts > 0) {
      recommendations.push({
        priority: 'HIGH',
        category: 'Performance',
        issue: `${analysis.timeouts} tests failing due to timeouts`,
        solution: 'Optimize test performance, increase timeouts for integration tests, add performance monitoring',
      });
    }
    
    // Logger error recommendations
    if (analysis.loggerErrors > 0) {
      recommendations.push({
        priority: 'HIGH',
        category: 'Infrastructure',
        issue: `${analysis.loggerErrors} tests failing due to logger mocking issues`,
        solution: 'Apply MetricsCollector logger fix pattern to other singleton classes',
      });
    }
    
    // Validation error recommendations
    if (analysis.validationErrors > 0) {
      recommendations.push({
        priority: 'MEDIUM',
        category: 'Test Logic',
        issue: `${analysis.validationErrors} tests failing validation checks`,
        solution: 'Review test expectations, fix mock data, improve error handling tests',
      });
    }
  }
  
  if (coverage) {
    // Coverage recommendations
    Object.entries(coverage.gaps).forEach(([metric, gap]) => {
      if (gap > 10) {
        recommendations.push({
          priority: 'MEDIUM',
          category: 'Coverage',
          issue: `${metric} coverage ${gap.toFixed(1)}% below target`,
          solution: `Add comprehensive ${metric} tests, focus on core modules first`,
        });
      }
    });
  }
  
  // Print recommendations
  recommendations.forEach((rec, index) => {
    console.log(`${index + 1}. [${rec.priority}] ${rec.category}`);
    console.log(`   Issue: ${rec.issue}`);
    console.log(`   Solution: ${rec.solution}`);
    console.log();
  });
  
  return recommendations;
}

/**
 * Create performance benchmarks for tests
 */
function createPerformanceBenchmarks() {
  console.log('\n⏱️  Creating Performance Benchmarks...');
  
  const benchmarks = {
    unit: [],
    integration: [],
    performance: [],
  };
  
  // Find test files and categorize them
  const testDirs = ['tests/unit', 'tests/integration', 'tests/e2e'];
  
  testDirs.forEach(dir => {
    if (fs.existsSync(dir)) {
      const files = fs.readdirSync(dir, { recursive: true })
        .filter(file => file.endsWith('.test.ts') || file.endsWith('.test.js'));
      
      files.forEach(file => {
        const category = dir.includes('unit') ? 'unit' : 
                        dir.includes('integration') ? 'integration' : 'performance';
        benchmarks[category].push({
          file: path.join(dir, file),
          expectedDuration: testCategories[category]?.maxDuration || 1000,
        });
      });
    }
  });
  
  console.log('Test Performance Benchmarks:');
  Object.entries(benchmarks).forEach(([category, tests]) => {
    console.log(`  ${category}: ${tests.length} test files`);
  });
  
  return benchmarks;
}

/**
 * Main execution
 */
async function main() {
  console.log('Starting test infrastructure analysis...\n');
  
  // Step 1: Analyze current test failures
  const analysis = analyzeTestFailures();
  
  // Step 2: Check test coverage
  const coverage = checkTestCoverage();
  
  // Step 3: Generate improvement recommendations
  const recommendations = generateRecommendations(analysis, coverage);
  
  // Step 4: Create performance benchmarks
  const benchmarks = createPerformanceBenchmarks();
  
  // Step 5: Save analysis results
  const results = {
    timestamp: new Date().toISOString(),
    analysis,
    coverage,
    recommendations,
    benchmarks,
  };
  
  const reportPath = 'development/reports/test-optimization-analysis.json';
  fs.mkdirSync(path.dirname(reportPath), { recursive: true });
  fs.writeFileSync(reportPath, JSON.stringify(results, null, 2));
  
  console.log(`\n📋 Analysis saved to: ${reportPath}`);
  console.log('\n✅ Test infrastructure analysis complete!');
  console.log('\nNext Steps:');
  console.log('1. Address HIGH priority recommendations first');
  console.log('2. Implement systematic test coverage improvements');
  console.log('3. Setup continuous performance monitoring');
  console.log('4. Run this analysis regularly to track progress');
}

// Run the analysis
if (require.main === module) {
  main().catch(console.error);
}

module.exports = {
  analyzeTestFailures,
  checkTestCoverage,
  generateRecommendations,
  createPerformanceBenchmarks,
};