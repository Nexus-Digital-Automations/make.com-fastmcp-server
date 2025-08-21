#!/usr/bin/env node

/**
 * Coverage validation script with comprehensive threshold enforcement
 * Validates test coverage against configured thresholds and provides detailed reporting
 */

import { readFileSync, existsSync } from 'fs';
import { join } from 'path';

class CoverageValidator {
  constructor() {
    this.coveragePath = 'coverage/coverage-summary.json';
    this.jestConfigPath = 'jest.config.js';
    this.thresholds = this.loadCoverageThresholds();
  }

  /**
   * Load coverage thresholds from jest configuration
   */
  loadCoverageThresholds() {
    try {
      // Import jest config dynamically
      const jestConfig = require('../jest.config.js');
      return jestConfig.default?.coverageThreshold || jestConfig.coverageThreshold || {};
    } catch (error) {
      console.warn('⚠️  Could not load jest config, using default thresholds');
      return {
        global: {
          branches: 80,
          functions: 80,
          lines: 80,
          statements: 80
        }
      };
    }
  }

  /**
   * Load coverage summary data
   */
  loadCoverageSummary() {
    if (!existsSync(this.coveragePath)) {
      throw new Error('❌ Coverage summary not found. Run tests with coverage first.');
    }

    try {
      const coverage = JSON.parse(readFileSync(this.coveragePath, 'utf8'));
      return coverage;
    } catch (error) {
      throw new Error(`❌ Failed to parse coverage summary: ${error.message}`);
    }
  }

  /**
   * Validate coverage against thresholds
   */
  validateCoverage() {
    console.log('🔍 Validating test coverage thresholds...\n');

    const coverage = this.loadCoverageSummary();
    const results = {
      passed: true,
      violations: [],
      summary: {}
    };

    // Validate each threshold configuration
    for (const [path, thresholds] of Object.entries(this.thresholds)) {
      const pathResults = this.validatePath(coverage, path, thresholds);
      
      if (!pathResults.passed) {
        results.passed = false;
        results.violations.push(...pathResults.violations);
      }
      
      results.summary[path] = pathResults;
    }

    return results;
  }

  /**
   * Validate coverage for a specific path
   */
  validatePath(coverage, path, thresholds) {
    const results = {
      passed: true,
      violations: [],
      coverage: null,
      thresholds
    };

    // Get coverage data for the path
    let coverageData;
    if (path === 'global') {
      coverageData = coverage.total;
    } else {
      // Find matching coverage data for specific paths
      const matchingKeys = Object.keys(coverage).filter(key => 
        key.startsWith(path.replace('./', '')) || key.includes(path)
      );
      
      if (matchingKeys.length === 0) {
        console.warn(`⚠️  No coverage data found for path: ${path}`);
        return results;
      }

      // Aggregate coverage for matching paths
      coverageData = this.aggregateCoverage(coverage, matchingKeys);
    }

    results.coverage = coverageData;

    // Check each metric threshold
    const metrics = ['lines', 'statements', 'functions', 'branches'];
    for (const metric of metrics) {
      if (thresholds[metric] !== undefined) {
        const actual = coverageData[metric]?.pct || 0;
        const required = thresholds[metric];
        
        if (actual < required) {
          results.passed = false;
          const violation = {
            path,
            metric,
            actual,
            required,
            deficit: required - actual
          };
          results.violations.push(violation);
        }
      }
    }

    return results;
  }

  /**
   * Aggregate coverage data from multiple paths
   */
  aggregateCoverage(coverage, keys) {
    const aggregated = {
      lines: { total: 0, covered: 0, pct: 0 },
      statements: { total: 0, covered: 0, pct: 0 },
      functions: { total: 0, covered: 0, pct: 0 },
      branches: { total: 0, covered: 0, pct: 0 }
    };

    for (const key of keys) {
      if (coverage[key]) {
        const data = coverage[key];
        for (const metric of Object.keys(aggregated)) {
          if (data[metric]) {
            aggregated[metric].total += data[metric].total;
            aggregated[metric].covered += data[metric].covered;
          }
        }
      }
    }

    // Calculate percentages
    for (const metric of Object.keys(aggregated)) {
      if (aggregated[metric].total > 0) {
        aggregated[metric].pct = Math.round(
          (aggregated[metric].covered / aggregated[metric].total) * 100 * 100
        ) / 100;
      }
    }

    return aggregated;
  }

  /**
   * Generate detailed coverage report
   */
  generateReport(results) {
    console.log('📊 Coverage Validation Report');
    console.log('════════════════════════════════════════════════════════════\n');

    // Overall status
    if (results.passed) {
      console.log('✅ All coverage thresholds passed!\n');
    } else {
      console.log('❌ Coverage thresholds failed!\n');
    }

    // Summary for each path
    for (const [path, pathResults] of Object.entries(results.summary)) {
      console.log(`📁 ${path === 'global' ? 'Global Coverage' : `Path: ${path}`}`);
      console.log('────────────────────────────────────────────────────────────');

      if (pathResults.coverage) {
        const coverage = pathResults.coverage;
        const thresholds = pathResults.thresholds;

        const metrics = [
          { name: 'Lines', key: 'lines', icon: '📏' },
          { name: 'Statements', key: 'statements', icon: '📝' },
          { name: 'Functions', key: 'functions', icon: '🔧' },
          { name: 'Branches', key: 'branches', icon: '🌿' }
        ];

        for (const metric of metrics) {
          const actual = coverage[metric.key]?.pct || 0;
          const required = thresholds[metric.key];
          const status = required === undefined ? '➖' : 
                        actual >= required ? '✅' : '❌';
          
          console.log(
            `  ${metric.icon} ${metric.name.padEnd(10)}: ${actual.toFixed(1).padStart(6)}%` +
            (required !== undefined ? ` (required: ${required}%) ${status}` : '')
          );
        }
      } else {
        console.log('  ⚠️  No coverage data available');
      }
      
      console.log('');
    }

    // Detailed violations
    if (results.violations.length > 0) {
      console.log('🚨 Coverage Violations');
      console.log('────────────────────────────────────────────────────────────');
      
      for (const violation of results.violations) {
        console.log(`❌ ${violation.path} - ${violation.metric}:`);
        console.log(`   Actual: ${violation.actual.toFixed(1)}%`);
        console.log(`   Required: ${violation.required}%`);
        console.log(`   Deficit: ${violation.deficit.toFixed(1)}%\n`);
      }
    }

    // Quality gates
    console.log('🚦 Quality Gates');
    console.log('────────────────────────────────────────────────────────────');
    console.log(`Coverage Validation: ${results.passed ? '✅ PASSED' : '❌ FAILED'}`);
    console.log(`Violations Found: ${results.violations.length}`);
    console.log(`Paths Validated: ${Object.keys(results.summary).length}\n`);

    return results;
  }

  /**
   * Generate machine-readable coverage report
   */
  generateMachineReport(results) {
    const report = {
      timestamp: new Date().toISOString(),
      passed: results.passed,
      violations: results.violations,
      summary: Object.entries(results.summary).map(([path, data]) => ({
        path,
        passed: data.passed,
        coverage: data.coverage,
        thresholds: data.thresholds
      }))
    };

    return JSON.stringify(report, null, 2);
  }

  /**
   * Run coverage validation
   */
  async run(options = {}) {
    const { format = 'human', failOnViolation = true } = options;

    try {
      const results = this.validateCoverage();
      
      if (format === 'json') {
        console.log(this.generateMachineReport(results));
      } else {
        this.generateReport(results);
      }

      // Exit with appropriate code
      if (failOnViolation && !results.passed) {
        console.log('💥 Exiting with error code due to coverage violations');
        process.exit(1);
      } else if (results.passed) {
        console.log('🎉 Coverage validation completed successfully!');
        process.exit(0);
      }
      
      return results;
    } catch (error) {
      console.error(`💥 Coverage validation failed: ${error.message}`);
      if (failOnViolation) {
        process.exit(1);
      }
      throw error;
    }
  }
}

// Parse command line arguments
const args = process.argv.slice(2);
const options = {
  format: args.includes('--json') ? 'json' : 'human',
  failOnViolation: !args.includes('--no-fail')
};

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const validator = new CoverageValidator();
  validator.run(options);
}

export default CoverageValidator;