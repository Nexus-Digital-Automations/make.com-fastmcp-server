#!/usr/bin/env node

/**
 * Test Performance Optimization Script
 * 
 * Analyzes test files and applies performance optimizations:
 * - Identifies slow setTimeout calls
 * - Reduces artificial delays
 * - Optimizes concurrent operations
 * - Suggests improvements for slow tests
 */

import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

class TestPerformanceOptimizer {
  constructor() {
    this.testDir = path.join(__dirname, '../tests');
    this.optimizations = [];
    this.slowPatterns = [
      /setTimeout\([^,]+,\s*(\d{3,})\)/, // setTimeout with 3+ digit delays
      /new Promise.*setTimeout.*(\d{3,})/, // Promise with long timeouts
      /await.*delay.*(\d{3,})/, // await delay patterns
      /jest\.advanceTimersByTime\((\d{4,})\)/ // Long timer advances
    ];
  }

  /**
   * Scan test files for performance issues
   */
  scanTestFiles() {
    console.log('🔍 Scanning test files for performance issues...\n');
    
    const testFiles = this.findTestFiles();
    const issues = [];

    testFiles.forEach(filePath => {
      const content = fs.readFileSync(filePath, 'utf8');
      const fileIssues = this.analyzeFileContent(filePath, content);
      issues.push(...fileIssues);
    });

    return issues;
  }

  /**
   * Find all test files recursively
   */
  findTestFiles() {
    const testFiles = [];
    
    const scanDirectory = (dir) => {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      
      entries.forEach(entry => {
        const fullPath = path.join(dir, entry.name);
        
        if (entry.isDirectory()) {
          scanDirectory(fullPath);
        } else if (entry.name.endsWith('.test.ts') || entry.name.endsWith('.test.js')) {
          testFiles.push(fullPath);
        }
      });
    };
    
    scanDirectory(this.testDir);
    return testFiles;
  }

  /**
   * Analyze file content for performance issues
   */
  analyzeFileContent(filePath, content) {
    const issues = [];
    const lines = content.split('\n');
    
    lines.forEach((line, index) => {
      this.slowPatterns.forEach(pattern => {
        const match = line.match(pattern);
        if (match) {
          const delay = parseInt(match[1]);
          if (delay > 100) { // Flag delays over 100ms
            issues.push({
              file: path.relative(this.testDir, filePath),
              line: index + 1,
              issue: 'Long delay found',
              delay: delay,
              suggestion: `Reduce delay from ${delay}ms to ${Math.min(delay, 50)}ms`,
              original: line.trim(),
              optimized: this.optimizeLine(line, delay)
            });
          }
        }
      });
      
      // Check for potential infinite loops or blocking operations
      if (line.includes('while (true)') || line.includes('for (;;)')) {
        issues.push({
          file: path.relative(this.testDir, filePath),
          line: index + 1,
          issue: 'Potential infinite loop',
          suggestion: 'Add timeout or exit condition',
          original: line.trim()
        });
      }
    });
    
    return issues;
  }

  /**
   * Optimize a line with long delays
   */
  optimizeLine(line, originalDelay) {
    const optimizedDelay = Math.min(originalDelay, 50);
    return line.replace(originalDelay.toString(), optimizedDelay.toString());
  }

  /**
   * Generate performance report
   */
  generateReport(issues) {
    console.log('📊 TEST PERFORMANCE ANALYSIS REPORT\n');
    console.log('=' .repeat(60));
    
    if (issues.length === 0) {
      console.log('✅ No performance issues detected!');
      return;
    }

    // Group issues by file
    const issuesByFile = issues.reduce((acc, issue) => {
      if (!acc[issue.file]) acc[issue.file] = [];
      acc[issue.file].push(issue);
      return acc;
    }, {});

    // Summary
    console.log(`\n📈 SUMMARY:`);
    console.log(`   Files with issues: ${Object.keys(issuesByFile).length}`);
    console.log(`   Total issues found: ${issues.length}`);
    console.log(`   Average delay reduction: ${this.calculateAverageReduction(issues)}ms\n`);

    // Detailed issues by file
    Object.entries(issuesByFile).forEach(([file, fileIssues]) => {
      console.log(`📄 ${file}`);
      console.log('-'.repeat(file.length + 3));
      
      fileIssues.forEach(issue => {
        console.log(`   Line ${issue.line}: ${issue.issue}`);
        if (issue.delay) {
          console.log(`   Current: ${issue.original}`);
          console.log(`   Optimized: ${issue.optimized}`);
          console.log(`   💡 ${issue.suggestion}`);
        }
        console.log('');
      });
    });

    // Recommendations
    this.generateRecommendations(issues);
  }

  /**
   * Calculate average delay reduction
   */
  calculateAverageReduction(issues) {
    const delayIssues = issues.filter(issue => issue.delay);
    if (delayIssues.length === 0) return 0;
    
    const totalReduction = delayIssues.reduce((sum, issue) => {
      return sum + (issue.delay - Math.min(issue.delay, 50));
    }, 0);
    
    return Math.round(totalReduction / delayIssues.length);
  }

  /**
   * Generate optimization recommendations
   */
  generateRecommendations(issues) {
    console.log('🚀 OPTIMIZATION RECOMMENDATIONS:\n');
    
    const recommendations = [
      {
        title: 'Jest Configuration',
        items: [
          'Reduce testTimeout from 30000ms to 10000ms',
          'Increase maxWorkers to 50% of CPU cores',
          'Disable coverage collection for development runs',
          'Enable test result caching'
        ]
      },
      {
        title: 'Test Delays',
        items: [
          'Replace setTimeout delays > 100ms with 10-50ms alternatives',
          'Use jest.useFakeTimers() for time-dependent tests',
          'Mock time-consuming operations instead of waiting',
          'Use Promise.resolve() for immediate async operations'
        ]
      },
      {
        title: 'Concurrent Operations',
        items: [
          'Limit concurrent test operations to 3-5 for unit tests',
          'Use batching for multiple operations',
          'Sample large datasets instead of processing all items',
          'Use test doubles for expensive operations'
        ]
      },
      {
        title: 'Resource Management',
        items: [
          'Clean up resources in afterEach hooks',
          'Use lightweight test fixtures',
          'Avoid creating large objects in test setup',
          'Use shallow rendering for component tests'
        ]
      }
    ];

    recommendations.forEach(section => {
      console.log(`📋 ${section.title}:`);
      section.items.forEach(item => {
        console.log(`   • ${item}`);
      });
      console.log('');
    });
  }

  /**
   * Apply automatic optimizations to files
   */
  applyOptimizations(issues) {
    console.log('🔧 Applying automatic optimizations...\n');
    
    const fileGroups = issues.reduce((acc, issue) => {
      if (!acc[issue.file] && issue.optimized) {
        acc[issue.file] = [];
      }
      if (issue.optimized) {
        acc[issue.file].push(issue);
      }
      return acc;
    }, {});

    Object.entries(fileGroups).forEach(([file, fileIssues]) => {
      const fullPath = path.join(this.testDir, file);
      let content = fs.readFileSync(fullPath, 'utf8');
      
      fileIssues.forEach(issue => {
        content = content.replace(issue.original, issue.optimized);
      });
      
      // Create backup
      const backupPath = fullPath + '.backup.' + Date.now();
      fs.writeFileSync(backupPath, fs.readFileSync(fullPath));
      
      // Apply optimizations
      fs.writeFileSync(fullPath, content);
      
      console.log(`✅ Optimized ${file} (backup: ${path.basename(backupPath)})`);
    });
  }

  /**
   * Run performance benchmarks
   */
  benchmarkTests() {
    console.log('⏱️  Running test performance benchmark...\n');
    
    try {
      const startTime = Date.now();
      
      // Run a subset of fast tests for benchmarking
      const result = execSync('npm test -- --testNamePattern="should.*efficiently|should.*fast" --maxWorkers=1 --verbose=false', 
        { cwd: path.dirname(this.testDir), encoding: 'utf8', timeout: 30000 });
      
      const endTime = Date.now();
      const duration = endTime - startTime;
      
      console.log(`📊 Benchmark Results:`);
      console.log(`   Total duration: ${duration}ms`);
      console.log(`   Average per test: ~${Math.round(duration / 10)}ms (estimated)`);
      
      if (duration < 5000) {
        console.log('   ✅ Performance: Excellent');
      } else if (duration < 10000) {
        console.log('   ⚠️  Performance: Good');
      } else {
        console.log('   ❌ Performance: Needs improvement');
      }
      
    } catch (error) {
      console.log('❌ Benchmark failed:', error.message);
    }
  }
}

// Main execution
async function main() {
  const optimizer = new TestPerformanceOptimizer();
  
  console.log('🚀 TEST PERFORMANCE OPTIMIZER\n');
  
  // Scan for issues
  const issues = optimizer.scanTestFiles();
  
  // Generate report
  optimizer.generateReport(issues);
  
  // Ask for optimization
  if (issues.length > 0) {
    console.log('Would you like to apply automatic optimizations? (This will create backups)');
    console.log('To apply optimizations, run: node scripts/optimize-test-performance.js --apply\n');
    
    if (process.argv.includes('--apply')) {
      optimizer.applyOptimizations(issues);
    }
  }
  
  // Run benchmark if requested
  if (process.argv.includes('--benchmark')) {
    optimizer.benchmarkTests();
  }
  
  console.log('\n✨ Analysis complete!');
  console.log('💡 Run with --apply to auto-fix issues');
  console.log('📊 Run with --benchmark to measure test performance');
}

// Run if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(console.error);
}

export default TestPerformanceOptimizer;