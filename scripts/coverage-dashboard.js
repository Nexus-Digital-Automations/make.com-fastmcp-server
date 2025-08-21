#!/usr/bin/env node

/**
 * Coverage dashboard and quality gates implementation
 * Creates interactive coverage dashboard with quality assessment and deployment validation
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';

class CoverageDashboard {
  constructor() {
    this.coveragePath = 'coverage/coverage-summary.json';
    this.reportsDir = 'coverage/reports';
    this.dashboardDir = 'docs/coverage-dashboard';
    this.qualityGatesConfig = this.loadQualityGatesConfig();
    
    // Ensure directories exist
    this.ensureDirectories();
  }

  ensureDirectories() {
    [this.reportsDir, this.dashboardDir].forEach(dir => {
      if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true });
      }
    });
  }

  /**
   * Load quality gates configuration
   */
  loadQualityGatesConfig() {
    try {
      const jestConfig = require('../jest.config.js');
      const thresholds = jestConfig.default?.coverageThreshold || jestConfig.coverageThreshold || {};
      
      return {
        global: thresholds.global || { branches: 80, functions: 80, lines: 80, statements: 80 },
        lib: thresholds['./src/lib/'] || { branches: 90, functions: 90, lines: 90, statements: 90 },
        utils: thresholds['./src/utils/'] || { branches: 85, functions: 85, lines: 85, statements: 85 },
        deployment: {
          minimum: { branches: 70, functions: 70, lines: 70, statements: 70 },
          recommended: { branches: 85, functions: 85, lines: 85, statements: 85 },
          excellent: { branches: 95, functions: 95, lines: 95, statements: 95 }
        }
      };
    } catch (error) {
      console.warn('⚠️ Could not load quality gates config, using defaults');
      return {
        global: { branches: 80, functions: 80, lines: 80, statements: 80 },
        lib: { branches: 90, functions: 90, lines: 90, statements: 90 },
        utils: { branches: 85, functions: 85, lines: 85, statements: 85 },
        deployment: {
          minimum: { branches: 70, functions: 70, lines: 70, statements: 70 },
          recommended: { branches: 85, functions: 85, lines: 85, statements: 85 },
          excellent: { branches: 95, functions: 95, lines: 95, statements: 95 }
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
      return JSON.parse(readFileSync(this.coveragePath, 'utf8'));
    } catch (error) {
      throw new Error(`❌ Failed to parse coverage summary: ${error.message}`);
    }
  }

  /**
   * Calculate overall coverage percentage
   */
  calculateOverallCoverage(total) {
    const metrics = ['lines', 'statements', 'functions', 'branches'];
    const sum = metrics.reduce((acc, metric) => acc + total[metric].pct, 0);
    return sum / metrics.length;
  }

  /**
   * Assess coverage quality based on thresholds
   */
  assessCoverageQuality(coverage) {
    const total = coverage.total;
    const overallPct = this.calculateOverallCoverage(total);
    
    const assessment = {
      overall: {
        percentage: overallPct,
        grade: this.calculateGrade(overallPct),
        status: this.calculateStatus(overallPct)
      },
      metrics: {},
      qualityGates: {},
      deploymentReadiness: this.assessDeploymentReadiness(total)
    };

    // Assess individual metrics
    const metrics = ['lines', 'statements', 'functions', 'branches'];
    for (const metric of metrics) {
      const pct = total[metric].pct;
      assessment.metrics[metric] = {
        percentage: pct,
        covered: total[metric].covered,
        total: total[metric].total,
        grade: this.calculateGrade(pct),
        status: this.calculateStatus(pct),
        meetsGlobal: pct >= this.qualityGatesConfig.global[metric]
      };
    }

    // Assess quality gates
    assessment.qualityGates = {
      global: this.assessQualityGate(total, this.qualityGatesConfig.global, 'Global'),
      lib: this.assessPathCoverage(coverage, './src/lib/', this.qualityGatesConfig.lib, 'Core Libraries'),
      utils: this.assessPathCoverage(coverage, './src/utils/', this.qualityGatesConfig.utils, 'Utilities')
    };

    return assessment;
  }

  /**
   * Assess quality gate for specific thresholds
   */
  assessQualityGate(coverage, thresholds, name) {
    const violations = [];
    const metrics = ['lines', 'statements', 'functions', 'branches'];
    
    for (const metric of metrics) {
      const actual = coverage[metric]?.pct || 0;
      const required = thresholds[metric];
      
      if (actual < required) {
        violations.push({
          metric,
          actual,
          required,
          deficit: required - actual
        });
      }
    }

    return {
      name,
      passed: violations.length === 0,
      violations,
      thresholds
    };
  }

  /**
   * Assess coverage for specific path
   */
  assessPathCoverage(coverage, path, thresholds, name) {
    // Find matching files for the path
    const matchingKeys = Object.keys(coverage).filter(key => 
      key !== 'total' && (key.startsWith(path.replace('./', '')) || key.includes(path))
    );

    if (matchingKeys.length === 0) {
      return {
        name,
        passed: false,
        violations: [{ metric: 'coverage', actual: 0, required: 80, deficit: 80 }],
        thresholds,
        note: 'No files found for path'
      };
    }

    // Aggregate coverage for matching files
    const aggregated = this.aggregateCoverage(coverage, matchingKeys);
    return this.assessQualityGate(aggregated, thresholds, name);
  }

  /**
   * Aggregate coverage data from multiple files
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
   * Assess deployment readiness
   */
  assessDeploymentReadiness(total) {
    const deployment = this.qualityGatesConfig.deployment;
    const overallPct = this.calculateOverallCoverage(total);
    
    let readiness = 'blocked';
    let level = 'minimum';
    let color = '#e05d44';
    
    if (this.meetsThresholds(total, deployment.excellent)) {
      readiness = 'excellent';
      level = 'excellent';
      color = '#4c1';
    } else if (this.meetsThresholds(total, deployment.recommended)) {
      readiness = 'ready';
      level = 'recommended';
      color = '#97ca00';
    } else if (this.meetsThresholds(total, deployment.minimum)) {
      readiness = 'conditional';
      level = 'minimum';
      color = '#dfb317';
    }

    return {
      status: readiness,
      level,
      color,
      percentage: overallPct,
      thresholds: deployment[level],
      canDeploy: readiness !== 'blocked',
      recommendations: this.generateDeploymentRecommendations(total, deployment)
    };
  }

  /**
   * Check if coverage meets thresholds
   */
  meetsThresholds(coverage, thresholds) {
    const metrics = ['lines', 'statements', 'functions', 'branches'];
    return metrics.every(metric => 
      (coverage[metric]?.pct || 0) >= thresholds[metric]
    );
  }

  /**
   * Generate deployment recommendations
   */
  generateDeploymentRecommendations(total, thresholds) {
    const recommendations = [];
    const metrics = ['lines', 'statements', 'functions', 'branches'];
    
    for (const metric of metrics) {
      const actual = total[metric]?.pct || 0;
      const minimum = thresholds.minimum[metric];
      const recommended = thresholds.recommended[metric];
      const excellent = thresholds.excellent[metric];
      
      if (actual < minimum) {
        recommendations.push({
          type: 'critical',
          metric,
          message: `${metric} coverage (${actual.toFixed(1)}%) is below minimum deployment threshold (${minimum}%)`,
          target: minimum,
          priority: 'high'
        });
      } else if (actual < recommended) {
        recommendations.push({
          type: 'improvement',
          metric,
          message: `${metric} coverage (${actual.toFixed(1)}%) could be improved to meet recommended threshold (${recommended}%)`,
          target: recommended,
          priority: 'medium'
        });
      } else if (actual < excellent) {
        recommendations.push({
          type: 'optimization',
          metric,
          message: `${metric} coverage (${actual.toFixed(1)}%) is good but could reach excellent level (${excellent}%)`,
          target: excellent,
          priority: 'low'
        });
      }
    }

    return recommendations;
  }

  /**
   * Calculate letter grade based on percentage
   */
  calculateGrade(percentage) {
    if (percentage >= 95) return 'A+';
    if (percentage >= 90) return 'A';
    if (percentage >= 85) return 'B+';
    if (percentage >= 80) return 'B';
    if (percentage >= 75) return 'C+';
    if (percentage >= 70) return 'C';
    if (percentage >= 65) return 'D+';
    if (percentage >= 60) return 'D';
    return 'F';
  }

  /**
   * Calculate status based on percentage
   */
  calculateStatus(percentage) {
    if (percentage >= 90) return 'excellent';
    if (percentage >= 80) return 'good';
    if (percentage >= 70) return 'fair';
    if (percentage >= 60) return 'poor';
    return 'critical';
  }

  /**
   * Generate interactive HTML dashboard
   */
  generateInteractiveDashboard(assessment) {
    const { overall, metrics, qualityGates, deploymentReadiness } = assessment;
    
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Coverage Dashboard - Make.com FastMCP Server</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: rgba(255, 255, 255, 0.95);
            padding: 40px;
            border-radius: 20px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            margin-bottom: 30px;
            text-align: center;
            backdrop-filter: blur(10px);
        }
        
        .title {
            font-size: 3rem;
            color: #2c3e50;
            margin-bottom: 10px;
            font-weight: 700;
        }
        
        .subtitle {
            color: #7f8c8d;
            font-size: 1.2rem;
        }
        
        .overall-score {
            background: rgba(255, 255, 255, 0.95);
            padding: 40px;
            border-radius: 20px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            margin-bottom: 30px;
            text-align: center;
            backdrop-filter: blur(10px);
        }
        
        .score-circle {
            width: 200px;
            height: 200px;
            border-radius: 50%;
            margin: 0 auto 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 3rem;
            font-weight: bold;
            color: white;
            background: conic-gradient(from 0deg, ${this.getScoreColor(overall.percentage)} ${overall.percentage * 3.6}deg, #e0e0e0 ${overall.percentage * 3.6}deg);
            position: relative;
        }
        
        .score-circle::before {
            content: '';
            width: 160px;
            height: 160px;
            border-radius: 50%;
            background: white;
            position: absolute;
        }
        
        .score-text {
            position: relative;
            z-index: 1;
            color: #2c3e50;
        }
        
        .grade {
            font-size: 2rem;
            font-weight: bold;
            color: ${this.getGradeColor(overall.grade)};
            margin-top: 10px;
        }
        
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .metric-card {
            background: rgba(255, 255, 255, 0.95);
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
            backdrop-filter: blur(10px);
            transition: transform 0.3s ease;
        }
        
        .metric-card:hover {
            transform: translateY(-5px);
        }
        
        .metric-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        
        .metric-title {
            font-size: 1.3rem;
            color: #2c3e50;
            font-weight: 600;
        }
        
        .metric-percentage {
            font-size: 2rem;
            font-weight: bold;
            color: ${this.getStatusColor('excellent')};
        }
        
        .progress-bar {
            height: 12px;
            background: #e0e0e0;
            border-radius: 6px;
            overflow: hidden;
            margin: 15px 0;
        }
        
        .progress-fill {
            height: 100%;
            border-radius: 6px;
            transition: width 0.8s ease;
        }
        
        .metric-details {
            color: #666;
            font-size: 0.9rem;
        }
        
        .quality-gates {
            background: rgba(255, 255, 255, 0.95);
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
            margin-bottom: 30px;
            backdrop-filter: blur(10px);
        }
        
        .quality-gate {
            border: 2px solid;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 15px;
        }
        
        .gate-passed {
            border-color: #27ae60;
            background: rgba(39, 174, 96, 0.1);
        }
        
        .gate-failed {
            border-color: #e74c3c;
            background: rgba(231, 76, 60, 0.1);
        }
        
        .deployment-readiness {
            background: rgba(255, 255, 255, 0.95);
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
            backdrop-filter: blur(10px);
        }
        
        .deployment-status {
            text-align: center;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            font-size: 1.2rem;
            font-weight: bold;
        }
        
        .status-excellent { background: rgba(39, 174, 96, 0.2); color: #27ae60; }
        .status-ready { background: rgba(46, 204, 113, 0.2); color: #2ecc71; }
        .status-conditional { background: rgba(243, 156, 18, 0.2); color: #f39c12; }
        .status-blocked { background: rgba(231, 76, 60, 0.2); color: #e74c3c; }
        
        .recommendations {
            list-style: none;
        }
        
        .recommendation {
            padding: 10px;
            margin: 10px 0;
            border-left: 4px solid;
            border-radius: 0 5px 5px 0;
        }
        
        .rec-critical { border-color: #e74c3c; background: rgba(231, 76, 60, 0.1); }
        .rec-improvement { border-color: #f39c12; background: rgba(243, 156, 18, 0.1); }
        .rec-optimization { border-color: #3498db; background: rgba(52, 152, 219, 0.1); }
        
        .timestamp {
            text-align: center;
            color: rgba(255, 255, 255, 0.8);
            margin-top: 30px;
            font-size: 0.9rem;
        }
        
        @media (max-width: 768px) {
            .container { padding: 10px; }
            .title { font-size: 2rem; }
            .score-circle { width: 150px; height: 150px; font-size: 2rem; }
            .metrics-grid { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1 class="title">📊 Coverage Dashboard</h1>
            <p class="subtitle">Make.com FastMCP Server - Comprehensive Test Coverage Analysis</p>
        </div>

        <div class="overall-score">
            <div class="score-circle">
                <div class="score-text">${overall.percentage.toFixed(1)}%</div>
            </div>
            <div class="grade">Grade: ${overall.grade}</div>
            <p>Overall Test Coverage</p>
        </div>

        <div class="metrics-grid">
            ${Object.entries(metrics).map(([metric, data]) => `
                <div class="metric-card">
                    <div class="metric-header">
                        <h3 class="metric-title">${this.getMetricIcon(metric)} ${this.capitalize(metric)}</h3>
                        <div class="metric-percentage" style="color: ${this.getStatusColor(data.status)}">${data.percentage.toFixed(1)}%</div>
                    </div>
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: ${data.percentage}%; background: ${this.getStatusColor(data.status)};"></div>
                    </div>
                    <div class="metric-details">
                        ${data.covered} / ${data.total} • Grade: ${data.grade} • ${data.meetsGlobal ? '✅' : '❌'} Global threshold
                    </div>
                </div>
            `).join('')}
        </div>

        <div class="quality-gates">
            <h2>🚦 Quality Gates</h2>
            ${Object.entries(qualityGates).map(([key, gate]) => `
                <div class="quality-gate ${gate.passed ? 'gate-passed' : 'gate-failed'}">
                    <h3>${gate.passed ? '✅' : '❌'} ${gate.name}</h3>
                    ${gate.violations.length > 0 ? `
                        <ul>
                            ${gate.violations.map(v => `
                                <li>${v.metric}: ${v.actual.toFixed(1)}% (required: ${v.required}%, deficit: ${v.deficit.toFixed(1)}%)</li>
                            `).join('')}
                        </ul>
                    ` : '<p>All thresholds met!</p>'}
                </div>
            `).join('')}
        </div>

        <div class="deployment-readiness">
            <h2>🚀 Deployment Readiness</h2>
            <div class="deployment-status status-${deploymentReadiness.status}">
                ${this.getDeploymentIcon(deploymentReadiness.status)} ${this.getDeploymentMessage(deploymentReadiness)}
            </div>
            
            ${deploymentReadiness.recommendations.length > 0 ? `
                <h3>📋 Recommendations</h3>
                <ul class="recommendations">
                    ${deploymentReadiness.recommendations.map(rec => `
                        <li class="recommendation rec-${rec.type}">
                            <strong>${rec.type.toUpperCase()}:</strong> ${rec.message}
                        </li>
                    `).join('')}
                </ul>
            ` : '<p>No recommendations - excellent coverage!</p>'}
        </div>

        <div class="timestamp">
            Generated on ${new Date().toLocaleString()} • Make.com FastMCP Server Coverage Dashboard
        </div>
    </div>

    <script>
        // Add interactive features
        document.addEventListener('DOMContentLoaded', function() {
            // Animate progress bars
            const progressBars = document.querySelectorAll('.progress-fill');
            progressBars.forEach(bar => {
                const width = bar.style.width;
                bar.style.width = '0%';
                setTimeout(() => {
                    bar.style.width = width;
                }, 100);
            });
            
            // Add tooltips to metric cards
            const metricCards = document.querySelectorAll('.metric-card');
            metricCards.forEach(card => {
                card.addEventListener('mouseenter', function() {
                    this.style.boxShadow = '0 15px 40px rgba(0,0,0,0.2)';
                });
                card.addEventListener('mouseleave', function() {
                    this.style.boxShadow = '0 5px 20px rgba(0,0,0,0.1)';
                });
            });
        });
    </script>
</body>
</html>`;
  }

  getScoreColor(percentage) {
    if (percentage >= 90) return '#27ae60';
    if (percentage >= 80) return '#2ecc71';
    if (percentage >= 70) return '#f39c12';
    return '#e74c3c';
  }

  getGradeColor(grade) {
    if (grade.startsWith('A')) return '#27ae60';
    if (grade.startsWith('B')) return '#2ecc71';
    if (grade.startsWith('C')) return '#f39c12';
    return '#e74c3c';
  }

  getStatusColor(status) {
    const colors = {
      excellent: '#27ae60',
      good: '#2ecc71',
      fair: '#f39c12',
      poor: '#e67e22',
      critical: '#e74c3c'
    };
    return colors[status] || '#95a5a6';
  }

  getMetricIcon(metric) {
    const icons = {
      lines: '📏',
      statements: '📝',
      functions: '🔧',
      branches: '🌿'
    };
    return icons[metric] || '📊';
  }

  getDeploymentIcon(status) {
    const icons = {
      excellent: '🎉',
      ready: '✅',
      conditional: '⚠️',
      blocked: '🚫'
    };
    return icons[status] || '❓';
  }

  getDeploymentMessage(readiness) {
    const messages = {
      excellent: `Excellent coverage (${readiness.percentage.toFixed(1)}%) - Ready for production deployment`,
      ready: `Good coverage (${readiness.percentage.toFixed(1)}%) - Ready for deployment`,
      conditional: `Conditional deployment (${readiness.percentage.toFixed(1)}%) - Consider improving coverage`,
      blocked: `Deployment blocked (${readiness.percentage.toFixed(1)}%) - Coverage below minimum thresholds`
    };
    return messages[readiness.status] || 'Unknown status';
  }

  capitalize(str) {
    return str.charAt(0).toUpperCase() + str.slice(1);
  }

  /**
   * Generate quality gates report for CI/CD
   */
  generateQualityGatesReport(assessment) {
    const { qualityGates, deploymentReadiness } = assessment;
    
    const report = {
      timestamp: new Date().toISOString(),
      project: 'make.com-fastmcp-server',
      gates: qualityGates,
      deployment: deploymentReadiness,
      summary: {
        totalGates: Object.keys(qualityGates).length,
        passedGates: Object.values(qualityGates).filter(g => g.passed).length,
        canDeploy: deploymentReadiness.canDeploy,
        overallStatus: Object.values(qualityGates).every(g => g.passed) ? 'passed' : 'failed'
      }
    };

    return report;
  }

  /**
   * Run dashboard generation
   */
  async run(options = {}) {
    const { format = 'all', output = true } = options;

    try {
      if (output) {
        console.log('📊 Generating coverage dashboard and quality gates...\n');
      }

      const coverage = this.loadCoverageSummary();
      const assessment = this.assessCoverageQuality(coverage);
      
      const results = {};

      // Generate interactive dashboard
      if (format === 'all' || format === 'dashboard') {
        const dashboard = this.generateInteractiveDashboard(assessment);
        const dashboardPath = join(this.dashboardDir, 'index.html');
        writeFileSync(dashboardPath, dashboard);
        results.dashboard = dashboardPath;
        
        if (output) {
          console.log('✅ Generated interactive dashboard');
        }
      }

      // Generate quality gates report
      if (format === 'all' || format === 'report') {
        const report = this.generateQualityGatesReport(assessment);
        const reportPath = join(this.reportsDir, 'quality-gates.json');
        writeFileSync(reportPath, JSON.stringify(report, null, 2));
        results.qualityGates = report;
        
        if (output) {
          console.log('✅ Generated quality gates report');
        }
      }

      // Generate assessment summary
      const summaryPath = join(this.reportsDir, 'coverage-assessment.json');
      writeFileSync(summaryPath, JSON.stringify(assessment, null, 2));
      results.assessment = assessment;

      if (output) {
        console.log('\n📁 Dashboard generated at:', this.dashboardDir);
        console.log('📁 Reports saved to:', this.reportsDir);
        
        console.log('\n📊 Quality Assessment:');
        console.log(`   Overall Grade: ${assessment.overall.grade} (${assessment.overall.percentage.toFixed(1)}%)`);
        console.log(`   Deployment Status: ${assessment.deploymentReadiness.status}`);
        console.log(`   Quality Gates: ${Object.values(assessment.qualityGates).filter(g => g.passed).length}/${Object.keys(assessment.qualityGates).length} passed`);
        
        if (assessment.deploymentReadiness.recommendations.length > 0) {
          console.log('\n💡 Top Recommendations:');
          assessment.deploymentReadiness.recommendations.slice(0, 3).forEach(rec => {
            console.log(`   ${rec.type.toUpperCase()}: ${rec.message.substring(0, 80)}...`);
          });
        }
        
        console.log('\n🎉 Dashboard generation completed successfully!');
      }

      return results;
    } catch (error) {
      console.error(`💥 Dashboard generation failed: ${error.message}`);
      throw error;
    }
  }
}

// Parse command line arguments
const args = process.argv.slice(2);
const options = {
  format: args.find(arg => ['dashboard', 'report', 'all'].includes(arg)) || 'all',
  output: !args.includes('--quiet')
};

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const dashboard = new CoverageDashboard();
  dashboard.run(options);
}

export default CoverageDashboard;