#!/usr/bin/env node

/**
 * Advanced coverage reporting script
 * Generates comprehensive coverage reports, badges, and dashboard data
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';

class CoverageReporter {
  constructor() {
    this.coveragePath = 'coverage/coverage-summary.json';
    this.lcovPath = 'coverage/lcov.info';
    this.reportsDir = 'coverage/reports';
    this.badgesDir = 'coverage/badges';
    
    // Ensure directories exist
    this.ensureDirectories();
  }

  ensureDirectories() {
    [this.reportsDir, this.badgesDir].forEach(dir => {
      if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true });
      }
    });
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
   * Generate coverage badge data
   */
  generateBadges(coverage) {
    const badges = {};
    const total = coverage.total;

    // Generate badges for each metric
    const metrics = [
      { key: 'lines', label: 'Lines', color: this.getBadgeColor(total.lines.pct) },
      { key: 'statements', label: 'Statements', color: this.getBadgeColor(total.statements.pct) },
      { key: 'functions', label: 'Functions', color: this.getBadgeColor(total.functions.pct) },
      { key: 'branches', label: 'Branches', color: this.getBadgeColor(total.branches.pct) }
    ];

    for (const metric of metrics) {
      const pct = total[metric.key].pct;
      badges[metric.key] = {
        schemaVersion: 1,
        label: `Coverage - ${metric.label}`,
        message: `${pct.toFixed(1)}%`,
        color: metric.color,
        style: 'flat'
      };
    }

    // Overall coverage badge
    const overallPct = this.calculateOverallCoverage(total);
    badges.overall = {
      schemaVersion: 1,
      label: 'Coverage',
      message: `${overallPct.toFixed(1)}%`,
      color: this.getBadgeColor(overallPct),
      style: 'flat'
    };

    return badges;
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
   * Get badge color based on coverage percentage
   */
  getBadgeColor(percentage) {
    if (percentage >= 90) return 'brightgreen';
    if (percentage >= 80) return 'green';
    if (percentage >= 70) return 'yellowgreen';
    if (percentage >= 60) return 'yellow';
    if (percentage >= 50) return 'orange';
    return 'red';
  }

  /**
   * Generate detailed HTML report
   */
  generateHTMLReport(coverage) {
    const total = coverage.total;
    const overallPct = this.calculateOverallCoverage(total);
    
    const html = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Coverage Report - Make.com FastMCP Server</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f8f9fa;
        }
        .header {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 30px;
            text-align: center;
        }
        .title {
            color: #2c3e50;
            margin: 0 0 10px 0;
            font-size: 2.5rem;
        }
        .subtitle {
            color: #7f8c8d;
            margin: 0;
            font-size: 1.2rem;
        }
        .overview {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .metric-card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.2s;
        }
        .metric-card:hover {
            transform: translateY(-2px);
        }
        .metric-title {
            font-size: 1.1rem;
            color: #34495e;
            margin: 0 0 15px 0;
            font-weight: 600;
        }
        .metric-value {
            font-size: 3rem;
            font-weight: bold;
            margin: 0 0 10px 0;
        }
        .metric-fraction {
            color: #7f8c8d;
            font-size: 1rem;
        }
        .excellent { color: #27ae60; }
        .good { color: #2ecc71; }
        .fair { color: #f39c12; }
        .poor { color: #e74c3c; }
        .details {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .details h2 {
            color: #2c3e50;
            border-bottom: 2px solid #ecf0f1;
            padding-bottom: 10px;
        }
        .timestamp {
            text-align: center;
            color: #7f8c8d;
            font-size: 0.9rem;
            margin-top: 30px;
        }
        .progress-bar {
            background: #ecf0f1;
            border-radius: 10px;
            height: 8px;
            margin: 10px 0;
            overflow: hidden;
        }
        .progress-fill {
            height: 100%;
            border-radius: 10px;
            transition: width 0.3s ease;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1 class="title">📊 Coverage Report</h1>
        <p class="subtitle">Make.com FastMCP Server - Test Coverage Analysis</p>
    </div>

    <div class="overview">
        <div class="metric-card">
            <h3 class="metric-title">📏 Lines</h3>
            <div class="metric-value ${this.getCoverageClass(total.lines.pct)}">${total.lines.pct.toFixed(1)}%</div>
            <div class="metric-fraction">${total.lines.covered} / ${total.lines.total}</div>
            <div class="progress-bar">
                <div class="progress-fill ${this.getCoverageClass(total.lines.pct)}" style="width: ${total.lines.pct}%; background: ${this.getProgressColor(total.lines.pct)};"></div>
            </div>
        </div>

        <div class="metric-card">
            <h3 class="metric-title">📝 Statements</h3>
            <div class="metric-value ${this.getCoverageClass(total.statements.pct)}">${total.statements.pct.toFixed(1)}%</div>
            <div class="metric-fraction">${total.statements.covered} / ${total.statements.total}</div>
            <div class="progress-bar">
                <div class="progress-fill" style="width: ${total.statements.pct}%; background: ${this.getProgressColor(total.statements.pct)};"></div>
            </div>
        </div>

        <div class="metric-card">
            <h3 class="metric-title">🔧 Functions</h3>
            <div class="metric-value ${this.getCoverageClass(total.functions.pct)}">${total.functions.pct.toFixed(1)}%</div>
            <div class="metric-fraction">${total.functions.covered} / ${total.functions.total}</div>
            <div class="progress-bar">
                <div class="progress-fill" style="width: ${total.functions.pct}%; background: ${this.getProgressColor(total.functions.pct)};"></div>
            </div>
        </div>

        <div class="metric-card">
            <h3 class="metric-title">🌿 Branches</h3>
            <div class="metric-value ${this.getCoverageClass(total.branches.pct)}">${total.branches.pct.toFixed(1)}%</div>
            <div class="metric-fraction">${total.branches.covered} / ${total.branches.total}</div>
            <div class="progress-bar">
                <div class="progress-fill" style="width: ${total.branches.pct}%; background: ${this.getProgressColor(total.branches.pct)};"></div>
            </div>
        </div>
    </div>

    <div class="details">
        <h2>📈 Overall Coverage: ${overallPct.toFixed(1)}%</h2>
        <p>This report shows the comprehensive test coverage for the Make.com FastMCP Server project. 
        The coverage analysis includes all source files and provides detailed metrics for lines, statements, 
        functions, and branches.</p>
        
        <h3>🎯 Coverage Thresholds</h3>
        <ul>
            <li><strong>Excellent (90%+):</strong> <span class="excellent">●</span> High-quality coverage</li>
            <li><strong>Good (80-89%):</strong> <span class="good">●</span> Acceptable coverage</li>
            <li><strong>Fair (70-79%):</strong> <span class="fair">●</span> Needs improvement</li>
            <li><strong>Poor (&lt;70%):</strong> <span class="poor">●</span> Requires attention</li>
        </ul>
        
        <h3>📁 Detailed Coverage</h3>
        <p>For detailed file-by-file coverage analysis, please refer to the full HTML coverage report 
        generated by Jest at <code>coverage/lcov-report/index.html</code>.</p>
    </div>

    <div class="timestamp">
        Generated on ${new Date().toLocaleString()} • Make.com FastMCP Server
    </div>
</body>
</html>`;

    return html;
  }

  getCoverageClass(percentage) {
    if (percentage >= 90) return 'excellent';
    if (percentage >= 80) return 'good';
    if (percentage >= 70) return 'fair';
    return 'poor';
  }

  getProgressColor(percentage) {
    if (percentage >= 90) return '#27ae60';
    if (percentage >= 80) return '#2ecc71';
    if (percentage >= 70) return '#f39c12';
    return '#e74c3c';
  }

  /**
   * Generate JSON report for CI/CD integration
   */
  generateJSONReport(coverage) {
    const total = coverage.total;
    const overallPct = this.calculateOverallCoverage(total);
    
    return {
      timestamp: new Date().toISOString(),
      project: 'make.com-fastmcp-server',
      overall: {
        percentage: Math.round(overallPct * 100) / 100,
        grade: this.getCoverageGrade(overallPct)
      },
      metrics: {
        lines: {
          percentage: total.lines.pct,
          covered: total.lines.covered,
          total: total.lines.total,
          grade: this.getCoverageGrade(total.lines.pct)
        },
        statements: {
          percentage: total.statements.pct,
          covered: total.statements.covered,
          total: total.statements.total,
          grade: this.getCoverageGrade(total.statements.pct)
        },
        functions: {
          percentage: total.functions.pct,
          covered: total.functions.covered,
          total: total.functions.total,
          grade: this.getCoverageGrade(total.functions.pct)
        },
        branches: {
          percentage: total.branches.pct,
          covered: total.branches.covered,
          total: total.branches.total,
          grade: this.getCoverageGrade(total.branches.pct)
        }
      },
      files: Object.keys(coverage).filter(key => key !== 'total').length,
      badges: this.generateBadges(coverage)
    };
  }

  getCoverageGrade(percentage) {
    if (percentage >= 90) return 'A';
    if (percentage >= 80) return 'B';
    if (percentage >= 70) return 'C';
    if (percentage >= 60) return 'D';
    return 'F';
  }

  /**
   * Generate README badge markdown
   */
  generateBadgeMarkdown(badges) {
    const markdown = `
<!-- Coverage Badges - Auto-generated -->
![Coverage](https://img.shields.io/badge/Coverage-${badges.overall.message}-${badges.overall.color})
![Lines](https://img.shields.io/badge/Lines-${badges.lines.message}-${badges.lines.color})
![Statements](https://img.shields.io/badge/Statements-${badges.statements.message}-${badges.statements.color})
![Functions](https://img.shields.io/badge/Functions-${badges.functions.message}-${badges.functions.color})
![Branches](https://img.shields.io/badge/Branches-${badges.branches.message}-${badges.branches.color})
`;
    return markdown.trim();
  }

  /**
   * Run coverage reporting
   */
  async run(options = {}) {
    const { format = 'all', output = true } = options;

    try {
      console.log('📊 Generating coverage reports...\n');

      const coverage = this.loadCoverageSummary();
      const reports = {};

      // Generate badges
      if (format === 'all' || format === 'badges') {
        const badges = this.generateBadges(coverage);
        reports.badges = badges;
        
        // Save individual badge files
        for (const [key, badge] of Object.entries(badges)) {
          const badgePath = join(this.badgesDir, `${key}.json`);
          writeFileSync(badgePath, JSON.stringify(badge, null, 2));
        }
        
        console.log('✅ Generated coverage badges');
      }

      // Generate HTML report
      if (format === 'all' || format === 'html') {
        const html = this.generateHTMLReport(coverage);
        const htmlPath = join(this.reportsDir, 'coverage-dashboard.html');
        writeFileSync(htmlPath, html);
        reports.html = htmlPath;
        
        console.log('✅ Generated HTML coverage dashboard');
      }

      // Generate JSON report
      if (format === 'all' || format === 'json') {
        const json = this.generateJSONReport(coverage);
        const jsonPath = join(this.reportsDir, 'coverage-summary.json');
        writeFileSync(jsonPath, JSON.stringify(json, null, 2));
        reports.json = json;
        
        console.log('✅ Generated JSON coverage report');
      }

      // Generate badge markdown
      if (format === 'all' || format === 'markdown') {
        const badges = reports.badges || this.generateBadges(coverage);
        const markdown = this.generateBadgeMarkdown(badges);
        const markdownPath = join(this.reportsDir, 'badges.md');
        writeFileSync(markdownPath, markdown);
        reports.markdown = markdown;
        
        console.log('✅ Generated badge markdown');
      }

      if (output) {
        console.log('\n📁 Report files generated in:', this.reportsDir);
        console.log('🎯 Badge files generated in:', this.badgesDir);
        console.log('\n🎉 Coverage reporting completed successfully!');
      }

      return reports;
    } catch (error) {
      console.error(`💥 Coverage reporting failed: ${error.message}`);
      throw error;
    }
  }
}

// Parse command line arguments
const args = process.argv.slice(2);
const format = args.find(arg => ['badges', 'html', 'json', 'markdown', 'all'].includes(arg)) || 'all';

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const reporter = new CoverageReporter();
  reporter.run({ format });
}

export default CoverageReporter;