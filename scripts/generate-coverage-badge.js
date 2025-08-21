#!/usr/bin/env node

/**
 * Coverage badge generation script
 * Generates coverage badges in multiple formats for README and CI integration
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';

class CoverageBadgeGenerator {
  constructor() {
    this.coveragePath = 'coverage/coverage-summary.json';
    this.badgesDir = 'coverage/badges';
    this.outputDir = 'docs/badges';
    
    // Ensure directories exist
    this.ensureDirectories();
  }

  ensureDirectories() {
    [this.badgesDir, this.outputDir].forEach(dir => {
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
   * Get badge color based on coverage percentage
   */
  getBadgeColor(percentage) {
    if (percentage >= 95) return '#4c1';      // bright green
    if (percentage >= 90) return '#97ca00';   // green
    if (percentage >= 80) return '#a4a61d';   // yellow-green
    if (percentage >= 70) return '#dfb317';   // yellow
    if (percentage >= 60) return '#fe7d37';   // orange
    if (percentage >= 50) return '#e05d44';   // red-orange
    return '#e05d44';                         // red
  }

  /**
   * Get shield.io color name for API badges
   */
  getShieldColor(percentage) {
    if (percentage >= 95) return 'brightgreen';
    if (percentage >= 90) return 'green';
    if (percentage >= 80) return 'yellowgreen';
    if (percentage >= 70) return 'yellow';
    if (percentage >= 60) return 'orange';
    return 'red';
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
   * Generate SVG badge
   */
  generateSVGBadge(label, value, color) {
    const labelWidth = Math.max(label.length * 7 + 10, 50);
    const valueWidth = Math.max(value.length * 7 + 10, 40);
    const totalWidth = labelWidth + valueWidth;
    
    return `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="${totalWidth}" height="20">
  <linearGradient id="b" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="a">
    <rect width="${totalWidth}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#a)">
    <path fill="#555" d="M0 0h${labelWidth}v20H0z"/>
    <path fill="${color}" d="M${labelWidth} 0h${valueWidth}v20H${labelWidth}z"/>
    <path fill="url(#b)" d="M0 0h${totalWidth}v20H0z"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="110">
    <text x="${labelWidth / 2 * 10}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="${(label.length * 7) * 10}">${label}</text>
    <text x="${labelWidth / 2 * 10}" y="140" transform="scale(.1)" textLength="${(label.length * 7) * 10}">${label}</text>
    <text x="${(labelWidth + valueWidth / 2) * 10}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="${(value.length * 7) * 10}">${value}</text>
    <text x="${(labelWidth + valueWidth / 2) * 10}" y="140" transform="scale(.1)" textLength="${(value.length * 7) * 10}">${value}</text>
  </g>
</svg>`;
  }

  /**
   * Generate Shields.io badge JSON
   */
  generateShieldsBadge(label, message, color, style = 'flat') {
    return {
      schemaVersion: 1,
      label: label,
      message: message,
      color: color,
      style: style,
      namedLogo: 'jest',
      logoColor: 'white'
    };
  }

  /**
   * Generate GitHub-style badge JSON
   */
  generateGitHubBadge(label, message, color) {
    return {
      label: label,
      message: message,
      color: color,
      style: 'for-the-badge',
      logo: 'jest',
      logoColor: 'white'
    };
  }

  /**
   * Generate all badge formats
   */
  generateAllBadges(coverage) {
    const total = coverage.total;
    const overallPct = this.calculateOverallCoverage(total);
    
    const badges = {
      overall: this.createBadgeSet('Coverage', `${overallPct.toFixed(1)}%`, overallPct),
      lines: this.createBadgeSet('Lines', `${total.lines.pct.toFixed(1)}%`, total.lines.pct),
      statements: this.createBadgeSet('Statements', `${total.statements.pct.toFixed(1)}%`, total.statements.pct),
      functions: this.createBadgeSet('Functions', `${total.functions.pct.toFixed(1)}%`, total.functions.pct),
      branches: this.createBadgeSet('Branches', `${total.branches.pct.toFixed(1)}%`, total.branches.pct)
    };

    return badges;
  }

  /**
   * Create complete badge set for a metric
   */
  createBadgeSet(label, message, percentage) {
    const color = this.getBadgeColor(percentage);
    const shieldColor = this.getShieldColor(percentage);
    
    return {
      svg: this.generateSVGBadge(label, message, color),
      shields: this.generateShieldsBadge(label, message, shieldColor),
      github: this.generateGitHubBadge(label, message, shieldColor),
      url: `https://img.shields.io/badge/${encodeURIComponent(label)}-${encodeURIComponent(message)}-${shieldColor}`,
      markdown: `![${label}](https://img.shields.io/badge/${encodeURIComponent(label)}-${encodeURIComponent(message)}-${shieldColor})`,
      html: `<img src="https://img.shields.io/badge/${encodeURIComponent(label)}-${encodeURIComponent(message)}-${shieldColor}" alt="${label}">`,
      percentage: percentage,
      color: color,
      shieldColor: shieldColor
    };
  }

  /**
   * Generate README badge section
   */
  generateREADMESection(badges) {
    const badgeOrder = ['overall', 'lines', 'statements', 'functions', 'branches'];
    const markdownBadges = badgeOrder.map(key => badges[key].markdown).join('\n');
    
    return `<!-- Coverage Badges - Auto-generated by generate-coverage-badge.js -->
## 📊 Test Coverage

${markdownBadges}

*Coverage badges are automatically updated on each test run*

<!-- End Coverage Badges -->`;
  }

  /**
   * Generate HTML badge gallery
   */
  generateHTMLGallery(badges) {
    const badgeOrder = ['overall', 'lines', 'statements', 'functions', 'branches'];
    const badgeIcons = {
      overall: '📊',
      lines: '📏',
      statements: '📝',
      functions: '🔧',
      branches: '🌿'
    };
    
    const badgeCards = badgeOrder.map(key => {
      const badge = badges[key];
      const icon = badgeIcons[key];
      return `
        <div class="badge-card">
          <div class="badge-icon">${icon}</div>
          <div class="badge-content">
            <h3>${badge.shields.label}</h3>
            <div class="badge-image">${badge.html}</div>
            <div class="badge-percentage">${badge.percentage.toFixed(1)}%</div>
          </div>
        </div>`;
    }).join('');

    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Coverage Badges - Make.com FastMCP Server</title>
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
            text-align: center;
            margin-bottom: 40px;
        }
        .title {
            color: #2c3e50;
            margin-bottom: 10px;
        }
        .subtitle {
            color: #7f8c8d;
            margin: 0;
        }
        .badge-gallery {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }
        .badge-card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.2s;
        }
        .badge-card:hover {
            transform: translateY(-2px);
        }
        .badge-icon {
            font-size: 2rem;
            margin-bottom: 15px;
        }
        .badge-content h3 {
            margin: 0 0 15px 0;
            color: #34495e;
        }
        .badge-image {
            margin: 15px 0;
        }
        .badge-percentage {
            font-size: 1.5rem;
            font-weight: bold;
            color: #2c3e50;
        }
        .instructions {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .instructions h2 {
            color: #2c3e50;
            margin-top: 0;
        }
        .code-block {
            background: #f4f4f4;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Monaco', 'Courier New', monospace;
            font-size: 14px;
            margin: 10px 0;
            overflow-x: auto;
        }
        .timestamp {
            text-align: center;
            color: #7f8c8d;
            font-size: 0.9rem;
            margin-top: 30px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1 class="title">📊 Coverage Badges</h1>
        <p class="subtitle">Make.com FastMCP Server - Test Coverage Visualization</p>
    </div>

    <div class="badge-gallery">
        ${badgeCards}
    </div>

    <div class="instructions">
        <h2>🚀 Using Coverage Badges</h2>
        
        <h3>📝 Markdown (README.md)</h3>
        <div class="code-block">${badgeOrder.map(key => badges[key].markdown).join('\n')}</div>
        
        <h3>🌐 HTML</h3>
        <div class="code-block">${badgeOrder.map(key => badges[key].html).join('\n')}</div>
        
        <h3>🔗 Direct URLs</h3>
        <div class="code-block">${badgeOrder.map(key => badges[key].url).join('\n')}</div>
    </div>

    <div class="timestamp">
        Generated on ${new Date().toLocaleString()} • Make.com FastMCP Server
    </div>
</body>
</html>`;
  }

  /**
   * Save all badge files
   */
  saveBadgeFiles(badges) {
    const files = [];
    
    // Save individual badge files
    for (const [metric, badge] of Object.entries(badges)) {
      // SVG files
      const svgPath = join(this.badgesDir, `${metric}.svg`);
      writeFileSync(svgPath, badge.svg);
      files.push(svgPath);
      
      // JSON files for Shields.io
      const shieldsPath = join(this.badgesDir, `${metric}-shields.json`);
      writeFileSync(shieldsPath, JSON.stringify(badge.shields, null, 2));
      files.push(shieldsPath);
      
      // GitHub-style JSON
      const githubPath = join(this.badgesDir, `${metric}-github.json`);
      writeFileSync(githubPath, JSON.stringify(badge.github, null, 2));
      files.push(githubPath);
    }

    // Save combined files
    const allBadgesPath = join(this.badgesDir, 'all-badges.json');
    writeFileSync(allBadgesPath, JSON.stringify(badges, null, 2));
    files.push(allBadgesPath);
    
    // Save README section
    const readmePath = join(this.outputDir, 'README-badges.md');
    writeFileSync(readmePath, this.generateREADMESection(badges));
    files.push(readmePath);
    
    // Save HTML gallery
    const htmlPath = join(this.outputDir, 'badges-gallery.html');
    writeFileSync(htmlPath, this.generateHTMLGallery(badges));
    files.push(htmlPath);
    
    return files;
  }

  /**
   * Generate dynamic badge endpoint data
   */
  generateEndpointData(badges) {
    const endpoints = {};
    
    for (const [metric, badge] of Object.entries(badges)) {
      endpoints[metric] = {
        endpoint: `/badge/coverage/${metric}`,
        shields: badge.shields,
        svg: badge.svg,
        url: badge.url,
        percentage: badge.percentage
      };
    }
    
    const endpointPath = join(this.badgesDir, 'badge-endpoints.json');
    writeFileSync(endpointPath, JSON.stringify(endpoints, null, 2));
    
    return endpoints;
  }

  /**
   * Run badge generation
   */
  async run(options = {}) {
    const { format = 'all', save = true, output = true } = options;

    try {
      if (output) {
        console.log('🎯 Generating coverage badges...\n');
      }

      const coverage = this.loadCoverageSummary();
      const badges = this.generateAllBadges(coverage);
      
      let savedFiles = [];
      let endpoints = null;
      
      if (save) {
        // Save badge files
        if (format === 'all' || format === 'files') {
          savedFiles = this.saveBadgeFiles(badges);
          if (output) {
            console.log('✅ Generated badge files');
          }
        }
        
        // Generate endpoint data
        if (format === 'all' || format === 'endpoints') {
          endpoints = this.generateEndpointData(badges);
          if (output) {
            console.log('✅ Generated badge endpoints');
          }
        }
      }

      if (output) {
        console.log('\n📁 Badge files saved to:', this.badgesDir);
        console.log('📁 Documentation saved to:', this.outputDir);
        console.log('\n🎉 Badge generation completed successfully!');
        
        console.log('\n📊 Coverage Summary:');
        const overallPct = this.calculateOverallCoverage(coverage.total);
        console.log(`   Overall: ${overallPct.toFixed(1)}%`);
        console.log(`   Lines: ${coverage.total.lines.pct.toFixed(1)}%`);
        console.log(`   Statements: ${coverage.total.statements.pct.toFixed(1)}%`);
        console.log(`   Functions: ${coverage.total.functions.pct.toFixed(1)}%`);
        console.log(`   Branches: ${coverage.total.branches.pct.toFixed(1)}%`);
      }

      return {
        badges,
        files: savedFiles,
        endpoints,
        coverage: coverage.total
      };
    } catch (error) {
      console.error(`💥 Badge generation failed: ${error.message}`);
      throw error;
    }
  }
}

// Parse command line arguments
const args = process.argv.slice(2);
const options = {
  format: args.find(arg => ['files', 'endpoints', 'all'].includes(arg)) || 'all',
  save: !args.includes('--no-save'),
  output: !args.includes('--quiet')
};

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const generator = new CoverageBadgeGenerator();
  generator.run(options);
}

export default CoverageBadgeGenerator;