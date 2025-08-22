#!/usr/bin/env node
/**
 * Refactoring Analyzer Script for Make.com FastMCP Server
 * 
 * This script analyzes large TypeScript files and provides detailed refactoring
 * recommendations, complexity metrics, and splitting strategies.
 * 
 * Usage:
 *   node scripts/refactoring/refactoring-analyzer.js [options]
 * 
 * Options:
 *   --file <path>     Analyze specific file
 *   --threshold <n>   Line count threshold (default: 400)
 *   --output <json|table|markdown>  Output format (default: table)
 *   --save <path>     Save analysis to file
 */

const fs = require('fs').promises;
const path = require('path');
const { execSync } = require('child_process');

class RefactoringAnalyzer {
  constructor(options = {}) {
    this.options = {
      threshold: 400,
      outputFormat: 'table',
      ...options
    };
    this.projectRoot = process.cwd();
    this.results = [];
  }

  async analyzeProject() {
    console.log('🔍 Starting refactoring analysis...');
    console.log(`📏 Using threshold: ${this.options.threshold} lines`);

    try {
      // Find all TypeScript files
      const tsFiles = await this.findTypeScriptFiles();
      
      // Analyze each file
      for (const file of tsFiles) {
        const analysis = await this.analyzeFile(file);
        if (analysis) {
          this.results.push(analysis);
        }
      }

      // Sort by line count (descending)
      this.results.sort((a, b) => b.lineCount - a.lineCount);

      // Generate output
      return this.generateOutput();

    } catch (error) {
      console.error('❌ Analysis failed:', error);
      throw error;
    }
  }

  async findTypeScriptFiles() {
    const toolsDir = path.join(this.projectRoot, 'src', 'tools');
    
    try {
      const files = await fs.readdir(toolsDir);
      const tsFiles = [];

      for (const file of files) {
        if (file.endsWith('.ts') && !file.endsWith('.test.ts') && !file.endsWith('.spec.ts')) {
          const fullPath = path.join(toolsDir, file);
          const stat = await fs.stat(fullPath);
          
          if (stat.isFile()) {
            tsFiles.push(fullPath);
          }
        }
      }

      return tsFiles;
    } catch (error) {
      console.error('❌ Could not find TypeScript files:', error);
      return [];
    }
  }

  async analyzeFile(filePath) {
    try {
      const content = await fs.readFile(filePath, 'utf8');
      const lines = content.split('\n');
      const lineCount = lines.length;

      // Skip files under threshold
      if (lineCount < this.options.threshold) {
        return null;
      }

      console.log(`📄 Analyzing ${path.basename(filePath)} (${lineCount} lines)...`);

      const analysis = {
        fileName: path.basename(filePath),
        filePath: path.relative(this.projectRoot, filePath),
        lineCount,
        ...await this.analyzeCodeStructure(content, lines),
        ...await this.calculateComplexityMetrics(content),
        refactoringRecommendations: await this.generateRefactoringRecommendations(filePath, content, lineCount)
      };

      return analysis;

    } catch (error) {
      console.warn(`⚠️  Could not analyze ${filePath}:`, error.message);
      return null;
    }
  }

  async analyzeCodeStructure(content, lines) {
    const structure = {
      imports: 0,
      exports: 0,
      interfaces: 0,
      types: 0,
      classes: 0,
      functions: 0,
      constants: 0,
      comments: 0,
      emptyLines: 0,
      toolRegistrations: 0,
    };

    lines.forEach(line => {
      const trimmed = line.trim();
      
      if (!trimmed) {
        structure.emptyLines++;
      } else if (trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*')) {
        structure.comments++;
      } else if (trimmed.startsWith('import ')) {
        structure.imports++;
      } else if (trimmed.startsWith('export ')) {
        structure.exports++;
      } else if (trimmed.includes('interface ')) {
        structure.interfaces++;
      } else if (trimmed.includes('type ') && trimmed.includes('=')) {
        structure.types++;
      } else if (trimmed.includes('class ')) {
        structure.classes++;
      } else if (trimmed.includes('function ') || /^\s*(async\s+)?function/.test(line)) {
        structure.functions++;
      } else if (trimmed.includes('const ') && trimmed.includes('=')) {
        structure.constants++;
      } else if (trimmed.includes('server.addTool(')) {
        structure.toolRegistrations++;
      }
    });

    // Calculate code density
    const codeLines = lines.length - structure.comments - structure.emptyLines;
    structure.codeDensity = codeLines / lines.length;
    structure.commentRatio = structure.comments / lines.length;

    return structure;
  }

  async calculateComplexityMetrics(content) {
    const metrics = {
      cyclomaticComplexity: 0,
      cognitiveComplexity: 0,
      nestingDepth: 0,
      functionComplexity: [],
    };

    try {
      // Use ts-complexity for detailed analysis
      const tempFile = path.join(__dirname, 'temp-analysis.ts');
      await fs.writeFile(tempFile, content);

      try {
        const complexityOutput = execSync(`npx ts-complexity ${tempFile} --format json`, {
          encoding: 'utf8',
          stdio: 'pipe'
        });

        const complexityData = JSON.parse(complexityOutput);
        
        if (complexityData && complexityData.length > 0) {
          const fileData = complexityData[0];
          metrics.cyclomaticComplexity = fileData.complexity || 0;
          metrics.functionComplexity = fileData.functions || [];
        }

      } catch (complexityError) {
        // Fallback to basic complexity analysis
        metrics.cyclomaticComplexity = this.calculateBasicComplexity(content);
      }

      // Clean up temp file
      try {
        await fs.unlink(tempFile);
      } catch (unlinkError) {
        // Ignore cleanup errors
      }

      // Calculate nesting depth
      metrics.nestingDepth = this.calculateNestingDepth(content);

    } catch (error) {
      console.warn('⚠️  Could not calculate complexity metrics:', error.message);
    }

    return metrics;
  }

  calculateBasicComplexity(content) {
    // Basic cyclomatic complexity calculation
    const complexityIndicators = [
      /\bif\b/g,
      /\belse\b/g,
      /\bwhile\b/g,
      /\bfor\b/g,
      /\bswitch\b/g,
      /\bcase\b/g,
      /\bcatch\b/g,
      /\b\?\s*:/g, // Ternary operators
      /\&\&/g,
      /\|\|/g,
    ];

    let complexity = 1; // Base complexity

    complexityIndicators.forEach(pattern => {
      const matches = content.match(pattern);
      if (matches) {
        complexity += matches.length;
      }
    });

    return complexity;
  }

  calculateNestingDepth(content) {
    const lines = content.split('\n');
    let maxDepth = 0;
    let currentDepth = 0;

    lines.forEach(line => {
      const trimmed = line.trim();
      
      // Count opening braces
      const openBraces = (line.match(/{/g) || []).length;
      const closeBraces = (line.match(/}/g) || []).length;
      
      currentDepth += openBraces - closeBraces;
      maxDepth = Math.max(maxDepth, currentDepth);
    });

    return maxDepth;
  }

  async generateRefactoringRecommendations(filePath, content, lineCount) {
    const recommendations = [];
    const fileName = path.basename(filePath, '.ts');

    // Line count recommendations
    if (lineCount > 2000) {
      recommendations.push({
        type: 'critical',
        category: 'size',
        message: `File is extremely large (${lineCount} lines). Immediate refactoring required.`,
        priority: 'high',
        effort: 'high',
        suggestedSplit: Math.ceil(lineCount / 400)
      });
    } else if (lineCount > 1000) {
      recommendations.push({
        type: 'warning',
        category: 'size',
        message: `File is large (${lineCount} lines). Consider splitting into modules.`,
        priority: 'medium',
        effort: 'medium',
        suggestedSplit: Math.ceil(lineCount / 400)
      });
    }

    // Tool registration analysis
    const toolMatches = content.match(/server\.addTool\(/g);
    const toolCount = toolMatches ? toolMatches.length : 0;
    
    if (toolCount > 10) {
      recommendations.push({
        type: 'warning',
        category: 'tools',
        message: `High number of tools (${toolCount}). Consider individual tool files.`,
        priority: 'medium',
        effort: 'medium',
        suggestedApproach: 'Split into individual tool files in tools/ directory'
      });
    }

    // Type definition analysis
    const typeMatches = content.match(/(?:interface|type)\s+\w+/g);
    const typeCount = typeMatches ? typeMatches.length : 0;
    
    if (typeCount > 20) {
      recommendations.push({
        type: 'info',
        category: 'types',
        message: `Many type definitions (${typeCount}). Consider separate types module.`,
        priority: 'low',
        effort: 'low',
        suggestedApproach: 'Extract to types/ directory'
      });
    }

    // Function analysis
    const functionMatches = content.match(/(?:function|async\s+function|\w+\s*=\s*(?:async\s+)?\()/g);
    const functionCount = functionMatches ? functionMatches.length : 0;
    
    if (functionCount > 30) {
      recommendations.push({
        type: 'info',
        category: 'functions',
        message: `Many functions (${functionCount}). Consider utility modules.`,
        priority: 'low',
        effort: 'low',
        suggestedApproach: 'Extract to utils/ directory'
      });
    }

    // Specific patterns for each large file
    const specificRecommendations = this.getFileSpecificRecommendations(fileName, content);
    recommendations.push(...specificRecommendations);

    return recommendations;
  }

  getFileSpecificRecommendations(fileName, content) {
    const recommendations = [];

    switch (fileName) {
      case 'ai-governance-engine':
        recommendations.push({
          type: 'info',
          category: 'ml',
          message: 'Contains ML logic. Consider ml/, governance/, and compliance/ modules.',
          priority: 'high',
          effort: 'high',
          suggestedStructure: ['ml/', 'governance/', 'compliance/', 'types/', 'utils/']
        });
        break;

      case 'blueprint-collaboration':
        recommendations.push({
          type: 'info',
          category: 'realtime',
          message: 'Contains real-time logic. Consider versioning/, collaboration/, conflict/ modules.',
          priority: 'high',
          effort: 'high',
          suggestedStructure: ['versioning/', 'collaboration/', 'conflict/', 'deployment/']
        });
        break;

      case 'connections':
        recommendations.push({
          type: 'info',
          category: 'services',
          message: 'Service integration logic. Consider adapters/, webhooks/, diagnostics/ modules.',
          priority: 'medium',
          effort: 'medium',
          suggestedStructure: ['adapters/', 'webhooks/', 'diagnostics/', 'security/']
        });
        break;

      case 'notifications':
        recommendations.push({
          type: 'info',
          category: 'channels',
          message: 'Multi-channel logic. Consider channels/, templates/, scheduling/ modules.',
          priority: 'medium',
          effort: 'medium',
          suggestedStructure: ['channels/', 'templates/', 'scheduling/', 'tracking/']
        });
        break;

      case 'billing':
        recommendations.push({
          type: 'info',
          category: 'financial',
          message: 'Financial logic. Consider accounts/, usage/, invoicing/, budgets/ modules.',
          priority: 'medium',
          effort: 'medium',
          suggestedStructure: ['accounts/', 'usage/', 'invoicing/', 'budgets/']
        });
        break;

      default:
        if (content.includes('compliance') || content.includes('policy')) {
          recommendations.push({
            type: 'info',
            category: 'compliance',
            message: 'Contains compliance logic. Consider policy/, validation/, audit/ modules.',
            priority: 'medium',
            effort: 'medium'
          });
        }
        break;
    }

    return recommendations;
  }

  generateOutput() {
    const summary = this.generateSummary();
    
    switch (this.options.outputFormat) {
      case 'json':
        return this.generateJsonOutput(summary);
      case 'markdown':
        return this.generateMarkdownOutput(summary);
      case 'table':
      default:
        return this.generateTableOutput(summary);
    }
  }

  generateSummary() {
    const totalFiles = this.results.length;
    const totalLines = this.results.reduce((sum, result) => sum + result.lineCount, 0);
    const avgLines = totalFiles > 0 ? Math.round(totalLines / totalFiles) : 0;
    const maxLines = totalFiles > 0 ? Math.max(...this.results.map(r => r.lineCount)) : 0;
    const criticalFiles = this.results.filter(r => r.lineCount > 2000).length;
    const warningFiles = this.results.filter(r => r.lineCount > 1000 && r.lineCount <= 2000).length;

    return {
      totalFiles,
      totalLines,
      avgLines,
      maxLines,
      criticalFiles,
      warningFiles,
      filesUnderThreshold: 0, // These aren't included in results
    };
  }

  generateTableOutput(summary) {
    let output = '\n🔍 REFACTORING ANALYSIS RESULTS\n';
    output += '=' .repeat(50) + '\n\n';

    // Summary
    output += '📊 SUMMARY:\n';
    output += `   Files analyzed: ${summary.totalFiles}\n`;
    output += `   Total lines: ${summary.totalLines.toLocaleString()}\n`;
    output += `   Average lines: ${summary.avgLines}\n`;
    output += `   Largest file: ${summary.maxLines.toLocaleString()} lines\n`;
    output += `   🚨 Critical files (>2000 lines): ${summary.criticalFiles}\n`;
    output += `   ⚠️  Warning files (1000-2000 lines): ${summary.warningFiles}\n\n`;

    // Detailed results
    if (this.results.length > 0) {
      output += '📋 DETAILED ANALYSIS:\n\n';
      
      // Table header
      output += '┌' + '─'.repeat(30) + '┬' + '─'.repeat(8) + '┬' + '─'.repeat(10) + '┬' + '─'.repeat(12) + '┬' + '─'.repeat(15) + '┐\n';
      output += '│' + ' File'.padEnd(30) + '│' + ' Lines'.padEnd(8) + '│' + ' Tools'.padEnd(10) + '│' + ' Complexity'.padEnd(12) + '│' + ' Priority'.padEnd(15) + '│\n';
      output += '├' + '─'.repeat(30) + '┼' + '─'.repeat(8) + '┼' + '─'.repeat(10) + '┼' + '─'.repeat(12) + '┼' + '─'.repeat(15) + '┤\n';

      this.results.forEach(result => {
        const fileName = result.fileName.length > 28 ? result.fileName.substring(0, 25) + '...' : result.fileName;
        const priority = result.lineCount > 2000 ? '🚨 Critical' : result.lineCount > 1000 ? '⚠️  Warning' : '✅ Good';
        
        output += '│' + ` ${fileName}`.padEnd(30) + 
                  '│' + ` ${result.lineCount.toLocaleString()}`.padEnd(8) + 
                  '│' + ` ${result.toolRegistrations}`.padEnd(10) + 
                  '│' + ` ${result.cyclomaticComplexity}`.padEnd(12) + 
                  '│' + ` ${priority}`.padEnd(15) + '│\n';
      });

      output += '└' + '─'.repeat(30) + '┴' + '─'.repeat(8) + '┴' + '─'.repeat(10) + '┴' + '─'.repeat(12) + '┴' + '─'.repeat(15) + '┘\n\n';

      // Recommendations
      output += '💡 REFACTORING RECOMMENDATIONS:\n\n';
      
      this.results.forEach((result, index) => {
        if (result.refactoringRecommendations.length > 0) {
          output += `📄 ${result.fileName}:\n`;
          
          result.refactoringRecommendations.forEach(rec => {
            const icon = rec.type === 'critical' ? '🚨' : rec.type === 'warning' ? '⚠️' : 'ℹ️';
            output += `   ${icon} ${rec.message}\n`;
            
            if (rec.suggestedStructure) {
              output += `      Suggested modules: ${rec.suggestedStructure.join(', ')}\n`;
            }
            if (rec.suggestedSplit) {
              output += `      Suggested split: ${rec.suggestedSplit} modules\n`;
            }
          });
          
          output += '\n';
        }
      });
    }

    // Next steps
    output += '🚀 NEXT STEPS:\n';
    output += '   1. Start with critical files (>2000 lines)\n';
    output += '   2. Use module generator: npm run generate:module\n';
    output += '   3. Follow phase-based refactoring approach\n';
    output += '   4. Maintain backward compatibility\n';
    output += '   5. Add comprehensive tests\n\n';

    return output;
  }

  generateJsonOutput(summary) {
    return JSON.stringify({
      summary,
      results: this.results,
      generatedAt: new Date().toISOString(),
    }, null, 2);
  }

  generateMarkdownOutput(summary) {
    let output = '# Refactoring Analysis Results\n\n';
    
    output += `**Generated**: ${new Date().toLocaleString()}\n\n`;
    
    output += '## Summary\n\n';
    output += `- **Files analyzed**: ${summary.totalFiles}\n`;
    output += `- **Total lines**: ${summary.totalLines.toLocaleString()}\n`;
    output += `- **Average lines**: ${summary.avgLines}\n`;
    output += `- **Largest file**: ${summary.maxLines.toLocaleString()} lines\n`;
    output += `- **🚨 Critical files** (>2000 lines): ${summary.criticalFiles}\n`;
    output += `- **⚠️ Warning files** (1000-2000 lines): ${summary.warningFiles}\n\n`;

    if (this.results.length > 0) {
      output += '## Detailed Analysis\n\n';
      output += '| File | Lines | Tools | Complexity | Priority |\n';
      output += '|------|-------|-------|------------|----------|\n';

      this.results.forEach(result => {
        const priority = result.lineCount > 2000 ? '🚨 Critical' : result.lineCount > 1000 ? '⚠️ Warning' : '✅ Good';
        output += `| ${result.fileName} | ${result.lineCount.toLocaleString()} | ${result.toolRegistrations} | ${result.cyclomaticComplexity} | ${priority} |\n`;
      });

      output += '\n## Refactoring Recommendations\n\n';

      this.results.forEach(result => {
        if (result.refactoringRecommendations.length > 0) {
          output += `### ${result.fileName}\n\n`;
          
          result.refactoringRecommendations.forEach(rec => {
            const icon = rec.type === 'critical' ? '🚨' : rec.type === 'warning' ? '⚠️' : 'ℹ️';
            output += `- ${icon} **${rec.category}**: ${rec.message}\n`;
            
            if (rec.suggestedStructure) {
              output += `  - Suggested modules: ${rec.suggestedStructure.join(', ')}\n`;
            }
            if (rec.suggestedSplit) {
              output += `  - Suggested split: ${rec.suggestedSplit} modules\n`;
            }
          });
          
          output += '\n';
        }
      });
    }

    output += '## Next Steps\n\n';
    output += '1. Start with critical files (>2000 lines)\n';
    output += '2. Use module generator: `npm run generate:module`\n';
    output += '3. Follow phase-based refactoring approach\n';
    output += '4. Maintain backward compatibility\n';
    output += '5. Add comprehensive tests\n';

    return output;
  }

  async saveResults(filePath, content) {
    try {
      await fs.writeFile(filePath, content, 'utf8');
      console.log(`💾 Analysis saved to ${filePath}`);
    } catch (error) {
      console.error('❌ Could not save analysis:', error);
    }
  }
}

// CLI interface
if (require.main === module) {
  const args = process.argv.slice(2);
  const options = {
    file: null,
    threshold: 400,
    outputFormat: 'table',
    saveFile: null,
  };

  // Parse command line arguments
  for (let i = 0; i < args.length; i += 2) {
    const flag = args[i];
    const value = args[i + 1];

    switch (flag) {
      case '--file':
        options.file = value;
        break;
      case '--threshold':
        options.threshold = parseInt(value, 10);
        break;
      case '--output':
        options.outputFormat = value;
        break;
      case '--save':
        options.saveFile = value;
        break;
      case '--help':
        console.log(`
Refactoring Analyzer - Analyze TypeScript files for refactoring opportunities

Usage: node scripts/refactoring/refactoring-analyzer.js [options]

Options:
  --file <path>         Analyze specific file
  --threshold <n>       Line count threshold (default: 400)
  --output <format>     Output format: json, table, markdown (default: table)
  --save <path>         Save analysis to file
  --help               Show this help message

Examples:
  node scripts/refactoring/refactoring-analyzer.js
  node scripts/refactoring/refactoring-analyzer.js --threshold 500 --output markdown
  node scripts/refactoring/refactoring-analyzer.js --save analysis-results.md --output markdown
        `);
        process.exit(0);
        break;
    }
  }

  // Run the analysis
  const analyzer = new RefactoringAnalyzer(options);
  analyzer.analyzeProject()
    .then(output => {
      console.log(output);
      
      if (options.saveFile) {
        return analyzer.saveResults(options.saveFile, output);
      }
    })
    .catch(error => {
      console.error('❌ Analysis failed:', error);
      process.exit(1);
    });
}

module.exports = { RefactoringAnalyzer };