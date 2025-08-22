#!/usr/bin/env node

/**
 * Advanced Refactoring Analyzer
 * Analyzes complexity metrics and provides specific refactoring recommendations
 */

import fs from 'fs';
import path from 'path';
import { Project } from 'ts-morph';

class RefactoringAnalyzer {
  constructor(projectPath = './') {
    this.projectPath = projectPath;
    this.project = new Project({
      tsConfigFilePath: path.join(projectPath, 'tsconfig.json'),
    });
  }

  analyzeFile(filePath) {
    const sourceFile = this.project.getSourceFileOrThrow(filePath);
    const fullText = sourceFile.getFullText();
    
    const analysis = {
      filePath,
      totalLines: fullText.split('\n').length,
      functions: this.analyzeFunctions(sourceFile),
      classes: this.analyzeClasses(sourceFile),
      interfaces: this.analyzeInterfaces(sourceFile),
      imports: this.analyzeImports(sourceFile),
      exports: this.analyzeExports(sourceFile),
      complexity: this.calculateComplexity(sourceFile),
      recommendations: []
    };

    analysis.recommendations = this.generateRecommendations(analysis);
    return analysis;
  }

  analyzeFunctions(sourceFile) {
    const functions = sourceFile.getFunctions();
    return functions.map(func => ({
      name: func.getName() || 'anonymous',
      lineCount: func.getEndLineNumber() - func.getStartLineNumber() + 1,
      parameterCount: func.getParameters().length,
      isAsync: func.isAsync(),
      isExported: func.isExported()
    }));
  }

  analyzeClasses(sourceFile) {
    const classes = sourceFile.getClasses();
    return classes.map(cls => ({
      name: cls.getName() || 'anonymous',
      lineCount: cls.getEndLineNumber() - cls.getStartLineNumber() + 1,
      methodCount: cls.getMethods().length,
      propertyCount: cls.getProperties().length,
      isExported: cls.isExported()
    }));
  }

  analyzeInterfaces(sourceFile) {
    const interfaces = sourceFile.getInterfaces();
    return interfaces.map(iface => ({
      name: iface.getName(),
      propertyCount: iface.getProperties().length,
      methodCount: iface.getMethods().length,
      isExported: iface.isExported()
    }));
  }

  analyzeImports(sourceFile) {
    const imports = sourceFile.getImportDeclarations();
    return imports.map(imp => ({
      moduleSpecifier: imp.getModuleSpecifierValue(),
      namedImports: imp.getNamedImports().map(ni => ni.getName()),
      defaultImport: imp.getDefaultImport()?.getText(),
      namespaceImport: imp.getNamespaceImport()?.getText()
    }));
  }

  analyzeExports(sourceFile) {
    const exports = sourceFile.getExportDeclarations();
    return exports.map(exp => ({
      moduleSpecifier: exp.getModuleSpecifierValue(),
      namedExports: exp.getNamedExports().map(ne => ne.getName())
    }));
  }

  calculateComplexity(sourceFile) {
    const functions = sourceFile.getFunctions();
    let totalComplexity = 0;
    let maxComplexity = 0;

    functions.forEach(func => {
      // Simple complexity calculation based on control flow statements
      const text = func.getFullText();
      const complexity = (text.match(/if|else|while|for|switch|case|catch|\?/g) || []).length + 1;
      totalComplexity += complexity;
      maxComplexity = Math.max(maxComplexity, complexity);
    });

    return {
      totalComplexity,
      maxComplexity,
      averageComplexity: functions.length > 0 ? totalComplexity / functions.length : 0
    };
  }

  generateRecommendations(analysis) {
    const recommendations = [];

    // File size recommendations
    if (analysis.totalLines > 1000) {
      recommendations.push({
        type: 'file-size',
        severity: 'high',
        message: `File has ${analysis.totalLines} lines. Consider splitting into multiple modules.`,
        suggestion: 'Split into domain-specific modules (types, core, services, tools)'
      });
    }

    // Function size recommendations
    analysis.functions.forEach(func => {
      if (func.lineCount > 50) {
        recommendations.push({
          type: 'function-size',
          severity: 'medium',
          message: `Function '${func.name}' has ${func.lineCount} lines. Consider breaking it down.`,
          suggestion: 'Extract smaller, focused functions with single responsibilities'
        });
      }
    });

    // Class size recommendations
    analysis.classes.forEach(cls => {
      if (cls.lineCount > 300) {
        recommendations.push({
          type: 'class-size',
          severity: 'high',
          message: `Class '${cls.name}' has ${cls.lineCount} lines. Consider splitting responsibilities.`,
          suggestion: 'Apply Single Responsibility Principle and extract related classes'
        });
      }
    });

    // Complexity recommendations
    if (analysis.complexity.maxComplexity > 15) {
      recommendations.push({
        type: 'complexity',
        severity: 'high',
        message: `Maximum cyclomatic complexity is ${analysis.complexity.maxComplexity}. Reduce complexity.`,
        suggestion: 'Break down complex functions and reduce nested conditions'
      });
    }

    return recommendations;
  }

  analyzeProject(targetFiles = []) {
    if (targetFiles.length === 0) {
      // Default to large files that need refactoring
      targetFiles = [
        'src/tools/ai-governance-engine.ts',
        'src/tools/blueprint-collaboration.ts',
        'src/tools/connections.ts',
        'src/tools/notifications.ts',
        'src/tools/billing.ts',
        'src/tools/policy-compliance-validation.ts',
        'src/tools/compliance-policy.ts',
        'src/tools/folders.ts',
        'src/tools/zero-trust-auth.ts'
      ];
    }

    const results = {};
    
    targetFiles.forEach(filePath => {
      const fullPath = path.join(this.projectPath, filePath);
      if (fs.existsSync(fullPath)) {
        try {
          results[filePath] = this.analyzeFile(filePath);
        } catch (error) {
          console.error(`Error analyzing ${filePath}:`, error.message);
          results[filePath] = { error: error.message };
        }
      }
    });

    return results;
  }

  generateReport(analysis, format = 'table') {
    if (format === 'json') {
      return JSON.stringify(analysis, null, 2);
    }

    if (format === 'markdown') {
      return this.generateMarkdownReport(analysis);
    }

    // Default table format
    return this.generateTableReport(analysis);
  }

  generateTableReport(analysis) {
    console.log('\n📊 REFACTORING ANALYSIS REPORT\n');
    console.log('┌─────────────────────────────────┬──────────┬─────────────┬───────────────┬─────────────────┐');
    console.log('│ File                            │ Lines    │ Functions   │ Max Complexity│ Recommendations │');
    console.log('├─────────────────────────────────┼──────────┼─────────────┼───────────────┼─────────────────┤');

    Object.entries(analysis).forEach(([filePath, data]) => {
      if (data.error) {
        console.log(`│ ${filePath.padEnd(31)} │ ERROR    │ -           │ -             │ ${data.error.substring(0, 13).padEnd(15)} │`);
      } else {
        const fileName = path.basename(filePath).padEnd(31);
        const lines = String(data.totalLines).padEnd(8);
        const functions = String(data.functions.length).padEnd(11);
        const complexity = String(data.complexity.maxComplexity).padEnd(13);
        const recommendations = String(data.recommendations.length).padEnd(15);
        
        console.log(`│ ${fileName} │ ${lines} │ ${functions} │ ${complexity} │ ${recommendations} │`);
      }
    });

    console.log('└─────────────────────────────────┴──────────┴─────────────┴───────────────┴─────────────────┘');

    // Show recommendations
    console.log('\n🔧 REFACTORING RECOMMENDATIONS\n');
    Object.entries(analysis).forEach(([filePath, data]) => {
      if (!data.error && data.recommendations.length > 0) {
        console.log(`📁 ${filePath}:`);
        data.recommendations.forEach((rec, index) => {
          const severity = rec.severity === 'high' ? '🔴' : rec.severity === 'medium' ? '🟡' : '🟢';
          console.log(`  ${index + 1}. ${severity} ${rec.message}`);
          console.log(`     💡 ${rec.suggestion}`);
        });
        console.log('');
      }
    });

    return analysis;
  }

  generateMarkdownReport(analysis) {
    let markdown = '# Refactoring Analysis Report\n\n';
    markdown += `Generated: ${new Date().toISOString()}\n\n`;
    markdown += '## File Analysis Summary\n\n';
    markdown += '| File | Lines | Functions | Max Complexity | Recommendations |\n';
    markdown += '|------|-------|-----------|----------------|-----------------|\n';

    Object.entries(analysis).forEach(([filePath, data]) => {
      if (data.error) {
        markdown += `| ${path.basename(filePath)} | ERROR | - | - | ${data.error} |\n`;
      } else {
        markdown += `| ${path.basename(filePath)} | ${data.totalLines} | ${data.functions.length} | ${data.complexity.maxComplexity} | ${data.recommendations.length} |\n`;
      }
    });

    markdown += '\n## Detailed Recommendations\n\n';
    Object.entries(analysis).forEach(([filePath, data]) => {
      if (!data.error && data.recommendations.length > 0) {
        markdown += `### ${path.basename(filePath)}\n\n`;
        data.recommendations.forEach((rec, index) => {
          const severity = rec.severity === 'high' ? '🔴' : rec.severity === 'medium' ? '🟡' : '🟢';
          markdown += `${index + 1}. ${severity} **${rec.type}**: ${rec.message}\n`;
          markdown += `   - **Suggestion**: ${rec.suggestion}\n\n`;
        });
      }
    });

    return markdown;
  }
}

// CLI Interface
const analyzer = new RefactoringAnalyzer();
const args = process.argv.slice(2);

let format = 'table';
let outputFile = null;
let targetFiles = [];

// Parse arguments
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--format' && args[i + 1]) {
    format = args[i + 1];
    i++;
  } else if (args[i] === '--output' && args[i + 1]) {
    outputFile = args[i + 1];
    i++;
  } else if (args[i] === '--files' && args[i + 1]) {
    targetFiles = args[i + 1].split(',');
    i++;
  }
}

console.log('🔍 Analyzing files for refactoring opportunities...\n');

const analysis = analyzer.analyzeProject(targetFiles);
const report = analyzer.generateReport(analysis, format);

if (outputFile) {
  fs.writeFileSync(outputFile, typeof report === 'string' ? report : JSON.stringify(report, null, 2));
  console.log(`\n📄 Report saved to: ${outputFile}`);
}

if (format === 'table') {
  // Report was already printed in generateTableReport
} else {
  console.log(report);
}

export default RefactoringAnalyzer;