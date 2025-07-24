#!/usr/bin/env node

/**
 * Configuration Report Script
 * Generates comprehensive configuration reports using the ConfigManager
 * Usage: node scripts/config-report.js [--format=json|text] [--env-file=.env]
 */

const fs = require('fs');
const path = require('path');

// Parse command line arguments
const args = process.argv.slice(2);
const format = args.find(arg => arg.startsWith('--format='))?.split('=')[1] || 'text';
const envFile = args.find(arg => arg.startsWith('--env-file='))?.split('=')[1] || '.env';

// Load environment variables from specified file
function loadEnvFile(filePath) {
  try {
    if (fs.existsSync(filePath)) {
      const envContent = fs.readFileSync(filePath, 'utf8');
      
      envContent.split('\n').forEach(line => {
        const trimmed = line.trim();
        if (trimmed && !trimmed.startsWith('#') && trimmed.includes('=')) {
          const [key, ...valueParts] = trimmed.split('=');
          const value = valueParts.join('=').replace(/^["']|["']$/g, '');
          if (!process.env[key.trim()]) {
            process.env[key.trim()] = value.trim();
          }
        }
      });
      
      console.log(`Loaded environment variables from: ${filePath}\n`);
    }
  } catch (error) {
    console.error(`Error loading environment file: ${error.message}`);
  }
}

// Import the configuration manager (after setting environment)
async function generateReport() {
  try {
    // Check if the compiled configuration exists
    const configPath = path.join(process.cwd(), 'dist', 'lib', 'config.js');
    const configSourcePath = path.join(process.cwd(), 'src', 'lib', 'config.ts');
    
    if (!fs.existsSync(configPath)) {
      console.error('❌ Configuration module not found. Please build the project first:');
      console.error('   npm run build');
      console.error('\nOr run from TypeScript source:');
      console.error('   npx tsx scripts/config-report.js');
      process.exit(1);
    }
    
    // Import configuration manager
    const { configManager, createConfigurationValidator, ConfigPresets } = require(configPath);
    
    if (format === 'json') {
      // JSON format output
      const report = {
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development',
        configuration: JSON.parse(configManager.getConfigurationReport()),
        validation: configManager.validateEnvironment(),
        presets: {
          development: ConfigPresets.development,
          production: ConfigPresets.production,
          testing: ConfigPresets.testing
        }
      };
      
      console.log(JSON.stringify(report, null, 2));
    } else {
      // Text format output
      console.log('🔧 Make.com FastMCP Server Configuration Report');
      console.log('===============================================\n');
      
      // Basic configuration report
      console.log('📊 Current Configuration:');
      console.log(configManager.getConfigurationReport());
      
      console.log('\n🔍 Environment Validation:');
      const validation = configManager.validateEnvironment();
      
      if (validation.valid) {
        console.log('✅ Environment validation: PASSED');
      } else {
        console.log('❌ Environment validation: FAILED');
        console.log('\nErrors:');
        validation.errors.forEach(error => console.log(`   • ${error}`));
      }
      
      if (validation.warnings.length > 0) {
        console.log('\nWarnings:');
        validation.warnings.forEach(warning => console.log(`   • ${warning}`));
      }
      
      // Configuration presets
      console.log('\n📋 Available Configuration Presets:');
      console.log('\n🚧 Development Preset:');
      console.log(`   • Log Level: ${ConfigPresets.development.logLevel}`);
      console.log(`   • Authentication: ${ConfigPresets.development.authentication.enabled ? 'Enabled' : 'Disabled'}`);
      console.log(`   • Rate Limit: ${ConfigPresets.development.rateLimit.maxRequests} requests/${ConfigPresets.development.rateLimit.windowMs}ms`);
      
      console.log('\n🏭 Production Preset:');
      console.log(`   • Log Level: ${ConfigPresets.production.logLevel}`);
      console.log(`   • Authentication: ${ConfigPresets.production.authentication.enabled ? 'Enabled' : 'Disabled'}`);
      console.log(`   • Rate Limit: ${ConfigPresets.production.rateLimit.maxRequests} requests/${ConfigPresets.production.rateLimit.windowMs}ms`);
      
      console.log('\n🧪 Testing Preset:');
      console.log(`   • Log Level: ${ConfigPresets.testing.logLevel}`);
      console.log(`   • Authentication: ${ConfigPresets.testing.authentication.enabled ? 'Enabled' : 'Disabled'}`);
      console.log(`   • Rate Limit: ${ConfigPresets.testing.rateLimit.maxRequests} requests/${ConfigPresets.testing.rateLimit.windowMs}ms`);
      
      // Validation utilities demo
      console.log('\n🛠️  Configuration Validation Utilities:');
      const validator = createConfigurationValidator();
      
      const makeApiKey = process.env.MAKE_API_KEY;
      if (makeApiKey) {
        console.log(`   • API Key Validation: ${validator.validateMakeApiKey(makeApiKey) ? '✅' : '❌'}`);
      }
      
      const port = parseInt(process.env.PORT || '3000');
      console.log(`   • Port Validation: ${validator.validatePort(port) ? '✅' : '❌'} (${port})`);
      
      const timeout = parseInt(process.env.MAKE_TIMEOUT || '30000');
      console.log(`   • Timeout Validation: ${validator.validateTimeout(timeout) ? '✅' : '❌'} (${timeout}ms)`);
      
      const logLevel = process.env.LOG_LEVEL || 'info';
      console.log(`   • Log Level Validation: ${validator.validateLogLevel(logLevel) ? '✅' : '❌'} (${logLevel})`);
      
      // Security recommendations
      console.log('\n🔒 Security Recommendations:');
      const nodeEnv = process.env.NODE_ENV || 'development';
      const authEnabled = process.env.AUTH_ENABLED;
      
      if (nodeEnv === 'production') {
        if (!authEnabled || !['true', '1', 'yes'].includes(authEnabled.toLowerCase())) {
          console.log('   ⚠️  Enable authentication in production (AUTH_ENABLED=true)');
        } else {
          console.log('   ✅ Authentication is properly enabled for production');
        }
        
        const authSecret = process.env.AUTH_SECRET;
        if (!authSecret || authSecret.length < 32) {
          console.log('   ⚠️  Use a strong AUTH_SECRET (32+ characters) in production');
        } else {
          console.log('   ✅ Authentication secret meets security requirements');
        }
      }
      
      if (makeApiKey && (makeApiKey.includes('example') || makeApiKey === 'your_make_api_key_here')) {
        console.log('   ❌ Replace example API key with real Make.com API key');
      } else if (makeApiKey) {
        console.log('   ✅ API key appears to be properly configured');
      }
      
      console.log('\n💡 Next Steps:');
      console.log('   1. Address any validation errors or warnings above');
      console.log('   2. Review security recommendations for your environment');
      console.log('   3. Test configuration with: npm run config:validate');
      console.log('   4. Start the server with: npm run dev');
    }
    
  } catch (error) {
    console.error(`❌ Error generating configuration report: ${error.message}`);
    if (process.env.NODE_ENV === 'development') {
      console.error(error.stack);
    }
    process.exit(1);
  }
}

// Run report generation
loadEnvFile(envFile);
generateReport();