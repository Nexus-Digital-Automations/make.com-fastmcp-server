#!/usr/bin/env node

/**
 * Configuration Validation Script
 * Validates environment variables and configuration settings
 * Usage: node scripts/validate-config.js [--env-file=.env] [--verbose]
 */

const fs = require('fs');
const path = require('path');

// Parse command line arguments
const args = process.argv.slice(2);
const envFile = args.find(arg => arg.startsWith('--env-file='))?.split('=')[1] || '.env';
const verbose = args.includes('--verbose');

// Load environment variables from specified file
function loadEnvFile(filePath) {
  try {
    if (fs.existsSync(filePath)) {
      const envContent = fs.readFileSync(filePath, 'utf8');
      const envVars = {};
      
      envContent.split('\n').forEach(line => {
        const trimmed = line.trim();
        if (trimmed && !trimmed.startsWith('#') && trimmed.includes('=')) {
          const [key, ...valueParts] = trimmed.split('=');
          const value = valueParts.join('=').replace(/^["']|["']$/g, '');
          envVars[key.trim()] = value.trim();
        }
      });
      
      // Set environment variables
      Object.entries(envVars).forEach(([key, value]) => {
        if (!process.env[key]) {
          process.env[key] = value;
        }
      });
      
      console.log(`✅ Loaded environment variables from: ${filePath}`);
      if (verbose) {
        console.log(`   Found ${Object.keys(envVars).length} variables`);
      }
    } else {
      console.warn(`⚠️  Environment file not found: ${filePath}`);
    }
  } catch (error) {
    console.error(`❌ Error loading environment file: ${error.message}`);
    process.exit(1);
  }
}

// Validation functions
const validators = {
  // Required environment variables
  required: {
    'MAKE_API_KEY': {
      validate: (value) => value && value.length >= 10,
      message: 'MAKE_API_KEY must be at least 10 characters long'
    }
  },
  
  // Optional environment variables with validation
  optional: {
    'MAKE_BASE_URL': {
      validate: (value) => !value || /^https?:\/\/.+/.test(value),
      message: 'MAKE_BASE_URL must be a valid HTTP/HTTPS URL'
    },
    'MAKE_TIMEOUT': {
      validate: (value) => !value || (parseInt(value) >= 1000 && parseInt(value) <= 300000),
      message: 'MAKE_TIMEOUT must be between 1000 and 300000 milliseconds'
    },
    'MAKE_RETRIES': {
      validate: (value) => !value || (parseInt(value) >= 0 && parseInt(value) <= 10),
      message: 'MAKE_RETRIES must be between 0 and 10'
    },
    'PORT': {
      validate: (value) => !value || (parseInt(value) >= 1 && parseInt(value) <= 65535),
      message: 'PORT must be between 1 and 65535'
    },
    'NODE_ENV': {
      validate: (value) => !value || ['development', 'production', 'test'].includes(value),
      message: 'NODE_ENV must be one of: development, production, test'
    },
    'LOG_LEVEL': {
      validate: (value) => !value || ['debug', 'info', 'warn', 'error'].includes(value),
      message: 'LOG_LEVEL must be one of: debug, info, warn, error'
    },
    'AUTH_ENABLED': {
      validate: (value) => !value || ['true', 'false', '1', '0', 'yes', 'no'].includes(value.toLowerCase()),
      message: 'AUTH_ENABLED must be a boolean value (true/false, 1/0, yes/no)'
    },
    'AUTH_SECRET': {
      validate: (value) => {
        const authEnabled = process.env.AUTH_ENABLED;
        if (authEnabled && ['true', '1', 'yes'].includes(authEnabled.toLowerCase())) {
          return value && value.length >= 32;
        }
        return true;
      },
      message: 'AUTH_SECRET must be at least 32 characters when AUTH_ENABLED is true'
    },
    'RATE_LIMIT_MAX_REQUESTS': {
      validate: (value) => !value || parseInt(value) >= 1,
      message: 'RATE_LIMIT_MAX_REQUESTS must be a positive integer'
    },
    'RATE_LIMIT_WINDOW_MS': {
      validate: (value) => !value || parseInt(value) >= 1000,
      message: 'RATE_LIMIT_WINDOW_MS must be at least 1000 milliseconds'
    },
    'RATE_LIMIT_SKIP_SUCCESS': {
      validate: (value) => !value || ['true', 'false', '1', '0', 'yes', 'no'].includes(value.toLowerCase()),
      message: 'RATE_LIMIT_SKIP_SUCCESS must be a boolean value'
    },
    'RATE_LIMIT_SKIP_FAILED': {
      validate: (value) => !value || ['true', 'false', '1', '0', 'yes', 'no'].includes(value.toLowerCase()),
      message: 'RATE_LIMIT_SKIP_FAILED must be a boolean value'
    }
  }
};

// Main validation function
function validateConfiguration() {
  console.log('🔍 Validating Make.com FastMCP Server Configuration');
  console.log('================================================\n');
  
  const errors = [];
  const warnings = [];
  const info = [];
  
  // Check required variables
  console.log('📋 Required Configuration:');
  Object.entries(validators.required).forEach(([key, validator]) => {
    const value = process.env[key];
    const status = value ? '✅' : '❌';
    
    console.log(`   ${status} ${key}: ${value ? (verbose ? value.substring(0, 20) + '...' : 'SET') : 'NOT SET'}`);
    
    if (!value) {
      errors.push(`Missing required environment variable: ${key}`);
    } else if (!validator.validate(value)) {
      errors.push(`${key}: ${validator.message}`);
      console.log(`      ❌ ${validator.message}`);
    }
  });
  
  console.log('\n📝 Optional Configuration:');
  Object.entries(validators.optional).forEach(([key, validator]) => {
    const value = process.env[key];
    const hasValue = value !== undefined && value !== '';
    const status = hasValue ? (validator.validate(value) ? '✅' : '❌') : '⚪';
    
    console.log(`   ${status} ${key}: ${hasValue ? (verbose ? value : 'SET') : 'NOT SET (using default)'}`);
    
    if (hasValue && !validator.validate(value)) {
      errors.push(`${key}: ${validator.message}`);
      console.log(`      ❌ ${validator.message}`);
    }
  });
  
  // Environment-specific warnings
  console.log('\n🔍 Environment-Specific Checks:');
  const nodeEnv = process.env.NODE_ENV || 'development';
  const authEnabled = process.env.AUTH_ENABLED;
  const logLevel = process.env.LOG_LEVEL || 'info';
  
  if (nodeEnv === 'production') {
    console.log('   🏭 Production environment detected');
    
    if (!authEnabled || !['true', '1', 'yes'].includes(authEnabled.toLowerCase())) {
      warnings.push('Authentication is disabled in production environment');
      console.log('   ⚠️  Authentication should be enabled in production');
    }
    
    if (logLevel === 'debug') {
      warnings.push('Debug logging is enabled in production environment');
      console.log('   ⚠️  Debug logging should be avoided in production');
    }
    
    const apiKey = process.env.MAKE_API_KEY;
    if (apiKey && apiKey.includes('example') || apiKey === 'your_make_api_key_here') {
      errors.push('Production environment is using example API key');
      console.log('   ❌ Using example API key in production');
    }
  }
  
  if (nodeEnv === 'development') {
    console.log('   🚧 Development environment detected');
    
    const port = parseInt(process.env.PORT || '3000');
    if (port < 1024) {
      warnings.push('Port numbers below 1024 require elevated privileges');
      console.log('   ⚠️  Port below 1024 requires elevated privileges');
    }
  }
  
  // Summary
  console.log('\n📊 Validation Summary:');
  console.log('=====================');
  
  if (errors.length === 0) {
    console.log('✅ Configuration validation passed!');
    if (warnings.length > 0) {
      console.log(`⚠️  ${warnings.length} warning(s) found:`);
      warnings.forEach(warning => console.log(`   • ${warning}`));
    }
    return true;
  } else {
    console.log(`❌ Configuration validation failed with ${errors.length} error(s):`);
    errors.forEach(error => console.log(`   • ${error}`));
    
    if (warnings.length > 0) {
      console.log(`\n⚠️  Additional ${warnings.length} warning(s):`);
      warnings.forEach(warning => console.log(`   • ${warning}`));
    }
    
    console.log('\n💡 Recommendations:');
    console.log('   1. Check your .env file against .env.example');
    console.log('   2. Ensure all required environment variables are set');
    console.log('   3. Verify that values meet the specified constraints');
    console.log('   4. Run with --verbose flag for more detailed output');
    
    return false;
  }
}

// Run validation
try {
  loadEnvFile(envFile);
  const isValid = validateConfiguration();
  process.exit(isValid ? 0 : 1);
} catch (error) {
  console.error(`❌ Validation script error: ${error.message}`);
  if (verbose) {
    console.error(error.stack);
  }
  process.exit(1);
}