#!/usr/bin/env ts-node
/**
 * Enhanced Logger Transports Example
 * Demonstrates how to use Fluentd and Google Cloud Logging transports
 */

import { EnhancedLogger } from '../lib/enhanced-logger';

// Example configuration for all transports
const loggingConfig = {
  elasticsearch: {
    enabled: false, // Disable for this example
    endpoint: 'http://localhost:9200',
    index: 'fastmcp-logs',
  },
  fluentd: {
    enabled: true,
    host: 'localhost',
    port: 24224,
    tag: 'example.fastmcp',
  },
  cloudLogging: {
    enabled: false, // Enable this when you have GCP credentials
    projectId: 'your-gcp-project',
    keyFilename: '/path/to/service-account-key.json',
    logName: 'fastmcp-example-logs',
  },
};

async function demonstrateLoggingTransports() {
  console.log('🚀 Enhanced Logger Transports Example\n');
  
  // Initialize the enhanced logger with transport configuration
  const logger = EnhancedLogger.getInstance(loggingConfig);
  
  // Show transport status
  const transportsStatus = logger.getTransportsStatus();
  console.log('📊 Transport Status:', transportsStatus);
  console.log('');

  // Demonstrate basic logging with trace correlation
  logger.info('Basic info message with trace correlation', {
    userId: 'user-123',
    operation: 'example-demo',
    requestId: 'req-456',
  });

  logger.warn('Warning message example', {
    component: 'LoggingExample',
    level: 'warning',
    details: 'This is a warning for demonstration',
  });

  logger.error('Error message example', {
    component: 'LoggingExample',
    errorCode: 'DEMO_ERROR',
    message: 'This is an error for demonstration purposes',
  });

  // Demonstrate business event logging
  logger.business('user_action', {
    action: 'login',
    userId: 'user-789',
    timestamp: new Date().toISOString(),
    metadata: {
      source: 'web_app',
      sessionId: 'session-abc123',
    },
  });

  // Demonstrate security event logging
  logger.security('authentication_attempt', {
    userId: 'user-789',
    ip: '192.168.1.100',
    userAgent: 'Mozilla/5.0 (Example Browser)',
    outcome: 'success',
    method: 'oauth',
  });

  // Demonstrate performance logging
  logger.performance('api_response_time', 125, 'milliseconds', {
    endpoint: '/api/example',
    method: 'GET',
    statusCode: 200,
  });

  // Demonstrate audit logging
  logger.audit('data_access', 'user_profile', 'success', {
    userId: 'user-789',
    dataType: 'personal_information',
    accessReason: 'profile_update',
  });

  // Demonstrate child logger with persistent context
  const childLogger = logger.child({
    component: 'ExampleModule',
    version: '1.0.0',
    sessionId: 'child-session-123',
  });

  childLogger.info('Child logger message', {
    specificData: 'This message includes persistent context',
  });

  childLogger.debug('Debug message from child logger', {
    debugLevel: 'detailed',
    extraInfo: 'Additional debugging information',
  });

  console.log('\n✅ Logging demonstration complete!');
  console.log('\n📝 Check your configured log destinations:');
  
  if (transportsStatus.fluentd) {
    console.log('   • Fluentd: Check your Fluentd server at localhost:24224');
  }
  
  if (transportsStatus.cloudLogging) {
    console.log('   • Google Cloud Logging: Check Google Cloud Console');
  }
  
  if (transportsStatus.elasticsearch) {
    console.log('   • Elasticsearch: Check Kibana or query Elasticsearch directly');
  }
}

// Export configuration examples for different environments
export const productionConfig = {
  elasticsearch: {
    enabled: true,
    endpoint: 'https://elasticsearch.company.com:9200',
    index: 'fastmcp-production-logs',
    username: process.env.ELASTICSEARCH_USER,
    password: process.env.ELASTICSEARCH_PASSWORD,
  },
  fluentd: {
    enabled: true,
    host: 'fluentd.company.com',
    port: 24224,
    tag: 'production.fastmcp',
  },
  cloudLogging: {
    enabled: true,
    projectId: process.env.GCP_PROJECT_ID,
    keyFilename: process.env.GCP_SERVICE_ACCOUNT_KEY,
    logName: 'fastmcp-production',
  },
};

export const developmentConfig = {
  elasticsearch: {
    enabled: true,
    endpoint: 'http://localhost:9200',
    index: 'fastmcp-dev-logs',
  },
  fluentd: {
    enabled: true,
    host: 'localhost',
    port: 24224,
    tag: 'development.fastmcp',
  },
  cloudLogging: {
    enabled: false, // Typically disabled in development
  },
};

export const testingConfig = {
  elasticsearch: {
    enabled: false, // Often disabled in tests
  },
  fluentd: {
    enabled: false, // Often disabled in tests
  },
  cloudLogging: {
    enabled: false, // Disabled in tests
  },
};

// Environment-specific configuration selector
export function getEnvironmentConfig() {
  const environment = process.env.NODE_ENV || 'development';
  
  switch (environment) {
    case 'production':
      return productionConfig;
    case 'development':
      return developmentConfig;
    case 'test':
      return testingConfig;
    default:
      return developmentConfig;
  }
}

// Usage instructions
export const usageInstructions = `
🔧 Enhanced Logger Transports Usage Instructions

1. **Fluentd Setup (for local testing):**
   \`\`\`bash
   # Using Docker
   docker run -d -p 24224:24224 -p 24224:24224/udp \\
     -v /data:/fluentd/log fluent/fluentd:v1.16-debian-1
   \`\`\`

2. **Google Cloud Logging Setup:**
   - Create a GCP project
   - Enable Cloud Logging API
   - Create a service account with logging permissions
   - Download the service account key JSON file
   - Set environment variables:
     \`\`\`bash
     export GCP_PROJECT_ID="your-project-id"
     export GCP_SERVICE_ACCOUNT_KEY="/path/to/key.json"
     \`\`\`

3. **Environment Configuration:**
   \`\`\`bash
   export NODE_ENV="production"  # or "development" or "test"
   export ELASTICSEARCH_USER="your-username"
   export ELASTICSEARCH_PASSWORD="your-password"
   \`\`\`

4. **Docker Compose Integration:**
   Add to your docker-compose.yml:
   \`\`\`yaml
   services:
     fluentd:
       image: fluent/fluentd:v1.16-debian-1
       ports:
         - "24224:24224"
         - "24224:24224/udp"
       volumes:
         - ./fluent.conf:/fluentd/etc/fluent.conf
         - fluentd-buffer:/var/log/fluentd-buffers
   \`\`\`

5. **Example Usage in Code:**
   \`\`\`typescript
   import { EnhancedLogger } from './lib/enhanced-logger';
   import { getEnvironmentConfig } from './examples/logging-transports-example';

   const config = getEnvironmentConfig();
   const logger = EnhancedLogger.getInstance(config);

   // Use logger with automatic transport routing
   logger.info('Application started', { version: '1.0.0' });
   logger.business('user_signup', { userId: 'user-123' });
   logger.security('login_attempt', { ip: '192.168.1.1' });
   \`\`\`
`;

// Run the example if called directly
if (require.main === module) {
  demonstrateLoggingTransports().catch(console.error);
}

export { demonstrateLoggingTransports };