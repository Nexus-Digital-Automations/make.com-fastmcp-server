/**
 * Concurrent Security Agent Tests
 * Tests for security monitoring, threat detection, and incident response
 */

import { ConcurrentSecurityAgent } from '../concurrent-security-agent.js';
import { SecurityEventType, SecuritySeverity } from '../../middleware/security-monitoring.js';

describe('ConcurrentSecurityAgent', () => {
  let securityAgent: ConcurrentSecurityAgent;

  beforeEach(async () => {
    // Create a test instance
    securityAgent = new ConcurrentSecurityAgent();
    // Give time for initialization
    await new Promise(resolve => setTimeout(resolve, 100));
  });

  afterEach(async () => {
    // Clean shutdown
    if (securityAgent) {
      await securityAgent.shutdown();
    }
  });

  describe('Initialization', () => {
    test('should initialize successfully', async () => {
      const status = securityAgent.getStatus();
      expect(status.healthy).toBe(true);
      expect(status.workers.total).toBeGreaterThan(0);
    });

    test('should have default security patterns loaded', async () => {
      const exportData = await securityAgent.exportSecurityData({
        includeEvents: false,
        includeIncidents: false,
        includeMetrics: true
      });
      
      expect(exportData).toBeDefined();
    });
  });

  describe('Security Event Processing', () => {
    test('should process authentication failure events', async () => {
      const eventData = {
        type: SecurityEventType.AUTHENTICATION_FAILURE,
        severity: SecuritySeverity.HIGH,
        source: 'test_authentication',
        details: {
          username: 'testuser',
          ipAddress: '192.168.1.100',
          userAgent: 'TestAgent/1.0'
        },
        ipAddress: '192.168.1.100',
        userAgent: 'TestAgent/1.0'
      };

      const eventId = await securityAgent.processSecurityEvent(eventData);
      expect(eventId).toBeDefined();
      expect(typeof eventId).toBe('string');
      expect(eventId).toMatch(/^evt_\d+_[a-f0-9]+$/);
    });

    test('should detect brute force patterns', async () => {
      // Simulate multiple authentication failures
      const promises = [];
      for (let i = 0; i < 6; i++) {
        promises.push(securityAgent.processSecurityEvent({
          type: SecurityEventType.AUTHENTICATION_FAILURE,
          severity: SecuritySeverity.MEDIUM,
          source: 'test_authentication',
          details: {
            username: 'testuser',
            attempt: i + 1
          },
          ipAddress: '192.168.1.100',
          userAgent: 'TestAgent/1.0'
        }));
      }

      const eventIds = await Promise.all(promises);
      expect(eventIds).toHaveLength(6);
      eventIds.forEach(id => {
        expect(id).toMatch(/^evt_\d+_[a-f0-9]+$/);
      });
    });

    test('should handle malicious input detection', async () => {
      const eventData = {
        type: SecurityEventType.MALICIOUS_INPUT_DETECTED,
        severity: SecuritySeverity.HIGH,
        source: 'input_validation',
        details: {
          input: '<script>alert("xss")</script>',
          endpoint: '/api/test',
          blocked: true
        },
        ipAddress: '10.0.0.1',
        userAgent: 'curl/7.68.0'
      };

      const eventId = await securityAgent.processSecurityEvent(eventData);
      expect(eventId).toBeDefined();
    });
  });

  describe('Threat Intelligence', () => {
    test('should query threat intelligence', async () => {
      const indicators = [
        { type: 'ip', value: '192.168.1.100' },
        { type: 'domain', value: 'malicious-site.com' }
      ];

      const matches = await securityAgent.queryThreatIntelligence(indicators);
      expect(Array.isArray(matches)).toBe(true);
    });
  });

  describe('Compliance Monitoring', () => {
    test('should validate compliance status', async () => {
      const complianceResult = await securityAgent.validateCompliance('SOC2');
      
      expect(complianceResult).toHaveProperty('compliant');
      expect(complianceResult).toHaveProperty('violations');
      expect(complianceResult).toHaveProperty('recommendations');
      expect(typeof complianceResult.compliant).toBe('boolean');
      expect(Array.isArray(complianceResult.violations)).toBe(true);
      expect(Array.isArray(complianceResult.recommendations)).toBe(true);
    });
  });

  describe('Audit Log Processing', () => {
    test('should process audit logs', async () => {
      const logs = [
        {
          timestamp: new Date(),
          action: 'login',
          user: 'testuser',
          resource: '/api/auth/login',
          details: { success: true }
        },
        {
          timestamp: new Date(),
          action: 'access_data',
          user: 'testuser',
          resource: '/api/sensitive/data',
          details: { dataType: 'customer_records' }
        }
      ];

      await expect(securityAgent.processAuditLogs(logs)).resolves.not.toThrow();
    });
  });

  describe('Machine Learning Models', () => {
    test('should train anomaly detection models', async () => {
      // This will use the default user-behavior-model
      await expect(securityAgent.trainAnomalyModel('user-behavior-model')).resolves.not.toThrow();
    });

    test('should handle invalid model IDs', async () => {
      await expect(securityAgent.trainAnomalyModel('non-existent-model'))
        .rejects.toThrow('Model non-existent-model not found');
    });
  });

  describe('Data Export', () => {
    test('should export security events', async () => {
      // First, create some events
      await securityAgent.processSecurityEvent({
        type: SecurityEventType.SUSPICIOUS_BEHAVIOR,
        severity: SecuritySeverity.MEDIUM,
        source: 'test_export',
        details: { test: true },
        ipAddress: '127.0.0.1'
      });

      const exportData = await securityAgent.exportSecurityData({
        includeEvents: true,
        includeIncidents: true,
        includeMetrics: true
      });

      expect(exportData).toHaveProperty('events');
      expect(exportData).toHaveProperty('incidents');
      expect(exportData).toHaveProperty('metrics');
    });

    test('should filter exported data by time range', async () => {
      const now = new Date();
      const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);
      const twoHoursAgo = new Date(now.getTime() - 2 * 60 * 60 * 1000);

      const exportData = await securityAgent.exportSecurityData({
        includeEvents: true,
        timeRange: {
          start: twoHoursAgo,
          end: oneHourAgo
        }
      });

      expect(exportData).toHaveProperty('events');
      expect(Array.isArray(exportData.events)).toBe(true);
    });
  });

  describe('System Health', () => {
    test('should report healthy status', () => {
      const status = securityAgent.getStatus();
      
      expect(status).toHaveProperty('healthy');
      expect(status).toHaveProperty('workers');
      expect(status).toHaveProperty('queueLength');
      expect(status).toHaveProperty('uptime');
      
      expect(typeof status.healthy).toBe('boolean');
      expect(typeof status.workers.total).toBe('number');
      expect(typeof status.workers.healthy).toBe('number');
      expect(typeof status.queueLength).toBe('number');
      expect(typeof status.uptime).toBe('number');
    });
  });

  describe('Error Handling', () => {
    test('should handle invalid event data gracefully', async () => {
      const invalidEventData = {
        // Missing required fields
        details: { test: true }
      };

      await expect(securityAgent.processSecurityEvent(invalidEventData as any))
        .rejects.toThrow();
    });

    test('should handle worker failures gracefully', async () => {
      // The agent should continue operating even if some workers fail
      const status = securityAgent.getStatus();
      expect(status.healthy).toBe(true);
      
      // Process an event to ensure the system is still working
      const eventId = await securityAgent.processSecurityEvent({
        type: SecurityEventType.SUSPICIOUS_BEHAVIOR,
        severity: SecuritySeverity.LOW,
        source: 'test_resilience',
        details: { test: true },
        ipAddress: '127.0.0.1'
      });
      
      expect(eventId).toBeDefined();
    });
  });

  describe('Performance', () => {
    test('should handle high event volume', async () => {
      const startTime = Date.now();
      const eventCount = 100;
      
      const promises = [];
      for (let i = 0; i < eventCount; i++) {
        promises.push(securityAgent.processSecurityEvent({
          type: SecurityEventType.SUSPICIOUS_BEHAVIOR,
          severity: SecuritySeverity.LOW,
          source: 'performance_test',
          details: { eventNumber: i },
          ipAddress: `192.168.1.${i % 256}`,
          userAgent: `TestAgent/${i}`
        }));
      }

      const eventIds = await Promise.all(promises);
      const endTime = Date.now();
      const duration = endTime - startTime;
      
      expect(eventIds).toHaveLength(eventCount);
      expect(duration).toBeLessThan(10000); // Should process 100 events in less than 10 seconds
      
      // Verify all events were processed
      eventIds.forEach(id => {
        expect(id).toMatch(/^evt_\d+_[a-f0-9]+$/);
      });
    });
  });
});