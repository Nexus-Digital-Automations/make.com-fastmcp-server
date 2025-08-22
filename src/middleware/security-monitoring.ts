/**
 * Advanced Security Monitoring and Metrics Collection
 * Real-time security metrics, alerting, and comprehensive audit logging
 * Phase 2 Security Enhancement Implementation
 */

import { EventEmitter } from 'events';
import logger from '../lib/logger.js';

// For Node.js fetch (18.0+ built-in, earlier versions need node-fetch)
declare const fetch: typeof global.fetch;

// Request interface for security middleware
interface HttpRequest {
  ip?: string;
  method?: string;
  url?: string;
  path?: string;
  headers: Record<string, string | string[] | undefined>;
  connection?: {
    remoteAddress?: string;
  };
  socket?: {
    remoteAddress?: string;
  };
  body?: unknown;
  user?: {
    id: string;
  };
  securityContext?: {
    correlationId: string;
    startTime: number;
    riskScore: number;
  };
}

// Response interface for middleware
interface HttpResponse {
  statusCode?: number;
  setHeader(name: string, value: string | number): void;
  status(code: number): HttpResponse;
  json(body: unknown): void;
  on(event: string, callback: () => void): void;
  locals?: Record<string, unknown>;
}

// Next function type
type NextFunction = (error?: unknown) => void;

// Security event types
export enum SecurityEventType {
  AUTHENTICATION_FAILURE = 'authentication_failure',
  AUTHORIZATION_FAILURE = 'authorization_failure',
  RATE_LIMIT_EXCEEDED = 'rate_limit_exceeded',
  DDOS_PROTECTION_TRIGGERED = 'ddos_protection_triggered',
  MALICIOUS_INPUT_DETECTED = 'malicious_input_detected',
  CIRCUIT_BREAKER_OPENED = 'circuit_breaker_opened',
  SUSPICIOUS_BEHAVIOR = 'suspicious_behavior',
  SECURITY_SCAN_COMPLETED = 'security_scan_completed',
  VULNERABILITY_DETECTED = 'vulnerability_detected',
  CSRF_TOKEN_INVALID = 'csrf_token_invalid',
  SQL_INJECTION_ATTEMPT = 'sql_injection_attempt',
  XSS_ATTEMPT = 'xss_attempt',
  FILE_UPLOAD_VIOLATION = 'file_upload_violation',
  IP_REPUTATION_CHANGE = 'ip_reputation_change'
}

// Security severity levels
export enum SecuritySeverity {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical'
}

// Security event interface
interface SecurityEvent {
  id: string;
  type: SecurityEventType;
  severity: SecuritySeverity;
  timestamp: Date;
  source: string;
  details: Record<string, unknown>;
  correlationId?: string;
  userId?: string;
  sessionId?: string;
  ipAddress?: string;
  userAgent?: string;
  resolved?: boolean;
  resolutionTime?: Date;
}

// Security metrics interface
interface SecurityMetrics {
  timestamp: Date;
  authenticationFailures: number;
  authorizationFailures: number;
  rateLimitViolations: number;
  ddosAttacks: number;
  maliciousInputs: number;
  circuitBreakerTrips: number;
  suspiciousBehavior: number;
  vulnerabilities: number;
  averageResponseTime: number;
  systemLoad: number;
  memoryUsage: number;
  activeConnections: number;
  blockedIPs: number;
  riskScore: number;
}

// Alert configuration interface
interface AlertConfig {
  type: SecurityEventType;
  severity: SecuritySeverity;
  threshold: number;
  timeWindow: number; // in milliseconds
  enabled: boolean;
  channels: string[]; // webhook URLs, email addresses, etc.
}

// Advanced security monitoring system
export class SecurityMonitoringSystem extends EventEmitter {
  private events: SecurityEvent[] = [];
  private metrics: SecurityMetrics[] = [];
  private alerts: AlertConfig[] = [];
  private eventCounts: Map<string, number> = new Map();
  private maxEventHistory = 10000;
  private maxMetricsHistory = 1440; // 24 hours at 1-minute intervals
  private metricsInterval!: NodeJS.Timeout;
  private currentMetrics: Partial<SecurityMetrics> = {};
  
  constructor() {
    super();
    this.setupDefaultAlerts();
    this.startMetricsCollection();
    this.setupEventCleanup();
  }
  
  private setupDefaultAlerts(): void {
    const defaultAlerts: AlertConfig[] = [
      {
        type: SecurityEventType.AUTHENTICATION_FAILURE,
        severity: SecuritySeverity.HIGH,
        threshold: 10,
        timeWindow: 5 * 60 * 1000, // 5 minutes
        enabled: true,
        channels: []
      },
      {
        type: SecurityEventType.DDOS_PROTECTION_TRIGGERED,
        severity: SecuritySeverity.CRITICAL,
        threshold: 1,
        timeWindow: 60 * 1000, // 1 minute
        enabled: true,
        channels: []
      },
      {
        type: SecurityEventType.MALICIOUS_INPUT_DETECTED,
        severity: SecuritySeverity.HIGH,
        threshold: 5,
        timeWindow: 10 * 60 * 1000, // 10 minutes
        enabled: true,
        channels: []
      },
      {
        type: SecurityEventType.CIRCUIT_BREAKER_OPENED,
        severity: SecuritySeverity.MEDIUM,
        threshold: 1,
        timeWindow: 5 * 60 * 1000, // 5 minutes
        enabled: true,
        channels: []
      },
      {
        type: SecurityEventType.VULNERABILITY_DETECTED,
        severity: SecuritySeverity.CRITICAL,
        threshold: 1,
        timeWindow: 1000, // Immediate
        enabled: true,
        channels: []
      }
    ];
    
    this.alerts = defaultAlerts;
  }
  
  private startMetricsCollection(): void {
    // Collect metrics every minute
    this.metricsInterval = setInterval(() => {
      this.collectMetrics();
    }, 60 * 1000);
    
    // Initial collection
    this.collectMetrics();
  }
  
  private collectMetrics(): void {
    const now = new Date();
    const oneMinuteAgo = new Date(now.getTime() - 60 * 1000);
    
    // Count events in the last minute
    const recentEvents = this.events.filter(event => event.timestamp >= oneMinuteAgo);
    
    const metrics: SecurityMetrics = {
      timestamp: now,
      authenticationFailures: recentEvents.filter(e => e.type === SecurityEventType.AUTHENTICATION_FAILURE).length,
      authorizationFailures: recentEvents.filter(e => e.type === SecurityEventType.AUTHORIZATION_FAILURE).length,
      rateLimitViolations: recentEvents.filter(e => e.type === SecurityEventType.RATE_LIMIT_EXCEEDED).length,
      ddosAttacks: recentEvents.filter(e => e.type === SecurityEventType.DDOS_PROTECTION_TRIGGERED).length,
      maliciousInputs: recentEvents.filter(e => e.type === SecurityEventType.MALICIOUS_INPUT_DETECTED).length,
      circuitBreakerTrips: recentEvents.filter(e => e.type === SecurityEventType.CIRCUIT_BREAKER_OPENED).length,
      suspiciousBehavior: recentEvents.filter(e => e.type === SecurityEventType.SUSPICIOUS_BEHAVIOR).length,
      vulnerabilities: recentEvents.filter(e => e.type === SecurityEventType.VULNERABILITY_DETECTED).length,
      averageResponseTime: this.currentMetrics.averageResponseTime || 0,
      systemLoad: this.getSystemLoad(),
      memoryUsage: this.getMemoryUsage(),
      activeConnections: this.currentMetrics.activeConnections || 0,
      blockedIPs: this.currentMetrics.blockedIPs || 0,
      riskScore: this.calculateRiskScore(recentEvents)
    };
    
    this.metrics.push(metrics);
    
    // Keep only recent metrics
    if (this.metrics.length > this.maxMetricsHistory) {
      this.metrics = this.metrics.slice(-this.maxMetricsHistory);
    }
    
    // Emit metrics event
    this.emit('metrics', metrics);
    
    // Log metrics for external monitoring systems
    logger.info('Security metrics collected', {
      timestamp: metrics.timestamp,
      authFailures: metrics.authenticationFailures,
      rateLimitViolations: metrics.rateLimitViolations,
      ddosAttacks: metrics.ddosAttacks,
      riskScore: metrics.riskScore,
      systemLoad: metrics.systemLoad,
      memoryUsage: metrics.memoryUsage
    });
  }
  
  private getSystemLoad(): number {
    const cpuUsage = process.cpuUsage();
    return (cpuUsage.user + cpuUsage.system) / 1000000; // Convert to seconds
  }
  
  private getMemoryUsage(): number {
    const memUsage = process.memoryUsage();
    return (memUsage.heapUsed / memUsage.heapTotal) * 100; // Percentage
  }
  
  private calculateRiskScore(events: SecurityEvent[]): number {
    if (events.length === 0) return 0;
    
    let riskScore = 0;
    const weights = {
      [SecuritySeverity.LOW]: 0.1,
      [SecuritySeverity.MEDIUM]: 0.3,
      [SecuritySeverity.HIGH]: 0.6,
      [SecuritySeverity.CRITICAL]: 1.0
    };
    
    events.forEach(event => {
      riskScore += weights[event.severity];
    });
    
    // Normalize to 0-100 scale
    return Math.min(riskScore * 10, 100);
  }
  
  private setupEventCleanup(): void {
    // Clean up old events every hour
    setInterval(() => {
      const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000); // 24 hours ago
      this.events = this.events.filter(event => event.timestamp >= cutoff);
      
      // Keep only the most recent events if we have too many
      if (this.events.length > this.maxEventHistory) {
        this.events = this.events.slice(-this.maxEventHistory);
      }
    }, 60 * 60 * 1000);
  }
  
  public recordSecurityEvent(
    type: SecurityEventType,
    severity: SecuritySeverity,
    source: string,
    details: Record<string, unknown>,
    context?: {
      correlationId?: string;
      userId?: string;
      sessionId?: string;
      ipAddress?: string;
      userAgent?: string;
    }
  ): string {
    const eventId = this.generateEventId();
    
    const event: SecurityEvent = {
      id: eventId,
      type,
      severity,
      timestamp: new Date(),
      source,
      details: this.sanitizeEventDetails(details),
      ...context
    };
    
    this.events.push(event);
    
    // Update event counts for alerting
    const countKey = `${type}:${Math.floor(Date.now() / 60000)}`; // Per-minute buckets
    this.eventCounts.set(countKey, (this.eventCounts.get(countKey) || 0) + 1);
    
    // Check for alerts
    this.checkAlerts(type);
    
    // Emit event
    this.emit('securityEvent', event);
    
    // Log the event
    logger.warn('Security event recorded', {
      eventId,
      type,
      severity,
      source,
      correlationId: context?.correlationId,
      ipAddress: context?.ipAddress ? this.hashIP(context.ipAddress) : undefined
    });
    
    return eventId;
  }
  
  private generateEventId(): string {
    return `sec_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
  
  private sanitizeEventDetails(details: Record<string, unknown>): Record<string, unknown> {
    const sanitized: Record<string, unknown> = {};
    
    for (const [key, value] of Object.entries(details)) {
      if (typeof value === 'string') {
        // Remove potential secrets and sensitive data
        if (/password|secret|token|key|auth/i.test(key)) {
          sanitized[key] = '[REDACTED]';
        } else {
          sanitized[key] = value.substring(0, 1000); // Limit string length
        }
      } else if (typeof value === 'object' && value !== null) {
        sanitized[key] = '[OBJECT]';
      } else {
        sanitized[key] = value;
      }
    }
    
    return sanitized;
  }
  
  private checkAlerts(eventType: SecurityEventType): void {
    const relevantAlerts = this.alerts.filter(alert => 
      alert.enabled && alert.type === eventType
    );
    
    relevantAlerts.forEach(alert => {
      const windowStart = Math.floor((Date.now() - alert.timeWindow) / 60000);
      const windowEnd = Math.floor(Date.now() / 60000);
      
      let eventCount = 0;
      for (let minute = windowStart; minute <= windowEnd; minute++) {
        const countKey = `${eventType}:${minute}`;
        eventCount += this.eventCounts.get(countKey) || 0;
      }
      
      if (eventCount >= alert.threshold) {
        this.triggerAlert(alert, eventCount);
      }
    });
  }
  
  private triggerAlert(alert: AlertConfig, eventCount: number): void {
    const alertEvent = {
      id: this.generateEventId(),
      type: 'SECURITY_ALERT',
      severity: alert.severity,
      message: `Security alert triggered: ${alert.type}`,
      eventCount,
      threshold: alert.threshold,
      timeWindow: alert.timeWindow,
      timestamp: new Date()
    };
    
    logger.error('Security alert triggered', alertEvent);
    
    // Emit alert event
    this.emit('securityAlert', alertEvent);
    
    // Send to configured channels (implement webhook/email sending here)
    alert.channels.forEach(channel => {
      this.sendAlertToChannel(channel, alertEvent);
    });
  }
  
  private async sendAlertToChannel(channel: string, alert: unknown): Promise<void> {
    try {
      if (channel.startsWith('http')) {
        // Webhook notification
        const response = await fetch(channel, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'User-Agent': 'MakeServer-SecurityMonitoring/1.0'
          },
          body: JSON.stringify(alert)
        });
        
        if (!response.ok) {
          throw new Error(`Webhook failed: ${response.status}`);
        }
      } else if (channel.includes('@')) {
        // Email notification (placeholder - implement with your email service)
        logger.info('Email alert would be sent', { 
          email: channel, 
          alertType: alert.type 
        });
      }
    } catch (error) {
      logger.error('Failed to send alert to channel', {
        channel: channel.substring(0, 50),
        error: error instanceof Error ? error.message : String(error)
      });
    }
  }
  
  private hashIP(ip: string): string {
    const crypto = require('crypto');
    return crypto.createHash('sha256')
      .update(ip + (process.env.IP_HASH_SALT || 'default-salt'))
      .digest('hex')
      .substring(0, 16);
  }
  
  public updateMetric(key: Exclude<keyof SecurityMetrics, 'timestamp'>, value: number): void {
    this.currentMetrics[key] = value;
  }
  
  public getRecentEvents(limit: number = 100): SecurityEvent[] {
    return this.events.slice(-limit);
  }
  
  public getEventsByType(type: SecurityEventType, limit: number = 100): SecurityEvent[] {
    return this.events
      .filter(event => event.type === type)
      .slice(-limit);
  }
  
  public getMetrics(hours: number = 1): SecurityMetrics[] {
    const cutoff = new Date(Date.now() - hours * 60 * 60 * 1000);
    return this.metrics.filter(metric => metric.timestamp >= cutoff);
  }
  
  public getSecuritySummary(): {
    totalEvents: number;
    eventsByType: Record<string, number>;
    eventsBySeverity: Record<string, number>;
    currentRiskScore: number;
    activeAlerts: number;
    lastMetrics?: SecurityMetrics;
  } {
    const eventsByType: Record<string, number> = {};
    const eventsBySeverity: Record<string, number> = {};
    
    this.events.forEach(event => {
      eventsByType[event.type] = (eventsByType[event.type] || 0) + 1;
      eventsBySeverity[event.severity] = (eventsBySeverity[event.severity] || 0) + 1;
    });
    
    const lastMetrics = this.metrics[this.metrics.length - 1];
    
    return {
      totalEvents: this.events.length,
      eventsByType,
      eventsBySeverity,
      currentRiskScore: lastMetrics?.riskScore || 0,
      activeAlerts: this.alerts.filter(alert => alert.enabled).length,
      lastMetrics
    };
  }
  
  public configureAlert(config: AlertConfig): void {
    const existingIndex = this.alerts.findIndex(alert => 
      alert.type === config.type && alert.severity === config.severity
    );
    
    if (existingIndex >= 0) {
      this.alerts[existingIndex] = config;
    } else {
      this.alerts.push(config);
    }
    
    logger.info('Security alert configured', {
      type: config.type,
      severity: config.severity,
      threshold: config.threshold,
      enabled: config.enabled
    });
  }
  
  public shutdown(): void {
    if (this.metricsInterval) {
      clearInterval(this.metricsInterval);
    }
    
    this.removeAllListeners();
    logger.info('Security monitoring system shut down');
  }
}

// Singleton instance
export const securityMonitoring = new SecurityMonitoringSystem();

// Middleware for automatic security event recording
export function createSecurityMonitoringMiddleware(): (req: HttpRequest, res: HttpResponse, next: NextFunction) => void {
  return (req: HttpRequest, res: HttpResponse, next: NextFunction): void => {
    const startTime = Date.now();
    
    // Record request start
    req.securityContext = {
      correlationId: req.headers['x-correlation-id'] || securityMonitoring['generateEventId'](),
      startTime,
      ipAddress: req.ip || req.connection?.remoteAddress,
      userAgent: req.headers['user-agent']
    };
    
    // Track response completion
    res.on('finish', () => {
      const responseTime = Date.now() - startTime;
      
      // Update response time metric
      securityMonitoring.updateMetric('averageResponseTime', responseTime);
      
      // Record security events based on response status
      if (res.statusCode === 401) {
        securityMonitoring.recordSecurityEvent(
          SecurityEventType.AUTHENTICATION_FAILURE,
          SecuritySeverity.MEDIUM,
          'auth_middleware',
          {
            endpoint: req.path,
            method: req.method,
            statusCode: res.statusCode
          },
          req.securityContext
        );
      } else if (res.statusCode === 403) {
        securityMonitoring.recordSecurityEvent(
          SecurityEventType.AUTHORIZATION_FAILURE,
          SecuritySeverity.MEDIUM,
          'auth_middleware',
          {
            endpoint: req.path,
            method: req.method,
            statusCode: res.statusCode
          },
          req.securityContext
        );
      } else if (res.statusCode === 429) {
        securityMonitoring.recordSecurityEvent(
          SecurityEventType.RATE_LIMIT_EXCEEDED,
          SecuritySeverity.HIGH,
          'rate_limiter',
          {
            endpoint: req.path,
            method: req.method,
            statusCode: res.statusCode
          },
          req.securityContext
        );
      }
    });
    
    next();
  };
}

// Utility functions for manual event recording
export function recordAuthenticationFailure(details: Record<string, unknown>, context?: Record<string, unknown>): string {
  return securityMonitoring.recordSecurityEvent(
    SecurityEventType.AUTHENTICATION_FAILURE,
    SecuritySeverity.HIGH,
    'authentication',
    details,
    context
  );
}

export function recordMaliciousInput(details: Record<string, unknown>, context?: Record<string, unknown>): string {
  return securityMonitoring.recordSecurityEvent(
    SecurityEventType.MALICIOUS_INPUT_DETECTED,
    SecuritySeverity.HIGH,
    'input_validation',
    details,
    context
  );
}

export function recordSuspiciousBehavior(details: Record<string, unknown>, context?: Record<string, unknown>): string {
  return securityMonitoring.recordSecurityEvent(
    SecurityEventType.SUSPICIOUS_BEHAVIOR,
    SecuritySeverity.MEDIUM,
    'behavior_analysis',
    details,
    context
  );
}

export function recordVulnerability(details: Record<string, unknown>, context?: Record<string, unknown>): string {
  return securityMonitoring.recordSecurityEvent(
    SecurityEventType.VULNERABILITY_DETECTED,
    SecuritySeverity.CRITICAL,
    'vulnerability_scanner',
    details,
    context
  );
}