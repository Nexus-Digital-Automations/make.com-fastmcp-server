/**
 * Concurrent Security Monitoring Agent
 * Advanced security monitoring with real-time threat detection, anomaly analysis, 
 * audit trail processing, and SIEM integration using Worker Threads
 */

import { Worker, isMainThread, parentPort, workerData } from 'worker_threads';
import { EventEmitter } from 'events';
import { createHash, randomBytes } from 'crypto';
import { writeFile, mkdir } from 'fs/promises';
import { join } from 'path';
import logger from '../lib/logger.js';
import { SecurityEventType, SecuritySeverity } from '../middleware/security-monitoring.js';

// Security monitoring types and interfaces
export interface SecurityEvent {
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
  geoLocation?: GeoLocation;
  deviceFingerprint?: string;
  threatScore: number;
  mitigationActions: string[];
}

export interface GeoLocation {
  country: string;
  region: string;
  city: string;
  latitude: number;
  longitude: number;
  timezone: string;
  isp: string;
}

export interface SecurityPattern {
  id: string;
  name: string;
  type: 'behavioral' | 'signature' | 'statistical' | 'ml_based';
  patterns: string[];
  thresholds: Record<string, number>;
  severity: SecuritySeverity;
  enabled: boolean;
  falsePositiveRate: number;
  lastUpdated: Date;
}

export interface ThreatIntelligence {
  id: string;
  type: 'ip' | 'domain' | 'hash' | 'pattern';
  value: string;
  severity: SecuritySeverity;
  source: string;
  firstSeen: Date;
  lastSeen: Date;
  confidence: number;
  tags: string[];
  references: string[];
}

export interface SecurityIncident {
  id: string;
  title: string;
  description: string;
  severity: SecuritySeverity;
  status: 'open' | 'investigating' | 'contained' | 'resolved';
  events: string[];
  assignee?: string;
  createdAt: Date;
  updatedAt: Date;
  responseTime: number;
  containmentTime?: number;
  resolutionTime?: number;
  mitigationActions: string[];
  rootCause?: string;
  lessonsLearned?: string[];
}

export interface SecurityMetrics {
  timestamp: Date;
  eventsProcessed: number;
  threatsDetected: number;
  incidentsCreated: number;
  falsePositives: number;
  responseTime: number;
  throughput: number;
  riskScore: number;
  systemHealth: number;
}

export interface AnomalyDetectionModel {
  id: string;
  name: string;
  type: 'statistical' | 'ml' | 'behavioral';
  features: string[];
  parameters: Record<string, unknown>;
  accuracy: number;
  lastTrained: Date;
  trainingDataSize: number;
  modelFile?: string;
}

// Worker thread types
interface WorkerMessage {
  type: 'analyze_event' | 'detect_anomaly' | 'process_logs' | 'update_threat_intel' | 'train_model';
  data: unknown;
  id: string;
}

interface WorkerResponse {
  type: string;
  data: unknown;
  id: string;
  error?: string;
}

/**
 * Main Concurrent Security Monitoring Agent
 * Orchestrates multiple worker threads for parallel security analysis
 */
export class ConcurrentSecurityAgent extends EventEmitter {
  private readonly workers: Map<string, Worker> = new Map();
  private readonly maxWorkers: number = 8;
  private readonly workerPool: Worker[] = [];
  private readonly taskQueue: WorkerMessage[] = [];
  private readonly pendingTasks: Map<string, { resolve: Function; reject: Function }> = new Map();
  private readonly securityEvents: Map<string, SecurityEvent> = new Map();
  private readonly incidents: Map<string, SecurityIncident> = new Map();
  private readonly patterns: Map<string, SecurityPattern> = new Map();
  private readonly threatIntel: Map<string, ThreatIntelligence> = new Map();
  private readonly anomalyModels: Map<string, AnomalyDetectionModel> = new Map();
  private metrics: SecurityMetrics[] = [];
  private isShutdown: boolean = false;
  private metricsInterval?: NodeJS.Timeout;

  constructor() {
    super();
    this.initialize();
  }

  private async initialize(): Promise<void> {
    try {
      // Initialize worker pool
      await this.createWorkerPool();
      
      // Load security patterns and threat intelligence
      await this.loadSecurityPatterns();
      await this.loadThreatIntelligence();
      await this.loadAnomalyModels();
      
      // Start metrics collection
      this.startMetricsCollection();
      
      logger.info('Concurrent Security Agent initialized', {
        workers: this.workerPool.length,
        patterns: this.patterns.size,
        threatIntel: this.threatIntel.size,
        models: this.anomalyModels.size
      });
    } catch (error) {
      logger.error('Failed to initialize Concurrent Security Agent', {
        error: error instanceof Error ? error.message : String(error)
      });
      throw error;
    }
  }

  private async createWorkerPool(): Promise<void> {
    for (let i = 0; i < this.maxWorkers; i++) {
      const worker = new Worker(new URL('./security-worker.js', import.meta.url), {
        workerData: { workerId: i }
      });

      worker.on('message', (message: WorkerResponse) => {
        this.handleWorkerMessage(message);
      });

      worker.on('error', (error) => {
        logger.error(`Security worker ${i} error`, { error: error.message });
        this.replaceWorker(i);
      });

      worker.on('exit', (code) => {
        if (code !== 0 && !this.isShutdown) {
          logger.warn(`Security worker ${i} stopped with exit code ${code}`);
          this.replaceWorker(i);
        }
      });

      this.workerPool.push(worker);
      this.workers.set(`worker-${i}`, worker);
    }
  }

  private replaceWorker(index: number): void {
    if (this.isShutdown) {return;}

    const oldWorker = this.workerPool[index];
    if (oldWorker) {
      oldWorker.terminate();
    }

    const newWorker = new Worker(new URL('./security-worker.js', import.meta.url), {
      workerData: { workerId: index }
    });

    newWorker.on('message', (message: WorkerResponse) => {
      this.handleWorkerMessage(message);
    });

    newWorker.on('error', (error) => {
      logger.error(`Replacement security worker ${index} error`, { error: error.message });
    });

    this.workerPool[index] = newWorker;
    this.workers.set(`worker-${index}`, newWorker);
  }

  private handleWorkerMessage(message: WorkerResponse): void {
    const pendingTask = this.pendingTasks.get(message.id);
    if (pendingTask) {
      this.pendingTasks.delete(message.id);
      
      if (message.error) {
        pendingTask.reject(new Error(message.error));
      } else {
        pendingTask.resolve(message.data);
      }
    }
  }

  private async loadSecurityPatterns(): Promise<void> {
    // Load default security patterns for threat detection
    const defaultPatterns: SecurityPattern[] = [
      {
        id: 'brute-force-login',
        name: 'Brute Force Login Attempts',
        type: 'behavioral',
        patterns: ['failed_login_attempts'],
        thresholds: { attempts: 5, timeWindow: 300000 }, // 5 attempts in 5 minutes
        severity: SecuritySeverity.HIGH,
        enabled: true,
        falsePositiveRate: 0.01,
        lastUpdated: new Date()
      },
      {
        id: 'credential-stuffing',
        name: 'Credential Stuffing Attack',
        type: 'behavioral',
        patterns: ['multiple_account_attempts', 'distributed_ips'],
        thresholds: { accounts: 10, timeWindow: 600000 }, // 10 accounts in 10 minutes
        severity: SecuritySeverity.CRITICAL,
        enabled: true,
        falsePositiveRate: 0.005,
        lastUpdated: new Date()
      },
      {
        id: 'privilege-escalation',
        name: 'Privilege Escalation Attempt',
        type: 'behavioral',
        patterns: ['permission_changes', 'admin_access_attempts'],
        thresholds: { changes: 3, timeWindow: 600000 },
        severity: SecuritySeverity.CRITICAL,
        enabled: true,
        falsePositiveRate: 0.02,
        lastUpdated: new Date()
      },
      {
        id: 'data-exfiltration',
        name: 'Data Exfiltration Pattern',
        type: 'behavioral',
        patterns: ['large_data_access', 'unusual_download_patterns'],
        thresholds: { dataSize: 1000000, requests: 50 }, // 1MB or 50 requests
        severity: SecuritySeverity.CRITICAL,
        enabled: true,
        falsePositiveRate: 0.03,
        lastUpdated: new Date()
      },
      {
        id: 'api-abuse',
        name: 'API Abuse Pattern',
        type: 'statistical',
        patterns: ['rate_limit_exceeded', 'abnormal_request_patterns'],
        thresholds: { requests: 1000, timeWindow: 300000 }, // 1000 requests in 5 minutes
        severity: SecuritySeverity.HIGH,
        enabled: true,
        falsePositiveRate: 0.02,
        lastUpdated: new Date()
      }
    ];

    defaultPatterns.forEach(pattern => {
      this.patterns.set(pattern.id, pattern);
    });
  }

  private async loadThreatIntelligence(): Promise<void> {
    // Load threat intelligence feeds
    // In production, this would connect to external threat intelligence sources
    const defaultThreatIntel: ThreatIntelligence[] = [
      {
        id: 'tor-exit-nodes',
        type: 'ip',
        value: 'tor_exit_node_ranges',
        severity: SecuritySeverity.MEDIUM,
        source: 'tor_project',
        firstSeen: new Date(),
        lastSeen: new Date(),
        confidence: 0.95,
        tags: ['anonymization', 'privacy', 'suspicious'],
        references: ['https://check.torproject.org/']
      }
    ];

    defaultThreatIntel.forEach(intel => {
      this.threatIntel.set(intel.id, intel);
    });
  }

  private async loadAnomalyModels(): Promise<void> {
    // Initialize anomaly detection models
    const defaultModels: AnomalyDetectionModel[] = [
      {
        id: 'user-behavior-model',
        name: 'User Behavior Anomaly Detection',
        type: 'behavioral',
        features: ['login_time', 'ip_address', 'user_agent', 'access_patterns'],
        parameters: {
          threshold: 0.7,
          lookbackWindow: 7 * 24 * 60 * 60 * 1000, // 7 days
          minDataPoints: 50
        },
        accuracy: 0.85,
        lastTrained: new Date(),
        trainingDataSize: 10000
      },
      {
        id: 'network-traffic-model',
        name: 'Network Traffic Anomaly Detection',
        type: 'statistical',
        features: ['request_rate', 'response_size', 'error_rate', 'geographic_distribution'],
        parameters: {
          threshold: 0.8,
          window: 300000, // 5 minutes
          minSamples: 100
        },
        accuracy: 0.92,
        lastTrained: new Date(),
        trainingDataSize: 50000
      }
    ];

    defaultModels.forEach(model => {
      this.anomalyModels.set(model.id, model);
    });
  }

  private startMetricsCollection(): void {
    this.metricsInterval = setInterval(() => {
      this.collectMetrics();
    }, 60000); // Every minute
  }

  private collectMetrics(): void {
    const now = new Date();
    const oneMinuteAgo = new Date(now.getTime() - 60000);

    const recentEvents = Array.from(this.securityEvents.values())
      .filter(event => event.timestamp >= oneMinuteAgo);

    const metrics: SecurityMetrics = {
      timestamp: now,
      eventsProcessed: recentEvents.length,
      threatsDetected: recentEvents.filter(e => e.threatScore > 0.7).length,
      incidentsCreated: Array.from(this.incidents.values())
        .filter(i => i.createdAt >= oneMinuteAgo).length,
      falsePositives: 0, // Calculate based on resolved incidents
      responseTime: this.calculateAverageResponseTime(),
      throughput: recentEvents.length,
      riskScore: this.calculateRiskScore(recentEvents),
      systemHealth: this.calculateSystemHealth()
    };

    this.metrics.push(metrics);

    // Keep only last hour of metrics
    if (this.metrics.length > 60) {
      this.metrics = this.metrics.slice(-60);
    }

    this.emit('metrics', metrics);
  }

  private calculateAverageResponseTime(): number {
    const recentIncidents = Array.from(this.incidents.values())
      .filter(i => i.responseTime > 0)
      .slice(-10); // Last 10 incidents

    if (recentIncidents.length === 0) {return 0;}

    return recentIncidents.reduce((sum, incident) => sum + incident.responseTime, 0) / recentIncidents.length;
  }

  private calculateRiskScore(events: SecurityEvent[]): number {
    if (events.length === 0) {return 0;}

    const weightedScore = events.reduce((sum, event) => {
      const severityWeight = {
        [SecuritySeverity.LOW]: 0.1,
        [SecuritySeverity.MEDIUM]: 0.3,
        [SecuritySeverity.HIGH]: 0.7,
        [SecuritySeverity.CRITICAL]: 1.0
      };
      return sum + (event.threatScore * severityWeight[event.severity]);
    }, 0);

    return Math.min(weightedScore / events.length * 100, 100);
  }

  private calculateSystemHealth(): number {
    const workingWorkers = this.workerPool.filter(worker => !worker.exitCode).length;
    const workerHealth = workingWorkers / this.maxWorkers;
    
    const queueHealth = Math.max(0, 1 - (this.taskQueue.length / 1000));
    
    const memoryUsage = process.memoryUsage();
    const memoryHealth = 1 - (memoryUsage.heapUsed / memoryUsage.heapTotal);

    return (workerHealth + queueHealth + memoryHealth) / 3 * 100;
  }

  /**
   * Process a security event through the concurrent analysis pipeline
   */
  public async processSecurityEvent(event: Omit<SecurityEvent, 'id' | 'timestamp' | 'threatScore' | 'mitigationActions'>): Promise<string> {
    const eventId = this.generateEventId();
    const timestamp = new Date();

    const securityEvent: SecurityEvent = {
      id: eventId,
      timestamp,
      threatScore: 0,
      mitigationActions: [],
      ...event
    };

    // Store event
    this.securityEvents.set(eventId, securityEvent);

    try {
      // Concurrent analysis
      const [threatAnalysis, anomalyAnalysis, patternMatches] = await Promise.all([
        this.analyzeEventThreat(securityEvent),
        this.detectAnomalies(securityEvent),
        this.matchSecurityPatterns(securityEvent)
      ]);

      // Update event with analysis results
      securityEvent.threatScore = Math.max(threatAnalysis.score, anomalyAnalysis.score);
      securityEvent.mitigationActions = [
        ...threatAnalysis.actions,
        ...anomalyAnalysis.actions,
        ...patternMatches.actions
      ];

      // Create incident if high threat score
      if (securityEvent.threatScore > 0.7) {
        await this.createSecurityIncident(securityEvent, {
          threatAnalysis,
          anomalyAnalysis,
          patternMatches
        });
      }

      // Emit events for external systems
      this.emit('securityEvent', securityEvent);

      if (securityEvent.threatScore > 0.5) {
        this.emit('threat', securityEvent);
      }

      return eventId;
    } catch (error) {
      logger.error('Failed to process security event', {
        eventId,
        error: error instanceof Error ? error.message : String(error)
      });
      throw error;
    }
  }

  private async analyzeEventThreat(event: SecurityEvent): Promise<{ score: number; actions: string[] }> {
    const taskId = this.generateTaskId();
    
    return new Promise((resolve, reject) => {
      this.pendingTasks.set(taskId, { resolve, reject });
      
      const message: WorkerMessage = {
        type: 'analyze_event',
        data: {
          event,
          threatIntel: Array.from(this.threatIntel.values()),
          patterns: Array.from(this.patterns.values())
        },
        id: taskId
      };

      this.executeTask(message);
    });
  }

  private async detectAnomalies(event: SecurityEvent): Promise<{ score: number; actions: string[] }> {
    const taskId = this.generateTaskId();
    
    return new Promise((resolve, reject) => {
      this.pendingTasks.set(taskId, { resolve, reject });
      
      const message: WorkerMessage = {
        type: 'detect_anomaly',
        data: {
          event,
          models: Array.from(this.anomalyModels.values()),
          historicalEvents: Array.from(this.securityEvents.values()).slice(-1000)
        },
        id: taskId
      };

      this.executeTask(message);
    });
  }

  private async matchSecurityPatterns(event: SecurityEvent): Promise<{ score: number; actions: string[] }> {
    let maxScore = 0;
    const actions: string[] = [];

    for (const pattern of this.patterns.values()) {
      if (!pattern.enabled) {continue;}

      const matches = this.evaluatePattern(event, pattern);
      if (matches.score > maxScore) {
        maxScore = matches.score;
      }
      actions.push(...matches.actions);
    }

    return { score: maxScore, actions };
  }

  private evaluatePattern(event: SecurityEvent, pattern: SecurityPattern): { score: number; actions: string[] } {
    // Simplified pattern matching - in production this would be more sophisticated
    const actions: string[] = [];
    let score = 0;

    switch (pattern.type) {
      case 'behavioral':
        score = this.evaluateBehavioralPattern(event, pattern);
        break;
      case 'signature':
        score = this.evaluateSignaturePattern(event, pattern);
        break;
      case 'statistical':
        score = this.evaluateStatisticalPattern(event, pattern);
        break;
      default:
        score = 0;
    }

    if (score > 0.5) {
      actions.push(`Pattern matched: ${pattern.name}`);
      if (score > 0.8) {
        actions.push('Immediate investigation required');
      }
    }

    return { score, actions };
  }

  private evaluateBehavioralPattern(event: SecurityEvent, pattern: SecurityPattern): number {
    // Behavioral pattern evaluation logic
    if (pattern.id === 'brute-force-login' && event.type === SecurityEventType.AUTHENTICATION_FAILURE) {
      const recentFailures = Array.from(this.securityEvents.values())
        .filter(e => 
          e.type === SecurityEventType.AUTHENTICATION_FAILURE &&
          e.ipAddress === event.ipAddress &&
          e.timestamp.getTime() > Date.now() - (pattern.thresholds.timeWindow)
        );
      
      return recentFailures.length >= (pattern.thresholds.attempts) ? 0.9 : 0;
    }

    return 0;
  }

  private evaluateSignaturePattern(event: SecurityEvent, pattern: SecurityPattern): number {
    // Signature-based pattern matching
    return 0;
  }

  private evaluateStatisticalPattern(event: SecurityEvent, pattern: SecurityPattern): number {
    // Statistical anomaly detection
    return 0;
  }

  private async createSecurityIncident(event: SecurityEvent, analysis: {
    threatAnalysis: { score: number; actions: string[] };
    anomalyAnalysis: { score: number; actions: string[] };
    patternMatches: { score: number; actions: string[] };
  }): Promise<string> {
    const incidentId = this.generateIncidentId();
    const now = new Date();

    const incident: SecurityIncident = {
      id: incidentId,
      title: `Security Incident - ${event.type}`,
      description: `High-risk security event detected: ${event.details}`,
      severity: event.severity,
      status: 'open',
      events: [event.id],
      createdAt: now,
      updatedAt: now,
      responseTime: 0, // Will be updated when first response action is taken
      mitigationActions: [
        ...analysis.threatAnalysis.actions,
        ...analysis.anomalyAnalysis.actions,
        ...analysis.patternMatches.actions
      ]
    };

    this.incidents.set(incidentId, incident);

    // Emit incident for external systems (SIEM, SOAR)
    this.emit('incident', incident);

    logger.warn('Security incident created', {
      incidentId,
      eventId: event.id,
      severity: event.severity,
      threatScore: event.threatScore,
      actions: incident.mitigationActions
    });

    return incidentId;
  }

  private executeTask(message: WorkerMessage): void {
    if (this.taskQueue.length > 10000) {
      // Queue is full, reject oldest tasks
      const oldTask = this.taskQueue.shift();
      if (oldTask) {
        const pendingTask = this.pendingTasks.get(oldTask.id);
        if (pendingTask) {
          this.pendingTasks.delete(oldTask.id);
          pendingTask.reject(new Error('Task queue overflow'));
        }
      }
    }

    this.taskQueue.push(message);
    this.processTaskQueue();
  }

  private processTaskQueue(): void {
    if (this.taskQueue.length === 0) {return;}

    const availableWorker = this.workerPool.find(worker => !worker.exitCode);
    if (availableWorker && this.taskQueue.length > 0) {
      const task = this.taskQueue.shift();
      if (task) {
        availableWorker.postMessage(task);
      }
    }

    // Schedule next processing cycle
    if (this.taskQueue.length > 0) {
      setImmediate(() => this.processTaskQueue());
    }
  }

  /**
   * SIEM Integration Methods
   */
  public async sendToSIEM(event: SecurityEvent): Promise<void> {
    // Integration with SIEM systems (Splunk, SentinelOne, etc.)
    const siemEvent = {
      timestamp: event.timestamp.toISOString(),
      source: 'make-fastmcp-security-agent',
      eventType: event.type,
      severity: event.severity,
      threatScore: event.threatScore,
      sourceIP: event.ipAddress,
      userAgent: event.userAgent,
      correlationId: event.correlationId,
      details: event.details,
      mitigationActions: event.mitigationActions
    };

    // In production, this would send to actual SIEM endpoints
    this.emit('siemEvent', siemEvent);
    
    logger.info('Event sent to SIEM', {
      eventId: event.id,
      siemTimestamp: siemEvent.timestamp
    });
  }

  public async queryThreatIntelligence(indicators: { type: string; value: string }[]): Promise<ThreatIntelligence[]> {
    const matches: ThreatIntelligence[] = [];
    
    for (const indicator of indicators) {
      for (const intel of this.threatIntel.values()) {
        if (intel.type === indicator.type && this.matchesPattern(intel.value, indicator.value)) {
          matches.push(intel);
        }
      }
    }

    return matches;
  }

  private matchesPattern(pattern: string, value: string): boolean {
    // Simplified pattern matching - in production this would use more sophisticated algorithms
    return pattern === value || pattern.includes('*') && value.includes(pattern.replace('*', ''));
  }

  /**
   * Audit Trail Processing
   */
  public async processAuditLogs(logs: Array<{ timestamp: Date; action: string; user: string; resource: string; details: Record<string, unknown> }>): Promise<void> {
    const taskId = this.generateTaskId();
    
    return new Promise((resolve, reject) => {
      this.pendingTasks.set(taskId, { resolve, reject });
      
      const message: WorkerMessage = {
        type: 'process_logs',
        data: {
          logs,
          patterns: Array.from(this.patterns.values())
        },
        id: taskId
      };

      this.executeTask(message);
    });
  }

  /**
   * Compliance Monitoring
   */
  public async validateCompliance(framework: string): Promise<{
    compliant: boolean;
    violations: Array<{ control: string; severity: string; description: string }>;
    recommendations: string[];
  }> {
    const violations: Array<{ control: string; severity: string; description: string }> = [];
    const recommendations: string[] = [];

    // Check for compliance violations based on security events
    const recentEvents = Array.from(this.securityEvents.values())
      .filter(event => event.timestamp.getTime() > Date.now() - 24 * 60 * 60 * 1000); // Last 24 hours

    // Example compliance checks
    const criticalEvents = recentEvents.filter(e => e.severity === SecuritySeverity.CRITICAL);
    if (criticalEvents.length > 0) {
      violations.push({
        control: 'Incident Response',
        severity: 'HIGH',
        description: `${criticalEvents.length} critical security events detected without proper resolution`
      });
      recommendations.push('Implement automated incident response procedures');
    }

    const unresolvedIncidents = Array.from(this.incidents.values())
      .filter(i => i.status !== 'resolved' && i.createdAt.getTime() < Date.now() - 2 * 60 * 60 * 1000); // Older than 2 hours

    if (unresolvedIncidents.length > 0) {
      violations.push({
        control: 'Timely Response',
        severity: 'MEDIUM',
        description: `${unresolvedIncidents.length} incidents remain unresolved beyond acceptable timeframe`
      });
      recommendations.push('Establish SLA-based incident escalation procedures');
    }

    return {
      compliant: violations.length === 0,
      violations,
      recommendations
    };
  }

  /**
   * Machine Learning Model Management
   */
  public async trainAnomalyModel(modelId: string): Promise<void> {
    const model = this.anomalyModels.get(modelId);
    if (!model) {
      throw new Error(`Model ${modelId} not found`);
    }

    const taskId = this.generateTaskId();
    
    return new Promise((resolve, reject) => {
      this.pendingTasks.set(taskId, { resolve, reject });
      
      const trainingData = Array.from(this.securityEvents.values())
        .slice(-model.trainingDataSize); // Use recent events for training

      const message: WorkerMessage = {
        type: 'train_model',
        data: {
          model,
          trainingData
        },
        id: taskId
      };

      this.executeTask(message);
    });
  }

  /**
   * Utility Methods
   */
  private generateEventId(): string {
    return `evt_${Date.now()}_${randomBytes(8).toString('hex')}`;
  }

  private generateIncidentId(): string {
    return `inc_${Date.now()}_${randomBytes(8).toString('hex')}`;
  }

  private generateTaskId(): string {
    return `task_${Date.now()}_${randomBytes(4).toString('hex')}`;
  }

  /**
   * Health Check and Status
   */
  public getStatus(): {
    healthy: boolean;
    workers: { total: number; healthy: number };
    queueLength: number;
    metrics: SecurityMetrics | null;
    uptime: number;
  } {
    const healthyWorkers = this.workerPool.filter(worker => !worker.exitCode).length;
    const latestMetrics = this.metrics[this.metrics.length - 1] || null;

    return {
      healthy: healthyWorkers >= this.maxWorkers * 0.75, // 75% of workers must be healthy
      workers: {
        total: this.maxWorkers,
        healthy: healthyWorkers
      },
      queueLength: this.taskQueue.length,
      metrics: latestMetrics,
      uptime: process.uptime()
    };
  }

  /**
   * Shutdown
   */
  public async shutdown(): Promise<void> {
    this.isShutdown = true;

    if (this.metricsInterval) {
      clearInterval(this.metricsInterval);
    }

    // Terminate all workers
    await Promise.all(
      this.workerPool.map(worker => worker.terminate())
    );

    this.workers.clear();
    this.workerPool.length = 0;

    // Clear pending tasks
    for (const [taskId, task] of this.pendingTasks) {
      task.reject(new Error('Security agent shutting down'));
    }
    this.pendingTasks.clear();

    logger.info('Concurrent Security Agent shut down');
  }

  /**
   * Export for external analysis
   */
  public async exportSecurityData(options: {
    includeEvents?: boolean;
    includeIncidents?: boolean;
    includeMetrics?: boolean;
    timeRange?: { start: Date; end: Date };
  }): Promise<{
    events?: SecurityEvent[];
    incidents?: SecurityIncident[];
    metrics?: SecurityMetrics[];
  }> {
    const result: { events?: SecurityEvent[]; incidents?: SecurityIncident[]; metrics?: SecurityMetrics[] } = {};

    if (options.includeEvents) {
      let events = Array.from(this.securityEvents.values());
      if (options.timeRange) {
        events = events.filter(e => 
          e.timestamp >= options.timeRange!.start && 
          e.timestamp <= options.timeRange!.end
        );
      }
      result.events = events;
    }

    if (options.includeIncidents) {
      let incidents = Array.from(this.incidents.values());
      if (options.timeRange) {
        incidents = incidents.filter(i => 
          i.createdAt >= options.timeRange!.start && 
          i.createdAt <= options.timeRange!.end
        );
      }
      result.incidents = incidents;
    }

    if (options.includeMetrics) {
      let metrics = [...this.metrics];
      if (options.timeRange) {
        metrics = metrics.filter(m => 
          m.timestamp >= options.timeRange!.start && 
          m.timestamp <= options.timeRange!.end
        );
      }
      result.metrics = metrics;
    }

    return result;
  }
}

// Singleton instance
export const concurrentSecurityAgent = new ConcurrentSecurityAgent();