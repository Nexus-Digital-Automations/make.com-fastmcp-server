/**
 * Security Worker Thread
 * Handles parallel security analysis tasks including threat detection,
 * anomaly analysis, log processing, and machine learning model operations
 */

const { isMainThread, parentPort, workerData } = require('worker_threads');
const crypto = require('crypto');

if (isMainThread || !parentPort) {
  throw new Error('This script should only be run as a worker thread');
}

/**
 * Security Analysis Worker Class
 */
class SecurityWorker {
  constructor(workerId) {
    this.workerId = workerId;
    this.initialize();
  }

  initialize() {
    // Set up message handling
    parentPort.on('message', (message) => {
      this.handleMessage(message);
    });

    // Initialize worker-specific resources
    this.threatPatterns = new Map();
    this.anomalyDetectors = new Map();
    this.statisticalModels = new Map();
    
    // Send ready signal
    this.sendMessage({
      type: 'worker_ready',
      data: { workerId: this.workerId },
      id: 'ready'
    });
  }

  async handleMessage(message) {
    try {
      let result;
      
      switch (message.type) {
        case 'analyze_event':
          result = await this.analyzeSecurityEvent(message.data);
          break;
        case 'detect_anomaly':
          result = await this.detectAnomalies(message.data);
          break;
        case 'process_logs':
          result = await this.processAuditLogs(message.data);
          break;
        case 'update_threat_intel':
          result = await this.updateThreatIntelligence(message.data);
          break;
        case 'train_model':
          result = await this.trainMLModel(message.data);
          break;
        default:
          throw new Error(`Unknown message type: ${message.type}`);
      }

      this.sendMessage({
        type: message.type + '_result',
        data: result,
        id: message.id
      });
    } catch (error) {
      this.sendMessage({
        type: message.type + '_error',
        data: null,
        id: message.id,
        error: error.message
      });
    }
  }

  sendMessage(message) {
    parentPort.postMessage(message);
  }

  /**
   * Analyze security event for threats
   */
  async analyzeSecurityEvent(data) {
    const { event, threatIntel, patterns } = data;
    let threatScore = 0;
    const actions = [];

    // IP reputation analysis
    if (event.ipAddress) {
      const ipThreat = await this.analyzeIPReputation(event.ipAddress, threatIntel);
      threatScore = Math.max(threatScore, ipThreat.score);
      actions.push(...ipThreat.actions);
    }

    // User agent analysis
    if (event.userAgent) {
      const uaThreat = await this.analyzeUserAgent(event.userAgent);
      threatScore = Math.max(threatScore, uaThreat.score);
      actions.push(...uaThreat.actions);
    }

    // Geographic analysis
    if (event.geoLocation) {
      const geoThreat = await this.analyzeGeographic(event.geoLocation);
      threatScore = Math.max(threatScore, geoThreat.score);
      actions.push(...geoThreat.actions);
    }

    // Pattern matching against threat signatures
    const signatureThreat = await this.matchThreatSignatures(event, patterns);
    threatScore = Math.max(threatScore, signatureThreat.score);
    actions.push(...signatureThreat.actions);

    // Behavioral analysis
    const behaviorThreat = await this.analyzeBehaviorPatterns(event);
    threatScore = Math.max(threatScore, behaviorThreat.score);
    actions.push(...behaviorThreat.actions);

    return {
      score: threatScore,
      actions: [...new Set(actions)] // Remove duplicates
    };
  }

  async analyzeIPReputation(ipAddress, threatIntel) {
    let score = 0;
    const actions = [];

    // Check against threat intelligence
    for (const intel of threatIntel) {
      if (intel.type === 'ip' && this.matchesIPPattern(ipAddress, intel.value)) {
        score = Math.max(score, intel.confidence * this.severityToScore(intel.severity));
        actions.push(`IP matched threat intelligence: ${intel.source}`);
      }
    }

    // Check for private/internal IPs
    if (this.isPrivateIP(ipAddress)) {
      score = Math.max(score, 0.1); // Low score for internal traffic
      actions.push('Internal IP address detected');
    }

    // Check for suspicious IP patterns
    const suspiciousPatterns = [
      /^10\.10\.10\./, // Common test patterns
      /^192\.168\.1\.1$/, // Default router
      /^127\.0\.0\.1$/ // Localhost
    ];

    for (const pattern of suspiciousPatterns) {
      if (pattern.test(ipAddress)) {
        score = Math.max(score, 0.3);
        actions.push('Suspicious IP pattern detected');
        break;
      }
    }

    return { score, actions };
  }

  async analyzeUserAgent(userAgent) {
    let score = 0;
    const actions = [];

    // Check for automated tools/bots
    const botPatterns = [
      /curl/i,
      /wget/i,
      /python-requests/i,
      /bot/i,
      /crawler/i,
      /scanner/i,
      /sqlmap/i,
      /nikto/i,
      /burp/i
    ];

    for (const pattern of botPatterns) {
      if (pattern.test(userAgent)) {
        score = Math.max(score, 0.6);
        actions.push('Automated tool/bot user agent detected');
        break;
      }
    }

    // Check for unusual or suspicious patterns
    if (userAgent.length < 10) {
      score = Math.max(score, 0.4);
      actions.push('Unusually short user agent');
    }

    if (userAgent.length > 500) {
      score = Math.max(score, 0.3);
      actions.push('Unusually long user agent');
    }

    // Check for missing common browser components
    const hasStandardBrowserMarkers = /Mozilla|Chrome|Safari|Firefox/i.test(userAgent);
    if (!hasStandardBrowserMarkers && userAgent.length > 0) {
      score = Math.max(score, 0.5);
      actions.push('Non-standard user agent pattern');
    }

    return { score, actions };
  }

  async analyzeGeographic(geoLocation) {
    let score = 0;
    const actions = [];

    // High-risk countries (simplified example)
    const highRiskCountries = ['XX', 'YY']; // Would be populated with actual high-risk country codes
    if (highRiskCountries.includes(geoLocation.country)) {
      score = Math.max(score, 0.4);
      actions.push(`Traffic from high-risk country: ${geoLocation.country}`);
    }

    // Check for VPN/proxy indicators
    if (geoLocation.isp && /vpn|proxy|hosting/i.test(geoLocation.isp)) {
      score = Math.max(score, 0.3);
      actions.push('VPN/proxy service detected');
    }

    return { score, actions };
  }

  async matchThreatSignatures(event, patterns) {
    let score = 0;
    const actions = [];

    for (const pattern of patterns) {
      if (!pattern.enabled) continue;

      const matchResult = this.evaluateSecurityPattern(event, pattern);
      if (matchResult.matches) {
        score = Math.max(score, matchResult.confidence);
        actions.push(`Security pattern matched: ${pattern.name}`);
      }
    }

    return { score, actions };
  }

  evaluateSecurityPattern(event, pattern) {
    let matches = false;
    let confidence = 0;

    switch (pattern.type) {
      case 'signature':
        matches = this.matchSignaturePattern(event, pattern);
        confidence = matches ? 0.8 : 0;
        break;
      case 'behavioral':
        const behaviorResult = this.matchBehaviorPattern(event, pattern);
        matches = behaviorResult.matches;
        confidence = behaviorResult.confidence;
        break;
      case 'statistical':
        const statResult = this.matchStatisticalPattern(event, pattern);
        matches = statResult.matches;
        confidence = statResult.confidence;
        break;
      case 'ml_based':
        // ML-based pattern matching would go here
        matches = false;
        confidence = 0;
        break;
    }

    return { matches, confidence };
  }

  matchSignaturePattern(event, pattern) {
    // Check if event details match any of the signature patterns
    const eventString = JSON.stringify(event.details).toLowerCase();
    return pattern.patterns.some(patternStr => {
      try {
        const regex = new RegExp(patternStr, 'i');
        return regex.test(eventString);
      } catch (e) {
        // If pattern is not a valid regex, do string matching
        return eventString.includes(patternStr.toLowerCase());
      }
    });
  }

  matchBehaviorPattern(event, pattern) {
    // Simplified behavioral pattern matching
    let matches = false;
    let confidence = 0;

    if (pattern.id === 'brute-force-login') {
      // This would typically check against historical data
      // For now, we'll use a simplified approach
      if (event.type === 'authentication_failure') {
        matches = true;
        confidence = 0.6;
      }
    } else if (pattern.id === 'privilege-escalation') {
      if (event.details && typeof event.details === 'object') {
        const detailsStr = JSON.stringify(event.details).toLowerCase();
        if (detailsStr.includes('admin') || detailsStr.includes('root') || detailsStr.includes('privilege')) {
          matches = true;
          confidence = 0.7;
        }
      }
    }

    return { matches, confidence };
  }

  matchStatisticalPattern(event, pattern) {
    // Statistical pattern matching based on thresholds
    let matches = false;
    let confidence = 0;

    // Example: API abuse detection
    if (pattern.id === 'api-abuse' && pattern.thresholds) {
      // This would normally check against time-series data
      // Simplified implementation
      if (event.details && event.details.requestCount && 
          event.details.requestCount > pattern.thresholds.requests) {
        matches = true;
        confidence = Math.min(event.details.requestCount / pattern.thresholds.requests, 1.0);
      }
    }

    return { matches, confidence };
  }

  async analyzeBehaviorPatterns(event) {
    let score = 0;
    const actions = [];

    // Time-based analysis
    const hour = event.timestamp.getHours();
    if (hour < 6 || hour > 22) { // Outside normal business hours
      score = Math.max(score, 0.2);
      actions.push('Activity outside normal business hours');
    }

    // Frequency analysis (simplified)
    if (event.details && event.details.frequency && event.details.frequency > 100) {
      score = Math.max(score, 0.5);
      actions.push('High frequency activity detected');
    }

    return { score, actions };
  }

  /**
   * Detect anomalies using various algorithms
   */
  async detectAnomalies(data) {
    const { event, models, historicalEvents } = data;
    let maxScore = 0;
    const actions = [];

    // Statistical anomaly detection
    const statResult = await this.detectStatisticalAnomalies(event, historicalEvents);
    maxScore = Math.max(maxScore, statResult.score);
    actions.push(...statResult.actions);

    // Behavioral anomaly detection
    const behaviorResult = await this.detectBehavioralAnomalies(event, historicalEvents);
    maxScore = Math.max(maxScore, behaviorResult.score);
    actions.push(...behaviorResult.actions);

    // ML-based anomaly detection
    for (const model of models) {
      const mlResult = await this.detectMLAnomalies(event, model, historicalEvents);
      maxScore = Math.max(maxScore, mlResult.score);
      actions.push(...mlResult.actions);
    }

    return {
      score: maxScore,
      actions: [...new Set(actions)]
    };
  }

  async detectStatisticalAnomalies(event, historicalEvents) {
    let score = 0;
    const actions = [];

    // Z-score based anomaly detection
    if (historicalEvents.length > 10) {
      // Calculate statistics for request patterns
      const requestCounts = historicalEvents
        .filter(e => e.ipAddress === event.ipAddress)
        .map(e => e.details && e.details.requestCount ? e.details.requestCount : 1);

      if (requestCounts.length > 0) {
        const mean = requestCounts.reduce((a, b) => a + b, 0) / requestCounts.length;
        const variance = requestCounts.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / requestCounts.length;
        const stdDev = Math.sqrt(variance);

        if (event.details && event.details.requestCount && stdDev > 0) {
          const zScore = Math.abs((event.details.requestCount - mean) / stdDev);
          
          if (zScore > 3) { // 3 standard deviations
            score = Math.max(score, 0.8);
            actions.push(`Statistical anomaly detected (Z-score: ${zScore.toFixed(2)})`);
          } else if (zScore > 2) {
            score = Math.max(score, 0.5);
            actions.push(`Unusual activity pattern detected (Z-score: ${zScore.toFixed(2)})`);
          }
        }
      }
    }

    return { score, actions };
  }

  async detectBehavioralAnomalies(event, historicalEvents) {
    let score = 0;
    const actions = [];

    // User behavior analysis
    const userEvents = historicalEvents.filter(e => e.userId === event.userId);
    
    if (userEvents.length > 5) {
      // Check for unusual timing patterns
      const eventHours = userEvents.map(e => e.timestamp.getHours());
      const userTypicalHours = [...new Set(eventHours)];
      const currentHour = event.timestamp.getHours();
      
      if (!userTypicalHours.includes(currentHour) && userTypicalHours.length > 0) {
        score = Math.max(score, 0.4);
        actions.push('Unusual access time for user');
      }

      // Check for unusual geographic patterns
      const userLocations = userEvents
        .filter(e => e.geoLocation)
        .map(e => e.geoLocation.country);
      const typicalCountries = [...new Set(userLocations)];
      
      if (event.geoLocation && 
          !typicalCountries.includes(event.geoLocation.country) && 
          typicalCountries.length > 0) {
        score = Math.max(score, 0.6);
        actions.push('Unusual geographic location for user');
      }
    }

    return { score, actions };
  }

  async detectMLAnomalies(event, model, historicalEvents) {
    let score = 0;
    const actions = [];

    // Simplified ML-based anomaly detection
    // In production, this would use actual ML models
    
    if (model.type === 'behavioral' && model.features.includes('access_patterns')) {
      // Simple pattern-based ML simulation
      const userEvents = historicalEvents.filter(e => e.userId === event.userId);
      
      if (userEvents.length > model.parameters.minDataPoints) {
        // Calculate feature vectors
        const eventFeatures = this.extractEventFeatures(event, model.features);
        const historicalFeatures = userEvents.map(e => this.extractEventFeatures(e, model.features));
        
        // Simple distance-based anomaly detection
        const anomalyScore = this.calculateAnomalyScore(eventFeatures, historicalFeatures);
        
        if (anomalyScore > model.parameters.threshold) {
          score = anomalyScore;
          actions.push(`ML anomaly detected (${model.name}): score ${anomalyScore.toFixed(3)}`);
        }
      }
    }

    return { score, actions };
  }

  extractEventFeatures(event, features) {
    const featureVector = {};
    
    for (const feature of features) {
      switch (feature) {
        case 'login_time':
          featureVector.loginTime = event.timestamp.getHours();
          break;
        case 'ip_address':
          featureVector.ipHash = this.hashString(event.ipAddress || '');
          break;
        case 'user_agent':
          featureVector.userAgentHash = this.hashString(event.userAgent || '');
          break;
        case 'access_patterns':
          featureVector.eventType = event.type;
          break;
        case 'request_rate':
          featureVector.requestRate = event.details && event.details.requestCount ? event.details.requestCount : 1;
          break;
      }
    }
    
    return featureVector;
  }

  calculateAnomalyScore(eventFeatures, historicalFeatures) {
    if (historicalFeatures.length === 0) return 0;
    
    // Calculate average distance to historical patterns
    let totalDistance = 0;
    let validComparisons = 0;
    
    for (const historical of historicalFeatures) {
      const distance = this.calculateFeatureDistance(eventFeatures, historical);
      if (!isNaN(distance)) {
        totalDistance += distance;
        validComparisons++;
      }
    }
    
    return validComparisons > 0 ? totalDistance / validComparisons : 0;
  }

  calculateFeatureDistance(features1, features2) {
    let distance = 0;
    let comparisons = 0;
    
    for (const key in features1) {
      if (key in features2) {
        if (typeof features1[key] === 'number' && typeof features2[key] === 'number') {
          distance += Math.abs(features1[key] - features2[key]);
        } else if (features1[key] !== features2[key]) {
          distance += 1;
        }
        comparisons++;
      }
    }
    
    return comparisons > 0 ? distance / comparisons : 0;
  }

  /**
   * Process audit logs for security analysis
   */
  async processAuditLogs(data) {
    const { logs, patterns } = data;
    const results = {
      processedLogs: logs.length,
      anomalies: [],
      violations: [],
      recommendations: []
    };

    for (const log of logs) {
      // Check for security violations
      const violations = await this.detectLogViolations(log, patterns);
      results.violations.push(...violations);

      // Check for anomalous patterns
      const anomalies = await this.detectLogAnomalies(log);
      results.anomalies.push(...anomalies);
    }

    // Generate recommendations based on findings
    if (results.violations.length > 0) {
      results.recommendations.push('Review and strengthen access controls');
    }
    if (results.anomalies.length > 5) {
      results.recommendations.push('Implement additional monitoring for unusual access patterns');
    }

    return results;
  }

  async detectLogViolations(log, patterns) {
    const violations = [];

    // Check for privilege escalation attempts
    if (log.action && /admin|root|privilege|sudo/i.test(log.action)) {
      violations.push({
        type: 'privilege_escalation_attempt',
        severity: 'HIGH',
        description: `Potential privilege escalation: ${log.action}`,
        timestamp: log.timestamp,
        user: log.user
      });
    }

    // Check for unauthorized access attempts
    if (log.details && log.details.status === 'failed' && log.action === 'login') {
      violations.push({
        type: 'unauthorized_access_attempt',
        severity: 'MEDIUM',
        description: 'Failed login attempt',
        timestamp: log.timestamp,
        user: log.user
      });
    }

    return violations;
  }

  async detectLogAnomalies(log) {
    const anomalies = [];

    // Check for unusual time patterns
    const hour = log.timestamp.getHours();
    if (hour < 6 || hour > 20) {
      anomalies.push({
        type: 'unusual_timing',
        description: 'Activity outside normal business hours',
        timestamp: log.timestamp,
        user: log.user
      });
    }

    // Check for rapid successive actions
    // This would typically compare against time-series data
    
    return anomalies;
  }

  /**
   * Update threat intelligence
   */
  async updateThreatIntelligence(data) {
    const { threatFeeds, indicators } = data;
    
    // Process threat intelligence updates
    const updates = {
      newIndicators: 0,
      updatedIndicators: 0,
      expiredIndicators: 0
    };

    // Process new indicators
    for (const indicator of indicators) {
      if (this.isValidIndicator(indicator)) {
        updates.newIndicators++;
      }
    }

    return updates;
  }

  isValidIndicator(indicator) {
    // Validate threat indicator format
    return indicator && 
           indicator.type && 
           indicator.value && 
           indicator.confidence >= 0 && 
           indicator.confidence <= 1;
  }

  /**
   * Train machine learning models
   */
  async trainMLModel(data) {
    const { model, trainingData } = data;
    
    // Simplified ML model training simulation
    const trainingResults = {
      modelId: model.id,
      accuracy: 0,
      precision: 0,
      recall: 0,
      f1Score: 0,
      trainingTime: Date.now()
    };

    // Extract features from training data
    const features = trainingData.map(event => 
      this.extractEventFeatures(event, model.features)
    );

    // Simulate model training
    const validFeatures = features.filter(f => Object.keys(f).length > 0);
    
    if (validFeatures.length > 10) {
      // Simulate improving accuracy with more data
      trainingResults.accuracy = Math.min(0.95, 0.6 + (validFeatures.length / 10000));
      trainingResults.precision = trainingResults.accuracy * 0.95;
      trainingResults.recall = trainingResults.accuracy * 0.9;
      trainingResults.f1Score = 2 * (trainingResults.precision * trainingResults.recall) / 
                                (trainingResults.precision + trainingResults.recall);
    } else {
      trainingResults.accuracy = 0.5; // Insufficient data
    }

    return trainingResults;
  }

  /**
   * Utility methods
   */
  matchesIPPattern(ip, pattern) {
    if (pattern.includes('*')) {
      const regex = new RegExp(pattern.replace(/\*/g, '.*'));
      return regex.test(ip);
    }
    return ip === pattern;
  }

  isPrivateIP(ip) {
    const privateRanges = [
      /^10\./,
      /^172\.(1[6-9]|2[0-9]|3[01])\./,
      /^192\.168\./,
      /^127\./,
      /^169\.254\./
    ];
    return privateRanges.some(range => range.test(ip));
  }

  severityToScore(severity) {
    const scores = {
      'low': 0.2,
      'medium': 0.5,
      'high': 0.8,
      'critical': 1.0
    };
    return scores[severity.toLowerCase()] || 0;
  }

  hashString(str) {
    return crypto.createHash('sha256').update(str).digest('hex').substring(0, 16);
  }
}

// Initialize the worker
const worker = new SecurityWorker(workerData.workerId);

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection in security worker:', reason);
  process.exit(1);
});

process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception in security worker:', error);
  process.exit(1);
});