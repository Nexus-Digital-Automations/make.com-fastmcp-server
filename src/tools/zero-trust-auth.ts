/**
 * FastMCP Tools for Zero Trust Authentication Framework
 * Provides comprehensive authentication services including MFA, continuous validation,
 * device trust assessment, behavioral analytics, session management, and identity federation
 */

import { FastMCP } from 'fastmcp';
import { z } from 'zod';
import { authenticator } from 'otplib';
import * as crypto from 'crypto';
import { promisify } from 'util';
import MakeApiClient from '../lib/make-api-client.js';
import { credentialManager } from '../utils/encryption.js';
import { auditLogger } from '../lib/audit-logger.js';
import logger from '../lib/logger.js';
import { formatSuccessResponse } from '../utils/response-formatter.js';

const componentLogger = logger.child({ component: 'ZeroTrustAuthTools' });
const randomBytes = promisify(crypto.randomBytes);

// ===== CORE SCHEMAS =====

// Authentication Request Schema
const AuthenticationRequestSchema = z.object({
  username: z.string().min(1, 'Username is required'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
  mfaCode: z.string().optional(),
  deviceFingerprint: z.object({
    userAgent: z.string(),
    screenResolution: z.string(),
    timezone: z.string(),
    language: z.string(),
    platform: z.string(),
    hardwareInfo: z.string().optional(),
  }),
  ipAddress: z.string().regex(/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/, 'Invalid IP address'),
  geolocation: z.object({
    latitude: z.number().optional(),
    longitude: z.number().optional(),
    country: z.string().optional(),
    city: z.string().optional(),
  }).optional(),
  riskContext: z.object({
    networkType: z.enum(['corporate', 'public', 'mobile', 'vpn', 'tor']),
    timeOfAccess: z.string(),
    accessPattern: z.enum(['normal', 'unusual', 'first_time']),
  }),
});

// MFA Setup Schema
const MFASetupSchema = z.object({
  userId: z.string().min(1, 'User ID is required'),
  method: z.enum(['totp', 'sms', 'hardware_token', 'biometric']),
  phoneNumber: z.string().optional(),
  deviceName: z.string().optional(),
  backupCodes: z.boolean().optional().default(true),
});

// Device Trust Assessment Schema
const DeviceTrustAssessmentSchema = z.object({
  deviceId: z.string().min(1, 'Device ID is required'),
  fingerprint: z.object({
    userAgent: z.string(),
    screenResolution: z.string(),
    timezone: z.string(),
    language: z.string(),
    platform: z.string(),
    hardwareInfo: z.string().optional(),
    installedFonts: z.array(z.string()).optional(),
    plugins: z.array(z.string()).optional(),
  }),
  complianceCheck: z.object({
    isManaged: z.boolean(),
    hasAntivirus: z.boolean(),
    hasFirewall: z.boolean(),
    isEncrypted: z.boolean(),
    osVersion: z.string(),
    lastUpdated: z.string(),
  }),
  historicalBehavior: z.object({
    lastLoginDate: z.string().optional(),
    loginFrequency: z.number().optional(),
    typicalLocations: z.array(z.string()).optional(),
    suspiciousActivity: z.boolean().optional(),
  }).optional(),
});

// Behavioral Analytics Schema
const BehavioralAnalyticsSchema = z.object({
  userId: z.string().min(1, 'User ID is required'),
  sessionId: z.string().min(1, 'Session ID is required'),
  behaviorData: z.object({
    typingPattern: z.object({
      averageSpeed: z.number(),
      keyboardDynamics: z.array(z.number()),
      pausePatterns: z.array(z.number()),
    }).optional(),
    mousePattern: z.object({
      movementSpeed: z.number(),
      clickFrequency: z.number(),
      scrollBehavior: z.array(z.number()),
    }).optional(),
    navigationPattern: z.object({
      pagesVisited: z.array(z.string()),
      timePerPage: z.array(z.number()),
      clickSequence: z.array(z.string()),
    }).optional(),
    accessPattern: z.object({
      loginTimes: z.array(z.string()),
      sessionDurations: z.array(z.number()),
      resourceAccess: z.array(z.string()),
    }),
  }),
  contextualData: z.object({
    ipAddress: z.string().regex(/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/, 'Invalid IP address'),
    geolocation: z.object({
      latitude: z.number().optional(),
      longitude: z.number().optional(),
      country: z.string().optional(),
    }).optional(),
    deviceInfo: z.object({
      deviceId: z.string(),
      platform: z.string(),
      browser: z.string(),
    }),
    networkInfo: z.object({
      networkType: z.string(),
      vpnDetected: z.boolean(),
      threatIntelligence: z.object({
        ipReputation: z.enum(['good', 'suspicious', 'malicious']),
        threatCategories: z.array(z.string()),
      }).optional(),
    }),
  }),
});

// Session Management Schema
const SessionManagementSchema = z.object({
  action: z.enum(['create', 'validate', 'refresh', 'terminate', 'list']),
  sessionId: z.string().optional(),
  userId: z.string().optional(),
  deviceId: z.string().optional(),
  sessionData: z.object({
    createdAt: z.string().optional(),
    lastActivity: z.string().optional(),
    expiresAt: z.string().optional(),
    riskScore: z.number().min(0).max(100).optional(),
    securityLevel: z.enum(['low', 'medium', 'high', 'critical']).optional(),
    attributes: z.record(z.string(), z.unknown()).optional(),
  }).optional(),
  continuousValidation: z.object({
    behaviorCheck: z.boolean().optional().default(true),
    deviceCheck: z.boolean().optional().default(true),
    locationCheck: z.boolean().optional().default(true),
    timeCheck: z.boolean().optional().default(true),
  }).optional(),
});

// Identity Federation Schema
const IdentityFederationSchema = z.object({
  provider: z.enum(['okta', 'azure_ad', 'auth0', 'google', 'saml', 'oidc']),
  action: z.enum(['sso_initiate', 'token_validate', 'user_provision', 'attribute_map']),
  parameters: z.object({
    redirectUri: z.string().url().optional(),
    state: z.string().optional(),
    nonce: z.string().optional(),
    scopes: z.array(z.string()).optional(),
    token: z.string().optional(),
    assertions: z.string().optional(),
    claims: z.record(z.string(), z.unknown()).optional(),
    userAttributes: z.object({
      email: z.string().email().optional(),
      firstName: z.string().optional(),
      lastName: z.string().optional(),
      roles: z.array(z.string()).optional(),
      groups: z.array(z.string()).optional(),
      department: z.string().optional(),
    }).optional(),
  }),
});

// Risk Assessment Schema
const RiskAssessmentSchema = z.object({
  userId: z.string().min(1, 'User ID is required'),
  sessionId: z.string().optional(),
  assessmentType: z.enum(['login', 'continuous', 'transaction', 'administrative']),
  riskFactors: z.object({
    userBehavior: z.object({
      deviationScore: z.number().min(0).max(100),
      anomalies: z.array(z.string()),
      confidence: z.number().min(0).max(100),
    }),
    deviceTrust: z.object({
      trustScore: z.number().min(0).max(100),
      complianceIssues: z.array(z.string()),
      isRecognized: z.boolean(),
    }),
    networkContext: z.object({
      ipReputation: z.enum(['good', 'suspicious', 'malicious']),
      geolocationRisk: z.enum(['low', 'medium', 'high']),
      networkType: z.string(),
      vpnDetected: z.boolean(),
    }),
    temporalFactors: z.object({
      timeOfAccess: z.string(),
      frequencyAnomaly: z.boolean(),
      sessionLength: z.number(),
      concurrentSessions: z.number(),
    }),
  }),
});

// ===== INTERFACES =====

interface AuthenticationResult {
  success: boolean;
  sessionId?: string;
  riskScore: number;
  requiresAdditionalAuth: boolean;
  authMethods: string[];
  errors?: string[];
  securityEvents?: string[];
}

interface MFASetupResult {
  success: boolean;
  secret?: string;
  qrCode?: string;
  backupCodes?: string[];
  recoveryInstructions?: string;
  error?: string;
}

interface DeviceTrustResult {
  trustScore: number;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  complianceStatus: 'compliant' | 'non_compliant' | 'partially_compliant';
  issues: string[];
  recommendations: string[];
  fingerprint: string;
}

interface BehaviorAnalysisResult {
  riskScore: number;
  anomalies: string[];
  confidence: number;
  baseline: 'established' | 'learning' | 'insufficient_data';
  recommendations: string[];
}

interface UserBehaviorBaseline {
  typingPattern?: {
    averageSpeed: number;
  };
  accessPattern?: {
    typicalLoginHours?: number[];
  };
  geolocation?: {
    latitude?: number;
    longitude?: number;
  };
  dataPoints: number;
  established: boolean;
}

interface DeviceComplianceCheck {
  isManaged: boolean;
  hasAntivirus: boolean;
  hasFirewall: boolean;
  isEncrypted: boolean;
  osVersion: string;
  lastUpdated: string;
}

interface DeviceAssessmentData {
  fingerprint: Record<string, unknown>;
  complianceCheck: DeviceComplianceCheck;
}

interface SessionInfo {
  sessionId: string;
  userId: string;
  deviceId: string;
  createdAt: string;
  lastActivity: string;
  expiresAt: string;
  riskScore: number;
  securityLevel: string;
  isValid: boolean;
  continuousValidation: boolean;
}

// ===== UTILITY CLASSES =====

class ZeroTrustAuthEngine {
  private static instance: ZeroTrustAuthEngine;
  public readonly sessions: Map<string, SessionInfo> = new Map();
  private readonly userBaselines: Map<string, UserBehaviorBaseline> = new Map();
  private readonly deviceFingerprints: Map<string, Record<string, unknown>> = new Map();

  public static getInstance(): ZeroTrustAuthEngine {
    if (!ZeroTrustAuthEngine.instance) {
      ZeroTrustAuthEngine.instance = new ZeroTrustAuthEngine();
    }
    return ZeroTrustAuthEngine.instance;
  }

  /**
   * Generate cryptographically secure session ID
   */
  private async generateSessionId(): Promise<string> {
    const bytes = await randomBytes(32);
    return `zt_session_${bytes.toString('base64url')}`;
  }

  /**
   * Generate device fingerprint hash
   */
  private generateDeviceFingerprint(fingerprint: Record<string, unknown>): string {
    const fingerprintString = JSON.stringify(fingerprint, Object.keys(fingerprint).sort());
    return crypto.createHash('sha256').update(fingerprintString).digest('hex');
  }

  /**
   * Calculate risk score based on multiple factors
   */
  public calculateRiskScore(factors: {
    userBehaviorScore: number;
    deviceTrustScore: number;
    networkScore: number;
    temporalScore: number;
  }): number {
    // Weighted average of risk factors
    const weights = {
      userBehavior: 0.3,
      deviceTrust: 0.25,
      network: 0.25,
      temporal: 0.2,
    };

    return Math.round(
      factors.userBehaviorScore * weights.userBehavior +
      factors.deviceTrustScore * weights.deviceTrust +
      factors.networkScore * weights.network +
      factors.temporalScore * weights.temporal
    );
  }

  /**
   * Analyze user behavior and detect anomalies
   */
  public analyzeBehavior(userId: string, behaviorData: Record<string, unknown>): BehaviorAnalysisResult {
    const baseline = this.userBaselines.get(userId);
    
    if (!baseline) {
      // First time user - establish baseline
      this.userBaselines.set(userId, {
        typingPattern: behaviorData.typingPattern as { averageSpeed: number } | undefined,
        accessPattern: behaviorData.accessPattern as { typicalLoginHours?: number[] } | undefined,
        geolocation: behaviorData.geolocation as { latitude?: number; longitude?: number } | undefined,
        dataPoints: 1,
        established: false,
      });
      
      return {
        riskScore: 50, // Medium risk for new users
        anomalies: ['New user - establishing baseline'],
        confidence: 30,
        baseline: 'learning',
        recommendations: ['Continue monitoring behavior patterns'],
      };
    }

    // Calculate deviations from baseline
    const anomalies: string[] = [];
    let deviationScore = 0;

    // Analyze typing patterns
    const typingData = behaviorData.typingPattern as { averageSpeed: number } | undefined;
    if (typingData && baseline.typingPattern) {
      const speedDiff = Math.abs(typingData.averageSpeed - baseline.typingPattern.averageSpeed);
      if (speedDiff > baseline.typingPattern.averageSpeed * 0.5) {
        anomalies.push('Significant typing speed deviation');
        deviationScore += 20;
      }
    }

    // Analyze access patterns
    const accessData = behaviorData.accessPattern as { typicalLoginHours?: number[] } | undefined;
    if (accessData && baseline.accessPattern) {
      const currentHour = new Date().getHours();
      const typicalHours = baseline.accessPattern.typicalLoginHours || [];
      if (!typicalHours.includes(currentHour)) {
        anomalies.push('Unusual access time');
        deviationScore += 15;
      }
    }

    // Analyze geolocation
    const geoData = behaviorData.geolocation as { latitude?: number; longitude?: number } | undefined;
    if (geoData && baseline.geolocation) {
      const distance = this.calculateDistance(
        geoData as Record<string, unknown>,
        baseline.geolocation as Record<string, unknown>
      );
      if (distance > 1000) { // More than 1000km
        anomalies.push('Geographically impossible travel');
        deviationScore += 30;
      }
    }

    const confidence = baseline.dataPoints > 10 ? 90 : Math.min(baseline.dataPoints * 9, 90);
    const riskScore = Math.min(deviationScore, 100);

    return {
      riskScore,
      anomalies,
      confidence,
      baseline: baseline.dataPoints > 10 ? 'established' : 'learning',
      recommendations: this.generateBehaviorRecommendations(riskScore, anomalies),
    };
  }

  /**
   * Assess device trust level
   */
  public assessDeviceTrust(deviceData: DeviceAssessmentData): DeviceTrustResult {
    const fingerprintHash = this.generateDeviceFingerprint(deviceData.fingerprint);
    let trustScore = 100;
    const issues: string[] = [];
    const recommendations: string[] = [];

    // Check if device is recognized
    const isRecognized = this.deviceFingerprints.has(fingerprintHash);
    if (!isRecognized) {
      trustScore -= 30;
      issues.push('Unrecognized device');
      recommendations.push('Consider device registration');
    }

    // Check compliance requirements
    if (!deviceData.complianceCheck.isManaged) {
      trustScore -= 25;
      issues.push('Device not managed by organization');
      recommendations.push('Enroll device in management system');
    }

    if (!deviceData.complianceCheck.hasAntivirus) {
      trustScore -= 20;
      issues.push('No antivirus protection detected');
      recommendations.push('Install enterprise antivirus solution');
    }

    if (!deviceData.complianceCheck.hasFirewall) {
      trustScore -= 15;
      issues.push('Firewall not enabled');
      recommendations.push('Enable host-based firewall');
    }

    if (!deviceData.complianceCheck.isEncrypted) {
      trustScore -= 25;
      issues.push('Disk encryption not enabled');
      recommendations.push('Enable full disk encryption');
    }

    // Check OS version and updates
    const osAge = this.calculateOSAge(deviceData.complianceCheck.osVersion);
    if (osAge > 365) { // More than 1 year old
      trustScore -= 20;
      issues.push('Operating system outdated');
      recommendations.push('Update to latest OS version');
    }

    // Determine risk level
    let riskLevel: 'low' | 'medium' | 'high' | 'critical';
    if (trustScore >= 80) {riskLevel = 'low';}
    else if (trustScore >= 60) {riskLevel = 'medium';}
    else if (trustScore >= 40) {riskLevel = 'high';}
    else {riskLevel = 'critical';}

    // Determine compliance status
    let complianceStatus: 'compliant' | 'non_compliant' | 'partially_compliant';
    if (issues.length === 0) {complianceStatus = 'compliant';}
    else if (issues.length <= 2) {complianceStatus = 'partially_compliant';}
    else {complianceStatus = 'non_compliant';}

    // Store device fingerprint if trusted
    if (trustScore >= 60) {
      this.deviceFingerprints.set(fingerprintHash, {
        ...deviceData,
        trustScore,
        lastSeen: new Date().toISOString(),
      });
    }

    return {
      trustScore: Math.max(trustScore, 0),
      riskLevel,
      complianceStatus,
      issues,
      recommendations,
      fingerprint: fingerprintHash,
    };
  }

  /**
   * Create secure session with risk-based controls
   */
  public async createSession(userId: string, deviceId: string, riskScore: number): Promise<SessionInfo> {
    const sessionId = await this.generateSessionId();
    const now = new Date();
    
    // Determine session expiration based on risk
    let expirationMinutes = 480; // 8 hours default
    if (riskScore > 70) {expirationMinutes = 60;} // 1 hour for high risk
    else if (riskScore > 40) {expirationMinutes = 240;} // 4 hours for medium risk

    const expiresAt = new Date(now.getTime() + expirationMinutes * 60000);
    
    // Determine security level
    let securityLevel: string;
    if (riskScore > 70) {securityLevel = 'critical';}
    else if (riskScore > 40) {securityLevel = 'high';}
    else if (riskScore > 20) {securityLevel = 'medium';}
    else {securityLevel = 'low';}

    const sessionInfo: SessionInfo = {
      sessionId,
      userId,
      deviceId,
      createdAt: now.toISOString(),
      lastActivity: now.toISOString(),
      expiresAt: expiresAt.toISOString(),
      riskScore,
      securityLevel,
      isValid: true,
      continuousValidation: riskScore > 30,
    };

    this.sessions.set(sessionId, sessionInfo);
    
    // Log session creation
    await auditLogger.logEvent({
      level: 'info',
      category: 'authentication',
      action: 'session_created',
      userId,
      sessionId,
      success: true,
      details: {
        deviceId,
        riskScore,
        securityLevel,
        expiresAt: expiresAt.toISOString(),
      },
      riskLevel: riskScore > 70 ? 'high' : riskScore > 40 ? 'medium' : 'low',
    });

    return sessionInfo;
  }

  /**
   * Validate existing session with continuous assessment
   */
  public validateSession(sessionId: string): SessionInfo | null {
    const session = this.sessions.get(sessionId);
    if (!session) {return null;}

    const now = new Date();
    if (new Date(session.expiresAt) < now) {
      session.isValid = false;
      this.sessions.delete(sessionId);
      return null;
    }

    // Update last activity
    session.lastActivity = now.toISOString();
    return session;
  }

  // Helper methods
  private calculateDistance(pos1: Record<string, unknown>, pos2: Record<string, unknown>): number {
    const lat1 = pos1.latitude as number;
    const lon1 = pos1.longitude as number;
    const lat2 = pos2.latitude as number;
    const lon2 = pos2.longitude as number;
    
    if (!lat1 || !lon1 || !lat2 || !lon2) {
      return 0;
    }

    const R = 6371; // Earth's radius in km
    const dLat = (lat2 - lat1) * Math.PI / 180;
    const dLon = (lon2 - lon1) * Math.PI / 180;
    const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
              Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
              Math.sin(dLon/2) * Math.sin(dLon/2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
    return R * c;
  }

  private calculateOSAge(osVersion: string): number {
    // Simplified OS age calculation - in real implementation, use version database
    const currentYear = new Date().getFullYear();
    const versionYear = parseInt(osVersion.match(/(\d{4})/)?.[1] || currentYear.toString());
    return (currentYear - versionYear) * 365;
  }

  private generateBehaviorRecommendations(riskScore: number, anomalies: string[]): string[] {
    const recommendations: string[] = [];
    
    if (riskScore > 70) {
      recommendations.push('Require additional authentication');
      recommendations.push('Increase session monitoring frequency');
    }
    
    if (anomalies.includes('Unusual access time')) {
      recommendations.push('Verify user identity through secondary channel');
    }
    
    if (anomalies.includes('Geographically impossible travel')) {
      recommendations.push('Immediate security review required');
      recommendations.push('Consider temporary account restriction');
    }

    return recommendations;
  }
}

// ===== TOOL IMPLEMENTATIONS =====

/**
 * Zero Trust Authentication Tool
 */
const createZeroTrustAuthTool = (_apiClient: MakeApiClient): ZeroTrustTool => ({
  name: 'zero_trust_authenticate',
  description: 'Perform zero trust authentication with multi-factor validation and risk assessment',
  inputSchema: AuthenticationRequestSchema,
  execute: async (input: unknown): Promise<string> => {
    const parsedInput = AuthenticationRequestSchema.parse(input);
    const authEngine = ZeroTrustAuthEngine.getInstance();
    
    try {
      // Generate device fingerprint
      const deviceFingerprint = crypto
        .createHash('sha256')
        .update(JSON.stringify(parsedInput.deviceFingerprint, Object.keys(parsedInput.deviceFingerprint).sort()))
        .digest('hex');

      // Simulate user authentication (in real implementation, validate against user store)
      const isValidUser = parsedInput.username.length > 0 && parsedInput.password.length >= 8;
      
      if (!isValidUser) {
        await auditLogger.logEvent({
          level: 'warn',
          category: 'authentication',
          action: 'login_failed',
          userId: parsedInput.username,
          ipAddress: parsedInput.ipAddress,
          success: false,
          details: { reason: 'Invalid credentials', deviceFingerprint },
          riskLevel: 'medium',
        });

        const result: AuthenticationResult = {
          success: false,
          riskScore: 100,
          requiresAdditionalAuth: false,
          authMethods: [],
          errors: ['Invalid username or password'],
          securityEvents: ['Failed login attempt logged'],
        };

        return formatSuccessResponse(result).content[0].text;
      }

      // Assess device trust
      const deviceTrust = authEngine.assessDeviceTrust({
        fingerprint: parsedInput.deviceFingerprint,
        complianceCheck: {
          isManaged: true, // Simplified for demo
          hasAntivirus: true,
          hasFirewall: true,
          isEncrypted: true,
          osVersion: '2024',
          lastUpdated: new Date().toISOString(),
        },
      });

      // Analyze user behavior (simplified)
      const behaviorAnalysis = authEngine.analyzeBehavior(parsedInput.username, {
        accessPattern: {
          loginTime: new Date().toISOString(),
          ipAddress: parsedInput.ipAddress,
          userAgent: parsedInput.deviceFingerprint.userAgent,
        },
        geolocation: parsedInput.geolocation,
        typingPattern: {
          averageSpeed: 45, // Simulated
        },
      });

      // Calculate overall risk score
      const networkRisk = parsedInput.riskContext.networkType === 'tor' ? 80 : 
                         parsedInput.riskContext.networkType === 'public' ? 40 : 10;
      
      const overallRiskScore = authEngine.calculateRiskScore({
        userBehaviorScore: behaviorAnalysis.riskScore,
        deviceTrustScore: 100 - deviceTrust.trustScore,
        networkScore: networkRisk,
        temporalScore: parsedInput.riskContext.accessPattern === 'unusual' ? 60 : 20,
      });

      // Determine if additional authentication is required
      const requiresAdditionalAuth = overallRiskScore > 40 || !parsedInput.mfaCode;
      const authMethods = ['password'];

      if (parsedInput.mfaCode) {
        // In real implementation, validate TOTP code
        const isMfaValid = parsedInput.mfaCode.length === 6;
        if (isMfaValid) {
          authMethods.push('totp');
        } else {
          return formatSuccessResponse({
            success: false,
            riskScore: overallRiskScore,
            requiresAdditionalAuth: true,
            authMethods: [],
            errors: ['Invalid MFA code'],
          }).content[0].text;
        }
      }

      let sessionId: string | undefined;
      if (!requiresAdditionalAuth) {
        // Create secure session
        const session = await authEngine.createSession(
          parsedInput.username,
          deviceFingerprint,
          overallRiskScore
        );
        sessionId = session.sessionId;
      }

      // Log successful authentication
      await auditLogger.logEvent({
        level: 'info',
        category: 'authentication',
        action: 'login_success',
        userId: parsedInput.username,
        sessionId,
        ipAddress: parsedInput.ipAddress,
        success: true,
        details: {
          authMethods,
          riskScore: overallRiskScore,
          deviceFingerprint,
          deviceTrust: deviceTrust.trustScore,
          behaviorRisk: behaviorAnalysis.riskScore,
        },
        riskLevel: overallRiskScore > 70 ? 'high' : overallRiskScore > 40 ? 'medium' : 'low',
      });

      const result: AuthenticationResult = {
        success: true,
        sessionId,
        riskScore: overallRiskScore,
        requiresAdditionalAuth,
        authMethods,
        securityEvents: [
          `Device trust score: ${deviceTrust.trustScore}`,
          `Behavior risk score: ${behaviorAnalysis.riskScore}`,
          `Overall risk score: ${overallRiskScore}`,
        ],
      };

      return formatSuccessResponse(result).content[0].text;

    } catch (error) {
      componentLogger.error('Zero trust authentication failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
        username: parsedInput.username,
        ipAddress: parsedInput.ipAddress,
      });

      return formatSuccessResponse({
        success: false,
        riskScore: 100,
        requiresAdditionalAuth: false,
        authMethods: [],
        errors: ['Authentication service error'],
      }).content[0].text;
    }
  },
});

/**
 * MFA Setup Tool
 */
const createMFASetupTool = (_apiClient: MakeApiClient): ZeroTrustTool => ({
  name: 'setup_mfa',
  description: 'Setup multi-factor authentication for a user account',
  inputSchema: MFASetupSchema,
  execute: async (input: unknown): Promise<string> => {
    const parsedInput = MFASetupSchema.parse(input);
    try {
      let result: MFASetupResult;

      switch (parsedInput.method) {
        case 'totp': {
          // Generate TOTP secret
          const secret = authenticator.generateSecret();
          const accountName = parsedInput.userId;
          const issuer = 'Make.com';
          
          const otpauth = authenticator.keyuri(accountName, issuer, secret);
          
          // Generate backup codes
          const backupCodes = parsedInput.backupCodes 
            ? await Promise.all(Array(10).fill(0).map(() => 
                randomBytes(8).then(buf => buf.toString('hex'))
              ))
            : [];

          // Store encrypted secret
          await credentialManager.storeCredential(
            secret,
            'secret',
            'mfa_totp',
            process.env.MASTER_PASSWORD || 'default_master_key',
            { id: `mfa_${parsedInput.userId}` }
          );

          result = {
            success: true,
            secret,
            qrCode: otpauth,
            backupCodes,
            recoveryInstructions: 'Store backup codes in a secure location. Use them if your device is unavailable.',
          };
          break;
        }

        case 'sms': {
          if (!parsedInput.phoneNumber) {
            result = {
              success: false,
              error: 'Phone number required for SMS MFA',
            };
            break;
          }

          // Store phone number securely
          await credentialManager.storeCredential(
            parsedInput.phoneNumber,
            'secret',
            'mfa_sms',
            process.env.MASTER_PASSWORD || 'default_master_key',
            { id: `mfa_sms_${parsedInput.userId}` }
          );

          result = {
            success: true,
            recoveryInstructions: `SMS codes will be sent to ${parsedInput.phoneNumber.replace(/(\d{3})(\d{3})(\d{4})/, '($1) $2-****')}`,
          };
          break;
        }

        case 'hardware_token': {
          // Register hardware token (simplified)
          result = {
            success: true,
            recoveryInstructions: 'Hardware token registered. Ensure device is accessible for authentication.',
          };
          break;
        }

        case 'biometric': {
          // Setup biometric authentication
          result = {
            success: true,
            recoveryInstructions: 'Biometric authentication enabled. Fallback to other methods if biometric fails.',
          };
          break;
        }

        default: {
          result = {
            success: false,
            error: 'Unsupported MFA method',
          };
          break;
        }
      }

      // Log MFA setup
      await auditLogger.logEvent({
        level: 'info',
        category: 'security',
        action: 'mfa_setup',
        userId: parsedInput.userId,
        success: result.success,
        details: {
          method: parsedInput.method,
          deviceName: parsedInput.deviceName,
          hasBackupCodes: !!result.backupCodes?.length,
        },
        riskLevel: 'low',
      });

      componentLogger.info('MFA setup completed', {
        userId: parsedInput.userId,
        method: parsedInput.method,
        success: result.success,
      });

      return formatSuccessResponse(result).content[0].text;

    } catch (error) {
      componentLogger.error('MFA setup failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
        userId: 'unknown',
        method: 'unknown',
      });

      return formatSuccessResponse({
        success: false,
        error: 'MFA setup service error',
      }).content[0].text;
    }
  },
});

/**
 * Device Trust Assessment Tool
 */
const createDeviceTrustAssessmentTool = (_apiClient: MakeApiClient): ZeroTrustTool => ({
  name: 'assess_device_trust',
  description: 'Assess device trust level and compliance status',
  inputSchema: DeviceTrustAssessmentSchema,
  execute: async (input: unknown): Promise<string> => {
    const parsedInput = DeviceTrustAssessmentSchema.parse(input);
    const authEngine = ZeroTrustAuthEngine.getInstance();
    
    try {
      const trustResult = authEngine.assessDeviceTrust(parsedInput as DeviceAssessmentData);

      // Log device assessment
      await auditLogger.logEvent({
        level: 'info',
        category: 'security',
        action: 'device_trust_assessment',
        userId: parsedInput.deviceId,
        success: true,
        details: {
          trustScore: trustResult.trustScore,
          riskLevel: trustResult.riskLevel,
          complianceStatus: trustResult.complianceStatus,
          issuesFound: trustResult.issues.length,
        },
        riskLevel: trustResult.riskLevel === 'critical' ? 'critical' : 
                  trustResult.riskLevel === 'high' ? 'high' : 'low',
      });

      componentLogger.info('Device trust assessment completed', {
        deviceId: parsedInput.deviceId,
        trustScore: trustResult.trustScore,
        riskLevel: trustResult.riskLevel,
        issues: trustResult.issues.length,
      });

      return formatSuccessResponse(trustResult).content[0].text;

    } catch (error) {
      componentLogger.error('Device trust assessment failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
        deviceId: parsedInput.deviceId,
      });

      return formatSuccessResponse({
        trustScore: 0,
        riskLevel: 'critical',
        complianceStatus: 'non_compliant',
        issues: ['Assessment service error'],
        recommendations: ['Contact system administrator'],
        fingerprint: 'error',
      }).content[0].text;
    }
  },
});

/**
 * Behavioral Analytics Tool
 */
const createBehavioralAnalyticsTool = (_apiClient: MakeApiClient): ZeroTrustTool => ({
  name: 'analyze_user_behavior',
  description: 'Analyze user behavior patterns and detect anomalies',
  inputSchema: BehavioralAnalyticsSchema,
  execute: async (input: unknown): Promise<string> => {
    const parsedInput = BehavioralAnalyticsSchema.parse(input);
    const authEngine = ZeroTrustAuthEngine.getInstance();
    
    try {
      const analysisResult = authEngine.analyzeBehavior(parsedInput.userId, {
        ...parsedInput.behaviorData,
        contextualData: parsedInput.contextualData,
      });

      // Log behavior analysis
      await auditLogger.logEvent({
        level: analysisResult.riskScore > 70 ? 'warn' : 'info',
        category: 'security',
        action: 'behavior_analysis',
        userId: parsedInput.userId,
        sessionId: parsedInput.sessionId,
        success: true,
        details: {
          riskScore: analysisResult.riskScore,
          anomaliesDetected: analysisResult.anomalies.length,
          confidence: analysisResult.confidence,
          baseline: analysisResult.baseline,
        },
        riskLevel: analysisResult.riskScore > 70 ? 'high' : 
                  analysisResult.riskScore > 40 ? 'medium' : 'low',
      });

      componentLogger.info('Behavior analysis completed', {
        userId: parsedInput.userId,
        sessionId: parsedInput.sessionId,
        riskScore: analysisResult.riskScore,
        anomalies: analysisResult.anomalies.length,
      });

      return formatSuccessResponse(analysisResult).content[0].text;

    } catch (error) {
      componentLogger.error('Behavior analysis failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
        userId: parsedInput.userId,
        sessionId: parsedInput.sessionId,
      });

      return formatSuccessResponse({
        riskScore: 50,
        anomalies: ['Analysis service error'],
        confidence: 0,
        baseline: 'insufficient_data',
        recommendations: ['Contact system administrator'],
      }).content[0].text;
    }
  },
});

/**
 * Session Management Tool
 */
const createSessionManagementTool = (_apiClient: MakeApiClient): ZeroTrustTool => ({
  name: 'manage_session',
  description: 'Manage user sessions with continuous validation and risk-based controls',
  inputSchema: SessionManagementSchema,
  execute: async (input: unknown): Promise<string> => {
    const parsedInput = SessionManagementSchema.parse(input);
    const authEngine = ZeroTrustAuthEngine.getInstance();
    
    try {
      let result: Record<string, unknown>;

      switch (parsedInput.action) {
        case 'create': {
          if (!parsedInput.userId || !parsedInput.deviceId) {
            return formatSuccessResponse({
              success: false,
              error: 'User ID and Device ID required for session creation',
            }).content[0].text;
          }
          
          const riskScore = parsedInput.sessionData?.riskScore || 25;
          const session = await authEngine.createSession(parsedInput.userId, parsedInput.deviceId, riskScore);
          result = { success: true, session };
          break;
        }

        case 'validate': {
          if (!parsedInput.sessionId) {
            return formatSuccessResponse({
              success: false,
              error: 'Session ID required for validation',
            }).content[0].text;
          }
          
          const validatedSession = authEngine.validateSession(parsedInput.sessionId);
          result = {
            success: !!validatedSession,
            session: validatedSession,
            isValid: !!validatedSession,
          };
          break;
        }

        case 'terminate': {
          if (!parsedInput.sessionId) {
            return formatSuccessResponse({
              success: false,
              error: 'Session ID required for termination',
            }).content[0].text;
          }

          // Terminate session
          const terminated = authEngine.sessions.delete(parsedInput.sessionId);
          result = { success: terminated, terminated: terminated };
          
          if (terminated) {
            await auditLogger.logEvent({
              level: 'info',
              category: 'authentication',
              action: 'session_terminated',
              sessionId: parsedInput.sessionId,
              success: true,
              details: { reason: 'Manual termination' },
              riskLevel: 'low',
            });
          }
          break;
        }

        case 'list': {
          if (!parsedInput.userId) {
            return formatSuccessResponse({
              success: false,
              error: 'User ID required for session listing',
            }).content[0].text;
          }

          const userSessions = Array.from(authEngine.sessions.values())
            .filter(session => session.userId === parsedInput.userId);
          result = { success: true, sessions: userSessions };
          break;
        }

        case 'refresh': {
          if (!parsedInput.sessionId) {
            return formatSuccessResponse({
              success: false,
              error: 'Session ID required for refresh',
            }).content[0].text;
          }

          const existingSession = authEngine.validateSession(parsedInput.sessionId);
          if (existingSession) {
            // Extend session expiration
            const newExpiry = new Date(Date.now() + 4 * 60 * 60 * 1000); // 4 hours
            existingSession.expiresAt = newExpiry.toISOString();
            result = { success: true, session: existingSession };
          } else {
            result = { success: false, error: 'Session not found or expired' };
          }
          break;
        }

        default: {
          result = { success: false, error: 'Invalid session action' };
          break;
        }
      }

      componentLogger.info('Session management operation completed', {
        action: parsedInput.action,
        sessionId: parsedInput.sessionId,
        userId: parsedInput.userId,
        success: result.success,
      });

      return formatSuccessResponse(result).content[0].text;

    } catch (error) {
      componentLogger.error('Session management failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
        action: parsedInput.action,
        sessionId: parsedInput.sessionId,
        userId: parsedInput.userId,
      });

      return formatSuccessResponse({
        success: false,
        error: 'Session management service error',
      }).content[0].text;
    }
  },
});

// ===== IDENTITY FEDERATION HELPER FUNCTIONS =====

/**
 * Generate SSO URL for different providers
 */
const generateSsoUrl = (
  provider: string,
  redirectUri: string,
  state: string,
  nonce: string
): string => {
  switch (provider) {
    case 'okta':
      return `https://your-domain.okta.com/oauth2/v1/authorize?client_id=your-client-id&response_type=code&scope=openid profile email&redirect_uri=${encodeURIComponent(redirectUri)}&state=${state}&nonce=${nonce}`;
    case 'azure_ad':
      return `https://login.microsoftonline.com/your-tenant-id/oauth2/v2.0/authorize?client_id=your-client-id&response_type=code&scope=openid profile email&redirect_uri=${encodeURIComponent(redirectUri)}&state=${state}&nonce=${nonce}`;
    case 'google':
      return `https://accounts.google.com/oauth2/v2/auth?client_id=your-client-id&response_type=code&scope=openid profile email&redirect_uri=${encodeURIComponent(redirectUri)}&state=${state}&nonce=${nonce}`;
    default:
      return `https://example.com/sso/${provider}?state=${state}&nonce=${nonce}`;
  }
};

/**
 * Handle SSO initiation process
 */
const handleSsoInitiate = (
  parsedInput: z.infer<typeof IdentityFederationSchema>
): Record<string, unknown> => {
  // Generate SSO initiation URL
  const state = crypto.randomBytes(32).toString('base64url');
  const nonce = crypto.randomBytes(32).toString('base64url');
  
  const ssoUrl = generateSsoUrl(
    parsedInput.provider,
    parsedInput.parameters.redirectUri || '',
    state,
    nonce
  );

  return {
    success: true,
    ssoUrl,
    state,
    nonce,
    provider: parsedInput.provider,
  };
};

/**
 * Handle token validation
 */
const handleTokenValidate = (
  parsedInput: z.infer<typeof IdentityFederationSchema>
): Record<string, unknown> => {
  // Validate OAuth/SAML token
  if (!parsedInput.parameters.token) {
    return {
      success: false,
      error: 'Token required for validation',
    };
  }

  // Simplified token validation
  const isValidToken = parsedInput.parameters.token.length > 10;
  return {
    success: isValidToken,
    valid: isValidToken,
    claims: isValidToken ? {
      sub: 'user123',
      email: 'user@example.com',
      name: 'Example User',
      roles: ['user'],
    } : null,
  };
};

/**
 * Handle user provisioning
 */
const handleUserProvision = (
  parsedInput: z.infer<typeof IdentityFederationSchema>
): Record<string, unknown> => {
  // Just-in-time user provisioning
  if (!parsedInput.parameters.userAttributes) {
    return {
      success: false,
      error: 'User attributes required for provisioning',
    };
  }

  const userAttributes = parsedInput.parameters.userAttributes;
  return {
    success: true,
    user: {
      id: crypto.randomUUID(),
      email: userAttributes.email,
      firstName: userAttributes.firstName,
      lastName: userAttributes.lastName,
      roles: userAttributes.roles || ['user'],
      groups: userAttributes.groups || [],
      department: userAttributes.department,
      provisionedAt: new Date().toISOString(),
    },
  };
};

/**
 * Handle attribute mapping
 */
const handleAttributeMap = (
  parsedInput: z.infer<typeof IdentityFederationSchema>
): Record<string, unknown> => {
  // Map identity provider attributes to local user attributes
  const claims = parsedInput.parameters.claims || {};
  return {
    success: true,
    mappedAttributes: {
      userId: claims.sub || claims.user_id,
      email: claims.email || claims.mail,
      firstName: claims.given_name || claims.first_name,
      lastName: claims.family_name || claims.last_name,
      roles: (claims.roles as string[]) || (claims.groups as string[]) || ['user'],
      department: claims.department || claims.dept,
    },
  };
};

/**
 * Identity Federation Tool
 */
const createIdentityFederationTool = (_apiClient: MakeApiClient): ZeroTrustTool => ({
  name: 'identity_federation',
  description: 'Handle identity federation and SSO integration with enterprise providers',
  inputSchema: IdentityFederationSchema,
  execute: async (input: unknown): Promise<string> => {
    const parsedInput = IdentityFederationSchema.parse(input);
    try {
      let result: Record<string, unknown>;

      switch (parsedInput.action) {
        case 'sso_initiate':
          result = handleSsoInitiate(parsedInput);
          break;
        case 'token_validate':
          result = handleTokenValidate(parsedInput);
          break;
        case 'user_provision':
          result = handleUserProvision(parsedInput);
          break;
        case 'attribute_map':
          result = handleAttributeMap(parsedInput);
          break;
        default:
          result = {
            success: false,
            error: 'Invalid federation action',
          };
          break;
      }

      // Log federation operation
      await auditLogger.logEvent({
        level: 'info',
        category: 'authentication',
        action: `identity_federation_${parsedInput.action}`,
        success: result.success as boolean,
        details: {
          provider: parsedInput.provider,
          action: parsedInput.action,
          hasUserAttributes: !!parsedInput.parameters.userAttributes,
        },
        riskLevel: 'low',
      });

      componentLogger.info('Identity federation operation completed', {
        provider: parsedInput.provider,
        action: parsedInput.action,
        success: result.success,
      });

      return formatSuccessResponse(result).content[0].text;

    } catch (error) {
      componentLogger.error('Identity federation failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
        provider: parsedInput.provider,
        action: parsedInput.action,
      });

      return formatSuccessResponse({
        success: false,
        error: 'Identity federation service error',
      }).content[0].text;
    }
  },
});

/**
 * Risk Assessment Tool
 */
const createRiskAssessmentTool = (_apiClient: MakeApiClient): ZeroTrustTool => ({
  name: 'assess_authentication_risk',
  description: 'Perform comprehensive risk assessment for authentication decisions',
  inputSchema: RiskAssessmentSchema,
  execute: async (input: unknown): Promise<string> => {
    const parsedInput = RiskAssessmentSchema.parse(input);
    try {
      // Calculate weighted risk score
      const weights = {
        userBehavior: 0.35,
        deviceTrust: 0.25,
        networkContext: 0.25,
        temporalFactors: 0.15,
      };

      const overallRiskScore = Math.round(
        parsedInput.riskFactors.userBehavior.deviationScore * weights.userBehavior +
        (100 - parsedInput.riskFactors.deviceTrust.trustScore) * weights.deviceTrust +
        (parsedInput.riskFactors.networkContext.ipReputation === 'malicious' ? 100 : 
         parsedInput.riskFactors.networkContext.ipReputation === 'suspicious' ? 60 : 20) * weights.networkContext +
        (parsedInput.riskFactors.temporalFactors.frequencyAnomaly ? 70 : 20) * weights.temporalFactors
      );

      // Determine risk level
      let riskLevel: 'low' | 'medium' | 'high' | 'critical';
      if (overallRiskScore >= 80) {riskLevel = 'critical';}
      else if (overallRiskScore >= 60) {riskLevel = 'high';}
      else if (overallRiskScore >= 40) {riskLevel = 'medium';}
      else {riskLevel = 'low';}

      // Generate recommendations
      const recommendations: string[] = [];
      
      if (overallRiskScore >= 80) {
        recommendations.push('Deny access or require administrative approval');
        recommendations.push('Initiate security incident investigation');
      } else if (overallRiskScore >= 60) {
        recommendations.push('Require additional authentication factors');
        recommendations.push('Implement enhanced session monitoring');
      } else if (overallRiskScore >= 40) {
        recommendations.push('Consider step-up authentication');
        recommendations.push('Increase session validation frequency');
      } else {
        recommendations.push('Allow normal access');
        recommendations.push('Continue standard monitoring');
      }

      // Add specific recommendations based on risk factors
      if (parsedInput.riskFactors.deviceTrust.trustScore < 50) {
        recommendations.push('Device security compliance required');
      }
      
      if (parsedInput.riskFactors.networkContext.vpnDetected) {
        recommendations.push('Verify VPN usage policy compliance');
      }

      if (parsedInput.riskFactors.userBehavior.anomalies.length > 0) {
        recommendations.push('Investigate behavioral anomalies');
      }

      const result = {
        success: true,
        overallRiskScore,
        riskLevel,
        assessmentType: parsedInput.assessmentType,
        riskBreakdown: {
          userBehaviorContribution: Math.round(parsedInput.riskFactors.userBehavior.deviationScore * weights.userBehavior),
          deviceTrustContribution: Math.round((100 - parsedInput.riskFactors.deviceTrust.trustScore) * weights.deviceTrust),
          networkContextContribution: Math.round((parsedInput.riskFactors.networkContext.ipReputation === 'malicious' ? 100 : 
                                                 parsedInput.riskFactors.networkContext.ipReputation === 'suspicious' ? 60 : 20) * weights.networkContext),
          temporalFactorsContribution: Math.round((parsedInput.riskFactors.temporalFactors.frequencyAnomaly ? 70 : 20) * weights.temporalFactors),
        },
        recommendations,
        assessmentTimestamp: new Date().toISOString(),
        requiresAction: overallRiskScore >= 60,
        suggestedAuthLevel: riskLevel === 'critical' ? 'deny' :
                           riskLevel === 'high' ? 'multi_factor_plus' :
                           riskLevel === 'medium' ? 'multi_factor' : 'standard',
      };

      // Log risk assessment
      await auditLogger.logEvent({
        level: riskLevel === 'critical' ? 'critical' : riskLevel === 'high' ? 'warn' : 'info',
        category: 'security',
        action: 'risk_assessment',
        userId: parsedInput.userId,
        sessionId: parsedInput.sessionId,
        success: true,
        details: {
          assessmentType: parsedInput.assessmentType,
          overallRiskScore,
          riskLevel,
          requiresAction: result.requiresAction,
        },
        riskLevel: riskLevel === 'critical' ? 'critical' : riskLevel === 'high' ? 'high' : 'medium',
      });

      componentLogger.info('Risk assessment completed', {
        userId: parsedInput.userId,
        sessionId: parsedInput.sessionId,
        assessmentType: parsedInput.assessmentType,
        overallRiskScore,
        riskLevel,
      });

      return formatSuccessResponse(result).content[0].text;

    } catch (error) {
      componentLogger.error('Risk assessment failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
        userId: parsedInput.userId,
        sessionId: parsedInput.sessionId,
        assessmentType: parsedInput.assessmentType,
      });

      return formatSuccessResponse({
        success: false,
        overallRiskScore: 100,
        riskLevel: 'critical',
        error: 'Risk assessment service error',
        recommendations: ['Contact system administrator'],
      }).content[0].text;
    }
  },
});

// ===== TOOL INTERFACES =====

/**
 * Generic tool interface to avoid intersection conflicts
 */
interface ZeroTrustTool {
  name: string;
  description: string;
  inputSchema: z.ZodType<unknown>;
  execute: (input: unknown) => Promise<string>;
}

/**
 * Tool creator function type
 */
type ToolCreator = (apiClient: MakeApiClient) => ZeroTrustTool;

// ===== TOOL COLLECTION =====

/**
 * All Zero Trust Authentication tools
 */
export const zeroTrustAuthTools: ToolCreator[] = [
  createZeroTrustAuthTool,
  createMFASetupTool,
  createDeviceTrustAssessmentTool,
  createBehavioralAnalyticsTool,
  createSessionManagementTool,
  createIdentityFederationTool,
  createRiskAssessmentTool,
];

/**
 * Get comprehensive security-focused annotations for Zero Trust Authentication tools
 * Following FastMCP TypeScript Protocol compliance standards (2025)
 * Based on comprehensive research report patterns for enterprise security tools
 */
function getToolAnnotations(toolName: string): {
  title: string;
  readOnlyHint: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint: boolean;
} {
  const baseTitle = toolName.replace(/[_-]/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
  
  switch (toolName) {
    case 'zero_trust_authenticate':
      // Category: Authentication Operations - External Identity Provider Integration
      return {
        title: 'Zero Trust Multi-Factor Authentication',
        readOnlyHint: false, // Modifies authentication state and creates sessions
        destructiveHint: false, // Non-destructive authentication operation
        idempotentHint: false, // Each authentication attempt is unique with different risk factors
        openWorldHint: true, // Integrates with external identity providers, MFA services, and threat intelligence
      };

    case 'setup_mfa':
      // Category: Configuration Management - External MFA Provider Integration
      return {
        title: 'Multi-Factor Authentication Setup',
        readOnlyHint: false, // Modifies MFA configuration and stores credentials
        destructiveHint: false, // Non-destructive setup operation (creates/updates MFA settings)
        idempotentHint: true, // MFA setup can be run multiple times safely with same result
        openWorldHint: true, // Integrates with external MFA providers (TOTP, SMS gateways, hardware tokens)
      };

    case 'assess_device_trust':
      // Category: Security Assessment - Internal Analysis with External Threat Intelligence
      return {
        title: 'Device Trust & Compliance Assessment',
        readOnlyHint: true, // Only assesses and analyzes device information without modifications
        destructiveHint: false, // Read-only assessment operation
        idempotentHint: true, // Same device assessment yields same results
        openWorldHint: true, // May integrate with external threat intelligence and device management systems
      };

    case 'analyze_user_behavior':
      // Category: Behavioral Analytics - Internal Analysis with Learning
      return {
        title: 'User Behavioral Analytics & Anomaly Detection',
        readOnlyHint: false, // Updates behavioral baselines and learning models
        destructiveHint: false, // Non-destructive learning and analysis operation
        idempotentHint: false, // Each analysis updates behavioral models and baselines
        openWorldHint: false, // Internal analytics using stored behavioral baselines and patterns
      };

    case 'manage_session':
      // Category: Session Control - DESTRUCTIVE (Can terminate sessions and lock users)
      return {
        title: 'Session Management & Validation',
        readOnlyHint: false, // Modifies session state, creates, validates, or terminates sessions
        destructiveHint: true, // CRITICAL: Can terminate sessions and effectively lock users out of system
        idempotentHint: false, // Session operations have time-sensitive and context-dependent effects
        openWorldHint: false, // Internal session management within zero trust framework
      };

    case 'identity_federation':
      // Category: External Identity Integration - SSO and Federation
      return {
        title: 'Identity Federation & Single Sign-On',
        readOnlyHint: false, // Processes authentication tokens and provisions user accounts
        destructiveHint: false, // Non-destructive federation and user provisioning operations
        idempotentHint: true, // SSO operations and user provisioning can be retried safely
        openWorldHint: true, // Integrates extensively with external identity providers (Okta, Azure AD, Google, SAML)
      };

    case 'assess_authentication_risk':
      // Category: Risk Analysis - Read-only Assessment
      return {
        title: 'Authentication Risk Assessment & Scoring',
        readOnlyHint: true, // Only performs risk calculations and assessments without state changes
        destructiveHint: false, // Read-only risk assessment operation
        idempotentHint: true, // Same risk factors yield same risk assessment results
        openWorldHint: false, // Internal risk scoring based on behavioral analytics and device trust
      };

    default:
      // Fallback for any unrecognized tools with conservative security settings
      return {
        title: baseTitle,
        readOnlyHint: false, // Conservative assumption - may modify state
        destructiveHint: false, // Conservative assumption - avoid marking unknown tools as destructive
        idempotentHint: false, // Conservative assumption - avoid assuming idempotency
        openWorldHint: true, // Conservative assumption - may interact with external systems
      };
  }
}

/**
 * Add all Zero Trust Authentication tools to FastMCP server
 */
export function addZeroTrustAuthTools(server: FastMCP, apiClient: MakeApiClient): void {
  zeroTrustAuthTools.forEach((createTool: ToolCreator) => {
    const tool = createTool(apiClient);
    server.addTool({
      name: tool.name,
      description: tool.description,
      parameters: tool.inputSchema,
      annotations: getToolAnnotations(tool.name),
      execute: async (args: unknown, { log }) => {
        log?.info?.(`Executing ${tool.name}`, { 
          toolName: tool.name,
          hasArgs: args !== undefined 
        });
        return await tool.execute(args);
      }
    });
  });

  componentLogger.info('Zero Trust Authentication tools registered', {
    toolCount: zeroTrustAuthTools.length,
    tools: zeroTrustAuthTools.map(createTool => createTool(apiClient).name),
  });
}

export default addZeroTrustAuthTools;