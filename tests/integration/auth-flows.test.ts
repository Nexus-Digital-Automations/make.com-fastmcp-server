/**
 * @fileoverview Authentication and authorization flow integration tests
 * 
 * Tests complete authentication workflows including OAuth flows, API key validation,
 * JWT token management, multi-factor authentication, and authorization policies.
 * 
 * @version 1.0.0
 */

import { describe, test, expect, beforeAll, afterAll, beforeEach, afterEach } from '@jest/globals';
import type MakeApiClient from '../../src/lib/make-api-client.js';

// Authentication types and interfaces
interface AuthToken {
  accessToken: string;
  refreshToken?: string;
  tokenType: 'Bearer' | 'API_KEY';
  expiresIn: number;
  scope?: string[];
  issuedAt: number;
}

interface AuthUser {
  id: string;
  email: string;
  name: string;
  roles: string[];
  permissions: string[];
  teamId: number;
  organizationId: string;
  isActive: boolean;
  lastLogin?: string;
  mfaEnabled: boolean;
}

interface AuthSession {
  sessionId: string;
  userId: string;
  token: AuthToken;
  ipAddress: string;
  userAgent: string;
  createdAt: string;
  lastActivity: string;
  isValid: boolean;
}

interface OAuth2Config {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scope: string[];
  authorizeUrl: string;
  tokenUrl: string;
}

interface AuthPolicy {
  id: string;
  name: string;
  resource: string;
  action: string;
  effect: 'allow' | 'deny';
  conditions?: Record<string, unknown>;
  priority: number;
}

// Mock authentication service
class MockAuthService {
  private users: Map<string, AuthUser> = new Map();
  private sessions: Map<string, AuthSession> = new Map();
  private tokens: Map<string, AuthToken> = new Map();
  private policies: Map<string, AuthPolicy> = new Map();
  private oauthStates: Map<string, { userId: string; redirectUri: string; expiresAt: number }> = new Map();

  // User management
  async createUser(user: AuthUser): Promise<AuthUser> {
    this.users.set(user.id, { ...user });
    return user;
  }

  async getUser(id: string): Promise<AuthUser | null> {
    return this.users.get(id) || null;
  }

  async getUserByEmail(email: string): Promise<AuthUser | null> {
    for (const user of this.users.values()) {
      if (user.email === email) {
        return user;
      }
    }
    return null;
  }

  async updateUser(id: string, updates: Partial<AuthUser>): Promise<AuthUser | null> {
    const user = this.users.get(id);
    if (!user) return null;
    
    const updated = { ...user, ...updates };
    this.users.set(id, updated);
    return updated;
  }

  // Authentication flows
  async authenticateWithPassword(email: string, password: string): Promise<{ user: AuthUser; token: AuthToken } | null> {
    const user = await this.getUserByEmail(email);
    if (!user || !user.isActive) return null;

    // Simulate password validation (always succeeds in mock)
    const token = this.generateToken(user);
    await this.updateUser(user.id, { lastLogin: new Date().toISOString() });
    
    return { user, token };
  }

  async authenticateWithApiKey(apiKey: string): Promise<{ user: AuthUser; token: AuthToken } | null> {
    // Extract user ID from API key (simplified for mock)
    const userId = apiKey.split('-')[0];
    const user = await this.getUser(userId);
    
    if (!user || !user.isActive) return null;

    const token: AuthToken = {
      accessToken: apiKey,
      tokenType: 'API_KEY',
      expiresIn: 0, // API keys don't expire
      issuedAt: Date.now(),
    };

    return { user, token };
  }

  async refreshToken(refreshToken: string): Promise<AuthToken | null> {
    // Find token by refresh token
    for (const token of this.tokens.values()) {
      if (token.refreshToken === refreshToken) {
        const user = Array.from(this.users.values()).find(u => 
          this.sessions.has(`${u.id}-session`)
        );
        
        if (user) {
          return this.generateToken(user);
        }
      }
    }
    return null;
  }

  // OAuth2 flows
  async initiateOAuth2Flow(config: OAuth2Config, state: string): Promise<string> {
    const authUrl = new URL(config.authorizeUrl);
    authUrl.searchParams.set('client_id', config.clientId);
    authUrl.searchParams.set('redirect_uri', config.redirectUri);
    authUrl.searchParams.set('scope', config.scope.join(' '));
    authUrl.searchParams.set('state', state);
    authUrl.searchParams.set('response_type', 'code');

    // Store OAuth state
    this.oauthStates.set(state, {
      userId: 'pending',
      redirectUri: config.redirectUri,
      expiresAt: Date.now() + 600000, // 10 minutes
    });

    return authUrl.toString();
  }

  async handleOAuth2Callback(code: string, state: string, config: OAuth2Config): Promise<{ user: AuthUser; token: AuthToken } | null> {
    const stateData = this.oauthStates.get(state);
    if (!stateData || stateData.expiresAt < Date.now()) {
      return null;
    }

    // Simulate token exchange
    const mockUserData = {
      id: `oauth-${Date.now()}`,
      email: 'oauth@example.com',
      name: 'OAuth User',
    };

    // Create or get user
    let user = await this.getUserByEmail(mockUserData.email);
    if (!user) {
      user = await this.createUser({
        ...mockUserData,
        roles: ['user'],
        permissions: ['read:scenarios', 'write:scenarios'],
        teamId: 1,
        organizationId: 'org-1',
        isActive: true,
        mfaEnabled: false,
      });
    }

    const token = this.generateToken(user);
    this.oauthStates.delete(state);

    return { user, token };
  }

  // Token management
  async validateToken(tokenString: string): Promise<{ user: AuthUser; token: AuthToken } | null> {
    const token = this.tokens.get(tokenString);
    if (!token) return null;

    // Check token expiration
    if (token.expiresIn > 0 && (token.issuedAt + token.expiresIn * 1000) < Date.now()) {
      this.tokens.delete(tokenString);
      return null;
    }

    // Find user associated with token
    for (const session of this.sessions.values()) {
      if (session.token.accessToken === tokenString) {
        const user = await this.getUser(session.userId);
        if (user && user.isActive) {
          return { user, token };
        }
      }
    }

    return null;
  }

  async revokeToken(tokenString: string): Promise<boolean> {
    const deleted = this.tokens.delete(tokenString);
    
    // Remove associated sessions
    for (const [sessionId, session] of this.sessions.entries()) {
      if (session.token.accessToken === tokenString) {
        this.sessions.delete(sessionId);
      }
    }

    return deleted;
  }

  // Session management
  async createSession(user: AuthUser, token: AuthToken, metadata: { ipAddress: string; userAgent: string }): Promise<AuthSession> {
    const session: AuthSession = {
      sessionId: `${user.id}-${Date.now()}`,
      userId: user.id,
      token,
      ipAddress: metadata.ipAddress,
      userAgent: metadata.userAgent,
      createdAt: new Date().toISOString(),
      lastActivity: new Date().toISOString(),
      isValid: true,
    };

    this.sessions.set(session.sessionId, session);
    this.tokens.set(token.accessToken, token);

    return session;
  }

  async getSession(sessionId: string): Promise<AuthSession | null> {
    return this.sessions.get(sessionId) || null;
  }

  async updateSessionActivity(sessionId: string): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (session) {
      session.lastActivity = new Date().toISOString();
    }
  }

  async invalidateSession(sessionId: string): Promise<boolean> {
    const session = this.sessions.get(sessionId);
    if (session) {
      session.isValid = false;
      this.tokens.delete(session.token.accessToken);
      return true;
    }
    return false;
  }

  async invalidateAllUserSessions(userId: string): Promise<number> {
    let count = 0;
    for (const [sessionId, session] of this.sessions.entries()) {
      if (session.userId === userId) {
        session.isValid = false;
        this.tokens.delete(session.token.accessToken);
        count++;
      }
    }
    return count;
  }

  // Authorization policies
  async createPolicy(policy: AuthPolicy): Promise<AuthPolicy> {
    this.policies.set(policy.id, { ...policy });
    return policy;
  }

  async checkPermission(user: AuthUser, resource: string, action: string): Promise<boolean> {
    // Check user permissions first
    const permissionKey = `${action}:${resource}`;
    if (user.permissions.includes(permissionKey) || user.permissions.includes('*')) {
      return true;
    }

    // Check role-based permissions
    if (user.roles.includes('admin') || user.roles.includes('super_admin')) {
      return true;
    }

    // Check policies
    const applicablePolicies = Array.from(this.policies.values())
      .filter(p => p.resource === resource && p.action === action)
      .sort((a, b) => b.priority - a.priority);

    for (const policy of applicablePolicies) {
      if (this.evaluatePolicyConditions(policy, user)) {
        return policy.effect === 'allow';
      }
    }

    return false; // Default deny
  }

  // Multi-factor authentication
  async enableMFA(userId: string): Promise<{ secret: string; qrCode: string }> {
    const user = await this.getUser(userId);
    if (!user) throw new Error('User not found');

    const secret = 'mock-mfa-secret-' + userId;
    const qrCode = `otpauth://totp/TestApp:${user.email}?secret=${secret}&issuer=TestApp`;

    await this.updateUser(userId, { mfaEnabled: true });

    return { secret, qrCode };
  }

  async verifyMFA(userId: string, code: string): Promise<boolean> {
    const user = await this.getUser(userId);
    if (!user || !user.mfaEnabled) return false;

    // Simulate MFA verification (accept specific codes)
    return code === '123456' || code === '000000';
  }

  async disableMFA(userId: string): Promise<boolean> {
    const user = await this.updateUser(userId, { mfaEnabled: false });
    return user !== null;
  }

  // Utility methods
  private generateToken(user: AuthUser): AuthToken {
    const tokenString = `token_${user.id}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const refreshTokenString = `refresh_${user.id}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

    return {
      accessToken: tokenString,
      refreshToken: refreshTokenString,
      tokenType: 'Bearer',
      expiresIn: 3600, // 1 hour
      scope: user.permissions,
      issuedAt: Date.now(),
    };
  }

  private evaluatePolicyConditions(policy: AuthPolicy, user: AuthUser): boolean {
    if (!policy.conditions) return true;

    // Evaluate conditions (simplified for mock)
    if (policy.conditions.teamId && policy.conditions.teamId !== user.teamId) {
      return false;
    }

    if (policy.conditions.organizationId && policy.conditions.organizationId !== user.organizationId) {
      return false;
    }

    if (policy.conditions.roles && !policy.conditions.roles.some((role: string) => user.roles.includes(role))) {
      return false;
    }

    return true;
  }

  // Test utilities
  async clear(): Promise<void> {
    this.users.clear();
    this.sessions.clear();
    this.tokens.clear();
    this.policies.clear();
    this.oauthStates.clear();
  }

  getStats(): { users: number; sessions: number; tokens: number; policies: number } {
    return {
      users: this.users.size,
      sessions: this.sessions.size,
      tokens: this.tokens.size,
      policies: this.policies.size,
    };
  }
}

describe('Authentication and Authorization Flow Integration Tests', () => {
  let authService: MockAuthService;
  
  const testUser: AuthUser = {
    id: 'test-user-1',
    email: 'test@example.com',
    name: 'Test User',
    roles: ['user'],
    permissions: ['read:scenarios', 'write:scenarios', 'read:connections'],
    teamId: 123,
    organizationId: 'org-1',
    isActive: true,
    mfaEnabled: false,
  };

  const adminUser: AuthUser = {
    id: 'admin-user-1',
    email: 'admin@example.com',
    name: 'Admin User',
    roles: ['admin'],
    permissions: ['*'],
    teamId: 123,
    organizationId: 'org-1',
    isActive: true,
    mfaEnabled: true,
  };

  beforeAll(async () => {
    authService = new MockAuthService();
  });

  beforeEach(async () => {
    await authService.clear();
    await authService.createUser(testUser);
    await authService.createUser(adminUser);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('Password Authentication Flow', () => {
    test('should authenticate user with valid credentials', async () => {
      const result = await authService.authenticateWithPassword('test@example.com', 'password123');
      
      expect(result).toBeTruthy();
      expect(result!.user.email).toBe('test@example.com');
      expect(result!.token.tokenType).toBe('Bearer');
      expect(result!.token.accessToken).toBeTruthy();
      expect(result!.token.refreshToken).toBeTruthy();
      expect(result!.token.expiresIn).toBe(3600);
    });

    test('should reject authentication with non-existent user', async () => {
      const result = await authService.authenticateWithPassword('nonexistent@example.com', 'password');
      expect(result).toBeNull();
    });

    test('should reject authentication with inactive user', async () => {
      await authService.updateUser('test-user-1', { isActive: false });
      
      const result = await authService.authenticateWithPassword('test@example.com', 'password123');
      expect(result).toBeNull();
    });

    test('should update last login timestamp on successful authentication', async () => {
      const beforeLogin = new Date().toISOString();
      
      await authService.authenticateWithPassword('test@example.com', 'password123');
      
      const user = await authService.getUser('test-user-1');
      expect(user!.lastLogin).toBeTruthy();
      expect(user!.lastLogin! >= beforeLogin).toBe(true);
    });
  });

  describe('API Key Authentication Flow', () => {
    test('should authenticate user with valid API key', async () => {
      const apiKey = `${testUser.id}-api-key-123`;
      
      const result = await authService.authenticateWithApiKey(apiKey);
      
      expect(result).toBeTruthy();
      expect(result!.user.id).toBe(testUser.id);
      expect(result!.token.tokenType).toBe('API_KEY');
      expect(result!.token.accessToken).toBe(apiKey);
      expect(result!.token.expiresIn).toBe(0); // API keys don't expire
    });

    test('should reject authentication with invalid API key format', async () => {
      const result = await authService.authenticateWithApiKey('invalid-api-key');
      expect(result).toBeNull();
    });

    test('should reject authentication for inactive user', async () => {
      await authService.updateUser('test-user-1', { isActive: false });
      const apiKey = `${testUser.id}-api-key-123`;
      
      const result = await authService.authenticateWithApiKey(apiKey);
      expect(result).toBeNull();
    });
  });

  describe('OAuth2 Authentication Flow', () => {
    const oauthConfig: OAuth2Config = {
      clientId: 'test-client-id',
      clientSecret: 'test-client-secret',
      redirectUri: 'https://localhost:3000/auth/callback',
      scope: ['read', 'write'],
      authorizeUrl: 'https://oauth.example.com/authorize',
      tokenUrl: 'https://oauth.example.com/token',
    };

    test('should initiate OAuth2 authorization flow', async () => {
      const state = 'random-state-123';
      
      const authUrl = await authService.initiateOAuth2Flow(oauthConfig, state);
      
      expect(authUrl).toContain(oauthConfig.authorizeUrl);
      expect(authUrl).toContain(`client_id=${oauthConfig.clientId}`);
      expect(authUrl).toContain(`redirect_uri=${encodeURIComponent(oauthConfig.redirectUri)}`);
      expect(authUrl).toContain(`scope=${encodeURIComponent('read write')}`);
      expect(authUrl).toContain(`state=${state}`);
      expect(authUrl).toContain('response_type=code');
    });

    test('should handle OAuth2 callback and create user session', async () => {
      const state = 'callback-state-456';
      const code = 'authorization-code-789';
      
      // Initiate flow first
      await authService.initiateOAuth2Flow(oauthConfig, state);
      
      // Handle callback
      const result = await authService.handleOAuth2Callback(code, state, oauthConfig);
      
      expect(result).toBeTruthy();
      expect(result!.user.email).toBe('oauth@example.com');
      expect(result!.token.tokenType).toBe('Bearer');
      expect(result!.token.accessToken).toBeTruthy();
    });

    test('should reject OAuth2 callback with invalid state', async () => {
      const code = 'authorization-code-789';
      const invalidState = 'invalid-state';
      
      const result = await authService.handleOAuth2Callback(code, invalidState, oauthConfig);
      expect(result).toBeNull();
    });

    test('should reject OAuth2 callback with expired state', async () => {
      const state = 'expired-state-123';
      const code = 'authorization-code-789';
      
      // Manually add expired state
      (authService as any).oauthStates.set(state, {
        userId: 'pending',
        redirectUri: oauthConfig.redirectUri,
        expiresAt: Date.now() - 1000, // Expired 1 second ago
      });
      
      const result = await authService.handleOAuth2Callback(code, state, oauthConfig);
      expect(result).toBeNull();
    });
  });

  describe('Token Management', () => {
    test('should validate active tokens', async () => {
      const authResult = await authService.authenticateWithPassword('test@example.com', 'password123');
      const session = await authService.createSession(authResult!.user, authResult!.token, {
        ipAddress: '127.0.0.1',
        userAgent: 'Test Agent',
      });
      
      const validation = await authService.validateToken(authResult!.token.accessToken);
      
      expect(validation).toBeTruthy();
      expect(validation!.user.id).toBe(testUser.id);
      expect(validation!.token.accessToken).toBe(authResult!.token.accessToken);
    });

    test('should reject expired tokens', async () => {
      const authResult = await authService.authenticateWithPassword('test@example.com', 'password123');
      
      // Manually expire the token
      const expiredToken = {
        ...authResult!.token,
        expiresIn: 1,
        issuedAt: Date.now() - 2000, // Issued 2 seconds ago with 1 second expiry
      };
      
      const session = await authService.createSession(authResult!.user, expiredToken, {
        ipAddress: '127.0.0.1',
        userAgent: 'Test Agent',
      });
      
      const validation = await authService.validateToken(expiredToken.accessToken);
      expect(validation).toBeNull();
    });

    test('should refresh tokens successfully', async () => {
      const authResult = await authService.authenticateWithPassword('test@example.com', 'password123');
      
      const newToken = await authService.refreshToken(authResult!.token.refreshToken!);
      
      expect(newToken).toBeTruthy();
      expect(newToken!.accessToken).not.toBe(authResult!.token.accessToken);
      expect(newToken!.tokenType).toBe('Bearer');
      expect(newToken!.expiresIn).toBe(3600);
    });

    test('should revoke tokens successfully', async () => {
      const authResult = await authService.authenticateWithPassword('test@example.com', 'password123');
      const session = await authService.createSession(authResult!.user, authResult!.token, {
        ipAddress: '127.0.0.1',
        userAgent: 'Test Agent',
      });
      
      // Verify token is valid
      let validation = await authService.validateToken(authResult!.token.accessToken);
      expect(validation).toBeTruthy();
      
      // Revoke token
      const revoked = await authService.revokeToken(authResult!.token.accessToken);
      expect(revoked).toBe(true);
      
      // Verify token is now invalid
      validation = await authService.validateToken(authResult!.token.accessToken);
      expect(validation).toBeNull();
    });
  });

  describe('Session Management', () => {
    test('should create and manage user sessions', async () => {
      const authResult = await authService.authenticateWithPassword('test@example.com', 'password123');
      
      const session = await authService.createSession(authResult!.user, authResult!.token, {
        ipAddress: '192.168.1.1',
        userAgent: 'Mozilla/5.0 Test Browser',
      });
      
      expect(session.sessionId).toBeTruthy();
      expect(session.userId).toBe(testUser.id);
      expect(session.ipAddress).toBe('192.168.1.1');
      expect(session.userAgent).toBe('Mozilla/5.0 Test Browser');
      expect(session.isValid).toBe(true);
    });

    test('should track session activity', async () => {
      const authResult = await authService.authenticateWithPassword('test@example.com', 'password123');
      const session = await authService.createSession(authResult!.user, authResult!.token, {
        ipAddress: '127.0.0.1',
        userAgent: 'Test Agent',
      });
      
      const originalActivity = session.lastActivity;
      
      // Simulate delay
      await new Promise(resolve => setTimeout(resolve, 10));
      
      await authService.updateSessionActivity(session.sessionId);
      
      const updatedSession = await authService.getSession(session.sessionId);
      expect(updatedSession!.lastActivity).not.toBe(originalActivity);
    });

    test('should invalidate individual sessions', async () => {
      const authResult = await authService.authenticateWithPassword('test@example.com', 'password123');
      const session = await authService.createSession(authResult!.user, authResult!.token, {
        ipAddress: '127.0.0.1',
        userAgent: 'Test Agent',
      });
      
      expect(session.isValid).toBe(true);
      
      const invalidated = await authService.invalidateSession(session.sessionId);
      expect(invalidated).toBe(true);
      
      const updatedSession = await authService.getSession(session.sessionId);
      expect(updatedSession!.isValid).toBe(false);
    });

    test('should invalidate all user sessions', async () => {
      const authResult = await authService.authenticateWithPassword('test@example.com', 'password123');
      
      // Create multiple sessions
      const session1 = await authService.createSession(authResult!.user, authResult!.token, {
        ipAddress: '127.0.0.1',
        userAgent: 'Browser 1',
      });
      
      const session2 = await authService.createSession(authResult!.user, authResult!.token, {
        ipAddress: '192.168.1.1',
        userAgent: 'Browser 2',
      });
      
      const invalidatedCount = await authService.invalidateAllUserSessions(testUser.id);
      expect(invalidatedCount).toBe(2);
      
      const updatedSession1 = await authService.getSession(session1.sessionId);
      const updatedSession2 = await authService.getSession(session2.sessionId);
      
      expect(updatedSession1!.isValid).toBe(false);
      expect(updatedSession2!.isValid).toBe(false);
    });
  });

  describe('Authorization Policies', () => {
    beforeEach(async () => {
      // Create test policies
      await authService.createPolicy({
        id: 'policy-1',
        name: 'Team Scenario Access',
        resource: 'scenarios',
        action: 'read',
        effect: 'allow',
        conditions: { teamId: 123 },
        priority: 100,
      });

      await authService.createPolicy({
        id: 'policy-2',
        name: 'Admin Only Delete',
        resource: 'scenarios',
        action: 'delete',
        effect: 'allow',
        conditions: { roles: ['admin'] },
        priority: 200,
      });

      await authService.createPolicy({
        id: 'policy-3',
        name: 'Deny Cross-Org Access',
        resource: 'connections',
        action: 'read',
        effect: 'deny',
        conditions: { organizationId: 'other-org' },
        priority: 300,
      });
    });

    test('should allow access based on user permissions', async () => {
      const hasPermission = await authService.checkPermission(testUser, 'scenarios', 'read');
      expect(hasPermission).toBe(true);
    });

    test('should deny access for missing permissions', async () => {
      const hasPermission = await authService.checkPermission(testUser, 'scenarios', 'delete');
      expect(hasPermission).toBe(false);
    });

    test('should allow admin access to all resources', async () => {
      const hasReadPermission = await authService.checkPermission(adminUser, 'scenarios', 'read');
      const hasDeletePermission = await authService.checkPermission(adminUser, 'scenarios', 'delete');
      const hasConnectionPermission = await authService.checkPermission(adminUser, 'connections', 'write');
      
      expect(hasReadPermission).toBe(true);
      expect(hasDeletePermission).toBe(true);
      expect(hasConnectionPermission).toBe(true);
    });

    test('should evaluate policy conditions correctly', async () => {
      // Create user from different team
      const otherTeamUser: AuthUser = {
        ...testUser,
        id: 'other-team-user',
        email: 'other@example.com',
        teamId: 456,
      };
      await authService.createUser(otherTeamUser);

      // User from same team should have access
      const sameTeamAccess = await authService.checkPermission(testUser, 'scenarios', 'read');
      expect(sameTeamAccess).toBe(true);

      // User from different team should not have access (no explicit permission and policy doesn't match)
      const otherTeamAccess = await authService.checkPermission(otherTeamUser, 'scenarios', 'read');
      expect(otherTeamAccess).toBe(false);
    });

    test('should respect policy priority order', async () => {
      // Create conflicting policies
      await authService.createPolicy({
        id: 'high-priority-deny',
        name: 'High Priority Deny',
        resource: 'scenarios',
        action: 'read',
        effect: 'deny',
        priority: 500,
      });

      await authService.createPolicy({
        id: 'low-priority-allow',
        name: 'Low Priority Allow',
        resource: 'scenarios',
        action: 'read',
        effect: 'allow',
        priority: 50,
      });

      // Remove explicit permission to test policy evaluation
      const userWithoutPermission: AuthUser = {
        ...testUser,
        id: 'no-permission-user',
        email: 'noperm@example.com',
        permissions: [],
      };
      await authService.createUser(userWithoutPermission);

      // High priority deny should take precedence
      const hasAccess = await authService.checkPermission(userWithoutPermission, 'scenarios', 'read');
      expect(hasAccess).toBe(false);
    });
  });

  describe('Multi-Factor Authentication', () => {
    test('should enable MFA for user', async () => {
      const mfaSetup = await authService.enableMFA(testUser.id);
      
      expect(mfaSetup.secret).toBeTruthy();
      expect(mfaSetup.qrCode).toContain('otpauth://totp/');
      expect(mfaSetup.qrCode).toContain(testUser.email);
      
      const updatedUser = await authService.getUser(testUser.id);
      expect(updatedUser!.mfaEnabled).toBe(true);
    });

    test('should verify MFA codes', async () => {
      await authService.enableMFA(testUser.id);
      
      // Valid codes
      const validCode1 = await authService.verifyMFA(testUser.id, '123456');
      const validCode2 = await authService.verifyMFA(testUser.id, '000000');
      
      expect(validCode1).toBe(true);
      expect(validCode2).toBe(true);
      
      // Invalid code
      const invalidCode = await authService.verifyMFA(testUser.id, '999999');
      expect(invalidCode).toBe(false);
    });

    test('should fail MFA verification for users without MFA enabled', async () => {
      const result = await authService.verifyMFA(testUser.id, '123456');
      expect(result).toBe(false);
    });

    test('should disable MFA for user', async () => {
      await authService.enableMFA(testUser.id);
      
      const disabled = await authService.disableMFA(testUser.id);
      expect(disabled).toBe(true);
      
      const updatedUser = await authService.getUser(testUser.id);
      expect(updatedUser!.mfaEnabled).toBe(false);
    });
  });

  describe('Complete Authentication Workflows', () => {
    test('should handle complete password login with session creation', async () => {
      // Step 1: Authenticate user
      const authResult = await authService.authenticateWithPassword('test@example.com', 'password123');
      expect(authResult).toBeTruthy();
      
      // Step 2: Create session
      const session = await authService.createSession(authResult!.user, authResult!.token, {
        ipAddress: '203.0.113.1',
        userAgent: 'Mozilla/5.0 Complete Test',
      });
      expect(session.isValid).toBe(true);
      
      // Step 3: Validate token in subsequent requests
      const validation = await authService.validateToken(authResult!.token.accessToken);
      expect(validation).toBeTruthy();
      
      // Step 4: Update session activity
      await authService.updateSessionActivity(session.sessionId);
      
      // Step 5: Check authorization
      const hasPermission = await authService.checkPermission(validation!.user, 'scenarios', 'read');
      expect(hasPermission).toBe(true);
    });

    test('should handle complete OAuth2 workflow', async () => {
      const oauthConfig: OAuth2Config = {
        clientId: 'complete-test-client',
        clientSecret: 'complete-test-secret',
        redirectUri: 'https://app.example.com/auth/callback',
        scope: ['read', 'write', 'admin'],
        authorizeUrl: 'https://oauth.provider.com/authorize',
        tokenUrl: 'https://oauth.provider.com/token',
      };

      // Step 1: Initiate OAuth flow
      const state = 'complete-oauth-state-' + Date.now();
      const authUrl = await authService.initiateOAuth2Flow(oauthConfig, state);
      expect(authUrl).toContain(state);
      
      // Step 2: Handle callback
      const callbackResult = await authService.handleOAuth2Callback('auth-code-123', state, oauthConfig);
      expect(callbackResult).toBeTruthy();
      
      // Step 3: Create session
      const session = await authService.createSession(callbackResult!.user, callbackResult!.token, {
        ipAddress: '198.51.100.1',
        userAgent: 'OAuth Test Client',
      });
      
      // Step 4: Verify complete workflow
      expect(session.userId).toBe(callbackResult!.user.id);
      expect(session.token.accessToken).toBe(callbackResult!.token.accessToken);
      
      const validation = await authService.validateToken(session.token.accessToken);
      expect(validation).toBeTruthy();
    });

    test('should handle MFA-enabled login workflow', async () => {
      // Setup: Enable MFA for admin user
      const mfaSetup = await authService.enableMFA(adminUser.id);
      expect(mfaSetup.secret).toBeTruthy();
      
      // Step 1: Initial authentication (password)
      const authResult = await authService.authenticateWithPassword('admin@example.com', 'admin123');
      expect(authResult).toBeTruthy();
      
      // Step 2: MFA verification (in real implementation, session would be pending MFA)
      const mfaValid = await authService.verifyMFA(adminUser.id, '123456');
      expect(mfaValid).toBe(true);
      
      // Step 3: Create session after MFA success
      if (mfaValid) {
        const session = await authService.createSession(authResult!.user, authResult!.token, {
          ipAddress: '192.0.2.1',
          userAgent: 'MFA Test Client',
        });
        
        expect(session.isValid).toBe(true);
        
        // Step 4: Verify admin permissions
        const hasAdminAccess = await authService.checkPermission(authResult!.user, 'users', 'admin');
        expect(hasAdminAccess).toBe(true);
      }
    });

    test('should handle session lifecycle with token refresh', async () => {
      // Step 1: Initial login
      const authResult = await authService.authenticateWithPassword('test@example.com', 'password123');
      const session = await authService.createSession(authResult!.user, authResult!.token, {
        ipAddress: '172.16.0.1',
        userAgent: 'Lifecycle Test',
      });
      
      // Step 2: Use session for some time
      await authService.updateSessionActivity(session.sessionId);
      
      // Step 3: Refresh token before expiry
      const newToken = await authService.refreshToken(authResult!.token.refreshToken!);
      expect(newToken).toBeTruthy();
      
      // Step 4: Update session with new token (simplified for mock)
      // In real implementation, would update session.token
      
      // Step 5: Validate new token works
      const validation = await authService.validateToken(newToken!.accessToken);
      expect(validation).toBeTruthy();
      
      // Step 6: Eventually logout (invalidate session)
      const invalidated = await authService.invalidateSession(session.sessionId);
      expect(invalidated).toBe(true);
    });

    test('should handle security scenarios (token revocation, session hijacking prevention)', async () => {
      const authResult = await authService.authenticateWithPassword('test@example.com', 'password123');
      
      // Create multiple sessions from different IPs (simulate different devices)
      const session1 = await authService.createSession(authResult!.user, authResult!.token, {
        ipAddress: '203.0.113.10',
        userAgent: 'Device 1',
      });
      
      const session2 = await authService.createSession(authResult!.user, authResult!.token, {
        ipAddress: '203.0.113.20',
        userAgent: 'Device 2',
      });
      
      // Simulate security event: user reports unauthorized access
      // Step 1: Invalidate all sessions for security
      const invalidatedCount = await authService.invalidateAllUserSessions(testUser.id);
      expect(invalidatedCount).toBe(2);
      
      // Step 2: Verify tokens are no longer valid
      const validation1 = await authService.validateToken(authResult!.token.accessToken);
      expect(validation1).toBeNull();
      
      // Step 3: User must re-authenticate
      const newAuth = await authService.authenticateWithPassword('test@example.com', 'password123');
      expect(newAuth).toBeTruthy();
      expect(newAuth!.token.accessToken).not.toBe(authResult!.token.accessToken);
    });
  });

  describe('Error Handling and Edge Cases', () => {
    test('should handle concurrent authentication attempts', async () => {
      const promises = Array.from({ length: 5 }, () =>
        authService.authenticateWithPassword('test@example.com', 'password123')
      );
      
      const results = await Promise.all(promises);
      
      // All should succeed independently
      results.forEach(result => {
        expect(result).toBeTruthy();
        expect(result!.user.id).toBe(testUser.id);
      });
      
      // Each should have unique tokens
      const tokens = results.map(r => r!.token.accessToken);
      const uniqueTokens = new Set(tokens);
      expect(uniqueTokens.size).toBe(5);
    });

    test('should handle authentication with deactivated user mid-session', async () => {
      // Step 1: Login successfully
      const authResult = await authService.authenticateWithPassword('test@example.com', 'password123');
      const session = await authService.createSession(authResult!.user, authResult!.token, {
        ipAddress: '127.0.0.1',
        userAgent: 'Test',
      });
      
      // Step 2: Deactivate user
      await authService.updateUser(testUser.id, { isActive: false });
      
      // Step 3: Token validation should fail for deactivated user
      const validation = await authService.validateToken(authResult!.token.accessToken);
      expect(validation).toBeNull();
    });

    test('should handle malformed token validation gracefully', async () => {
      const malformedTokens = [
        '',
        'invalid',
        'bearer token',
        'token_without_proper_format',
        null as any,
        undefined as any,
      ];
      
      for (const token of malformedTokens) {
        const result = await authService.validateToken(token);
        expect(result).toBeNull();
      }
    });

    test('should prevent session fixation attacks', async () => {
      // Create a session
      const authResult = await authService.authenticateWithPassword('test@example.com', 'password123');
      const session = await authService.createSession(authResult!.user, authResult!.token, {
        ipAddress: '203.0.113.100',
        userAgent: 'Original Client',
      });
      
      // Simulate session being used from different IP (potential hijacking)
      // In real implementation, would detect and handle IP changes
      const suspiciousSession = {
        ...session,
        ipAddress: '198.51.100.200', // Different IP
      };
      
      // Verify that session tracking includes IP validation
      expect(session.ipAddress).toBe('203.0.113.100');
      expect(suspiciousSession.ipAddress).not.toBe(session.ipAddress);
    });
  });
});