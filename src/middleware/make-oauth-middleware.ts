/**
 * Make.com OAuth Middleware for FastMCP Server
 * Provides OAuth 2.1 + PKCE authentication middleware for FastMCP requests
 * Integrates with existing OAuth21Authenticator infrastructure
 */

import { OAuth21Authenticator } from "../lib/oauth-authenticator.js";
import {
  getMakeOAuthConfig,
  validateProductionConfig,
} from "../config/make-oauth-config.js";
import { AuthenticationError } from "../utils/errors.js";
import logger from "../lib/logger.js";
import crypto from "crypto";

// Session storage interface (Redis-backed in production)
interface SessionStore {
  get(sessionId: string): Promise<SessionData | null>;
  set(sessionId: string, data: SessionData, ttl?: number): Promise<void>;
  delete(sessionId: string): Promise<void>;
}

// Session data structure
interface SessionData {
  userId?: string;
  accessToken?: string;
  refreshToken?: string;
  tokenExpiry?: Date;
  codeVerifier?: string;
  state?: string;
  scopes?: string[];
  userInfo?: Record<string, unknown>;
  lastActivity: Date;
}

// OAuth flow state
interface OAuthFlowState {
  codeVerifier: string;
  codeChallenge: string;
  state: string;
  redirectUri: string;
  scopes: string;
}

/**
 * Make.com OAuth Middleware for FastMCP Server
 * Handles OAuth 2.1 authentication flows with PKCE
 */
export class MakeOAuthMiddleware {
  private readonly oauthClient: OAuth21Authenticator;
  private readonly sessionStore: SessionStore;
  private readonly componentLogger: ReturnType<typeof logger.child>;
  private readonly config: ReturnType<typeof getMakeOAuthConfig>;

  constructor(sessionStore: SessionStore) {
    this.componentLogger = logger.child({
      component: "MakeOAuthMiddleware",
      integration: "make.com",
    });

    // Load and validate Make.com OAuth configuration
    this.config = getMakeOAuthConfig();
    const validation = validateProductionConfig(this.config);

    if (!validation.valid) {
      throw new AuthenticationError(
        `OAuth configuration invalid: ${validation.errors.join(", ")}`,
      );
    }

    if (validation.warnings.length > 0) {
      this.componentLogger.warn("OAuth configuration warnings", {
        warnings: validation.warnings,
      });
    }

    // Initialize OAuth client with Make.com configuration
    this.oauthClient = new OAuth21Authenticator({
      clientId: this.config.clientId,
      clientSecret: this.config.clientSecret,
      redirectUri: this.config.redirectUri,
      scope: this.config.scope,
      tokenEndpoint: this.config.tokenEndpoint,
      authEndpoint: this.config.authEndpoint,
      revokeEndpoint: this.config.revokeEndpoint,
      usePKCE: this.config.usePKCE,
    });

    this.sessionStore = sessionStore;

    this.componentLogger.info("Make.com OAuth middleware initialized", {
      clientId: this.config.clientId,
      usePKCE: this.config.usePKCE,
      scope: this.config.scope.split(" ").length,
    });
  }

  /**
   * Initiate OAuth authorization flow
   * Generates authorization URL with PKCE challenge
   */
  async initiateOAuthFlow(
    sessionId: string,
    customScopes?: string,
    customRedirectUri?: string,
  ): Promise<{
    authorizationUrl: string;
    state: string;
    codeVerifier: string;
  }> {
    const correlationId = crypto.randomUUID();
    const componentLogger = this.componentLogger.child({
      operation: "initiateOAuthFlow",
      sessionId: sessionId.substring(0, 8),
      correlationId,
    });

    try {
      // Generate PKCE challenge
      const pkceChallenge = this.oauthClient.generatePKCEChallenge();
      const state = crypto.randomBytes(16).toString("hex");

      // Create OAuth flow state
      const flowState: OAuthFlowState = {
        codeVerifier: pkceChallenge.code_verifier,
        codeChallenge: pkceChallenge.code_challenge,
        state,
        redirectUri: customRedirectUri || this.config.redirectUri,
        scopes: customScopes || this.config.scope,
      };

      // Store PKCE verifier and state in session
      await this.sessionStore.set(
        sessionId,
        {
          codeVerifier: flowState.codeVerifier,
          state: flowState.state,
          lastActivity: new Date(),
        },
        1800,
      ); // 30 minutes

      // Generate authorization URL
      const authorizationUrl = this.oauthClient.generateAuthorizationUrl(
        state,
        pkceChallenge,
      );

      componentLogger.info("OAuth flow initiated successfully", {
        hasCustomScopes: !!customScopes,
        hasCustomRedirect: !!customRedirectUri,
        scopeCount: flowState.scopes.split(" ").length,
      });

      return {
        authorizationUrl,
        state: flowState.state,
        codeVerifier: flowState.codeVerifier,
      };
    } catch (error) {
      componentLogger.error("OAuth flow initiation failed", { error });
      throw new AuthenticationError("Failed to initiate OAuth flow");
    }
  }

  /**
   * Handle OAuth callback and exchange code for tokens
   */
  async handleOAuthCallback(
    sessionId: string,
    authorizationCode: string,
    state: string,
    receivedState?: string,
  ): Promise<{
    accessToken: string;
    refreshToken?: string;
    userInfo?: Record<string, unknown>;
  }> {
    const correlationId = crypto.randomUUID();
    const componentLogger = this.componentLogger.child({
      operation: "handleOAuthCallback",
      sessionId: sessionId.substring(0, 8),
      correlationId,
    });

    try {
      // Retrieve session data
      const session = await this.sessionStore.get(sessionId);
      if (!session) {
        throw new AuthenticationError("Invalid or expired session");
      }

      // Validate state parameter (CSRF protection)
      if (state !== session.state) {
        componentLogger.warn("State parameter mismatch", {
          expected: session.state,
          received: receivedState,
        });
        throw new AuthenticationError("Invalid state parameter");
      }

      // Exchange authorization code for tokens using PKCE
      const tokens = await this.oauthClient.exchangeCodeForToken(
        authorizationCode,
        session.codeVerifier,
        correlationId,
      );

      // Fetch user information if userinfo endpoint is configured
      let userInfo: Record<string, unknown> | undefined;
      try {
        const userInfoResponse = await fetch(this.config.userinfoEndpoint, {
          method: "GET",
          headers: {
            Authorization: `Bearer ${tokens.access_token}`,
            Accept: "application/json",
          },
        });

        if (userInfoResponse.ok) {
          userInfo = await userInfoResponse.json();
          componentLogger.debug("User info retrieved successfully");
        }
      } catch (error) {
        componentLogger.warn("Failed to fetch user info", { error });
        // Non-critical - continue without user info
      }

      // Update session with tokens and user info
      const tokenExpiry = tokens.expires_in
        ? new Date(Date.now() + tokens.expires_in * 1000)
        : new Date(Date.now() + 3600 * 1000); // Default 1 hour

      await this.sessionStore.set(
        sessionId,
        {
          ...session,
          accessToken: tokens.access_token,
          refreshToken: tokens.refresh_token,
          tokenExpiry,
          userInfo,
          lastActivity: new Date(),
          // Clear OAuth flow state
          codeVerifier: undefined,
          state: undefined,
        },
        3600,
      ); // 1 hour session

      componentLogger.info("OAuth callback handled successfully", {
        hasRefreshToken: !!tokens.refresh_token,
        hasUserInfo: !!userInfo,
        tokenExpiry: tokenExpiry.toISOString(),
      });

      return {
        accessToken: tokens.access_token,
        refreshToken: tokens.refresh_token,
        userInfo,
      };
    } catch (error) {
      componentLogger.error("OAuth callback handling failed", { error });

      // Clean up failed session
      try {
        await this.sessionStore.delete(sessionId);
      } catch (cleanupError) {
        componentLogger.warn("Failed to clean up session after OAuth failure", {
          cleanupError,
        });
      }

      if (error instanceof AuthenticationError) {
        throw error;
      }
      throw new AuthenticationError("OAuth callback processing failed");
    }
  }

  /**
   * Authenticate FastMCP request using OAuth token
   */
  async authenticateRequest(
    sessionId: string,
    correlationId?: string,
  ): Promise<{
    authenticated: boolean;
    userId?: string;
    scopes?: string[];
    userInfo?: Record<string, unknown>;
  }> {
    const requestId = correlationId || crypto.randomUUID();
    const componentLogger = this.componentLogger.child({
      operation: "authenticateRequest",
      sessionId: sessionId.substring(0, 8),
      correlationId: requestId,
    });

    try {
      // Retrieve session
      const session = await this.sessionStore.get(sessionId);
      if (!session?.accessToken) {
        componentLogger.debug("No valid session found");
        return { authenticated: false };
      }

      // Check token expiry
      if (session.tokenExpiry && session.tokenExpiry <= new Date()) {
        componentLogger.debug("Access token expired, attempting refresh");

        if (session.refreshToken) {
          try {
            await this.refreshAccessToken(sessionId);
            // Retry with refreshed token
            const updatedSession = await this.sessionStore.get(sessionId);
            if (updatedSession?.accessToken) {
              return this.validateAccessToken(
                updatedSession,
                componentLogger,
                requestId,
              );
            }
          } catch (error) {
            componentLogger.warn("Token refresh failed", { error });
          }
        }

        componentLogger.debug("Token expired and refresh failed");
        return { authenticated: false };
      }

      return this.validateAccessToken(session, componentLogger, requestId);
    } catch (error) {
      componentLogger.error("Request authentication failed", { error });
      return { authenticated: false };
    }
  }

  /**
   * Validate access token with Make.com
   */
  private async validateAccessToken(
    session: SessionData,
    componentLogger: ReturnType<typeof logger.child>,
    requestId: string,
  ): Promise<{
    authenticated: boolean;
    userId?: string;
    scopes?: string[];
    userInfo?: Record<string, unknown>;
  }> {
    if (!session.accessToken) {
      return { authenticated: false };
    }

    try {
      // Validate token using OAuth21Authenticator
      const validation = await this.oauthClient.validateBearerToken(
        session.accessToken,
        requestId,
      );

      if (validation.valid) {
        // Update session last activity
        await this.sessionStore.set(session.userId || requestId, {
          ...session,
          lastActivity: new Date(),
        });

        componentLogger.debug("Access token validated successfully");

        return {
          authenticated: true,
          userId: session.userId || (session.userInfo?.sub as string),
          scopes: session.scopes,
          userInfo: session.userInfo,
        };
      } else {
        componentLogger.warn("Access token validation failed", {
          error: validation.error,
        });
        return { authenticated: false };
      }
    } catch (error) {
      componentLogger.error("Token validation error", { error });
      return { authenticated: false };
    }
  }

  /**
   * Refresh access token using refresh token
   */
  async refreshAccessToken(sessionId: string): Promise<void> {
    const correlationId = crypto.randomUUID();
    const componentLogger = this.componentLogger.child({
      operation: "refreshAccessToken",
      sessionId: sessionId.substring(0, 8),
      correlationId,
    });

    try {
      const session = await this.sessionStore.get(sessionId);
      if (!session?.refreshToken) {
        throw new AuthenticationError("No refresh token available");
      }

      // Refresh tokens
      const newTokens = await this.oauthClient.refreshToken(
        session.refreshToken,
        correlationId,
      );

      // Update session with new tokens
      const tokenExpiry = newTokens.expires_in
        ? new Date(Date.now() + newTokens.expires_in * 1000)
        : new Date(Date.now() + 3600 * 1000);

      await this.sessionStore.set(sessionId, {
        ...session,
        accessToken: newTokens.access_token,
        refreshToken: newTokens.refresh_token || session.refreshToken,
        tokenExpiry,
        lastActivity: new Date(),
      });

      componentLogger.info("Access token refreshed successfully");
    } catch (error) {
      componentLogger.error("Token refresh failed", { error });
      throw new AuthenticationError("Failed to refresh access token");
    }
  }

  /**
   * Revoke tokens and clear session
   */
  async logout(sessionId: string): Promise<void> {
    const correlationId = crypto.randomUUID();
    const componentLogger = this.componentLogger.child({
      operation: "logout",
      sessionId: sessionId.substring(0, 8),
      correlationId,
    });

    try {
      const session = await this.sessionStore.get(sessionId);

      // Revoke access token if available
      if (session?.accessToken) {
        try {
          await this.oauthClient.revokeToken(
            session.accessToken,
            correlationId,
          );
        } catch (error) {
          componentLogger.warn("Token revocation failed", { error });
          // Continue with session cleanup even if revocation fails
        }
      }

      // Clear session
      await this.sessionStore.delete(sessionId);

      componentLogger.info("User logged out successfully");
    } catch (error) {
      componentLogger.error("Logout failed", { error });
      throw new AuthenticationError("Logout failed");
    }
  }

  /**
   * Get OAuth configuration for client applications
   */
  getPublicConfig(): Partial<ReturnType<typeof getMakeOAuthConfig>> {
    return this.oauthClient.getPublicConfig();
  }
}

export default MakeOAuthMiddleware;
