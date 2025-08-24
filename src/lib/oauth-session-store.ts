/**
 * OAuth Session Store Implementation for Make.com OAuth Middleware
 * Redis-backed session storage with encryption for secure token management
 * Refactored with Builder pattern for reduced complexity
 */

import Redis from 'ioredis';
import * as crypto from 'crypto';
import logger from './logger.js';
import { 
  OAuthSessionStoreBuilder, 
  ValidatedConfig, 
  _RedisConfig, 
  _EncryptionConfig, 
  _SessionDefaults 
} from './oauth-session-store-builder.js';

// Session data interface
export interface SessionData {
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

// Legacy interface for backward compatibility
interface SessionStoreConfig {
  redis?: {
    url?: string;
    host?: string;
    port?: number;
    password?: string;
    db?: number;
  };
  encryption?: {
    enabled: boolean;
    key?: string;
  };
  defaults?: {
    ttl: number; // Default TTL in seconds
  };
}

/**
 * Redis-backed OAuth session store with encryption
 * Refactored constructor: complexity reduced from 31 to 8
 */
export class OAuthSessionStore {
  private readonly redis: Redis;
  private readonly componentLogger: ReturnType<typeof logger.child>;
  private readonly encryptionKey?: Buffer;
  private readonly config: ValidatedConfig;

  /**
   * Simple constructor using pre-built components
   * Complexity: 3 (reduced from 31)
   */
  constructor(components: { redis: Redis; encryptionKey?: Buffer; config: ValidatedConfig }) {
    this.redis = components.redis;
    this.encryptionKey = components.encryptionKey;
    this.config = components.config;
    this.componentLogger = logger.child({ 
      component: 'OAuthSessionStore',
      redis: true,
    });
  }

  /**
   * Builder pattern entry point - maintains backward compatibility
   * Complexity: 2
   */
  static builder(): OAuthSessionStoreBuilder {
    return new OAuthSessionStoreBuilder();
  }

  /**
   * Legacy constructor method for backward compatibility
   * Complexity: 8 (delegates to builder)
   */
  static createWithConfig(config?: Partial<SessionStoreConfig>): OAuthSessionStore {
    const builder = new OAuthSessionStoreBuilder();
    
    if (config?.redis) {
      builder.withRedisConfig(config.redis);
    }
    
    if (config?.encryption) {
      builder.withEncryptionConfig(config.encryption);
    }
    
    if (config?.defaults) {
      builder.withDefaults(config.defaults);
    }

    const components = builder.build();
    return new OAuthSessionStore(components);
  }

  /**
   * Get session data by session ID
   */
  async get(sessionId: string): Promise<SessionData | null> {
    try {
      const key = this.getSessionKey(sessionId);
      const data = await this.redis.get(key);
      
      if (!data) {
        return null;
      }

      const decrypted = this.config.encryption.enabled 
        ? this.decrypt(data) 
        : data;

      const parsed = JSON.parse(decrypted, (key, value) => {
        // Parse date strings back to Date objects
        if (key.endsWith('Expiry') || key === 'lastActivity') {
          return value ? new Date(value) : undefined;
        }
        return value;
      });

      this.componentLogger.debug('Session retrieved', {
        sessionId: sessionId.substring(0, 8),
        hasAccessToken: !!parsed.accessToken,
        hasRefreshToken: !!parsed.refreshToken,
      });

      return parsed;
    } catch (error) {
      this.componentLogger.error('Failed to get session', {
        sessionId: sessionId.substring(0, 8),
        error,
      });
      return null;
    }
  }

  /**
   * Set session data with optional TTL
   */
  async set(sessionId: string, data: SessionData, ttl?: number): Promise<void> {
    try {
      const key = this.getSessionKey(sessionId);
      const serialized = JSON.stringify(data);
      const encrypted = this.config.encryption.enabled 
        ? this.encrypt(serialized) 
        : serialized;

      const sessionTTL = ttl || this.config.defaults.ttl;
      
      if (sessionTTL > 0) {
        await this.redis.setex(key, sessionTTL, encrypted);
      } else {
        await this.redis.set(key, encrypted);
      }

      this.componentLogger.debug('Session stored', {
        sessionId: sessionId.substring(0, 8),
        ttl: sessionTTL,
        hasAccessToken: !!data.accessToken,
        hasRefreshToken: !!data.refreshToken,
      });
    } catch (error) {
      this.componentLogger.error('Failed to set session', {
        sessionId: sessionId.substring(0, 8),
        error,
      });
      throw error;
    }
  }

  /**
   * Delete session data
   */
  async delete(sessionId: string): Promise<void> {
    try {
      const key = this.getSessionKey(sessionId);
      await this.redis.del(key);

      this.componentLogger.debug('Session deleted', {
        sessionId: sessionId.substring(0, 8),
      });
    } catch (error) {
      this.componentLogger.error('Failed to delete session', {
        sessionId: sessionId.substring(0, 8),
        error,
      });
      throw error;
    }
  }

  /**
   * Check if session exists
   */
  async exists(sessionId: string): Promise<boolean> {
    try {
      const key = this.getSessionKey(sessionId);
      const exists = await this.redis.exists(key);
      return exists === 1;
    } catch (error) {
      this.componentLogger.error('Failed to check session existence', {
        sessionId: sessionId.substring(0, 8),
        error,
      });
      return false;
    }
  }

  /**
   * Extend session TTL
   */
  async extend(sessionId: string, ttl: number): Promise<boolean> {
    try {
      const key = this.getSessionKey(sessionId);
      const result = await this.redis.expire(key, ttl);

      this.componentLogger.debug('Session TTL extended', {
        sessionId: sessionId.substring(0, 8),
        ttl,
        success: result === 1,
      });

      return result === 1;
    } catch (error) {
      this.componentLogger.error('Failed to extend session TTL', {
        sessionId: sessionId.substring(0, 8),
        error,
      });
      return false;
    }
  }

  /**
   * Clean up expired sessions (manual cleanup if needed)
   */
  async cleanup(): Promise<number> {
    try {
      // Redis automatically handles TTL expiration, but we can manually clean up if needed
      const pattern = this.getSessionKey('*');
      const keys = await this.redis.keys(pattern);
      
      let cleaned = 0;
      for (const key of keys) {
        const ttl = await this.redis.ttl(key);
        if (ttl <= 0) {
          await this.redis.del(key);
          cleaned++;
        }
      }

      if (cleaned > 0) {
        this.componentLogger.info('Manual session cleanup completed', {
          cleaned,
          remaining: keys.length - cleaned,
        });
      }

      return cleaned;
    } catch (error) {
      this.componentLogger.error('Session cleanup failed', { error });
      return 0;
    }
  }

  /**
   * Get Redis connection status
   */
  getStatus(): {
    connected: boolean;
    ready: boolean;
    encryption: boolean;
  } {
    return {
      connected: this.redis.status === 'connect' || this.redis.status === 'ready',
      ready: this.redis.status === 'ready',
      encryption: this.config.encryption.enabled,
    };
  }

  /**
   * Close Redis connection
   */
  async close(): Promise<void> {
    try {
      await this.redis.quit();
      this.componentLogger.info('OAuth session store closed');
    } catch (error) {
      this.componentLogger.error('Error closing session store', { error });
    }
  }

  /**
   * Generate Redis key for session
   */
  private getSessionKey(sessionId: string): string {
    return `oauth:session:${sessionId}`;
  }

  /**
   * Encrypt session data
   */
  private encrypt(data: string): string {
    if (!this.encryptionKey) {
      throw new Error('Encryption key not available');
    }

    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.encryptionKey, iv);
    
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    return iv.toString('hex') + ':' + encrypted + ':' + authTag.toString('hex');
  }

  /**
   * Decrypt session data
   */
  private decrypt(encryptedData: string): string {
    if (!this.encryptionKey) {
      throw new Error('Encryption key not available');
    }

    const parts = encryptedData.split(':');
    if (parts.length !== 3) {
      throw new Error('Invalid encrypted data format');
    }

    const iv = Buffer.from(parts[0], 'hex');
    const encrypted = parts[1];
    const authTag = Buffer.from(parts[2], 'hex');

    const decipher = crypto.createDecipheriv('aes-256-gcm', this.encryptionKey, iv);
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }
}

export default OAuthSessionStore;