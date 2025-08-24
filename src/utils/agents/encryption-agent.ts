/**
 * Encryption Agent - Handles credential encryption operations, key management, and secure credential generation
 * Ensures all credentials are properly encrypted and manages encryption keys securely
 */

import {
  RotationAgentBase,
  AgentConfig,
  AgentMessage,
} from "../rotation-agent-base.js";
import type { EncryptionAlgorithm } from "../../types/rotation-types.js";
import * as crypto from "crypto";
import { promisify } from "util";

const _sleep = promisify(setTimeout);

/**
 * Encryption operation types
 */
type _EncryptionOperationType =
  | "encrypt"
  | "decrypt"
  | "generate_key"
  | "rotate_key"
  | "generate_credential"
  | "validate_encryption";

/**
 * Encryption configuration interface
 */
interface EncryptionConfig {
  algorithm: EncryptionAlgorithm;
  keySize: number;
  ivSize: number;
  tagSize: number;
  saltSize: number;
  iterations: number;
}

/**
 * Key derivation result
 */
interface _KeyDerivationResult {
  key: Buffer;
  salt: Buffer;
  iterations: number;
  algorithm: string;
}

/**
 * Encryption Agent configuration
 */
export interface EncryptionAgentConfig extends AgentConfig {
  defaultAlgorithm?: EncryptionAlgorithm;
  keyRotationIntervalMs?: number;
  maxKeyAge?: number;
  enableHardwareSecurityModule?: boolean;
  keyStorageEnabled?: boolean;
  keyDerivationIterations?: number;
  credentialGenerationDefaults?: {
    length: number;
    includeSpecialChars: boolean;
    excludeSimilarChars: boolean;
  };
}

/**
 * Key metadata for tracking
 */
interface KeyMetadata {
  keyId: string;
  algorithm: EncryptionAlgorithm;
  createdAt: Date;
  lastUsed: Date;
  usageCount: number;
  maxAge: number;
  status: "active" | "deprecated" | "revoked";
}

/**
 * Encryption result interface
 */
interface EncryptionResult {
  success: boolean;
  encryptedData?: string;
  keyId?: string;
  algorithm?: EncryptionAlgorithm;
  metadata?: Record<string, unknown>;
  error?: string;
}

/**
 * Encryption Agent - handles all encryption operations for credential rotation
 */
export class EncryptionAgent extends RotationAgentBase {
  private readonly config: EncryptionAgentConfig;
  private readonly encryptionConfigs: Map<
    EncryptionAlgorithm,
    EncryptionConfig
  > = new Map();
  private readonly activeKeys: Map<string, KeyMetadata> = new Map();
  private readonly keyStorage: Map<string, Buffer> = new Map();

  // Performance tracking
  private encryptionCount = 0;
  private decryptionCount = 0;
  private keyGenerationCount = 0;
  private totalEncryptionTime = 0;
  private totalDecryptionTime = 0;
  private encryptionFailures = 0;

  // Key rotation management
  private keyRotationTimer?: NodeJS.Timeout;
  private currentMasterKeyId?: string;

  constructor(config: EncryptionAgentConfig) {
    super({
      ...config,
      role: "encryption",
    });

    this.config = config;
    this.setupEncryptionConfigs();

    this.componentLogger.info("Encryption Agent created", {
      defaultAlgorithm: config.defaultAlgorithm,
      keyRotationInterval: config.keyRotationIntervalMs,
      hsmEnabled: config.enableHardwareSecurityModule,
    });
  }

  protected async initializeAgent(): Promise<void> {
    this.componentLogger.info("Initializing Encryption Agent");

    // Generate initial master key
    await this.generateMasterKey();

    // Start key rotation timer if configured
    if (this.config.keyRotationIntervalMs) {
      this.startKeyRotationTimer();
    }

    this.componentLogger.info("Encryption Agent initialized successfully");
  }

  protected async shutdownAgent(): Promise<void> {
    this.componentLogger.info("Shutting down Encryption Agent");

    // Stop key rotation timer
    if (this.keyRotationTimer) {
      clearInterval(this.keyRotationTimer);
    }

    // Securely clear key storage
    this.keyStorage.clear();
    this.activeKeys.clear();

    this.componentLogger.info("Encryption Agent shutdown completed");
  }

  protected async processMessage(
    message: AgentMessage,
  ): Promise<Record<string, unknown>> {
    const { type, payload } = message;

    switch (type) {
      case "encrypt_credential":
        return this.encryptCredential(payload);

      case "decrypt_credential":
        return this.decryptCredential(payload);

      case "generate_credential":
        return this.generateCredential(payload);

      case "generate_encryption_key":
        return this.generateEncryptionKey(payload);

      case "rotate_encryption_keys":
        return this.rotateEncryptionKeys(payload);

      case "validate_encryption":
        return this.validateEncryption(payload);

      case "get_encryption_status":
        return this.getEncryptionStatus();

      case "derive_key":
        return this.deriveKey(payload);

      default:
        throw new Error(`Unknown message type: ${type}`);
    }
  }

  /**
   * Encrypt credential data
   */
  private async encryptCredential(
    payload: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const { credentialData, algorithm, keyId } = payload;
    const startTime = Date.now();

    this.componentLogger.info("Starting credential encryption", {
      algorithm: algorithm || this.config.defaultAlgorithm,
      keyId: keyId || "default",
    });

    try {
      if (!credentialData || typeof credentialData !== "string") {
        throw new Error("Invalid credential data provided");
      }

      const encryptionAlgorithm =
        (algorithm as EncryptionAlgorithm) ||
        this.config.defaultAlgorithm ||
        "aes-256-gcm";
      const targetKeyId = (keyId as string) || this.currentMasterKeyId;

      if (!targetKeyId) {
        throw new Error("No encryption key available");
      }

      const result = await this.performEncryption(
        credentialData,
        encryptionAlgorithm,
        targetKeyId,
      );

      const duration = Date.now() - startTime;
      this.encryptionCount++;
      this.totalEncryptionTime += duration;

      // Update key usage
      const keyMetadata = this.activeKeys.get(targetKeyId);
      if (keyMetadata) {
        keyMetadata.lastUsed = new Date();
        keyMetadata.usageCount++;
      }

      this.componentLogger.info("Credential encryption completed", {
        algorithm: encryptionAlgorithm,
        keyId: targetKeyId,
        durationMs: duration,
      });

      return {
        success: true,
        encryptedCredential: result.encryptedData,
        keyId: targetKeyId,
        algorithm: encryptionAlgorithm,
        performanceMs: duration,
        metadata: {
          encryptionTimestamp: new Date().toISOString(),
          keyUsageCount: keyMetadata?.usageCount || 0,
        },
      };
    } catch (error) {
      this.encryptionFailures++;
      const duration = Date.now() - startTime;

      this.componentLogger.error("Credential encryption failed", {
        error: error instanceof Error ? error.message : "Unknown error",
        durationMs: duration,
      });

      return {
        success: false,
        error:
          error instanceof Error ? error.message : "Unknown encryption error",
        performanceMs: duration,
      };
    }
  }

  /**
   * Decrypt credential data
   */
  private async decryptCredential(
    payload: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const { encryptedData, keyId, algorithm } = payload;
    const startTime = Date.now();

    this.componentLogger.info("Starting credential decryption", {
      keyId,
      algorithm,
    });

    try {
      if (!encryptedData || !keyId) {
        throw new Error("Missing encrypted data or key ID");
      }

      const decryptionAlgorithm =
        (algorithm as EncryptionAlgorithm) || "aes-256-gcm";
      const decryptedData = await this.performDecryption(
        encryptedData as string,
        decryptionAlgorithm,
        keyId as string,
      );

      const duration = Date.now() - startTime;
      this.decryptionCount++;
      this.totalDecryptionTime += duration;

      // Update key usage
      const keyMetadata = this.activeKeys.get(keyId as string);
      if (keyMetadata) {
        keyMetadata.lastUsed = new Date();
        keyMetadata.usageCount++;
      }

      this.componentLogger.info("Credential decryption completed", {
        keyId,
        durationMs: duration,
      });

      return {
        success: true,
        decryptedData,
        performanceMs: duration,
        keyUsageCount: keyMetadata?.usageCount || 0,
      };
    } catch (error) {
      const duration = Date.now() - startTime;

      this.componentLogger.error("Credential decryption failed", {
        keyId,
        error: error instanceof Error ? error.message : "Unknown error",
        durationMs: duration,
      });

      return {
        success: false,
        error:
          error instanceof Error ? error.message : "Unknown decryption error",
        performanceMs: duration,
      };
    }
  }

  /**
   * Generate new credential
   */
  private async generateCredential(
    payload: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const {
      type = "api_key",
      length,
      includeSpecialChars,
      excludeSimilarChars,
      priority = "normal",
    } = payload;

    const startTime = Date.now();

    this.componentLogger.info("Generating new credential", {
      type,
      length: length || "default",
      priority,
    });

    try {
      const credentialLength =
        (length as number) ||
        this.config.credentialGenerationDefaults?.length ||
        32;
      const useSpecialChars =
        (includeSpecialChars as boolean) ??
        this.config.credentialGenerationDefaults?.includeSpecialChars ??
        true;
      const excludeSimilar =
        (excludeSimilarChars as boolean) ??
        this.config.credentialGenerationDefaults?.excludeSimilarChars ??
        true;

      // Define character sets
      let charset =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

      if (useSpecialChars) {
        charset += "!@#$%^&*()_+-=[]{}|;:,.<>?";
      }

      if (excludeSimilar) {
        // Remove similar looking characters
        charset = charset.replace(/[0O1lI|]/g, "");
      }

      // Generate secure random credential
      let credential = "";
      const prefix =
        type === "api_key"
          ? "mcp_"
          : type === "oauth_token"
            ? "mcp_oauth_"
            : "";

      // Generate main credential
      const mainLength = credentialLength - prefix.length;
      const randomBytes = crypto.randomBytes(mainLength * 2); // Extra bytes for filtering

      for (let i = 0; i < mainLength && credential.length < mainLength; i++) {
        const randomIndex = randomBytes[i] % charset.length;
        credential += charset[randomIndex];
      }

      const finalCredential = prefix + credential;

      // Validate credential strength
      const strengthValidation =
        this.validateCredentialStrength(finalCredential);

      const duration = Date.now() - startTime;

      // Generate metadata
      const credentialId = `cred_${Date.now()}_${crypto.randomUUID().slice(0, 8)}`;

      this.componentLogger.info("Credential generation completed", {
        credentialId,
        type,
        length: finalCredential.length,
        strengthScore: strengthValidation.score,
        durationMs: duration,
      });

      return {
        success: true,
        credentialId,
        credential: finalCredential,
        type,
        metadata: {
          length: finalCredential.length,
          strengthValidation,
          generatedAt: new Date().toISOString(),
          algorithm: "secure_random",
          charset: useSpecialChars ? "alphanumeric_special" : "alphanumeric",
        },
        performanceMs: duration,
      };
    } catch (error) {
      const duration = Date.now() - startTime;

      this.componentLogger.error("Credential generation failed", {
        type,
        error: error instanceof Error ? error.message : "Unknown error",
        durationMs: duration,
      });

      return {
        success: false,
        error:
          error instanceof Error
            ? error.message
            : "Unknown credential generation error",
        performanceMs: duration,
      };
    }
  }

  /**
   * Generate new encryption key
   */
  private async generateEncryptionKey(
    payload: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const { algorithm, keySize } = payload;
    const startTime = Date.now();

    this.componentLogger.info("Generating encryption key", {
      algorithm: algorithm || "default",
      keySize: keySize || "default",
    });

    try {
      const encryptionAlgorithm =
        (algorithm as EncryptionAlgorithm) || "aes-256-gcm";
      const _config = this.encryptionConfigs.get(encryptionAlgorithm);

      if (!_config) {
        throw new Error(
          `Unsupported encryption algorithm: ${encryptionAlgorithm}`,
        );
      }

      const targetKeySize = (keySize as number) || _config.keySize;
      const key = crypto.randomBytes(targetKeySize);
      const keyId = `key_${Date.now()}_${crypto.randomUUID().slice(0, 8)}`;

      // Store key and metadata
      this.keyStorage.set(keyId, key);

      const metadata: KeyMetadata = {
        keyId,
        algorithm: encryptionAlgorithm,
        createdAt: new Date(),
        lastUsed: new Date(),
        usageCount: 0,
        maxAge: this.config.maxKeyAge || 90 * 24 * 60 * 60 * 1000, // 90 days default
        status: "active",
      };

      this.activeKeys.set(keyId, metadata);
      this.keyGenerationCount++;

      const duration = Date.now() - startTime;

      this.componentLogger.info("Encryption key generated", {
        keyId,
        algorithm: encryptionAlgorithm,
        keySize: targetKeySize,
        durationMs: duration,
      });

      return {
        success: true,
        keyId,
        algorithm: encryptionAlgorithm,
        keySize: targetKeySize,
        createdAt: metadata.createdAt.toISOString(),
        maxAge: metadata.maxAge,
        performanceMs: duration,
      };
    } catch (error) {
      const duration = Date.now() - startTime;

      this.componentLogger.error("Encryption key generation failed", {
        algorithm,
        error: error instanceof Error ? error.message : "Unknown error",
        durationMs: duration,
      });

      return {
        success: false,
        error:
          error instanceof Error
            ? error.message
            : "Unknown key generation error",
        performanceMs: duration,
      };
    }
  }

  /**
   * Rotate encryption keys
   */
  private async rotateEncryptionKeys(
    payload: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const { forceRotation = false } = payload;
    const startTime = Date.now();

    this.componentLogger.info("Starting encryption key rotation", {
      forceRotation,
      activeKeys: this.activeKeys.size,
    });

    try {
      const keysToRotate: string[] = [];
      const now = new Date();

      // Find keys that need rotation
      for (const [keyId, metadata] of this.activeKeys) {
        const keyAge = now.getTime() - metadata.createdAt.getTime();
        const shouldRotate =
          forceRotation ||
          keyAge > metadata.maxAge ||
          metadata.status === "deprecated";

        if (shouldRotate && metadata.status === "active") {
          keysToRotate.push(keyId);
        }
      }

      const rotationResults: Record<string, unknown>[] = [];

      // Rotate each key
      for (const oldKeyId of keysToRotate) {
        try {
          const oldMetadata = this.activeKeys.get(oldKeyId);
          if (!oldMetadata) {
            continue;
          }

          // Generate new key with same algorithm
          const newKeyResult = await this.generateEncryptionKey({
            algorithm: oldMetadata.algorithm,
          });

          if (newKeyResult.success) {
            // Mark old key as deprecated
            oldMetadata.status = "deprecated";

            rotationResults.push({
              oldKeyId,
              newKeyId: newKeyResult.keyId,
              algorithm: oldMetadata.algorithm,
              rotatedAt: new Date().toISOString(),
            });

            // Update master key if this was the current one
            if (this.currentMasterKeyId === oldKeyId) {
              this.currentMasterKeyId = newKeyResult.keyId as string;
            }
          }
        } catch (error) {
          this.componentLogger.error("Failed to rotate individual key", {
            keyId: oldKeyId,
            error: error instanceof Error ? error.message : "Unknown error",
          });
        }
      }

      const duration = Date.now() - startTime;

      this.componentLogger.info("Encryption key rotation completed", {
        keysRotated: rotationResults.length,
        totalKeys: this.activeKeys.size,
        durationMs: duration,
      });

      return {
        success: true,
        rotatedKeys: rotationResults.length,
        rotationResults,
        newMasterKeyId: this.currentMasterKeyId,
        performanceMs: duration,
      };
    } catch (error) {
      const duration = Date.now() - startTime;

      this.componentLogger.error("Encryption key rotation failed", {
        error: error instanceof Error ? error.message : "Unknown error",
        durationMs: duration,
      });

      return {
        success: false,
        error:
          error instanceof Error ? error.message : "Unknown key rotation error",
        performanceMs: duration,
      };
    }
  }

  /**
   * Validate encryption implementation
   */
  private async validateEncryption(
    payload: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const { testData = "test_credential_data_12345" } = payload;
    const startTime = Date.now();

    this.componentLogger.info("Starting encryption validation");

    try {
      const validationResults: Record<string, unknown>[] = [];

      // Test each supported algorithm
      for (const [algorithm, _config] of this.encryptionConfigs) {
        try {
          // Generate test key
          const keyResult = await this.generateEncryptionKey({ algorithm });
          if (!keyResult.success) {
            throw new Error(`Failed to generate key for ${algorithm}`);
          }

          const keyId = keyResult.keyId as string;

          // Test encryption
          const encryptResult = await this.performEncryption(
            testData as string,
            algorithm,
            keyId,
          );

          // Test decryption
          const decryptedData = await this.performDecryption(
            encryptResult.encryptedData!,
            algorithm,
            keyId,
          );

          // Verify data integrity
          const dataIntact = decryptedData === testData;

          validationResults.push({
            algorithm,
            keyId,
            encryptionSuccess: true,
            decryptionSuccess: true,
            dataIntegrity: dataIntact,
            testPassed: dataIntact,
          });

          // Clean up test key
          this.keyStorage.delete(keyId);
          this.activeKeys.delete(keyId);
        } catch (error) {
          validationResults.push({
            algorithm,
            encryptionSuccess: false,
            decryptionSuccess: false,
            dataIntegrity: false,
            testPassed: false,
            error: error instanceof Error ? error.message : "Unknown error",
          });
        }
      }

      const allTestsPassed = validationResults.every(
        (result) => result.testPassed,
      );
      const duration = Date.now() - startTime;

      this.componentLogger.info("Encryption validation completed", {
        algorithmsTest: validationResults.length,
        allTestsPassed,
        durationMs: duration,
      });

      return {
        success: true,
        validationResults,
        allTestsPassed,
        testedAlgorithms: this.encryptionConfigs.size,
        performanceMs: duration,
      };
    } catch (error) {
      const duration = Date.now() - startTime;

      this.componentLogger.error("Encryption validation failed", {
        error: error instanceof Error ? error.message : "Unknown error",
        durationMs: duration,
      });

      return {
        success: false,
        error:
          error instanceof Error ? error.message : "Unknown validation error",
        performanceMs: duration,
      };
    }
  }

  /**
   * Get encryption agent status
   */
  private getEncryptionStatus(): Record<string, unknown> {
    const avgEncryptionTime =
      this.encryptionCount > 0
        ? this.totalEncryptionTime / this.encryptionCount
        : 0;
    const avgDecryptionTime =
      this.decryptionCount > 0
        ? this.totalDecryptionTime / this.decryptionCount
        : 0;

    const activeKeyCount = Array.from(this.activeKeys.values()).filter(
      (k) => k.status === "active",
    ).length;
    const deprecatedKeyCount = Array.from(this.activeKeys.values()).filter(
      (k) => k.status === "deprecated",
    ).length;
    const revokedKeyCount = Array.from(this.activeKeys.values()).filter(
      (k) => k.status === "revoked",
    ).length;

    return {
      agentStatus: this.status,
      currentMasterKeyId: this.currentMasterKeyId,
      keyManagement: {
        totalKeys: this.activeKeys.size,
        activeKeys: activeKeyCount,
        deprecatedKeys: deprecatedKeyCount,
        revokedKeys: revokedKeyCount,
      },
      operationMetrics: {
        totalEncryptions: this.encryptionCount,
        totalDecryptions: this.decryptionCount,
        totalKeyGenerations: this.keyGenerationCount,
        encryptionFailures: this.encryptionFailures,
        avgEncryptionTimeMs: Math.round(avgEncryptionTime),
        avgDecryptionTimeMs: Math.round(avgDecryptionTime),
      },
      supportedAlgorithms: Array.from(this.encryptionConfigs.keys()),
      configuration: {
        defaultAlgorithm: this.config.defaultAlgorithm,
        keyRotationInterval: this.config.keyRotationIntervalMs,
        maxKeyAge: this.config.maxKeyAge,
        hsmEnabled: this.config.enableHardwareSecurityModule,
      },
    };
  }

  /**
   * Derive encryption key from password/passphrase
   */
  private async deriveKey(
    payload: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const { passphrase, salt, iterations, keyLength } = payload;
    const startTime = Date.now();

    try {
      if (!passphrase) {
        throw new Error("Passphrase required for key derivation");
      }

      const derivationSalt = salt
        ? Buffer.from(salt as string, "hex")
        : crypto.randomBytes(32);
      const derivationIterations =
        (iterations as number) || this.config.keyDerivationIterations || 100000;
      const derivedKeyLength = (keyLength as number) || 32;

      // Use PBKDF2 for key derivation
      const derivedKey = crypto.pbkdf2Sync(
        passphrase as string,
        derivationSalt,
        derivationIterations,
        derivedKeyLength,
        "sha256",
      );

      const keyId = `derived_${Date.now()}_${crypto.randomUUID().slice(0, 8)}`;

      // Store derived key
      this.keyStorage.set(keyId, derivedKey);

      const metadata: KeyMetadata = {
        keyId,
        algorithm: "derived" as EncryptionAlgorithm,
        createdAt: new Date(),
        lastUsed: new Date(),
        usageCount: 0,
        maxAge: this.config.maxKeyAge || 90 * 24 * 60 * 60 * 1000,
        status: "active",
      };

      this.activeKeys.set(keyId, metadata);

      const duration = Date.now() - startTime;

      return {
        success: true,
        keyId,
        salt: derivationSalt.toString("hex"),
        iterations: derivationIterations,
        keyLength: derivedKeyLength,
        performanceMs: duration,
      };
    } catch (error) {
      const duration = Date.now() - startTime;

      return {
        success: false,
        error:
          error instanceof Error ? error.message : "Unknown derivation error",
        performanceMs: duration,
      };
    }
  }

  /**
   * Perform actual encryption operation
   */
  private async performEncryption(
    data: string,
    algorithm: EncryptionAlgorithm,
    keyId: string,
  ): Promise<EncryptionResult> {
    const key = this.keyStorage.get(keyId);
    if (!key) {
      throw new Error(`Encryption key not found: ${keyId}`);
    }

    const config = this.encryptionConfigs.get(algorithm);
    if (!config) {
      throw new Error(`Unsupported encryption algorithm: ${algorithm}`);
    }

    const _iv = crypto.randomBytes(config.ivSize);
    const cipher = crypto.createCipher(algorithm, key);

    let encrypted = cipher.update(data, "utf8", "hex");
    encrypted += cipher.final("hex");

    // For GCM mode, include auth tag
    let authTag = "";
    if (algorithm.includes("gcm")) {
      authTag = (cipher as any).getAuthTag().toString("hex");
    }

    const encryptedData = JSON.stringify({
      data: encrypted,
      iv: _iv.toString("hex"),
      authTag,
      algorithm,
      keyId,
    });

    return {
      success: true,
      encryptedData,
      keyId,
      algorithm,
    };
  }

  /**
   * Perform actual decryption operation
   */
  private async performDecryption(
    encryptedData: string,
    algorithm: EncryptionAlgorithm,
    keyId: string,
  ): Promise<string> {
    const key = this.keyStorage.get(keyId);
    if (!key) {
      throw new Error(`Decryption key not found: ${keyId}`);
    }

    const encrypted = JSON.parse(encryptedData);
    const _iv = Buffer.from(encrypted.iv, "hex");
    const decipher = crypto.createDecipher(algorithm, key);

    // For GCM mode, set auth tag
    if (algorithm.includes("gcm") && encrypted.authTag) {
      (decipher as any).setAuthTag(Buffer.from(encrypted.authTag, "hex"));
    }

    let decrypted = decipher.update(encrypted.data, "hex", "utf8");
    decrypted += decipher.final("utf8");

    return decrypted;
  }

  /**
   * Validate credential strength
   */
  private validateCredentialStrength(credential: string): {
    score: number;
    details: Record<string, boolean>;
  } {
    const checks = {
      hasMinLength: credential.length >= 16,
      hasLetter: /[a-zA-Z]/.test(credential),
      hasNumber: /[0-9]/.test(credential),
      hasSpecial: /[^a-zA-Z0-9]/.test(credential),
      hasUppercase: /[A-Z]/.test(credential),
      hasLowercase: /[a-z]/.test(credential),
      noRepeatedChars: !/(.)\1{3,}/.test(credential),
      noCommonPatterns: !/123|abc|qwe|asd/i.test(credential),
    };

    const score = Object.values(checks).filter(Boolean).length;

    return { score, details: checks };
  }

  /**
   * Setup encryption configurations
   */
  private setupEncryptionConfigs(): void {
    const configs: Array<[EncryptionAlgorithm, EncryptionConfig]> = [
      [
        "aes-256-gcm",
        {
          algorithm: "aes-256-gcm",
          keySize: 32,
          ivSize: 16,
          tagSize: 16,
          saltSize: 32,
          iterations: 100000,
        },
      ],
      [
        "aes-256-cbc",
        {
          algorithm: "aes-256-cbc",
          keySize: 32,
          ivSize: 16,
          tagSize: 0,
          saltSize: 32,
          iterations: 100000,
        },
      ],
      [
        "chacha20-poly1305",
        {
          algorithm: "chacha20-poly1305",
          keySize: 32,
          ivSize: 12,
          tagSize: 16,
          saltSize: 32,
          iterations: 100000,
        },
      ],
    ];

    configs.forEach(([algorithm, config]) => {
      this.encryptionConfigs.set(algorithm, config);
    });
  }

  /**
   * Generate initial master key
   */
  private async generateMasterKey(): Promise<void> {
    const result = await this.generateEncryptionKey({
      algorithm: this.config.defaultAlgorithm || "aes-256-gcm",
    });

    if (result.success) {
      this.currentMasterKeyId = result.keyId as string;
      this.componentLogger.info("Master key generated", {
        keyId: this.currentMasterKeyId,
      });
    } else {
      throw new Error("Failed to generate initial master key");
    }
  }

  /**
   * Start key rotation timer
   */
  private startKeyRotationTimer(): void {
    const interval = this.config.keyRotationIntervalMs!;

    this.keyRotationTimer = setInterval(async () => {
      try {
        await this.rotateEncryptionKeys({ forceRotation: false });
      } catch (error) {
        this.componentLogger.error("Automatic key rotation failed", {
          error: error instanceof Error ? error.message : "Unknown error",
        });
      }
    }, interval);
  }

  public override getPerformanceMetrics(): Record<string, unknown> {
    const baseMetrics = super.getPerformanceMetrics();
    const avgEncryptionTime =
      this.encryptionCount > 0
        ? this.totalEncryptionTime / this.encryptionCount
        : 0;
    const avgDecryptionTime =
      this.decryptionCount > 0
        ? this.totalDecryptionTime / this.decryptionCount
        : 0;

    return {
      ...baseMetrics,
      encryptionMetrics: {
        totalEncryptions: this.encryptionCount,
        totalDecryptions: this.decryptionCount,
        totalKeyGenerations: this.keyGenerationCount,
        encryptionFailures: this.encryptionFailures,
        avgEncryptionTimeMs: Math.round(avgEncryptionTime),
        avgDecryptionTimeMs: Math.round(avgDecryptionTime),
      },
      keyMetrics: {
        totalKeys: this.activeKeys.size,
        activeKeys: Array.from(this.activeKeys.values()).filter(
          (k) => k.status === "active",
        ).length,
        currentMasterKeyId: this.currentMasterKeyId,
        supportedAlgorithms: Array.from(this.encryptionConfigs.keys()),
      },
    };
  }
}

export default EncryptionAgent;
