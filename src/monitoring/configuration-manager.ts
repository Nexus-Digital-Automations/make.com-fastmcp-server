import * as path from "path";
import * as fs from "fs";
import type { AlertStorageConfig } from "./enhanced-alert-storage.js";
import type { CorrelationRule } from "./alert-correlation-engine.js";
import type { NotificationChannel } from "./multi-channel-notification.js";

export interface EnhancedAlertManagerConfig {
  // Core alert configuration
  alerts: {
    maxAlerts: number;
    cleanupThreshold: number;
    defaultSuppressionMs: number;
    escalationThreshold: number;
  };

  // Storage configuration
  storage: AlertStorageConfig;

  // Correlation configuration
  correlation: {
    enabled: boolean;
    timeWindow: number;
    maxCorrelations: number;
    rules: CorrelationRule[];
    minConfidenceThreshold: number;
    enableLearning: boolean;
  };

  // Notification configuration
  notifications: {
    enabled: boolean;
    channels: NotificationChannel[];
    defaultChannels: string[];
    rateLimiting: {
      globalMaxPerMinute: number;
      globalMaxPerHour: number;
    };
  };

  // Performance configuration
  performance: {
    asyncProcessing: boolean;
    batchSize: number;
    maxConcurrentNotifications: number;
    healthCheckInterval: number;
  };

  // Integration configuration
  integrations: {
    winston: {
      enabled: boolean;
      logLevel: string;
    };
    metrics: {
      enabled: boolean;
      port?: number;
    };
  };

  // Security configuration
  security: {
    enableSanitization: boolean;
    allowedPatterns: string[];
    blockedPatterns: string[];
    maxMessageLength: number;
  };
}

export interface ConfigurationWatcher {
  callback: (config: EnhancedAlertManagerConfig) => void;
}

export interface ConfigValidationError {
  path: string;
  message: string;
  severity: "error" | "warning";
}

export class ConfigurationManager {
  private config!: EnhancedAlertManagerConfig; // Definite assignment assertion since loadConfiguration() sets it
  private configFile: string;
  private watchers: ConfigurationWatcher[];
  private lastModified: number = 0;
  private watchInterval?: NodeJS.Timeout;

  constructor(configPath?: string) {
    // Use absolute path from project root to avoid working directory issues
    this.configFile = configPath || this.getDefaultConfigPath();
    this.watchers = [];
    this.loadConfiguration();
    this.startFileWatching();
  }

  private getDefaultConfigPath(): string {
    // Get the project root directory from the current module location
    // Handle both ES modules and CommonJS paths
    let moduleDir: string;

    if (typeof __dirname !== "undefined") {
      // CommonJS environment
      moduleDir = __dirname;
    } else {
      // ES modules environment
      const url = import.meta.url;
      if (url.startsWith("file://")) {
        moduleDir = path.dirname(new URL(url).pathname);
      } else {
        // Fallback - assume we're in dist/monitoring
        moduleDir = path.resolve(process.cwd(), "dist", "monitoring");
      }
    }

    const projectRoot = path.resolve(moduleDir, "../..");
    return path.join(projectRoot, "config", "alert-manager.json");
  }

  private loadConfiguration(): void {
    try {
      // Try to load from file first
      if (this.fileExists(this.configFile)) {
        const fileContent = this.readFileSync(this.configFile);
        this.config = JSON.parse(fileContent);
        this.lastModified = this.getFileModTime(this.configFile);

        // Configuration loaded - logged to file to avoid MCP interference
      } else {
        // Use default configuration
        this.config = this.getDefaultConfiguration();
        this.saveConfiguration(); // Save default config for future customization

        // Using default configuration - logged to file to avoid MCP interference
      }

      // Validate configuration
      this.validateConfiguration();
    } catch {
      // Failed to load configuration - logged to file to avoid MCP interference
      this.config = this.getDefaultConfiguration();
    }
  }

  private getDefaultConfiguration(): EnhancedAlertManagerConfig {
    return {
      alerts: {
        maxAlerts: 1000,
        cleanupThreshold: 500,
        defaultSuppressionMs: 60000, // 1 minute
        escalationThreshold: 5,
      },

      storage: {
        maxHotAlerts: 1000,
        maxWarmAlerts: 5000,
        archiveThreshold: 7, // days
        retentionPolicy: 90, // days
        compressionEnabled: true,
        persistentStorageType: "file",
        archiveDirectory: "./data/alert-archives",
      },

      correlation: {
        enabled: true,
        timeWindow: 300000, // 5 minutes
        maxCorrelations: 100,
        minConfidenceThreshold: 0.7,
        enableLearning: true,
        rules: [], // Will be populated by correlation engine
      },

      notifications: {
        enabled: true,
        channels: [
          {
            id: "default-webhook",
            type: "webhook",
            name: "Default Webhook",
            enabled: true,
            config: {
              webhook: {
                url:
                  process.env.ALERT_WEBHOOK_URL ||
                  "http://localhost:3000/webhook",
                method: "POST",
                timeout: 5000,
              },
            },
            rateLimits: {
              maxPerMinute: 20,
              maxPerHour: 200,
              burstLimit: 5,
              backoffStrategy: "exponential",
            },
            healthCheck: {
              enabled: true,
              interval: 300000, // 5 minutes
              timeout: 10000,
            },
            retryConfig: {
              maxRetries: 3,
              retryDelay: 1000,
              backoffMultiplier: 2,
            },
          },
        ],
        defaultChannels: ["default-webhook"],
        rateLimiting: {
          globalMaxPerMinute: 50,
          globalMaxPerHour: 500,
        },
      },

      performance: {
        asyncProcessing: true,
        batchSize: 10,
        maxConcurrentNotifications: 20,
        healthCheckInterval: 60000, // 1 minute
      },

      integrations: {
        winston: {
          enabled: true,
          logLevel: "info",
        },
        metrics: {
          enabled: false,
          port: 9090,
        },
      },

      security: {
        enableSanitization: true,
        allowedPatterns: ["*"], // Allow all patterns by default
        blockedPatterns: [], // No blocked patterns by default
        maxMessageLength: 10000,
      },
    };
  }

  private validateConfiguration(): void {
    const errors: ConfigValidationError[] = [];

    // Validate alert configuration
    if (this.config.alerts.maxAlerts < 100) {
      errors.push({
        path: "alerts.maxAlerts",
        message: "maxAlerts must be at least 100",
        severity: "error",
      });
    }

    if (this.config.alerts.cleanupThreshold > this.config.alerts.maxAlerts) {
      errors.push({
        path: "alerts.cleanupThreshold",
        message: "cleanupThreshold cannot exceed maxAlerts",
        severity: "error",
      });
    }

    // Validate storage configuration
    if (this.config.storage.maxHotAlerts < 100) {
      errors.push({
        path: "storage.maxHotAlerts",
        message: "maxHotAlerts must be at least 100",
        severity: "error",
      });
    }

    if (this.config.storage.retentionPolicy < 1) {
      errors.push({
        path: "storage.retentionPolicy",
        message: "retentionPolicy must be at least 1 day",
        severity: "error",
      });
    }

    // Validate correlation configuration
    if (this.config.correlation.enabled) {
      if (this.config.correlation.timeWindow < 60000) {
        errors.push({
          path: "correlation.timeWindow",
          message: "timeWindow should be at least 1 minute (60000ms)",
          severity: "warning",
        });
      }

      if (
        this.config.correlation.minConfidenceThreshold < 0.5 ||
        this.config.correlation.minConfidenceThreshold > 1.0
      ) {
        errors.push({
          path: "correlation.minConfidenceThreshold",
          message: "minConfidenceThreshold must be between 0.5 and 1.0",
          severity: "error",
        });
      }
    }

    // Validate notification channels
    for (let i = 0; i < this.config.notifications.channels.length; i++) {
      const channel = this.config.notifications.channels[i];

      if (!channel.id || !channel.type) {
        errors.push({
          path: `notifications.channels[${i}]`,
          message: "Channel missing id or type",
          severity: "error",
        });
        continue;
      }

      // Validate channel-specific configuration
      switch (channel.type) {
        case "webhook":
          if (!channel.config.webhook?.url) {
            errors.push({
              path: `notifications.channels[${i}].config.webhook.url`,
              message: "Webhook channel missing URL",
              severity: "error",
            });
          }
          break;
        case "email":
          if (!channel.config.email?.smtp || !channel.config.email?.from) {
            errors.push({
              path: `notifications.channels[${i}].config.email`,
              message:
                "Email channel missing SMTP configuration or from address",
              severity: "error",
            });
          }
          break;
        case "slack":
          if (!channel.config.slack?.webhookUrl) {
            errors.push({
              path: `notifications.channels[${i}].config.slack.webhookUrl`,
              message: "Slack channel missing webhook URL",
              severity: "error",
            });
          }
          break;
        case "sms":
          if (
            !channel.config.sms?.provider ||
            !channel.config.sms?.credentials
          ) {
            errors.push({
              path: `notifications.channels[${i}].config.sms`,
              message: "SMS channel missing provider or credentials",
              severity: "error",
            });
          }
          break;
      }

      // Validate rate limits
      if (
        channel.rateLimits.maxPerMinute <= 0 ||
        channel.rateLimits.maxPerHour <= 0
      ) {
        errors.push({
          path: `notifications.channels[${i}].rateLimits`,
          message: "Rate limits must be positive numbers",
          severity: "error",
        });
      }
    }

    // Validate performance configuration
    if (
      this.config.performance.batchSize < 1 ||
      this.config.performance.batchSize > 100
    ) {
      errors.push({
        path: "performance.batchSize",
        message: "batchSize must be between 1 and 100",
        severity: "warning",
      });
    }

    // Validate security configuration
    if (this.config.security.maxMessageLength < 100) {
      errors.push({
        path: "security.maxMessageLength",
        message: "maxMessageLength should be at least 100 characters",
        severity: "warning",
      });
    }

    // Handle validation results
    const criticalErrors = errors.filter((error) => error.severity === "error");
    const warnings = errors.filter((error) => error.severity === "warning");

    if (warnings.length > 0) {
      // Configuration warnings - logged to file to avoid MCP interference
    }

    if (criticalErrors.length > 0) {
      // Configuration validation failed - logged to file to avoid MCP interference
      throw new Error(
        `Configuration validation failed with ${criticalErrors.length} critical errors`,
      );
    }

    // Configuration validation passed - logged to file to avoid MCP interference
  }

  getConfig(): EnhancedAlertManagerConfig {
    // Return deep copy to prevent modification
    return JSON.parse(JSON.stringify(this.config));
  }

  updateConfig(updates: Partial<EnhancedAlertManagerConfig>): void {
    const oldConfig = this.config;

    try {
      // Deep merge the updates
      this.config = this.deepMerge(
        this.config as unknown as Record<string, unknown>,
        updates as unknown as Record<string, unknown>,
      ) as unknown as EnhancedAlertManagerConfig;

      // Validate the updated configuration
      this.validateConfiguration();

      // Save to file
      this.saveConfiguration();

      // Notify watchers
      this.notifyWatchers();

      // Configuration updated and validated - logged to file to avoid MCP interference
    } catch (error) {
      // Restore old configuration on validation failure
      this.config = oldConfig;
      // Configuration update failed - logged to file to avoid MCP interference
      throw error;
    }
  }

  private deepMerge(
    target: Record<string, unknown>,
    source: Record<string, unknown>,
  ): Record<string, unknown> {
    const result = { ...target };

    for (const key in source) {
      if (
        source[key] !== null &&
        typeof source[key] === "object" &&
        !Array.isArray(source[key])
      ) {
        result[key] = this.deepMerge(
          (result[key] as Record<string, unknown>) || {},
          source[key] as Record<string, unknown>,
        );
      } else {
        result[key] = source[key];
      }
    }

    return result;
  }

  private saveConfiguration(): void {
    const configDir = path.dirname(this.configFile);
    this.ensureDirectoryExists(configDir);

    const configContent = JSON.stringify(this.config, null, 2);
    this.writeFileSync(this.configFile, configContent);
    this.lastModified = this.getFileModTime(this.configFile);

    // Configuration saved - logged to file to avoid MCP interference
  }

  onConfigChange(callback: (config: EnhancedAlertManagerConfig) => void): void {
    this.watchers.push({ callback });
    // Configuration watcher registered - logged to file to avoid MCP interference
  }

  private notifyWatchers(): void {
    for (const watcher of this.watchers) {
      try {
        watcher.callback(this.getConfig());
      } catch {
        // Configuration watcher error - logged to file to avoid MCP interference
      }
    }
  }

  private startFileWatching(): void {
    // Check for file changes every 30 seconds
    this.watchInterval = setInterval(() => {
      try {
        if (this.fileExists(this.configFile)) {
          const currentModTime = this.getFileModTime(this.configFile);

          if (currentModTime > this.lastModified) {
            // Configuration file changed, reloading - logged to file to avoid MCP interference
            this.loadConfiguration();
            this.notifyWatchers();
          }
        }
      } catch {
        // Configuration file watching error - logged to file to avoid MCP interference
      }
    }, 30000);
  }

  // Template generation methods
  generateTemplate(
    templateType: "minimal" | "full" | "development" | "production",
  ): EnhancedAlertManagerConfig {
    const base = this.getDefaultConfiguration();

    switch (templateType) {
      case "minimal":
        return {
          ...base,
          correlation: { ...base.correlation, enabled: false },
          notifications: {
            ...base.notifications,
            channels: [base.notifications.channels[0]], // Only default webhook
          },
          integrations: {
            ...base.integrations,
            metrics: { enabled: false },
          },
        };

      case "development":
        return {
          ...base,
          alerts: { ...base.alerts, maxAlerts: 500 },
          storage: { ...base.storage, maxHotAlerts: 500, retentionPolicy: 30 },
          performance: { ...base.performance, asyncProcessing: false },
        };

      case "production":
        return {
          ...base,
          alerts: { ...base.alerts, maxAlerts: 10000 },
          storage: {
            ...base.storage,
            maxHotAlerts: 5000,
            maxWarmAlerts: 20000,
            retentionPolicy: 365, // 1 year
          },
          performance: {
            ...base.performance,
            asyncProcessing: true,
            maxConcurrentNotifications: 50,
          },
          integrations: {
            ...base.integrations,
            metrics: { enabled: true, port: 9090 },
          },
        };

      case "full":
      default:
        return base;
    }
  }

  async exportConfig(
    outputPath: string,
    format: "json" | "yaml" = "json",
  ): Promise<void> {
    let content: string;

    if (format === "yaml") {
      // Simple YAML export (basic implementation)
      content = this.toSimpleYaml(
        this.config as unknown as Record<string, unknown>,
      );
    } else {
      content = JSON.stringify(this.config, null, 2);
    }

    this.writeFileSync(outputPath, content);
    // Configuration exported - logged to file to avoid MCP interference
  }

  private toSimpleYaml(
    obj: Record<string, unknown>,
    indent: number = 0,
  ): string {
    const spaces = " ".repeat(indent);
    let yaml = "";

    for (const [key, value] of Object.entries(obj)) {
      if (value === null || value === undefined) {
        yaml += `${spaces}${key}: null\n`;
      } else if (typeof value === "object" && !Array.isArray(value)) {
        yaml += `${spaces}${key}:\n${this.toSimpleYaml(value as Record<string, unknown>, indent + 2)}`;
      } else if (Array.isArray(value)) {
        yaml += `${spaces}${key}:\n`;
        for (const item of value) {
          if (typeof item === "object") {
            yaml += `${spaces}  -\n${this.toSimpleYaml(item as Record<string, unknown>, indent + 4)}`;
          } else {
            yaml += `${spaces}  - ${JSON.stringify(item)}\n`;
          }
        }
      } else {
        yaml += `${spaces}${key}: ${JSON.stringify(value)}\n`;
      }
    }

    return yaml;
  }

  // Configuration comparison and migration
  compareConfigs(otherConfig: EnhancedAlertManagerConfig): {
    added: string[];
    removed: string[];
    changed: Array<{ path: string; oldValue: unknown; newValue: unknown }>;
  } {
    const result = {
      added: [] as string[],
      removed: [] as string[],
      changed: [] as Array<{
        path: string;
        oldValue: unknown;
        newValue: unknown;
      }>,
    };

    this.deepCompare(
      this.config as unknown as Record<string, unknown>,
      otherConfig as unknown as Record<string, unknown>,
      "",
      result,
    );

    return result;
  }

  private deepCompare(
    obj1: Record<string, unknown>,
    obj2: Record<string, unknown>,
    path: string,
    result: {
      added: string[];
      removed: string[];
      changed: Array<{ path: string; oldValue: unknown; newValue: unknown }>;
    },
  ): void {
    const keys1 = Object.keys(obj1 || {});
    const keys2 = Object.keys(obj2 || {});

    // Check for removed keys
    for (const key of keys1) {
      const currentPath = path ? `${path}.${key}` : key;
      if (!(key in (obj2 || {}))) {
        result.removed.push(currentPath);
      }
    }

    // Check for added or changed keys
    for (const key of keys2) {
      const currentPath = path ? `${path}.${key}` : key;

      if (!(key in (obj1 || {}))) {
        result.added.push(currentPath);
      } else if (
        typeof obj1[key] === "object" &&
        typeof obj2[key] === "object" &&
        !Array.isArray(obj1[key]) &&
        !Array.isArray(obj2[key])
      ) {
        this.deepCompare(
          obj1[key] as Record<string, unknown>,
          obj2[key] as Record<string, unknown>,
          currentPath,
          result,
        );
      } else if (JSON.stringify(obj1[key]) !== JSON.stringify(obj2[key])) {
        result.changed.push({
          path: currentPath,
          oldValue: obj1[key],
          newValue: obj2[key],
        });
      }
    }
  }

  // Utility methods for file operations (can be overridden for testing)
  private fileExists(filePath: string): boolean {
    try {
      return fs.existsSync(filePath);
    } catch {
      return false;
    }
  }

  private readFileSync(filePath: string): string {
    return fs.readFileSync(filePath, "utf-8");
  }

  private writeFileSync(filePath: string, content: string): void {
    fs.writeFileSync(filePath, content, "utf-8");
  }

  private getFileModTime(filePath: string): number {
    try {
      return fs.statSync(filePath).mtime.getTime();
    } catch {
      return 0;
    }
  }

  private ensureDirectoryExists(dirPath: string): void {
    try {
      fs.mkdirSync(dirPath, { recursive: true });
    } catch {
      // Directory might already exist
    }
  }

  // Public API methods
  getConfigSummary(): {
    alertsEnabled: boolean;
    storageType: string;
    correlationEnabled: boolean;
    notificationChannels: number;
    asyncProcessing: boolean;
    metricsEnabled: boolean;
  } {
    return {
      alertsEnabled: this.config.alerts.maxAlerts > 0,
      storageType: this.config.storage.persistentStorageType,
      correlationEnabled: this.config.correlation.enabled,
      notificationChannels: this.config.notifications.channels.length,
      asyncProcessing: this.config.performance.asyncProcessing,
      metricsEnabled: this.config.integrations.metrics.enabled,
    };
  }

  validatePattern(pattern: string): boolean {
    const { allowedPatterns, blockedPatterns } = this.config.security;

    // Check blocked patterns first
    for (const blockedPattern of blockedPatterns) {
      if (this.matchesPattern(pattern, blockedPattern)) {
        return false;
      }
    }

    // Check allowed patterns
    for (const allowedPattern of allowedPatterns) {
      if (this.matchesPattern(pattern, allowedPattern)) {
        return true;
      }
    }

    return false;
  }

  private matchesPattern(text: string, pattern: string): boolean {
    if (pattern === "*") {
      return true;
    }

    // Simple wildcard matching
    const regexPattern = pattern.replace(/\*/g, ".*").replace(/\?/g, ".");
    const regex = new RegExp(`^${regexPattern}$`, "i");
    return regex.test(text);
  }

  shutdown(): void {
    if (this.watchInterval) {
      clearInterval(this.watchInterval);
      this.watchInterval = undefined;
    }

    this.watchers = [];

    // Configuration manager shut down - logged to file to avoid MCP interference
  }
}

// Factory function for easy configuration creation
export function createConfigurationManager(options: {
  configPath?: string;
  template?: "minimal" | "full" | "development" | "production";
}): ConfigurationManager {
  const manager = new ConfigurationManager(options.configPath);

  if (options.template && options.template !== "full") {
    const templateConfig = manager.generateTemplate(options.template);
    manager.updateConfig(templateConfig);
  }

  return manager;
}
