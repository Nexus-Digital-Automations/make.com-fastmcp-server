import { AlertManager, type PatternAlert } from "./alert-manager.js";
import type { PatternMatch } from "./log-pattern-analyzer.js";
import { EnhancedAlertStorage } from "./enhanced-alert-storage.js";
import {
  BasicCorrelationEngine,
  type AlertCorrelation,
} from "./alert-correlation-engine.js";
import {
  MultiChannelNotificationManager,
  createSlackChannel,
  type NotificationSummary,
  type BaseNotificationChannel,
} from "./multi-channel-notification.js";
import {
  ConfigurationManager,
  type EnhancedAlertManagerConfig,
} from "./configuration-manager.js";

export interface EnhancedAlertTriggerResult {
  alert: PatternAlert | null;
  correlation?: AlertCorrelation;
  notificationSummary?: NotificationSummary;
  suppressed: boolean;
  reason?: string;
}

export interface AlertProcessingMetrics {
  totalProcessed: number;
  suppressed: number;
  correlated: number;
  notificationsSent: number;
  notificationFailures: number;
  averageProcessingTime: number;
}

export class EnhancedAlertManager {
  private static instance: EnhancedAlertManager;

  private configManager: ConfigurationManager;
  private alertStorage!: EnhancedAlertStorage; // Definite assignment assertion
  private correlationEngine!: BasicCorrelationEngine; // Definite assignment assertion
  private notificationManager!: MultiChannelNotificationManager; // Definite assignment assertion

  private processingMetrics: AlertProcessingMetrics;
  private initialized: boolean = false;

  private constructor(configPath?: string) {
    this.configManager = new ConfigurationManager(configPath);

    // Initialize metrics
    this.processingMetrics = {
      totalProcessed: 0,
      suppressed: 0,
      correlated: 0,
      notificationsSent: 0,
      notificationFailures: 0,
      averageProcessingTime: 0,
    };

    this.initializeComponents();
  }

  static getInstance(configPath?: string): EnhancedAlertManager {
    if (!EnhancedAlertManager.instance) {
      EnhancedAlertManager.instance = new EnhancedAlertManager(configPath);
    }
    return EnhancedAlertManager.instance;
  }

  private initializeComponents(): void {
    try {
      const config = this.configManager.getConfig();

      // Initialize enhanced storage
      this.alertStorage = new EnhancedAlertStorage(config.storage);

      // Initialize correlation engine
      this.correlationEngine = new BasicCorrelationEngine({
        correlationWindow: config.correlation.timeWindow,
        maxActiveCorrelations: config.correlation.maxCorrelations,
        minConfidenceThreshold: config.correlation.minConfidenceThreshold,
        enableLearning: config.correlation.enableLearning,
      });

      // Initialize notification manager
      this.notificationManager = new MultiChannelNotificationManager();
      this.setupNotificationChannels(config);

      // Set up alert source for correlation engine
      this.correlationEngine.setAlertSource((cutoffTime: number) => {
        return this.getAllRecentAlerts(cutoffTime);
      });

      // Watch for configuration changes
      this.configManager.onConfigChange((newConfig) => {
        this.handleConfigurationChange(newConfig);
      });

      this.initialized = true;

      console.warn("🚀 Enhanced Alert Manager initialized successfully");
      console.warn(
        `   Storage: ${config.storage.persistentStorageType} (${config.storage.maxHotAlerts} hot alerts)`,
      );
      console.warn(
        `   Correlation: ${config.correlation.enabled ? "enabled" : "disabled"} (${config.correlation.rules.length} rules)`,
      );
      console.warn(
        `   Notifications: ${config.notifications.channels.length} channels configured`,
      );
    } catch (error) {
      console.error("❌ Failed to initialize Enhanced Alert Manager:", error);
      throw error;
    }
  }

  private setupNotificationChannels(config: EnhancedAlertManagerConfig): void {
    for (const channelConfig of config.notifications.channels) {
      try {
        let channel: BaseNotificationChannel;

        switch (channelConfig.type) {
          case "webhook":
            channel =
              new (require("./multi-channel-notification.js").WebhookNotificationChannel)(
                channelConfig,
              );
            break;
          case "slack":
            channel =
              new (require("./multi-channel-notification.js").SlackNotificationChannel)(
                channelConfig,
              );
            break;
          case "email":
            channel =
              new (require("./multi-channel-notification.js").EmailNotificationChannel)(
                channelConfig,
              );
            break;
          case "sms":
            channel =
              new (require("./multi-channel-notification.js").SMSNotificationChannel)(
                channelConfig,
              );
            break;
          default:
            console.warn(`⚠️ Unsupported channel type: ${channelConfig.type}`);
            continue;
        }

        this.notificationManager.addChannel(channel);
      } catch (error) {
        console.error(`❌ Failed to setup channel ${channelConfig.id}:`, error);
      }
    }
  }

  private handleConfigurationChange(
    newConfig: EnhancedAlertManagerConfig,
  ): void {
    console.warn("🔄 Configuration changed, updating components...");

    try {
      // Recreate notification manager with new channels
      this.notificationManager = new MultiChannelNotificationManager();
      this.setupNotificationChannels(newConfig);

      console.warn("✅ Enhanced Alert Manager updated with new configuration");
    } catch (error) {
      console.error(
        "❌ Failed to update Enhanced Alert Manager configuration:",
        error,
      );
    }
  }

  async triggerAlert(match: PatternMatch): Promise<EnhancedAlertTriggerResult> {
    if (!this.initialized) {
      throw new Error("Enhanced Alert Manager not initialized");
    }

    const startTime = Date.now();
    this.processingMetrics.totalProcessed++;

    try {
      // Use original AlertManager to create/update the alert
      const alert = AlertManager.triggerAlert(match);

      if (!alert) {
        // Alert was suppressed by original logic
        this.processingMetrics.suppressed++;
        return {
          alert: null,
          suppressed: true,
          reason: "Standard suppression logic",
        };
      }

      // Store in enhanced storage
      await this.alertStorage.storeAlert(alert);

      // Check for correlation
      const correlation = this.correlationEngine.correlateAlert(alert);
      if (correlation) {
        this.processingMetrics.correlated++;

        // Handle correlation actions
        if (
          correlation.correlationType === "cluster" &&
          correlation.suppressedCount > 0
        ) {
          this.processingMetrics.suppressed += correlation.suppressedCount;
        }
      }

      // Send notifications through enhanced notification manager
      let notificationSummary: NotificationSummary | undefined;
      const config = this.configManager.getConfig();

      if (
        config.notifications.enabled &&
        this.shouldSendNotification(alert, correlation || undefined)
      ) {
        try {
          notificationSummary = await this.notificationManager.sendAlert(alert);
          this.processingMetrics.notificationsSent +=
            notificationSummary.successfulChannels;
          this.processingMetrics.notificationFailures +=
            notificationSummary.failedChannels;
        } catch (error) {
          console.error(`❌ Notification failed for alert ${alert.id}:`, error);
          this.processingMetrics.notificationFailures++;
        }
      }

      // Update processing time metrics
      const processingTime = Date.now() - startTime;
      this.updateProcessingTimeMetrics(processingTime);

      return {
        alert,
        correlation: correlation || undefined,
        notificationSummary,
        suppressed: false,
      };
    } catch (error) {
      console.error("❌ Enhanced alert processing failed:", error);

      // Fall back to standard AlertManager behavior
      const fallbackAlert = AlertManager.triggerAlert(match);
      return {
        alert: fallbackAlert,
        suppressed: false,
        reason: "Fallback to standard processing due to error",
      };
    }
  }

  private shouldSendNotification(
    alert: PatternAlert,
    correlation?: AlertCorrelation,
  ): boolean {
    // Don't send notifications for suppressed alerts in correlation
    if (
      correlation &&
      correlation.suppressedCount > 0 &&
      correlation.correlationType !== "escalate"
    ) {
      return false;
    }

    // Always send for critical alerts
    if (alert.severity === "critical") {
      return true;
    }

    // Send for high escalation levels
    if (alert.escalationLevel >= 2) {
      return true;
    }

    // Default behavior for other alerts
    return true;
  }

  private updateProcessingTimeMetrics(newTime: number): void {
    // Simple moving average
    const alpha = 0.1; // Smoothing factor
    this.processingMetrics.averageProcessingTime =
      (1 - alpha) * this.processingMetrics.averageProcessingTime +
      alpha * newTime;
  }

  private getAllRecentAlerts(cutoffTime: number): PatternAlert[] {
    // Get all alerts from both enhanced storage and original AlertManager
    const originalAlerts = AlertManager.getAllAlerts(true);

    return originalAlerts.filter(
      (alert) => alert.lastOccurrence.getTime() > cutoffTime,
    );
  }

  // Enhanced API methods

  async getAlert(alertId: string): Promise<PatternAlert | null> {
    // Try enhanced storage first, then fall back to original
    const enhancedAlert = await this.alertStorage.getAlert(alertId);
    if (enhancedAlert) {
      return enhancedAlert;
    }

    return AlertManager.getAlertById(alertId);
  }

  getActiveAlerts(): PatternAlert[] {
    return AlertManager.getActiveAlerts();
  }

  getAllAlerts(includeResolved: boolean = false): PatternAlert[] {
    return AlertManager.getAllAlerts(includeResolved);
  }

  getAlertStats() {
    const originalStats = AlertManager.getAlertStats();
    const storageStats = this.alertStorage.getStorageStats();
    const correlationStats = this.correlationEngine.getCorrelationStats();
    const channelStatuses = this.notificationManager.getChannelStatuses();

    return {
      ...originalStats,
      storage: storageStats,
      correlation: correlationStats,
      notifications: {
        channels: channelStatuses.length,
        healthyChannels: channelStatuses.filter((c) => c.healthy).length,
        enabledChannels: channelStatuses.filter((c) => c.enabled).length,
      },
      processing: this.processingMetrics,
    };
  }

  getActiveCorrelations(): AlertCorrelation[] {
    return this.correlationEngine.getActiveCorrelations();
  }

  getNotificationChannelStatuses() {
    return this.notificationManager.getChannelStatuses();
  }

  async testAllNotificationChannels() {
    return await this.notificationManager.testAllChannels();
  }

  // Configuration management
  getConfiguration(): EnhancedAlertManagerConfig {
    return this.configManager.getConfig();
  }

  updateConfiguration(updates: Partial<EnhancedAlertManagerConfig>): void {
    this.configManager.updateConfig(updates);
  }

  getConfigurationSummary() {
    return this.configManager.getConfigSummary();
  }

  // Administrative methods
  resolveAlert(alertId: string, reason: string): boolean {
    return AlertManager.resolveAlert(alertId, reason);
  }

  resolveAlertsByPattern(patternId: string, reason: string): number {
    return AlertManager.resolveAlertsByPattern(patternId, reason);
  }

  clearResolvedAlerts(): number {
    return AlertManager.clearResolvedAlerts();
  }

  clearAllAlerts(): number {
    return AlertManager.clearAllAlerts();
  }

  // Advanced features
  async exportConfiguration(
    outputPath: string,
    format: "json" | "yaml" = "json",
  ): Promise<void> {
    return await this.configManager.exportConfig(outputPath, format);
  }

  compareConfigurations(otherConfig: EnhancedAlertManagerConfig) {
    return this.configManager.compareConfigs(otherConfig);
  }

  validatePattern(pattern: string): boolean {
    return this.configManager.validatePattern(pattern);
  }

  // Health and monitoring
  async getSystemHealth(): Promise<{
    alertManager: { healthy: boolean; details?: string };
    storage: { healthy: boolean; stats: unknown };
    correlation: { healthy: boolean; stats: unknown };
    notifications: { healthy: boolean; channels: unknown[] };
    configuration: { healthy: boolean; summary: unknown };
  }> {
    const storageStats = this.alertStorage.getStorageStats();
    const correlationStats = this.correlationEngine.getCorrelationStats();
    const channelStatuses = this.notificationManager.getChannelStatuses();
    const configSummary = this.configManager.getConfigSummary();

    return {
      alertManager: {
        healthy: this.initialized,
        details: this.initialized ? "Operational" : "Not initialized",
      },
      storage: {
        healthy: true,
        stats: storageStats,
      },
      correlation: {
        healthy: correlationStats.totalRules > 0,
        stats: correlationStats,
      },
      notifications: {
        healthy: channelStatuses.some((c) => c.healthy && c.enabled),
        channels: channelStatuses,
      },
      configuration: {
        healthy: true,
        summary: configSummary,
      },
    };
  }

  // Graceful shutdown
  async shutdown(): Promise<void> {
    console.warn("🔄 Shutting down Enhanced Alert Manager...");

    try {
      // Shutdown components in reverse order
      await this.alertStorage.shutdown();
      this.correlationEngine.shutdown();
      this.configManager.shutdown();

      this.initialized = false;

      console.warn("✅ Enhanced Alert Manager shutdown complete");
    } catch (error) {
      console.error("❌ Error during Enhanced Alert Manager shutdown:", error);
    }
  }

  // Factory method for easy setup
  static createWithDefaults(
    options: {
      configPath?: string;
      template?: "minimal" | "full" | "development" | "production";
      webhookUrl?: string;
      slackWebhookUrl?: string;
      enableCorrelation?: boolean;
    } = {},
  ): EnhancedAlertManager {
    const manager = EnhancedAlertManager.getInstance(options.configPath);

    // Apply template configuration if specified
    if (options.template && options.template !== "full") {
      const templateConfig = manager.configManager.generateTemplate(
        options.template,
      );

      // Override with provided options
      if (options.webhookUrl) {
        templateConfig.notifications.channels[0].config.webhook!.url =
          options.webhookUrl;
      }

      if (options.slackWebhookUrl) {
        const slackChannel = createSlackChannel({
          id: "default-slack",
          name: "Default Slack Channel",
          webhookUrl: options.slackWebhookUrl,
          channel: "#alerts",
        });
        templateConfig.notifications.channels.push({
          id: slackChannel.config.id,
          type: slackChannel.config.type,
          name: slackChannel.config.name,
          enabled: slackChannel.config.enabled,
          config: slackChannel.config.config,
          rateLimits: slackChannel.config.rateLimits,
          healthCheck: slackChannel.config.healthCheck,
          retryConfig: slackChannel.config.retryConfig,
        });
      }

      if (options.enableCorrelation !== undefined) {
        templateConfig.correlation.enabled = options.enableCorrelation;
      }

      manager.updateConfiguration(templateConfig);
    }

    return manager;
  }
}

// Global instance access for backward compatibility
export const enhancedAlertManager = EnhancedAlertManager.getInstance();

// Export factory function for convenience
export function createEnhancedAlertManager(options?: {
  configPath?: string;
  template?: "minimal" | "full" | "development" | "production";
  webhookUrl?: string;
  slackWebhookUrl?: string;
  enableCorrelation?: boolean;
}): EnhancedAlertManager {
  return EnhancedAlertManager.createWithDefaults(options);
}
