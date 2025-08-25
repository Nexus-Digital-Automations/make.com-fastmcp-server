import {
  EnhancedAlertManager,
  createEnhancedAlertManager,
  type AlertProcessingMetrics,
} from "../monitoring/enhanced-alert-manager.js";
import type { EnhancedAlertManagerConfig } from "../monitoring/configuration-manager.js";

let enhancedAlertManagerInstance: EnhancedAlertManager | null = null;

function getEnhancedAlertManager(): EnhancedAlertManager {
  if (!enhancedAlertManagerInstance) {
    enhancedAlertManagerInstance = createEnhancedAlertManager({
      template: "development", // Default to development template
      enableCorrelation: true,
    });
  }
  return enhancedAlertManagerInstance;
}

export const enhancedAlertTools = [
  {
    name: "get-enhanced-alert-stats",
    description:
      "Get comprehensive statistics from the enhanced alert manager including storage, correlation, and notification metrics",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
    handler: async (): Promise<{
      stats: unknown;
      systemHealth: unknown;
      processingMetrics: AlertProcessingMetrics;
    }> => {
      try {
        const manager = getEnhancedAlertManager();

        const stats = manager.getAlertStats();
        const systemHealth = await manager.getSystemHealth();

        return {
          stats,
          systemHealth,
          processingMetrics: stats.processing,
        };
      } catch (error) {
        throw new Error(
          `Failed to get enhanced alert statistics: ${error instanceof Error ? error.message : "Unknown error"}`,
        );
      }
    },
  },

  {
    name: "get-active-correlations",
    description:
      "Get all currently active alert correlations showing related alerts and their relationships",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
    handler: async () => {
      try {
        const manager = getEnhancedAlertManager();
        const correlations = manager.getActiveCorrelations();

        return {
          correlations,
          count: correlations.length,
        };
      } catch (error) {
        throw new Error(
          `Failed to get active correlations: ${error instanceof Error ? error.message : "Unknown error"}`,
        );
      }
    },
  },

  {
    name: "get-notification-channel-status",
    description:
      "Get the status and health information of all configured notification channels",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
    handler: async () => {
      try {
        const manager = getEnhancedAlertManager();
        const channelStatuses = manager.getNotificationChannelStatuses();

        const summary = {
          totalChannels: channelStatuses.length,
          healthyChannels: channelStatuses.filter((c) => c.healthy).length,
          enabledChannels: channelStatuses.filter((c) => c.enabled).length,
          unhealthyChannels: channelStatuses.filter((c) => !c.healthy).length,
        };

        return {
          summary,
          channels: channelStatuses,
        };
      } catch (error) {
        throw new Error(
          `Failed to get notification channel status: ${error instanceof Error ? error.message : "Unknown error"}`,
        );
      }
    },
  },

  {
    name: "test-notification-channels",
    description: "Test connectivity to all configured notification channels",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
    handler: async () => {
      try {
        const manager = getEnhancedAlertManager();
        const testResults = await manager.testAllNotificationChannels();

        const summary = {
          totalTested: testResults.length,
          successful: testResults.filter((r) => r.success).length,
          failed: testResults.filter((r) => !r.success).length,
        };

        return {
          summary,
          results: testResults,
        };
      } catch (error) {
        throw new Error(
          `Failed to test notification channels: ${error instanceof Error ? error.message : "Unknown error"}`,
        );
      }
    },
  },

  {
    name: "get-enhanced-alert-configuration",
    description: "Get the current enhanced alert manager configuration",
    inputSchema: {
      type: "object",
      properties: {
        includeSecrets: {
          type: "boolean",
          description:
            "Whether to include sensitive configuration like API keys (default: false)",
          default: false,
        },
      },
      required: [],
    },
    handler: async (args: { includeSecrets?: boolean } = {}) => {
      try {
        const manager = getEnhancedAlertManager();
        const config = manager.getConfiguration();
        const summary = manager.getConfigurationSummary();

        // Sanitize sensitive information unless explicitly requested
        if (!args.includeSecrets) {
          // Remove sensitive data from configuration
          const sanitizedConfig = JSON.parse(JSON.stringify(config));

          for (const channel of sanitizedConfig.notifications.channels) {
            if (channel.config.webhook?.headers) {
              channel.config.webhook.headers = {
                "[REDACTED]": "Sensitive headers hidden",
              };
            }
            if (channel.config.email?.smtp?.auth) {
              channel.config.email.smtp.auth = {
                "[REDACTED]": "SMTP credentials hidden",
              };
            }
            if (channel.config.sms?.credentials) {
              channel.config.sms.credentials = {
                "[REDACTED]": "SMS credentials hidden",
              };
            }
          }

          return {
            summary,
            configuration: sanitizedConfig,
            note: "Sensitive information has been redacted. Use includeSecrets=true to view full configuration.",
          };
        }

        return {
          summary,
          configuration: config,
        };
      } catch (error) {
        throw new Error(
          `Failed to get enhanced alert configuration: ${error instanceof Error ? error.message : "Unknown error"}`,
        );
      }
    },
  },

  {
    name: "update-alert-configuration",
    description:
      "Update the enhanced alert manager configuration. Only specify the fields you want to change.",
    inputSchema: {
      type: "object",
      properties: {
        updates: {
          type: "object",
          description: "Partial configuration updates to apply",
          properties: {
            correlation: {
              type: "object",
              properties: {
                enabled: { type: "boolean" },
                timeWindow: {
                  type: "number",
                  description: "Correlation time window in milliseconds",
                },
                minConfidenceThreshold: {
                  type: "number",
                  minimum: 0.5,
                  maximum: 1.0,
                },
                enableLearning: { type: "boolean" },
              },
            },
            notifications: {
              type: "object",
              properties: {
                enabled: { type: "boolean" },
              },
            },
            performance: {
              type: "object",
              properties: {
                asyncProcessing: { type: "boolean" },
                batchSize: { type: "number", minimum: 1, maximum: 100 },
                maxConcurrentNotifications: { type: "number", minimum: 1 },
              },
            },
          },
        },
      },
      required: ["updates"],
    },
    handler: async (args: { updates: Partial<EnhancedAlertManagerConfig> }) => {
      try {
        const manager = getEnhancedAlertManager();

        // Validate the updates object
        if (!args.updates || typeof args.updates !== "object") {
          throw new Error("Updates must be a valid object");
        }

        manager.updateConfiguration(args.updates);
        const newSummary = manager.getConfigurationSummary();

        return {
          success: true,
          message: "Configuration updated successfully",
          newConfiguration: newSummary,
        };
      } catch (error) {
        throw new Error(
          `Failed to update alert configuration: ${error instanceof Error ? error.message : "Unknown error"}`,
        );
      }
    },
  },

  {
    name: "export-alert-configuration",
    description:
      "Export the current enhanced alert manager configuration to a file",
    inputSchema: {
      type: "object",
      properties: {
        outputPath: {
          type: "string",
          description: "Path where to save the configuration file",
        },
        format: {
          type: "string",
          enum: ["json", "yaml"],
          description: "Export format (json or yaml)",
          default: "json",
        },
      },
      required: ["outputPath"],
    },
    handler: async (args: { outputPath: string; format?: "json" | "yaml" }) => {
      try {
        const manager = getEnhancedAlertManager();

        await manager.exportConfiguration(
          args.outputPath,
          args.format || "json",
        );

        return {
          success: true,
          message: `Configuration exported successfully to ${args.outputPath}`,
          format: args.format || "json",
        };
      } catch (error) {
        throw new Error(
          `Failed to export configuration: ${error instanceof Error ? error.message : "Unknown error"}`,
        );
      }
    },
  },

  {
    name: "get-alert-storage-stats",
    description:
      "Get detailed statistics about the enhanced alert storage system including hot/warm/archived alert counts and memory usage",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
    handler: async () => {
      try {
        const manager = getEnhancedAlertManager();
        const stats = manager.getAlertStats();

        return {
          storage: stats.storage,
          totalAlerts: stats.total,
          activeAlerts: stats.active,
          resolvedAlerts: stats.resolved,
        };
      } catch (error) {
        throw new Error(
          `Failed to get alert storage statistics: ${error instanceof Error ? error.message : "Unknown error"}`,
        );
      }
    },
  },

  {
    name: "resolve-alert-by-id",
    description: "Resolve a specific alert by its ID with a reason",
    inputSchema: {
      type: "object",
      properties: {
        alertId: {
          type: "string",
          description: "The ID of the alert to resolve",
        },
        reason: {
          type: "string",
          description: "Reason for resolving the alert",
        },
      },
      required: ["alertId", "reason"],
    },
    handler: async (args: { alertId: string; reason: string }) => {
      try {
        const manager = getEnhancedAlertManager();

        const success = manager.resolveAlert(args.alertId, args.reason);

        if (success) {
          return {
            success: true,
            message: `Alert ${args.alertId} resolved successfully`,
            reason: args.reason,
          };
        } else {
          return {
            success: false,
            message: `Alert ${args.alertId} not found or already resolved`,
          };
        }
      } catch (error) {
        throw new Error(
          `Failed to resolve alert: ${error instanceof Error ? error.message : "Unknown error"}`,
        );
      }
    },
  },

  {
    name: "resolve-alerts-by-pattern",
    description: "Resolve all alerts matching a specific pattern ID",
    inputSchema: {
      type: "object",
      properties: {
        patternId: {
          type: "string",
          description: "The pattern ID to resolve alerts for",
        },
        reason: {
          type: "string",
          description: "Reason for resolving the alerts",
        },
      },
      required: ["patternId", "reason"],
    },
    handler: async (args: { patternId: string; reason: string }) => {
      try {
        const manager = getEnhancedAlertManager();

        const resolvedCount = manager.resolveAlertsByPattern(
          args.patternId,
          args.reason,
        );

        return {
          success: true,
          message: `Resolved ${resolvedCount} alerts for pattern ${args.patternId}`,
          resolvedCount,
          patternId: args.patternId,
          reason: args.reason,
        };
      } catch (error) {
        throw new Error(
          `Failed to resolve alerts by pattern: ${error instanceof Error ? error.message : "Unknown error"}`,
        );
      }
    },
  },

  {
    name: "get-system-health-report",
    description:
      "Get a comprehensive system health report including all enhanced alert manager components",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
    handler: async () => {
      try {
        const manager = getEnhancedAlertManager();

        const healthReport = await manager.getSystemHealth();
        const stats = manager.getAlertStats();
        const configSummary = manager.getConfigurationSummary();

        // Calculate overall health score
        const healthChecks = Object.values(healthReport);
        const healthyCount = healthChecks.filter(
          (check) => check.healthy,
        ).length;
        const overallHealth = (healthyCount / healthChecks.length) * 100;

        return {
          overallHealth: Math.round(overallHealth),
          overallStatus:
            overallHealth >= 80
              ? "Healthy"
              : overallHealth >= 60
                ? "Degraded"
                : "Unhealthy",
          components: healthReport,
          statistics: stats,
          configuration: configSummary,
          timestamp: new Date().toISOString(),
        };
      } catch (error) {
        throw new Error(
          `Failed to generate system health report: ${error instanceof Error ? error.message : "Unknown error"}`,
        );
      }
    },
  },
];

export default enhancedAlertTools;
