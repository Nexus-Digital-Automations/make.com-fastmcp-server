import type { PatternAlert } from "./alert-manager.js";
import {
  logNotificationChannelAdded,
  logNotificationChannelRemoved,
  logNotificationChannelUnhealthy,
  logNotificationChannelRestored,
  logNotificationChannelHealthCheckFailed,
  logNoApplicableChannelsFound,
  logAlertNotificationSummary,
  logEmailNotificationSent,
  logSMSNotificationSent,
} from "../utils/logger.js";

export interface NotificationChannel {
  id: string;
  type: "email" | "webhook" | "sms" | "slack" | "teams";
  name: string;
  enabled: boolean;
  config: ChannelConfig;
  rateLimits: RateLimitConfig;
  healthCheck: HealthCheckConfig;
  retryConfig: RetryConfig;
}

export interface ChannelConfig {
  email?: {
    smtp: {
      host: string;
      port: number;
      secure: boolean;
      auth: { user: string; pass: string };
    };
    from: string;
    to: string[];
  };
  webhook?: {
    url: string;
    method: "POST" | "PUT";
    headers?: Record<string, string>;
    timeout: number;
  };
  slack?: {
    webhookUrl: string;
    channel: string;
    username?: string;
  };
  sms?: {
    provider: "twilio" | "aws-sns";
    credentials: Record<string, string>;
    phoneNumbers: string[];
  };
  teams?: {
    webhookUrl: string;
    title?: string;
  };
}

export interface RateLimitConfig {
  maxPerMinute: number;
  maxPerHour: number;
  burstLimit: number;
  backoffStrategy: "linear" | "exponential";
}

export interface HealthCheckConfig {
  enabled: boolean;
  interval: number; // milliseconds
  timeout: number; // milliseconds
}

export interface RetryConfig {
  maxRetries: number;
  retryDelay: number; // milliseconds
  backoffMultiplier: number;
}

export interface NotificationResult {
  success: boolean;
  channel: string;
  error?: string;
  statusCode?: number;
  responseTime?: number;
  messageId?: string;
  retryAfter?: number;
}

export interface NotificationSummary {
  alertId: string;
  totalChannels: number;
  successfulChannels: number;
  failedChannels: number;
  results: NotificationResult[];
}

export interface ChannelHealthStatus {
  healthy: boolean;
  lastCheck: number;
  errorCount: number;
  lastError?: string;
}

class RateLimiter {
  private requests: number[] = [];
  private burstRequests: number = 0;

  constructor(private config: RateLimitConfig) {}

  allowRequest(): boolean {
    const now = Date.now();
    const oneMinuteAgo = now - 60 * 1000;
    const oneHourAgo = now - 60 * 60 * 1000;

    // Clean old requests
    this.requests = this.requests.filter((time) => time > oneHourAgo);

    const recentMinuteRequests = this.requests.filter(
      (time) => time > oneMinuteAgo,
    );

    // Check burst limit
    if (this.burstRequests >= this.config.burstLimit) {
      return false;
    }

    // Check per-minute limit
    if (recentMinuteRequests.length >= this.config.maxPerMinute) {
      return false;
    }

    // Check per-hour limit
    if (this.requests.length >= this.config.maxPerHour) {
      return false;
    }

    // Allow request
    this.requests.push(now);
    this.burstRequests++;

    // Reset burst counter every minute
    setTimeout(() => {
      this.burstRequests = Math.max(0, this.burstRequests - 1);
    }, 60 * 1000);

    return true;
  }

  getRetryDelay(): number {
    const baseDelay = 60 * 1000; // 1 minute base delay
    if (this.config.backoffStrategy === "exponential") {
      return baseDelay * Math.pow(2, Math.min(this.burstRequests, 5));
    }
    return baseDelay * (this.burstRequests + 1);
  }
}

export abstract class BaseNotificationChannel {
  public config: NotificationChannel; // Made public for external access
  protected rateLimiter: RateLimiter;
  protected healthStatus: ChannelHealthStatus;

  constructor(config: NotificationChannel) {
    this.config = config;
    this.rateLimiter = new RateLimiter(config.rateLimits);
    this.healthStatus = { healthy: true, lastCheck: Date.now(), errorCount: 0 };

    // Start health checking if enabled
    if (config.healthCheck.enabled) {
      this.startHealthChecking();
    }
  }

  abstract sendNotification(alert: PatternAlert): Promise<NotificationResult>;
  abstract testConnection(): Promise<boolean>;

  async send(alert: PatternAlert): Promise<NotificationResult> {
    // Check if channel is enabled
    if (!this.config.enabled) {
      return {
        success: false,
        channel: this.config.id,
        error: "Channel disabled",
      };
    }

    // Check rate limits
    if (!this.rateLimiter.allowRequest()) {
      return {
        success: false,
        channel: this.config.id,
        error: "Rate limit exceeded",
        retryAfter: this.rateLimiter.getRetryDelay(),
      };
    }

    // Check health status
    if (!this.healthStatus.healthy) {
      return {
        success: false,
        channel: this.config.id,
        error: "Channel unhealthy",
      };
    }

    const startTime = Date.now();

    try {
      const result = await this.sendWithRetries(alert);
      this.updateHealthStatus(true);
      return {
        ...result,
        responseTime: Date.now() - startTime,
      };
    } catch (error) {
      this.updateHealthStatus(false, error);
      return {
        success: false,
        channel: this.config.id,
        error: error instanceof Error ? error.message : "Unknown error",
        responseTime: Date.now() - startTime,
      };
    }
  }

  private async sendWithRetries(
    alert: PatternAlert,
  ): Promise<NotificationResult> {
    let lastError: Error | null = null;

    for (
      let attempt = 0;
      attempt <= this.config.retryConfig.maxRetries;
      attempt++
    ) {
      try {
        return await this.sendNotification(alert);
      } catch (error) {
        lastError = error instanceof Error ? error : new Error("Unknown error");

        if (attempt < this.config.retryConfig.maxRetries) {
          const delay =
            this.config.retryConfig.retryDelay *
            Math.pow(this.config.retryConfig.backoffMultiplier, attempt);

          await new Promise((resolve) => setTimeout(resolve, delay));
        }
      }
    }

    throw lastError;
  }

  private updateHealthStatus(success: boolean, error?: unknown): void {
    this.healthStatus.lastCheck = Date.now();

    if (success) {
      this.healthStatus.healthy = true;
      this.healthStatus.errorCount = Math.max(
        0,
        this.healthStatus.errorCount - 1,
      );
    } else {
      this.healthStatus.errorCount++;
      this.healthStatus.lastError =
        error instanceof Error ? error.message : "Unknown error";

      // Mark unhealthy after 3 consecutive errors
      if (this.healthStatus.errorCount >= 3) {
        this.healthStatus.healthy = false;
        logNotificationChannelUnhealthy(
          this.config.id,
          this.healthStatus.errorCount,
        );
      }
    }
  }

  private startHealthChecking(): void {
    setInterval(async () => {
      try {
        const isHealthy = await this.testConnection();
        if (isHealthy && !this.healthStatus.healthy) {
          this.healthStatus.healthy = true;
          this.healthStatus.errorCount = 0;
          logNotificationChannelRestored(this.config.id);
        }
      } catch (error) {
        logNotificationChannelHealthCheckFailed(this.config.id, error);
      }
    }, this.config.healthCheck.interval);
  }

  getHealthStatus(): ChannelHealthStatus {
    return { ...this.healthStatus };
  }
}

export class WebhookNotificationChannel extends BaseNotificationChannel {
  async sendNotification(alert: PatternAlert): Promise<NotificationResult> {
    const webhookConfig = this.config.config.webhook!;

    const payload = {
      alertId: alert.id,
      patternId: alert.patternId,
      message: alert.message,
      severity: alert.severity,
      timestamp: alert.lastOccurrence.toISOString(),
      metadata: {
        count: alert.count,
        escalationLevel: alert.escalationLevel,
        correlationId: (alert as PatternAlert & { correlationId?: string })
          .correlationId,
        suppressionReason: (
          alert as PatternAlert & { suppressionReason?: string }
        ).suppressionReason,
        firstOccurrence: alert.firstOccurrence.toISOString(),
        resolved: alert.resolved,
      },
    };

    const response = await fetch(webhookConfig.url, {
      method: webhookConfig.method,
      headers: {
        "Content-Type": "application/json",
        ...webhookConfig.headers,
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(webhookConfig.timeout),
    });

    if (!response.ok) {
      throw new Error(
        `Webhook failed: ${response.status} ${response.statusText}`,
      );
    }

    return {
      success: true,
      channel: this.config.id,
      statusCode: response.status,
    };
  }

  async testConnection(): Promise<boolean> {
    try {
      const response = await fetch(this.config.config.webhook!.url, {
        method: "HEAD",
        signal: AbortSignal.timeout(5000),
      });
      return response.ok;
    } catch {
      return false;
    }
  }
}

export class SlackNotificationChannel extends BaseNotificationChannel {
  async sendNotification(alert: PatternAlert): Promise<NotificationResult> {
    const slackConfig = this.config.config.slack!;

    const severityColors = {
      critical: "#FF0000",
      warning: "#FFA500",
      info: "#0000FF",
    };

    const payload = {
      channel: slackConfig.channel,
      username: slackConfig.username || "FastMCP Alert Bot",
      attachments: [
        {
          color: severityColors[alert.severity] || "#808080",
          title: `🚨 ${alert.severity.toUpperCase()} Alert: ${alert.patternId}`,
          text: alert.message,
          fields: [
            {
              title: "Count",
              value: alert.count.toString(),
              short: true,
            },
            {
              title: "Escalation Level",
              value: alert.escalationLevel.toString(),
              short: true,
            },
            {
              title: "First Occurrence",
              value: alert.firstOccurrence.toISOString(),
              short: true,
            },
            {
              title: "Action Required",
              value: alert.action,
              short: false,
            },
          ],
          timestamp: Math.floor(alert.lastOccurrence.getTime() / 1000),
        },
      ],
    };

    const response = await fetch(slackConfig.webhookUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(10000),
    });

    if (!response.ok) {
      throw new Error(
        `Slack webhook failed: ${response.status} ${response.statusText}`,
      );
    }

    return {
      success: true,
      channel: this.config.id,
      statusCode: response.status,
    };
  }

  async testConnection(): Promise<boolean> {
    try {
      const testPayload = {
        text: "FastMCP Alert System - Connection Test",
        channel: this.config.config.slack!.channel,
      };

      const response = await fetch(this.config.config.slack!.webhookUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(testPayload),
        signal: AbortSignal.timeout(5000),
      });

      return response.ok;
    } catch {
      return false;
    }
  }
}

export class EmailNotificationChannel extends BaseNotificationChannel {
  async sendNotification(alert: PatternAlert): Promise<NotificationResult> {
    // This is a placeholder implementation
    // In a real implementation, you would use nodemailer or similar
    logEmailNotificationSent(alert.id, this.config.config.email!.to);

    return {
      success: true,
      channel: this.config.id,
      messageId: `email_${Date.now()}`,
    };
  }

  async testConnection(): Promise<boolean> {
    // Placeholder - would test SMTP connection
    return true;
  }
}

export class SMSNotificationChannel extends BaseNotificationChannel {
  async sendNotification(alert: PatternAlert): Promise<NotificationResult> {
    // This is a placeholder implementation
    // In a real implementation, you would use Twilio, AWS SNS, etc.
    logSMSNotificationSent(alert.id, this.config.config.sms!.phoneNumbers);

    return {
      success: true,
      channel: this.config.id,
      messageId: `sms_${Date.now()}`,
    };
  }

  async testConnection(): Promise<boolean> {
    // Placeholder - would test SMS service connection
    return true;
  }
}

export class MultiChannelNotificationManager {
  private channels: Map<string, BaseNotificationChannel>;
  private routingRules: NotificationRoutingRule[];

  constructor() {
    this.channels = new Map();
    this.routingRules = [];
    this.initializeDefaultRoutingRules();
  }

  addChannel(channel: BaseNotificationChannel): void {
    this.channels.set(channel.config.id, channel);
    logNotificationChannelAdded(channel.config.id, channel.config.type);
  }

  removeChannel(channelId: string): boolean {
    const removed = this.channels.delete(channelId);
    if (removed) {
      logNotificationChannelRemoved(channelId);
    }
    return removed;
  }

  async sendAlert(alert: PatternAlert): Promise<NotificationSummary> {
    const applicableChannels = this.selectChannels(alert);
    const results: NotificationResult[] = [];

    if (applicableChannels.length === 0) {
      logNoApplicableChannelsFound(alert.id);
      return {
        alertId: alert.id,
        totalChannels: 0,
        successfulChannels: 0,
        failedChannels: 0,
        results: [],
      };
    }

    // Send notifications in parallel
    const promises = applicableChannels.map(async (channel) => {
      try {
        return await channel.send(alert);
      } catch (error) {
        return {
          success: false,
          channel: channel.config.id,
          error: error instanceof Error ? error.message : "Unknown error",
        };
      }
    });

    const channelResults = await Promise.allSettled(promises);

    for (const result of channelResults) {
      if (result.status === "fulfilled") {
        results.push(result.value);
      } else {
        results.push({
          success: false,
          channel: "unknown",
          error:
            result.reason instanceof Error
              ? result.reason.message
              : "Unknown error",
        });
      }
    }

    const summary = {
      alertId: alert.id,
      totalChannels: applicableChannels.length,
      successfulChannels: results.filter((r) => r.success).length,
      failedChannels: results.filter((r) => !r.success).length,
      results: results,
    };

    logAlertNotificationSummary(
      alert.id,
      summary.successfulChannels,
      summary.totalChannels,
    );

    return summary;
  }

  private selectChannels(alert: PatternAlert): BaseNotificationChannel[] {
    const channels = Array.from(this.channels.values());

    // Filter by enabled status first
    const enabledChannels = channels.filter(
      (channel) => channel.config.enabled,
    );

    // Apply routing rules
    const selectedChannels: BaseNotificationChannel[] = [];

    for (const rule of this.routingRules) {
      if (rule.condition(alert)) {
        for (const channelId of rule.channelIds) {
          const channel = this.channels.get(channelId);
          if (channel && enabledChannels.includes(channel)) {
            selectedChannels.push(channel);
          }
        }
      }
    }

    // If no routing rules matched, use default selection logic
    if (selectedChannels.length === 0) {
      return this.getDefaultChannelsForAlert(alert, enabledChannels);
    }

    // Remove duplicates
    return Array.from(new Set(selectedChannels));
  }

  private getDefaultChannelsForAlert(
    alert: PatternAlert,
    enabledChannels: BaseNotificationChannel[],
  ): BaseNotificationChannel[] {
    // Route critical alerts to all channels
    if (alert.severity === "critical") {
      return enabledChannels;
    }

    // Route high escalation alerts to primary channels
    if (alert.escalationLevel >= 3) {
      return enabledChannels.filter((channel) =>
        ["webhook", "email", "slack"].includes(channel.config.type),
      );
    }

    // Default to webhook and email for regular alerts
    return enabledChannels.filter((channel) =>
      ["webhook", "email"].includes(channel.config.type),
    );
  }

  private initializeDefaultRoutingRules(): void {
    // Critical alerts go to all channels
    this.routingRules.push({
      name: "Critical Alert Broadcast",
      condition: (alert) => alert.severity === "critical",
      channelIds: [], // Will be populated with all channel IDs when channels are added
    });

    // Security alerts go to specific channels
    this.routingRules.push({
      name: "Security Alert Routing",
      condition: (alert) =>
        alert.patternId.includes("SECURITY") ||
        alert.patternId.includes("UNAUTHORIZED"),
      channelIds: ["security-slack", "security-email"], // Specific security channels
    });
  }

  getChannelStatuses(): Array<{
    id: string;
    type: string;
    name: string;
    enabled: boolean;
    healthy: boolean;
    errorCount: number;
    lastCheck: string;
  }> {
    return Array.from(this.channels.values()).map((channel) => {
      const health = channel.getHealthStatus();
      return {
        id: channel.config.id,
        type: channel.config.type,
        name: channel.config.name,
        enabled: channel.config.enabled,
        healthy: health.healthy,
        errorCount: health.errorCount,
        lastCheck: new Date(health.lastCheck).toISOString(),
      };
    });
  }

  async testAllChannels(): Promise<
    Array<{ channelId: string; success: boolean; error?: string }>
  > {
    const results: Array<{
      channelId: string;
      success: boolean;
      error?: string;
    }> = [];

    for (const [channelId, channel] of this.channels) {
      try {
        const success = await channel.testConnection();
        results.push({ channelId, success });
      } catch (error) {
        results.push({
          channelId,
          success: false,
          error: error instanceof Error ? error.message : "Unknown error",
        });
      }
    }

    return results;
  }
}

interface NotificationRoutingRule {
  name: string;
  condition: (alert: PatternAlert) => boolean;
  channelIds: string[];
}

// Factory functions for easy channel creation
export function createWebhookChannel(config: {
  id: string;
  name: string;
  url: string;
  enabled?: boolean;
}): WebhookNotificationChannel {
  return new WebhookNotificationChannel({
    id: config.id,
    type: "webhook",
    name: config.name,
    enabled: config.enabled ?? true,
    config: {
      webhook: {
        url: config.url,
        method: "POST",
        timeout: 10000,
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
  });
}

export function createSlackChannel(config: {
  id: string;
  name: string;
  webhookUrl: string;
  channel: string;
  enabled?: boolean;
}): SlackNotificationChannel {
  return new SlackNotificationChannel({
    id: config.id,
    type: "slack",
    name: config.name,
    enabled: config.enabled ?? true,
    config: {
      slack: {
        webhookUrl: config.webhookUrl,
        channel: config.channel,
        username: "FastMCP Alert Bot",
      },
    },
    rateLimits: {
      maxPerMinute: 10,
      maxPerHour: 100,
      burstLimit: 3,
      backoffStrategy: "exponential",
    },
    healthCheck: {
      enabled: true,
      interval: 600000, // 10 minutes
      timeout: 10000,
    },
    retryConfig: {
      maxRetries: 2,
      retryDelay: 2000,
      backoffMultiplier: 2,
    },
  });
}
