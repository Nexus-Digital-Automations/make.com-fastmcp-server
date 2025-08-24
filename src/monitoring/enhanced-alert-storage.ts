import { promises as fs } from "fs";
import * as path from "path";
import type { PatternAlert } from "./alert-manager.js";

export interface AlertStorageConfig {
  maxHotAlerts: number; // Active alerts in memory (default: 1000)
  maxWarmAlerts: number; // Compressed alerts in memory (default: 5000)
  archiveThreshold: number; // Days before archiving (default: 7)
  retentionPolicy: number; // Days to retain archived alerts (default: 90)
  compressionEnabled: boolean; // Enable alert compression (default: true)
  persistentStorageType: "file" | "database";
  archiveDirectory: string; // Directory for archived alerts
}

export interface ArchivedAlert {
  id: string;
  patternId: string;
  category: string;
  timestamp: number;
  resolvedAt?: number;
  compressed: boolean;
  metadata: {
    severity: "info" | "warning" | "critical";
    correlationId?: string;
    suppressionReason?: string;
    count: number;
    escalationLevel: number;
  };
}

export interface CompressedAlert {
  id: string;
  patternId: string;
  timestamp: number;
  metadata: string; // JSON stringified compressed data
  compressedAt: number;
}

export class AlertArchiveManager {
  constructor(private config: AlertStorageConfig) {}

  async archiveAlert(alert: PatternAlert): Promise<void> {
    const archivedAlert: ArchivedAlert = {
      id: alert.id,
      patternId: alert.patternId,
      category: this.extractCategory(alert.patternId),
      timestamp: alert.firstOccurrence.getTime(),
      resolvedAt: alert.resolved ? alert.lastOccurrence.getTime() : undefined,
      compressed: this.config.compressionEnabled,
      metadata: {
        severity: alert.severity,
        correlationId: (alert as PatternAlert & { correlationId?: string })
          .correlationId,
        suppressionReason: (
          alert as PatternAlert & { suppressionReason?: string }
        ).suppressionReason,
        count: alert.count,
        escalationLevel: alert.escalationLevel,
      },
    };

    if (this.config.persistentStorageType === "file") {
      await this.writeToFile(archivedAlert);
    } else {
      await this.writeToDatabase(archivedAlert);
    }
  }

  async retrieveAlert(alertId: string): Promise<PatternAlert | null> {
    if (this.config.persistentStorageType === "file") {
      return await this.readFromFile(alertId);
    } else {
      return await this.readFromDatabase(alertId);
    }
  }

  private extractCategory(patternId: string): string {
    // Extract category from pattern ID (e.g., "DATABASE_CONNECTION_ERROR" -> "DATABASE")
    const parts = patternId.split("_");
    return parts[0] || "GENERAL";
  }

  private async writeToFile(alert: ArchivedAlert): Promise<void> {
    try {
      // Create archive directory if it doesn't exist
      await fs.mkdir(this.config.archiveDirectory, { recursive: true });

      // Create category subdirectory
      const categoryDir = path.join(
        this.config.archiveDirectory,
        alert.category,
      );
      await fs.mkdir(categoryDir, { recursive: true });

      // Generate filename with date for organization
      const date = new Date(alert.timestamp).toISOString().split("T")[0];
      const filename = `${date}-${alert.id}.json`;
      const filePath = path.join(categoryDir, filename);

      // Write alert data
      await fs.writeFile(filePath, JSON.stringify(alert, null, 2));

      console.warn(`📁 Alert archived to: ${filePath}`);
    } catch (error) {
      console.error(`❌ Failed to archive alert ${alert.id}:`, error);
      throw error;
    }
  }

  private async readFromFile(alertId: string): Promise<PatternAlert | null> {
    try {
      // This is a simplified implementation - in production, you'd want an index
      const categories = await fs.readdir(this.config.archiveDirectory);

      for (const category of categories) {
        const categoryPath = path.join(this.config.archiveDirectory, category);
        const files = await fs.readdir(categoryPath);

        for (const file of files) {
          if (file.includes(alertId)) {
            const filePath = path.join(categoryPath, file);
            const data = await fs.readFile(filePath, "utf-8");
            const archived: ArchivedAlert = JSON.parse(data);
            return this.convertArchivedToPatternAlert(archived);
          }
        }
      }
    } catch (error) {
      console.warn(`⚠️ Failed to retrieve archived alert ${alertId}:`, error);
    }

    return null;
  }

  private async writeToDatabase(_alert: ArchivedAlert): Promise<void> {
    // Placeholder for database integration
    console.warn("📊 Database storage not implemented yet");
  }

  private async readFromDatabase(
    _alertId: string,
  ): Promise<PatternAlert | null> {
    // Placeholder for database integration
    console.warn("📊 Database retrieval not implemented yet");
    return null;
  }

  private convertArchivedToPatternAlert(archived: ArchivedAlert): PatternAlert {
    return {
      id: archived.id,
      patternId: archived.patternId,
      severity: archived.metadata.severity,
      message: `Pattern detected: ${archived.patternId}`,
      action: "Investigate archived alert",
      count: archived.metadata.count,
      firstOccurrence: new Date(archived.timestamp),
      lastOccurrence: new Date(archived.resolvedAt || archived.timestamp),
      resolved: !!archived.resolvedAt,
      escalationLevel: archived.metadata.escalationLevel,
      suppressedUntil: undefined, // Archived alerts are not suppressed
    };
  }

  async cleanupOldArchives(): Promise<number> {
    const cutoffTime =
      Date.now() - this.config.retentionPolicy * 24 * 60 * 60 * 1000;
    let cleanedCount = 0;

    try {
      const categories = await fs.readdir(this.config.archiveDirectory);

      for (const category of categories) {
        const categoryPath = path.join(this.config.archiveDirectory, category);
        const files = await fs.readdir(categoryPath);

        for (const file of files) {
          const filePath = path.join(categoryPath, file);
          const stats = await fs.stat(filePath);

          if (stats.mtime.getTime() < cutoffTime) {
            await fs.unlink(filePath);
            cleanedCount++;
          }
        }
      }

      if (cleanedCount > 0) {
        console.warn(`🧹 Cleaned up ${cleanedCount} old archived alerts`);
      }
    } catch (error) {
      console.error("❌ Failed to cleanup old archives:", error);
    }

    return cleanedCount;
  }
}

export class EnhancedAlertStorage {
  private hotAlerts: Map<string, PatternAlert>; // Active alerts
  private warmAlerts: Map<string, CompressedAlert>; // Compressed recent alerts
  private archiveManager: AlertArchiveManager;
  private config: AlertStorageConfig;

  constructor(config: AlertStorageConfig) {
    this.config = config;
    this.hotAlerts = new Map();
    this.warmAlerts = new Map();
    this.archiveManager = new AlertArchiveManager(config);

    // Start background cleanup process
    this.startBackgroundProcesses();
  }

  async storeAlert(alert: PatternAlert): Promise<void> {
    // Store in hot storage for immediate access
    this.hotAlerts.set(alert.id, alert);

    // Trigger archiving if thresholds exceeded
    if (this.hotAlerts.size > this.config.maxHotAlerts) {
      await this.archiveOldAlerts();
    }
  }

  private async archiveOldAlerts(): Promise<void> {
    const alertsArray = Array.from(this.hotAlerts.values());
    const oldAlerts = alertsArray
      .filter((alert) => this.shouldArchive(alert))
      .sort(
        (a, b) => a.firstOccurrence.getTime() - b.firstOccurrence.getTime(),
      );

    for (const alert of oldAlerts) {
      try {
        // Move to warm storage if recently resolved
        if (this.isRecentlyResolved(alert)) {
          const compressed = this.compressAlert(alert);
          this.warmAlerts.set(alert.id, compressed);

          // Maintain warm storage limits
          if (this.warmAlerts.size > this.config.maxWarmAlerts) {
            await this.archiveFromWarmStorage();
          }
        } else {
          // Archive to persistent storage
          await this.archiveManager.archiveAlert(alert);
        }

        // Remove from hot storage
        this.hotAlerts.delete(alert.id);
      } catch (error) {
        console.error(`❌ Failed to archive alert ${alert.id}:`, error);
      }
    }
  }

  private shouldArchive(alert: PatternAlert): boolean {
    const ageThreshold =
      Date.now() - this.config.archiveThreshold * 24 * 60 * 60 * 1000;
    return (
      alert.resolved ||
      alert.lastOccurrence.getTime() < ageThreshold ||
      alert.firstOccurrence.getTime() < ageThreshold
    );
  }

  private isRecentlyResolved(alert: PatternAlert): boolean {
    if (!alert.resolved) {
      return false;
    }

    const recentThreshold = Date.now() - 24 * 60 * 60 * 1000; // 1 day
    return alert.lastOccurrence.getTime() > recentThreshold;
  }

  private compressAlert(alert: PatternAlert): CompressedAlert {
    const metadata = {
      severity: alert.severity,
      message: alert.message,
      action: alert.action,
      count: alert.count,
      resolved: alert.resolved,
      escalationLevel: alert.escalationLevel,
      suppressedUntil: alert.suppressedUntil,
      firstOccurrence: alert.firstOccurrence.getTime(),
      lastOccurrence: alert.lastOccurrence.getTime(),
    };

    return {
      id: alert.id,
      patternId: alert.patternId,
      timestamp: alert.firstOccurrence.getTime(),
      metadata: JSON.stringify(metadata),
      compressedAt: Date.now(),
    };
  }

  private decompressAlert(compressed: CompressedAlert): PatternAlert {
    const metadata = JSON.parse(compressed.metadata);

    return {
      id: compressed.id,
      patternId: compressed.patternId,
      severity: metadata.severity,
      message: metadata.message,
      action: metadata.action,
      count: metadata.count,
      firstOccurrence: new Date(metadata.firstOccurrence),
      lastOccurrence: new Date(metadata.lastOccurrence),
      resolved: metadata.resolved,
      escalationLevel: metadata.escalationLevel,
      suppressedUntil: metadata.suppressedUntil
        ? new Date(metadata.suppressedUntil)
        : undefined,
    };
  }

  private async archiveFromWarmStorage(): Promise<void> {
    const warmArray = Array.from(this.warmAlerts.values());
    const oldWarmAlerts = warmArray
      .sort((a, b) => a.compressedAt - b.compressedAt)
      .slice(0, Math.floor(this.config.maxWarmAlerts * 0.2)); // Archive oldest 20%

    for (const compressed of oldWarmAlerts) {
      try {
        const alert = this.decompressAlert(compressed);
        await this.archiveManager.archiveAlert(alert);
        this.warmAlerts.delete(compressed.id);
      } catch (error) {
        console.error(
          `❌ Failed to archive from warm storage ${compressed.id}:`,
          error,
        );
      }
    }
  }

  async getAlert(alertId: string): Promise<PatternAlert | null> {
    // Check hot storage first
    if (this.hotAlerts.has(alertId)) {
      return this.hotAlerts.get(alertId)!;
    }

    // Check warm storage
    if (this.warmAlerts.has(alertId)) {
      return this.decompressAlert(this.warmAlerts.get(alertId)!);
    }

    // Check archived storage
    return await this.archiveManager.retrieveAlert(alertId);
  }

  getAllHotAlerts(): Map<string, PatternAlert> {
    return new Map(this.hotAlerts);
  }

  getStorageStats(): {
    hotAlerts: number;
    warmAlerts: number;
    totalMemoryAlerts: number;
    approximateMemoryUsage: string;
  } {
    const approximateMemoryUsage = this.calculateApproximateMemoryUsage();

    return {
      hotAlerts: this.hotAlerts.size,
      warmAlerts: this.warmAlerts.size,
      totalMemoryAlerts: this.hotAlerts.size + this.warmAlerts.size,
      approximateMemoryUsage,
    };
  }

  private calculateApproximateMemoryUsage(): string {
    // Rough estimation - each hot alert ~2KB, each warm alert ~0.5KB
    const hotMemory = this.hotAlerts.size * 2; // KB
    const warmMemory = this.warmAlerts.size * 0.5; // KB
    const totalKB = hotMemory + warmMemory;

    if (totalKB < 1024) {
      return `${Math.round(totalKB)}KB`;
    } else {
      return `${Math.round((totalKB / 1024) * 10) / 10}MB`;
    }
  }

  private startBackgroundProcesses(): void {
    // Periodic cleanup of old archives
    setInterval(
      async () => {
        try {
          await this.archiveManager.cleanupOldArchives();
        } catch (error) {
          console.error("❌ Background archive cleanup failed:", error);
        }
      },
      60 * 60 * 1000,
    ); // Run every hour

    // Periodic archiving check
    setInterval(
      async () => {
        try {
          if (this.hotAlerts.size > this.config.maxHotAlerts * 0.8) {
            await this.archiveOldAlerts();
          }
        } catch (error) {
          console.error("❌ Background archiving failed:", error);
        }
      },
      10 * 60 * 1000,
    ); // Check every 10 minutes
  }

  async shutdown(): Promise<void> {
    console.warn("🔄 Shutting down enhanced alert storage...");

    // Archive all resolvable alerts before shutdown
    const alertsToArchive = Array.from(this.hotAlerts.values()).filter(
      (alert) => this.shouldArchive(alert),
    );

    for (const alert of alertsToArchive) {
      try {
        await this.archiveManager.archiveAlert(alert);
      } catch (error) {
        console.error(
          `❌ Failed to archive alert during shutdown ${alert.id}:`,
          error,
        );
      }
    }

    console.warn(
      `✅ Enhanced alert storage shutdown complete. Archived ${alertsToArchive.length} alerts.`,
    );
  }
}
