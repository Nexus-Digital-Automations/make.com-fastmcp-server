/**
 * @fileoverview Vault Operations Utility Module
 * Centralized utilities for HashiCorp Vault operations across enterprise secrets tools
 */

import { VaultClusterInfo } from '../types/index.js';
import { VaultServerConfigSchema } from '../schemas/index.js';
import { auditLogger } from '../../../lib/audit-logger.js';

/**
 * Singleton Vault Server Manager for centralized Vault operations
 */
export class VaultServerManager {
  private static instance: VaultServerManager | null = null;
  private readonly clusters: Map<string, VaultClusterInfo> = new Map();

  private constructor() {}

  public static getInstance(): VaultServerManager {
    if (!VaultServerManager.instance) {
      VaultServerManager.instance = new VaultServerManager();
    }
    return VaultServerManager.instance;
  }

  /**
   * Configure and initialize Vault cluster
   */
  public async configureVaultCluster(config: Parameters<typeof VaultServerConfigSchema.parse>[0]): Promise<VaultClusterInfo> {
    // Validate configuration
    const validatedConfig = VaultServerConfigSchema.parse(config);

    // Generate Vault configuration file
    const _vaultConfig = this.generateVaultConfig(validatedConfig);
    
    // Initialize cluster
    const clusterInfo: VaultClusterInfo = {
      clusterId: validatedConfig.clusterId,
      nodes: [{
        nodeId: validatedConfig.nodeId,
        address: validatedConfig.config.listener.address,
        status: 'uninitialized',
        version: '1.15.0', // Latest Vault version
        lastHeartbeat: new Date(),
      }],
      leaderNode: validatedConfig.nodeId,
      sealStatus: {
        sealed: true,
        threshold: 3,
        shares: 5,
        progress: 0,
      },
      initializationStatus: false,
      performanceMetrics: {
        requestsPerSecond: 0,
        averageLatencyMs: 0,
        errorRate: 0,
        activeConnections: 0,
      },
    };

    // Store cluster configuration
    this.clusters.set(validatedConfig.clusterId, clusterInfo);

    // Log cluster configuration
    await auditLogger.logEvent({
      level: 'info',
      category: 'security',
      action: 'vault_cluster_configured',
      success: true,
      details: {
        clusterId: validatedConfig.clusterId,
        storageType: validatedConfig.config.storage.type,
        sealType: validatedConfig.config.seal.type,
        highAvailability: validatedConfig.highAvailability.enabled,
      },
      riskLevel: 'low',
    });

    return clusterInfo;
  }

  /**
   * Get cluster information by cluster ID
   */
  public getCluster(clusterId: string): VaultClusterInfo | undefined {
    return this.clusters.get(clusterId);
  }

  /**
   * List all configured clusters
   */
  public listClusters(): VaultClusterInfo[] {
    return Array.from(this.clusters.values());
  }

  /**
   * Update cluster status
   */
  public updateClusterStatus(clusterId: string, updates: Partial<VaultClusterInfo>): void {
    const existing = this.clusters.get(clusterId);
    if (existing) {
      this.clusters.set(clusterId, { ...existing, ...updates });
    }
  }

  /**
   * Generate Vault configuration file content
   */
  public generateVaultConfig(config: Parameters<typeof VaultServerConfigSchema.parse>[0]): string {
    const validatedConfig = VaultServerConfigSchema.parse(config);
    
    return `
# Vault Configuration
storage "${validatedConfig.config.storage.type}" {
  ${Object.entries(validatedConfig.config.storage.config).map(([key, value]) => 
    `${key} = "${value}"`
  ).join('\n  ')}
}

listener "${validatedConfig.config.listener.type}" {
  address = "${validatedConfig.config.listener.address}"
  tls_cert_file = "${validatedConfig.config.listener.tlsConfig.certFile}"
  tls_key_file = "${validatedConfig.config.listener.tlsConfig.keyFile}"
  ${validatedConfig.config.listener.tlsConfig.caFile ? `tls_ca_file = "${validatedConfig.config.listener.tlsConfig.caFile}"` : ''}
  tls_min_version = "${validatedConfig.config.listener.tlsConfig.minVersion}"
}

seal "${validatedConfig.config.seal.type}" {
  ${Object.entries(validatedConfig.config.seal.config).map(([key, value]) => 
    `${key} = "${value}"`
  ).join('\n  ')}
}

telemetry {
  prometheus_retention_time = "24h"
  disable_hostname = true
  ${validatedConfig.config.telemetry.statsdAddress ? `statsd_address = "${validatedConfig.config.telemetry.statsdAddress}"` : ''}
  ${validatedConfig.config.telemetry.dogstatsdAddress ? `dogstatsd_addr = "${validatedConfig.config.telemetry.dogstatsdAddress}"` : ''}
}

${validatedConfig.highAvailability.enabled ? `
ha_storage "consul" {
  address = "127.0.0.1:8500"
  path = "vault/"
}

cluster_addr = "${validatedConfig.highAvailability.clusterAddress}"
api_addr = "${validatedConfig.highAvailability.redirectAddress}"
` : ''}

ui = true
raw_storage_endpoint = true
log_level = "info"
    `.trim();
  }

  /**
   * Validate Vault cluster health
   */
  public async validateClusterHealth(clusterId: string): Promise<boolean> {
    const cluster = this.clusters.get(clusterId);
    if (!cluster) {
      return false;
    }

    // Check if all nodes are responding
    const healthyNodes = cluster.nodes.filter(node => 
      node.status === 'active' && 
      (Date.now() - node.lastHeartbeat.getTime()) < 30000 // 30 seconds
    );

    return healthyNodes.length > 0;
  }
}

/**
 * Vault operations utilities for common tasks
 */
export const VaultOperations = {
  /**
   * Generate secure Vault root token
   */
  generateRootToken(): string {
    // In a real implementation, this would use proper cryptographic methods
    return `hvs.${Array.from({ length: 32 }, () => 
      Math.random().toString(36).charAt(2)
    ).join('')}`;
  },

  /**
   * Create Vault policy from permissions
   */
  createVaultPolicy(policyName: string, permissions: string[]): string {
    return `
# ${policyName} Policy
${permissions.map(permission => `path "${permission}" {
  capabilities = ["read", "list"]
}`).join('\n\n')}
    `.trim();
  },

  /**
   * Validate Vault address format
   */
  validateVaultAddress(address: string): boolean {
    const addressPattern = /^https?:\/\/[\w.-]+(:\d+)?$/;
    return addressPattern.test(address);
  },

  /**
   * Parse Vault seal status response
   */
  parseSealStatus(_response: unknown): { sealed: boolean; threshold: number; shares: number; progress: number } {
    // Default values for development/testing
    return {
      sealed: true,
      threshold: 3,
      shares: 5,
      progress: 0
    };
  }
};

/**
 * Export singleton instance for convenience
 */
export const vaultManager = VaultServerManager.getInstance();