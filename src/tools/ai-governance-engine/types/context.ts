/**
 * AI Governance Engine Context Types
 * Generated on 2025-08-22T09:54:20.000Z
 */

import type { FastMCPToolContext } from '../../../types/index.js';

export interface GovernanceContext extends FastMCPToolContext {
  config: {
    enabled: boolean;
    settings: {
      defaultMonitoringInterval?: number;
      defaultRiskThreshold?: number;
      enableMLPredictions?: boolean;
      enableAutomatedRemediation?: boolean;
    };
    metadata: {
      version: string;
      createdAt: Date;
    };
  };
}