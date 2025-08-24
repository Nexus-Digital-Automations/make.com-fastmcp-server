/**
 * Server Split Configuration
 * 
 * Splits the monolithic FastMCP server into 3 focused servers to ensure
 * each server can initialize within 60 seconds.
 */

// Server 1: Essential Operations (Most commonly used tools)
export const essentialToolCategories = [
  'scenarios',
  'connections', 
  'variables',
  'templates',
  'folders'
];

// Server 2: Development & Integration (Development-focused tools)
export const developmentToolCategories = [
  'custom-apps',
  'sdk',
  'marketplace',
  'blueprint-collaboration',
  'cicd-integration',
  'procedures'
];

// Server 3: Analytics & Governance (Monitoring and compliance tools)
export const governanceToolCategories = [
  'analytics',
  'performance-analysis',
  'real-time-monitoring',
  'log-streaming',
  'audit-compliance',
  'policy-compliance-validation',
  'compliance-policy',
  'zero-trust-auth',
  'multi-tenant-security',
  'naming-convention-policy',
  'scenario-archival-policy',
  'notifications',
  'budget-control',
  'certificates',
  'ai-governance-engine'
];

// Remaining tools for enterprise/admin server
export const enterpriseToolCategories = [
  'permissions',
  'billing',
  'ai-agents', 
  'enterprise-secrets'
];

export interface ServerConfig {
  name: string;
  categories: string[];
  port: number;
  description: string;
  timeout: number;
}

export const serverConfigs: ServerConfig[] = [
  {
    name: 'make-essential-server',
    categories: essentialToolCategories,
    port: 3000,
    description: 'Essential Operations - Scenarios, Connections, Variables, Templates, Folders',
    timeout: 25000
  },
  {
    name: 'make-dev-server', 
    categories: developmentToolCategories,
    port: 3001,
    description: 'Development & Integration - Custom Apps, SDK, Marketplace, Blueprints, CI/CD, Procedures',
    timeout: 25000
  },
  {
    name: 'make-governance-server',
    categories: governanceToolCategories, 
    port: 3002,
    description: 'Analytics & Governance - Monitoring, Compliance, Security, Policies, Notifications',
    timeout: 30000
  },
  {
    name: 'make-enterprise-server',
    categories: enterpriseToolCategories,
    port: 3003, 
    description: 'Enterprise Management - Permissions, Billing, AI Agents, Enterprise Secrets',
    timeout: 20000
  }
];