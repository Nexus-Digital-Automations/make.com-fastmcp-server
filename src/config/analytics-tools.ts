/**
 * Analytics Server Tool Configuration  
 * Monitoring, analytics, compliance, policy enforcement, background processing
 */

import { ToolRegistration } from '../servers/base-server.js';
import addAnalyticsTools from '../tools/analytics.js';
import { addPerformanceAnalysisTools } from '../tools/performance-analysis.js';
import { addRealTimeMonitoringTools } from '../tools/real-time-monitoring.js';
import { addLogStreamingTools } from '../tools/log-streaming.js';
import { addAuditComplianceTools } from '../tools/audit-compliance.js';
import { addPolicyComplianceValidationTools } from '../tools/policy-compliance-validation.js';
import { addCompliancePolicyTools } from '../tools/compliance-policy.js';
import { addZeroTrustAuthTools } from '../tools/zero-trust-auth.js';
import { addMultiTenantSecurityTools } from '../tools/multi-tenant-security.js';
import { addCICDIntegrationTools } from '../tools/cicd-integration.js';
import { addProcedureTools } from '../tools/procedures.js';
import { addNamingConventionPolicyTools } from '../tools/naming-convention-policy.js';
import { addScenarioArchivalPolicyTools } from '../tools/scenario-archival-policy.js';
import { addNotificationTools } from '../tools/notifications.js';
import { addBudgetControlTools } from '../tools/budget-control.js';
import { addCertificateTools } from '../tools/certificates.js';
import { addAIGovernanceEngineTools } from '../tools/ai-governance-engine.js';

export const analyticsToolCategories = [
  'analytics',
  'performance-analysis', 
  'real-time-monitoring',
  'log-streaming',
  'audit-compliance',
  'policy-compliance-validation',
  'compliance-policy',
  'zero-trust-auth',
  'multi-tenant-security',
  'cicd-integration',
  'procedures',
  'naming-convention-policy', 
  'scenario-archival-policy',
  'notifications',
  'budget-control',
  'certificates',
  'ai-governance-engine'
];

export const analyticsToolRegistrations: ToolRegistration[] = [
  {
    name: 'analytics',
    category: 'analytics',
    registerFunction: addAnalyticsTools
  },
  {
    name: 'performance-analysis',
    category: 'performance-analysis',
    registerFunction: addPerformanceAnalysisTools
  },
  {
    name: 'real-time-monitoring',
    category: 'real-time-monitoring',
    registerFunction: addRealTimeMonitoringTools
  },
  {
    name: 'log-streaming',
    category: 'log-streaming',
    registerFunction: addLogStreamingTools
  },
  {
    name: 'audit-compliance',
    category: 'audit-compliance',
    registerFunction: addAuditComplianceTools
  },
  {
    name: 'policy-compliance-validation',
    category: 'policy-compliance-validation',
    registerFunction: addPolicyComplianceValidationTools
  },
  {
    name: 'compliance-policy',
    category: 'compliance-policy',
    registerFunction: addCompliancePolicyTools
  },
  {
    name: 'zero-trust-auth',
    category: 'zero-trust-auth',
    registerFunction: addZeroTrustAuthTools
  },
  {
    name: 'multi-tenant-security',
    category: 'multi-tenant-security',
    registerFunction: addMultiTenantSecurityTools
  },
  {
    name: 'cicd-integration',
    category: 'cicd-integration',
    registerFunction: addCICDIntegrationTools
  },
  {
    name: 'procedures',
    category: 'procedures',
    registerFunction: addProcedureTools
  },
  {
    name: 'naming-convention-policy',
    category: 'naming-convention-policy',
    registerFunction: addNamingConventionPolicyTools
  },
  {
    name: 'scenario-archival-policy',
    category: 'scenario-archival-policy',
    registerFunction: addScenarioArchivalPolicyTools
  },
  {
    name: 'notifications',
    category: 'notifications',
    registerFunction: addNotificationTools
  },
  {
    name: 'budget-control',
    category: 'budget-control',
    registerFunction: addBudgetControlTools
  },
  {
    name: 'certificates',
    category: 'certificates',
    registerFunction: addCertificateTools
  },
  {
    name: 'ai-governance-engine',
    category: 'ai-governance-engine',
    registerFunction: addAIGovernanceEngineTools
  }
];

export const analyticsServerDescription = `Analytics & Governance Server providing monitoring, performance analysis, compliance enforcement, security management, and policy automation including real-time monitoring, log streaming, audit compliance, security policies, CI/CD integration, automated procedures, and AI governance.`;

export const analyticsCapabilityDescription = `
- **Analytics & Insights**: Generate comprehensive analytics and performance insights
- **Performance Analysis**: Monitor system performance, identify bottlenecks, and optimize operations  
- **Real-time Monitoring**: Live monitoring of scenarios, connections, and system health
- **Log Management**: Stream, analyze, and export execution logs and diagnostic data
- **Audit Compliance**: Maintain audit trails and ensure regulatory compliance
- **Policy Enforcement**: Validate compliance with organizational policies and standards
- **Security Governance**: Implement zero-trust authentication and multi-tenant security
- **CI/CD Integration**: Automate deployment pipelines and continuous integration workflows
- **Automated Procedures**: Execute automated maintenance, monitoring, and management procedures
- **Governance Policies**: Enforce naming conventions, archival policies, and operational standards
- **Notification System**: Manage alerts, notifications, and communication workflows
- **Budget Control**: Monitor usage, enforce spending limits, and optimize resource allocation
- **Certificate Management**: Manage SSL/TLS certificates, validation, and security compliance
- **AI Governance**: Oversee AI model deployment, monitoring, and compliance frameworks
`;