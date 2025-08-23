/**
 * Core Server Tool Configuration
 * User-facing operations, real-time interactions, CRUD operations
 */

import { ToolRegistration } from '../servers/base-server.js';
import { addScenarioTools } from '../tools/scenarios.js';
import addConnectionTools from '../tools/connections.js';
import addPermissionTools from '../tools/permissions.js';
import { addVariableTools } from '../tools/variables.js';
import { addTemplateTools } from '../tools/templates.js';
import { addFolderTools } from '../tools/folders.js';
import { addCustomAppTools } from '../tools/custom-apps.js';
import { addSDKTools } from '../tools/sdk.js';
import { addMarketplaceTools } from '../tools/marketplace.js';
import { addBillingTools } from '../tools/billing.js';
import { addAIAgentTools } from '../tools/ai-agents.js';
import { addEnterpriseSecretsTools } from '../tools/enterprise-secrets.js';
import { addBlueprintCollaborationTools } from '../tools/blueprint-collaboration.js';

export const coreToolCategories = [
  'scenarios',
  'connections', 
  'permissions',
  'variables',
  'templates',
  'folders',
  'custom-apps',
  'sdk',
  'marketplace',
  'billing',
  'ai-agents',
  'enterprise-secrets',
  'blueprint-collaboration'
];

export const coreToolRegistrations: ToolRegistration[] = [
  {
    name: 'scenarios',
    category: 'scenarios',
    registerFunction: addScenarioTools
  },
  {
    name: 'connections',
    category: 'connections',
    registerFunction: addConnectionTools
  },
  {
    name: 'permissions',
    category: 'permissions', 
    registerFunction: addPermissionTools
  },
  {
    name: 'variables',
    category: 'variables',
    registerFunction: addVariableTools
  },
  {
    name: 'templates',
    category: 'templates',
    registerFunction: addTemplateTools
  },
  {
    name: 'folders',
    category: 'folders',
    registerFunction: addFolderTools
  },
  {
    name: 'custom-apps',
    category: 'custom-apps',
    registerFunction: addCustomAppTools
  },
  {
    name: 'sdk',
    category: 'sdk',
    registerFunction: addSDKTools
  },
  {
    name: 'marketplace',
    category: 'marketplace',
    registerFunction: addMarketplaceTools
  },
  {
    name: 'billing',
    category: 'billing',
    registerFunction: addBillingTools
  },
  {
    name: 'ai-agents',
    category: 'ai-agents',
    registerFunction: addAIAgentTools
  },
  {
    name: 'enterprise-secrets',
    category: 'enterprise-secrets',
    registerFunction: addEnterpriseSecretsTools
  },
  {
    name: 'blueprint-collaboration',
    category: 'blueprint-collaboration',
    registerFunction: addBlueprintCollaborationTools
  }
];

export const coreServerDescription = `Core Operations Server providing user-facing functionality including scenario management, connections, permissions, variables, templates, folders, custom apps, SDK integration, marketplace access, billing management, AI agents, enterprise secrets, and blueprint collaboration tools.`;

export const coreCapabilityDescription = `
- **Scenario Management**: Create, update, run, and troubleshoot automation scenarios
- **Connection Management**: Configure API connections, webhooks, and diagnostics  
- **Permission System**: Manage user permissions and access controls
- **Variable & Template Management**: Handle dynamic data and reusable templates
- **Folder Organization**: Organize and manage workspace folders and structures
- **Custom Applications**: Build and deploy custom integrations and applications
- **SDK Integration**: Manage Make.com SDK installations and configurations
- **Marketplace Access**: Browse and install marketplace applications and templates
- **Billing Management**: Handle subscriptions, usage tracking, and payment processing
- **AI Agent Management**: Configure and manage AI-powered automation agents
- **Enterprise Security**: Manage enterprise-grade secrets, encryption, and security policies
- **Blueprint Collaboration**: Collaborate on automation blueprints with version control
`;