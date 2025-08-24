import addPermissionTools from '../tools/permissions.js';
import { addBillingTools } from '../tools/billing.js';
import { addAIAgentTools } from '../tools/ai-agents.js';
import { addEnterpriseSecretsTools } from '../tools/enterprise-secrets.js';

export const enterpriseToolCategories = [
  'permissions',
  'billing',
  'ai-agents',
  'enterprise-secrets'
];

export const enterpriseToolRegistrations = [
  {
    name: 'permissions',
    category: 'permissions',
    registerFunction: addPermissionTools
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
  }
];

export const enterpriseServerDescription = `Enterprise Management Server providing administrative functionality including user permissions, billing management, AI agent configuration, and enterprise-grade security with secrets management.`;

export const enterpriseCapabilityDescription = `
- **Permission System**: Manage user permissions and access controls
- **Billing Management**: Handle subscriptions, usage tracking, and payment processing
- **AI Agent Management**: Configure and manage AI-powered automation agents
- **Enterprise Security**: Manage enterprise-grade secrets, encryption, and security policies
`;