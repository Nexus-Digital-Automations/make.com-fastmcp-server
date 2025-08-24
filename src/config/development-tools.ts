import { addCustomAppTools } from '../tools/custom-apps.js';
import { addSDKTools } from '../tools/sdk.js';
import { addMarketplaceTools } from '../tools/marketplace.js';
import { addBlueprintCollaborationTools } from '../tools/blueprint-collaboration.js';
import { addCICDIntegrationTools } from '../tools/cicd-integration.js';
import { addProcedureTools } from '../tools/procedures.js';

export const developmentToolCategories = [
  'custom-apps',
  'sdk',
  'marketplace',
  'blueprint-collaboration', 
  'cicd-integration',
  'procedures'
];

export const developmentToolRegistrations = [
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
    name: 'blueprint-collaboration',
    category: 'blueprint-collaboration',
    registerFunction: addBlueprintCollaborationTools
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
  }
];

export const developmentServerDescription = `Development & Integration Server providing developer-focused functionality including custom app development, SDK management, marketplace integration, blueprint collaboration, CI/CD workflows, and automated procedures.`;

export const developmentCapabilityDescription = `
- **Custom Applications**: Build and deploy custom integrations and applications
- **SDK Integration**: Manage Make.com SDK installations and configurations
- **Marketplace Access**: Browse and install marketplace applications and templates
- **Blueprint Collaboration**: Collaborate on automation blueprints with version control
- **CI/CD Integration**: Automate deployment pipelines and continuous integration workflows
- **Automated Procedures**: Execute automated maintenance, monitoring, and management procedures
`;