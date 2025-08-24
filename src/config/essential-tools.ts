import { addScenarioTools } from '../tools/scenarios.js';
import addConnectionTools from '../tools/connections.js';
import { addVariableTools } from '../tools/variables.js';
import { addTemplateTools } from '../tools/templates.js';
import { addFolderTools } from '../tools/folders.js';

export const essentialToolCategories = [
  'scenarios',
  'connections',
  'variables', 
  'templates',
  'folders'
];

export const essentialToolRegistrations = [
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
  }
];

export const essentialServerDescription = `Essential Operations Server providing core user-facing functionality including scenario management, connection configuration, variable handling, template management, and folder organization.`;

export const essentialCapabilityDescription = `
- **Scenario Management**: Create, update, run, and troubleshoot automation scenarios
- **Connection Management**: Configure API connections, webhooks, and diagnostics
- **Variable Management**: Handle dynamic data and scenario variables
- **Template Management**: Create and manage reusable automation templates  
- **Folder Organization**: Organize and manage workspace folders and structures
`;