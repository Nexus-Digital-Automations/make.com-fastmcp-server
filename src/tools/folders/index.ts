/**
 * folders module entry point
 * Generated on 2025-08-22T09:20:06.379Z
 */

// Export all module components
export * from './types/index.js';
export * from './schemas/index.js';
export * from './core/index.js';
export * from './services/index.js';
export * from './utils/index.js';
export * from './tools/index.js';

// Default export
export { FoldersManager } from './core/index.js';
export { foldersTools } from './tools/index.js';

// Module metadata
export const moduleInfo = {
  name: 'folders',
  version: '1.0.0',
  description: 'Modular folders implementation for FastMCP server',
  generatedAt: '2025-08-22T09:20:06.379Z',
  components: {
    types: true,
    schemas: true,
    core: true,
    services: true,
    utils: true,
    tools: true
  }
};
