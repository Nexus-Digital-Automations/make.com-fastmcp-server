/**
 * Mock implementation of fastmcp for Jest tests
 * Provides basic FastMCP functionality without ES module complexity
 */

export class UserError extends Error {
  constructor(message: string, public code?: string) {
    super(message);
    this.name = 'UserError';
  }
}

export class FastMCP {
  private tools: Map<string, any> = new Map();
  
  constructor(config?: any) {
    // Mock constructor
  }
  
  tool(name: string, config: any, handler: Function) {
    this.tools.set(name, { name, config, handler });
    return this;
  }
  
  addTool(toolDefinition: any) {
    const tool = {
      name: toolDefinition.name,
      description: toolDefinition.description,
      parameters: toolDefinition.parameters,
      annotations: toolDefinition.annotations,
      execute: toolDefinition.execute,
    };
    this.tools.set(toolDefinition.name, tool);
    return this;
  }
  
  getTool(name: string) {
    return this.tools.get(name);
  }
  
  getTools() {
    return Array.from(this.tools.values());
  }
  
  async serve() {
    // Mock serve method
    return Promise.resolve();
  }
  
  // Mock progress reporting
  progress(message: string, progress?: number) {
    return { message, progress };
  }
}

export default FastMCP;