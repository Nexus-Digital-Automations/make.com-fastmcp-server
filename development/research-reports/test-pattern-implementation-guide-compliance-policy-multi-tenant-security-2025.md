# Test Pattern Implementation Guide - Compliance Policy & Multi-Tenant Security Modules

**Implementation Guide Date**: August 22, 2025  
**Project**: Make.com FastMCP Server  
**Target Modules**: compliance-policy-basic.test.ts, multi-tenant-security-basic.test.ts  
**Task Reference**: task_1755822051155_2zzc4jkyu  
**Based On**: successful-test-patterns-make-com-fastmcp-server-2025.md

## Executive Summary

This implementation guide provides step-by-step instructions for migrating the failing test patterns in `compliance-policy-basic.test.ts` and `multi-tenant-security-basic.test.ts` to the proven successful patterns from `enterprise-secrets-basic.test.ts` and `budget-control-basic.test.ts`. The guide includes specific code examples, migration steps, and expected outcomes.

## 1. Current Problem Analysis

### 1.1 Identified Issues in Failing Tests

#### Compliance Policy Test Issues:
1. **❌ Mixed testing approach**: Using both `addCompliancePolicyTools` registration AND trying to use `executeTool`
2. **❌ Problematic logger mocking**: Complex jest mocking that may not be working properly
3. **❌ Missing mock context**: Some tests use `executeTool` without proper context
4. **❌ Skipped tests**: One test is marked as `.skip` due to logger issues

#### Multi-Tenant Security Test Issues:
1. **❌ Using `executeTool` helper**: Instead of direct `tool.execute()`
2. **❌ Registration-based tool access**: Using `findTool` after registration
3. **❌ Missing individual tool imports**: No direct tool creator imports

## 2. Migration Strategy

### 2.1 Two-Track Approach

Since these modules have different architectures, we'll use a two-track approach:

#### Track A: Modular Architecture (Like Enterprise Secrets)
- **Target**: Modules with individual tool creators
- **Method**: Import individual tool creators directly
- **Pattern**: `enterprise-secrets-basic.test.ts` approach

#### Track B: Monolithic Architecture (Like Budget Control)  
- **Target**: Modules with single registration function
- **Method**: Use registration for discovery, direct execution for testing
- **Pattern**: `budget-control-basic.test.ts` approach

## 3. Step-by-Step Migration Instructions

### 3.1 Phase 1: Identify Module Architecture

First, determine which track to use by checking the module structure:

```bash
# Check if module has individual tool creators
ls src/tools/compliance-policy/tools/
ls src/tools/multi-tenant-security/tools/

# If individual tool files exist → Track A (Modular)
# If no individual tools → Track B (Monolithic)
```

### 3.2 Phase 2: Compliance Policy Migration (Track B - Monolithic)

#### Current Problematic Pattern:
```typescript
// ❌ PROBLEMATIC: Mixed approach with complex mocking
jest.mock('../../../src/lib/logger.js', () => {
  const mockLogger = {
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    debug: jest.fn(),
    child: jest.fn(() => mockLogger),
  };
  return { default: mockLogger };
});

// ❌ PROBLEMATIC: Using executeTool without proper context
const result = await executeTool(toolConfig, input);
```

#### ✅ CORRECTED Pattern (Budget Control Style):
```typescript
// ✅ WORKING: Simple mock context creation
const mockContext = {
  log: {
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    debug: jest.fn(),
  },
  reportProgress: jest.fn(),
  session: { authenticated: true },
};

// ✅ WORKING: Direct tool execution with context
const result = await toolConfig.execute(input, mockContext);
```

#### Specific Migration Steps for Compliance Policy:

**Step 1: Remove Complex Logger Mocking**
```typescript
// ❌ REMOVE: Complex jest.mock for logger
// jest.mock('../../../src/lib/logger.js', () => { ... });

// ✅ ADD: Simple mock context in beforeEach
beforeEach(async () => {
  const serverSetup = createMockServer();
  mockServer = serverSetup.server;
  mockTool = serverSetup.mockTool;
  mockApiClient = new MockMakeApiClient();
  
  // ✅ NEW: Create mock context for tool execution
  mockContext = {
    log: {
      info: jest.fn(),
      error: jest.fn(),
      warn: jest.fn(),
      debug: jest.fn(),
    },
    reportProgress: jest.fn(),
    session: { authenticated: true },
  };
  
  mockTool.mockClear();
});
```

**Step 2: Fix Tool Execution Pattern**
```typescript
// ❌ CHANGE FROM: executeTool helper
const result = await executeTool(toolConfig, input);

// ✅ CHANGE TO: Direct execution with context
const result = await toolConfig.execute(input, mockContext);
```

**Step 3: Un-skip Tests**
```typescript
// ❌ CHANGE FROM: Skipped test
it.skip('should register all expected compliance policy tools', async () => {

// ✅ CHANGE TO: Active test
it('should register all expected compliance policy tools', async () => {
```

### 3.3 Phase 3: Multi-Tenant Security Migration (Track A - Modular)

#### Current Problematic Pattern:
```typescript
// ❌ PROBLEMATIC: Using findTool and executeTool
const provisionTool = tools.find(tool => tool.name === 'provision_tenant');
const result = await executeTool(provisionTool, input);
```

#### ✅ CORRECTED Pattern (Enterprise Secrets Style):
```typescript
// ✅ WORKING: Import individual tool creators
import { createProvisionTenantTool } from '../../../src/tools/multi-tenant-security/tools/provision-tenant.js';

// ✅ WORKING: Create tool with context and execute directly
const toolContext = {
  server: mockServer,
  apiClient: mockApiClient,
  logger: {
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    debug: jest.fn(),
  }
};

const tool = createProvisionTenantTool(toolContext);
const result = await tool.execute(input, mockContext);
```

#### Specific Migration Steps for Multi-Tenant Security:

**Step 1: Add Individual Tool Imports**
```typescript
// ✅ ADD: Individual tool creator imports
import { createProvisionTenantTool } from '../../../src/tools/multi-tenant-security/tools/provision-tenant.js';
import { createManageCryptographicIsolationTool } from '../../../src/tools/multi-tenant-security/tools/manage-cryptographic-isolation.js';
import { createConfigureNetworkSegmentationTool } from '../../../src/tools/multi-tenant-security/tools/configure-network-segmentation.js';
// ... add other tool imports as needed
```

**Step 2: Create Tool Execution Tests Section**
```typescript
describe('Tool Execution', () => {
  it('should execute tenant provisioning successfully', async () => {
    // ✅ NEW: Import and create tool directly
    const { createProvisionTenantTool } = await import('../../../src/tools/multi-tenant-security/tools/provision-tenant.js');
    
    const toolContext = {
      server: mockServer,
      apiClient: mockApiClient,
      logger: {
        info: jest.fn(),
        error: jest.fn(),
        warn: jest.fn(),
        debug: jest.fn(),
      }
    };
    
    const tool = createProvisionTenantTool(toolContext);
    const input = {
      tenantId: 'tenant-001',
      organizationId: 'org-123',
      // ... other required fields
    };

    const result = await tool.execute(input, mockContext);
    
    expect(result).toBeDefined();
    expect(typeof result).toBe('string');
    
    const parsedResult = JSON.parse(result);
    expect(parsedResult.success).toBe(true);
    expect(parsedResult.tenantId).toBe('tenant-001');
  });
});
```

## 4. Complete Template Files

### 4.1 Template for Compliance Policy (Monolithic Pattern)

```typescript
/**
 * Basic Test Suite for Compliance Policy Tools - CORRECTED VERSION
 * Tests core functionality of enterprise compliance policy management tools
 */

import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { createMockServer, expectValidZodParse, expectInvalidZodParse } from '../../utils/test-helpers.js';
import { MockMakeApiClient } from '../../mocks/make-api-client.mock.js';

describe('Compliance Policy Tools - Basic Tests', () => {
  let mockServer: any;
  let mockTool: jest.MockedFunction<any>;
  let mockApiClient: MockMakeApiClient;
  let mockContext: any;

  beforeEach(async () => {
    const serverSetup = createMockServer();
    mockServer = serverSetup.server;
    mockTool = serverSetup.mockTool;
    mockApiClient = new MockMakeApiClient();
    
    // ✅ CORRECTED: Simple mock context creation
    mockContext = {
      log: {
        info: jest.fn(),
        error: jest.fn(),
        warn: jest.fn(),
        debug: jest.fn(),
      },
      reportProgress: jest.fn(),
      session: { authenticated: true },
    };
    
    mockTool.mockClear();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('Tool Registration', () => {
    it('should successfully import and register all compliance policy tools', async () => {
      const { addCompliancePolicyTools } = await import('../../../src/tools/compliance-policy.js');
      
      expect(() => {
        addCompliancePolicyTools(mockServer, mockApiClient as any);
      }).not.toThrow();
      
      expect(mockTool).toHaveBeenCalled();
      expect(mockTool.mock.calls.length).toBeGreaterThan(0);
    });

    it('should register all expected compliance policy tools', async () => {
      const { addCompliancePolicyTools } = await import('../../../src/tools/compliance-policy.js');
      addCompliancePolicyTools(mockServer, mockApiClient as any);
      
      const toolNames = mockTool.mock.calls.map(call => call[0].name);
      
      const expectedToolNames = [
        'create-compliance-policy',
        'validate-compliance',
        'generate-compliance-report',
        'list-compliance-policies',
        'update-compliance-policy',
        'get-compliance-templates',
        'create-policy-from-template'
      ];
      
      expectedToolNames.forEach(toolName => {
        expect(toolNames).toContain(toolName);
      });
      
      expect(toolNames.length).toBe(7);
    });
  });

  describe('Tool Execution', () => {
    beforeEach(async () => {
      const { addCompliancePolicyTools } = await import('../../../src/tools/compliance-policy.js');
      addCompliancePolicyTools(mockServer, mockApiClient as any);
    });

    it('should execute create-compliance-policy successfully', async () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'create-compliance-policy')[0];
      
      const input = {
        policyName: 'Test SOX Policy',
        description: 'Test SOX compliance policy',
        framework: ['sox'],
        version: '1.0.0',
        effectiveDate: new Date().toISOString(),
        scope: {
          organizationScope: 'global' as const,
        },
        controls: {
          preventive: [{
            controlId: 'SOX-001',
            name: 'Segregation of Duties',
            description: 'Implement segregation of duties',
            framework: ['sox'],
            category: 'preventive' as const,
            automationLevel: 'manual' as const,
            frequency: 'monthly' as const,
          }],
          detective: [],
          corrective: [],
        },
        enforcement: {
          automatedChecks: [],
          violations: { severity: 'high' as const, actions: [] },
          reporting: { frequency: 'monthly' as const, recipients: [], format: ['json'] },
        },
      };

      // ✅ CORRECTED: Direct tool execution with context
      const result = await toolConfig.execute(input, mockContext);
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult.success).toBe(true);
      expect(parsedResult.policyId).toBeDefined();
      expect(parsedResult.policy.name).toBe('Test SOX Policy');
    });

    it('should execute generate-compliance-report successfully', async () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'generate-compliance-report')[0];
      
      const input = {
        startDate: '2024-01-01T00:00:00Z',
        endDate: '2024-01-31T23:59:59Z',
        format: 'json' as const,
        includeViolations: true,
        includeMetrics: true,
        includeRecommendations: true,
      };

      // ✅ CORRECTED: Direct tool execution with context
      const result = await toolConfig.execute(input, mockContext);
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult.success).toBe(true);
      expect(parsedResult.reportId).toBeDefined();
    });
  });

  describe('Schema Validation', () => {
    beforeEach(async () => {
      const { addCompliancePolicyTools } = await import('../../../src/tools/compliance-policy.js');
      addCompliancePolicyTools(mockServer, mockApiClient as any);
    });

    it('should validate create-compliance-policy schema with valid data', () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'create-compliance-policy')[0];
      
      const validInput = {
        policyName: 'SOX Financial Controls',
        description: 'Comprehensive SOX compliance policy',
        framework: ['sox'],
        version: '1.0.0',
        effectiveDate: new Date().toISOString(),
        scope: { organizationScope: 'global' as const },
        controls: { preventive: [], detective: [], corrective: [] },
        enforcement: {
          automatedChecks: [],
          violations: { severity: 'high' as const, actions: [] },
          reporting: { frequency: 'monthly' as const, recipients: [], format: ['json'] },
        },
      };

      expectValidZodParse(toolConfig.parameters, validInput);
    });

    it('should reject invalid compliance policy data', () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'create-compliance-policy')[0];
      
      const invalidInputs = [
        {}, // Missing required fields
        {
          policyName: 'Test',
          framework: ['invalid-framework'],
          // ... missing other required fields
        },
      ];

      invalidInputs.forEach(invalidInput => {
        expectInvalidZodParse(toolConfig.parameters, invalidInput);
      });
    });
  });
});
```

### 4.2 Template for Multi-Tenant Security (Modular Pattern)

```typescript
/**
 * Basic Test Suite for Multi-Tenant Security Tools - CORRECTED VERSION
 * Tests core functionality of multi-tenant security management tools
 */

import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { createMockServer, expectValidZodParse, expectInvalidZodParse } from '../../utils/test-helpers.js';
import { MockMakeApiClient } from '../../mocks/make-api-client.mock.js';

describe('Multi-Tenant Security Tools - Basic Tests', () => {
  let mockServer: any;
  let mockTool: jest.MockedFunction<any>;
  let mockApiClient: MockMakeApiClient;
  let mockContext: any;

  beforeEach(async () => {
    const serverSetup = createMockServer();
    mockServer = serverSetup.server;
    mockTool = serverSetup.mockTool;
    mockApiClient = new MockMakeApiClient();
    
    // ✅ CORRECTED: Standardized mock context
    mockContext = {
      log: {
        info: jest.fn(),
        error: jest.fn(),
        warn: jest.fn(),
        debug: jest.fn(),
      },
      reportProgress: jest.fn(),
      session: { authenticated: true },
    };
    
    mockTool.mockClear();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('Tool Registration', () => {
    it('should successfully import and register multi-tenant security tools', async () => {
      const { addMultiTenantSecurityTools } = await import('../../../src/tools/multi-tenant-security.js');
      
      expect(() => {
        addMultiTenantSecurityTools(mockServer, mockApiClient as any);
      }).not.toThrow();
      
      expect(mockTool).toHaveBeenCalled();
      expect(mockTool.mock.calls.length).toBeGreaterThan(0);
    });

    it('should register all expected multi-tenant security tools', async () => {
      const { addMultiTenantSecurityTools } = await import('../../../src/tools/multi-tenant-security.js');
      addMultiTenantSecurityTools(mockServer, mockApiClient as any);
      
      const registeredToolNames = mockTool.mock.calls.map(call => call[0]?.name).filter(Boolean);
      
      const expectedToolNames = [
        'provision_tenant',
        'manage_cryptographic_isolation',
        'configure_network_segmentation',
        'manage_resource_quotas',
        'manage_governance_policies',
        'prevent_data_leakage',
        'manage_compliance_boundaries'
      ];
      
      expectedToolNames.forEach(expectedName => {
        expect(registeredToolNames).toContain(expectedName);
      });
    });
  });

  describe('Tool Execution', () => {
    it('should execute tenant provisioning successfully', async () => {
      // ✅ CORRECTED: Import individual tool creator (if available)
      const { createProvisionTenantTool } = await import('../../../src/tools/multi-tenant-security/tools/provision-tenant.js');
      
      const toolContext = {
        server: mockServer,
        apiClient: mockApiClient,
        logger: {
          info: jest.fn(),
          error: jest.fn(),
          warn: jest.fn(),
          debug: jest.fn(),
        }
      };
      
      const tool = createProvisionTenantTool(toolContext);
      const input = {
        tenantId: 'tenant-001',
        organizationId: 'org-123',
        config: {
          name: 'Test Tenant',
          description: 'Test tenant for validation',
          tier: 'enterprise' as const,
          features: ['encryption', 'audit', 'compliance'],
          securityLevel: 'high' as const,
          dataResidency: 'us-east-1',
          complianceFrameworks: ['soc2', 'gdpr']
        },
        cryptographicIsolation: {
          enabled: true,
          keyManagement: 'hsm' as const,
          encryptionStandard: 'aes256' as const
        },
        resourceQuotas: {
          maxScenarios: 1000,
          maxExecutions: 10000,
          storageGB: 100,
          bandwidthMBps: 50
        }
      };

      // ✅ CORRECTED: Direct tool execution with context
      const result = await tool.execute(input, mockContext);
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult.success).toBe(true);
      expect(parsedResult.tenantId).toBe('tenant-001');
      expect(parsedResult.tenant.config.name).toBe('Test Tenant');
    });

    it('should execute cryptographic isolation management successfully', async () => {
      // ✅ CORRECTED: Import individual tool creator
      const { createManageCryptographicIsolationTool } = await import('../../../src/tools/multi-tenant-security/tools/manage-cryptographic-isolation.js');
      
      const toolContext = {
        server: mockServer,
        apiClient: mockApiClient,
        logger: {
          info: jest.fn(),
          error: jest.fn(),
          warn: jest.fn(),
          debug: jest.fn(),
        }
      };
      
      const tool = createManageCryptographicIsolationTool(toolContext);
      const input = {
        tenantId: 'tenant-001',
        action: 'update' as const,
        config: {
          encryptionStandard: 'aes256' as const,
          keyRotationPolicy: {
            enabled: true,
            intervalDays: 90,
            autoRotate: true
          },
          hsmConfiguration: {
            provider: 'aws_cloudhsm' as const,
            enabled: true,
            config: {
              region: 'us-east-1',
              clusterId: 'cluster-123'
            }
          }
        }
      };

      const result = await tool.execute(input, mockContext);
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult.success).toBe(true);
      expect(parsedResult.tenantId).toBe('tenant-001');
    });

    // ✅ FALLBACK: For tools without individual creators, use registration pattern
    it('should execute network segmentation configuration successfully (fallback pattern)', async () => {
      const { addMultiTenantSecurityTools } = await import('../../../src/tools/multi-tenant-security.js');
      addMultiTenantSecurityTools(mockServer, mockApiClient as any);
      
      const tool = mockTool.mock.calls.find(call => call[0].name === 'configure_network_segmentation')?.[0];
      expect(tool).toBeDefined();
      
      const input = {
        tenantId: 'tenant-001',
        segmentationConfig: {
          vpcIsolation: true,
          subnetConfiguration: 'private' as const,
          firewallRules: [
            {
              ruleId: 'rule-001',
              type: 'allow' as const,
              protocol: 'https',
              port: 443,
              source: 'tenant-network',
              destination: 'make-api'
            }
          ]
        }
      };

      // ✅ CORRECTED: Direct execution with context
      const result = await tool.execute(input, mockContext);
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult.success).toBe(true);
    });
  });

  describe('Schema Validation', () => {
    beforeEach(async () => {
      const { addMultiTenantSecurityTools } = await import('../../../src/tools/multi-tenant-security.js');
      addMultiTenantSecurityTools(mockServer, mockApiClient as any);
    });

    it('should validate tenant provisioning schema', () => {
      const tool = mockTool.mock.calls.find(call => call[0].name === 'provision_tenant')?.[0];
      expect(tool).toBeDefined();
      
      const validInput = {
        tenantId: 'tenant-123',
        organizationId: 'org-456',
        config: {
          name: 'Valid Tenant',
          description: 'Valid tenant configuration',
          tier: 'enterprise' as const,
          features: ['encryption'],
          securityLevel: 'high' as const,
          dataResidency: 'us-east-1',
          complianceFrameworks: ['soc2']
        },
        cryptographicIsolation: {
          enabled: true,
          keyManagement: 'vault' as const,
          encryptionStandard: 'aes256' as const
        },
        resourceQuotas: {
          maxScenarios: 100,
          maxExecutions: 1000,
          storageGB: 10,
          bandwidthMBps: 10
        }
      };

      expectValidZodParse(tool.parameters, validInput);
    });

    it('should reject invalid tenant provisioning data', () => {
      const tool = mockTool.mock.calls.find(call => call[0].name === 'provision_tenant')?.[0];
      expect(tool).toBeDefined();
      
      const invalidInputs = [
        {}, // Missing required fields
        {
          tenantId: '',
          organizationId: 'org-456',
          // Missing config
        },
        {
          tenantId: 'tenant-123',
          organizationId: 'org-456',
          config: {
            name: '',
            tier: 'invalid-tier'
          }
        }
      ];

      invalidInputs.forEach(invalidInput => {
        expectInvalidZodParse(tool.parameters, invalidInput);
      });
    });
  });

  describe('Error Handling', () => {
    it('should handle invalid tenant provisioning gracefully', async () => {
      // Test error handling for individual tool creators
      const { createProvisionTenantTool } = await import('../../../src/tools/multi-tenant-security/tools/provision-tenant.js');
      
      const toolContext = {
        server: mockServer,
        apiClient: mockApiClient,
        logger: {
          info: jest.fn(),
          error: jest.fn(),
          warn: jest.fn(),
          debug: jest.fn(),
        }
      };
      
      const tool = createProvisionTenantTool(toolContext);
      const invalidInput = {
        tenantId: '',
        organizationId: '',
        config: {}
      };

      await expect(tool.execute(invalidInput, mockContext)).rejects.toThrow();
    });
  });
});
```

## 5. Migration Checklist

### 5.1 For Each Failing Test Module:

#### Pre-Migration Checklist:
- [ ] Identify module architecture (modular vs monolithic)
- [ ] Check for individual tool creator files in `src/tools/[module]/tools/`
- [ ] Review current test structure and identify problematic patterns
- [ ] Back up current test file

#### Migration Execution Checklist:
- [ ] Remove complex jest mocking (especially logger mocking)
- [ ] Add standardized mock context in `beforeEach`
- [ ] Replace `executeTool` calls with direct `tool.execute(input, mockContext)`
- [ ] Add individual tool imports (if modular architecture)
- [ ] Create tool context for individual tools (if modular)
- [ ] Update all test execution patterns
- [ ] Un-skip any skipped tests
- [ ] Update schema validation tests if needed

#### Post-Migration Validation Checklist:
- [ ] Run tests and verify they pass
- [ ] Check that all expected tools are being tested
- [ ] Verify schema validation is working
- [ ] Ensure error handling tests are functioning
- [ ] Compare test coverage with successful modules

### 5.2 Expected Outcomes:

After applying these patterns, you should see:
- **✅ All tests passing** (similar to enterprise-secrets: 33/33)
- **✅ No logger mocking errors** (`logger_js_1.default.child is not a function`)
- **✅ Proper tool execution** with context
- **✅ Consistent test structure** across modules
- **✅ No skipped tests** due to technical issues

## 6. Troubleshooting Guide

### 6.1 Common Issues After Migration:

#### Issue: "Cannot find module" errors for individual tool imports
**Solution**: Verify tool file structure and use fallback registration pattern:
```typescript
// If individual tool import fails, use registration pattern
const { addToolsFunction } = await import('../../../src/tools/module.js');
addToolsFunction(mockServer, mockApiClient as any);
const tool = mockTool.mock.calls.find(call => call[0].name === 'tool-name')?.[0];
```

#### Issue: Tool execution still failing with context
**Solution**: Verify mock context structure matches expected interface:
```typescript
const mockContext = {
  log: {
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    debug: jest.fn(),
  },
  reportProgress: jest.fn(),
  session: { authenticated: true },
};
```

#### Issue: Schema validation errors
**Solution**: Check that test data matches the actual schema requirements in the tool definition.

### 6.2 Verification Commands:

```bash
# Run specific test file
npm test tests/unit/tools/compliance-policy-basic.test.ts

# Run with verbose output
npm test tests/unit/tools/compliance-policy-basic.test.ts -- --verbose

# Run all related tests
npm test tests/unit/tools/compliance-policy-basic.test.ts tests/unit/tools/multi-tenant-security-basic.test.ts
```

## Conclusion

This implementation guide provides a systematic approach to migrating failing test patterns to the proven successful patterns. The key insight is to distinguish between modular architectures (which benefit from individual tool imports) and monolithic architectures (which work better with registration-based discovery and direct execution).

By following these patterns, the failing tests should achieve the same success rate as the enterprise-secrets module (33/33 tests passing) and budget-control module (consistent passing).

---

**Next Steps After Implementation**:
1. Apply these patterns to compliance-policy-basic.test.ts
2. Apply these patterns to multi-tenant-security-basic.test.ts  
3. Validate test passing rates
4. Use these patterns as templates for other failing test modules
5. Document any module-specific variations discovered during implementation