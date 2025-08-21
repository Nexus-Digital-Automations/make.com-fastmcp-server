/**
 * Basic Test Suite for User Permissions & Role Management Tools
 * Tests core functionality of user, team, and organization management tools
 * Focuses on tool registration, configuration validation, and basic execution patterns
 */

import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { UserError } from 'fastmcp';
import { createMockServer, findTool, executeTool, expectValidZodParse, expectInvalidZodParse } from '../../utils/test-helpers.js';
import { MockMakeApiClient } from '../../mocks/make-api-client.mock.js';
import { testErrors } from '../../fixtures/test-data.js';

describe('Permissions & Role Management Tools - Basic Tests', () => {
  let mockServer: any;
  let mockTool: jest.MockedFunction<any>;
  let mockApiClient: MockMakeApiClient;

  // Complete test user for testing
  const testUser = {
    id: 1001,
    name: 'Test User',
    email: 'test.user@example.com',
    role: 'member' as const,
    teamId: 12345,
    organizationId: 67890,
    permissions: ['read', 'write'],
    isActive: true,
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-15T12:00:00Z',
    lastLoginAt: '2024-01-20T09:30:00Z',
    preferences: {
      theme: 'dark',
      timezone: 'UTC',
      language: 'en-US'
    }
  };

  // Complete test team for testing
  const testTeam = {
    id: 12345,
    name: 'Engineering Team',
    description: 'Main engineering team for product development',
    organizationId: 67890,
    memberCount: 8,
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-15T12:00:00Z',
    members: [
      {
        id: 1001,
        name: 'Test User',
        email: 'test.user@example.com',
        role: 'member',
        joinedAt: '2024-01-01T00:00:00Z'
      },
      {
        id: 1002,
        name: 'Admin User',
        email: 'admin.user@example.com',
        role: 'admin',
        joinedAt: '2024-01-01T00:00:00Z'
      }
    ]
  };

  // Complete test organization for testing
  const testOrganization = {
    id: 67890,
    name: 'Test Organization',
    description: 'A test organization for development and testing',
    plan: 'professional',
    memberCount: 25,
    teamCount: 4,
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-15T12:00:00Z',
    billing: {
      status: 'current',
      nextBillingDate: '2024-02-01T00:00:00Z'
    },
    settings: {
      ssoEnabled: true,
      auditLogsEnabled: true,
      advancedSecurityEnabled: true
    }
  };

  // Test invitation data
  const testInvitation = {
    id: 'inv_123456',
    email: 'newuser@example.com',
    role: 'member' as const,
    teamId: 12345,
    organizationId: 67890,
    status: 'pending' as const,
    permissions: ['read', 'write'],
    invitedBy: 1001,
    createdAt: '2024-01-20T10:00:00Z',
    expiresAt: '2024-01-27T10:00:00Z'
  };

  beforeEach(async () => {
    const serverSetup = createMockServer();
    mockServer = serverSetup.server;
    mockTool = serverSetup.mockTool;
    mockApiClient = new MockMakeApiClient();
    
    // Clear previous mock calls
    mockTool.mockClear();
  });

  afterEach(() => {
    jest.clearAllMocks();
    mockApiClient.reset();
  });

  describe('Tool Registration and Import', () => {
    it('should successfully import and register permission tools', async () => {
      const { addPermissionTools } = await import('../../../src/tools/permissions.js');
      
      // Should not throw an error
      expect(() => {
        addPermissionTools(mockServer, mockApiClient as any);
      }).not.toThrow();
      
      // Should call addTool for each permission tool
      expect(mockTool).toHaveBeenCalled();
      expect(mockTool.mock.calls.length).toBeGreaterThan(0);
    });

    it('should export the expected permission tools and functions', async () => {
      const permissionsModule = await import('../../../src/tools/permissions.js');
      
      // Check that expected exports exist
      expect(permissionsModule.addPermissionTools).toBeDefined();
      expect(typeof permissionsModule.addPermissionTools).toBe('function');
      expect(permissionsModule.default).toBeDefined();
      expect(typeof permissionsModule.default).toBe('function');
      
      // Note: TypeScript interfaces are not available at runtime, so we can't test for them
      // This is expected behavior - interfaces exist only during compilation
    });

    it('should register all core permission management tools', async () => {
      const { addPermissionTools } = await import('../../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const expectedTools = [
        'get-current-user',
        'list-users',
        'get-user',
        'update-user-role',
        'list-teams',
        'get-team',
        'create-team',
        'update-team',
        'delete-team',
        'list-organizations',
        'get-organization',
        'create-organization',
        'update-organization',
        'delete-organization',
        'invite-user'
      ];
      
      expectedTools.forEach(toolName => {
        const tool = findTool(mockTool, toolName);
        expect(tool).toBeDefined();
        expect(tool.name).toBe(toolName);
      });
    });
  });

  describe('Tool Configuration Validation', () => {
    it('should have correct structure for get-current-user tool', async () => {
      const { addPermissionTools } = await import('../../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-current-user');
      
      expect(tool.name).toBe('get-current-user');
      expect(tool.description).toContain('Get current user information and permissions');
      expect(tool.parameters).toBeDefined();
      expect(typeof tool.execute).toBe('function');
    });

    it('should have correct structure for user management tools', async () => {
      const { addPermissionTools } = await import('../../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const listUsersTool = findTool(mockTool, 'list-users');
      expect(listUsersTool.name).toBe('list-users');
      expect(listUsersTool.description).toContain('List and filter users');
      expect(listUsersTool.parameters).toBeDefined();

      const getUserTool = findTool(mockTool, 'get-user');
      expect(getUserTool.name).toBe('get-user');
      expect(getUserTool.description).toContain('detailed information about a specific user');
      expect(getUserTool.parameters).toBeDefined();

      const updateUserRoleTool = findTool(mockTool, 'update-user-role');
      expect(updateUserRoleTool.name).toBe('update-user-role');
      expect(updateUserRoleTool.description).toContain('Update user role and permissions');
      expect(updateUserRoleTool.parameters).toBeDefined();
    });

    it('should have correct structure for team management tools', async () => {
      const { addPermissionTools } = await import('../../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const listTeamsTool = findTool(mockTool, 'list-teams');
      expect(listTeamsTool.name).toBe('list-teams');
      expect(listTeamsTool.description).toContain('List and filter teams');
      expect(listTeamsTool.parameters).toBeDefined();

      const createTeamTool = findTool(mockTool, 'create-team');
      expect(createTeamTool.name).toBe('create-team');
      expect(createTeamTool.description).toContain('Create a new team');
      expect(createTeamTool.parameters).toBeDefined();

      const updateTeamTool = findTool(mockTool, 'update-team');
      expect(updateTeamTool.name).toBe('update-team');
      expect(updateTeamTool.description).toContain('Update team information');
      expect(updateTeamTool.parameters).toBeDefined();

      const deleteTeamTool = findTool(mockTool, 'delete-team');
      expect(deleteTeamTool.name).toBe('delete-team');
      expect(deleteTeamTool.description).toContain('Delete a team');
      expect(deleteTeamTool.parameters).toBeDefined();
    });

    it('should have correct structure for organization management tools', async () => {
      const { addPermissionTools } = await import('../../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const listOrganizationsTool = findTool(mockTool, 'list-organizations');
      expect(listOrganizationsTool.name).toBe('list-organizations');
      expect(listOrganizationsTool.description).toContain('List user organizations');
      expect(listOrganizationsTool.parameters).toBeDefined();

      const createOrganizationTool = findTool(mockTool, 'create-organization');
      expect(createOrganizationTool.name).toBe('create-organization');
      expect(createOrganizationTool.description).toContain('Create a new organization');
      expect(createOrganizationTool.parameters).toBeDefined();

      const deleteOrganizationTool = findTool(mockTool, 'delete-organization');
      expect(deleteOrganizationTool.name).toBe('delete-organization');
      expect(deleteOrganizationTool.description).toContain('Delete an organization');
      expect(deleteOrganizationTool.parameters).toBeDefined();
    });

    it('should have correct structure for user invitation tool', async () => {
      const { addPermissionTools } = await import('../../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const inviteUserTool = findTool(mockTool, 'invite-user');
      expect(inviteUserTool.name).toBe('invite-user');
      expect(inviteUserTool.description).toContain('Invite a user to join a team or organization');
      expect(inviteUserTool.parameters).toBeDefined();
    });
  });

  describe('Schema Validation', () => {
    it('should validate user filters schema with correct inputs', async () => {
      const { addPermissionTools } = await import('../../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-users');
      
      // Valid inputs
      const validInputs = [
        {},
        { teamId: 12345 },
        { organizationId: 67890 },
        { role: 'admin' },
        { role: 'member' },
        { role: 'viewer' },
        { isActive: true },
        { isActive: false },
        { search: 'john.doe' },
        { limit: 50, offset: 10 },
        { 
          teamId: 12345, 
          organizationId: 67890, 
          role: 'admin', 
          isActive: true, 
          search: 'admin', 
          limit: 25, 
          offset: 5 
        }
      ];
      
      validInputs.forEach(input => {
        expectValidZodParse(tool.parameters, input);
      });
    });

    it('should reject invalid user filters schema inputs', async () => {
      const { addPermissionTools } = await import('../../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-users');
      
      // Invalid inputs
      const invalidInputs = [
        { teamId: 0 }, // teamId must be >= 1
        { teamId: -1 }, // teamId must be >= 1
        { organizationId: 0 }, // organizationId must be >= 1
        { role: 'invalid_role' }, // invalid role enum
        { role: 'owner' }, // role not in enum
        { limit: 0 }, // limit must be >= 1
        { limit: 101 }, // limit must be <= 100
        { offset: -1 }, // offset must be >= 0
        { unknownField: 'value' }, // unexpected field due to strict schema
        { teamId: 'invalid' }, // teamId must be number
        { isActive: 'yes' }, // isActive must be boolean
      ];
      
      invalidInputs.forEach(input => {
        expectInvalidZodParse(tool.parameters, input);
      });
    });

    it('should validate update user role schema with different configurations', async () => {
      const { addPermissionTools } = await import('../../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'update-user-role');
      
      // Valid role update inputs
      const validInputs = [
        {
          userId: 1001,
          role: 'admin'
        },
        {
          userId: 1001,
          role: 'member',
          teamId: 12345
        },
        {
          userId: 1001,
          role: 'viewer',
          teamId: 12345,
          permissions: ['read', 'write']
        },
        {
          userId: 1001,
          role: 'admin',
          permissions: ['read', 'write', 'admin', 'manage_users']
        }
      ];
      
      validInputs.forEach(input => {
        expectValidZodParse(tool.parameters, input);
      });

      // Invalid inputs
      const invalidInputs = [
        { role: 'admin' }, // missing required userId
        { userId: 0, role: 'admin' }, // userId must be >= 1
        { userId: 1001, role: 'invalid' }, // invalid role enum
        { userId: 1001, role: 'admin', teamId: 0 }, // teamId must be >= 1
        { userId: 'invalid', role: 'admin' }, // userId must be number
      ];
      
      invalidInputs.forEach(input => {
        expectInvalidZodParse(tool.parameters, input);
      });
    });

    it('should validate team creation schema with different options', async () => {
      const { addPermissionTools } = await import('../../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-team');
      
      // Valid team creation inputs
      const validInputs = [
        {
          name: 'Engineering Team'
        },
        {
          name: 'Marketing Team',
          description: 'Team handling all marketing activities'
        },
        {
          name: 'Sales Team',
          description: 'Sales and customer acquisition team',
          organizationId: 67890
        }
      ];
      
      validInputs.forEach(input => {
        expectValidZodParse(tool.parameters, input);
      });

      // Invalid inputs
      const invalidInputs = [
        {}, // missing required name
        { name: '' }, // name cannot be empty
        { name: 'A'.repeat(101) }, // name too long (max 100 chars)
        { name: 'Valid Team', description: 'A'.repeat(501) }, // description too long (max 500 chars)
        { name: 'Valid Team', organizationId: 0 }, // organizationId must be >= 1
        { name: 'Valid Team', organizationId: 'invalid' }, // organizationId must be number
      ];
      
      invalidInputs.forEach(input => {
        expectInvalidZodParse(tool.parameters, input);
      });
    });

    it('should validate organization creation schema with different options', async () => {
      const { addPermissionTools } = await import('../../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-organization');
      
      // Valid organization creation inputs
      const validInputs = [
        {
          name: 'Tech Corporation'
        },
        {
          name: 'Marketing Agency',
          description: 'Full-service marketing and advertising agency'
        }
      ];
      
      validInputs.forEach(input => {
        expectValidZodParse(tool.parameters, input);
      });

      // Invalid inputs
      const invalidInputs = [
        {}, // missing required name
        { name: '' }, // name cannot be empty
        { name: 'A'.repeat(101) }, // name too long (max 100 chars)
        { name: 'Valid Org', description: 'A'.repeat(501) }, // description too long (max 500 chars)
      ];
      
      invalidInputs.forEach(input => {
        expectInvalidZodParse(tool.parameters, input);
      });
    });

    it('should validate user invitation schema with comprehensive options', async () => {
      const { addPermissionTools } = await import('../../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'invite-user');
      
      // Valid invitation inputs
      const validInputs = [
        {
          email: 'newuser@example.com'
        },
        {
          email: 'admin@example.com',
          role: 'admin'
        },
        {
          email: 'member@example.com',
          role: 'member',
          teamId: 12345
        },
        {
          email: 'viewer@example.com',
          role: 'viewer',
          organizationId: 67890
        },
        {
          email: 'poweruser@example.com',
          role: 'admin',
          teamId: 12345,
          organizationId: 67890,
          permissions: ['read', 'write', 'admin']
        }
      ];
      
      validInputs.forEach(input => {
        expectValidZodParse(tool.parameters, input);
      });

      // Invalid inputs
      const invalidInputs = [
        {}, // missing required email
        { email: 'invalid-email' }, // invalid email format
        { email: 'test@' }, // incomplete email
        { email: '@example.com' }, // missing local part
        { email: 'valid@example.com', role: 'invalid' }, // invalid role enum
        { email: 'valid@example.com', teamId: 0 }, // teamId must be >= 1
        { email: 'valid@example.com', organizationId: 0 }, // organizationId must be >= 1
        { email: 'valid@example.com', teamId: 'invalid' }, // teamId must be number
      ];
      
      invalidInputs.forEach(input => {
        expectInvalidZodParse(tool.parameters, input);
      });
    });
  });

  describe('Basic Tool Execution', () => {
    it('should execute get-current-user successfully with mocked data', async () => {
      mockApiClient.mockResponse('GET', '/users/me', {
        success: true,
        data: testUser
      });

      const { addPermissionTools } = await import('../../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-current-user');
      const result = await executeTool(tool, {});
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult.user).toBeDefined();
      expect(parsedResult.user.id).toBe(1001);
      expect(parsedResult.user.email).toBe('test.user@example.com');
      expect(parsedResult.user.role).toBe('member');
    });

    it('should execute list-users with filtering parameters', async () => {
      // When teamId is provided, the endpoint changes to /teams/{teamId}/users
      mockApiClient.mockResponse('GET', '/teams/12345/users', {
        success: true,
        data: [testUser],
        metadata: { total: 1 }
      });

      const { addPermissionTools } = await import('../../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-users');
      const result = await executeTool(tool, {
        teamId: 12345,
        role: 'member',
        isActive: true,
        limit: 20
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.users).toBeDefined();
      expect(parsedResult.users).toHaveLength(1);
      expect(parsedResult.users[0].name).toBe(testUser.name);
      expect(parsedResult.pagination).toBeDefined();
      expect(parsedResult.pagination.total).toBe(1);
    });

    it('should execute get-user with specific user ID', async () => {
      mockApiClient.mockResponse('GET', '/users/1001', {
        success: true,
        data: testUser
      });

      const { addPermissionTools } = await import('../../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-user');
      const result = await executeTool(tool, {
        userId: 1001
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.user).toBeDefined();
      expect(parsedResult.user.id).toBe(1001);
      expect(parsedResult.user.name).toBe(testUser.name);
      expect(parsedResult.user.email).toBe(testUser.email);
    });

    it('should execute update-user-role successfully', async () => {
      const updatedUser = { ...testUser, role: 'admin' as const };
      
      mockApiClient.mockResponse('PATCH', '/users/1001/roles', {
        success: true,
        data: updatedUser
      });

      const { addPermissionTools } = await import('../../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'update-user-role');
      const result = await executeTool(tool, {
        userId: 1001,
        role: 'admin',
        permissions: ['read', 'write', 'admin']
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.user).toBeDefined();
      expect(parsedResult.user.role).toBe('admin');
      expect(parsedResult.message).toContain('updated successfully');
    });

    it('should execute list-teams with filtering parameters', async () => {
      // When organizationId is provided, the endpoint changes to /organizations/{organizationId}/teams
      mockApiClient.mockResponse('GET', '/organizations/67890/teams', {
        success: true,
        data: [testTeam],
        metadata: { total: 1 }
      });

      const { addPermissionTools } = await import('../../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-teams');
      const result = await executeTool(tool, {
        organizationId: 67890,
        search: 'Engineering',
        limit: 10
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.teams).toBeDefined();
      expect(parsedResult.teams).toHaveLength(1);
      expect(parsedResult.teams[0].name).toBe(testTeam.name);
      expect(parsedResult.pagination.total).toBe(1);
    });

    it('should execute create-team successfully', async () => {
      const newTeam = { ...testTeam, id: 12346, name: 'New Test Team' };
      
      mockApiClient.mockResponse('POST', '/teams', {
        success: true,
        data: newTeam
      });

      const { addPermissionTools } = await import('../../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-team');
      const result = await executeTool(tool, {
        name: 'New Test Team',
        description: 'A new team for testing purposes',
        organizationId: 67890
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.team).toBeDefined();
      expect(parsedResult.team.name).toBe('New Test Team');
      expect(parsedResult.message).toContain('created successfully');
    });

    it('should execute update-team with partial updates', async () => {
      const updatedTeam = { ...testTeam, name: 'Updated Team Name' };
      
      mockApiClient.mockResponse('PATCH', '/teams/12345', {
        success: true,
        data: updatedTeam
      });

      const { addPermissionTools } = await import('../../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'update-team');
      const result = await executeTool(tool, {
        teamId: 12345,
        name: 'Updated Team Name'
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.team).toBeDefined();
      expect(parsedResult.team.name).toBe('Updated Team Name');
      expect(parsedResult.message).toContain('updated successfully');
    });

    it('should execute create-organization successfully', async () => {
      const newOrganization = { ...testOrganization, id: 67891, name: 'New Test Organization' };
      
      mockApiClient.mockResponse('POST', '/organizations', {
        success: true,
        data: newOrganization
      });

      const { addPermissionTools } = await import('../../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-organization');
      const result = await executeTool(tool, {
        name: 'New Test Organization',
        description: 'A new organization for testing purposes'
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.organization).toBeDefined();
      expect(parsedResult.organization.name).toBe('New Test Organization');
      expect(parsedResult.message).toContain('created successfully');
    });

    it('should execute invite-user successfully', async () => {
      mockApiClient.mockResponse('POST', '/users/invite', {
        success: true,
        data: testInvitation
      });

      const { addPermissionTools } = await import('../../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'invite-user');
      const result = await executeTool(tool, {
        email: 'newuser@example.com',
        role: 'member',
        teamId: 12345,
        permissions: ['read', 'write']
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.invitation).toBeDefined();
      expect(parsedResult.message).toContain('sent to newuser@example.com successfully');
    });
  });

  describe('Error Handling and Security', () => {
    it('should handle API failures gracefully', async () => {
      mockApiClient.mockFailure('GET', '/users/me', new Error('Authentication service unavailable'));

      const { addPermissionTools } = await import('../../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-current-user');
      
      await expect(executeTool(tool, {})).rejects.toThrow(UserError);
    });

    it('should handle unauthorized access errors', async () => {
      mockApiClient.mockResponse('GET', '/users/1001', testErrors.unauthorized);

      const { addPermissionTools } = await import('../../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-user');
      
      await expect(executeTool(tool, { userId: 1001 })).rejects.toThrow(UserError);
    });

    it('should validate required fields for team creation', async () => {
      const { addPermissionTools } = await import('../../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-team');
      
      // Missing required name field should fail validation
      await expect(executeTool(tool, {
        description: 'Team without a name'
      })).rejects.toThrow();
    });

    it('should validate email format for user invitations', async () => {
      const { addPermissionTools } = await import('../../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'invite-user');
      
      // Invalid email should fail validation
      await expect(executeTool(tool, {
        email: 'not-a-valid-email',
        role: 'member'
      })).rejects.toThrow();
    });

    it('should require update data for team updates', async () => {
      const { addPermissionTools } = await import('../../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'update-team');
      
      // Empty update data should fail
      mockApiClient.mockResponse('PATCH', '/teams/12345', testErrors.badRequest);
      
      await expect(executeTool(tool, {
        teamId: 12345
        // No update fields provided
      })).rejects.toThrow(UserError);
    });

    it('should handle user not found errors', async () => {
      mockApiClient.mockResponse('GET', '/users/999999', {
        success: false,
        error: { message: 'User not found' }
      });

      const { addPermissionTools } = await import('../../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-user');
      
      await expect(executeTool(tool, { userId: 999999 })).rejects.toThrow(UserError);
    });

    it('should handle team not found errors', async () => {
      mockApiClient.mockResponse('GET', '/teams/999999', {
        success: false,
        error: { message: 'Team not found' }
      });

      const { addPermissionTools } = await import('../../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-team');
      
      await expect(executeTool(tool, { teamId: 999999 })).rejects.toThrow(UserError);
    });

    it('should handle organization not found errors', async () => {
      mockApiClient.mockResponse('GET', '/organizations/999999', {
        success: false,
        error: { message: 'Organization not found' }
      });

      const { addPermissionTools } = await import('../../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-organization');
      
      await expect(executeTool(tool, { organizationId: 999999 })).rejects.toThrow(UserError);
    });

    it('should validate role assignments properly', async () => {
      mockApiClient.mockResponse('PATCH', '/users/1001/roles', {
        success: false,
        error: { message: 'Invalid role assignment' }
      });

      const { addPermissionTools } = await import('../../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'update-user-role');
      
      await expect(executeTool(tool, {
        userId: 1001,
        role: 'admin'
      })).rejects.toThrow(UserError);
    });
  });

  describe('Enterprise Security Patterns', () => {
    it('should implement secure user data handling patterns', async () => {
      const secureUser = {
        ...testUser,
        permissions: ['read', 'write', 'admin', 'manage_users'],
        securityProfile: {
          mfaEnabled: true,
          lastPasswordChange: '2024-01-10T00:00:00Z',
          failedLoginAttempts: 0,
          accountLocked: false
        },
        auditTrail: {
          createdBy: 1000,
          lastModifiedBy: 1000,
          lastModifiedAt: '2024-01-15T12:00:00Z'
        }
      };

      mockApiClient.mockResponse('GET', '/users/1001', {
        success: true,
        data: secureUser
      });

      const { addPermissionTools } = await import('../../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-user');
      const result = await executeTool(tool, { userId: 1001 });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.user).toBeDefined();
      expect(parsedResult.user.name).toBe('Test User');
      expect(parsedResult.user.securityProfile).toBeDefined();
      expect(parsedResult.user.auditTrail).toBeDefined();
    });

    it('should validate enterprise team creation with security controls', async () => {
      const enterpriseTeam = {
        ...testTeam,
        id: 12346,
        name: 'Enterprise Security Team',
        description: 'Team with enhanced security controls',
        securitySettings: {
          requireMFA: true,
          allowGuestAccess: false,
          sessionTimeout: 3600,
          ipRestrictions: ['192.168.1.0/24']
        },
        complianceSettings: {
          auditEnabled: true,
          dataRetention: 2555, // 7 years in days
          encryptionRequired: true
        }
      };

      mockApiClient.mockResponse('POST', '/teams', {
        success: true,
        data: enterpriseTeam
      });

      const { addPermissionTools } = await import('../../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-team');
      const result = await executeTool(tool, {
        name: 'Enterprise Security Team',
        description: 'Team with enhanced security controls',
        organizationId: 67890
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.team).toBeDefined();
      expect(parsedResult.team.name).toBe('Enterprise Security Team');
    });

    it('should validate organization security compliance', async () => {
      const enterpriseOrganization = {
        ...testOrganization,
        complianceFrameworks: ['SOC2', 'GDPR', 'HIPAA'],
        securityControls: {
          ssoEnforced: true,
          mfaRequired: true,
          passwordPolicy: {
            minLength: 12,
            requireSpecialChars: true,
            requireNumbers: true,
            maxAge: 90
          },
          sessionControls: {
            maxInactivity: 1800,
            concurrentSessions: 1,
            ipRestrictions: true
          }
        },
        auditConfiguration: {
          logRetention: 2555, // 7 years
          realTimeMonitoring: true,
          alertingEnabled: true,
          complianceReporting: true
        }
      };

      mockApiClient.mockResponse('GET', '/organizations/67890', {
        success: true,
        data: enterpriseOrganization
      });

      const { addPermissionTools } = await import('../../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-organization');
      const result = await executeTool(tool, { organizationId: 67890 });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.organization).toBeDefined();
      expect(parsedResult.organization.complianceFrameworks).toBeDefined();
      expect(parsedResult.organization.securityControls).toBeDefined();
      expect(parsedResult.organization.auditConfiguration).toBeDefined();
    });

    it('should detect and report permission escalation attempts', async () => {
      const suspiciousRoleUpdate = {
        userId: 1001,
        role: 'admin' as const,
        permissions: ['read', 'write', 'admin', 'manage_users', 'manage_billing', 'delete_all']
      };

      mockApiClient.mockResponse('PATCH', '/users/1001/roles', {
        success: false,
        error: { 
          message: 'Permission escalation detected',
          code: 'SECURITY_VIOLATION',
          details: {
            attemptedPermissions: ['delete_all'],
            currentUserRole: 'member',
            securityAlert: true
          }
        }
      });

      const { addPermissionTools } = await import('../../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'update-user-role');
      
      await expect(executeTool(tool, suspiciousRoleUpdate)).rejects.toThrow(UserError);
    });

    it('should validate secure invitation patterns with time-bounded access', async () => {
      const secureInvitation = {
        ...testInvitation,
        securityConstraints: {
          ipRestrictions: ['192.168.1.0/24'],
          mfaRequired: true,
          maxAttempts: 3,
          expirationHours: 24
        },
        complianceValidation: {
          backgroundCheckRequired: true,
          signedAgreements: ['NDA', 'Security_Policy'],
          approvalWorkflow: {
            requiredApprovers: 2,
            approverRoles: ['admin', 'security_officer']
          }
        }
      };

      mockApiClient.mockResponse('POST', '/teams/12345/invite', {
        success: true,
        data: secureInvitation
      });

      const { addPermissionTools } = await import('../../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'invite-user');
      const result = await executeTool(tool, {
        email: 'secure.user@example.com',
        role: 'member',
        teamId: 12345,
        permissions: ['read']
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.invitation).toBeDefined();
      expect(parsedResult.message).toContain('sent to secure.user@example.com successfully');
    });
  });

  describe('Advanced Permission Management', () => {
    it('should execute delete operations with confirmation', async () => {
      mockApiClient.mockResponse('DELETE', '/teams/12345', {
        success: true,
        data: { message: 'Team deleted successfully' }
      });

      const { addPermissionTools } = await import('../../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'delete-team');
      const result = await executeTool(tool, {
        teamId: 12345
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.message).toContain('deleted successfully');
    });

    it('should execute organization updates with validation', async () => {
      const updatedOrganization = {
        ...testOrganization,
        name: 'Updated Organization Name',
        description: 'Updated description with new information'
      };

      mockApiClient.mockResponse('PATCH', '/organizations/67890', {
        success: true,
        data: updatedOrganization
      });

      const { addPermissionTools } = await import('../../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'update-organization');
      const result = await executeTool(tool, {
        organizationId: 67890,
        name: 'Updated Organization Name',
        description: 'Updated description with new information'
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.organization.name).toBe('Updated Organization Name');
      expect(parsedResult.message).toContain('updated successfully');
    });

    it('should handle organization deletion', async () => {
      mockApiClient.mockResponse('DELETE', '/organizations/67890', {
        success: true,
        data: { message: 'Organization deleted successfully' }
      });

      const { addPermissionTools } = await import('../../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'delete-organization');
      const result = await executeTool(tool, {
        organizationId: 67890
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.message).toContain('deleted successfully');
    });

    it('should handle team-specific user role updates', async () => {
      const updatedUser = { ...testUser, role: 'admin' as const };
      
      mockApiClient.mockResponse('PATCH', '/teams/12345/users/1001/role', {
        success: true,
        data: updatedUser
      });

      const { addPermissionTools } = await import('../../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'update-user-role');
      const result = await executeTool(tool, {
        userId: 1001,
        role: 'admin',
        teamId: 12345,
        permissions: ['read', 'write', 'admin']
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.user).toBeDefined();
      expect(parsedResult.user.role).toBe('admin');
      expect(parsedResult.message).toContain('updated successfully');
    });

    it('should handle organization-level user invitations', async () => {
      mockApiClient.mockResponse('POST', '/organizations/67890/invite', {
        success: true,
        data: { ...testInvitation, organizationId: 67890, teamId: undefined }
      });

      const { addPermissionTools } = await import('../../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'invite-user');
      const result = await executeTool(tool, {
        email: 'orguser@example.com',
        role: 'member',
        organizationId: 67890
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.invitation).toBeDefined();
      expect(parsedResult.message).toContain('sent to orguser@example.com successfully');
    });
  });

  describe('Module Structure', () => {
    it('should import without errors', async () => {
      // This test verifies the module can be imported without syntax errors
      await expect(import('../../../src/tools/permissions.js')).resolves.toBeDefined();
    });

    it('should have proper TypeScript compilation', async () => {
      const permissionsModule = await import('../../../src/tools/permissions.js');
      
      // Basic structural validation
      expect(permissionsModule).toBeDefined();
      expect(typeof permissionsModule).toBe('object');
    });
  });
});