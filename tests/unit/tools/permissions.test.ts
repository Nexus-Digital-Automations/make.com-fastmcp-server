/**
 * Unit tests for permissions management tools
 * Tests user management, role assignments, team operations, organization management, and invitation system
 */

import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { UserError } from 'fastmcp';
import { MockMakeApiClient } from '../../mocks/make-api-client.mock.js';
import { 
  createMockServer, 
  findTool, 
  executeTool, 
  expectToolCall,
  expectProgressReported,
  expectValidZodParse,
  expectInvalidZodParse
} from '../../utils/test-helpers.js';
import { testUser, testTeam, testOrganization, testErrors } from '../../fixtures/test-data.js';

describe('Permissions Management Tools - Comprehensive Test Suite', () => {
  let mockServer: any;
  let mockApiClient: MockMakeApiClient;
  let mockTool: jest.MockedFunction<any>;
  let mockLog: jest.MockedFunction<any>;
  let mockReportProgress: jest.MockedFunction<any>;

  const testCurrentUser = {
    id: 1,
    email: 'test@example.com',
    name: 'Test User',
    role: 'admin',
    teams: [{ id: 1, name: 'Test Team', role: 'admin' }],
    organizations: [{ id: 1, name: 'Test Org', role: 'admin' }],
    permissions: ['user:read', 'user:write', 'team:admin'],
    preferences: { timezone: 'UTC', language: 'en' },
    lastLoginAt: '2024-01-01T12:00:00Z',
    createdAt: '2023-01-01T12:00:00Z'
  };

  const testUsersList = [
    { id: 1, email: 'user1@example.com', name: 'User One', role: 'admin', isActive: true },
    { id: 2, email: 'user2@example.com', name: 'User Two', role: 'member', isActive: true },
    { id: 3, email: 'user3@example.com', name: 'User Three', role: 'viewer', isActive: false }
  ];

  beforeEach(() => {
    const serverSetup = createMockServer();
    mockServer = serverSetup.server;
    mockTool = serverSetup.mockTool;
    mockApiClient = new MockMakeApiClient();
    mockLog = jest.fn();
    mockReportProgress = jest.fn();
  });

  afterEach(() => {
    jest.clearAllMocks();
    mockApiClient.reset();
  });

  describe('Tool Registration and Configuration', () => {
    it('should register all permission management tools with correct configuration', async () => {
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
        expect(tool.description).toBeDefined();
        expect(tool.parameters).toBeDefined();
      });
    });
  });

  describe('User Management Tools', () => {
    describe('get-current-user tool', () => {
      it('should get current user information successfully', async () => {
        mockApiClient.mockResponse('GET', '/users/me', {
          success: true,
          data: testCurrentUser
        });

        const { addPermissionTools } = await import('../../../src/tools/permissions.js');
        addPermissionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-current-user');
        const result = await executeTool(tool, {}, { log: mockLog });
        
        expect(result).toContain(testCurrentUser.email);
        expect(result).toContain(testCurrentUser.role);
        expect(result).toContain('Test User');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/users/me');
        expect(calls[0].method).toBe('GET');
      });

      it('should handle authentication errors for current user', async () => {
        mockApiClient.mockResponse('GET', '/users/me', {
          success: false,
          error: testErrors.authentication
        });

        const { addPermissionTools } = await import('../../../src/tools/permissions.js');
        addPermissionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-current-user');
        
        await expect(executeTool(tool, {}, { log: mockLog }))
          .rejects.toThrow(UserError);
        await expect(executeTool(tool, {}, { log: mockLog }))
          .rejects.toThrow('Failed to get current user');
      });

      it('should handle missing user data', async () => {
        mockApiClient.mockResponse('GET', '/users/me', {
          success: true,
          data: null
        });

        const { addPermissionTools } = await import('../../../src/tools/permissions.js');
        addPermissionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-current-user');
        
        await expect(executeTool(tool, {}, { log: mockLog }))
          .rejects.toThrow('Current user information not available');
      });
    });

    describe('list-users tool', () => {
      it('should list users with default filters', async () => {
        mockApiClient.mockResponse('GET', '/users', {
          success: true,
          data: testUsersList,
          metadata: { total: 3 }
        });

        const { addPermissionTools } = await import('../../../src/tools/permissions.js');
        addPermissionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-users');
        const result = await executeTool(tool, {}, { log: mockLog });
        
        expect(result).toContain('user1@example.com');
        expect(result).toContain('user2@example.com'); 
        expect(result).toContain('"total": 3');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].params).toEqual({ limit: 20, offset: 0 });
      });

      it('should filter users by team ID', async () => {
        const teamId = 123;
        mockApiClient.mockResponse('GET', `/teams/${teamId}/users`, {
          success: true,
          data: testUsersList.slice(0, 2),
          metadata: { total: 2 }
        });

        const { addPermissionTools } = await import('../../../src/tools/permissions.js');
        addPermissionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-users');
        const result = await executeTool(tool, { teamId }, { log: mockLog });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe(`/teams/${teamId}/users`);
        expect(calls[0].params.teamId).toBe(teamId);
      });

      it('should filter users by organization ID', async () => {
        const organizationId = 456;
        mockApiClient.mockResponse('GET', `/organizations/${organizationId}/users`, {
          success: true,
          data: testUsersList,
          metadata: { total: 3 }
        });

        const { addPermissionTools } = await import('../../../src/tools/permissions.js');
        addPermissionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-users');
        await executeTool(tool, { organizationId }, { log: mockLog });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe(`/organizations/${organizationId}/users`);
      });

      it('should apply multiple filters correctly', async () => {
        mockApiClient.mockResponse('GET', '/users', {
          success: true,
          data: testUsersList.filter(u => u.role === 'admin'),
          metadata: { total: 1 }
        });

        const { addPermissionTools } = await import('../../../src/tools/permissions.js');
        addPermissionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-users');
        await executeTool(tool, { 
          role: 'admin', 
          isActive: true, 
          search: 'user', 
          limit: 10 
        }, { log: mockLog });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].params).toEqual({
          limit: 10,
          offset: 0,
          role: 'admin',
          active: true,
          search: 'user'
        });
      });

      it('should validate input parameters', async () => {
        const { addPermissionTools } = await import('../../../src/tools/permissions.js');
        addPermissionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-users');
        
        // Test invalid role
        await expectInvalidZodParse(() => 
          executeTool(tool, { role: 'invalid-role' }, { log: mockLog })
        );
        
        // Test invalid limit
        await expectInvalidZodParse(() => 
          executeTool(tool, { limit: 0 }, { log: mockLog })
        );
        
        // Test invalid offset
        await expectInvalidZodParse(() => 
          executeTool(tool, { offset: -1 }, { log: mockLog })
        );
      });
    });

    describe('get-user tool', () => {
      it('should get user details successfully', async () => {
        const userId = 123;
        mockApiClient.mockResponse('GET', `/users/${userId}`, {
          success: true,
          data: testCurrentUser
        });

        const { addPermissionTools } = await import('../../../src/tools/permissions.js');
        addPermissionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-user');
        const result = await executeTool(tool, { userId }, { log: mockLog });
        
        expect(result).toContain(testCurrentUser.email);
        expect(result).toContain(testCurrentUser.role);
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe(`/users/${userId}`);
      });

      it('should handle user not found', async () => {
        const userId = 999;
        mockApiClient.mockResponse('GET', `/users/${userId}`, {
          success: true,
          data: null
        });

        const { addPermissionTools } = await import('../../../src/tools/permissions.js');
        addPermissionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-user');
        
        await expect(executeTool(tool, { userId }, { log: mockLog }))
          .rejects.toThrow(`User with ID ${userId} not found`);
      });
    });

    describe('update-user-role tool', () => {
      it('should update user role successfully', async () => {
        const userId = 123;
        const updatedUser = { ...testCurrentUser, role: 'member' };
        
        mockApiClient.mockResponse('PATCH', `/users/${userId}/roles`, {
          success: true,
          data: updatedUser
        });

        const { addPermissionTools } = await import('../../../src/tools/permissions.js');
        addPermissionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'update-user-role');
        const result = await executeTool(tool, { 
          userId, 
          role: 'member' 
        }, { log: mockLog });
        
        expect(result).toContain('member');
        expect(result).toContain('User role updated successfully');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe(`/users/${userId}/roles`);
        expect(calls[0].data).toEqual({ role: 'member' });
      });

      it('should update team-specific user role', async () => {
        const userId = 123;
        const teamId = 456;
        
        mockApiClient.mockResponse('PATCH', `/teams/${teamId}/users/${userId}/role`, {
          success: true,
          data: testCurrentUser
        });

        const { addPermissionTools } = await import('../../../src/tools/permissions.js');
        addPermissionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'update-user-role');
        await executeTool(tool, { 
          userId, 
          role: 'admin', 
          teamId,
          permissions: ['team:read', 'team:write']
        }, { log: mockLog });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe(`/teams/${teamId}/users/${userId}/role`);
        expect(calls[0].data).toEqual({
          role: 'admin',
          teamId: 456,
          permissions: ['team:read', 'team:write']
        });
      });

      it('should validate role parameter', async () => {
        const { addPermissionTools } = await import('../../../src/tools/permissions.js');
        addPermissionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'update-user-role');
        
        await expectInvalidZodParse(() => 
          executeTool(tool, { userId: 123, role: 'invalid-role' }, { log: mockLog })
        );
      });
    });
  });

  describe('Team Management Tools', () => {
    describe('list-teams tool', () => {
      it('should list teams with default filters', async () => {
        const teamsList = [testTeam, { ...testTeam, id: 2, name: 'Team Two' }];
        
        mockApiClient.mockResponse('GET', '/teams', {
          success: true,
          data: teamsList,
          metadata: { total: 2 }
        });

        const { addPermissionTools } = await import('../../../src/tools/permissions.js');
        addPermissionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-teams');
        const result = await executeTool(tool, {}, { log: mockLog });
        
        expect(result).toContain(testTeam.name);
        expect(result).toContain('Team Two');
        expect(result).toContain('"total": 2');
      });

      it('should filter teams by organization', async () => {
        const organizationId = 123;
        
        mockApiClient.mockResponse('GET', `/organizations/${organizationId}/teams`, {
          success: true,
          data: [testTeam],
          metadata: { total: 1 }
        });

        const { addPermissionTools } = await import('../../../src/tools/permissions.js');
        addPermissionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-teams');
        await executeTool(tool, { organizationId }, { log: mockLog });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe(`/organizations/${organizationId}/teams`);
      });
    });

    describe('create-team tool', () => {
      it('should create team successfully', async () => {
        const newTeam = { ...testTeam, id: 999 };
        
        mockApiClient.mockResponse('POST', '/teams', {
          success: true,
          data: newTeam
        });

        const { addPermissionTools } = await import('../../../src/tools/permissions.js');
        addPermissionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-team');
        const result = await executeTool(tool, { 
          name: 'New Team',
          description: 'A new test team',
          organizationId: 123
        }, { log: mockLog });
        
        expect(result).toContain('New Team');
        expect(result).toContain('created successfully');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].data).toEqual({
          name: 'New Team',
          description: 'A new test team',
          organizationId: 123
        });
      });

      it('should validate team name length', async () => {
        const { addPermissionTools } = await import('../../../src/tools/permissions.js');
        addPermissionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-team');
        
        await expectInvalidZodParse(() => 
          executeTool(tool, { name: '' }, { log: mockLog })
        );
        
        await expectInvalidZodParse(() => 
          executeTool(tool, { name: 'a'.repeat(101) }, { log: mockLog })
        );
      });
    });

    describe('update-team tool', () => {
      it('should update team successfully', async () => {
        const teamId = 123;
        const updatedTeam = { ...testTeam, name: 'Updated Team' };
        
        mockApiClient.mockResponse('PATCH', `/teams/${teamId}`, {
          success: true,
          data: updatedTeam
        });

        const { addPermissionTools } = await import('../../../src/tools/permissions.js');
        addPermissionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'update-team');
        const result = await executeTool(tool, { 
          teamId, 
          name: 'Updated Team',
          description: 'Updated description'
        }, { log: mockLog });
        
        expect(result).toContain('Updated Team');
        expect(result).toContain('updated successfully');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].data).toEqual({
          name: 'Updated Team',
          description: 'Updated description'
        });
      });

      it('should require at least one update field', async () => {
        const { addPermissionTools } = await import('../../../src/tools/permissions.js');
        addPermissionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'update-team');
        
        await expect(executeTool(tool, { teamId: 123 }, { log: mockLog }))
          .rejects.toThrow('No update data provided');
      });
    });

    describe('delete-team tool', () => {
      it('should delete team successfully', async () => {
        const teamId = 123;
        
        mockApiClient.mockResponse('DELETE', `/teams/${teamId}`, {
          success: true,
          data: {}
        });

        const { addPermissionTools } = await import('../../../src/tools/permissions.js');
        addPermissionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'delete-team');
        const result = await executeTool(tool, { teamId }, { log: mockLog });
        
        expect(result).toContain('deleted successfully');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe(`/teams/${teamId}`);
        expect(calls[0].method).toBe('DELETE');
      });
    });
  });

  describe('Organization Management Tools', () => {
    describe('list-organizations tool', () => {
      it('should list organizations successfully', async () => {
        const orgsList = [testOrganization, { ...testOrganization, id: 2, name: 'Org Two' }];
        
        mockApiClient.mockResponse('GET', '/organizations', {
          success: true,
          data: orgsList,
          metadata: { total: 2 }
        });

        const { addPermissionTools } = await import('../../../src/tools/permissions.js');
        addPermissionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-organizations');
        const result = await executeTool(tool, {}, { log: mockLog });
        
        expect(result).toContain(testOrganization.name);
        expect(result).toContain('Org Two');
        expect(result).toContain('"total": 2');
      });

      it('should apply search filter', async () => {
        mockApiClient.mockResponse('GET', '/organizations', {
          success: true,
          data: [testOrganization],
          metadata: { total: 1 }
        });

        const { addPermissionTools } = await import('../../../src/tools/permissions.js');
        addPermissionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-organizations');
        await executeTool(tool, { search: 'test' }, { log: mockLog });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].params.search).toBe('test');
      });
    });

    describe('create-organization tool', () => {
      it('should create organization successfully', async () => {
        const newOrg = { ...testOrganization, id: 999, name: 'New Organization' };
        
        mockApiClient.mockResponse('POST', '/organizations', {
          success: true,
          data: newOrg
        });

        const { addPermissionTools } = await import('../../../src/tools/permissions.js');
        addPermissionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-organization');
        const result = await executeTool(tool, { 
          name: 'New Organization',
          description: 'A new test organization'
        }, { log: mockLog });
        
        expect(result).toContain('New Organization');
        expect(result).toContain('created successfully');
      });
    });
  });

  describe('User Invitation Tools', () => {
    describe('invite-user tool', () => {
      it('should invite user to organization successfully', async () => {
        const invitation = {
          id: 123,
          email: 'newuser@example.com',
          role: 'member',
          status: 'sent',
          expiresAt: '2024-02-01T12:00:00Z'
        };
        
        mockApiClient.mockResponse('POST', '/organizations/456/invite', {
          success: true,
          data: invitation
        });

        const { addPermissionTools } = await import('../../../src/tools/permissions.js');
        addPermissionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'invite-user');
        const result = await executeTool(tool, { 
          email: 'newuser@example.com',
          role: 'member',
          organizationId: 456,
          permissions: ['read:scenarios']
        }, { log: mockLog });
        
        expect(result).toContain('newuser@example.com');
        expect(result).toContain('successfully');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/organizations/456/invite');
        expect(calls[0].data).toEqual({
          email: 'newuser@example.com',
          role: 'member',
          permissions: ['read:scenarios']
        });
      });

      it('should invite user to team successfully', async () => {
        const invitation = {
          id: 124,
          email: 'teamuser@example.com',
          role: 'admin',
          status: 'sent'
        };
        
        mockApiClient.mockResponse('POST', '/teams/789/invite', {
          success: true,
          data: invitation
        });

        const { addPermissionTools } = await import('../../../src/tools/permissions.js');
        addPermissionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'invite-user');
        await executeTool(tool, { 
          email: 'teamuser@example.com',
          role: 'admin',
          teamId: 789
        }, { log: mockLog });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/teams/789/invite');
      });

      it('should validate email format', async () => {
        const { addPermissionTools } = await import('../../../src/tools/permissions.js');
        addPermissionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'invite-user');
        
        await expectInvalidZodParse(() => 
          executeTool(tool, { email: 'invalid-email' }, { log: mockLog })
        );
      });
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle API errors gracefully', async () => {
      mockApiClient.mockResponse('GET', '/users/me', {
        success: false,
        error: testErrors.serverError
      });

      const { addPermissionTools } = await import('../../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-current-user');
      
      await expect(executeTool(tool, {}, { log: mockLog }))
        .rejects.toThrow(UserError);
    });

    it('should handle network errors', async () => {
      mockApiClient.mockError('GET', '/users/me', new Error('Network error'));

      const { addPermissionTools } = await import('../../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-current-user');
      
      await expect(executeTool(tool, {}, { log: mockLog }))
        .rejects.toThrow('Failed to get current user: Network error');
    });

    it('should log operations correctly', async () => {
      mockApiClient.mockResponse('GET', '/users/me', {
        success: true,
        data: testCurrentUser
      });

      const { addPermissionTools } = await import('../../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-current-user');
      await executeTool(tool, {}, { log: mockLog });
      
      expect(mockLog).toHaveBeenCalledWith(
        'info',
        'Getting current user information'
      );
      expect(mockLog).toHaveBeenCalledWith(
        'info',
        'Successfully retrieved current user',
        expect.objectContaining({
          userId: testCurrentUser.id,
          email: testCurrentUser.email,
          role: testCurrentUser.role
        })
      );
    });
  });

  describe('Input Validation', () => {
    it('should validate user ID parameters', async () => {
      const { addPermissionTools } = await import('../../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-user');
      
      await expectInvalidZodParse(() => 
        executeTool(tool, { userId: 0 }, { log: mockLog })
      );
      
      await expectInvalidZodParse(() => 
        executeTool(tool, { userId: -1 }, { log: mockLog })
      );
    });

    it('should validate pagination parameters', async () => {
      const { addPermissionTools } = await import('../../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-users');
      
      await expectInvalidZodParse(() => 
        executeTool(tool, { limit: 101 }, { log: mockLog })
      );
      
      await expectInvalidZodParse(() => 
        executeTool(tool, { offset: -1 }, { log: mockLog })
      );
    });

    it('should validate string length constraints', async () => {
      const { addPermissionTools } = await import('../../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-team');
      
      await expectInvalidZodParse(() => 
        executeTool(tool, { name: 'a'.repeat(101) }, { log: mockLog })
      );
      
      await expectInvalidZodParse(() => 
        executeTool(tool, { description: 'a'.repeat(501) }, { log: mockLog })
      );
    });
  });
});