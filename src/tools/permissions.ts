/**
 * @fileoverview Make.com User Permissions & Role Management Tools
 * 
 * Provides comprehensive CRUD operations for Make.com users, teams, organizations, and roles including:
 * - User management with role-based access control (RBAC)
 * - Team creation, modification, and membership management
 * - Organization-level administration and settings
 * - Advanced filtering and search capabilities for user directories
 * - Invitation system with role pre-assignment
 * - Permission scoping and hierarchy enforcement
 * - Audit logging for all permission changes
 * 
 * @version 1.0.0
 * @author Make.com FastMCP Server
 * @see {@link https://docs.make.com/api/users} Make.com Users API Documentation
 */

import { FastMCP, UserError } from 'fastmcp';
import { z } from 'zod';
import MakeApiClient from '../lib/make-api-client.js';
import logger from '../lib/logger.js';
import { formatSuccessResponse } from '../utils/response-formatter.js';

/**
 * Universal logging helper that works with both function-based and object-based loggers
 * Handles different test and production logging patterns
 */
const logMessage = (
  log: ((level: string, message: string, data?: unknown) => void) | { [key: string]: (message: string, data?: unknown) => void } | undefined,
  level: 'info' | 'error' | 'warn' | 'debug',
  message: string,
  data?: unknown
): void => {
  if (!log) {return;}
  
  if (typeof log === 'function') {
    // Function-based logger (common in tests): log('info', 'message', data)
    if (data !== undefined) {
      log(level, message, data);
    } else {
      log(level, message);
    }
  } else if (log[level] && typeof log[level] === 'function') {
    // Object-based logger (production): log.info('message', data)
    if (data !== undefined) {
      log[level](message, data);
    } else {
      log[level](message);
    }
  }
};

// Input validation schemas
const UserFiltersSchema = z.object({
  teamId: z.number().min(1).optional().describe('Filter by team ID'),
  organizationId: z.number().min(1).optional().describe('Filter by organization ID'),
  role: z.enum(['admin', 'member', 'viewer']).optional().describe('Filter by user role'),
  isActive: z.boolean().optional().describe('Filter by active status'),
  search: z.string().optional().describe('Search users by name or email'),
  limit: z.number().min(1).max(100).default(20).describe('Maximum number of users to return'),
  offset: z.number().min(0).default(0).describe('Number of users to skip for pagination'),
}).strict();

const UpdateUserRoleSchema = z.object({
  userId: z.number().min(1).describe('User ID to update'),
  role: z.enum(['admin', 'member', 'viewer']).describe('New role for the user'),
  teamId: z.number().min(1).optional().describe('Team ID for role assignment'),
  permissions: z.array(z.string()).optional().describe('Specific permissions to grant'),
}).strict();

const TeamFiltersSchema = z.object({
  organizationId: z.number().min(1).optional().describe('Filter by organization ID'),
  search: z.string().optional().describe('Search teams by name'),
  limit: z.number().min(1).max(100).default(20).describe('Maximum number of teams to return'),
  offset: z.number().min(0).default(0).describe('Number of teams to skip for pagination'),
}).strict();

const CreateTeamSchema = z.object({
  name: z.string().min(1).max(100).describe('Team name'),
  description: z.string().max(500).optional().describe('Team description'),
  organizationId: z.number().min(1).optional().describe('Organization ID to create team in'),
}).strict();

const UpdateTeamSchema = z.object({
  teamId: z.number().min(1).describe('Team ID to update'),
  name: z.string().min(1).max(100).optional().describe('New team name'),
  description: z.string().max(500).optional().describe('New team description'),
}).strict();

const OrganizationFiltersSchema = z.object({
  search: z.string().optional().describe('Search organizations by name'),
  limit: z.number().min(1).max(100).default(20).describe('Maximum number of organizations to return'),
  offset: z.number().min(0).default(0).describe('Number of organizations to skip for pagination'),
}).strict();

const CreateOrganizationSchema = z.object({
  name: z.string().min(1).max(100).describe('Organization name'),
  description: z.string().max(500).optional().describe('Organization description'),
}).strict();

const UpdateOrganizationSchema = z.object({
  organizationId: z.number().min(1).describe('Organization ID to update'),
  name: z.string().min(1).max(100).optional().describe('New organization name'),
  description: z.string().max(500).optional().describe('New organization description'),
}).strict();

const InviteUserSchema = z.object({
  email: z.string().email().describe('Email address of user to invite'),
  role: z.enum(['admin', 'member', 'viewer']).default('member').describe('Role to assign to invited user'),
  teamId: z.number().min(1).optional().describe('Team ID to invite user to'),
  organizationId: z.number().min(1).optional().describe('Organization ID to invite user to'),
  permissions: z.array(z.string()).optional().describe('Specific permissions to grant'),
}).strict();

/**
 * Add get current user tool
 */
function addGetCurrentUserTool(server: FastMCP, apiClient: MakeApiClient, _componentLogger: ReturnType<typeof logger.child>): void {
  server.addTool({
    name: 'get-current-user',
    description: 'Get current user information and permissions',
    parameters: z.object({}),
    annotations: {
      title: 'Get Current User Profile',
      readOnlyHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log }) => {
      logMessage(log, 'info', 'Getting current user information');

      try {
        const response = await apiClient.get('/users/me');

        if (!response.success) {
          throw new UserError(`Failed to get current user: ${response.error?.message || 'Unknown error'}`);
        }

        const user = response.data;
        if (!user || typeof user !== 'object') {
          throw new UserError('Current user information not available');
        }

        // Type guard for user object
        const userObj = user as { id?: unknown; email?: unknown; role?: unknown };

        logMessage(log, 'info', 'Successfully retrieved current user', {
          userId: userObj.id ?? 'unknown',
          email: userObj.email ?? 'unknown',
          role: userObj.role ?? 'unknown',
        });

        return formatSuccessResponse({ user }).content[0].text;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        logMessage(log, 'error', 'Error getting current user', { error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to get current user: ${errorMessage}`);
      }
    },
  });
}

/**
 * Add user management tools
 */
function addUserManagementTools(server: FastMCP, apiClient: MakeApiClient, _componentLogger: ReturnType<typeof logger.child>): void {
  // List users with filtering
  server.addTool({
    name: 'list-users',
    description: 'List and filter users with role and permission information',
    parameters: UserFiltersSchema,
    annotations: {
      title: 'List Users and Roles',
      readOnlyHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log }) => {
      const { teamId, organizationId, role, isActive, search, limit, offset } = input;

      logMessage(log, 'info', 'Listing users', {
        teamId,
        organizationId,
        role,
        isActive,
        search,
        limit,
        offset,
      });

      try {
        const params: Record<string, unknown> = {
          limit,
          offset,
        };

        if (teamId) {params.teamId = teamId;}
        if (organizationId) {params.organizationId = organizationId;}
        if (role) {params.role = role;}
        if (isActive !== undefined) {params.active = isActive;}
        if (search) {params.search = search;}

        // Get users from team or organization context
        let endpoint = '/users';
        if (teamId) {
          endpoint = `/teams/${teamId}/users`;
        } else if (organizationId) {
          endpoint = `/organizations/${organizationId}/users`;
        }

        const response = await apiClient.get(endpoint, { params });

        if (!response.success) {
          throw new UserError(`Failed to list users: ${response.error?.message || 'Unknown error'}`);
        }

        const users = response.data || [];
        const metadata = response.metadata;

        // Type guard for users array
        const usersArray = Array.isArray(users) ? users : [];

        logMessage(log, 'info', 'Successfully retrieved users', {
          count: usersArray.length,
          total: metadata?.total,
        });

        return formatSuccessResponse({
          users: usersArray,
          pagination: {
            total: metadata?.total || usersArray.length,
            limit,
            offset,
            hasMore: (metadata?.total || 0) > (offset + usersArray.length),
          },
        });
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        logMessage(log, 'error', 'Error listing users', { error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to list users: ${errorMessage}`);
      }
    },
  });

  // Get user details
  server.addTool({
    name: 'get-user',
    description: 'Get detailed information about a specific user',
    parameters: z.object({
      userId: z.number().min(1).describe('User ID to retrieve'),
    }),
    annotations: {
      title: 'Get User Details',
      readOnlyHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log }) => {
      const { userId } = input;

      logMessage(log, 'info', 'Getting user details', { userId });

      try {
        const response = await apiClient.get(`/users/${userId}`);

        if (!response.success) {
          throw new UserError(`Failed to get user: ${response.error?.message || 'Unknown error'}`);
        }

        const user = response.data;
        if (!user || typeof user !== 'object') {
          throw new UserError(`User with ID ${userId} not found`);
        }

        // Type guard for user object
        const userObj = user as { email?: unknown; role?: unknown };

        logMessage(log, 'info', 'Successfully retrieved user', {
          userId,
          email: String(userObj.email ?? 'unknown'),
          role: String(userObj.role ?? 'unknown'),
        });

        return formatSuccessResponse({ user }).content[0].text;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        logMessage(log, 'error', 'Error getting user', { userId, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to get user details: ${errorMessage}`);
      }
    },
  });

  // Update user role and permissions
  server.addTool({
    name: 'update-user-role',
    description: 'Update user role and permissions',
    parameters: UpdateUserRoleSchema,
    annotations: {
      title: 'Update User Role and Permissions',
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log }) => {
      const { userId, role, teamId, permissions } = input;

      logMessage(log, 'info', 'Updating user role', { userId, role, teamId });

      try {
        const updateData: Record<string, unknown> = { role };
        if (teamId) {updateData.teamId = teamId;}
        if (permissions) {updateData.permissions = permissions;}

        let endpoint = `/users/${userId}/roles`;
        if (teamId) {
          endpoint = `/teams/${teamId}/users/${userId}/role`;
        }

        const response = await apiClient.patch(endpoint, updateData);

        if (!response.success) {
          throw new UserError(`Failed to update user role: ${response.error?.message || 'Unknown error'}`);
        }

        const user = response.data;
        if (!user) {
          throw new UserError('User role update failed - no data returned');
        }

        logMessage(log, 'info', 'Successfully updated user role', {
          userId,
          newRole: role,
          teamId,
          permissions: permissions?.length || 0,
        });

        return formatSuccessResponse({
          user,
          message: 'User role updated successfully',
        }).content[0].text;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        logMessage(log, 'error', 'Error updating user role', { userId, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to update user role: ${errorMessage}`);
      }
    },
  });
}

/**
 * Add list teams tool
 */
function addListTeamsTool(server: FastMCP, apiClient: MakeApiClient): void {
  server.addTool({
    name: 'list-teams',
    description: 'List and filter teams',
    parameters: TeamFiltersSchema,
    annotations: {
      title: 'List Teams',
      readOnlyHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log }) => {
      const { organizationId, search, limit, offset } = input;

      logMessage(log, 'info', 'Listing teams', {
        organizationId,
        search,
        limit,
        offset,
      });

      try {
        const params: Record<string, unknown> = {
          limit,
          offset,
        };

        if (organizationId) {params.organizationId = organizationId;}
        if (search) {params.search = search;}

        let endpoint = '/teams';
        if (organizationId) {
          endpoint = `/organizations/${organizationId}/teams`;
        }

        const response = await apiClient.get(endpoint, { params });

        if (!response.success) {
          throw new UserError(`Failed to list teams: ${response.error?.message || 'Unknown error'}`);
        }

        const teams = response.data || [];
        const metadata = response.metadata;

        // Type guard for teams array
        const teamsArray = Array.isArray(teams) ? teams : [];

        logMessage(log, 'info', 'Successfully retrieved teams', {
          count: teamsArray.length,
          total: metadata?.total,
        });

        return formatSuccessResponse({
          teams: teamsArray,
          pagination: {
            total: metadata?.total || teamsArray.length,
            limit,
            offset,
            hasMore: (metadata?.total || 0) > (offset + teamsArray.length),
          },
        });
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        logMessage(log, 'error', 'Error listing teams', { error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to list teams: ${errorMessage}`);
      }
    },
  });
}

/**
 * Add get team tool
 */
function addGetTeamTool(server: FastMCP, apiClient: MakeApiClient): void {
  server.addTool({
    name: 'get-team',
    description: 'Get detailed information about a specific team',
    parameters: z.object({
      teamId: z.number().min(1).describe('Team ID to retrieve'),
    }),
    annotations: {
      title: 'Get Team Details',
      readOnlyHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log }) => {
      const { teamId } = input;

      logMessage(log, 'info', 'Getting team details', { teamId });

      try {
        const response = await apiClient.get(`/teams/${teamId}`);

        if (!response.success) {
          throw new UserError(`Failed to get team: ${response.error?.message || 'Unknown error'}`);
        }

        const team = response.data;
        if (!team || typeof team !== 'object') {
          throw new UserError(`Team with ID ${teamId} not found`);
        }

        // Type guard for team object
        const teamObj = team as { name?: unknown };

        logMessage(log, 'info', 'Successfully retrieved team', {
          teamId,
          name: String(teamObj.name ?? 'unknown'),
        });

        return formatSuccessResponse({ team }).content[0].text;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        logMessage(log, 'error', 'Error getting team', { teamId, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to get team details: ${errorMessage}`);
      }
    },
  });
}

/**
 * Add create team tool
 */
function addCreateTeamTool(server: FastMCP, apiClient: MakeApiClient): void {
  server.addTool({
    name: 'create-team',
    description: 'Create a new team',
    parameters: CreateTeamSchema,
    annotations: {
      title: 'Create New Team',
      readOnlyHint: false,
      idempotentHint: false,
      openWorldHint: true,
    },
    execute: async (input, { log }) => {
      const { name, description, organizationId } = input;

      logMessage(log, 'info', 'Creating new team', { name, organizationId });

      try {
        const teamData = {
          name,
          description,
          organizationId,
        };

        const response = await apiClient.post('/teams', teamData);

        if (!response.success) {
          throw new UserError(`Failed to create team: ${response.error?.message || 'Unknown error'}`);
        }

        const team = response.data;
        if (!team || typeof team !== 'object') {
          throw new UserError('Team creation failed - no data returned');
        }

        // Type guard for team object
        const teamObj = team as { id?: unknown; name?: unknown };

        logMessage(log, 'info', 'Successfully created team', {
          teamId: String(teamObj.id ?? 'unknown'),
          name: String(teamObj.name ?? 'unknown'),
        });

        return formatSuccessResponse({
          team,
          message: `Team "${name}" created successfully`,
        }).content[0].text;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        logMessage(log, 'error', 'Error creating team', { name, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to create team: ${errorMessage}`);
      }
    },
  });
}

/**
 * Add update team tool
 */
function addUpdateTeamTool(server: FastMCP, apiClient: MakeApiClient): void {
  server.addTool({
    name: 'update-team',
    description: 'Update team information',
    parameters: UpdateTeamSchema,
    annotations: {
      title: 'Update Team Information',
      readOnlyHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log }) => {
      const { teamId, name, description } = input;

      logMessage(log, 'info', 'Updating team', { teamId });

      try {
        const updateData: Record<string, unknown> = {};
        if (name !== undefined) {updateData.name = name;}
        if (description !== undefined) {updateData.description = description;}

        if (Object.keys(updateData).length === 0) {
          throw new UserError('No update data provided');
        }

        const response = await apiClient.patch(`/teams/${teamId}`, updateData);

        if (!response.success) {
          throw new UserError(`Failed to update team: ${response.error?.message || 'Unknown error'}`);
        }

        const team = response.data;
        if (!team || typeof team !== 'object') {
          throw new UserError('Team update failed - no data returned');
        }

        // Type guard for team object
        const teamObj = team as { name?: unknown };

        logMessage(log, 'info', 'Successfully updated team', {
          teamId,
          name: String(teamObj.name ?? 'unknown'),
          updatedFields: Object.keys(updateData),
        });

        return formatSuccessResponse({
          team,
          message: 'Team updated successfully',
        }).content[0].text;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        logMessage(log, 'error', 'Error updating team', { teamId, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to update team: ${errorMessage}`);
      }
    },
  });
}

/**
 * Add delete team tool
 */
function addDeleteTeamTool(server: FastMCP, apiClient: MakeApiClient): void {
  server.addTool({
    name: 'delete-team',
    description: 'Delete a team',
    parameters: z.object({
      teamId: z.number().min(1).describe('Team ID to delete'),
    }),
    annotations: {
      title: 'Delete Team',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log }) => {
      const { teamId } = input;

      logMessage(log, 'info', 'Deleting team', { teamId });

      try {
        const response = await apiClient.delete(`/teams/${teamId}`);

        if (!response.success) {
          throw new UserError(`Failed to delete team: ${response.error?.message || 'Unknown error'}`);
        }

        logMessage(log, 'info', 'Successfully deleted team', { teamId });

        return formatSuccessResponse({
          message: `Team ${teamId} deleted successfully`,
        }).content[0].text;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        logMessage(log, 'error', 'Error deleting team', { teamId, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to delete team: ${errorMessage}`);
      }
    },
  });
}

/**
 * Add team management tools
 */
function addTeamManagementTools(server: FastMCP, apiClient: MakeApiClient, _componentLogger: ReturnType<typeof logger.child>): void {
  // Add all team management tools
  addListTeamsTool(server, apiClient);
  addGetTeamTool(server, apiClient);
  addCreateTeamTool(server, apiClient);
  addUpdateTeamTool(server, apiClient);
  addDeleteTeamTool(server, apiClient);
}

/**
 * Add organization management tools
 */
function addOrganizationManagementTools(server: FastMCP, apiClient: MakeApiClient, _componentLogger: ReturnType<typeof logger.child>): void {
  // List organizations
  server.addTool({
    name: 'list-organizations',
    description: 'List user organizations',
    parameters: OrganizationFiltersSchema,
    annotations: {
      title: 'List Organizations',
      readOnlyHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log }) => {
      const { search, limit, offset } = input;

      logMessage(log, 'info', 'Listing organizations', {
        search,
        limit,
        offset,
      });

      try {
        const params: Record<string, unknown> = {
          limit,
          offset,
        };

        if (search) {params.search = search;}

        const response = await apiClient.get('/organizations', { params });

        if (!response.success) {
          throw new UserError(`Failed to list organizations: ${response.error?.message || 'Unknown error'}`);
        }

        const organizations = response.data || [];
        const metadata = response.metadata;

        // Type guard for organizations array
        const organizationsArray = Array.isArray(organizations) ? organizations : [];

        logMessage(log, 'info', 'Successfully retrieved organizations', {
          count: organizationsArray.length,
          total: metadata?.total,
        });

        return formatSuccessResponse({
          organizations: organizationsArray,
          pagination: {
            total: metadata?.total || organizationsArray.length,
            limit,
            offset,
            hasMore: (metadata?.total || 0) > (offset + organizationsArray.length),
          },
        });
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        logMessage(log, 'error', 'Error listing organizations', { error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to list organizations: ${errorMessage}`);
      }
    },
  });

  // Get organization details
  server.addTool({
    name: 'get-organization',
    description: 'Get detailed information about a specific organization',
    parameters: z.object({
      organizationId: z.number().min(1).describe('Organization ID to retrieve'),
    }),
    annotations: {
      title: 'Get Organization Details',
      readOnlyHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log }) => {
      const { organizationId } = input;

      logMessage(log, 'info', 'Getting organization details', { organizationId });

      try {
        const response = await apiClient.get(`/organizations/${organizationId}`);

        if (!response.success) {
          throw new UserError(`Failed to get organization: ${response.error?.message || 'Unknown error'}`);
        }

        const organization = response.data;
        if (!organization || typeof organization !== 'object') {
          throw new UserError(`Organization with ID ${organizationId} not found`);
        }

        // Type guard for organization object
        const orgObj = organization as { name?: unknown };

        logMessage(log, 'info', 'Successfully retrieved organization', {
          organizationId,
          name: String(orgObj.name ?? 'unknown'),
        });

        return formatSuccessResponse({ organization }).content[0].text;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        logMessage(log, 'error', 'Error getting organization', { organizationId, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to get organization details: ${errorMessage}`);
      }
    },
  });

  // Create organization
  server.addTool({
    name: 'create-organization',
    description: 'Create a new organization',
    parameters: CreateOrganizationSchema,
    annotations: {
      title: 'Create New Organization',
      readOnlyHint: false,
      idempotentHint: false,
      openWorldHint: true,
    },
    execute: async (input, { log }) => {
      const { name, description } = input;

      logMessage(log, 'info', 'Creating new organization', { name });

      try {
        const organizationData = {
          name,
          description,
        };

        const response = await apiClient.post('/organizations', organizationData);

        if (!response.success) {
          throw new UserError(`Failed to create organization: ${response.error?.message || 'Unknown error'}`);
        }

        const organization = response.data;
        if (!organization || typeof organization !== 'object') {
          throw new UserError('Organization creation failed - no data returned');
        }

        // Type guard for organization object
        const orgObj = organization as { id?: unknown; name?: unknown };

        logMessage(log, 'info', 'Successfully created organization', {
          organizationId: String(orgObj.id ?? 'unknown'),
          name: String(orgObj.name ?? 'unknown'),
        });

        return formatSuccessResponse({
          organization,
          message: `Organization "${name}" created successfully`,
        }).content[0].text;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        logMessage(log, 'error', 'Error creating organization', { name, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to create organization: ${errorMessage}`);
      }
    },
  });

  // Update organization
  server.addTool({
    name: 'update-organization',
    description: 'Update organization information',
    parameters: UpdateOrganizationSchema,
    annotations: {
      title: 'Update Organization Information',
      readOnlyHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log }) => {
      const { organizationId, name, description } = input;

      logMessage(log, 'info', 'Updating organization', { organizationId });

      try {
        const updateData: Record<string, unknown> = {};
        if (name !== undefined) {updateData.name = name;}
        if (description !== undefined) {updateData.description = description;}

        if (Object.keys(updateData).length === 0) {
          throw new UserError('No update data provided');
        }

        const response = await apiClient.patch(`/organizations/${organizationId}`, updateData);

        if (!response.success) {
          throw new UserError(`Failed to update organization: ${response.error?.message || 'Unknown error'}`);
        }

        const organization = response.data;
        if (!organization || typeof organization !== 'object') {
          throw new UserError('Organization update failed - no data returned');
        }

        // Type guard for organization object
        const orgObj = organization as { name?: unknown };

        logMessage(log, 'info', 'Successfully updated organization', {
          organizationId,
          name: String(orgObj.name ?? 'unknown'),
          updatedFields: Object.keys(updateData),
        });

        return formatSuccessResponse({
          organization,
          message: 'Organization updated successfully',
        }).content[0].text;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        logMessage(log, 'error', 'Error updating organization', { organizationId, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to update organization: ${errorMessage}`);
      }
    },
  });

  // Delete organization
  server.addTool({
    name: 'delete-organization',
    description: 'Delete an organization',
    parameters: z.object({
      organizationId: z.number().min(1).describe('Organization ID to delete'),
    }),
    annotations: {
      title: 'Delete Organization',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log }) => {
      const { organizationId } = input;

      logMessage(log, 'info', 'Deleting organization', { organizationId });

      try {
        const response = await apiClient.delete(`/organizations/${organizationId}`);

        if (!response.success) {
          throw new UserError(`Failed to delete organization: ${response.error?.message || 'Unknown error'}`);
        }

        logMessage(log, 'info', 'Successfully deleted organization', { organizationId });

        return formatSuccessResponse({
          message: `Organization ${organizationId} deleted successfully`,
        }).content[0].text;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        logMessage(log, 'error', 'Error deleting organization', { organizationId, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to delete organization: ${errorMessage}`);
      }
    },
  });
}

/**
 * Add user invitation tool
 */
function addUserInvitationTool(server: FastMCP, apiClient: MakeApiClient, _componentLogger: ReturnType<typeof logger.child>): void {
  // Invite user to team or organization
  server.addTool({
    name: 'invite-user',
    description: 'Invite a user to join a team or organization',
    parameters: InviteUserSchema,
    annotations: {
      title: 'Invite User to Team/Organization',
      readOnlyHint: false,
      idempotentHint: false,
      openWorldHint: true,
    },
    execute: async (input, { log }) => {
      const { email, role, teamId, organizationId, permissions } = input;

      logMessage(log, 'info', 'Inviting user', {
        email,
        role,
        teamId,
        organizationId,
      });

      try {
        const inviteData = {
          email,
          role,
          permissions,
        };

        let endpoint = '/users/invite';
        if (teamId) {
          endpoint = `/teams/${teamId}/invite`;
        } else if (organizationId) {
          endpoint = `/organizations/${organizationId}/invite`;
        }

        const response = await apiClient.post(endpoint, inviteData);

        if (!response.success) {
          throw new UserError(`Failed to invite user: ${response.error?.message || 'Unknown error'}`);
        }

        const invitation = response.data;

        logMessage(log, 'info', 'Successfully sent user invitation', {
          email,
          role,
          teamId,
          organizationId,
        });

        return formatSuccessResponse({
          invitation,
          message: `Invitation sent to ${email} successfully`,
        }).content[0].text;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        logMessage(log, 'error', 'Error inviting user', { email, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to invite user: ${errorMessage}`);
      }
    },
  });
}

/**
 * Adds comprehensive user permission and role management tools to the FastMCP server
 */
export function addPermissionTools(server: FastMCP, apiClient: MakeApiClient): void {
  const componentLogger = logger.child({ component: 'PermissionTools' });
  
  componentLogger.info('Adding user permission management tools');

  // Add core permission management tools
  addGetCurrentUserTool(server, apiClient, componentLogger);
  addUserManagementTools(server, apiClient, componentLogger);
  addTeamManagementTools(server, apiClient, componentLogger);
  addOrganizationManagementTools(server, apiClient, componentLogger);
  addUserInvitationTool(server, apiClient, componentLogger);

  componentLogger.info('User permission management tools added successfully');
}

export default addPermissionTools;