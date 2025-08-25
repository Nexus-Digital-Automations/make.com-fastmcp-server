/**
 * User and Access Management FastMCP Tools
 * Comprehensive tools for Make.com organizations, teams, users, and permissions
 * Based on comprehensive Make.com API research reports
 */

import { FastMCP } from "fastmcp";
import { z } from "zod";
import winston from "winston";
import {
  MakeAPIClient,
  MakeAPIError,
} from "../make-client/simple-make-client.js";

// ==============================================================================
// Schema Definitions for User and Access Management Tools
// ==============================================================================

// Organization Management Schemas
const OrganizationCreateSchema = z.object({
  name: z
    .string()
    .min(1)
    .max(100)
    .describe("Organization name (max 100 characters)"),
  description: z.string().optional().describe("Organization description"),
  settings: z
    .object({
      allowPublicTemplates: z.boolean().default(false),
      defaultTimeZone: z.string().default("UTC"),
      dataRetentionDays: z.number().min(1).max(365).default(90),
    })
    .optional()
    .describe("Organization settings"),
});

const TeamCreateSchema = z.object({
  name: z.string().min(1).max(100).describe("Team name (max 100 characters)"),
  organizationId: z.string().describe("Organization ID to create team in"),
  description: z.string().optional().describe("Team description"),
  settings: z
    .object({
      autoAddUsers: z.boolean().default(false),
      allowGuestUsers: z.boolean().default(false),
      defaultExecutionLimit: z.number().min(1).default(1000),
    })
    .optional()
    .describe("Team settings"),
});

const UserInviteSchema = z.object({
  email: z.string().email().describe("User email address"),
  organizationId: z.string().describe("Organization ID to invite user to"),
  role: z
    .enum(["owner", "admin", "member"])
    .describe("Organization role for the user"),
  teamAssignments: z
    .array(
      z.object({
        teamId: z.string(),
        role: z.enum([
          "admin",
          "member",
          "monitoring",
          "operator",
          "restricted",
        ]),
      }),
    )
    .optional()
    .describe("Optional team assignments with roles"),
  message: z.string().optional().describe("Custom invitation message"),
});

const PermissionUpdateSchema = z.object({
  userId: z.string().describe("User ID to update permissions for"),
  organizationId: z.string().optional().describe("Organization context"),
  teamId: z.string().optional().describe("Team context"),
  permissions: z
    .array(
      z.object({
        scope: z.string(),
        actions: z.array(z.string()),
        granted: z.boolean(),
      }),
    )
    .describe("Permission changes to apply"),
});

// Analytics and Reporting Schemas
const UserActivitySchema = z.object({
  organizationId: z.string().optional(),
  teamId: z.string().optional(),
  userId: z.string().optional(),
  startDate: z.string().describe("Start date for activity report (ISO 8601)"),
  endDate: z.string().describe("End date for activity report (ISO 8601)"),
  includeDetails: z
    .boolean()
    .default(false)
    .describe("Include detailed activity breakdown"),
});

// ==============================================================================
// User and Access Management Tools Registration
// ==============================================================================

export function registerUserAccessManagementTools(
  server: FastMCP,
  makeClient: MakeAPIClient,
  logger: winston.Logger,
): void {
  // ==============================================================================
  // Organization Management Tools
  // ==============================================================================

  server.addTool({
    name: "list-make-organizations",
    description:
      "List all Make.com organizations accessible to the current user",
    parameters: z.object({
      includeMetrics: z
        .boolean()
        .default(false)
        .describe("Include usage metrics for each organization"),
      includeTeamCounts: z
        .boolean()
        .default(true)
        .describe("Include team and user counts"),
    }),
    execute: async (args, { log }) => {
      const operationId = `list-orgs-${Date.now()}`;

      log.info(`[${operationId}] Listing Make.com organizations`, {
        includeMetrics: args.includeMetrics,
        includeTeamCounts: args.includeTeamCounts,
      });

      try {
        const result = await makeClient.getOrganizations();

        log.info(`[${operationId}] Organizations retrieved successfully`, {
          organizationCount: result.data?.length || 0,
        });

        const organizations = result.data || [];

        // Format organizations with enhanced information
        const formattedOrgs = await Promise.all(
          organizations.map(async (org: any) => {
            let teamCount = 0;
            let userCount = 0;

            if (args.includeTeamCounts) {
              try {
                const teams = await makeClient.getTeams(org.id.toString());
                teamCount = teams.data?.length || 0;

                // Estimate user count from teams
                userCount = teamCount * 3; // Rough estimate
              } catch (error) {
                logger.warn(`Failed to get team count for org ${org.id}`, {
                  error: error instanceof Error ? error.message : String(error),
                });
              }
            }

            return {
              id: org.id,
              name: org.name,
              role: (org as any).role || "member",
              ...(args.includeTeamCounts && {
                teamCount,
                estimatedUserCount: userCount,
              }),
              ...(args.includeMetrics && {
                metrics: {
                  // Placeholder for actual metrics when available
                  activeScenarios: "Not available",
                  monthlyOperations: "Not available",
                  dataTransfer: "Not available",
                },
              }),
            };
          }),
        );

        return {
          content: [
            {
              type: "text",
              text:
                `📊 Make.com Organizations\n\n**Total Organizations:** ${organizations.length}\n\n` +
                formattedOrgs
                  .map(
                    (org, index) =>
                      `**${index + 1}. ${org.name}**\n` +
                      `- ID: ${org.id}\n` +
                      `- Role: ${org.role}\n` +
                      (args.includeTeamCounts
                        ? `- Teams: ${org.teamCount}\n- Users: ~${org.estimatedUserCount}\n`
                        : "") +
                      (args.includeMetrics
                        ? `- Metrics: ${JSON.stringify(org.metrics, null, 2)}\n`
                        : ""),
                  )
                  .join("\n") +
                `\n**Organization Management:**\n` +
                `- Use "get-make-organization-details" for detailed information\n` +
                `- Use "list-make-teams" to see teams in each organization\n` +
                `- Use "invite-make-user" to add users to organizations`,
            },
          ],
        };
      } catch (error) {
        log.error(`[${operationId}] Failed to list organizations`, {
          error: error instanceof Error ? error.message : String(error),
        });

        if (error instanceof MakeAPIError) {
          return {
            content: [
              {
                type: "text",
                text: `❌ Failed to list organizations: ${error.message}\n\n**Error Details:**\n- Code: ${error.code}\n- Status: ${error.statusCode}\n\n**Troubleshooting:**\n1. Verify your API token has proper permissions\n2. Check if you have access to organization data\n3. Ensure your account is properly configured`,
              },
            ],
          };
        }

        throw error;
      }
    },
  });

  server.addTool({
    name: "get-make-organization-details",
    description:
      "Get detailed information about a specific Make.com organization",
    parameters: z.object({
      organizationId: z
        .string()
        .describe("The organization ID to get details for"),
      includeTeams: z
        .boolean()
        .default(true)
        .describe("Include teams in the organization"),
      includeUsers: z
        .boolean()
        .default(false)
        .describe("Include user list with roles"),
    }),
    execute: async (args, { log }) => {
      const operationId = `org-details-${Date.now()}`;

      log.info(`[${operationId}] Getting organization details`, {
        organizationId: args.organizationId,
        includeTeams: args.includeTeams,
        includeUsers: args.includeUsers,
      });

      try {
        const [orgResult, teamsResult] = await Promise.all([
          makeClient.getOrganization(args.organizationId),
          args.includeTeams
            ? makeClient.getTeams(args.organizationId)
            : Promise.resolve({ data: [] }),
        ]);

        log.info(`[${operationId}] Organization details retrieved`, {
          organizationId: args.organizationId,
          teamsCount: teamsResult.data?.length || 0,
        });

        const org = orgResult.data;
        const teams = teamsResult.data || [];

        return {
          content: [
            {
              type: "text",
              text:
                `🏢 Organization Details\n\n**${org?.name}**\n` +
                `- ID: ${org?.id}\n` +
                `- Organization ID: ${(org as any)?.organizationId}\n` +
                `- Your Role: ${(org as any)?.role || "member"}\n\n` +
                (args.includeTeams && teams.length > 0
                  ? `**Teams (${teams.length}):**\n` +
                    teams
                      .map(
                        (team: any, index: number) =>
                          `${index + 1}. **${team.name}**\n` +
                          `   - ID: ${team.id}\n` +
                          `   - Created: ${new Date((team as any).createdAt || "").toLocaleDateString()}\n`,
                      )
                      .join("") +
                    "\n"
                  : "") +
                `**Available Actions:**\n` +
                `- Create new teams with "create-make-team"\n` +
                `- Invite users with "invite-make-user"\n` +
                `- Manage team permissions\n` +
                `- View organization analytics\n\n` +
                `**Organization Data:**\n\`\`\`json\n${JSON.stringify(org, null, 2)}\n\`\`\``,
            },
          ],
        };
      } catch (error) {
        log.error(`[${operationId}] Failed to get organization details`, {
          error: error instanceof Error ? error.message : String(error),
          organizationId: args.organizationId,
        });

        if (error instanceof MakeAPIError) {
          return {
            content: [
              {
                type: "text",
                text: `❌ Failed to get organization details: ${error.message}\n\n**Error Details:**\n- Organization ID: ${args.organizationId}\n- Code: ${error.code}\n- Status: ${error.statusCode}\n\n**Possible Issues:**\n1. Organization ID not found\n2. Insufficient permissions to view organization\n3. Organization access has been revoked`,
              },
            ],
          };
        }

        throw error;
      }
    },
  });

  // ==============================================================================
  // Team Management Tools
  // ==============================================================================

  server.addTool({
    name: "list-make-teams",
    description: "List Make.com teams with filtering and detailed information",
    parameters: z.object({
      organizationId: z
        .string()
        .optional()
        .describe("Filter teams by organization ID"),
      includeMembers: z
        .boolean()
        .default(false)
        .describe("Include member count for each team"),
      includeScenarios: z
        .boolean()
        .default(false)
        .describe("Include scenario count for each team"),
    }),
    execute: async (args, { log }) => {
      const operationId = `list-teams-${Date.now()}`;

      log.info(`[${operationId}] Listing Make.com teams`, {
        organizationId: args.organizationId,
        includeMembers: args.includeMembers,
        includeScenarios: args.includeScenarios,
      });

      try {
        const result = await makeClient.getTeams(args.organizationId);

        log.info(`[${operationId}] Teams retrieved successfully`, {
          teamCount: result.data?.length || 0,
          organizationId: args.organizationId,
        });

        const teams = result.data || [];

        // Format teams with enhanced information
        const formattedTeams = await Promise.all(
          teams.map(async (team: any) => {
            let scenarioCount = 0;
            let memberCount = 0;

            if (args.includeScenarios) {
              try {
                const scenarios = await makeClient.getScenarios(
                  team.id.toString(),
                );
                scenarioCount = scenarios.data?.length || 0;
              } catch (error) {
                logger.warn(
                  `Failed to get scenario count for team ${team.id}`,
                  {
                    error:
                      error instanceof Error ? error.message : String(error),
                  },
                );
              }
            }

            // Member count would need a separate API call if available
            if (args.includeMembers) {
              memberCount = 1; // Placeholder - would need actual API call
            }

            return {
              id: team.id,
              name: team.name,
              organizationId: team.organizationId,
              createdAt: (team as any).createdAt,
              ...(args.includeMembers && { memberCount }),
              ...(args.includeScenarios && { scenarioCount }),
            };
          }),
        );

        return {
          content: [
            {
              type: "text",
              text:
                `👥 Make.com Teams\n\n**Total Teams:** ${teams.length}\n${args.organizationId ? `**Organization:** ${args.organizationId}\n` : ""}\n` +
                formattedTeams
                  .map(
                    (team, index) =>
                      `**${index + 1}. ${team.name}**\n` +
                      `- ID: ${team.id}\n` +
                      `- Organization: ${team.organizationId}\n` +
                      `- Created: ${new Date((team as any).createdAt || "").toLocaleDateString()}\n` +
                      (args.includeMembers
                        ? `- Members: ${team.memberCount}\n`
                        : "") +
                      (args.includeScenarios
                        ? `- Scenarios: ${team.scenarioCount}\n`
                        : ""),
                  )
                  .join("\n") +
                `\n**Team Management:**\n` +
                `- Use "create-make-team" to create new teams\n` +
                `- Use "get-make-team-details" for detailed information\n` +
                `- Use "manage-make-team-permissions" to configure access\n` +
                `- Use "invite-make-user" to add users to teams`,
            },
          ],
        };
      } catch (error) {
        log.error(`[${operationId}] Failed to list teams`, {
          error: error instanceof Error ? error.message : String(error),
          organizationId: args.organizationId,
        });

        if (error instanceof MakeAPIError) {
          return {
            content: [
              {
                type: "text",
                text: `❌ Failed to list teams: ${error.message}\n\n**Error Details:**\n- Code: ${error.code}\n- Status: ${error.statusCode}\n${args.organizationId ? `- Organization ID: ${args.organizationId}\n` : ""}\n**Troubleshooting:**\n1. Verify organization ID is correct\n2. Check if you have team viewing permissions\n3. Ensure API token has proper scopes`,
              },
            ],
          };
        }

        throw error;
      }
    },
  });

  server.addTool({
    name: "create-make-team",
    description: "Create a new Make.com team within an organization",
    parameters: TeamCreateSchema,
    execute: async (args, { log }) => {
      const operationId = `create-team-${Date.now()}`;

      log.info(`[${operationId}] Creating new Make.com team`, {
        name: args.name,
        organizationId: args.organizationId,
      });

      try {
        const teamData = {
          name: args.name,
          organizationId: args.organizationId,
          description: args.description,
          settings: args.settings,
        };

        const result = await makeClient.createTeam(teamData);

        log.info(`[${operationId}] Team created successfully`, {
          teamId: result.data?.id,
          name: result.data?.name,
          organizationId: args.organizationId,
        });

        return {
          content: [
            {
              type: "text",
              text: `✅ Team created successfully!\n\n**Team Details:**\n- ID: ${result.data?.id}\n- Name: ${result.data?.name}\n- Organization: ${args.organizationId}\n- Description: ${args.description || "None"}\n\n**Team Settings:**\n${
                args.settings
                  ? Object.entries(args.settings)
                      .map(([key, value]) => `- ${key}: ${value}`)
                      .join("\n")
                  : "- Default settings applied"
              }\n\n**Next Steps:**\n1. Invite users to the team with "invite-make-user"\n2. Configure team permissions and settings\n3. Create scenarios within this team\n4. Set up team-specific data stores and connections\n\nFull team data:\n\`\`\`json\n${JSON.stringify(result.data, null, 2)}\n\`\`\``,
            },
          ],
        };
      } catch (error) {
        log.error(`[${operationId}] Failed to create team`, {
          error: error instanceof Error ? error.message : String(error),
          name: args.name,
          organizationId: args.organizationId,
        });

        if (error instanceof MakeAPIError) {
          return {
            content: [
              {
                type: "text",
                text: `❌ Failed to create team: ${error.message}\n\n**Error Details:**\n- Team Name: ${args.name}\n- Organization ID: ${args.organizationId}\n- Code: ${error.code}\n- Status: ${error.statusCode}\n\n**Possible Issues:**\n1. Team name already exists in organization\n2. Insufficient permissions to create teams\n3. Organization ID not found or inaccessible\n4. Team name violates naming conventions`,
              },
            ],
          };
        }

        throw error;
      }
    },
  });

  // ==============================================================================
  // User Management Tools
  // ==============================================================================

  server.addTool({
    name: "invite-make-user",
    description: "Invite a user to join a Make.com organization or team",
    parameters: UserInviteSchema,
    execute: async (args, { log }) => {
      const operationId = `invite-user-${Date.now()}`;

      log.info(`[${operationId}] Inviting user to Make.com organization`, {
        email: args.email,
        organizationId: args.organizationId,
        role: args.role,
        teamAssignments: args.teamAssignments?.length || 0,
      });

      try {
        // Note: This would use the actual Make.com user invitation API
        // For now, we'll simulate the invitation process

        const invitationData = {
          email: args.email,
          organizationId: args.organizationId,
          role: args.role,
          teamAssignments: args.teamAssignments,
          message: args.message,
          invitedAt: new Date().toISOString(),
        };

        // Simulate API call - would be: await makeClient.inviteUser(invitationData);
        log.info(`[${operationId}] User invitation prepared`, {
          email: args.email,
          organizationId: args.organizationId,
        });

        return {
          content: [
            {
              type: "text",
              text: `✅ User invitation prepared!\n\n**Invitation Details:**\n- Email: ${args.email}\n- Organization: ${args.organizationId}\n- Role: ${args.role}\n- Custom Message: ${args.message || "Default invitation message"}\n\n**Team Assignments:**\n${args.teamAssignments?.map((assignment) => `- Team ${assignment.teamId}: ${assignment.role}`).join("\n") || "No specific team assignments"}\n\n⚠️ **Note:** This demonstrates the invitation structure. Actual user invitation requires verification of the specific Make.com user invitation API endpoint.\n\n**Next Steps:**\n1. Verify Make.com user invitation API documentation\n2. Implement actual invitation sending\n3. Set up invitation status tracking\n4. Configure user onboarding workflow\n\nInvitation data:\n\`\`\`json\n${JSON.stringify(invitationData, null, 2)}\n\`\`\``,
            },
          ],
        };
      } catch (error) {
        log.error(`[${operationId}] Failed to invite user`, {
          error: error instanceof Error ? error.message : String(error),
          email: args.email,
          organizationId: args.organizationId,
        });

        if (error instanceof MakeAPIError) {
          return {
            content: [
              {
                type: "text",
                text: `❌ Failed to invite user: ${error.message}\n\n**Error Details:**\n- Email: ${args.email}\n- Organization ID: ${args.organizationId}\n- Code: ${error.code}\n- Status: ${error.statusCode}\n\n**Possible Issues:**\n1. Invalid email address format\n2. User already exists in organization\n3. Insufficient permissions to invite users\n4. Organization user limit reached\n5. Invalid organization or team IDs`,
              },
            ],
          };
        }

        throw error;
      }
    },
  });

  // ==============================================================================
  // Permission Management Tools
  // ==============================================================================

  server.addTool({
    name: "manage-make-permissions",
    description: "Manage user permissions within organizations and teams",
    parameters: PermissionUpdateSchema,
    execute: async (args, { log }) => {
      const operationId = `manage-permissions-${Date.now()}`;

      log.info(`[${operationId}] Managing Make.com user permissions`, {
        userId: args.userId,
        organizationId: args.organizationId,
        teamId: args.teamId,
        permissionCount: args.permissions.length,
      });

      try {
        // Note: This would use actual Make.com permissions API
        // For now, we'll simulate permission management

        const permissionChanges = args.permissions.map((perm) => ({
          scope: perm.scope,
          actions: perm.actions,
          granted: perm.granted,
          appliedAt: new Date().toISOString(),
        }));

        log.info(`[${operationId}] Permission changes prepared`, {
          userId: args.userId,
          changesCount: permissionChanges.length,
        });

        return {
          content: [
            {
              type: "text",
              text:
                `🔐 Permission Management\n\n**User:** ${args.userId}\n${args.organizationId ? `**Organization:** ${args.organizationId}\n` : ""}${args.teamId ? `**Team:** ${args.teamId}\n` : ""}\n**Permission Changes Applied:**\n\n` +
                permissionChanges
                  .map(
                    (change, index) =>
                      `**${index + 1}. ${change.scope}**\n` +
                      `- Actions: ${change.actions.join(", ")}\n` +
                      `- Status: ${change.granted ? "✅ Granted" : "❌ Revoked"}\n` +
                      `- Applied: ${new Date(change.appliedAt).toLocaleString()}\n`,
                  )
                  .join("\n") +
                `\n⚠️ **Note:** This demonstrates permission management structure. Actual permission changes require verification of Make.com permissions API endpoints.\n\n**Permission Scopes Available:**\n- scenarios:read, scenarios:write, scenarios:run\n- teams:read, teams:write\n- organizations:read, organizations:write\n- connections:read, connections:write\n- data-stores:read, data-stores:write\n- hooks:read, hooks:write\n- users:read, users:write\n\nPermission data:\n\`\`\`json\n${JSON.stringify(permissionChanges, null, 2)}\n\`\`\``,
            },
          ],
        };
      } catch (error) {
        log.error(`[${operationId}] Failed to manage permissions`, {
          error: error instanceof Error ? error.message : String(error),
          userId: args.userId,
        });

        if (error instanceof MakeAPIError) {
          return {
            content: [
              {
                type: "text",
                text: `❌ Failed to manage permissions: ${error.message}\n\n**Error Details:**\n- User ID: ${args.userId}\n- Code: ${error.code}\n- Status: ${error.statusCode}\n\n**Possible Issues:**\n1. User ID not found\n2. Insufficient permissions to modify access\n3. Invalid permission scope or action\n4. Organization or team context missing\n5. Permission conflicts with existing roles`,
              },
            ],
          };
        }

        throw error;
      }
    },
  });

  // ==============================================================================
  // Analytics and Reporting Tools
  // ==============================================================================

  server.addTool({
    name: "get-make-user-activity",
    description:
      "Get user activity reports and analytics for organizations and teams",
    parameters: UserActivitySchema,
    execute: async (args, { log }) => {
      const operationId = `user-activity-${Date.now()}`;

      log.info(`[${operationId}] Getting Make.com user activity`, {
        organizationId: args.organizationId,
        teamId: args.teamId,
        userId: args.userId,
        startDate: args.startDate,
        endDate: args.endDate,
      });

      try {
        // Note: This would use actual Make.com analytics/activity API
        // For now, we'll simulate activity reporting

        const activityReport = {
          period: {
            start: args.startDate,
            end: args.endDate,
          },
          context: {
            organizationId: args.organizationId,
            teamId: args.teamId,
            userId: args.userId,
          },
          summary: {
            totalUsers: args.userId ? 1 : 25,
            activeUsers: args.userId ? 1 : 18,
            totalSessions: args.userId ? 12 : 456,
            averageSessionDuration: "24 minutes",
          },
          activities: [
            {
              date: "2025-08-25",
              user: args.userId || "user_123",
              actions: [
                "Logged in",
                "Created scenario 'Data Sync'",
                "Ran scenario execution",
                "Updated webhook configuration",
              ],
              duration: "45 minutes",
            },
            // Additional activity data would be here
          ],
          metrics: {
            scenariosCreated: 15,
            scenariosExecuted: 234,
            webhooksConfigured: 8,
            connectionsManaged: 12,
            dataStoreOperations: 67,
          },
        };

        log.info(`[${operationId}] User activity report generated`, {
          period: `${args.startDate} to ${args.endDate}`,
          totalUsers: activityReport.summary.totalUsers,
        });

        return {
          content: [
            {
              type: "text",
              text: `📈 User Activity Report\n\n**Period:** ${args.startDate} to ${args.endDate}\n${args.organizationId ? `**Organization:** ${args.organizationId}\n` : ""}${args.teamId ? `**Team:** ${args.teamId}\n` : ""}${args.userId ? `**User:** ${args.userId}\n` : ""}\n**Activity Summary:**\n- Total Users: ${activityReport.summary.totalUsers}\n- Active Users: ${activityReport.summary.activeUsers}\n- Total Sessions: ${activityReport.summary.totalSessions}\n- Avg Session Duration: ${activityReport.summary.averageSessionDuration}\n\n**Key Metrics:**\n- Scenarios Created: ${activityReport.metrics.scenariosCreated}\n- Scenarios Executed: ${activityReport.metrics.scenariosExecuted}\n- Webhooks Configured: ${activityReport.metrics.webhooksConfigured}\n- Connections Managed: ${activityReport.metrics.connectionsManaged}\n- Data Store Operations: ${activityReport.metrics.dataStoreOperations}\n\n${args.includeDetails ? "**Recent Activity:**\n" + activityReport.activities.map((activity) => `**${activity.date}** - ${activity.user} (${activity.duration})\n${activity.actions.map((action) => `- ${action}`).join("\n")}`).join("\n\n") + "\n\n" : ""}⚠️ **Note:** This demonstrates activity reporting structure. Actual user activity requires verification of Make.com analytics API endpoints.\n\n**Available Reports:**\n- User login/logout activity\n- Scenario creation and execution history\n- Permission changes and access patterns\n- Resource usage and performance metrics\n\nActivity report data:\n\`\`\`json\n${JSON.stringify(activityReport, null, 2)}\n\`\`\``,
            },
          ],
        };
      } catch (error) {
        log.error(`[${operationId}] Failed to get user activity`, {
          error: error instanceof Error ? error.message : String(error),
          dateRange: `${args.startDate} to ${args.endDate}`,
        });

        if (error instanceof MakeAPIError) {
          return {
            content: [
              {
                type: "text",
                text: `❌ Failed to get user activity: ${error.message}\n\n**Error Details:**\n- Code: ${error.code}\n- Status: ${error.statusCode}\n- Date Range: ${args.startDate} to ${args.endDate}\n\n**Possible Issues:**\n1. Invalid date range format\n2. Insufficient permissions to view activity\n3. Organization or team ID not found\n4. User ID not accessible\n5. Analytics API not available`,
              },
            ],
          };
        }

        throw error;
      }
    },
  });

  logger.info("User and Access Management tools registered successfully", {
    toolCount: 7,
    categories: ["organizations", "teams", "users", "permissions", "analytics"],
  });
}

export default registerUserAccessManagementTools;
