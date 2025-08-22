/**
 * @fileoverview Make.com Naming Convention Policy Management Tools
 * 
 * Provides comprehensive naming convention policy creation, management, and enforcement tools including:
 * - Policy creation with flexible rule definitions and patterns
 * - Template-based naming standards for different resource types
 * - Validation and compliance checking mechanisms
 * - Integration with existing permissions and audit systems
 * - Enforcement capabilities with real-time validation
 * - Policy templates for common enterprise patterns
 * 
 * @version 1.0.0
 * @author Make.com FastMCP Server
 * @see {@link https://docs.make.com/api} Make.com API Documentation
 */

import { FastMCP, UserError } from 'fastmcp';
import { z } from 'zod';
import MakeApiClient from '../lib/make-api-client.js';
import { auditLogger } from '../lib/audit-logger.js';
import logger from '../lib/logger.js';
import { formatSuccessResponse } from '../utils/response-formatter.js';

// Define comprehensive naming convention policy interfaces and schemas

/**
 * Supported resource types for naming conventions
 */
export enum ResourceType {
  SCENARIO = 'scenario',
  CONNECTION = 'connection',
  TEMPLATE = 'template',
  FOLDER = 'folder',
  VARIABLE = 'variable',
  WEBHOOK = 'webhook',
  TEAM = 'team',
  ORGANIZATION = 'organization',
  DATA_STORE = 'data_store',
  FUNCTION = 'function',
  APP = 'app',
  CERTIFICATE = 'certificate',
  PROCEDURE = 'procedure',
}

/**
 * Pattern validation types
 */
export enum PatternType {
  REGEX = 'regex',
  TEMPLATE = 'template',
  CUSTOM = 'custom',
  STARTS_WITH = 'starts_with',
  ENDS_WITH = 'ends_with',
  CONTAINS = 'contains',
  LENGTH = 'length',
  CASE = 'case',
}

/**
 * Case enforcement options
 */
export enum CaseType {
  CAMEL_CASE = 'camelCase',
  PASCAL_CASE = 'PascalCase',
  SNAKE_CASE = 'snake_case',
  KEBAB_CASE = 'kebab-case',
  UPPER_CASE = 'UPPER_CASE',
  LOWER_CASE = 'lower_case',
  TITLE_CASE = 'Title Case',
}

/**
 * Policy enforcement levels
 */
export enum EnforcementLevel {
  STRICT = 'strict',      // Blocks non-compliant operations
  WARNING = 'warning',    // Warns but allows operations
  ADVISORY = 'advisory',  // Informational only
  DISABLED = 'disabled',  // Policy exists but not enforced
}

/**
 * Naming rule definition schema
 */
const NamingRuleSchema = z.object({
  id: z.string().min(1).describe('Unique rule identifier'),
  name: z.string().min(1).describe('Human-readable rule name'),
  description: z.string().optional().describe('Rule description and purpose'),
  resourceTypes: z.array(z.nativeEnum(ResourceType)).min(1).describe('Resource types this rule applies to'),
  patternType: z.nativeEnum(PatternType).describe('Type of pattern validation'),
  pattern: z.string().min(1).describe('Pattern definition (regex, template, etc.)'),
  caseType: z.nativeEnum(CaseType).optional().describe('Required case format'),
  minLength: z.number().min(1).optional().describe('Minimum name length'),
  maxLength: z.number().min(1).optional().describe('Maximum name length'),
  required: z.boolean().default(true).describe('Whether this rule is mandatory'),
  enforcementLevel: z.nativeEnum(EnforcementLevel).default(EnforcementLevel.STRICT).describe('Enforcement level'),
  allowedCharacters: z.string().optional().describe('Allowed character set (regex)'),
  forbiddenWords: z.array(z.string()).optional().describe('Forbidden words or phrases'),
  requiredPrefix: z.string().optional().describe('Required prefix'),
  requiredSuffix: z.string().optional().describe('Required suffix'),
  customValidationFunction: z.string().optional().describe('Custom JavaScript validation function'),
  priority: z.number().min(1).max(100).default(50).describe('Rule priority (1=highest, 100=lowest)'),
  tags: z.array(z.string()).optional().describe('Rule tags for categorization'),
  createdAt: z.string().optional().describe('Rule creation timestamp'),
  updatedAt: z.string().optional().describe('Rule last update timestamp'),
  createdBy: z.string().optional().describe('User who created the rule'),
}).strict();

/**
 * Policy template definition schema
 */
const PolicyTemplateSchema = z.object({
  id: z.string().min(1).describe('Template identifier'),
  name: z.string().min(1).describe('Template name'),
  description: z.string().describe('Template description'),
  category: z.string().describe('Template category (enterprise, startup, government, etc.)'),
  rules: z.array(NamingRuleSchema).describe('Predefined rules in this template'),
  metadata: z.record(z.unknown()).optional().describe('Additional template metadata'),
}).strict();

/**
 * Create naming convention policy schema
 */
const CreateNamingPolicySchema = z.object({
  name: z.string().min(1).max(100).describe('Policy name'),
  description: z.string().max(500).optional().describe('Policy description'),
  scope: z.object({
    organizationId: z.number().optional().describe('Organization scope'),
    teamId: z.number().optional().describe('Team scope'),
    global: z.boolean().default(false).describe('Apply globally'),
  }).describe('Policy application scope'),
  rules: z.array(NamingRuleSchema).min(1).describe('Naming rules to include in policy'),
  templateId: z.string().optional().describe('Base template to use'),
  enforcementLevel: z.nativeEnum(EnforcementLevel).default(EnforcementLevel.STRICT).describe('Default enforcement level'),
  active: z.boolean().default(true).describe('Whether policy is active'),
  effectiveFrom: z.string().optional().describe('Policy effective date (ISO string)'),
  effectiveUntil: z.string().optional().describe('Policy expiration date (ISO string)'),
  notificationSettings: z.object({
    notifyOnViolation: z.boolean().default(true).describe('Send notifications on violations'),
    notifyOnUpdate: z.boolean().default(false).describe('Send notifications on policy updates'),
    recipients: z.array(z.string()).optional().describe('Notification recipient emails'),
  }).optional().describe('Notification configuration'),
  metadata: z.record(z.unknown()).optional().describe('Additional policy metadata'),
}).strict();

/**
 * Validate names against policy schema
 */
const ValidateNamesSchema = z.object({
  policyId: z.string().min(1).describe('Policy ID to validate against'),
  names: z.array(z.object({
    resourceType: z.nativeEnum(ResourceType).describe('Type of resource'),
    name: z.string().min(1).describe('Name to validate'),
    resourceId: z.string().optional().describe('Resource identifier'),
    metadata: z.record(z.unknown()).optional().describe('Additional resource metadata'),
  })).min(1).describe('Names to validate'),
  returnDetails: z.boolean().default(true).describe('Return detailed validation results'),
}).strict();

/**
 * Update naming policy schema
 */
const UpdateNamingPolicySchema = z.object({
  policyId: z.string().min(1).describe('Policy ID to update'),
  name: z.string().min(1).max(100).optional().describe('New policy name'),
  description: z.string().max(500).optional().describe('New policy description'),
  rules: z.array(NamingRuleSchema).optional().describe('Updated naming rules'),
  enforcementLevel: z.nativeEnum(EnforcementLevel).optional().describe('New enforcement level'),
  active: z.boolean().optional().describe('Policy activation status'),
  effectiveFrom: z.string().optional().describe('New effective date'),
  effectiveUntil: z.string().optional().describe('New expiration date'),
  notificationSettings: z.object({
    notifyOnViolation: z.boolean().optional(),
    notifyOnUpdate: z.boolean().optional(),
    recipients: z.array(z.string()).optional(),
  }).optional().describe('Updated notification settings'),
  metadata: z.record(z.unknown()).optional().describe('Updated metadata'),
}).strict();

/**
 * Policy filters schema
 */
const PolicyFiltersSchema = z.object({
  organizationId: z.number().optional().describe('Filter by organization'),
  teamId: z.number().optional().describe('Filter by team'),
  active: z.boolean().optional().describe('Filter by active status'),
  resourceType: z.nativeEnum(ResourceType).optional().describe('Filter by resource type'),
  enforcementLevel: z.nativeEnum(EnforcementLevel).optional().describe('Filter by enforcement level'),
  search: z.string().optional().describe('Search by name or description'),
  limit: z.number().min(1).max(100).default(20).describe('Maximum policies to return'),
  offset: z.number().min(0).default(0).describe('Pagination offset'),
}).strict();

/**
 * Built-in policy templates
 */
const POLICY_TEMPLATES: Record<string, z.infer<typeof PolicyTemplateSchema>> = {
  'enterprise-standard': {
    id: 'enterprise-standard',
    name: 'Enterprise Standard Naming',
    description: 'Comprehensive enterprise naming conventions with strict governance',
    category: 'enterprise',
    rules: [
      {
        id: 'scenario-prefix-rule',
        name: 'Scenario Department Prefix',
        description: 'Scenarios must start with department code',
        resourceTypes: [ResourceType.SCENARIO],
        patternType: PatternType.REGEX,
        pattern: '^(HR|FIN|OPS|DEV|MKT|SALES|IT)-[A-Z][a-zA-Z0-9_-]+$',
        minLength: 6,
        maxLength: 50,
        required: true,
        enforcementLevel: EnforcementLevel.STRICT,
        priority: 10,
        tags: ['department', 'prefix'],
      },
      {
        id: 'connection-naming-standard',
        name: 'Connection Service Naming',
        description: 'Connections must follow service-environment-purpose format',
        resourceTypes: [ResourceType.CONNECTION],
        patternType: PatternType.TEMPLATE,
        pattern: '{service}_{environment}_{purpose}',
        caseType: CaseType.SNAKE_CASE,
        minLength: 10,
        maxLength: 60,
        required: true,
        enforcementLevel: EnforcementLevel.STRICT,
        priority: 15,
        tags: ['service', 'environment'],
      },
      {
        id: 'template-organization',
        name: 'Template Organization Structure',
        description: 'Templates must include team and version information',
        resourceTypes: [ResourceType.TEMPLATE],
        patternType: PatternType.REGEX,
        pattern: '^[A-Z]{2,4}-[a-zA-Z0-9_-]+-v\\d+(\\.\\d+)?$',
        minLength: 8,
        maxLength: 40,
        required: true,
        enforcementLevel: EnforcementLevel.STRICT,
        priority: 20,
        tags: ['versioning', 'team'],
      },
      {
        id: 'folder-hierarchy',
        name: 'Folder Hierarchy Standard',
        description: 'Folders must follow department/project/type structure',
        resourceTypes: [ResourceType.FOLDER],
        patternType: PatternType.REGEX,
        pattern: '^(dept|proj|type)-[a-z0-9][a-z0-9-]*[a-z0-9]$',
        caseType: CaseType.KEBAB_CASE,
        minLength: 6,
        maxLength: 30,
        required: true,
        enforcementLevel: EnforcementLevel.STRICT,
        forbiddenWords: ['temp', 'test', 'old', 'backup'],
        priority: 25,
        tags: ['hierarchy', 'organization'],
      },
    ],
  },
  'startup-agile': {
    id: 'startup-agile',
    name: 'Startup Agile Naming',
    description: 'Flexible naming conventions for fast-moving startup environments',
    category: 'startup',
    rules: [
      {
        id: 'scenario-descriptive',
        name: 'Descriptive Scenario Names',
        description: 'Clear, descriptive scenario names without strict prefixes',
        resourceTypes: [ResourceType.SCENARIO],
        patternType: PatternType.REGEX,
        pattern: '^[A-Z][a-zA-Z0-9\\s_-]+$',
        minLength: 5,
        maxLength: 80,
        required: true,
        enforcementLevel: EnforcementLevel.WARNING,
        forbiddenWords: ['untitled', 'new', 'copy'],
        priority: 30,
        tags: ['descriptive', 'flexible'],
      },
      {
        id: 'connection-simple',
        name: 'Simple Connection Naming',
        description: 'Simple, clear connection names',
        resourceTypes: [ResourceType.CONNECTION],
        patternType: PatternType.REGEX,
        pattern: '^[a-zA-Z][a-zA-Z0-9_-]*[a-zA-Z0-9]$',
        minLength: 3,
        maxLength: 40,
        required: true,
        enforcementLevel: EnforcementLevel.WARNING,
        priority: 35,
        tags: ['simple', 'clear'],
      },
    ],
  },
  'government-compliance': {
    id: 'government-compliance',
    name: 'Government Compliance Naming',
    description: 'Strict naming conventions for government and regulatory compliance',
    category: 'government',
    rules: [
      {
        id: 'scenario-classification',
        name: 'Security Classification Prefix',
        description: 'Scenarios must include security classification',
        resourceTypes: [ResourceType.SCENARIO],
        patternType: PatternType.REGEX,
        pattern: '^(UNCLASS|CUI|SECRET|TOPSECRET)-[A-Z0-9][A-Z0-9_-]+$',
        minLength: 10,
        maxLength: 60,
        required: true,
        enforcementLevel: EnforcementLevel.STRICT,
        allowedCharacters: '[A-Z0-9_-]',
        priority: 5,
        tags: ['security', 'classification'],
      },
      {
        id: 'audit-trail-naming',
        name: 'Audit Trail Compliance',
        description: 'All resources must include audit-friendly naming',
        resourceTypes: [ResourceType.CONNECTION, ResourceType.TEMPLATE, ResourceType.FOLDER],
        patternType: PatternType.REGEX,
        pattern: '^[A-Z]{3,5}-[0-9]{4}-[A-Z0-9_-]+$',
        minLength: 10,
        maxLength: 50,
        required: true,
        enforcementLevel: EnforcementLevel.STRICT,
        allowedCharacters: '[A-Z0-9_-]',
        priority: 8,
        tags: ['audit', 'compliance'],
      },
    ],
  },
};

/**
 * Naming convention validation utilities
 */
class NamingConventionValidator {
  /**
   * Validate a name against a specific rule
   */
  static validateAgainstRule(name: string, rule: z.infer<typeof NamingRuleSchema>): {
    isValid: boolean;
    errors: string[];
    warnings: string[];
  } {
    const errors: string[] = [];
    const warnings: string[] = [];

    try {
      // Length validation
      if (rule.minLength && name.length < rule.minLength) {
        errors.push(`Name too short. Minimum length: ${rule.minLength}, actual: ${name.length}`);
      }
      if (rule.maxLength && name.length > rule.maxLength) {
        errors.push(`Name too long. Maximum length: ${rule.maxLength}, actual: ${name.length}`);
      }

      // Pattern validation
      if (rule.patternType === PatternType.REGEX && rule.pattern) {
        const regex = new RegExp(rule.pattern);
        if (!regex.test(name)) {
          errors.push(`Name does not match required pattern: ${rule.pattern}`);
        }
      }

      // Case validation
      if (rule.caseType) {
        const isValidCase = this.validateCaseFormat(name, rule.caseType);
        if (!isValidCase) {
          errors.push(`Name does not follow required case format: ${rule.caseType}`);
        }
      }

      // Character set validation
      if (rule.allowedCharacters) {
        const allowedRegex = new RegExp(`^${rule.allowedCharacters}+$`);
        if (!allowedRegex.test(name)) {
          errors.push(`Name contains invalid characters. Allowed: ${rule.allowedCharacters}`);
        }
      }

      // Forbidden words validation
      if (rule.forbiddenWords && rule.forbiddenWords.length > 0) {
        const lowerName = name.toLowerCase();
        const foundForbidden = rule.forbiddenWords.filter(word => 
          lowerName.includes(word.toLowerCase())
        );
        if (foundForbidden.length > 0) {
          errors.push(`Name contains forbidden words: ${foundForbidden.join(', ')}`);
        }
      }

      // Prefix/suffix validation
      if (rule.requiredPrefix && !name.startsWith(rule.requiredPrefix)) {
        errors.push(`Name must start with: ${rule.requiredPrefix}`);
      }
      if (rule.requiredSuffix && !name.endsWith(rule.requiredSuffix)) {
        errors.push(`Name must end with: ${rule.requiredSuffix}`);
      }

      // Custom validation function
      if (rule.customValidationFunction) {
        try {
          // Safely evaluate custom function (in production, this would be more secure)
          const customFunction = new Function('name', 'rule', rule.customValidationFunction);
          const customResult = customFunction(name, rule);
          if (customResult !== true && typeof customResult === 'string') {
            errors.push(`Custom validation failed: ${customResult}`);
          }
        } catch (error) {
          warnings.push(`Custom validation function error: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
      }

      return {
        isValid: errors.length === 0,
        errors,
        warnings,
      };
    } catch (error) {
      return {
        isValid: false,
        errors: [`Validation error: ${error instanceof Error ? error.message : 'Unknown error'}`],
        warnings,
      };
    }
  }

  /**
   * Validate case format
   */
  private static validateCaseFormat(name: string, caseType: CaseType): boolean {
    switch (caseType) {
      case CaseType.CAMEL_CASE:
        return /^[a-z][a-zA-Z0-9]*$/.test(name);
      case CaseType.PASCAL_CASE:
        return /^[A-Z][a-zA-Z0-9]*$/.test(name);
      case CaseType.SNAKE_CASE:
        return /^[a-z][a-z0-9_]*[a-z0-9]$/.test(name);
      case CaseType.KEBAB_CASE:
        return /^[a-z][a-z0-9-]*[a-z0-9]$/.test(name);
      case CaseType.UPPER_CASE:
        return /^[A-Z][A-Z0-9_]*$/.test(name);
      case CaseType.LOWER_CASE:
        return /^[a-z][a-z0-9]*$/.test(name);
      case CaseType.TITLE_CASE:
        return /^[A-Z][a-zA-Z0-9\s]*$/.test(name) && 
               name.split(' ').every(word => /^[A-Z][a-z]*$/.test(word));
      default:
        return true;
    }
  }

  /**
   * Generate name suggestions based on rules
   */
  static generateNameSuggestions(resourceType: ResourceType, rules: z.infer<typeof NamingRuleSchema>[]): string[] {
    const suggestions: string[] = [];
    const applicableRules = rules.filter(rule => rule.resourceTypes.includes(resourceType));

    for (const rule of applicableRules.slice(0, 3)) { // Limit to top 3 rules
      try {
        let suggestion = '';
        
        // Generate based on pattern type
        switch (rule.patternType) {
          case PatternType.TEMPLATE:
            suggestion = this.generateFromTemplate(rule.pattern);
            break;
          case PatternType.STARTS_WITH:
            suggestion = `${rule.pattern}ExampleName`;
            break;
          case PatternType.ENDS_WITH:
            suggestion = `ExampleName${rule.pattern}`;
            break;
          default:
            suggestion = this.generateFromPattern(rule, resourceType);
        }

        if (suggestion && !suggestions.includes(suggestion)) {
          suggestions.push(suggestion);
        }
      } catch (error) {
        // Skip invalid patterns
      }
    }

    return suggestions;
  }

  private static generateFromTemplate(template: string): string {
    return template
      .replace('{service}', 'api')
      .replace('{environment}', 'prod')
      .replace('{purpose}', 'integration')
      .replace('{department}', 'OPS')
      .replace('{version}', 'v1.0');
  }

  private static generateFromPattern(rule: z.infer<typeof NamingRuleSchema>, resourceType: ResourceType): string {
    const base = resourceType.charAt(0).toUpperCase() + resourceType.slice(1);
    let suggestion = base;

    if (rule.requiredPrefix) {
      suggestion = `${rule.requiredPrefix}${suggestion}`;
    }
    if (rule.requiredSuffix) {
      suggestion = `${suggestion}${rule.requiredSuffix}`;
    }

    // Apply case format
    if (rule.caseType) {
      suggestion = this.applyCaseFormat(suggestion, rule.caseType);
    }

    return suggestion;
  }

  private static applyCaseFormat(text: string, caseType: CaseType): string {
    switch (caseType) {
      case CaseType.CAMEL_CASE:
        return text.charAt(0).toLowerCase() + text.slice(1);
      case CaseType.PASCAL_CASE:
        return text.charAt(0).toUpperCase() + text.slice(1);
      case CaseType.SNAKE_CASE:
        return text.toLowerCase().replace(/[A-Z]/g, letter => `_${letter.toLowerCase()}`);
      case CaseType.KEBAB_CASE:
        return text.toLowerCase().replace(/[A-Z]/g, letter => `-${letter.toLowerCase()}`);
      case CaseType.UPPER_CASE:
        return text.toUpperCase();
      case CaseType.LOWER_CASE:
        return text.toLowerCase();
      default:
        return text;
    }
  }
}

/**
 * Adds comprehensive naming convention policy tools to the FastMCP server
 * 
 * @param {FastMCP} server - The FastMCP server instance
 * @param {MakeApiClient} apiClient - Make.com API client with rate limiting and authentication
 * @returns {void}
 */
export function addNamingConventionPolicyTools(server: FastMCP, apiClient: MakeApiClient): void {
  const componentLogger = logger.child({ component: 'NamingConventionPolicyTools' });
  
  componentLogger.info('Adding naming convention policy management tools');

  /**
   * Create a comprehensive naming convention policy
   * 
   * Creates a new naming convention policy with flexible rule definitions, templates,
   * and enforcement mechanisms for various Make.com resource types.
   * 
   * @tool create-naming-convention-policy
   * @category Policy Management
   * @permission policy_admin
   * 
   * @param {Object} args - Policy creation parameters
   * @param {string} args.name - Policy name
   * @param {string} [args.description] - Policy description
   * @param {Object} args.scope - Policy application scope
   * @param {Array} args.rules - Naming rules array
   * @param {string} [args.templateId] - Base template identifier
   * @param {string} [args.enforcementLevel] - Default enforcement level
   * @param {boolean} [args.active] - Policy active status
   * @param {string} [args.effectiveFrom] - Policy effective date
   * @param {string} [args.effectiveUntil] - Policy expiration date
   * @param {Object} [args.notificationSettings] - Notification configuration
   * @param {Object} [args.metadata] - Additional metadata
   * 
   * @returns {Promise<string>} JSON response containing:
   * - policy: Complete policy object with generated ID
   * - validationResults: Results of rule validation
   * - suggestions: Generated name suggestions based on rules
   * - enforcementCapabilities: Available enforcement mechanisms
   * - auditTrail: Policy creation audit information
   * 
   * @throws {UserError} When policy creation fails or validation errors occur
   * 
   * @example
   * ```typescript
   * // Create enterprise naming policy
   * const policy = await createNamingConventionPolicy({
   *   name: "Enterprise Standard Naming Policy",
   *   description: "Comprehensive enterprise naming conventions",
   *   scope: { organizationId: 123, global: false },
   *   rules: [
   *     {
   *       id: "scenario-prefix",
   *       name: "Scenario Department Prefix",
   *       resourceTypes: ["scenario"],
   *       patternType: "regex",
   *       pattern: "^(HR|FIN|OPS)-[A-Za-z0-9_-]+$",
   *       enforcementLevel: "strict",
   *       priority: 10
   *     }
   *   ],
   *   enforcementLevel: "strict",
   *   active: true
   * });
   * ```
   */
  server.addTool({
    name: 'create-naming-convention-policy',
    description: 'Create a comprehensive naming convention policy with flexible rules and enforcement',
    parameters: CreateNamingPolicySchema,
    annotations: {
      title: 'Create Naming Convention Policy',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true,
    },
    execute: async (input, { log }) => {
      log.info('Creating naming convention policy', {
        name: input.name,
        rulesCount: input.rules.length,
        scope: input.scope,
        enforcementLevel: input.enforcementLevel,
      });

      try {
        // Generate unique policy ID
        const policyId = `policy_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        const timestamp = new Date().toISOString();

        // Apply template if specified
        let finalRules = [...input.rules];
        if (input.templateId && POLICY_TEMPLATES[input.templateId]) {
          const template = POLICY_TEMPLATES[input.templateId];
          finalRules = [...template.rules, ...input.rules];
          log.info('Applied policy template', { templateId: input.templateId, templateRulesCount: template.rules.length });
        }

        // Sort rules by priority
        finalRules.sort((a, b) => (a.priority || 50) - (b.priority || 50));

        // Validate policy rules
        const validationResults: Record<string, unknown> = {};
        const ruleValidations = finalRules.map(rule => {
          const ruleId = rule.id;
          try {
            // Validate rule pattern
            if (rule.patternType === PatternType.REGEX) {
              new RegExp(rule.pattern); // Test regex validity
            }
            
            validationResults[ruleId] = {
              isValid: true,
              message: 'Rule validation passed',
            };
            
            return { ruleId, isValid: true };
          } catch (error) {
            validationResults[ruleId] = {
              isValid: false,
              error: error instanceof Error ? error.message : 'Unknown validation error',
            };
            
            return { ruleId, isValid: false, error: error instanceof Error ? error.message : 'Unknown error' };
          }
        });

        const invalidRules = ruleValidations.filter(r => !r.isValid);
        if (invalidRules.length > 0) {
          throw new UserError(`Policy contains invalid rules: ${invalidRules.map(r => r.ruleId).join(', ')}`);
        }

        // Generate name suggestions for each resource type
        const suggestions: Record<string, string[]> = {};
        for (const resourceType of Object.values(ResourceType)) {
          suggestions[resourceType] = NamingConventionValidator.generateNameSuggestions(resourceType, finalRules);
        }

        // Create policy object
        const policy = {
          id: policyId,
          name: input.name,
          description: input.description || '',
          scope: input.scope,
          rules: finalRules,
          templateId: input.templateId,
          enforcementLevel: input.enforcementLevel || EnforcementLevel.STRICT,
          active: input.active !== false,
          effectiveFrom: input.effectiveFrom || timestamp,
          effectiveUntil: input.effectiveUntil,
          notificationSettings: {
            notifyOnViolation: true,
            notifyOnUpdate: false,
            recipients: [],
            ...input.notificationSettings,
          },
          metadata: {
            ...input.metadata,
            rulesCount: finalRules.length,
            resourceTypesCount: new Set(finalRules.flatMap(r => r.resourceTypes)).size,
            averagePriority: finalRules.reduce((sum, r) => sum + (r.priority || 50), 0) / finalRules.length,
          },
          createdAt: timestamp,
          updatedAt: timestamp,
          version: '1.0.0',
        };

        // Store policy (in production, this would be stored in database)
        const response = await apiClient.post('/policies/naming-conventions', policy);
        
        if (!response.success) {
          throw new UserError(`Failed to create naming policy: ${response.error?.message || 'Unknown error'}`);
        }

        // Log policy creation audit event
        await auditLogger.logEvent({
          level: 'info',
          category: 'configuration',
          action: 'naming_policy_created',
          resource: `policy:${policyId}`,
          success: true,
          details: {
            policyId,
            name: input.name,
            rulesCount: finalRules.length,
            enforcementLevel: input.enforcementLevel,
            scope: input.scope,
            templateUsed: input.templateId || null,
          },
          riskLevel: 'medium',
        });

        log.info('Successfully created naming convention policy', {
          policyId,
          name: input.name,
          rulesCount: finalRules.length,
          resourceTypes: Object.keys(suggestions).length,
        });

        return formatSuccessResponse({
          success: true,
          policy,
          validationResults,
          suggestions,
          enforcementCapabilities: {
            realTimeValidation: true,
            batchValidation: true,
            auditLogging: true,
            notificationSystem: true,
            customValidation: true,
            templateSupport: true,
          },
          auditTrail: {
            createdAt: timestamp,
            action: 'policy_created',
            policyId,
            rulesValidated: finalRules.length,
            templateApplied: input.templateId || null,
          },
          message: `Naming convention policy "${input.name}" created successfully with ${finalRules.length} rules`,
        }).content[0].text;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error creating naming convention policy', { error: errorMessage, name: input.name });
        
        // Log failure audit event
        await auditLogger.logEvent({
          level: 'error',
          category: 'configuration',
          action: 'naming_policy_creation_failed',
          success: false,
          details: {
            name: input.name,
            error: errorMessage,
            rulesCount: input.rules.length,
          },
          riskLevel: 'low',
        });
        
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to create naming convention policy: ${errorMessage}`);
      }
    },
  });

  /**
   * Validate names against a naming convention policy
   * 
   * Validates one or more resource names against specified policy rules,
   * returning detailed compliance results and suggestions for improvement.
   * 
   * @tool validate-names-against-policy
   * @category Policy Management
   * @permission policy_read
   */
  server.addTool({
    name: 'validate-names-against-policy',
    description: 'Validate resource names against naming convention policy rules',
    parameters: ValidateNamesSchema,
    annotations: {
      title: 'Validate Names Against Policy',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log }) => {
      log.info('Validating names against policy', {
        policyId: input.policyId,
        namesCount: input.names.length,
        returnDetails: input.returnDetails,
      });

      try {
        // Fetch policy (in production, from database)
        const policyResponse = await apiClient.get(`/policies/naming-conventions/${input.policyId}`);
        
        if (!policyResponse.success) {
          throw new UserError(`Policy not found: ${input.policyId}`);
        }

        const policy = policyResponse.data as { 
          name: string; 
          rules: Array<{ resourceTypes: ResourceType[]; enforcementLevel: EnforcementLevel; [key: string]: unknown }> 
        };
        const validationResults: Record<string, unknown> = {};
        const summaryStats = {
          totalNames: input.names.length,
          validNames: 0,
          invalidNames: 0,
          warningNames: 0,
          skippedNames: 0,
        };

        // Validate each name
        for (const nameInput of input.names) {
          const nameId = nameInput.resourceId || `${nameInput.resourceType}_${nameInput.name}`;
          const applicableRules = policy.rules.filter((rule: { resourceTypes: ResourceType[]; }) => 
            rule.resourceTypes.includes(nameInput.resourceType)
          );

          if (applicableRules.length === 0) {
            validationResults[nameId] = {
              name: nameInput.name,
              resourceType: nameInput.resourceType,
              status: 'skipped',
              message: 'No applicable rules for this resource type',
              details: input.returnDetails ? { applicableRulesCount: 0 } : undefined,
            };
            summaryStats.skippedNames++;
            continue;
          }

          const ruleResults: unknown[] = [];
          let hasErrors = false;
          let hasWarnings = false;

          // Apply each applicable rule
          for (const rule of applicableRules) {
            const ruleResult = NamingConventionValidator.validateAgainstRule(nameInput.name, rule as z.infer<typeof NamingRuleSchema>);
            
            ruleResults.push({
              ruleId: rule.id,
              ruleName: rule.name,
              enforcementLevel: rule.enforcementLevel,
              isValid: ruleResult.isValid,
              errors: ruleResult.errors,
              warnings: ruleResult.warnings,
              priority: rule.priority || 50,
            });

            if (!ruleResult.isValid && rule.enforcementLevel === EnforcementLevel.STRICT) {
              hasErrors = true;
            } else if (ruleResult.errors.length > 0 || ruleResult.warnings.length > 0) {
              hasWarnings = true;
            }
          }

          // Generate suggestions if name is invalid
          let suggestions: string[] = [];
          if (hasErrors || hasWarnings) {
            suggestions = NamingConventionValidator.generateNameSuggestions(
              nameInput.resourceType,
              applicableRules as z.infer<typeof NamingRuleSchema>[]
            ).slice(0, 3);
          }

          const overallStatus = hasErrors ? 'invalid' : hasWarnings ? 'warning' : 'valid';
          
          validationResults[nameId] = {
            name: nameInput.name,
            resourceType: nameInput.resourceType,
            status: overallStatus,
            message: hasErrors 
              ? 'Name violates strict naming rules'
              : hasWarnings 
              ? 'Name has warnings but is acceptable'
              : 'Name complies with all applicable rules',
            suggestions: suggestions.length > 0 ? suggestions : undefined,
            details: input.returnDetails ? {
              applicableRulesCount: applicableRules.length,
              ruleResults,
              metadata: nameInput.metadata,
            } : undefined,
          };

          // Update summary stats
          if (overallStatus === 'valid') summaryStats.validNames++;
          else if (overallStatus === 'invalid') summaryStats.invalidNames++;
          else summaryStats.warningNames++;
        }

        // Log validation audit event
        await auditLogger.logEvent({
          level: summaryStats.invalidNames > 0 ? 'warn' : 'info',
          category: 'data_access',
          action: 'naming_policy_validation',
          resource: `policy:${input.policyId}`,
          success: summaryStats.invalidNames === 0,
          details: {
            policyId: input.policyId,
            validatedCount: input.names.length,
            validNames: summaryStats.validNames,
            invalidNames: summaryStats.invalidNames,
            warningNames: summaryStats.warningNames,
          },
          riskLevel: summaryStats.invalidNames > 0 ? 'medium' : 'low',
        });

        log.info('Name validation completed', {
          policyId: input.policyId,
          totalNames: summaryStats.totalNames,
          validNames: summaryStats.validNames,
          invalidNames: summaryStats.invalidNames,
          warningNames: summaryStats.warningNames,
        });

        return formatSuccessResponse({
          success: true,
          policyId: input.policyId,
          policyName: policy.name,
          validationResults,
          summary: summaryStats,
          compliance: {
            overallScore: Math.round((summaryStats.validNames / summaryStats.totalNames) * 100),
            strictCompliance: summaryStats.invalidNames === 0,
            recommendationsCount: Object.values(validationResults).filter(
              (r: unknown): r is { suggestions?: string[] } => 
                typeof r === 'object' && 
                r !== null && 
                'suggestions' in r && 
                Array.isArray((r as { suggestions?: unknown }).suggestions)
            ).length,
          },
          timestamp: new Date().toISOString(),
          message: `Validated ${summaryStats.totalNames} names: ${summaryStats.validNames} valid, ${summaryStats.invalidNames} invalid, ${summaryStats.warningNames} warnings`,
        });
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error validating names against policy', { error: errorMessage, policyId: input.policyId });
        
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to validate names against policy: ${errorMessage}`);
      }
    },
  });

  /**
   * List naming convention policies with filtering
   * 
   * Retrieves and filters naming convention policies with pagination support
   * and detailed policy information.
   * 
   * @tool list-naming-convention-policies
   * @category Policy Management
   * @permission policy_read
   */
  server.addTool({
    name: 'list-naming-convention-policies',
    description: 'List and filter naming convention policies',
    parameters: PolicyFiltersSchema,
    annotations: {
      title: 'List Naming Convention Policies',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log }) => {
      log.info('Listing naming convention policies', {
        filters: input,
        limit: input.limit,
        offset: input.offset,
      });

      try {
        const params = {
          ...input,
          limit: input.limit,
          offset: input.offset,
        };

        const response = await apiClient.get('/policies/naming-conventions', { params });
        
        if (!response.success) {
          throw new UserError(`Failed to list policies: ${response.error?.message || 'Unknown error'}`);
        }

        const policies = response.data || [];
        const metadata = response.metadata;

        // Calculate summary statistics
        const summaryStats = {
          totalPolicies: Array.isArray(policies) ? policies.length : 0,
          activePolicies: Array.isArray(policies) ? policies.filter((p: unknown) => 
            typeof p === 'object' && p !== null && 'active' in p && (p as { active: boolean }).active
          ).length : 0,
          inactivePolicies: Array.isArray(policies) ? policies.filter((p: unknown) => 
            typeof p === 'object' && p !== null && 'active' in p && !(p as { active: boolean }).active
          ).length : 0,
          enforcementLevels: Array.isArray(policies) 
            ? policies.reduce((acc: Record<string, number>, policy: unknown) => {
                if (typeof policy === 'object' && policy !== null && 'enforcementLevel' in policy) {
                  const level = (policy as { enforcementLevel: string }).enforcementLevel;
                  acc[level] = (acc[level] || 0) + 1;
                }
                return acc;
              }, {})
            : {},
          resourceTypeCoverage: Array.isArray(policies)
            ? new Set(policies.flatMap((p: unknown) => {
                if (typeof p === 'object' && p !== null && 'rules' in p) {
                  const rules = (p as { rules?: unknown[] }).rules;
                  if (Array.isArray(rules)) {
                    return rules.flatMap((r: unknown) => {
                      if (typeof r === 'object' && r !== null && 'resourceTypes' in r) {
                        const resourceTypes = (r as { resourceTypes?: unknown }).resourceTypes;
                        return Array.isArray(resourceTypes) ? resourceTypes : [];
                      }
                      return [];
                    });
                  }
                }
                return [];
              })).size
            : 0,
        };

        log.info('Successfully retrieved naming convention policies', {
          count: summaryStats.totalPolicies,
          active: summaryStats.activePolicies,
          inactive: summaryStats.inactivePolicies,
        });

        return formatSuccessResponse({
          success: true,
          policies: Array.isArray(policies) ? policies : [],
          summary: summaryStats,
          pagination: {
            total: metadata?.total || summaryStats.totalPolicies,
            limit: input.limit,
            offset: input.offset,
            hasMore: (metadata?.total || 0) > (input.offset + summaryStats.totalPolicies),
          },
          templates: {
            available: Object.keys(POLICY_TEMPLATES),
            count: Object.keys(POLICY_TEMPLATES).length,
          },
          timestamp: new Date().toISOString(),
        });
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error listing naming convention policies', { error: errorMessage });
        
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to list naming convention policies: ${errorMessage}`);
      }
    },
  });

  /**
   * Update naming convention policy
   * 
   * Updates an existing naming convention policy with new rules, settings,
   * or enforcement levels.
   * 
   * @tool update-naming-convention-policy
   * @category Policy Management
   * @permission policy_admin
   */
  server.addTool({
    name: 'update-naming-convention-policy',
    description: 'Update an existing naming convention policy',
    parameters: UpdateNamingPolicySchema,
    annotations: {
      title: 'Update Naming Convention Policy',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log }) => {
      log.info('Updating naming convention policy', {
        policyId: input.policyId,
        updates: Object.keys(input).filter(k => k !== 'policyId' && input[k as keyof typeof input] !== undefined),
      });

      try {
        // Get existing policy
        const existingResponse = await apiClient.get(`/policies/naming-conventions/${input.policyId}`);
        
        if (!existingResponse.success) {
          throw new UserError(`Policy not found: ${input.policyId}`);
        }

        const existingPolicy = existingResponse.data as Record<string, unknown>;
        const timestamp = new Date().toISOString();
        
        // Prepare update data
        const updateData: Record<string, unknown> = {
          ...(typeof existingPolicy === 'object' && existingPolicy !== null ? existingPolicy : {}),
          updatedAt: timestamp,
        };

        // Apply updates
        if (input.name !== undefined) updateData.name = input.name;
        if (input.description !== undefined) updateData.description = input.description;
        if (input.rules !== undefined) {
          // Validate new rules
          for (const rule of input.rules) {
            if (rule.patternType === PatternType.REGEX) {
              try {
                new RegExp(rule.pattern);
              } catch (error) {
                throw new UserError(`Invalid regex pattern in rule ${rule.id}: ${error instanceof Error ? error.message : 'Unknown error'}`);
              }
            }
          }
          updateData.rules = input.rules.sort((a, b) => (a.priority || 50) - (b.priority || 50));
          const existingMeta = (existingPolicy.metadata as Record<string, unknown>) || {};
          updateData.metadata = {
            ...existingMeta,
            rulesCount: input.rules.length,
            resourceTypesCount: new Set(input.rules.flatMap(r => r.resourceTypes)).size,
            averagePriority: input.rules.reduce((sum, r) => sum + (r.priority || 50), 0) / input.rules.length,
            lastRulesUpdate: timestamp,
          };
        }
        if (input.enforcementLevel !== undefined) updateData.enforcementLevel = input.enforcementLevel;
        if (input.active !== undefined) updateData.active = input.active;
        if (input.effectiveFrom !== undefined) updateData.effectiveFrom = input.effectiveFrom;
        if (input.effectiveUntil !== undefined) updateData.effectiveUntil = input.effectiveUntil;
        if (input.notificationSettings !== undefined) {
          const existingNotifications = (existingPolicy.notificationSettings as Record<string, unknown>) || {};
          updateData.notificationSettings = {
            ...existingNotifications,
            ...input.notificationSettings,
          };
        }
        if (input.metadata !== undefined) {
          const existingMetadata = (existingPolicy.metadata as Record<string, unknown>) || {};
          updateData.metadata = {
            ...existingMetadata,
            ...input.metadata,
            lastMetadataUpdate: timestamp,
          };
        }

        // Update policy
        const response = await apiClient.patch(`/policies/naming-conventions/${input.policyId}`, updateData);
        
        if (!response.success) {
          throw new UserError(`Failed to update policy: ${response.error?.message || 'Unknown error'}`);
        }

        const updatedPolicy = response.data as { name: string; [key: string]: unknown };

        // Log policy update audit event
        await auditLogger.logEvent({
          level: 'info',
          category: 'configuration',
          action: 'naming_policy_updated',
          resource: `policy:${input.policyId}`,
          success: true,
          details: {
            policyId: input.policyId,
            updatedFields: Object.keys(input).filter(k => k !== 'policyId' && input[k as keyof typeof input] !== undefined),
            rulesCount: input.rules?.length || (existingPolicy.rules as unknown[] | undefined)?.length || 0,
            enforcementLevel: input.enforcementLevel || (existingPolicy.enforcementLevel as string | undefined),
            active: input.active !== undefined ? input.active : (existingPolicy.active as boolean | undefined),
          },
          riskLevel: 'medium',
        });

        log.info('Successfully updated naming convention policy', {
          policyId: input.policyId,
          name: updatedPolicy.name,
          updatedFields: Object.keys(input).filter(k => k !== 'policyId' && input[k as keyof typeof input] !== undefined).length,
        });

        return formatSuccessResponse({
          success: true,
          policy: updatedPolicy,
          changes: {
            updatedFields: Object.keys(input).filter(k => k !== 'policyId' && input[k as keyof typeof input] !== undefined),
            timestamp,
            version: `${(existingPolicy.version as string | undefined) || '1.0.0'}-updated`,
          },
          auditTrail: {
            updatedAt: timestamp,
            action: 'policy_updated',
            policyId: input.policyId,
            fieldsChanged: Object.keys(input).filter(k => k !== 'policyId' && input[k as keyof typeof input] !== undefined).length,
          },
          message: `Naming convention policy "${updatedPolicy.name}" updated successfully`,
        });
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error updating naming convention policy', { error: errorMessage, policyId: input.policyId });
        
        // Log failure audit event
        await auditLogger.logEvent({
          level: 'error',
          category: 'configuration',
          action: 'naming_policy_update_failed',
          resource: `policy:${input.policyId}`,
          success: false,
          details: {
            policyId: input.policyId,
            error: errorMessage,
          },
          riskLevel: 'low',
        });
        
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to update naming convention policy: ${errorMessage}`);
      }
    },
  });

  /**
   * Get policy templates and examples
   * 
   * Retrieves available policy templates with detailed rule definitions
   * and usage examples for different organizational contexts.
   * 
   * @tool get-naming-policy-templates
   * @category Policy Management
   * @permission policy_read
   */
  server.addTool({
    name: 'get-naming-policy-templates',
    description: 'Get available naming convention policy templates and examples',
    parameters: z.object({
      category: z.string().optional().describe('Filter templates by category'),
      includeExamples: z.boolean().default(true).describe('Include usage examples'),
      includeRuleDetails: z.boolean().default(true).describe('Include detailed rule information'),
    }),
    annotations: {
      title: 'Get Naming Policy Templates',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log }) => {
      log.info('Retrieving naming policy templates', {
        category: input.category,
        includeExamples: input.includeExamples,
        includeRuleDetails: input.includeRuleDetails,
      });

      try {
        const filteredTemplates = Object.values(POLICY_TEMPLATES).filter(template =>
          !input.category || template.category === input.category
        );

        const templatesWithDetails = filteredTemplates.map(template => {
          const templateData: Record<string, unknown> = {
            ...template,
            rulesCount: template.rules.length,
            resourceTypes: new Set(template.rules.flatMap(r => r.resourceTypes)).size,
            enforcementLevels: template.rules.reduce((acc, rule) => {
              acc[rule.enforcementLevel] = (acc[rule.enforcementLevel] || 0) + 1;
              return acc;
            }, {} as Record<string, number>),
          };

          if (input.includeRuleDetails) {
            templateData.ruleDetails = template.rules.map(rule => ({
              id: rule.id,
              name: rule.name,
              description: rule.description,
              resourceTypes: rule.resourceTypes,
              patternType: rule.patternType,
              pattern: rule.pattern,
              enforcementLevel: rule.enforcementLevel,
              priority: rule.priority,
              tags: rule.tags,
            }));
          }

          if (input.includeExamples) {
            templateData.examples = {
              validNames: generateExampleNames(template.rules, true),
              invalidNames: generateExampleNames(template.rules, false),
              useCases: generateUseCases(template.category),
            };
          }

          return templateData;
        });

        const categories = Array.from(new Set(Object.values(POLICY_TEMPLATES).map(t => t.category)));
        const summary = {
          totalTemplates: filteredTemplates.length,
          categories,
          totalRules: filteredTemplates.reduce((sum, t) => sum + t.rules.length, 0),
          resourceTypesCovered: new Set(
            filteredTemplates.flatMap(t => t.rules.flatMap(r => r.resourceTypes))
          ).size,
        };

        log.info('Successfully retrieved naming policy templates', {
          templatesCount: templatesWithDetails.length,
          categoriesCount: categories.length,
          totalRules: summary.totalRules,
        });

        return formatSuccessResponse({
          success: true,
          templates: templatesWithDetails,
          summary,
          categories: categories.map(cat => ({
            name: cat,
            count: filteredTemplates.filter(t => t.category === cat).length,
            description: getCategoryDescription(cat),
          })),
          usage: {
            howToUse: 'Specify templateId in create-naming-convention-policy to apply template rules',
            customization: 'Template rules can be extended with additional custom rules',
            enforcement: 'Templates include recommended enforcement levels that can be adjusted',
          },
          timestamp: new Date().toISOString(),
        });
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error retrieving naming policy templates', { error: errorMessage });
        
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to retrieve naming policy templates: ${errorMessage}`);
      }
    },
  });

  /**
   * Delete naming convention policy
   * 
   * Safely deletes a naming convention policy with proper validation
   * and audit logging.
   * 
   * @tool delete-naming-convention-policy
   * @category Policy Management
   * @permission policy_admin
   */
  server.addTool({
    name: 'delete-naming-convention-policy',
    description: 'Delete a naming convention policy',
    parameters: z.object({
      policyId: z.string().min(1).describe('Policy ID to delete'),
      confirmDeletion: z.boolean().default(false).describe('Confirm policy deletion'),
    }),
    annotations: {
      title: 'Delete Naming Convention Policy',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log }) => {
      log.info('Deleting naming convention policy', { policyId: input.policyId });

      try {
        if (!input.confirmDeletion) {
          throw new UserError('Policy deletion requires explicit confirmation. Set confirmDeletion to true.');
        }

        // Get policy details before deletion
        const policyResponse = await apiClient.get(`/policies/naming-conventions/${input.policyId}`);
        
        if (!policyResponse.success) {
          throw new UserError(`Policy not found: ${input.policyId}`);
        }

        const policy = policyResponse.data as { 
          name: string; 
          rules?: unknown[]; 
          active: boolean; 
          enforcementLevel: string; 
          [key: string]: unknown 
        };

        // Delete policy
        const response = await apiClient.delete(`/policies/naming-conventions/${input.policyId}`);
        
        if (!response.success) {
          throw new UserError(`Failed to delete policy: ${response.error?.message || 'Unknown error'}`);
        }

        // Log policy deletion audit event
        await auditLogger.logEvent({
          level: 'warn',
          category: 'configuration',
          action: 'naming_policy_deleted',
          resource: `policy:${input.policyId}`,
          success: true,
          details: {
            policyId: input.policyId,
            policyName: policy.name,
            rulesCount: policy.rules?.length || 0,
            wasActive: policy.active,
            enforcementLevel: policy.enforcementLevel,
          },
          riskLevel: 'medium',
        });

        log.info('Successfully deleted naming convention policy', {
          policyId: input.policyId,
          name: policy.name,
        });

        return formatSuccessResponse({
          success: true,
          deletedPolicy: {
            id: input.policyId,
            name: policy.name,
            rulesCount: policy.rules?.length || 0,
            wasActive: policy.active,
          },
          auditTrail: {
            deletedAt: new Date().toISOString(),
            action: 'policy_deleted',
            policyId: input.policyId,
            confirmationRequired: true,
          },
          message: `Naming convention policy "${policy.name}" deleted successfully`,
        });
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error deleting naming convention policy', { error: errorMessage, policyId: input.policyId });
        
        // Log failure audit event
        await auditLogger.logEvent({
          level: 'error',
          category: 'configuration',
          action: 'naming_policy_deletion_failed',
          resource: `policy:${input.policyId}`,
          success: false,
          details: {
            policyId: input.policyId,
            error: errorMessage,
          },
          riskLevel: 'low',
        });
        
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to delete naming convention policy: ${errorMessage}`);
      }
    },
  });

  // Helper methods for template examples and descriptions
  const generateExampleNames = (rules: z.infer<typeof NamingRuleSchema>[], valid: boolean): Record<string, string[]> => {
    const examples: Record<string, string[]> = {};
    
    for (const resourceType of Object.values(ResourceType)) {
      const applicableRules = rules.filter(rule => rule.resourceTypes.includes(resourceType));
      if (applicableRules.length === 0) continue;

      examples[resourceType] = [];
      
      for (const rule of applicableRules.slice(0, 2)) {
        if (valid) {
          // Generate valid examples
          if (rule.patternType === PatternType.REGEX) {
            switch (resourceType) {
              case ResourceType.SCENARIO:
                examples[resourceType].push('OPS-DataSync-v1');
                break;
              case ResourceType.CONNECTION:
                examples[resourceType].push('api_prod_integration');
                break;
              default:
                examples[resourceType].push(`${resourceType}Example`);
            }
          }
        } else {
          // Generate invalid examples
          examples[resourceType].push('invalid name', 'temp123', '');
        }
      }
    }
    
    return examples;
  };

  const generateUseCases = (category: string): string[] => {
    switch (category) {
      case 'enterprise':
        return [
          'Large organizations with multiple departments',
          'Strict governance and compliance requirements',
          'Complex resource hierarchies and dependencies',
          'Audit and regulatory compliance needs',
        ];
      case 'startup':
        return [
          'Fast-moving development teams',
          'Flexible naming requirements',
          'Agile development processes',
          'Growth-oriented resource organization',
        ];
      case 'government':
        return [
          'Government agencies and departments',
          'Security classification requirements',
          'Regulatory compliance mandates',
          'Audit trail and transparency needs',
        ];
      default:
        return ['General purpose naming conventions'];
    }
  };

  const getCategoryDescription = (category: string): string => {
    switch (category) {
      case 'enterprise':
        return 'Comprehensive naming conventions for large enterprise organizations';
      case 'startup':
        return 'Flexible naming conventions optimized for agile startup environments';
      case 'government':
        return 'Strict naming conventions for government and regulatory compliance';
      default:
        return 'Standard naming conventions';
    }
  };

  componentLogger.info('Naming convention policy management tools added successfully');
}

export default addNamingConventionPolicyTools;