/**
 * Input validation utilities for Make.com FastMCP Server
 * Provides common validation functions and schemas
 */

import { z } from 'zod';

// Common validation schemas
export const idSchema = z.number().int().positive();
export const nameSchema = z.string().min(1).max(255);
export const emailSchema = z.string().email();
export const urlSchema = z.string().url();
export const teamIdSchema = z.number().int().positive().optional();
export const organizationIdSchema = z.number().int().positive().optional();

// Pagination schemas
export const paginationSchema = z.object({
  page: z.number().int().min(1).default(1),
  limit: z.number().int().min(1).max(100).default(20),
  sortBy: z.string().optional(),
  sortOrder: z.enum(['asc', 'desc']).default('asc'),
});

// Date range schema
export const dateRangeSchema = z.object({
  startDate: z.string().datetime().optional(),
  endDate: z.string().datetime().optional(),
});

// Scenario schemas
export const scenarioCreateSchema = z.object({
  name: nameSchema,
  teamId: z.number().int().positive(),
  folderId: z.number().int().positive().optional(),
  blueprint: z.any(),
  scheduling: z.object({
    type: z.enum(['immediate', 'indefinitely', 'on-demand']),
    interval: z.number().int().positive().optional(),
  }),
  isActive: z.boolean().default(true),
});

export const scenarioUpdateSchema = z.object({
  name: nameSchema.optional(),
  folderId: z.number().int().positive().optional(),
  blueprint: z.any().optional(),
  scheduling: z.object({
    type: z.enum(['immediate', 'indefinitely', 'on-demand']),
    interval: z.number().int().positive().optional(),
  }).optional(),
  isActive: z.boolean().optional(),
});

// Connection schemas
export const connectionCreateSchema = z.object({
  name: nameSchema,
  accountName: z.string().min(1).max(255),
  service: z.string().min(1).max(100),
  metadata: z.record(z.any()),
});

export const connectionUpdateSchema = z.object({
  name: nameSchema.optional(),
  accountName: z.string().min(1).max(255).optional(),
  metadata: z.record(z.any()).optional(),
});

// Template schemas
export const templateCreateSchema = z.object({
  name: nameSchema,
  description: z.string().max(1000).optional(),
  category: z.string().max(100).optional(),
  blueprint: z.any(),
  tags: z.array(z.string()).default([]),
  isPublic: z.boolean().default(false),
});

export const templateUpdateSchema = z.object({
  name: nameSchema.optional(),
  description: z.string().max(1000).optional(),
  category: z.string().max(100).optional(),
  blueprint: z.any().optional(),
  tags: z.array(z.string()).optional(),
  isPublic: z.boolean().optional(),
});

// User schemas
export const userCreateSchema = z.object({
  name: nameSchema,
  email: emailSchema,
  role: z.enum(['admin', 'member', 'viewer']),
  teamId: z.number().int().positive(),
  organizationId: z.number().int().positive().optional(),
  permissions: z.array(z.string()).default([]),
});

export const userUpdateSchema = z.object({
  name: nameSchema.optional(),
  email: emailSchema.optional(),
  role: z.enum(['admin', 'member', 'viewer']).optional(),
  permissions: z.array(z.string()).optional(),
  isActive: z.boolean().optional(),
});

// Webhook schemas
export const webhookCreateSchema = z.object({
  name: nameSchema,
  url: urlSchema,
  method: z.enum(['GET', 'POST', 'PUT', 'DELETE']).default('POST'),
  headers: z.record(z.string()).optional(),
  scenarioId: z.number().int().positive().optional(),
  isActive: z.boolean().default(true),
});

export const webhookUpdateSchema = z.object({
  name: nameSchema.optional(),
  url: urlSchema.optional(),
  method: z.enum(['GET', 'POST', 'PUT', 'DELETE']).optional(),
  headers: z.record(z.string()).optional(),
  isActive: z.boolean().optional(),
});

// Variable schemas
export const variableCreateSchema = z.object({
  name: z.string().min(1).max(100).regex(/^[a-zA-Z_][a-zA-Z0-9_]*$/),
  value: z.any(),
  type: z.enum(['string', 'number', 'boolean', 'json']),
  scope: z.enum(['global', 'team', 'scenario']),
  isEncrypted: z.boolean().default(false),
});

export const variableUpdateSchema = z.object({
  name: z.string().min(1).max(100).regex(/^[a-zA-Z_][a-zA-Z0-9_]*$/).optional(),
  value: z.any().optional(),
  type: z.enum(['string', 'number', 'boolean', 'json']).optional(),
  isEncrypted: z.boolean().optional(),
});

// Validation helper functions
export function validateId(id: any): number {
  const result = idSchema.safeParse(id);
  if (!result.success) {
    throw new Error(`Invalid ID: ${result.error.message}`);
  }
  return result.data;
}

export function validatePagination(params: any): z.infer<typeof paginationSchema> {
  const result = paginationSchema.safeParse(params);
  if (!result.success) {
    throw new Error(`Invalid pagination parameters: ${result.error.message}`);
  }
  return result.data;
}

export function validateDateRange(params: any): z.infer<typeof dateRangeSchema> {
  const result = dateRangeSchema.safeParse(params);
  if (!result.success) {
    throw new Error(`Invalid date range: ${result.error.message}`);
  }
  
  // Additional validation: start date should be before end date
  if (result.data.startDate && result.data.endDate) {
    if (new Date(result.data.startDate) >= new Date(result.data.endDate)) {
      throw new Error('Start date must be before end date');
    }
  }
  
  return result.data;
}

export function sanitizeString(str: string): string {
  return str.trim().replace(/[<>"'&]/g, '');
}

export function isValidEmail(email: string): boolean {
  return emailSchema.safeParse(email).success;
}

export function isValidUrl(url: string): boolean {
  return urlSchema.safeParse(url).success;
}

// Type-safe validation wrapper
export function validateSchema<T>(schema: z.ZodSchema<T>, data: unknown): T {
  const result = schema.safeParse(data);
  if (!result.success) {
    throw new Error(`Validation failed: ${result.error.message}`);
  }
  return result.data;
}