/**
 * Enhanced Security-Focused Input validation utilities for Make.com FastMCP Server
 * Provides enterprise-grade validation with XSS/injection prevention
 * Phase 2 Security Enhancement Implementation
 */

import { z } from "zod";
// DOMPurify import removed as it's not currently used
// import DOMPurify from 'isomorphic-dompurify';
import validator from "validator";

// Enhanced security-focused string sanitization
export function sanitizeString(str: string): string {
  // Remove dangerous patterns first
  let sanitized = str.trim();

  // Remove dangerous protocols
  sanitized = sanitized.replace(/javascript:/gi, "");
  sanitized = sanitized.replace(/data:.*base64/gi, "");
  sanitized = sanitized.replace(/vbscript:/gi, "");

  // Replace script tags while preserving inner content
  sanitized = sanitized.replace(
    /<script[^>]*>(.*?)<\/script>/gi,
    "script$1/script",
  );

  // Remove HTML tags but preserve text content
  sanitized = sanitized.replace(/<[^>]+>/g, "");

  // Remove dangerous characters while preserving safe alphanumeric content
  // eslint-disable-next-line no-control-regex
  sanitized = sanitized.replace(/[<>"'&\x00-\x1F\x7F]/g, "");

  return sanitized;
}

// Enhanced security string schema with XSS prevention and default max length
export const secureStringSchema = z
  .string()
  .min(1, "Field cannot be empty")
  .max(1000, "Field exceeds maximum length")
  .refine((val) => !/<script|javascript:|data:|vbscript:/i.test(val), {
    message: "Potentially malicious content detected",
  })
  .refine((val) => !validator.contains(val, "\u0000"), {
    message: "Null bytes not allowed",
  })
  .transform((val) => sanitizeString(val));

// Factory function for secure string schema with custom max length
export const createSecureStringSchema = (
  maxLength: number = 1000,
): z.ZodSchema<string> =>
  z
    .string()
    .min(1, "Field cannot be empty")
    .max(maxLength, `Field exceeds maximum length of ${maxLength}`)
    .refine((val) => !/<script|javascript:|data:|vbscript:/i.test(val), {
      message: "Potentially malicious content detected",
    })
    .refine((val) => !validator.contains(val, "\u0000"), {
      message: "Null bytes not allowed",
    })
    .transform((val) => sanitizeString(val));

// Secure ID schema with enhanced validation
export const secureIdSchema = z
  .union([
    z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
    z
      .string()
      .regex(/^\d+$/)
      .transform((val) => parseInt(val, 10)),
  ])
  .refine((val) => val > 0 && val <= Number.MAX_SAFE_INTEGER, {
    message: "Invalid ID format",
  });

// Common validation schemas
export const idSchema = z.number().int().positive();
export const nameSchema = z.string().min(1).max(255);
export const emailSchema = z.string().email();
export const urlSchema = z
  .string()
  .url()
  .refine((url) => url.startsWith("http://") || url.startsWith("https://"), {
    message: "Only HTTP and HTTPS URLs are allowed",
  });
export const teamIdSchema = z.number().int().positive().optional();
export const organizationIdSchema = z.number().int().positive().optional();

// Pagination schemas
export const paginationSchema = z.object({
  page: z.number().int().min(1).default(1),
  limit: z.number().int().min(1).max(100).default(20),
  sortBy: z.string().optional(),
  sortOrder: z.enum(["asc", "desc"]).default("asc"),
});

// Date range schema
export const dateRangeSchema = z.object({
  startDate: z.string().datetime().optional(),
  endDate: z.string().datetime().optional(),
});

// Enhanced secure scenario schemas with deep validation
export const secureScenarioCreateSchema = z
  .object({
    name: secureStringSchema,
    teamId: secureIdSchema,
    folderId: secureIdSchema.optional(),
    blueprint: z
      .unknown()
      .refine(
        (val) => {
          const str = JSON.stringify(val);
          return str.length <= 1024 * 1024; // 1MB limit
        },
        { message: "Blueprint payload too large" },
      )
      .refine(
        (val) => {
          const str = JSON.stringify(val);
          return !/<script|javascript:|data:|vbscript:/i.test(str);
        },
        { message: "Blueprint contains potentially malicious content" },
      ),
    scheduling: z.object({
      type: z.enum(["immediate", "indefinitely", "on-demand"]),
      interval: z.number().int().positive().max(86400).optional(), // Max 24 hours
    }),
    isActive: z.boolean().default(true),
    metadata: z
      .record(z.string(), z.unknown())
      .refine((val) => Object.keys(val).length <= 50, {
        message: "Too many metadata fields",
      })
      .optional(),
  })
  .strict(); // Prevent additional properties

// Legacy schema for backward compatibility
export const scenarioCreateSchema = secureScenarioCreateSchema;

export const secureScenarioUpdateSchema = z
  .object({
    name: secureStringSchema.optional(),
    folderId: secureIdSchema.optional(),
    blueprint: z
      .unknown()
      .refine(
        (val) => {
          const str = JSON.stringify(val);
          return str.length <= 1024 * 1024;
        },
        { message: "Blueprint payload too large" },
      )
      .refine(
        (val) => {
          const str = JSON.stringify(val);
          return !/<script|javascript:|data:|vbscript:/i.test(str);
        },
        { message: "Blueprint contains potentially malicious content" },
      )
      .optional(),
    scheduling: z
      .object({
        type: z.enum(["immediate", "indefinitely", "on-demand"]),
        interval: z.number().int().positive().max(86400).optional(),
      })
      .optional(),
    isActive: z.boolean().optional(),
    metadata: z
      .record(z.string(), z.unknown())
      .refine((val) => Object.keys(val).length <= 50)
      .optional(),
  })
  .strict();

export const scenarioUpdateSchema = secureScenarioUpdateSchema;

// Enhanced secure connection schemas
export const secureConnectionCreateSchema = z
  .object({
    name: secureStringSchema,
    accountName: createSecureStringSchema(255),
    service: createSecureStringSchema(100).refine(
      (val) => /^[a-zA-Z0-9_-]+$/.test(val),
      {
        message:
          "Service name can only contain alphanumeric characters, underscores, and hyphens",
      },
    ),
    credentials: z
      .record(z.string(), z.unknown())
      .refine((val) => Object.keys(val).length <= 20, {
        message: "Too many credential fields",
      })
      .optional(),
    metadata: z
      .record(z.string(), z.unknown())
      .refine((val) => Object.keys(val).length <= 30)
      .optional(),
  })
  .strict();

export const connectionCreateSchema = secureConnectionCreateSchema;

export const secureConnectionUpdateSchema = z
  .object({
    name: secureStringSchema.optional(),
    accountName: createSecureStringSchema(255).optional(),
    credentials: z
      .record(z.string(), z.unknown())
      .refine((val) => Object.keys(val).length <= 20)
      .optional(),
    metadata: z
      .record(z.string(), z.unknown())
      .refine((val) => Object.keys(val).length <= 30)
      .optional(),
  })
  .strict();

export const connectionUpdateSchema = secureConnectionUpdateSchema;

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
  role: z.enum(["admin", "member", "viewer"]),
  teamId: z.number().int().positive(),
  organizationId: z.number().int().positive().optional(),
  permissions: z.array(z.string()).default([]),
});

export const userUpdateSchema = z.object({
  name: nameSchema.optional(),
  email: emailSchema.optional(),
  role: z.enum(["admin", "member", "viewer"]).optional(),
  permissions: z.array(z.string()).optional(),
  isActive: z.boolean().optional(),
});

// Webhook schemas
export const webhookCreateSchema = z.object({
  name: nameSchema,
  url: urlSchema,
  method: z.enum(["GET", "POST", "PUT", "DELETE"]).default("POST"),
  headers: z.record(z.string(), z.string()).optional(),
  scenarioId: z.number().int().positive().optional(),
  isActive: z.boolean().default(true),
});

export const webhookUpdateSchema = z.object({
  name: nameSchema.optional(),
  url: urlSchema.optional(),
  method: z.enum(["GET", "POST", "PUT", "DELETE"]).optional(),
  headers: z.record(z.string(), z.string()).optional(),
  isActive: z.boolean().optional(),
});

// Variable schemas
export const variableCreateSchema = z.object({
  name: z
    .string()
    .min(1)
    .max(100)
    .regex(/^[a-zA-Z_][a-zA-Z0-9_]*$/),
  value: z.any(),
  type: z.enum(["string", "number", "boolean", "json"]),
  scope: z.enum(["global", "team", "scenario"]),
  isEncrypted: z.boolean().default(false),
});

export const variableUpdateSchema = z.object({
  name: z
    .string()
    .min(1)
    .max(100)
    .regex(/^[a-zA-Z_][a-zA-Z0-9_]*$/)
    .optional(),
  value: z.any().optional(),
  type: z.enum(["string", "number", "boolean", "json"]).optional(),
  isEncrypted: z.boolean().optional(),
});

// Validation helper functions
export function validateId(id: unknown): number {
  const result = idSchema.safeParse(id);
  if (!result.success) {
    throw new Error(`Invalid ID: ${result.error.message}`);
  }
  return result.data;
}

export function validatePagination(
  params: unknown,
): z.infer<typeof paginationSchema> {
  const result = paginationSchema.safeParse(params);
  if (!result.success) {
    throw new Error(`Invalid pagination parameters: ${result.error.message}`);
  }
  return result.data;
}

export function validateDateRange(
  params: unknown,
): z.infer<typeof dateRangeSchema> {
  const result = dateRangeSchema.safeParse(params);
  if (!result.success) {
    throw new Error(`Invalid date range: ${result.error.message}`);
  }

  // Additional validation: start date should be before end date
  if (result.data.startDate && result.data.endDate) {
    if (new Date(result.data.startDate) >= new Date(result.data.endDate)) {
      throw new Error("Start date must be before end date");
    }
  }

  return result.data;
}

// SQL injection prevention for search terms
export const secureSearchSchema = z
  .string()
  .max(500, "Search term too long")
  .refine(
    (val) =>
      !/(union|select|insert|update|delete|drop|create|alter|exec|execute)\s/i.test(
        val,
      ),
    {
      message: "Search term contains potentially dangerous SQL keywords",
    },
  )
  .transform((val) => sanitizeString(val));

// File upload validation
export const fileUploadSchema = z.object({
  filename: z
    .string()
    .max(255, "Filename too long")
    .refine(
      (val) =>
        !new RegExp(
          '[\\/<>:"|?*' +
            String.fromCharCode(0) +
            "-" +
            String.fromCharCode(31) +
            "]",
        ).test(val),
      {
        message: "Filename contains invalid characters",
      },
    )
    .refine((val) => !/(\.\.|\/\.\.|\.\.\/)/g.test(val), {
      message: "Path traversal patterns not allowed",
    }),
  size: z.number().max(50 * 1024 * 1024, "File too large (max 50MB)"),
  mimeType: z
    .string()
    .refine(
      (val) =>
        /^(image|text|application\/(json|pdf|zip|tar|gzip))\//i.test(val),
      {
        message: "File type not allowed",
      },
    ),
});

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

// Type guard utilities for API responses
export function isValidRecord(data: unknown): data is Record<string, unknown> {
  return typeof data === "object" && data !== null && !Array.isArray(data);
}

export function isValidArray(data: unknown): data is unknown[] {
  return Array.isArray(data);
}

export function safeGetRecord(data: unknown): Record<string, unknown> {
  return isValidRecord(data) ? data : {};
}

export function safeGetArray(data: unknown): unknown[] {
  return isValidArray(data) ? data : [];
}

export function safeGetProperty<T>(
  obj: Record<string, unknown>,
  key: string,
  defaultValue: T,
): T {
  const value = obj[key];
  return value !== undefined ? (value as T) : defaultValue;
}

// Helper for logging without exposing undefined values
export function safeLogObject(
  obj: Record<string, unknown>,
): Record<string, unknown> {
  const logSafe: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj)) {
    logSafe[key] = value ?? null;
  }
  return logSafe;
}
