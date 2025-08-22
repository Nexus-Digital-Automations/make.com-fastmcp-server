/**
 * TypeScript type definitions for folders module
 * Extracted from original folders.ts on 2025-08-22T09:19:00.000Z
 */

import type { ToolContext } from '../../../types/index.js';

// Base interfaces for folders functionality
export interface FoldersConfig {
  enabled: boolean;
  settings: Record<string, unknown>;
  metadata?: {
    version: string;
    createdAt: Date;
    updatedAt?: Date;
  };
}

export interface FoldersContext extends Omit<ToolContext, 'config'> {
  config: FoldersConfig;
  // Add module-specific context properties
}

export interface FoldersResult {
  success: boolean;
  data?: unknown;
  message?: string;
  errors?: string[];
  metadata?: {
    operationId: string;
    timestamp: Date;
    duration?: number;
  };
}

// Make.com folder types
export interface MakeFolder {
  id: number;
  name: string;
  description?: string;
  parentId?: number;
  path: string;
  organizationId?: number;
  teamId?: number; 
  type: 'template' | 'scenario' | 'connection' | 'mixed';
  permissions: {
    read: string[];
    write: string[];
    admin: string[];
  };
  itemCount: {
    templates: number;
    scenarios: number;
    connections: number;
    subfolders: number;
    total: number;
  };
  metadata: {
    size: number; // bytes
    lastActivity: string;
    mostActiveItem?: {
      type: string;
      id: number;
      name: string;
      activity: number;
    };
  };
  createdAt: string;
  updatedAt: string;
  createdBy: number;
  createdByName: string;
}

export interface MakeDataStructure {
  id: number;
  name: string;
  description?: string;
  organizationId?: number;
  teamId?: number;
  specification: Array<{
    name: string;
    type: 'text' | 'number' | 'boolean' | 'date' | 'array' | 'collection';
    required?: boolean;
    default?: unknown;
    constraints?: {
      minLength?: number;
      maxLength?: number;
      minimum?: number;
      maximum?: number;
      pattern?: string;
      enum?: unknown[];
    };
    spec?: Array<unknown>; // For nested collections and arrays
  }>;
  strict: boolean;
  usage: {
    dataStoresCount: number;
    totalRecords: number;
    lastUsed?: string;
  };
  validation: {
    enabled: boolean;
    rules: string[];
    lastValidation?: string;
    validationErrors?: number;
  };
  createdAt: string;
  updatedAt: string;
  createdBy: number;
}

export interface MakeDataStore {
  id: number;
  name: string;
  description?: string;
  type: 'data_structure' | 'key_value' | 'queue' | 'cache';
  organizationId?: number;
  teamId?: number;
  structure: {
    fields?: Array<{
      name: string;
      type: 'string' | 'number' | 'boolean' | 'date' | 'object' | 'array';
      required: boolean;
      defaultValue?: unknown;
      validation?: {
        min?: number;
        max?: number;
        pattern?: string;
        enum?: unknown[];
      };
    }>;
    indexes?: Array<{
      fields: string[];
      unique: boolean;
      name: string;
    }>;
  };
  settings: {
    maxSize: number; // MB
    ttl?: number; // seconds
    autoCleanup: boolean;
    encryption: boolean;
    compression: boolean;
  };
  usage: {
    recordCount: number;
    sizeUsed: number; // bytes
    operationsToday: number;
    lastOperation: string;
  };
  permissions: {
    read: string[];
    write: string[];
    admin: string[];
  };
  createdAt: string;
  updatedAt: string;
  createdBy: number;
}

// Interface for recursive data structure field
export interface DataStructureField {
  name: string;
  type: 'text' | 'number' | 'boolean' | 'date' | 'array' | 'collection';
  required?: boolean;
  default?: unknown;
  constraints?: {
    minLength?: number;
    maxLength?: number;
    minimum?: number;
    maximum?: number;
    pattern?: string;
    enum?: unknown[];
  };
  spec?: DataStructureField[];
}

// Tool-specific request/response interfaces
export interface CreateFolderRequest {
  name: string;
  description?: string;
  parentId?: number;
  type: 'template' | 'scenario' | 'connection' | 'mixed';
  organizationId?: number;
  teamId?: number;
  permissions: {
    read: string[];
    write: string[];
    admin: string[];
  };
}

export interface CreateFolderResponse extends FoldersResult {
  data?: MakeFolder;
}

export interface ListFoldersRequest {
  parentId?: number;
  type?: 'template' | 'scenario' | 'connection' | 'mixed' | 'all';
  organizationId?: number;
  teamId?: number;
  searchQuery?: string;
  includeEmpty?: boolean;
  includeContents?: boolean;
  limit?: number;
  offset?: number;
  sortBy?: 'name' | 'createdAt' | 'updatedAt' | 'itemCount' | 'lastActivity';
  sortOrder?: 'asc' | 'desc';
}

export interface ListFoldersResponse extends FoldersResult {
  data?: {
    folders: MakeFolder[];
    pagination: {
      total: number;
      limit: number;
      offset: number;
      hasMore: boolean;
    };
  };
}

export interface GetFolderContentsRequest {
  folderId: number;
  includeSubfolders?: boolean;
  includeTemplates?: boolean;
  includeScenarios?: boolean;
  includeConnections?: boolean;
  limit?: number;
  offset?: number;
}

export interface GetFolderContentsResponse extends FoldersResult {
  data?: {
    folder: MakeFolder;
    contents: {
      subfolders: MakeFolder[];
      templates: unknown[];
      scenarios: unknown[];
      connections: unknown[];
    };
    pagination: {
      total: number;
      limit: number;
      offset: number;
      hasMore: boolean;
    };
  };
}

export interface MoveItemsRequest {
  items: Array<{
    type: 'template' | 'scenario' | 'connection' | 'folder';
    id: number;
  }>;
  targetFolderId?: number;
  copyInsteadOfMove?: boolean;
}

export interface MoveItemsResponse extends FoldersResult {
  data?: {
    movedItems: Array<{
      type: string;
      id: number;
      oldPath: string;
      newPath: string;
    }>;
  };
}

export interface CreateDataStoreRequest {
  name: string;
  description?: string;
  type: 'data_structure' | 'key_value' | 'queue' | 'cache';
  organizationId?: number;
  teamId?: number;
  structure?: {
    fields?: Array<{
      name: string;
      type: 'string' | 'number' | 'boolean' | 'date' | 'object' | 'array';
      required: boolean;
      defaultValue?: unknown;
      validation?: {
        min?: number;
        max?: number;
        pattern?: string;
        enum?: unknown[];
      };
    }>;
    indexes?: Array<{
      fields: string[];
      unique: boolean;
      name: string;
    }>;
  };
  settings: {
    maxSize: number;
    ttl?: number;
    autoCleanup: boolean;
    encryption: boolean;
    compression: boolean;
  };
  permissions: {
    read: string[];
    write: string[];
    admin: string[];
  };
}

export interface CreateDataStoreResponse extends FoldersResult {
  data?: MakeDataStore;
}

export interface ListDataStoresRequest {
  type?: 'data_structure' | 'key_value' | 'queue' | 'cache' | 'all';
  organizationId?: number;
  teamId?: number;
  searchQuery?: string;
  limit?: number;
  offset?: number;
  sortBy?: 'name' | 'createdAt' | 'updatedAt' | 'recordCount' | 'sizeUsed';
  sortOrder?: 'asc' | 'desc';
}

export interface ListDataStoresResponse extends FoldersResult {
  data?: {
    dataStores: MakeDataStore[];
    pagination: {
      total: number;
      limit: number;
      offset: number;
      hasMore: boolean;
    };
  };
}

export interface ListDataStructuresRequest {
  organizationId?: number;
  teamId?: number;
  searchQuery?: string;
  limit?: number;
  offset?: number;
  sortBy?: 'name' | 'createdAt' | 'updatedAt' | 'usage';
  sortOrder?: 'asc' | 'desc';
}

export interface ListDataStructuresResponse extends FoldersResult {
  data?: {
    dataStructures: MakeDataStructure[];
    pagination: {
      total: number;
      limit: number;
      offset: number;
      hasMore: boolean;
    };
  };
}

export interface GetDataStructureRequest {
  id: number;
}

export interface GetDataStructureResponse extends FoldersResult {
  data?: MakeDataStructure;
}

export interface CreateDataStructureRequest {
  name: string;
  description?: string;
  organizationId?: number;
  teamId?: number;
  specification: DataStructureField[];
  strict?: boolean;
  validation?: {
    enabled: boolean;
    rules: string[];
  };
}

export interface CreateDataStructureResponse extends FoldersResult {
  data?: MakeDataStructure;
}

export interface UpdateDataStructureRequest {
  id: number;
  name?: string;
  description?: string;
  specification?: DataStructureField[];
  strict?: boolean;
  validation?: {
    enabled: boolean;
    rules: string[];
  };
}

export interface UpdateDataStructureResponse extends FoldersResult {
  data?: MakeDataStructure;
}

export interface DeleteDataStructureRequest {
  id: number;
}

export interface DeleteDataStructureResponse extends FoldersResult {
  data?: {
    deleted: boolean;
    id: number;
  };
}

export interface GetDataStoreRequest {
  id: number;
}

export interface GetDataStoreResponse extends FoldersResult {
  data?: MakeDataStore;
}

export interface UpdateDataStoreRequest {
  id: number;
  name?: string;
  description?: string;
  settings?: Partial<MakeDataStore['settings']>;
  permissions?: Partial<MakeDataStore['permissions']>;
}

export interface UpdateDataStoreResponse extends FoldersResult {
  data?: MakeDataStore;
}

export interface DeleteDataStoreRequest {
  id: number;
}

export interface DeleteDataStoreResponse extends FoldersResult {
  data?: {
    deleted: boolean;
    id: number;
  };
}

// Event types for module communication
export type FoldersEvent = 
  | { type: 'create_folder'; payload: CreateFolderRequest }
  | { type: 'list_folders'; payload: ListFoldersRequest }
  | { type: 'get_folder_contents'; payload: GetFolderContentsRequest }
  | { type: 'move_items'; payload: MoveItemsRequest }
  | { type: 'create_data_store'; payload: CreateDataStoreRequest }
  | { type: 'list_data_stores'; payload: ListDataStoresRequest }
  | { type: 'list_data_structures'; payload: ListDataStructuresRequest }
  | { type: 'get_data_structure'; payload: GetDataStructureRequest }
  | { type: 'create_data_structure'; payload: CreateDataStructureRequest }
  | { type: 'update_data_structure'; payload: UpdateDataStructureRequest }
  | { type: 'delete_data_structure'; payload: DeleteDataStructureRequest }
  | { type: 'get_data_store'; payload: GetDataStoreRequest }
  | { type: 'update_data_store'; payload: UpdateDataStoreRequest }
  | { type: 'delete_data_store'; payload: DeleteDataStoreRequest }
  | { type: 'module_error'; payload: { error: string; context?: unknown } };

// Module state interface
export interface FoldersState {
  initialized: boolean;
  config: FoldersConfig;
  statistics: {
    totalOperations: number;
    successfulOperations: number;
    failedOperations: number;
    lastOperation?: Date;
  };
}
