/**
 * Data Store Management for folders module
 * Handles all data store operations and business logic
 * Generated on 2025-08-22T09:20:06.377Z
 */

import type { 
  FoldersResult,
  CreateDataStoreRequest,
  ListDataStoresRequest,
  GetDataStoreRequest,
  UpdateDataStoreRequest,
  DeleteDataStoreRequest,
  MakeDataStore
} from '../types/index.js';

import logger from '../../../lib/logger.js';
import { MakeApiClient } from '../../../lib/make-api-client.js';

/**
 * DataStore Manager class
 * Handles all data store-related operations
 */
export class DataStoreManager {
  private readonly apiClient: MakeApiClient;

  constructor(apiClient: MakeApiClient) {
    this.apiClient = apiClient;
  }

  /**
   * createDataStore operation handler
   */
  async createDataStore(request: unknown): Promise<FoldersResult> {
    const operationId = this.generateOperationId();
    const startTime = Date.now();

    try {
      logger.info(`Starting createDataStore operation`, {
        operationId,
        module: 'folders',
        operation: 'createDataStore'
      });

      // Implement createDataStore business logic here
      const result = await this.executeCreateDataStore(request);

      logger.info(`createDataStore operation completed successfully`, {
        operationId,
        module: 'folders',
        operation: 'createDataStore',
        duration: Date.now() - startTime
      });

      return {
        success: true,
        data: result,
        message: 'createDataStore completed successfully',
        metadata: {
          operationId,
          timestamp: new Date(),
          duration: Date.now() - startTime
        }
      };
    } catch (error) {
      logger.error(`createDataStore operation failed`, {
        operationId,
        module: 'folders',
        operation: 'createDataStore',
        error: error instanceof Error ? error.message : String(error),
        duration: Date.now() - startTime
      });

      return {
        success: false,
        message: `createDataStore operation failed`,
        errors: [error instanceof Error ? error.message : String(error)],
        metadata: {
          operationId,
          timestamp: new Date(),
          duration: Date.now() - startTime
        }
      };
    }
  }

  /**
   * Execute createDataStore business logic
   */
  private async executeCreateDataStore(request: unknown): Promise<MakeDataStore> {
    // Validate request as CreateDataStoreRequest
    const dataStoreRequest = request as CreateDataStoreRequest;
    const {
      name,
      description,
      type,
      organizationId,
      teamId,
      structure,
      settings,
      permissions
    } = dataStoreRequest;

    if (!name || !type || !settings || !permissions) {
      throw new Error('Name, type, settings, and permissions are required for data store creation');
    }

    if (!['data_structure', 'key_value', 'queue', 'cache'].includes(type)) {
      throw new Error(`Invalid data store type: ${type}. Must be one of: data_structure, key_value, queue, cache`);
    }

    try {
      const dataStoreData = {
        name,
        description,
        type,
        organizationId,
        teamId,
        structure: {
          fields: structure?.fields || [],
          indexes: structure?.indexes || []
        },
        settings: {
          maxSize: settings.maxSize,
          ttl: settings.ttl,
          autoCleanup: settings.autoCleanup,
          encryption: settings.encryption,
          compression: settings.compression
        },
        permissions: {
          read: permissions.read || [],
          write: permissions.write || [],
          admin: permissions.admin || []
        }
      };

      // Determine appropriate endpoint based on context
      let endpoint = '/data-stores';
      if (organizationId) {
        endpoint = `/organizations/${organizationId}/data-stores`;
      } else if (teamId) {
        endpoint = `/teams/${teamId}/data-stores`;
      }

      const response = await this.apiClient.post(endpoint, dataStoreData);

      if (!response.success) {
        throw new Error(`Failed to create data store: ${response.error?.message || 'Unknown error'}`);
      }

      const dataStore = response.data as MakeDataStore;
      if (!dataStore) {
        throw new Error('Data store creation failed - no data returned');
      }

      logger.info('Successfully created data store', {
        dataStoreId: dataStore.id,
        name: dataStore.name,
        type: dataStore.type,
        organizationId: dataStore.organizationId,
        teamId: dataStore.teamId,
        module: 'folders'
      });

      return dataStore;
    } catch (error) {
      logger.error('Failed to create data store', {
        error: error instanceof Error ? error.message : String(error),
        request: dataStoreRequest,
        module: 'folders'
      });
      throw error;
    }
  }

  /**
   * listDataStores operation handler
   */
  async listDataStores(request: unknown): Promise<FoldersResult> {
    const operationId = this.generateOperationId();
    const startTime = Date.now();

    try {
      logger.info(`Starting listDataStores operation`, {
        operationId,
        module: 'folders',
        operation: 'listDataStores'
      });

      // Implement listDataStores business logic here
      const result = await this.executeListDataStores(request);

      logger.info(`listDataStores operation completed successfully`, {
        operationId,
        module: 'folders',
        operation: 'listDataStores',
        duration: Date.now() - startTime
      });

      return {
        success: true,
        data: result,
        message: 'listDataStores completed successfully',
        metadata: {
          operationId,
          timestamp: new Date(),
          duration: Date.now() - startTime
        }
      };
    } catch (error) {
      logger.error(`listDataStores operation failed`, {
        operationId,
        module: 'folders',
        operation: 'listDataStores',
        error: error instanceof Error ? error.message : String(error),
        duration: Date.now() - startTime
      });

      return {
        success: false,
        message: `listDataStores operation failed`,
        errors: [error instanceof Error ? error.message : String(error)],
        metadata: {
          operationId,
          timestamp: new Date(),
          duration: Date.now() - startTime
        }
      };
    }
  }

  /**
   * Execute listDataStores business logic
   */
  private async executeListDataStores(request: unknown): Promise<{ dataStores: MakeDataStore[]; pagination: { total: number; limit: number; offset: number; hasMore: boolean } }> {
    // Validate request as ListDataStoresRequest
    const listRequest = request as ListDataStoresRequest;
    const {
      type = 'all',
      organizationId,
      teamId,
      searchQuery,
      limit = 50,
      offset = 0,
      sortBy = 'name',
      sortOrder = 'asc'
    } = listRequest;

    try {
      // Build query parameters
      const params: Record<string, unknown> = {
        limit,
        offset,
        sortBy,
        sortOrder,
      };

      if (type !== 'all') {params.type = type;}
      if (organizationId) {params.organizationId = organizationId;}
      if (teamId) {params.teamId = teamId;}
      if (searchQuery) {params.search = searchQuery;}

      const response = await this.apiClient.get('/data-stores', { params });

      if (!response.success) {
        throw new Error(`Failed to list data stores: ${response.error?.message || 'Unknown error'}`);
      }

      const dataStores = response.data as MakeDataStore[] || [];
      const metadata = response.metadata;

      logger.info('Successfully retrieved data stores', {
        count: dataStores.length,
        total: metadata?.total,
        type,
        module: 'folders'
      });

      return {
        dataStores,
        pagination: {
          total: metadata?.total || dataStores.length,
          limit,
          offset,
          hasMore: (offset + dataStores.length) < (metadata?.total || dataStores.length)
        }
      };
    } catch (error) {
      logger.error('Failed to list data stores', {
        error: error instanceof Error ? error.message : String(error),
        request: listRequest,
        module: 'folders'
      });
      throw error;
    }
  }

  /**
   * getDataStore operation handler
   */
  async getDataStore(request: unknown): Promise<FoldersResult> {
    const operationId = this.generateOperationId();
    const startTime = Date.now();

    try {
      logger.info(`Starting getDataStore operation`, {
        operationId,
        module: 'folders',
        operation: 'getDataStore'
      });

      // Implement getDataStore business logic here
      const result = await this.executeGetDataStore(request);

      logger.info(`getDataStore operation completed successfully`, {
        operationId,
        module: 'folders',
        operation: 'getDataStore',
        duration: Date.now() - startTime
      });

      return {
        success: true,
        data: result,
        message: 'getDataStore completed successfully',
        metadata: {
          operationId,
          timestamp: new Date(),
          duration: Date.now() - startTime
        }
      };
    } catch (error) {
      logger.error(`getDataStore operation failed`, {
        operationId,
        module: 'folders',
        operation: 'getDataStore',
        error: error instanceof Error ? error.message : String(error),
        duration: Date.now() - startTime
      });

      return {
        success: false,
        message: `getDataStore operation failed`,
        errors: [error instanceof Error ? error.message : String(error)],
        metadata: {
          operationId,
          timestamp: new Date(),
          duration: Date.now() - startTime
        }
      };
    }
  }

  /**
   * Execute getDataStore business logic
   */
  private async executeGetDataStore(request: unknown): Promise<MakeDataStore> {
    // Validate request as GetDataStoreRequest
    const getRequest = request as GetDataStoreRequest;
    const { id } = getRequest;

    if (!id) {
      throw new Error('Data store ID is required');
    }

    try {
      const response = await this.apiClient.get(`/data-stores/${id}`);

      if (!response.success) {
        throw new Error(`Failed to get data store: ${response.error?.message || 'Unknown error'}`);
      }

      const dataStore = response.data as MakeDataStore;
      if (!dataStore) {
        throw new Error(`Data store with ID ${id} not found`);
      }

      logger.info('Successfully retrieved data store', {
        dataStoreId: dataStore.id,
        name: dataStore.name,
        type: dataStore.type,
        recordCount: dataStore.usage.recordCount,
        sizeUsed: dataStore.usage.sizeUsed,
        organizationId: dataStore.organizationId,
        teamId: dataStore.teamId,
        module: 'folders'
      });

      return dataStore;
    } catch (error) {
      logger.error('Failed to get data store', {
        error: error instanceof Error ? error.message : String(error),
        dataStoreId: id,
        module: 'folders'
      });
      throw error;
    }
  }

  /**
   * updateDataStore operation handler
   */
  async updateDataStore(request: unknown): Promise<FoldersResult> {
    const operationId = this.generateOperationId();
    const startTime = Date.now();

    try {
      logger.info(`Starting updateDataStore operation`, {
        operationId,
        module: 'folders',
        operation: 'updateDataStore'
      });

      // Implement updateDataStore business logic here
      const result = await this.executeUpdateDataStore(request);

      logger.info(`updateDataStore operation completed successfully`, {
        operationId,
        module: 'folders',
        operation: 'updateDataStore',
        duration: Date.now() - startTime
      });

      return {
        success: true,
        data: result,
        message: 'updateDataStore completed successfully',
        metadata: {
          operationId,
          timestamp: new Date(),
          duration: Date.now() - startTime
        }
      };
    } catch (error) {
      logger.error(`updateDataStore operation failed`, {
        operationId,
        module: 'folders',
        operation: 'updateDataStore',
        error: error instanceof Error ? error.message : String(error),
        duration: Date.now() - startTime
      });

      return {
        success: false,
        message: `updateDataStore operation failed`,
        errors: [error instanceof Error ? error.message : String(error)],
        metadata: {
          operationId,
          timestamp: new Date(),
          duration: Date.now() - startTime
        }
      };
    }
  }

  /**
   * Execute updateDataStore business logic
   */
  private async executeUpdateDataStore(request: unknown): Promise<MakeDataStore> {
    // Validate request as UpdateDataStoreRequest
    const updateRequest = request as UpdateDataStoreRequest;
    const {
      id,
      name,
      description,
      settings,
      permissions
    } = updateRequest;

    if (!id) {
      throw new Error('Data store ID is required for update');
    }

    try {
      // Build update payload - only include provided fields
      const updateData: Record<string, unknown> = {};
      
      if (name !== undefined) {updateData.name = name;}
      if (description !== undefined) {updateData.description = description;}
      if (settings !== undefined) {updateData.settings = settings;}
      if (permissions !== undefined) {updateData.permissions = permissions;}

      if (Object.keys(updateData).length === 0) {
        throw new Error('At least one field must be provided for update');
      }

      // Validate settings if provided
      if (settings) {
        if (settings.maxSize !== undefined && settings.maxSize <= 0) {
          throw new Error('Max size must be greater than 0');
        }
        if (settings.ttl !== undefined && settings.ttl < 0) {
          throw new Error('TTL cannot be negative');
        }
      }

      // Validate permissions if provided
      if (permissions) {
        const permissionTypes = ['read', 'write', 'admin'] as const;
        for (const type of permissionTypes) {
          if (permissions[type] !== undefined && !Array.isArray(permissions[type])) {
            throw new Error(`Permission ${type} must be an array`);
          }
        }
      }

      const response = await this.apiClient.patch(`/data-stores/${id}`, updateData);

      if (!response.success) {
        throw new Error(`Failed to update data store: ${response.error?.message || 'Unknown error'}`);
      }

      const dataStore = response.data as MakeDataStore;
      if (!dataStore) {
        throw new Error('Data store update failed - no data returned');
      }

      logger.info('Successfully updated data store', {
        dataStoreId: dataStore.id,
        name: dataStore.name,
        type: dataStore.type,
        updatedFields: Object.keys(updateData),
        module: 'folders'
      });

      return dataStore;
    } catch (error) {
      logger.error('Failed to update data store', {
        error: error instanceof Error ? error.message : String(error),
        dataStoreId: id,
        request: updateRequest,
        module: 'folders'
      });
      throw error;
    }
  }

  /**
   * deleteDataStore operation handler
   */
  async deleteDataStore(request: unknown): Promise<FoldersResult> {
    const operationId = this.generateOperationId();
    const startTime = Date.now();

    try {
      logger.info(`Starting deleteDataStore operation`, {
        operationId,
        module: 'folders',
        operation: 'deleteDataStore'
      });

      // Implement deleteDataStore business logic here
      const result = await this.executeDeleteDataStore(request);

      logger.info(`deleteDataStore operation completed successfully`, {
        operationId,
        module: 'folders',
        operation: 'deleteDataStore',
        duration: Date.now() - startTime
      });

      return {
        success: true,
        data: result,
        message: 'deleteDataStore completed successfully',
        metadata: {
          operationId,
          timestamp: new Date(),
          duration: Date.now() - startTime
        }
      };
    } catch (error) {
      logger.error(`deleteDataStore operation failed`, {
        operationId,
        module: 'folders',
        operation: 'deleteDataStore',
        error: error instanceof Error ? error.message : String(error),
        duration: Date.now() - startTime
      });

      return {
        success: false,
        message: `deleteDataStore operation failed`,
        errors: [error instanceof Error ? error.message : String(error)],
        metadata: {
          operationId,
          timestamp: new Date(),
          duration: Date.now() - startTime
        }
      };
    }
  }

  /**
   * Execute deleteDataStore business logic
   */
  private async executeDeleteDataStore(request: unknown): Promise<{ deleted: boolean; id: number }> {
    // Validate request as DeleteDataStoreRequest
    const deleteRequest = request as DeleteDataStoreRequest;
    const { id } = deleteRequest;

    if (!id) {
      throw new Error('Data store ID is required for deletion');
    }

    try {
      // Check if data store exists before deletion
      const checkResponse = await this.apiClient.get(`/data-stores/${id}`);
      if (!checkResponse.success) {
        throw new Error(`Data store with ID ${id} not found`);
      }

      const dataStore = checkResponse.data as MakeDataStore;
      
      // Check if data store has active records
      if (dataStore.usage.recordCount > 0) {
        logger.warn('Deleting data store with existing records', {
          dataStoreId: id,
          recordCount: dataStore.usage.recordCount,
          sizeUsed: dataStore.usage.sizeUsed,
          module: 'folders'
        });
      }

      // Check for recent operations
      const lastOperationDate = new Date(dataStore.usage.lastOperation);
      const daysSinceLastOperation = Math.floor((Date.now() - lastOperationDate.getTime()) / (1000 * 60 * 60 * 24));
      
      if (daysSinceLastOperation < 7) {
        logger.warn('Deleting data store with recent activity', {
          dataStoreId: id,
          lastOperation: dataStore.usage.lastOperation,
          daysSinceLastOperation,
          module: 'folders'
        });
      }

      // Perform deletion
      const response = await this.apiClient.delete(`/data-stores/${id}`);

      if (!response.success) {
        throw new Error(`Failed to delete data store: ${response.error?.message || 'Unknown error'}`);
      }

      logger.info('Successfully deleted data store', {
        dataStoreId: id,
        name: dataStore.name,
        type: dataStore.type,
        recordCount: dataStore.usage.recordCount,
        organizationId: dataStore.organizationId,
        teamId: dataStore.teamId,
        module: 'folders'
      });

      return {
        deleted: true,
        id
      };
    } catch (error) {
      logger.error('Failed to delete data store', {
        error: error instanceof Error ? error.message : String(error),
        dataStoreId: id,
        module: 'folders'
      });
      throw error;
    }
  }

  /**
   * Generate unique operation ID
   */
  private generateOperationId(): string {
    return `datastore_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}