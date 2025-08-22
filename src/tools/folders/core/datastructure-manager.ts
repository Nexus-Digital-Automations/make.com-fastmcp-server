/**
 * Data Structure Manager for folders module
 * Handles all data structure operations for Make.com platform
 * Generated on 2025-08-22T09:20:06.377Z
 */

import type {
  FoldersResult,
  ListDataStructuresRequest,
  GetDataStructureRequest,
  CreateDataStructureRequest,
  UpdateDataStructureRequest,
  DeleteDataStructureRequest,
  MakeDataStructure
} from '../types/index.js';

import logger from '../../../lib/logger.js';
import { MakeApiClient } from '../../../lib/make-api-client.js';

/**
 * DataStructureManager class
 * Manages all data structure related operations
 */
export class DataStructureManager {
  private readonly apiClient: MakeApiClient;

  constructor(apiClient: MakeApiClient) {
    this.apiClient = apiClient;
  }

  /**
   * Generate unique operation ID
   */
  private generateOperationId(): string {
    return `datastructures_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * listDataStructures operation handler
   */
  async listDataStructures(request: unknown): Promise<FoldersResult> {
    const operationId = this.generateOperationId();
    const startTime = Date.now();

    try {
      // Validate request
      // const validRequest = validateListdatastructuresRequest(request);

      logger.info(`Starting listDataStructures operation`, {
        operationId,
        module: 'folders',
        operation: 'listDataStructures'
      });

      // Implement listDataStructures business logic here
      const result = await this.executeListdatastructures(request);

      logger.info(`listDataStructures operation completed successfully`, {
        operationId,
        module: 'folders',
        operation: 'listDataStructures',
        duration: Date.now() - startTime
      });

      return {
        success: true,
        data: result,
        message: 'listDataStructures completed successfully',
        metadata: {
          operationId,
          timestamp: new Date(),
          duration: Date.now() - startTime
        }
      };
    } catch (error) {
      logger.error(`listDataStructures operation failed`, {
        operationId,
        module: 'folders',
        operation: 'listDataStructures',
        error: error instanceof Error ? error.message : String(error),
        duration: Date.now() - startTime
      });

      return {
        success: false,
        message: `listDataStructures operation failed`,
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
   * Execute listDataStructures business logic
   */
  private async executeListdatastructures(request: unknown): Promise<{ dataStructures: MakeDataStructure[]; pagination: { total: number; limit: number; offset: number; hasMore: boolean } }> {
    // Validate request as ListDataStructuresRequest
    const listRequest = request as ListDataStructuresRequest;
    const {
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

      if (organizationId) {params.organizationId = organizationId;}
      if (teamId) {params.teamId = teamId;}
      if (searchQuery) {params.search = searchQuery;}

      const response = await this.apiClient.get('/data-structures', { params });

      if (!response.success) {
        throw new Error(`Failed to list data structures: ${response.error?.message || 'Unknown error'}`);
      }

      const dataStructures = response.data as MakeDataStructure[] || [];
      const metadata = response.metadata;

      logger.info('Successfully retrieved data structures', {
        count: dataStructures.length,
        total: metadata?.total,
        module: 'folders'
      });

      return {
        dataStructures,
        pagination: {
          total: metadata?.total || dataStructures.length,
          limit,
          offset,
          hasMore: (offset + dataStructures.length) < (metadata?.total || dataStructures.length)
        }
      };
    } catch (error) {
      logger.error('Failed to list data structures', {
        error: error instanceof Error ? error.message : String(error),
        request: listRequest,
        module: 'folders'
      });
      throw error;
    }
  }

  /**
   * getDataStructure operation handler
   */
  async getDataStructure(request: unknown): Promise<FoldersResult> {
    const operationId = this.generateOperationId();
    const startTime = Date.now();

    try {
      // Validate request
      // const validRequest = validateGetdatastructureRequest(request);

      logger.info(`Starting getDataStructure operation`, {
        operationId,
        module: 'folders',
        operation: 'getDataStructure'
      });

      // Implement getDataStructure business logic here
      const result = await this.executeGetdatastructure(request);

      logger.info(`getDataStructure operation completed successfully`, {
        operationId,
        module: 'folders',
        operation: 'getDataStructure',
        duration: Date.now() - startTime
      });

      return {
        success: true,
        data: result,
        message: 'getDataStructure completed successfully',
        metadata: {
          operationId,
          timestamp: new Date(),
          duration: Date.now() - startTime
        }
      };
    } catch (error) {
      logger.error(`getDataStructure operation failed`, {
        operationId,
        module: 'folders',
        operation: 'getDataStructure',
        error: error instanceof Error ? error.message : String(error),
        duration: Date.now() - startTime
      });

      return {
        success: false,
        message: `getDataStructure operation failed`,
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
   * Execute getDataStructure business logic
   */
  private async executeGetdatastructure(request: unknown): Promise<MakeDataStructure> {
    // Validate request as GetDataStructureRequest
    const getRequest = request as GetDataStructureRequest;
    const { id } = getRequest;

    if (!id) {
      throw new Error('Data structure ID is required');
    }

    try {
      const response = await this.apiClient.get(`/data-structures/${id}`);

      if (!response.success) {
        throw new Error(`Failed to get data structure: ${response.error?.message || 'Unknown error'}`);
      }

      const dataStructure = response.data as MakeDataStructure;
      if (!dataStructure) {
        throw new Error(`Data structure with ID ${id} not found`);
      }

      logger.info('Successfully retrieved data structure', {
        dataStructureId: dataStructure.id,
        name: dataStructure.name,
        organizationId: dataStructure.organizationId,
        teamId: dataStructure.teamId,
        module: 'folders'
      });

      return dataStructure;
    } catch (error) {
      logger.error('Failed to get data structure', {
        error: error instanceof Error ? error.message : String(error),
        dataStructureId: id,
        module: 'folders'
      });
      throw error;
    }
  }

  /**
   * createDataStructure operation handler
   */
  async createDataStructure(request: unknown): Promise<FoldersResult> {
    const operationId = this.generateOperationId();
    const startTime = Date.now();

    try {
      // Validate request
      // const validRequest = validateCreatedatastructureRequest(request);

      logger.info(`Starting createDataStructure operation`, {
        operationId,
        module: 'folders',
        operation: 'createDataStructure'
      });

      // Implement createDataStructure business logic here
      const result = await this.executeCreatedatastructure(request);

      logger.info(`createDataStructure operation completed successfully`, {
        operationId,
        module: 'folders',
        operation: 'createDataStructure',
        duration: Date.now() - startTime
      });

      return {
        success: true,
        data: result,
        message: 'createDataStructure completed successfully',
        metadata: {
          operationId,
          timestamp: new Date(),
          duration: Date.now() - startTime
        }
      };
    } catch (error) {
      logger.error(`createDataStructure operation failed`, {
        operationId,
        module: 'folders',
        operation: 'createDataStructure',
        error: error instanceof Error ? error.message : String(error),
        duration: Date.now() - startTime
      });

      return {
        success: false,
        message: `createDataStructure operation failed`,
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
   * Execute createDataStructure business logic
   */
  private async executeCreatedatastructure(request: unknown): Promise<MakeDataStructure> {
    // Validate request as CreateDataStructureRequest
    const dataStructureRequest = request as CreateDataStructureRequest;
    const {
      name,
      description,
      organizationId,
      teamId,
      specification,
      strict = true,
      validation
    } = dataStructureRequest;

    if (!name || !specification || !Array.isArray(specification)) {
      throw new Error('Name and specification array are required for data structure creation');
    }

    if (specification.length === 0) {
      throw new Error('Data structure specification cannot be empty');
    }

    try {
      const dataStructureData = {
        name,
        description,
        organizationId,
        teamId,
        specification,
        strict,
        validation: validation || {
          enabled: false,
          rules: []
        }
      };

      // Determine appropriate endpoint based on context
      let endpoint = '/data-structures';
      if (organizationId) {
        endpoint = `/organizations/${organizationId}/data-structures`;
      } else if (teamId) {
        endpoint = `/teams/${teamId}/data-structures`;
      }

      const response = await this.apiClient.post(endpoint, dataStructureData);

      if (!response.success) {
        throw new Error(`Failed to create data structure: ${response.error?.message || 'Unknown error'}`);
      }

      const dataStructure = response.data as MakeDataStructure;
      if (!dataStructure) {
        throw new Error('Data structure creation failed - no data returned');
      }

      logger.info('Successfully created data structure', {
        dataStructureId: dataStructure.id,
        name: dataStructure.name,
        fieldsCount: dataStructure.specification.length,
        strict: dataStructure.strict,
        organizationId: dataStructure.organizationId,
        teamId: dataStructure.teamId,
        module: 'folders'
      });

      return dataStructure;
    } catch (error) {
      logger.error('Failed to create data structure', {
        error: error instanceof Error ? error.message : String(error),
        request: dataStructureRequest,
        module: 'folders'
      });
      throw error;
    }
  }

  /**
   * updateDataStructure operation handler
   */
  async updateDataStructure(request: unknown): Promise<FoldersResult> {
    const operationId = this.generateOperationId();
    const startTime = Date.now();

    try {
      // Validate request
      // const validRequest = validateUpdatedatastructureRequest(request);

      logger.info(`Starting updateDataStructure operation`, {
        operationId,
        module: 'folders',
        operation: 'updateDataStructure'
      });

      // Implement updateDataStructure business logic here
      const result = await this.executeUpdatedatastructure(request);

      logger.info(`updateDataStructure operation completed successfully`, {
        operationId,
        module: 'folders',
        operation: 'updateDataStructure',
        duration: Date.now() - startTime
      });

      return {
        success: true,
        data: result,
        message: 'updateDataStructure completed successfully',
        metadata: {
          operationId,
          timestamp: new Date(),
          duration: Date.now() - startTime
        }
      };
    } catch (error) {
      logger.error(`updateDataStructure operation failed`, {
        operationId,
        module: 'folders',
        operation: 'updateDataStructure',
        error: error instanceof Error ? error.message : String(error),
        duration: Date.now() - startTime
      });

      return {
        success: false,
        message: `updateDataStructure operation failed`,
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
   * Execute updateDataStructure business logic
   */
  private async executeUpdatedatastructure(request: unknown): Promise<MakeDataStructure> {
    // Validate request as UpdateDataStructureRequest
    const updateRequest = request as UpdateDataStructureRequest;
    const {
      id,
      name,
      description,
      specification,
      strict,
      validation
    } = updateRequest;

    if (!id) {
      throw new Error('Data structure ID is required for update');
    }

    try {
      // Build update payload - only include provided fields
      const updateData: Record<string, unknown> = {};
      
      if (name !== undefined) {updateData.name = name;}
      if (description !== undefined) {updateData.description = description;}
      if (specification !== undefined) {updateData.specification = specification;}
      if (strict !== undefined) {updateData.strict = strict;}
      if (validation !== undefined) {updateData.validation = validation;}

      if (Object.keys(updateData).length === 0) {
        throw new Error('At least one field must be provided for update');
      }

      const response = await this.apiClient.patch(`/data-structures/${id}`, updateData);

      if (!response.success) {
        throw new Error(`Failed to update data structure: ${response.error?.message || 'Unknown error'}`);
      }

      const dataStructure = response.data as MakeDataStructure;
      if (!dataStructure) {
        throw new Error('Data structure update failed - no data returned');
      }

      logger.info('Successfully updated data structure', {
        dataStructureId: dataStructure.id,
        name: dataStructure.name,
        updatedFields: Object.keys(updateData),
        module: 'folders'
      });

      return dataStructure;
    } catch (error) {
      logger.error('Failed to update data structure', {
        error: error instanceof Error ? error.message : String(error),
        dataStructureId: id,
        request: updateRequest,
        module: 'folders'
      });
      throw error;
    }
  }

  /**
   * deleteDataStructure operation handler
   */
  async deleteDataStructure(request: unknown): Promise<FoldersResult> {
    const operationId = this.generateOperationId();
    const startTime = Date.now();

    try {
      // Validate request
      // const validRequest = validateDeletedatastructureRequest(request);

      logger.info(`Starting deleteDataStructure operation`, {
        operationId,
        module: 'folders',
        operation: 'deleteDataStructure'
      });

      // Implement deleteDataStructure business logic here
      const result = await this.executeDeletedatastructure(request);

      logger.info(`deleteDataStructure operation completed successfully`, {
        operationId,
        module: 'folders',
        operation: 'deleteDataStructure',
        duration: Date.now() - startTime
      });

      return {
        success: true,
        data: result,
        message: 'deleteDataStructure completed successfully',
        metadata: {
          operationId,
          timestamp: new Date(),
          duration: Date.now() - startTime
        }
      };
    } catch (error) {
      logger.error(`deleteDataStructure operation failed`, {
        operationId,
        module: 'folders',
        operation: 'deleteDataStructure',
        error: error instanceof Error ? error.message : String(error),
        duration: Date.now() - startTime
      });

      return {
        success: false,
        message: `deleteDataStructure operation failed`,
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
   * Execute deleteDataStructure business logic
   */
  private async executeDeletedatastructure(request: unknown): Promise<{ deleted: boolean; id: number }> {
    // Validate request as DeleteDataStructureRequest
    const deleteRequest = request as DeleteDataStructureRequest;
    const { id } = deleteRequest;

    if (!id) {
      throw new Error('Data structure ID is required for deletion');
    }

    try {
      // Check if data structure exists before deletion
      const checkResponse = await this.apiClient.get(`/data-structures/${id}`);
      if (!checkResponse.success) {
        throw new Error(`Data structure with ID ${id} not found`);
      }

      const dataStructure = checkResponse.data as MakeDataStructure;
      
      // Check if data structure is in use by any data stores
      if (dataStructure.usage.dataStoresCount > 0) {
        throw new Error(`Cannot delete data structure ${id}: it is currently used by ${dataStructure.usage.dataStoresCount} data store(s)`);
      }

      // Perform deletion
      const response = await this.apiClient.delete(`/data-structures/${id}`);

      if (!response.success) {
        throw new Error(`Failed to delete data structure: ${response.error?.message || 'Unknown error'}`);
      }

      logger.info('Successfully deleted data structure', {
        dataStructureId: id,
        name: dataStructure.name,
        organizationId: dataStructure.organizationId,
        teamId: dataStructure.teamId,
        module: 'folders'
      });

      return {
        deleted: true,
        id
      };
    } catch (error) {
      logger.error('Failed to delete data structure', {
        error: error instanceof Error ? error.message : String(error),
        dataStructureId: id,
        module: 'folders'
      });
      throw error;
    }
  }
}