/**
 * Folder management functionality for Make.com platform
 * Extracted from core folders module for better maintainability
 * Generated on 2025-08-22T15:14:32.485Z
 */

import type { 
  CreateFolderRequest,
  ListFoldersRequest,
  GetFolderContentsRequest,
  MoveItemsRequest,
  MakeFolder
} from '../types/index.js';

import logger from '../../../lib/logger.js';
import { MakeApiClient } from '../../../lib/make-api-client.js';

/**
 * Folder management class
 * Handles folder-specific operations including creation, listing, content retrieval, and item movement
 */
export class FolderManager {
  private readonly apiClient: MakeApiClient;

  constructor(apiClient: MakeApiClient) {
    this.apiClient = apiClient;
  }

  /**
   * Create a new folder
   */
  async createFolder(request: CreateFolderRequest): Promise<MakeFolder> {
    const { 
      name, 
      description, 
      parentId, 
      type, 
      organizationId, 
      teamId, 
      permissions 
    } = request;

    if (!name || !type) {
      throw new Error('Name and type are required for folder creation');
    }

    try {
      // Validate parent folder exists if specified
      if (parentId) {
        const parentResponse = await this.apiClient.get(`/folders/${parentId}`);
        if (!parentResponse.success) {
          throw new Error(`Parent folder with ID ${parentId} not found`);
        }
      }

      const folderData = {
        name,
        description,
        parentId,
        type,
        organizationId,
        teamId,
        permissions: {
          read: permissions?.read ?? [],
          write: permissions?.write ?? [],
          admin: permissions?.admin ?? [],
        },
      };

      // Determine appropriate endpoint based on context
      let endpoint = '/folders';
      if (organizationId) {
        endpoint = `/organizations/${organizationId}/folders`;
      } else if (teamId) {
        endpoint = `/teams/${teamId}/folders`;
      }

      const response = await this.apiClient.post(endpoint, folderData);

      if (!response.success) {
        throw new Error(`Failed to create folder: ${response.error?.message || 'Unknown error'}`);
      }

      const folder = response.data as MakeFolder;
      if (!folder) {
        throw new Error('Folder creation failed - no data returned');
      }

      logger.info('Successfully created folder', {
        folderId: folder.id,
        name: folder.name,
        type: folder.type,
        path: folder.path,
        module: 'folders'
      });

      return folder;
    } catch (error) {
      logger.error('Failed to create folder', {
        error: error instanceof Error ? error.message : String(error),
        request,
        module: 'folders'
      });
      throw error;
    }
  }

  /**
   * List folders with pagination and filtering
   */
  async listFolders(request: ListFoldersRequest): Promise<{ folders: MakeFolder[]; pagination: { total: number; limit: number; offset: number; hasMore: boolean } }> {
    const {
      parentId,
      type = 'all',
      organizationId,
      teamId,
      searchQuery,
      includeEmpty = false,
      includeContents = false,
      limit = 50,
      offset = 0,
      sortBy = 'name',
      sortOrder = 'asc'
    } = request;

    try {
      // Build query parameters
      const params: Record<string, unknown> = {
        limit,
        offset,
        sortBy,
        sortOrder,
        includeEmpty,
        includeContents,
      };

      if (parentId) {params.parentId = parentId;}
      if (type !== 'all') {params.type = type;}
      if (organizationId) {params.organizationId = organizationId;}
      if (teamId) {params.teamId = teamId;}
      if (searchQuery) {params.search = searchQuery;}

      const response = await this.apiClient.get('/folders', { params });

      if (!response.success) {
        throw new Error(`Failed to list folders: ${response.error?.message || 'Unknown error'}`);
      }

      const folders = response.data as MakeFolder[] || [];
      const metadata = response.metadata;

      logger.info('Successfully retrieved folders', {
        count: folders.length,
        total: metadata?.total,
        module: 'folders'
      });

      return {
        folders,
        pagination: {
          total: metadata?.total || folders.length,
          limit,
          offset,
          hasMore: (offset + folders.length) < (metadata?.total || folders.length)
        }
      };
    } catch (error) {
      logger.error('Failed to list folders', {
        error: error instanceof Error ? error.message : String(error),
        request,
        module: 'folders'
      });
      throw error;
    }
  }

  /**
   * Get folder contents including subfolders and items
   */
  async getFolderContents(request: GetFolderContentsRequest): Promise<{ folder: MakeFolder; contents: unknown; pagination: { total: number; limit: number; offset: number; hasMore: boolean } }> {
    const {
      folderId,
      includeSubfolders = true,
      includeTemplates = true,
      includeScenarios = true,
      includeConnections = true,
      limit = 50,
      offset = 0
    } = request;

    if (!folderId) {
      throw new Error('Folder ID is required to get folder contents');
    }

    try {
      // Build query parameters
      const params: Record<string, unknown> = {
        includeSubfolders,
        includeTemplates,
        includeScenarios,
        includeConnections,
        limit,
        offset,
      };

      const response = await this.apiClient.get(`/folders/${folderId}/contents`, { params });

      if (!response.success) {
        throw new Error(`Failed to get folder contents: ${response.error?.message || 'Unknown error'}`);
      }

      const data = (response.data as { folder: MakeFolder; contents: unknown }) || { folder: {} as MakeFolder, contents: {} };
      const metadata = response.metadata;

      logger.info('Successfully retrieved folder contents', {
        folderId,
        folder: data.folder?.name,
        module: 'folders'
      });

      return {
        folder: data.folder,
        contents: data.contents || {},
        pagination: {
          total: metadata?.total || 0,
          limit,
          offset,
          hasMore: (offset + limit) < (metadata?.total || 0)
        }
      };
    } catch (error) {
      logger.error('Failed to get folder contents', {
        error: error instanceof Error ? error.message : String(error),
        request,
        module: 'folders'
      });
      throw error;
    }
  }

  /**
   * Move or copy items between folders
   */
  async moveItems(request: MoveItemsRequest): Promise<{ movedItems: Array<{ type: string; id: number; oldPath: string; newPath: string }> }> {
    const { 
      items, 
      targetFolderId, 
      copyInsteadOfMove = false 
    } = request;

    this.validateMoveRequest(items);

    try {
      await this.validateTargetFolder(targetFolderId);
      
      const movedItems: Array<{ type: string; id: number; oldPath: string; newPath: string }> = [];

      // Process each item for move/copy operation
      for (const item of items) {
        const movedItem = await this.processItemMove(item, targetFolderId, copyInsteadOfMove);
        movedItems.push(movedItem);
      }

      logger.info(`Successfully ${copyInsteadOfMove ? 'copied' : 'moved'} items`, {
        itemCount: movedItems.length,
        targetFolderId,
        copyInsteadOfMove,
        module: 'folders'
      });

      return { movedItems };
    } catch (error) {
      logger.error(`Failed to ${copyInsteadOfMove ? 'copy' : 'move'} items`, {
        error: error instanceof Error ? error.message : String(error),
        request,
        module: 'folders'
      });
      throw error;
    }
  }

  /**
   * Validate move request parameters
   */
  private validateMoveRequest(items: unknown): void {
    if (!items || !Array.isArray(items) || items.length === 0) {
      throw new Error('At least one item is required to move');
    }

    for (const item of items) {
      if (!item.type || !item.id) {
        throw new Error('Each item must have a type and id');
      }
      if (!['template', 'scenario', 'connection', 'folder'].includes(item.type)) {
        throw new Error(`Invalid item type: ${item.type}. Must be one of: template, scenario, connection, folder`);
      }
    }
  }

  /**
   * Validate that target folder exists
   */
  private async validateTargetFolder(targetFolderId?: number): Promise<void> {
    if (targetFolderId) {
      const targetResponse = await this.apiClient.get(`/folders/${targetFolderId}`);
      if (!targetResponse.success) {
        throw new Error(`Target folder with ID ${targetFolderId} not found`);
      }
    }
  }

  /**
   * Process move/copy operation for a single item
   */
  private async processItemMove(
    item: { type: string; id: number },
    targetFolderId: number | undefined,
    copyInsteadOfMove: boolean
  ): Promise<{ type: string; id: number; oldPath: string; newPath: string }> {
    const { type, id } = item;

    // Get current item details to capture old path
    const currentItemResponse = await this.apiClient.get(`/${type}s/${id}`);
    if (!currentItemResponse.success) {
      throw new Error(`Item ${type} with ID ${id} not found`);
    }

    const currentItem = currentItemResponse.data as { path?: string; folderId?: number };
    const oldPath = currentItem.path || `/${type}s/${id}`;

    // Prepare move/copy payload
    const movePayload = {
      targetFolderId: targetFolderId || null,
      copyInsteadOfMove
    };

    // Determine the appropriate endpoint for move/copy operation
    const endpoint = copyInsteadOfMove ? `/${type}s/${id}/copy` : `/${type}s/${id}/move`;

    const response = await this.apiClient.post(endpoint, movePayload);

    if (!response.success) {
      throw new Error(`Failed to ${copyInsteadOfMove ? 'copy' : 'move'} ${type} ${id}: ${response.error?.message || 'Unknown error'}`);
    }

    const updatedItem = response.data as { path?: string; folderId?: number };
    const newPath = updatedItem.path || `/${type}s/${id}`;

    const movedItem = {
      type,
      id,
      oldPath,
      newPath
    };

    logger.info(`Successfully ${copyInsteadOfMove ? 'copied' : 'moved'} item`, {
      ...movedItem,
      targetFolderId,
      module: 'folders'
    });

    return movedItem;
  }
}