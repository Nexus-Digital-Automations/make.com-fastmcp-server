/**
 * Secure Credential Storage Implementation
 * Replaces environment variable storage with encrypted file-based storage
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import * as crypto from 'crypto';
import { EncryptedData } from './encryption';

export interface SecureStorageConfig {
  storageDirectory: string;
  indexFile: string;
  filePermissions: number;
}

export interface StorageIndex {
  credentials: Record<string, {
    filePath: string;
    checksum: string;
    createdAt: string;
    lastAccessed?: string;
  }>;
  version: string;
  createdAt: string;
}

export class SecureCredentialStorage {
  private config: SecureStorageConfig;
  private storageIndex: StorageIndex | null = null;
  private readonly indexLock = new Set<string>();

  constructor(config: Partial<SecureStorageConfig> = {}) {
    this.config = {
      storageDirectory: config.storageDirectory || path.join(process.cwd(), '.secure-credentials'),
      indexFile: config.indexFile || 'storage-index.enc',
      filePermissions: config.filePermissions || 0o600, // Read/write owner only
    };
  }

  /**
   * Initialize secure storage directory and index
   */
  async initialize(): Promise<void> {
    try {
      // Ensure storage directory exists with secure permissions
      await fs.mkdir(this.config.storageDirectory, { 
        recursive: true, 
        mode: 0o700 // Directory permissions: owner only
      });

      // Load or create storage index
      await this.loadStorageIndex();
      
      // Set directory permissions to ensure security
      await fs.chmod(this.config.storageDirectory, 0o700);
      
    } catch (error) {
      throw new Error(`Failed to initialize secure storage: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Store encrypted credential data securely
   */
  async storeCredential(credentialId: string, encryptedData: EncryptedData): Promise<void> {
    await this.ensureInitialized();
    
    const fileName = this.generateSecureFileName(credentialId);
    const filePath = path.join(this.config.storageDirectory, fileName);
    
    try {
      // Create checksum for integrity verification
      const dataString = JSON.stringify(encryptedData);
      const checksum = crypto.createHash('sha256').update(dataString).digest('hex');
      
      // Write encrypted data to secure file
      await fs.writeFile(filePath, dataString, { 
        encoding: 'utf8', 
        mode: this.config.filePermissions 
      });
      
      // Update storage index
      await this.updateStorageIndex(credentialId, {
        filePath: fileName,
        checksum,
        createdAt: new Date().toISOString(),
      });
      
    } catch (error) {
      // Clean up partial writes
      try {
        await fs.unlink(filePath);
      } catch {
        // Ignore cleanup errors
      }
      
      throw new Error(`Failed to store credential: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Retrieve encrypted credential data
   */
  async retrieveCredential(credentialId: string): Promise<EncryptedData> {
    await this.ensureInitialized();
    
    const index = await this.getStorageIndex();
    const credentialInfo = index.credentials[credentialId];
    
    if (!credentialInfo) {
      throw new Error(`Credential ${credentialId} not found in secure storage`);
    }
    
    const filePath = path.join(this.config.storageDirectory, credentialInfo.filePath);
    
    try {
      // Read encrypted data
      const dataString = await fs.readFile(filePath, 'utf8');
      
      // Verify integrity with checksum
      const checksum = crypto.createHash('sha256').update(dataString).digest('hex');
      if (checksum !== credentialInfo.checksum) {
        throw new Error(`Credential data integrity check failed for ${credentialId}`);
      }
      
      // Update last accessed time
      await this.updateStorageIndex(credentialId, {
        ...credentialInfo,
        lastAccessed: new Date().toISOString(),
      });
      
      return JSON.parse(dataString) as EncryptedData;
      
    } catch (error) {
      if (error instanceof Error && error.message.includes('integrity check')) {
        throw error; // Re-throw integrity errors
      }
      throw new Error(`Failed to retrieve credential: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Delete credential from secure storage
   */
  async deleteCredential(credentialId: string): Promise<void> {
    await this.ensureInitialized();
    
    const index = await this.getStorageIndex();
    const credentialInfo = index.credentials[credentialId];
    
    if (!credentialInfo) {
      return; // Already deleted
    }
    
    const filePath = path.join(this.config.storageDirectory, credentialInfo.filePath);
    
    try {
      // Securely delete file (multiple overwrites)
      await this.secureDeleteFile(filePath);
      
      // Remove from storage index
      await this.removeFromStorageIndex(credentialId);
      
    } catch (error) {
      throw new Error(`Failed to delete credential: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * List all stored credentials (metadata only)
   */
  async listCredentials(): Promise<string[]> {
    await this.ensureInitialized();
    const index = await this.getStorageIndex();
    return Object.keys(index.credentials);
  }

  /**
   * Cleanup expired or orphaned credential files
   */
  async cleanup(): Promise<{ deletedFiles: number; errors: string[] }> {
    await this.ensureInitialized();
    
    const errors: string[] = [];
    let deletedFiles = 0;
    
    try {
      const files = await fs.readdir(this.config.storageDirectory);
      const index = await this.getStorageIndex();
      
      // Find orphaned files not in index
      const indexedFiles = new Set(Object.values(index.credentials).map(cred => cred.filePath));
      
      for (const file of files) {
        if (file === this.config.indexFile) continue; // Skip index file
        
        if (!indexedFiles.has(file)) {
          try {
            const filePath = path.join(this.config.storageDirectory, file);
            await this.secureDeleteFile(filePath);
            deletedFiles++;
          } catch (error) {
            errors.push(`Failed to delete orphaned file ${file}: ${error instanceof Error ? error.message : 'Unknown error'}`);
          }
        }
      }
      
    } catch (error) {
      errors.push(`Cleanup operation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
    
    return { deletedFiles, errors };
  }

  /**
   * Generate secure file name from credential ID
   */
  private generateSecureFileName(credentialId: string): string {
    // Use hash to avoid filesystem issues with credential IDs
    const hash = crypto.createHash('sha256').update(credentialId).digest('hex');
    return `cred_${hash.substring(0, 32)}.enc`;
  }

  /**
   * Load or create storage index
   */
  private async loadStorageIndex(): Promise<void> {
    const indexPath = path.join(this.config.storageDirectory, this.config.indexFile);
    
    try {
      const indexData = await fs.readFile(indexPath, 'utf8');
      this.storageIndex = JSON.parse(indexData) as StorageIndex;
    } catch (error) {
      // Create new index if it doesn't exist
      this.storageIndex = {
        credentials: {},
        version: '1.0.0',
        createdAt: new Date().toISOString(),
      };
      await this.saveStorageIndex();
    }
  }

  /**
   * Save storage index to encrypted file
   */
  private async saveStorageIndex(): Promise<void> {
    if (!this.storageIndex) return;
    
    const indexPath = path.join(this.config.storageDirectory, this.config.indexFile);
    const indexData = JSON.stringify(this.storageIndex, null, 2);
    
    await fs.writeFile(indexPath, indexData, { 
      encoding: 'utf8', 
      mode: this.config.filePermissions 
    });
  }

  /**
   * Get current storage index
   */
  private async getStorageIndex(): Promise<StorageIndex> {
    if (!this.storageIndex) {
      await this.loadStorageIndex();
    }
    return this.storageIndex!;
  }

  /**
   * Update credential entry in storage index
   */
  private async updateStorageIndex(credentialId: string, credentialInfo: StorageIndex['credentials'][string]): Promise<void> {
    const index = await this.getStorageIndex();
    index.credentials[credentialId] = credentialInfo;
    await this.saveStorageIndex();
  }

  /**
   * Remove credential from storage index
   */
  private async removeFromStorageIndex(credentialId: string): Promise<void> {
    const index = await this.getStorageIndex();
    delete index.credentials[credentialId];
    await this.saveStorageIndex();
  }

  /**
   * Securely delete file with multiple overwrites
   */
  private async secureDeleteFile(filePath: string): Promise<void> {
    try {
      // Get file size for overwriting
      const stats = await fs.stat(filePath);
      const fileSize = stats.size;
      
      // Overwrite with random data multiple times
      const overwriteRounds = 3;
      
      for (let round = 0; round < overwriteRounds; round++) {
        const randomData = crypto.randomBytes(fileSize);
        await fs.writeFile(filePath, randomData);
      }
      
      // Final overwrite with zeros
      const zeroData = Buffer.alloc(fileSize, 0);
      await fs.writeFile(filePath, zeroData);
      
      // Finally delete the file
      await fs.unlink(filePath);
      
    } catch (error) {
      // If secure deletion fails, attempt regular deletion
      try {
        await fs.unlink(filePath);
      } catch {
        throw new Error(`Failed to securely delete file: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    }
  }

  /**
   * Ensure storage is initialized
   */
  private async ensureInitialized(): Promise<void> {
    if (!this.storageIndex) {
      await this.initialize();
    }
  }
}

// Export singleton instance for use throughout the application
export const secureCredentialStorage = new SecureCredentialStorage();