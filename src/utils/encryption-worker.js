/**
 * Encryption Worker Thread - FIPS 140-2 Compliant Cryptographic Operations
 * Handles CPU-intensive cryptographic operations in isolated worker context
 */

const { parentPort, workerData } = require('worker_threads');
const crypto = require('crypto');

/**
 * Worker configuration from parent
 */
const { workerId, hsmConfig } = workerData;

/**
 * Cryptographic operation handlers
 */
class CryptographicWorker {
  constructor() {
    this.workerId = workerId;
    this.hsmConfig = hsmConfig;
    this.jobsProcessed = 0;
    this.errorCount = 0;
  }

  /**
   * Process encryption job request
   */
  async processJob(request) {
    const startTime = Date.now();
    
    try {
      let result;
      
      switch (request.operation) {
        case 'encrypt':
          result = await this.performEncryption(request);
          break;
          
        case 'decrypt':
          result = await this.performDecryption(request);
          break;
          
        case 'hash':
          result = await this.performHashing(request);
          break;
          
        case 'sign':
          result = await this.performSigning(request);
          break;
          
        case 'verify':
          result = await this.performVerification(request);
          break;
          
        case 'derive_key':
          result = await this.performKeyDerivation(request);
          break;
          
        case 'generate_random':
          result = await this.generateSecureRandom(request);
          break;
          
        default:
          throw new Error(`Unsupported operation: ${request.operation}`);
      }

      const processingTime = Date.now() - startTime;
      this.jobsProcessed++;

      return {
        id: request.id,
        success: true,
        result,
        metadata: {
          algorithm: request.algorithm.algorithm,
          processingTime,
          workerId: this.workerId,
          hsm: request.hsm?.enabled || false
        }
      };

    } catch (error) {
      this.errorCount++;
      const processingTime = Date.now() - startTime;
      
      return {
        id: request.id,
        success: false,
        error: {
          code: 'WORKER_PROCESSING_ERROR',
          message: error.message,
          stack: error.stack
        },
        metadata: {
          processingTime,
          workerId: this.workerId
        }
      };
    }
  }

  /**
   * Perform AES-256-GCM encryption
   */
  async performEncryption(request) {
    const { algorithm, data, key } = request;
    
    if (algorithm.algorithm === 'aes-256-gcm') {
      return this.encryptAES256GCM(data, key, algorithm);
    } else if (algorithm.algorithm === 'aes-256-cbc') {
      return this.encryptAES256CBC(data, key, algorithm);
    } else if (algorithm.algorithm === 'rsa-4096') {
      return this.encryptRSA4096(data, key);
    }
    
    throw new Error(`Unsupported encryption algorithm: ${algorithm.algorithm}`);
  }

  /**
   * Perform AES-256-GCM decryption
   */
  async performDecryption(request) {
    const { algorithm, data, key } = request;
    
    if (algorithm.algorithm === 'aes-256-gcm') {
      return this.decryptAES256GCM(data, key, algorithm);
    } else if (algorithm.algorithm === 'aes-256-cbc') {
      return this.decryptAES256CBC(data, key, algorithm);
    } else if (algorithm.algorithm === 'rsa-4096') {
      return this.decryptRSA4096(data, key);
    }
    
    throw new Error(`Unsupported decryption algorithm: ${algorithm.algorithm}`);
  }

  /**
   * Perform cryptographic hashing
   */
  async performHashing(request) {
    const { data } = request;
    const algorithm = request.algorithm?.hashAlgorithm || 'sha256';
    
    const supportedHashes = ['sha256', 'sha384', 'sha512', 'sha3-256', 'sha3-384', 'sha3-512'];
    if (!supportedHashes.includes(algorithm)) {
      throw new Error(`Unsupported hash algorithm: ${algorithm}`);
    }
    
    const hash = crypto.createHash(algorithm);
    hash.update(data);
    return hash.digest('hex');
  }

  /**
   * Perform digital signing
   */
  async performSigning(request) {
    const { algorithm, data, key } = request;
    
    if (algorithm.algorithm === 'ecdsa-p384') {
      return this.signECDSAP384(data, key);
    } else if (algorithm.algorithm === 'rsa-pss-4096') {
      return this.signRSAPSS4096(data, key);
    }
    
    throw new Error(`Unsupported signing algorithm: ${algorithm.algorithm}`);
  }

  /**
   * Perform signature verification
   */
  async performVerification(request) {
    const { algorithm, data, signature, key } = request;
    
    if (algorithm.algorithm === 'ecdsa-p384') {
      return this.verifyECDSAP384(data, signature, key);
    } else if (algorithm.algorithm === 'rsa-pss-4096') {
      return this.verifyRSAPSS4096(data, signature, key);
    }
    
    throw new Error(`Unsupported verification algorithm: ${algorithm.algorithm}`);
  }

  /**
   * Perform key derivation
   */
  async performKeyDerivation(request) {
    const { data, algorithm } = request;
    const derivationParams = request.derivationParams || {};
    
    if (algorithm.algorithm === 'pbkdf2') {
      return this.deriveKeyPBKDF2(data, derivationParams);
    } else if (algorithm.algorithm === 'scrypt') {
      return this.deriveKeyScrypt(data, derivationParams);
    } else if (algorithm.algorithm === 'hkdf') {
      return this.deriveKeyHKDF(data, derivationParams);
    }
    
    throw new Error(`Unsupported key derivation algorithm: ${algorithm.algorithm}`);
  }

  /**
   * Generate cryptographically secure random data
   */
  async generateSecureRandom(request) {
    const length = request.length || 32;
    const format = request.format || 'hex';
    
    const randomBytes = crypto.randomBytes(length);
    
    switch (format) {
      case 'hex':
        return randomBytes.toString('hex');
      case 'base64':
        return randomBytes.toString('base64');
      case 'base64url':
        return randomBytes.toString('base64url');
      case 'buffer':
        return randomBytes;
      default:
        throw new Error(`Unsupported format: ${format}`);
    }
  }

  // AES-256-GCM Implementation
  encryptAES256GCM(plaintext, keyMaterial, algorithm) {
    const key = this.deriveKeyFromMaterial(keyMaterial, 32); // 256 bits
    const iv = crypto.randomBytes(algorithm.ivLength || 16);
    
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    
    let encrypted = cipher.update(plaintext, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    
    const authTag = cipher.getAuthTag();
    
    return {
      data: encrypted,
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64'),
      algorithm: 'aes-256-gcm'
    };
  }

  decryptAES256GCM(encryptedData, keyMaterial, algorithm) {
    const key = this.deriveKeyFromMaterial(keyMaterial, 32);
    const iv = Buffer.from(encryptedData.iv, 'base64');
    const authTag = Buffer.from(encryptedData.authTag, 'base64');
    
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    
    let decrypted = decipher.update(encryptedData.data, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }

  // AES-256-CBC Implementation
  encryptAES256CBC(plaintext, keyMaterial, algorithm) {
    const key = this.deriveKeyFromMaterial(keyMaterial, 32);
    const iv = crypto.randomBytes(algorithm.ivLength || 16);
    
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    
    let encrypted = cipher.update(plaintext, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    
    return {
      data: encrypted,
      iv: iv.toString('base64'),
      algorithm: 'aes-256-cbc'
    };
  }

  decryptAES256CBC(encryptedData, keyMaterial, algorithm) {
    const key = this.deriveKeyFromMaterial(keyMaterial, 32);
    const iv = Buffer.from(encryptedData.iv, 'base64');
    
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    
    let decrypted = decipher.update(encryptedData.data, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }

  // RSA-4096 Implementation
  encryptRSA4096(plaintext, publicKey) {
    const buffer = Buffer.from(plaintext, 'utf8');
    const encrypted = crypto.publicEncrypt({
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    }, buffer);
    
    return {
      data: encrypted.toString('base64'),
      algorithm: 'rsa-4096'
    };
  }

  decryptRSA4096(encryptedData, privateKey) {
    const buffer = Buffer.from(encryptedData.data, 'base64');
    const decrypted = crypto.privateDecrypt({
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    }, buffer);
    
    return decrypted.toString('utf8');
  }

  // ECDSA P-384 Implementation
  signECDSAP384(data, privateKey) {
    const sign = crypto.createSign('SHA384');
    sign.update(data);
    sign.end();
    
    const signature = sign.sign(privateKey, 'base64');
    
    return {
      signature,
      algorithm: 'ecdsa-p384',
      hashAlgorithm: 'sha384'
    };
  }

  verifyECDSAP384(data, signatureData, publicKey) {
    const verify = crypto.createVerify('SHA384');
    verify.update(data);
    verify.end();
    
    return verify.verify(publicKey, signatureData.signature, 'base64');
  }

  // RSA-PSS 4096 Implementation
  signRSAPSS4096(data, privateKey) {
    const sign = crypto.createSign('SHA256');
    sign.update(data);
    sign.end();
    
    const signature = sign.sign({
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
    }, 'base64');
    
    return {
      signature,
      algorithm: 'rsa-pss-4096',
      hashAlgorithm: 'sha256'
    };
  }

  verifyRSAPSS4096(data, signatureData, publicKey) {
    const verify = crypto.createVerify('SHA256');
    verify.update(data);
    verify.end();
    
    return verify.verify({
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
    }, signatureData.signature, 'base64');
  }

  // Key Derivation Implementations
  deriveKeyPBKDF2(password, params) {
    const salt = params.salt || crypto.randomBytes(32);
    const iterations = params.iterations || 100000;
    const keyLength = params.keyLength || 32;
    
    const derivedKey = crypto.pbkdf2Sync(password, salt, iterations, keyLength, 'sha256');
    
    return {
      derivedKey: derivedKey.toString('base64'),
      salt: salt.toString('base64'),
      iterations,
      keyLength,
      algorithm: 'pbkdf2'
    };
  }

  deriveKeyScrypt(password, params) {
    const salt = params.salt || crypto.randomBytes(32);
    const keyLength = params.keyLength || 32;
    const options = {
      N: params.cost || 32768,
      r: params.blockSize || 8,
      p: params.parallelization || 1
    };
    
    const derivedKey = crypto.scryptSync(password, salt, keyLength, options);
    
    return {
      derivedKey: derivedKey.toString('base64'),
      salt: salt.toString('base64'),
      keyLength,
      algorithm: 'scrypt',
      options
    };
  }

  deriveKeyHKDF(keyMaterial, params) {
    const salt = params.salt || Buffer.alloc(0);
    const info = params.info || Buffer.alloc(0);
    const keyLength = params.keyLength || 32;
    
    const derivedKey = crypto.hkdfSync('sha256', keyMaterial, salt, info, keyLength);
    
    return {
      derivedKey: derivedKey.toString('base64'),
      salt: salt.toString('base64'),
      info: info.toString('base64'),
      keyLength,
      algorithm: 'hkdf'
    };
  }

  /**
   * Derive cryptographic key from key material
   */
  deriveKeyFromMaterial(keyMaterial, keyLength) {
    if (Buffer.isBuffer(keyMaterial)) {
      if (keyMaterial.length === keyLength) {
        return keyMaterial;
      } else if (keyMaterial.length > keyLength) {
        return keyMaterial.subarray(0, keyLength);
      }
    }
    
    // Use PBKDF2 to derive key of correct length
    const salt = crypto.randomBytes(16);
    return crypto.pbkdf2Sync(keyMaterial, salt, 100000, keyLength, 'sha256');
  }

  /**
   * Get worker health status
   */
  getHealthStatus() {
    return {
      workerId: this.workerId,
      status: 'active',
      jobsProcessed: this.jobsProcessed,
      errorCount: this.errorCount,
      uptime: process.uptime(),
      memoryUsage: process.memoryUsage(),
      cpuUsage: process.cpuUsage()
    };
  }
}

// Initialize worker
const worker = new CryptographicWorker();

// Handle messages from parent thread
parentPort.on('message', async (request) => {
  try {
    if (request.type === 'job') {
      const result = await worker.processJob(request.payload);
      parentPort.postMessage(result);
    } else if (request.type === 'batch') {
      // Process batch of jobs
      const batch = request.payload;
      const results = [];
      
      for (const job of batch.jobs) {
        const result = await worker.processJob(job);
        results.push(result);
      }
      
      parentPort.postMessage({
        type: 'batch_result',
        batchId: batch.batchId,
        results
      });
    } else if (request.type === 'health_check') {
      const healthStatus = worker.getHealthStatus();
      parentPort.postMessage({
        type: 'health_status',
        status: healthStatus
      });
    } else if (request.type === 'shutdown') {
      // Graceful shutdown
      parentPort.postMessage({
        type: 'shutdown_ack',
        workerId: worker.workerId
      });
      process.exit(0);
    }
  } catch (error) {
    parentPort.postMessage({
      type: 'error',
      workerId: worker.workerId,
      error: {
        message: error.message,
        stack: error.stack
      }
    });
  }
});

// Send ready signal
parentPort.postMessage({
  type: 'ready',
  workerId: worker.workerId
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  parentPort.postMessage({
    type: 'error',
    workerId: worker.workerId,
    error: {
      message: error.message,
      stack: error.stack,
      fatal: true
    }
  });
  process.exit(1);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  parentPort.postMessage({
    type: 'error',
    workerId: worker.workerId,
    error: {
      message: `Unhandled promise rejection: ${reason}`,
      promise: promise.toString(),
      fatal: true
    }
  });
  process.exit(1);
});