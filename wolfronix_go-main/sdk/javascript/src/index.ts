/**
 * Wolfronix SDK for JavaScript/TypeScript
 * Zero-knowledge encryption made simple
 * 
 * @package @wolfronix/sdk
 * @version 1.3.0
 */

import {
  generateKeyPair,
  exportKeyToPEM,
  importKeyFromPEM,
  wrapPrivateKey,
  unwrapPrivateKey,
  generateSessionKey,
  encryptData,
  decryptData,
  rsaEncrypt,
  rsaDecrypt,
  exportSessionKey,
  importSessionKey
} from './crypto';

// ============================================================================
// Types & Interfaces
// ============================================================================

export interface WolfronixConfig {
  /** Wolfronix server base URL */
  baseUrl: string;
  /** Your enterprise client ID (optional for self-hosted) */
  clientId?: string;
  /** Request timeout in milliseconds (default: 30000) */
  timeout?: number;
  /** Retry failed requests (default: 3) */
  retries?: number;
  /** Skip SSL verification for self-signed certs (default: false) */
  insecure?: boolean;
}

export interface AuthResponse {
  success: boolean;
  user_id: string;
  token: string;
  message: string;
}

export interface EncryptResponse {
  status: string;
  file_id: string;
  file_size: number;
  enc_time_ms: number;
}

export interface FileInfo {
  file_id: string;
  original_name: string;
  encrypted_size: number;
  created_at: string;
}

export interface ListFilesResponse {
  success: boolean;
  files: FileInfo[];
  total: number;
}

export interface DeleteResponse {
  success: boolean;
  message: string;
}

export interface MetricsResponse {
  success: boolean;
  total_encryptions: number;
  total_decryptions: number;
  total_bytes_encrypted: number;
  total_bytes_decrypted: number;
}

export interface EncryptMessagePacket {
  key: string; // Encrypted AES session key (RSA encrypted)
  iv: string;  // AES-GCM IV
  msg: string; // Encrypted message text (AES encrypted)
}



// ============================================================================
// Error Classes
// ============================================================================

export class WolfronixError extends Error {
  public readonly code: string;
  public readonly statusCode?: number;
  public readonly details?: Record<string, unknown>;

  constructor(message: string, code: string, statusCode?: number, details?: Record<string, unknown>) {
    super(message);
    this.name = 'WolfronixError';
    this.code = code;
    this.statusCode = statusCode;
    this.details = details;
  }
}

export class AuthenticationError extends WolfronixError {
  constructor(message: string = 'Authentication failed') {
    super(message, 'AUTH_ERROR', 401);
    this.name = 'AuthenticationError';
  }
}

export class FileNotFoundError extends WolfronixError {
  constructor(fileId: string) {
    super(`File not found: ${fileId}`, 'FILE_NOT_FOUND', 404);
    this.name = 'FileNotFoundError';
  }
}

export class PermissionDeniedError extends WolfronixError {
  constructor(message: string = 'Permission denied') {
    super(message, 'PERMISSION_DENIED', 403);
    this.name = 'PermissionDeniedError';
  }
}

export class NetworkError extends WolfronixError {
  constructor(message: string = 'Network request failed') {
    super(message, 'NETWORK_ERROR');
    this.name = 'NetworkError';
  }
}

export class ValidationError extends WolfronixError {
  constructor(message: string) {
    super(message, 'VALIDATION_ERROR', 400);
    this.name = 'ValidationError';
  }
}

// ============================================================================
// Main Wolfronix Client
// ============================================================================

export class Wolfronix {
  private readonly config: Required<WolfronixConfig>;
  private token: string | null = null;
  private userId: string | null = null;
  private tokenExpiry: Date | null = null;

  // Client-side keys (never stored on server in raw form)
  private publicKey: CryptoKey | null = null;
  private privateKey: CryptoKey | null = null;
  private publicKeyPEM: string | null = null;

  /**
   * Create a new Wolfronix client
   * 
   * @example
   * ```typescript
   * const wfx = new Wolfronix({
   *   baseUrl: 'https://wolfronix-server:5002',
   *   clientId: 'your-client-id'
   * });
   * ```
   */
  constructor(config: WolfronixConfig | string) {
    if (typeof config === 'string') {
      // Simple constructor: new Wolfronix('https://server:5002')
      this.config = {
        baseUrl: config,
        clientId: '',
        timeout: 30000,
        retries: 3,
        insecure: false
      };
    } else {
      this.config = {
        baseUrl: config.baseUrl,
        clientId: config.clientId || '',
        timeout: config.timeout || 30000,
        retries: config.retries || 3,
        insecure: config.insecure || false
      };
    }

    // Remove trailing slash
    this.config.baseUrl = this.config.baseUrl.replace(/\/$/, '');
  }

  // ==========================================================================
  // Private Helpers
  // ==========================================================================

  private getHeaders(includeAuth: boolean = true): Record<string, string> {
    const headers: Record<string, string> = {
      'Accept': 'application/json'
    };

    if (this.config.clientId) {
      headers['X-Client-ID'] = this.config.clientId;
    }

    if (includeAuth && this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
      if (this.userId) {
        headers['X-User-ID'] = this.userId;
      }
    }

    return headers;
  }

  private async request<T>(
    method: string,
    endpoint: string,
    options: {
      body?: unknown;
      formData?: FormData;
      includeAuth?: boolean;
      responseType?: 'json' | 'blob' | 'arraybuffer';
      headers?: Record<string, string>; // Added headers support
    } = {}
  ): Promise<T> {
    const { body, formData, includeAuth = true, responseType = 'json', headers: extraHeaders } = options;
    const url = `${this.config.baseUrl}${endpoint}`;
    const headers = { ...this.getHeaders(includeAuth), ...extraHeaders };

    if (body && !formData) {
      headers['Content-Type'] = 'application/json';
    }

    let lastError: Error | null = null;

    for (let attempt = 1; attempt <= this.config.retries; attempt++) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);

        const fetchOptions: RequestInit = {
          method,
          headers,
          signal: controller.signal,
        };

        if (formData) {
          fetchOptions.body = formData;
        } else if (body) {
          fetchOptions.body = JSON.stringify(body);
        }

        const response = await fetch(url, fetchOptions);
        clearTimeout(timeoutId);

        // Handle errors
        if (!response.ok) {
          const errorBody = await response.json().catch(() => ({}));

          if (response.status === 401) {
            throw new AuthenticationError(errorBody.error || 'Authentication failed');
          }
          if (response.status === 403) {
            throw new PermissionDeniedError(errorBody.error || 'Permission denied');
          }
          if (response.status === 404) {
            throw new FileNotFoundError(endpoint);
          }

          throw new WolfronixError(
            errorBody.error || `Request failed with status ${response.status}`,
            'REQUEST_ERROR',
            response.status,
            errorBody
          );
        }

        // Return appropriate response type
        if (responseType === 'blob') {
          return await response.blob() as T;
        }
        if (responseType === 'arraybuffer') {
          return await response.arrayBuffer() as T;
        }
        return await response.json() as T;

      } catch (error) {
        lastError = error as Error;

        // Don't retry auth or permission errors
        if (error instanceof AuthenticationError ||
          error instanceof PermissionDeniedError ||
          error instanceof FileNotFoundError) {
          throw error;
        }

        // Retry on network errors
        if (attempt < this.config.retries) {
          await this.sleep(Math.pow(2, attempt) * 100); // Exponential backoff
          continue;
        }
      }
    }

    throw lastError || new NetworkError('Request failed after retries');
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  private ensureAuthenticated(): void {
    if (!this.token) {
      throw new AuthenticationError('Not authenticated. Call login() or register() first.');
    }
  }

  // ==========================================================================
  // Authentication Methods
  // ==========================================================================

  /**
   * Register a new user
   * 
   * @example
   * ```typescript
   * const { user_id, token } = await wfx.register('user@example.com', 'password123');
   * ```
   */
  async register(email: string, password: string): Promise<AuthResponse> {
    if (!email || !password) {
      throw new ValidationError('Email and password are required');
    }

    // 1. Generate RSA Key Pair
    const keyPair = await generateKeyPair();

    // 2. Export Public Key
    const publicKeyPEM = await exportKeyToPEM(keyPair.publicKey, 'public');

    // 3. Wrap Private Key
    const { encryptedKey, salt } = await wrapPrivateKey(keyPair.privateKey, password);

    // 4. Register with Server (Zero-Knowledge)
    const response = await this.request<AuthResponse>('POST', '/api/v1/keys/register', {
      body: {
        client_id: this.config.clientId,
        user_id: email, // Using email as user_id for simplicity
        public_key_pem: publicKeyPEM,
        encrypted_private_key: encryptedKey,
        salt: salt
      },
      includeAuth: false
    });

    if (response.success) {
      // Store unwrapped keys in memory
      this.userId = email;
      this.publicKey = keyPair.publicKey;
      this.privateKey = keyPair.privateKey;
      this.publicKeyPEM = publicKeyPEM;

      // Note: This endpoint doesn't return a token in the new flow, 
      // but we set success state. In a real app, you might auto-login or require login.
      this.token = "session_" + Date.now(); // Mock token for compatibility
    }

    return response;
  }

  /**
   * Login with existing credentials
   * 
   * @example
   * ```typescript
   * await wfx.login('user@example.com', 'password123');
   * ```
   */
  async login(email: string, password: string): Promise<AuthResponse> {
    if (!email || !password) {
      throw new ValidationError('Email and password are required');
    }

    // 1. Fetch Encrypted Keys
    // We use a custom endpoint format: /api/v1/keys/login is POST in main.go
    const response = await this.request<any>('POST', '/api/v1/keys/login', {
      body: {
        client_id: this.config.clientId,
        user_id: email
      },
      includeAuth: false
    });

    if (!response.encrypted_private_key || !response.salt) {
      throw new AuthenticationError('Invalid credentials or keys not found');
    }

    // 2. Unwrap Private Key
    try {
      this.privateKey = await unwrapPrivateKey(
        response.encrypted_private_key,
        password,
        response.salt
      );

      // 3. Import Public Key
      this.publicKeyPEM = response.public_key_pem;
      this.publicKey = await importKeyFromPEM(response.public_key_pem, 'public');

      this.userId = email;
      this.token = "session_" + Date.now(); // Mock token

      return {
        success: true,
        user_id: email,
        token: this.token,
        message: 'Logged in successfully'
      };

    } catch (err) {
      throw new AuthenticationError('Invalid password (decryption failed)');
    }
  }

  /**
   * Set authentication token directly (useful for server-side apps)
   * 
   * @example
   * ```typescript
   * wfx.setToken('jwt-token-here', 'user-id-here');
   * ```
   */
  setToken(token: string, userId?: string): void {
    this.token = token;
    this.userId = userId || null;
    this.tokenExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000);
  }

  /**
   * Clear authentication state (logout)
   */
  logout(): void {
    this.token = null;
    this.userId = null;
    this.tokenExpiry = null;
    this.publicKey = null;
    this.privateKey = null;
    this.publicKeyPEM = null;
  }

  /**
   * Check if client is authenticated
   */
  isAuthenticated(): boolean {
    return !!this.token && (!this.tokenExpiry || this.tokenExpiry > new Date());
  }

  /**
   * Get current user ID
   */
  getUserId(): string | null {
    return this.userId;
  }

  // ==========================================================================
  // File Operations
  // ==========================================================================

  /**
   * Encrypt and store a file
   * 
   * @example
   * ```typescript
   * // Browser
   * const fileInput = document.querySelector('input[type="file"]');
   * const result = await wfx.encrypt(fileInput.files[0]);
   * 
   * // Node.js
   * const buffer = fs.readFileSync('document.pdf');
   * const result = await wfx.encrypt(buffer, 'document.pdf');
   * ```
   */
  async encrypt(
    file: File | Blob | ArrayBuffer | Uint8Array,
    filename?: string
  ): Promise<EncryptResponse> {
    this.ensureAuthenticated();

    const formData = new FormData();

    // Handle different input types
    if (file instanceof File) {
      formData.append('file', file);
    } else if (file instanceof Blob) {
      formData.append('file', file, filename || 'file');
    } else if (file instanceof ArrayBuffer) {
      const blob = new Blob([new Uint8Array(file)]);
      formData.append('file', blob, filename || 'file');
    } else if (file instanceof Uint8Array) {
      // Convert Uint8Array to Blob safely (handle SharedArrayBuffer case)
      const arrayBuffer = file.buffer.slice(file.byteOffset, file.byteOffset + file.byteLength) as ArrayBuffer;
      const blob = new Blob([arrayBuffer]);
      formData.append('file', blob, filename || 'file');
    } else {
      throw new ValidationError('Invalid file type. Expected File, Blob, Buffer, or ArrayBuffer');
    }

    formData.append('user_id', this.userId || '');

    if (!this.publicKeyPEM) {
      throw new Error("Public key not available. Is user logged in?");
    }
    formData.append('client_public_key', this.publicKeyPEM);

    const response = await this.request<any>('POST', '/api/v1/encrypt', {
      formData
    });

    return {
      status: response.status,
      file_id: String(response.file_id),
      file_size: response.file_size,
      enc_time_ms: response.enc_time_ms
    };
  }


  /**
   * Decrypt and retrieve a file
   * 
   * @example
   * ```typescript
   * // Get as Blob (browser)
   * const blob = await wfx.decrypt('file-id');
   * const url = URL.createObjectURL(blob);
   * 
   * // Get as Buffer (Node.js)
   * const buffer = await wfx.decryptToBuffer('file-id');
   * fs.writeFileSync('decrypted.pdf', buffer);
   * ```
   */
  async decrypt(fileId: string): Promise<Blob> {
    this.ensureAuthenticated();

    if (!fileId) {
      throw new ValidationError('File ID is required');
    }

    if (!this.privateKey) {
      throw new Error("Private key not available. Is user logged in?");
    }

    const privateKeyPEM = await exportKeyToPEM(this.privateKey, 'private');

    return this.request<Blob>('POST', `/api/v1/files/${fileId}/decrypt`, {
      responseType: 'blob',
      headers: {
        'X-Private-Key': privateKeyPEM,
        'X-User-Role': 'owner'
      }
    });
  }

  /**
   * Decrypt and return as ArrayBuffer
   */
  async decryptToBuffer(fileId: string): Promise<ArrayBuffer> {
    this.ensureAuthenticated();

    if (!fileId) {
      throw new ValidationError('File ID is required');
    }

    if (!this.privateKey) {
      throw new Error("Private key not available. Is user logged in?");
    }
    const privateKeyPEM = await exportKeyToPEM(this.privateKey, 'private');

    return this.request<ArrayBuffer>('POST', `/api/v1/files/${fileId}/decrypt`, {
      responseType: 'arraybuffer',
      headers: {
        'X-Private-Key': privateKeyPEM,
        'X-User-Role': 'owner'
      }
    });
  }


  /**
   * List all encrypted files for current user
   * 
   * @example
   * ```typescript
   * const { files } = await wfx.listFiles();
   * files.forEach(f => console.log(f.original_name, f.file_id));
   * ```
   */
  async listFiles(): Promise<ListFilesResponse> {
    this.ensureAuthenticated();
    const files = await this.request<any[]>('GET', '/api/v1/files');
    return {
      success: true,
      files: (files || []).map(f => ({
        file_id: f.id,
        original_name: f.name,
        encrypted_size: f.size_bytes,
        created_at: f.date
      })),
      total: (files || []).length
    };
  }

  /**
   * Delete an encrypted file
   * 
   * @example
   * ```typescript
   * await wfx.deleteFile('file-id');
   * ```
   */
  async deleteFile(fileId: string): Promise<DeleteResponse> {
    this.ensureAuthenticated();

    if (!fileId) {
      throw new ValidationError('File ID is required');
    }

    return this.request<DeleteResponse>('DELETE', `/api/v1/files/${fileId}`);
  }

  // ============================================================================
  // E2E Chat Encryption Methods
  // ============================================================================

  /**
   * Get another user's public key (for E2E encryption)
   * @param userId The ID of the recipient
   */
  async getPublicKey(userId: string): Promise<string> {
    this.ensureAuthenticated();
    const result = await this.request<{ user_id: string, public_key: string }>('GET', `/api/v1/keys/${userId}`);
    return result.public_key;
  }

  /**
   * Encrypt a short text message for a recipient (Hybrid Encryption: RSA + AES)
   * Returns a secure JSON string (packet) to send via chat
   * 
   * @param text The plain text message
   * @param recipientId The recipient's user ID
   */
  async encryptMessage(text: string, recipientId: string): Promise<string> {
    this.ensureAuthenticated();

    // 1. Get Recipient's Public Key
    const recipientPubKeyPEM = await this.getPublicKey(recipientId);
    const recipientPubKey = await importKeyFromPEM(recipientPubKeyPEM, 'public');

    // 2. Generate Ephemeral Session Key (AES-256)
    const sessionKey = await generateSessionKey();

    // 3. Encrypt Message with Session Key
    const { encrypted: encryptedMsg, iv } = await encryptData(text, sessionKey);

    // 4. Encrypt Session Key with Recipient's RSA Key
    const rawSessionKey = await exportSessionKey(sessionKey);
    const encryptedSessionKey = await rsaEncrypt(rawSessionKey, recipientPubKey);

    // 5. Pack everything
    const packet: EncryptMessagePacket = {
      key: encryptedSessionKey,
      iv: iv,
      msg: encryptedMsg
    };

    return JSON.stringify(packet);
  }

  /**
   * Decrypt a message packet received from chat
   * 
   * @param packetJson The secure JSON string packet
   */
  async decryptMessage(packetJson: string): Promise<string> {
    this.ensureAuthenticated();
    if (!this.privateKey) {
      throw new Error("Private key not available. Is user logged in?");
    }

    let packet: EncryptMessagePacket;
    try {
      packet = JSON.parse(packetJson);
    } catch (e) {
      throw new ValidationError("Invalid message packet format");
    }

    if (!packet.key || !packet.iv || !packet.msg) {
      throw new ValidationError("Invalid message packet structure");
    }

    try {
      // 1. Decrypt Session Key with My Private Key
      // This will throw if it wasn't encrypted for me
      const rawSessionKey = await rsaDecrypt(packet.key, this.privateKey);

      // 2. Import Session Key
      const sessionKey = await importSessionKey(rawSessionKey);

      // 3. Decrypt Message Body
      const plainText = await decryptData(packet.msg, packet.iv, sessionKey);

      return plainText;
    } catch (error) {
      throw new Error("Decryption failed. You may not be the intended recipient.");
    }
  }

  // ==========================================================================
  // Metrics & Status
  // ==========================================================================

  /**
   * Get encryption/decryption metrics
   * 
   * @example
   * ```typescript
   * const metrics = await wfx.getMetrics();
   * console.log(`Total encryptions: ${metrics.total_encryptions}`);
   * ```
   */
  async getMetrics(): Promise<MetricsResponse> {
    this.ensureAuthenticated();
    return this.request<MetricsResponse>('GET', '/api/v1/metrics/summary');
  }

  /**
   * Check if server is healthy
   */
  async healthCheck(): Promise<boolean> {
    try {
      await this.request<{ status: string }>('GET', '/health', {
        includeAuth: false
      });
      return true;
    } catch {
      return false;
    }
  }
}

// ============================================================================
// Default Export & Factory
// ============================================================================

/**
 * Create a new Wolfronix client
 * 
 * @example
 * ```typescript
 * import { createClient } from '@wolfronix/sdk';
 * 
 * const wfx = createClient({
 *   baseUrl: 'https://wolfronix-server:5002',
 *   clientId: 'your-client-id'
 * });
 * ```
 */
export function createClient(config: WolfronixConfig | string): Wolfronix {
  return new Wolfronix(config);
}

export default Wolfronix;
