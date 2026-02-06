/**
 * Wolfronix SDK for JavaScript/TypeScript
 * Zero-knowledge encryption made simple
 * 
 * @package @wolfronix/sdk
 * @version 1.0.0
 */

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
  success: boolean;
  file_id: string;
  original_name: string;
  encrypted_size: number;
  message: string;
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

export interface StreamToken {
  token: string;
  expires_at: string;
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
    } = {}
  ): Promise<T> {
    const { body, formData, includeAuth = true, responseType = 'json' } = options;
    const url = `${this.config.baseUrl}${endpoint}`;
    const headers = this.getHeaders(includeAuth);

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

    const response = await this.request<AuthResponse>('POST', '/api/v1/register', {
      body: { email, password },
      includeAuth: false
    });

    if (response.success) {
      this.token = response.token;
      this.userId = response.user_id;
      this.tokenExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
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

    const response = await this.request<AuthResponse>('POST', '/api/v1/login', {
      body: { email, password },
      includeAuth: false
    });

    if (response.success) {
      this.token = response.token;
      this.userId = response.user_id;
      this.tokenExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
    }

    return response;
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

    return this.request<EncryptResponse>('POST', '/api/v1/encrypt', {
      formData
    });
  }

  /**
   * Encrypt a file using streaming (for large files)
   * 
   * @example
   * ```typescript
   * const result = await wfx.encryptStream(largeFile, (progress) => {
   *   console.log(`Progress: ${progress}%`);
   * });
   * ```
   */
  async encryptStream(
    file: File | Blob,
    onProgress?: (percent: number) => void
  ): Promise<EncryptResponse> {
    this.ensureAuthenticated();

    // Get stream token first
    const tokenResponse = await this.request<{ token: string }>('POST', '/api/v1/stream/token', {
      body: { 
        user_id: this.userId,
        client_id: this.config.clientId
      }
    });

    const formData = new FormData();
    formData.append('file', file);
    formData.append('user_id', this.userId || '');
    formData.append('stream_token', tokenResponse.token);

    // For progress tracking (browser only)
    if (onProgress && typeof XMLHttpRequest !== 'undefined') {
      return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        
        xhr.upload.onprogress = (event) => {
          if (event.lengthComputable) {
            onProgress(Math.round((event.loaded / event.total) * 100));
          }
        };

        xhr.onload = () => {
          if (xhr.status >= 200 && xhr.status < 300) {
            resolve(JSON.parse(xhr.responseText));
          } else {
            reject(new WolfronixError('Upload failed', 'UPLOAD_ERROR', xhr.status));
          }
        };

        xhr.onerror = () => reject(new NetworkError('Upload failed'));

        xhr.open('POST', `${this.config.baseUrl}/api/v1/stream/encrypt`);
        
        const headers = this.getHeaders();
        Object.entries(headers).forEach(([key, value]) => {
          xhr.setRequestHeader(key, value);
        });

        xhr.send(formData);
      });
    }

    return this.request<EncryptResponse>('POST', '/api/v1/stream/encrypt', {
      formData
    });
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

    return this.request<Blob>('GET', `/api/v1/decrypt/${fileId}`, {
      responseType: 'blob'
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

    return this.request<ArrayBuffer>('GET', `/api/v1/decrypt/${fileId}`, {
      responseType: 'arraybuffer'
    });
  }

  /**
   * Decrypt using streaming (for large files)
   */
  async decryptStream(
    fileId: string,
    onProgress?: (percent: number) => void
  ): Promise<Blob> {
    this.ensureAuthenticated();

    // For progress tracking (browser only)
    if (onProgress && typeof XMLHttpRequest !== 'undefined') {
      return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.responseType = 'blob';

        xhr.onprogress = (event) => {
          if (event.lengthComputable) {
            onProgress(Math.round((event.loaded / event.total) * 100));
          }
        };

        xhr.onload = () => {
          if (xhr.status >= 200 && xhr.status < 300) {
            resolve(xhr.response);
          } else {
            reject(new WolfronixError('Download failed', 'DOWNLOAD_ERROR', xhr.status));
          }
        };

        xhr.onerror = () => reject(new NetworkError('Download failed'));

        xhr.open('GET', `${this.config.baseUrl}/api/v1/stream/decrypt/${fileId}`);
        
        const headers = this.getHeaders();
        Object.entries(headers).forEach(([key, value]) => {
          xhr.setRequestHeader(key, value);
        });

        xhr.send();
      });
    }

    return this.request<Blob>('GET', `/api/v1/stream/decrypt/${fileId}`, {
      responseType: 'blob'
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
    return this.request<ListFilesResponse>('GET', '/api/v1/files');
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
    return this.request<MetricsResponse>('GET', '/api/v1/metrics');
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
