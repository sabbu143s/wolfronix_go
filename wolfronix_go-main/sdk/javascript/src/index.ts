/**
 * Wolfronix SDK for JavaScript/TypeScript
 * Zero-knowledge encryption made simple
 * 
 * @package @wolfronix/sdk
 * @version 3.0.0
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
  rsaDecryptBase64,
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
  /** API key for authentication (X-Wolfronix-Key header) */
  wolfronixKey?: string;
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

export interface KeyPartResponse {
  file_id: string;
  key_part_a: string;
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

// --- Server-Side Message Encryption Types ---

export interface ServerEncryptResult {
  /** Base64-encoded ciphertext */
  encrypted_message: string;
  /** Base64-encoded nonce */
  nonce: string;
  /** Base64-encoded client key half (Layer 4) or full key (Layer 3) */
  key_part_a: string;
  /** Tag for server's key_part_b lookup (Layer 4 only, empty for Layer 3) */
  message_tag: string;
  /** Unix timestamp */
  timestamp: number;
}

export interface ServerDecryptParams {
  /** Base64-encoded ciphertext (from ServerEncryptResult) */
  encryptedMessage: string;
  /** Base64-encoded nonce */
  nonce: string;
  /** Base64-encoded key_part_a */
  keyPartA: string;
  /** Message tag for Layer 4 (omit for Layer 3) */
  messageTag?: string;
}

export interface ServerBatchEncryptResult {
  results: Array<{
    id: string;
    encrypted_message: string;
    nonce: string;
    seq: number;
  }>;
  /** Shared key_part_a for the batch */
  key_part_a: string;
  /** Shared batch tag for key_part_b lookup (Layer 4) */
  batch_tag: string;
  timestamp: number;
}

export interface StreamSession {
  /** Client's key half (encrypt direction only) */
  keyPartA?: string;
  /** Stream tag for the session */
  streamTag?: string;
}

export interface StreamChunk {
  data: string;  // base64
  seq: number;
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

  /** Expose private key status for testing */
  hasPrivateKey(): boolean {
    return this.privateKey !== null;
  }

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
        wolfronixKey: '',
        timeout: 30000,
        retries: 3,
        insecure: false
      };
    } else {
      this.config = {
        baseUrl: config.baseUrl,
        clientId: config.clientId || '',
        wolfronixKey: config.wolfronixKey || '',
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

    // API key authentication (required by server middleware)
    if (this.config.wolfronixKey) {
      headers['X-Wolfronix-Key'] = this.config.wolfronixKey;
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

        // Support self-signed certs in Node.js (insecure mode)
        // Node.js 18+ supports the `dispatcher` option via undici
        if (this.config.insecure && typeof process !== 'undefined') {
          try {
            // @ts-ignore – Node.js specific: undici Agent with rejectUnauthorized
            const { Agent } = await import('undici');
            (fetchOptions as any).dispatcher = new Agent({
              connect: { rejectUnauthorized: false }
            });
          } catch {
            // undici not available; user should set NODE_TLS_REJECT_UNAUTHORIZED=0
          }
        }

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
      this.token = 'zk-session'; // Local session marker (auth via X-Wolfronix-Key header)
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
      this.token = 'zk-session'; // Local session marker (auth via X-Wolfronix-Key header)

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
   * Decrypt and retrieve a file using zero-knowledge flow.
   * 
   * Flow:
   * 1. GET /api/v1/files/{id}/key → encrypted key_part_a
   * 2. Decrypt key_part_a client-side with private key (RSA-OAEP)
   * 3. POST /api/v1/files/{id}/decrypt with { decrypted_key_a } in body
   * 
   * The private key NEVER leaves the client.
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
  async decrypt(fileId: string, role: string = 'owner'): Promise<Blob> {
    this.ensureAuthenticated();

    if (!fileId) {
      throw new ValidationError('File ID is required');
    }

    if (!this.privateKey) {
      throw new Error("Private key not available. Is user logged in?");
    }

    // Step 1: Fetch encrypted key_part_a from server
    const keyResponse = await this.getFileKey(fileId);

    // Step 2: Decrypt key_part_a client-side with our private key (RSA-OAEP)
    const decryptedKeyA = await rsaDecryptBase64(keyResponse.key_part_a, this.privateKey);

    // Step 3: Send decrypted_key_a to server (private key never leaves client)
    return this.request<Blob>('POST', `/api/v1/files/${fileId}/decrypt`, {
      responseType: 'blob',
      body: {
        decrypted_key_a: decryptedKeyA,
        user_role: role
      }
    });
  }

  /**
   * Decrypt and return as ArrayBuffer (zero-knowledge flow)
   */
  async decryptToBuffer(fileId: string, role: string = 'owner'): Promise<ArrayBuffer> {
    this.ensureAuthenticated();

    if (!fileId) {
      throw new ValidationError('File ID is required');
    }

    if (!this.privateKey) {
      throw new Error("Private key not available. Is user logged in?");
    }

    // Step 1: Fetch encrypted key_part_a from server
    const keyResponse = await this.getFileKey(fileId);

    // Step 2: Decrypt key_part_a client-side (RSA-OAEP)
    const decryptedKeyA = await rsaDecryptBase64(keyResponse.key_part_a, this.privateKey);

    // Step 3: Send decrypted_key_a to server
    return this.request<ArrayBuffer>('POST', `/api/v1/files/${fileId}/decrypt`, {
      responseType: 'arraybuffer',
      body: {
        decrypted_key_a: decryptedKeyA,
        user_role: role
      }
    });
  }

  /**
   * Fetch the encrypted key_part_a for a file (for client-side decryption)
   * 
   * @param fileId The file ID to get the key for
   * @returns KeyPartResponse containing the RSA-OAEP encrypted key_part_a
   */
  async getFileKey(fileId: string): Promise<KeyPartResponse> {
    this.ensureAuthenticated();

    if (!fileId) {
      throw new ValidationError('File ID is required');
    }

    return this.request<KeyPartResponse>('GET', `/api/v1/files/${fileId}/key`);
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
   * @param clientId Optional: override the configured clientId
   */
  async getPublicKey(userId: string, clientId?: string): Promise<string> {
    this.ensureAuthenticated();
    const cid = clientId || this.config.clientId;
    if (!cid) {
      throw new ValidationError('clientId is required for getPublicKey(). Set it in config or pass as second argument.');
    }
    const result = await this.request<{ client_id: string, user_id: string, public_key_pem: string }>(
      'GET', `/api/v1/keys/public/${encodeURIComponent(cid)}/${encodeURIComponent(userId)}`
    );
    return result.public_key_pem;
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
  // Server-Side Message Encryption (Dual-Key Split)
  // ==========================================================================

  /**
   * Encrypt a text message via the Wolfronix server (dual-key split).
   * The server generates an AES key, encrypts the message, and splits the key —
   * you get key_part_a, the server holds key_part_b.
   * 
   * Use this for server-managed message encryption (e.g., stored encrypted messages).
   * For true E2E (where the server never sees plaintext), use encryptMessage() instead.
   * 
   * @param message The plaintext message to encrypt
   * @param options.layer 3 = AES only (full key returned), 4 = dual-key split (default)
   * 
   * @example
   * ```typescript
   * const result = await wfx.serverEncrypt('Hello, World!');
   * // Store result.encrypted_message, result.nonce, result.key_part_a, result.message_tag
   * ```
   */
  async serverEncrypt(message: string, options?: { layer?: number }): Promise<ServerEncryptResult> {
    this.ensureAuthenticated();

    if (!message) {
      throw new ValidationError('Message is required');
    }

    return this.request<ServerEncryptResult>('POST', '/api/v1/messages/encrypt', {
      body: {
        message,
        user_id: this.userId,
        layer: options?.layer || 4,
      }
    });
  }

  /**
   * Decrypt a message previously encrypted via serverEncrypt().
   * 
   * @param params The encrypted message data (from serverEncrypt result)
   * @returns The decrypted plaintext message
   * 
   * @example
   * ```typescript
   * const text = await wfx.serverDecrypt({
   *   encryptedMessage: result.encrypted_message,
   *   nonce: result.nonce,
   *   keyPartA: result.key_part_a,
   *   messageTag: result.message_tag,
   * });
   * ```
   */
  async serverDecrypt(params: ServerDecryptParams): Promise<string> {
    this.ensureAuthenticated();

    if (!params.encryptedMessage || !params.nonce || !params.keyPartA) {
      throw new ValidationError('encryptedMessage, nonce, and keyPartA are required');
    }

    const response = await this.request<{ message: string; timestamp: number }>(
      'POST', '/api/v1/messages/decrypt', {
      body: {
        encrypted_message: params.encryptedMessage,
        nonce: params.nonce,
        key_part_a: params.keyPartA,
        message_tag: params.messageTag || '',
        user_id: this.userId,
      }
    });

    return response.message;
  }

  /**
   * Encrypt multiple messages in a single round-trip (batch).
   * All messages share one AES key (different nonce per message).
   * Efficient for chat history encryption or bulk operations.
   * 
   * @param messages Array of { id, message } objects (max 100)
   * @param options.layer 3 or 4 (default: 4)
   * 
   * @example
   * ```typescript
   * const result = await wfx.serverEncryptBatch([
   *   { id: 'msg1', message: 'Hello' },
   *   { id: 'msg2', message: 'World' },
   * ]);
   * // result.results[0].encrypted_message, result.key_part_a, result.batch_tag
   * ```
   */
  async serverEncryptBatch(
    messages: Array<{ id: string; message: string }>,
    options?: { layer?: number }
  ): Promise<ServerBatchEncryptResult> {
    this.ensureAuthenticated();

    if (!messages || messages.length === 0) {
      throw new ValidationError('At least one message is required');
    }
    if (messages.length > 100) {
      throw new ValidationError('Maximum 100 messages per batch');
    }

    return this.request<ServerBatchEncryptResult>('POST', '/api/v1/messages/batch/encrypt', {
      body: {
        messages,
        user_id: this.userId,
        layer: options?.layer || 4,
      }
    });
  }

  /**
   * Decrypt a single message from a batch result.
   * Uses the shared key_part_a and batch_tag from the batch result.
   * 
   * @param batchResult The batch encrypt result
   * @param index The index of the message to decrypt
   */
  async serverDecryptBatchItem(
    batchResult: ServerBatchEncryptResult,
    index: number
  ): Promise<string> {
    if (index < 0 || index >= batchResult.results.length) {
      throw new ValidationError('Invalid batch index');
    }

    const item = batchResult.results[index];
    return this.serverDecrypt({
      encryptedMessage: item.encrypted_message,
      nonce: item.nonce,
      keyPartA: batchResult.key_part_a,
      messageTag: batchResult.batch_tag,
    });
  }

  // ==========================================================================
  // Real-Time Streaming Encryption (WebSocket)
  // ==========================================================================

  /**
   * Create a streaming encryption/decryption session over WebSocket.
   * Data flows in real-time: send chunks, receive encrypted/decrypted chunks back.
   * 
   * @param direction 'encrypt' for plaintext→ciphertext, 'decrypt' for reverse
   * @param streamKey Required for decrypt — the key_part_a and stream_tag from the encrypt session
   * 
   * @example
   * ```typescript
   * // Encrypt stream
   * const stream = await wfx.createStream('encrypt');
   * stream.onData((chunk, seq) => console.log('Encrypted chunk', seq));
   * stream.send('Hello chunk 1');
   * stream.send('Hello chunk 2');
   * const summary = await stream.end();
   * // Save stream.keyPartA and stream.streamTag for decryption
   * 
   * // Decrypt stream
   * const dStream = await wfx.createStream('decrypt', {
   *   keyPartA: stream.keyPartA!,
   *   streamTag: stream.streamTag!,
   * });
   * dStream.onData((chunk, seq) => console.log('Decrypted:', chunk));
   * dStream.send(encryptedChunk1);
   * await dStream.end();
   * ```
   */
  async createStream(
    direction: 'encrypt' | 'decrypt',
    streamKey?: { keyPartA: string; streamTag: string }
  ): Promise<WolfronixStream> {
    this.ensureAuthenticated();

    if (direction === 'decrypt' && !streamKey) {
      throw new ValidationError('streamKey (keyPartA + streamTag) is required for decrypt streams');
    }

    const stream = new WolfronixStream(this.config, this.userId!);
    await stream.connect(direction, streamKey);
    return stream;
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
// WolfronixStream — Real-Time Streaming Encryption over WebSocket
// ============================================================================

type StreamDataCallback = (data: string, seq: number) => void;
type StreamErrorCallback = (error: Error) => void;

/**
 * Real-time streaming encryption/decryption over WebSocket.
 * Each chunk is individually encrypted with AES-256-GCM using counter-based nonces.
 * 
 * @example
 * ```typescript
 * const stream = await wfx.createStream('encrypt');
 * stream.onData((chunk, seq) => sendToRecipient(chunk));
 * stream.onError((err) => console.error(err));
 * await stream.send('audio chunk data...');
 * const summary = await stream.end();
 * ```
 */
export class WolfronixStream {
  private ws: WebSocket | null = null;
  private dataCallbacks: StreamDataCallback[] = [];
  private errorCallbacks: StreamErrorCallback[] = [];
  private pendingChunks: Map<number, { resolve: (data: string) => void; reject: (err: Error) => void }> = new Map();
  private seqCounter = 0;

  /** Client's key half (available after encrypt stream init) */
  public keyPartA: string | null = null;
  /** Stream tag (available after encrypt stream init) */
  public streamTag: string | null = null;

  /** @internal */
  constructor(
    private readonly config: Required<WolfronixConfig>,
    private readonly userId: string
  ) { }

  /** @internal Connect and initialize the stream session */
  async connect(
    direction: 'encrypt' | 'decrypt',
    streamKey?: { keyPartA: string; streamTag: string }
  ): Promise<void> {
    return new Promise((resolve, reject) => {
      // Build WebSocket URL with query-param auth (browsers can't set custom WS headers)
      const wsBase = this.config.baseUrl.replace(/^http/, 'ws');
      const params = new URLSearchParams();
      if (this.config.wolfronixKey) {
        params.set('wolfronix_key', this.config.wolfronixKey);
      }
      if (this.config.clientId) {
        params.set('client_id', this.config.clientId);
      }
      const wsUrl = `${wsBase}/api/v1/stream?${params.toString()}`;

      this.ws = new WebSocket(wsUrl);

      this.ws.onopen = () => {
        // Send init message
        const initMsg: Record<string, string> = { type: 'init', direction };
        if (direction === 'decrypt' && streamKey) {
          initMsg.key_part_a = streamKey.keyPartA;
          initMsg.stream_tag = streamKey.streamTag;
        }
        this.ws!.send(JSON.stringify(initMsg));
      };

      let initResolved = false;

      this.ws.onmessage = (event: MessageEvent) => {
        try {
          const msg = JSON.parse(event.data as string);

          if (msg.type === 'error') {
            const err = new Error(msg.error);
            if (!initResolved) {
              initResolved = true;
              reject(err);
            }
            this.errorCallbacks.forEach(cb => cb(err));
            return;
          }

          if (msg.type === 'init_ack' && !initResolved) {
            initResolved = true;
            if (msg.key_part_a) this.keyPartA = msg.key_part_a;
            if (msg.stream_tag) this.streamTag = msg.stream_tag;
            resolve();
            return;
          }

          if (msg.type === 'data') {
            // Notify all data callbacks
            this.dataCallbacks.forEach(cb => cb(msg.data, msg.seq));
            // Resolve pending promise for this sequence
            const pending = this.pendingChunks.get(msg.seq);
            if (pending) {
              pending.resolve(msg.data);
              this.pendingChunks.delete(msg.seq);
            }
            return;
          }

          if (msg.type === 'end_ack') {
            // Handled by end() promise
            return;
          }
        } catch (e) {
          const err = new Error('Failed to parse stream message');
          this.errorCallbacks.forEach(cb => cb(err));
        }
      };

      this.ws.onerror = (event) => {
        const err = new Error('WebSocket error');
        if (!initResolved) {
          initResolved = true;
          reject(err);
        }
        this.errorCallbacks.forEach(cb => cb(err));
      };

      this.ws.onclose = () => {
        // Reject all pending chunks
        this.pendingChunks.forEach(p => p.reject(new Error('Stream closed')));
        this.pendingChunks.clear();
      };
    });
  }

  /**
   * Send a data chunk for encryption/decryption.
   * Returns a promise that resolves with the processed (encrypted/decrypted) chunk.
   * 
   * @param data String or base64-encoded binary data
   * @returns The processed chunk (base64-encoded)
   */
  async send(data: string): Promise<string> {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new Error('Stream not connected');
    }

    // If data is plain text, base64-encode it
    const b64Data = this.isBase64(data) ? data : btoa(data);
    const seq = this.seqCounter++;

    return new Promise<string>((resolve, reject) => {
      this.pendingChunks.set(seq, { resolve, reject });
      this.ws!.send(JSON.stringify({ type: 'data', data: b64Data }));
    });
  }

  /**
   * Send raw binary data for encryption/decryption.
   * 
   * @param buffer ArrayBuffer or Uint8Array
   * @returns The processed chunk (base64-encoded)
   */
  async sendBinary(buffer: ArrayBuffer | Uint8Array): Promise<string> {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    const b64 = btoa(binary);
    return this.send(b64);
  }

  /**
   * Register a callback for incoming data chunks.
   * 
   * @param callback Called with (base64Data, sequenceNumber) for each chunk
   */
  onData(callback: StreamDataCallback): void {
    this.dataCallbacks.push(callback);
  }

  /**
   * Register a callback for stream errors.
   */
  onError(callback: StreamErrorCallback): void {
    this.errorCallbacks.push(callback);
  }

  /**
   * End the stream session. Returns the total number of chunks processed.
   */
  async end(): Promise<{ chunksProcessed: number }> {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      return { chunksProcessed: this.seqCounter };
    }

    return new Promise((resolve) => {
      const originalHandler = this.ws!.onmessage;
      this.ws!.onmessage = (event: MessageEvent) => {
        try {
          const msg = JSON.parse(event.data as string);
          if (msg.type === 'end_ack') {
            resolve({ chunksProcessed: msg.chunks_processed || this.seqCounter });
            this.ws!.close();
            return;
          }
        } catch { /* ignore */ }
        // Forward other messages
        if (originalHandler && this.ws) originalHandler.call(this.ws, event);
      };

      this.ws!.send(JSON.stringify({ type: 'end' }));

      // Timeout fallback
      setTimeout(() => {
        resolve({ chunksProcessed: this.seqCounter });
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
          this.ws.close();
        }
      }, 5000);
    });
  }

  /**
   * Close the stream immediately without sending an end message.
   */
  close(): void {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this.pendingChunks.forEach(p => p.reject(new Error('Stream closed')));
    this.pendingChunks.clear();
  }

  private isBase64(str: string): boolean {
    if (str.length % 4 !== 0) return false;
    return /^[A-Za-z0-9+/]*={0,2}$/.test(str);
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
