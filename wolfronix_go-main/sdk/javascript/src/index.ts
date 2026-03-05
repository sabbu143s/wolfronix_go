/**
 * Wolfronix SDK for JavaScript/TypeScript
 * Zero-knowledge encryption made simple
 * 
 * @package @wolfronix/sdk
 * @version 2.4.3
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

export interface RecoverySetup {
  recoveryPhrase: string;
  recoveryWords: string[];
}

export interface RegisterOptions {
  enableRecovery?: boolean;
  recoveryPhrase?: string;
}

export interface EncryptResponse {
  status: string;
  file_id: string;
  file_size: number;
  enc_time_ms: number;
  /** Detailed timing breakdown from server */
  upload_ms?: number;
  read_ms?: number;
  encrypt_ms?: number;
  store_ms?: number;
  total_ms?: number;
  /** Any extra fields from the server response */
  [key: string]: unknown;
}

export interface ChunkedEncryptResult {
  upload_id: string;
  filename: string;
  total_chunks: number;
  chunk_size_bytes: number;
  uploaded_chunks: number;
  chunk_file_ids: string[];
  complete: boolean;
}

export interface ResumableUploadState {
  upload_id: string;
  filename: string;
  file_size: number;
  chunk_size_bytes: number;
  total_chunks: number;
  uploaded_chunks: number[];
  chunk_file_ids: string[];
  created_at: number;
  updated_at: number;
}

export interface ResumableEncryptOptions {
  filename?: string;
  chunkSizeBytes?: number;
  existingState?: ResumableUploadState;
  onProgress?: (uploadedChunks: number, totalChunks: number) => void;
}

export interface ChunkedDecryptManifest {
  filename: string;
  chunk_file_ids: string[];
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

export interface GroupEncryptPacket {
  v: 1;
  type: 'group_sender_key';
  sender_id: string;
  group_id: string;
  timestamp: number;
  ciphertext: string;
  iv: string;
  recipient_keys: Record<string, string>;
}

export interface PfsPreKeyBundle {
  protocol: 'wfx-dr-v1';
  user_id?: string;
  ratchet_pub_jwk: JsonWebKey;
  created_at: number;
}

export interface PfsMessagePacket {
  v: 1;
  type: 'pfs_ratchet';
  session_id: string;
  n: number;
  pn: number;
  ratchet_pub_jwk: JsonWebKey;
  iv: string;
  ciphertext: string;
  timestamp: number;
}

export interface PfsSessionState {
  protocol: 'wfx-dr-v1';
  session_id: string;
  role: 'initiator' | 'responder';
  root_key: string;
  send_chain_key: string;
  recv_chain_key: string;
  send_count: number;
  recv_count: number;
  prev_send_count: number;
  my_ratchet_private_jwk: JsonWebKey;
  my_ratchet_public_jwk: JsonWebKey;
  their_ratchet_public_jwk: JsonWebKey;
  skipped_keys: Record<string, string>;
  created_at: number;
  updated_at: number;
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

// --- Enterprise Admin Types ---

/** Supported managed connector database types */
export type DBType = 'supabase' | 'mongodb' | 'mysql' | 'firebase' | 'postgresql' | 'custom_api';

export interface WolfronixAdminConfig {
  /** Wolfronix server base URL */
  baseUrl: string;
  /** Admin API key (X-Admin-Key header) */
  adminKey: string;
  /** Request timeout in milliseconds (default: 30000) */
  timeout?: number;
  /** Skip SSL verification for self-signed certs (default: false) */
  insecure?: boolean;
}

export interface EnterpriseClient {
  id: number;
  client_id: string;
  client_name: string;
  api_endpoint: string;
  api_key: string;
  wolfronix_key: string;
  db_type: DBType;
  db_config: string;
  user_count: number;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface RegisterClientRequest {
  /** Unique client identifier */
  client_id: string;
  /** Human-readable client name */
  client_name: string;
  /** Database type — managed connector or custom_api */
  db_type: DBType;
  /** JSON string with database credentials (required for managed connectors) */
  db_config?: string;
  /** Client's storage API URL (required only for custom_api) */
  api_endpoint?: string;
  /** API key for client's custom API (optional) */
  api_key?: string;
}

export interface RegisterClientResponse {
  status: string;
  client_id: string;
  wolfronix_key: string;
  db_type: DBType;
  message: string;
  connector?: string;
  api_endpoint?: string;
}

export interface ListClientsResponse {
  clients: EnterpriseClient[] | null;
  count: number;
}

export interface UpdateClientRequest {
  api_endpoint?: string;
  db_type?: DBType;
  db_config?: string;
}

export interface UpdateClientResponse {
  status: string;
  message: string;
}

export interface DeactivateClientResponse {
  status: string;
  message: string;
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

const RECOVERY_WORDS = [
  'able', 'about', 'absorb', 'access', 'acid', 'across', 'action', 'adapt', 'admit', 'adult',
  'agent', 'agree', 'ahead', 'air', 'alert', 'alpha', 'anchor', 'angle', 'apple', 'arch',
  'arena', 'argue', 'armed', 'arrow', 'asset', 'atlas', 'attack', 'audio', 'august', 'auto',
  'avoid', 'awake', 'aware', 'badge', 'balance', 'banana', 'basic', 'beach', 'beauty', 'before',
  'begin', 'below', 'benefit', 'best', 'beyond', 'bicycle', 'bird', 'black', 'bless', 'board',
  'bold', 'bonus', 'border', 'borrow', 'bottle', 'bottom', 'brain', 'brand', 'brave', 'breeze',
  'brick', 'brief', 'bring', 'brother', 'budget', 'build', 'camera', 'camp', 'canal', 'carbon',
  'carry', 'casual', 'center', 'chain', 'change', 'charge', 'chase', 'cheap', 'check', 'chief',
  'choice', 'circle', 'city', 'claim', 'class', 'clean', 'clear', 'client', 'clock', 'cloud',
  'coach', 'coast', 'color', 'column', 'combo', 'common', 'concept', 'confirm', 'connect', 'copy',
  'core', 'corner', 'correct', 'cost', 'cover', 'craft', 'create', 'credit', 'cross', 'crowd',
  'crystal', 'current', 'custom', 'cycle', 'daily', 'danger', 'data', 'dealer', 'debate', 'decide',
  'deep', 'define', 'degree', 'delay', 'demand', 'denial', 'design', 'detail', 'device', 'dialog',
  'digital', 'direct', 'doctor', 'domain', 'double', 'draft', 'dragon', 'drama', 'dream', 'drive',
  'early', 'earth', 'easy', 'echo', 'edge', 'edit', 'effect', 'either', 'elder', 'element',
  'elite', 'email', 'energy', 'engine', 'enough', 'enter', 'equal', 'error', 'escape', 'estate',
  'event', 'exact', 'example', 'exchange', 'exist', 'expand', 'expect', 'expert', 'extra', 'fabric',
  'factor', 'family', 'famous', 'feature', 'fence', 'field', 'figure', 'filter', 'final', 'finger',
  'finish', 'first', 'focus', 'follow', 'force', 'forest', 'format', 'forward', 'frame', 'fresh',
  'front', 'future', 'gallery', 'general', 'giant', 'global', 'gold', 'good', 'grace', 'grant',
  'green', 'group', 'guard', 'habit', 'half', 'hammer', 'handle', 'happy', 'harbor', 'health',
  'height', 'hidden', 'history', 'honest', 'host', 'hotel', 'human', 'hybrid', 'idea', 'image',
  'impact', 'income', 'index', 'input', 'inside', 'insight', 'island', 'item', 'jacket', 'jazz',
  'join', 'jungle', 'keep', 'keyboard', 'kind', 'king', 'kitchen', 'label', 'ladder', 'language',
  'large', 'laser', 'later', 'launch', 'layer', 'leader', 'learn', 'level', 'light', 'limit',
  'linear', 'link', 'listen', 'local', 'logic', 'lucky', 'machine', 'magic', 'major', 'manage',
  'manual', 'market', 'master', 'matrix', 'matter', 'member', 'memory', 'message', 'method', 'middle',
  'million', 'mind', 'mirror', 'mobile', 'model', 'module', 'moment', 'monitor', 'moral', 'motion',
  'mountain', 'music', 'native', 'nature', 'network', 'never', 'normal', 'notice', 'number', 'object',
  'ocean', 'offer', 'office', 'online', 'option', 'orange', 'order', 'origin', 'output', 'owner',
  'packet', 'panel', 'paper', 'parent', 'partner', 'pattern', 'pause', 'payment', 'people', 'perfect',
  'phone', 'phrase', 'pilot', 'pixel', 'planet', 'platform', 'please', 'plus', 'policy', 'portal',
  'position', 'power', 'predict', 'premium', 'prepare', 'present', 'pretty', 'price', 'prime', 'private',
  'process', 'profile', 'project', 'protect', 'public', 'quality', 'quick', 'quiet', 'radio', 'random',
  'rapid', 'rate', 'ready', 'reason', 'record', 'recover', 'region', 'release', 'remote', 'repair',
  'repeat', 'report', 'request', 'result', 'return', 'review', 'right', 'rival', 'river', 'robot',
  'route', 'royal', 'safe', 'sample', 'scale', 'scene', 'school', 'science', 'screen', 'search',
  'secure', 'select', 'seller', 'senior', 'series', 'server', 'session', 'shadow', 'shape', 'share',
  'shield', 'shift', 'ship', 'short', 'signal', 'silver', 'simple', 'single', 'skill', 'smart',
  'smooth', 'social', 'solid', 'source', 'space', 'special', 'speed', 'spirit', 'split', 'square',
  'stable', 'stack', 'stage', 'start', 'state', 'status', 'steel', 'step', 'stock', 'store',
  'storm', 'story', 'stream', 'strike', 'strong', 'studio', 'style', 'subject', 'submit', 'success',
  'sudden', 'sugar', 'supply', 'support', 'surface', 'switch', 'system', 'table', 'target', 'task',
  'team', 'temple', 'tempo', 'tenant', 'term', 'test', 'theme', 'theory', 'thing', 'thread',
  'time', 'title', 'token', 'tool', 'topic', 'total', 'tower', 'track', 'trade', 'traffic',
  'train', 'travel', 'trust', 'tunnel', 'type', 'unable', 'update', 'upload', 'usage', 'useful',
  'user', 'valid', 'value', 'vector', 'verify', 'version', 'video', 'view', 'virtual', 'vision',
  'voice', 'volume', 'wait', 'wallet', 'watch', 'water', 'wealth', 'web', 'welcome', 'window',
  'winner', 'wire', 'wise', 'wonder', 'work', 'world', 'write', 'xenon', 'year', 'yield',
  'zone'
];

function randomInt(maxExclusive: number): number {
  const values = new Uint32Array(1);
  globalThis.crypto.getRandomValues(values);
  return values[0] % maxExclusive;
}

function generateRecoveryWords(count: number = 24): string[] {
  const words: string[] = [];
  for (let i = 0; i < count; i++) {
    words.push(RECOVERY_WORDS[randomInt(RECOVERY_WORDS.length)]);
  }
  return words;
}

const PFS_PROTOCOL = 'wfx-dr-v1';
const ZERO_32 = new Uint8Array(32);

function toBase64(buf: ArrayBuffer): string {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(buf).toString('base64');
  }
  const bytes = new Uint8Array(buf);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function fromBase64(b64: string): ArrayBuffer {
  if (typeof Buffer !== 'undefined') {
    const buf = Buffer.from(b64, 'base64');
    return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
  }
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function concatBuffers(...buffers: ArrayBuffer[]): ArrayBuffer {
  const total = buffers.reduce((n, b) => n + b.byteLength, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const b of buffers) {
    const view = new Uint8Array(b);
    out.set(view, offset);
    offset += view.byteLength;
  }
  return out.buffer;
}

function normalizeJwk(jwk: JsonWebKey): string {
  return JSON.stringify({
    kty: jwk.kty || '',
    crv: jwk.crv || '',
    x: jwk.x || '',
    y: jwk.y || ''
  });
}

function ratchetKeyId(jwk: JsonWebKey, n: number): string {
  const j = normalizeJwk(jwk);
  if (typeof Buffer !== 'undefined') {
    return `${Buffer.from(j).toString('base64')}:${n}`;
  }
  return `${btoa(j)}:${n}`;
}

async function generatePfsRatchetKeyPair(): Promise<CryptoKeyPair> {
  return globalThis.crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits']
  );
}

async function exportPublicJwk(key: CryptoKey): Promise<JsonWebKey> {
  return globalThis.crypto.subtle.exportKey('jwk', key);
}

async function exportPrivateJwk(key: CryptoKey): Promise<JsonWebKey> {
  return globalThis.crypto.subtle.exportKey('jwk', key);
}

async function importPfsPublicJwk(jwk: JsonWebKey): Promise<CryptoKey> {
  return globalThis.crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  );
}

async function importPfsPrivateJwk(jwk: JsonWebKey): Promise<CryptoKey> {
  return globalThis.crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveBits']
  );
}

async function deriveEcdhSecret(privateJwk: JsonWebKey, publicJwk: JsonWebKey): Promise<ArrayBuffer> {
  const priv = await importPfsPrivateJwk(privateJwk);
  const pub = await importPfsPublicJwk(publicJwk);
  return globalThis.crypto.subtle.deriveBits({ name: 'ECDH', public: pub }, priv, 256);
}

async function hkdfExpand(ikm: ArrayBuffer, salt: ArrayBuffer, info: string, outBits: number): Promise<ArrayBuffer> {
  const ikmKey = await globalThis.crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return globalThis.crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt,
      info: new TextEncoder().encode(info)
    },
    ikmKey,
    outBits
  );
}

async function hmacSha256(keyRaw: ArrayBuffer, input: string): Promise<ArrayBuffer> {
  const key = await globalThis.crypto.subtle.importKey(
    'raw',
    keyRaw,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  return globalThis.crypto.subtle.sign('HMAC', key, new TextEncoder().encode(input));
}

async function deriveRootAndChains(rootKeyB64: string, dhSecret: ArrayBuffer): Promise<{ rootKey: string; chainA: string; chainB: string }> {
  const rootKeyRaw = rootKeyB64 ? fromBase64(rootKeyB64) : ZERO_32.buffer;
  const mixed = await hkdfExpand(dhSecret, rootKeyRaw, `${PFS_PROTOCOL}:root`, 96 * 8);
  const bytes = new Uint8Array(mixed);
  return {
    rootKey: toBase64(bytes.slice(0, 32).buffer),
    chainA: toBase64(bytes.slice(32, 64).buffer),
    chainB: toBase64(bytes.slice(64, 96).buffer)
  };
}

async function deriveMessageKey(chainKeyB64: string, n: number): Promise<ArrayBuffer> {
  return hmacSha256(fromBase64(chainKeyB64), `msg:${n}`);
}

async function deriveNextChainKey(chainKeyB64: string): Promise<string> {
  const next = await hmacSha256(fromBase64(chainKeyB64), 'chain');
  return toBase64(next);
}

async function encryptWithRawKey(rawKey: ArrayBuffer, plaintext: string): Promise<{ ciphertext: string; iv: string }> {
  const key = await globalThis.crypto.subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['encrypt']);
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const out = await globalThis.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintext));
  return {
    ciphertext: toBase64(out),
    iv: toBase64(iv.buffer)
  };
}

async function decryptWithRawKey(rawKey: ArrayBuffer, ciphertextB64: string, ivB64: string): Promise<string> {
  const key = await globalThis.crypto.subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['decrypt']);
  const out = await globalThis.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(fromBase64(ivB64)) },
    key,
    fromBase64(ciphertextB64)
  );
  return new TextDecoder().decode(out);
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
  private pfsIdentityPrivateJwk: JsonWebKey | null = null;
  private pfsIdentityPublicJwk: JsonWebKey | null = null;
  private pfsSessions: Map<string, PfsSessionState> = new Map();

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
        // Skip timeout for file uploads (FormData) — large files can take hours
        const timeoutId = formData
          ? null
          : setTimeout(() => controller.abort(), this.config.timeout);

        const fetchOptions: RequestInit = {
          method,
          headers,
          signal: controller.signal,
        };

        // Support self-signed certs in Node.js (insecure mode)
        // Sets NODE_TLS_REJECT_UNAUTHORIZED for the process lifetime
        if (this.config.insecure && typeof process !== 'undefined' && process.env) {
          process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
        }

        if (formData) {
          fetchOptions.body = formData;
        } else if (body) {
          fetchOptions.body = JSON.stringify(body);
        }

        const response = await fetch(url, fetchOptions);
        if (timeoutId) clearTimeout(timeoutId);

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

  private toBlob(file: File | Blob | ArrayBuffer | Uint8Array): Blob {
    if (file instanceof File || file instanceof Blob) {
      return file;
    }
    if (file instanceof ArrayBuffer) {
      return new Blob([new Uint8Array(file)]);
    }
    if (file instanceof Uint8Array) {
      const arrayBuffer = file.buffer.slice(file.byteOffset, file.byteOffset + file.byteLength) as ArrayBuffer;
      return new Blob([arrayBuffer]);
    }
    throw new ValidationError('Invalid file type. Expected File, Blob, Buffer, or ArrayBuffer');
  }

  private async ensurePfsIdentity(): Promise<void> {
    if (this.pfsIdentityPrivateJwk && this.pfsIdentityPublicJwk) {
      return;
    }
    const kp = await generatePfsRatchetKeyPair();
    this.pfsIdentityPrivateJwk = await exportPrivateJwk(kp.privateKey);
    this.pfsIdentityPublicJwk = await exportPublicJwk(kp.publicKey);
  }

  private getPfsSession(sessionId: string): PfsSessionState {
    const session = this.pfsSessions.get(sessionId);
    if (!session) {
      throw new ValidationError(`PFS session not found: ${sessionId}`);
    }
    return session;
  }

  private async ratchetForSend(session: PfsSessionState): Promise<void> {
    const nextRatchet = await generatePfsRatchetKeyPair();
    const nextPriv = await exportPrivateJwk(nextRatchet.privateKey);
    const nextPub = await exportPublicJwk(nextRatchet.publicKey);

    const dh = await deriveEcdhSecret(nextPriv, session.their_ratchet_public_jwk);
    const mixed = await deriveRootAndChains(session.root_key, dh);

    session.root_key = mixed.rootKey;
    session.send_chain_key = mixed.chainA;
    session.recv_chain_key = mixed.chainB;
    session.prev_send_count = session.send_count;
    session.send_count = 0;
    session.my_ratchet_private_jwk = nextPriv;
    session.my_ratchet_public_jwk = nextPub;
    session.updated_at = Date.now();
  }

  private async ratchetForReceive(session: PfsSessionState, theirRatchetPub: JsonWebKey): Promise<void> {
    const dh = await deriveEcdhSecret(session.my_ratchet_private_jwk, theirRatchetPub);
    const mixed = await deriveRootAndChains(session.root_key, dh);

    session.root_key = mixed.rootKey;
    session.recv_chain_key = mixed.chainA;
    session.send_chain_key = mixed.chainB;
    session.recv_count = 0;
    session.their_ratchet_public_jwk = theirRatchetPub;
    session.updated_at = Date.now();
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
  async register(email: string, password: string, options: RegisterOptions = {}): Promise<AuthResponse & Partial<RecoverySetup>> {
    if (!email || !password) {
      throw new ValidationError('Email and password are required');
    }

    // 1. Generate RSA Key Pair
    const keyPair = await generateKeyPair();

    // 2. Export Public Key
    const publicKeyPEM = await exportKeyToPEM(keyPair.publicKey, 'public');

    // 3. Wrap Private Key
    const { encryptedKey, salt } = await wrapPrivateKey(keyPair.privateKey, password);

    // Optional recovery phrase flow
    const enableRecovery = options.enableRecovery !== false;
    const recoveryWords = enableRecovery
      ? (options.recoveryPhrase ? options.recoveryPhrase.trim().split(/\s+/).filter(Boolean) : generateRecoveryWords(24))
      : [];
    const recoveryPhrase = recoveryWords.join(' ');

    let recoveryEncryptedPrivateKey = '';
    let recoverySalt = '';
    if (enableRecovery && recoveryPhrase) {
      const recoveryWrap = await wrapPrivateKey(keyPair.privateKey, recoveryPhrase);
      recoveryEncryptedPrivateKey = recoveryWrap.encryptedKey;
      recoverySalt = recoveryWrap.salt;
    }

    // 4. Register with Server (Zero-Knowledge)
    const response = await this.request<any>('POST', '/api/v1/keys/register', {
      body: {
        client_id: this.config.clientId,
        user_id: email, // Using email as user_id for simplicity
        public_key_pem: publicKeyPEM,
        encrypted_private_key: encryptedKey,
        salt: salt,
        recovery_encrypted_private_key: recoveryEncryptedPrivateKey,
        recovery_salt: recoverySalt
      },
      includeAuth: false
    });

    if (response.status === 'success' || response.success) {
      // Store unwrapped keys in memory
      this.userId = email;
      this.publicKey = keyPair.publicKey;
      this.privateKey = keyPair.privateKey;
      this.publicKeyPEM = publicKeyPEM;
      this.token = 'zk-session'; // Local session marker (auth via X-Wolfronix-Key header)
    }

    const out: AuthResponse & Partial<RecoverySetup> = {
      success: response.status === 'success' || response.success === true,
      user_id: response.user_id || email,
      token: this.token || 'zk-session',
      message: response.message || 'Keys registered successfully'
    };
    if (enableRecovery && recoveryPhrase) {
      out.recoveryPhrase = recoveryPhrase;
      out.recoveryWords = recoveryWords;
    }
    return out;
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
   * Recover account keys using a 24-word recovery phrase and set a new password.
   * Returns a fresh local auth session if recovery succeeds.
   */
  async recoverAccount(email: string, recoveryPhrase: string, newPassword: string): Promise<AuthResponse> {
    if (!email || !recoveryPhrase || !newPassword) {
      throw new ValidationError('email, recoveryPhrase, and newPassword are required');
    }

    const response = await this.request<any>('POST', '/api/v1/keys/recover', {
      body: {
        client_id: this.config.clientId,
        user_id: email
      },
      includeAuth: false
    });

    if (!response.recovery_encrypted_private_key || !response.recovery_salt || !response.public_key_pem) {
      throw new AuthenticationError('Recovery material not found for this account');
    }

    // 1. Unwrap private key using recovery phrase
    const recoveredPrivateKey = await unwrapPrivateKey(
      response.recovery_encrypted_private_key,
      recoveryPhrase,
      response.recovery_salt
    );

    // 2. Re-wrap private key with the new password
    const newPasswordWrap = await wrapPrivateKey(recoveredPrivateKey, newPassword);

    // 3. Persist new password-wrapped key
    await this.request<any>('POST', '/api/v1/keys/update-password', {
      body: {
        client_id: this.config.clientId,
        user_id: email,
        encrypted_private_key: newPasswordWrap.encryptedKey,
        salt: newPasswordWrap.salt
      },
      includeAuth: false
    });

    // 4. Initialize local session
    this.privateKey = recoveredPrivateKey;
    this.publicKeyPEM = response.public_key_pem;
    this.publicKey = await importKeyFromPEM(response.public_key_pem, 'public');
    this.userId = email;
    this.token = 'zk-session';

    return {
      success: true,
      user_id: email,
      token: this.token,
      message: 'Account recovered successfully'
    };
  }

  /**
   * Rotates long-term RSA identity keys and re-wraps with password (+ optional recovery phrase).
   * Use this periodically to reduce long-term key exposure.
   */
  async rotateIdentityKeys(password: string, recoveryPhrase?: string): Promise<{ success: boolean; message: string; recoveryPhrase?: string }> {
    this.ensureAuthenticated();
    if (!this.userId) {
      throw new AuthenticationError('No active user session');
    }
    if (!password) {
      throw new ValidationError('password is required');
    }

    const keyPair = await generateKeyPair();
    const publicKeyPEM = await exportKeyToPEM(keyPair.publicKey, 'public');
    const passwordWrap = await wrapPrivateKey(keyPair.privateKey, password);

    const words = recoveryPhrase ? recoveryPhrase.trim().split(/\s+/).filter(Boolean) : generateRecoveryWords(24);
    const phrase = words.join(' ');
    const recoveryWrap = await wrapPrivateKey(keyPair.privateKey, phrase);

    await this.request<any>('POST', '/api/v1/keys/register', {
      body: {
        client_id: this.config.clientId,
        user_id: this.userId,
        public_key_pem: publicKeyPEM,
        encrypted_private_key: passwordWrap.encryptedKey,
        salt: passwordWrap.salt,
        recovery_encrypted_private_key: recoveryWrap.encryptedKey,
        recovery_salt: recoveryWrap.salt
      }
    });

    this.publicKey = keyPair.publicKey;
    this.privateKey = keyPair.privateKey;
    this.publicKeyPEM = publicKeyPEM;

    return {
      success: true,
      message: 'Identity keys rotated successfully',
      recoveryPhrase: phrase
    };
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
    const blob = this.toBlob(file);
    formData.append('file', blob, filename || (file instanceof File ? file.name : 'file'));

    formData.append('user_id', this.userId || '');

    if (!this.publicKeyPEM) {
      throw new Error("Public key not available. Is user logged in?");
    }
    formData.append('client_public_key', this.publicKeyPEM);

    const response = await this.request<any>('POST', '/api/v1/encrypt', {
      formData
    });

    return {
      ...response,
      file_id: String(response.file_id),
    };
  }

  /**
   * Resumable large-file encryption upload.
   * Splits a file into chunks (default 10MB) and uploads each chunk independently.
   * If upload fails mid-way, pass the returned state as `existingState` to resume.
   */
  async encryptResumable(
    file: File | Blob | ArrayBuffer | Uint8Array,
    options: ResumableEncryptOptions = {}
  ): Promise<{ result: ChunkedEncryptResult; state: ResumableUploadState }> {
    this.ensureAuthenticated();

    const chunkSize = options.chunkSizeBytes || 10 * 1024 * 1024;
    if (chunkSize < 1024 * 1024) {
      throw new ValidationError('chunkSizeBytes must be at least 1MB');
    }

    const blob = this.toBlob(file);
    const filename = options.filename || (file instanceof File ? file.name : 'file.bin');
    const totalChunks = Math.ceil(blob.size / chunkSize);
    const baseUploadId = `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;

    const state: ResumableUploadState = options.existingState || {
      upload_id: baseUploadId,
      filename,
      file_size: blob.size,
      chunk_size_bytes: chunkSize,
      total_chunks: totalChunks,
      uploaded_chunks: [],
      chunk_file_ids: new Array(totalChunks).fill(''),
      created_at: Date.now(),
      updated_at: Date.now()
    };

    if (state.file_size !== blob.size || state.total_chunks !== totalChunks) {
      throw new ValidationError('existingState does not match current file/chunking settings');
    }

    const uploadedSet = new Set(state.uploaded_chunks);
    let uploaded = uploadedSet.size;

    for (let i = 0; i < totalChunks; i++) {
      if (uploadedSet.has(i)) {
        continue;
      }

      const start = i * chunkSize;
      const end = Math.min(start + chunkSize, blob.size);
      const chunkBlob = blob.slice(start, end);

      const chunkName = `${filename}.part-${String(i + 1).padStart(6, '0')}-of-${String(totalChunks).padStart(6, '0')}`;
      const enc = await this.encrypt(chunkBlob, chunkName);

      state.chunk_file_ids[i] = enc.file_id;
      state.uploaded_chunks.push(i);
      state.updated_at = Date.now();
      uploaded++;

      if (options.onProgress) {
        options.onProgress(uploaded, totalChunks);
      }
    }

    const result: ChunkedEncryptResult = {
      upload_id: state.upload_id,
      filename: state.filename,
      total_chunks: state.total_chunks,
      chunk_size_bytes: state.chunk_size_bytes,
      uploaded_chunks: state.uploaded_chunks.length,
      chunk_file_ids: state.chunk_file_ids,
      complete: state.uploaded_chunks.length === state.total_chunks
    };

    return { result, state };
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
   * Decrypts and reassembles a chunked upload produced by `encryptResumable`.
   */
  async decryptChunkedToBuffer(manifest: ChunkedDecryptManifest, role: string = 'owner'): Promise<ArrayBuffer> {
    this.ensureAuthenticated();
    if (!manifest?.chunk_file_ids?.length) {
      throw new ValidationError('manifest.chunk_file_ids is required');
    }

    const chunks: Uint8Array[] = [];
    let totalLength = 0;

    for (const fileId of manifest.chunk_file_ids) {
      if (!fileId) {
        throw new ValidationError('manifest contains empty chunk file ID');
      }
      const part = await this.decryptToBuffer(fileId, role);
      const bytes = new Uint8Array(part);
      chunks.push(bytes);
      totalLength += bytes.byteLength;
    }

    const merged = new Uint8Array(totalLength);
    let offset = 0;
    for (const part of chunks) {
      merged.set(part, offset);
      offset += part.byteLength;
    }
    return merged.buffer;
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

  /**
   * Create/share a pre-key bundle for Double Ratchet PFS session setup.
   * Exchange this bundle out-of-band with the peer.
   */
  async createPfsPreKeyBundle(): Promise<PfsPreKeyBundle> {
    this.ensureAuthenticated();
    await this.ensurePfsIdentity();
    return {
      protocol: 'wfx-dr-v1',
      user_id: this.userId || undefined,
      ratchet_pub_jwk: this.pfsIdentityPublicJwk as JsonWebKey,
      created_at: Date.now()
    };
  }

  /**
   * Initialize a local PFS ratchet session from peer bundle.
   * Both sides must call this with opposite `asInitiator` values.
   */
  async initPfsSession(sessionId: string, peerBundle: PfsPreKeyBundle, asInitiator: boolean): Promise<PfsSessionState> {
    this.ensureAuthenticated();
    if (!sessionId) {
      throw new ValidationError('sessionId is required');
    }
    if (!peerBundle || peerBundle.protocol !== PFS_PROTOCOL || !peerBundle.ratchet_pub_jwk) {
      throw new ValidationError('Invalid peerBundle');
    }

    await this.ensurePfsIdentity();
    const myPriv = this.pfsIdentityPrivateJwk as JsonWebKey;
    const myPub = this.pfsIdentityPublicJwk as JsonWebKey;
    const theirPub = peerBundle.ratchet_pub_jwk;

    const dh = await deriveEcdhSecret(myPriv, theirPub);
    const mixed = await deriveRootAndChains(toBase64(ZERO_32.buffer), dh);

    const session: PfsSessionState = {
      protocol: 'wfx-dr-v1',
      session_id: sessionId,
      role: asInitiator ? 'initiator' : 'responder',
      root_key: mixed.rootKey,
      send_chain_key: asInitiator ? mixed.chainA : mixed.chainB,
      recv_chain_key: asInitiator ? mixed.chainB : mixed.chainA,
      send_count: 0,
      recv_count: 0,
      prev_send_count: 0,
      my_ratchet_private_jwk: myPriv,
      my_ratchet_public_jwk: myPub,
      their_ratchet_public_jwk: theirPub,
      skipped_keys: {},
      created_at: Date.now(),
      updated_at: Date.now()
    };

    this.pfsSessions.set(sessionId, session);
    return session;
  }

  /**
   * Export session state for persistence (e.g., localStorage/DB).
   */
  exportPfsSession(sessionId: string): PfsSessionState {
    const session = this.getPfsSession(sessionId);
    return JSON.parse(JSON.stringify(session));
  }

  /**
   * Import session state from storage.
   */
  importPfsSession(session: PfsSessionState): void {
    if (!session || session.protocol !== PFS_PROTOCOL || !session.session_id) {
      throw new ValidationError('Invalid PFS session payload');
    }
    this.pfsSessions.set(session.session_id, JSON.parse(JSON.stringify(session)));
  }

  /**
   * Encrypt a message using Double Ratchet session state.
   */
  async pfsEncryptMessage(sessionId: string, plaintext: string): Promise<PfsMessagePacket> {
    this.ensureAuthenticated();
    if (!plaintext) {
      throw new ValidationError('plaintext is required');
    }
    const session = this.getPfsSession(sessionId);

    await this.ratchetForSend(session);
    const n = session.send_count;
    const msgKey = await deriveMessageKey(session.send_chain_key, n);
    const enc = await encryptWithRawKey(msgKey, plaintext);
    session.send_chain_key = await deriveNextChainKey(session.send_chain_key);
    session.send_count += 1;
    session.updated_at = Date.now();

    return {
      v: 1,
      type: 'pfs_ratchet',
      session_id: sessionId,
      n,
      pn: session.prev_send_count,
      ratchet_pub_jwk: session.my_ratchet_public_jwk,
      iv: enc.iv,
      ciphertext: enc.ciphertext,
      timestamp: Date.now()
    };
  }

  /**
   * Decrypt a Double Ratchet packet for a session.
   * Handles basic out-of-order delivery through skipped message keys.
   */
  async pfsDecryptMessage(sessionId: string, packet: PfsMessagePacket | string): Promise<string> {
    this.ensureAuthenticated();
    const session = this.getPfsSession(sessionId);
    const msg: PfsMessagePacket = typeof packet === 'string' ? JSON.parse(packet) : packet;

    if (!msg || msg.type !== 'pfs_ratchet' || msg.session_id !== sessionId) {
      throw new ValidationError('Invalid PFS message packet');
    }

    if (normalizeJwk(msg.ratchet_pub_jwk) !== normalizeJwk(session.their_ratchet_public_jwk)) {
      await this.ratchetForReceive(session, msg.ratchet_pub_jwk);
    }

    while (session.recv_count < msg.n) {
      const skippedKey = await deriveMessageKey(session.recv_chain_key, session.recv_count);
      session.skipped_keys[ratchetKeyId(session.their_ratchet_public_jwk, session.recv_count)] = toBase64(skippedKey);
      session.recv_chain_key = await deriveNextChainKey(session.recv_chain_key);
      session.recv_count += 1;
    }

    const skipId = ratchetKeyId(session.their_ratchet_public_jwk, msg.n);
    let msgKey: ArrayBuffer;
    if (session.skipped_keys[skipId]) {
      msgKey = fromBase64(session.skipped_keys[skipId]);
      delete session.skipped_keys[skipId];
    } else {
      msgKey = await deriveMessageKey(session.recv_chain_key, msg.n);
      session.recv_chain_key = await deriveNextChainKey(session.recv_chain_key);
      session.recv_count = msg.n + 1;
    }

    session.updated_at = Date.now();
    return decryptWithRawKey(msgKey, msg.ciphertext, msg.iv);
  }

  /**
   * Group message encryption using sender-key fanout:
   * message encrypted once with AES key, AES key wrapped for each group member with their RSA public key.
   */
  async encryptGroupMessage(text: string, groupId: string, recipientIds: string[]): Promise<string> {
    this.ensureAuthenticated();
    if (!text || !groupId) {
      throw new ValidationError('text and groupId are required');
    }
    if (!recipientIds?.length) {
      throw new ValidationError('recipientIds cannot be empty');
    }

    const uniqueRecipients = Array.from(new Set(recipientIds.filter(Boolean)));
    if (this.userId && !uniqueRecipients.includes(this.userId)) {
      uniqueRecipients.push(this.userId);
    }

    const sessionKey = await generateSessionKey();
    const { encrypted: ciphertext, iv } = await encryptData(text, sessionKey);
    const rawSessionKey = await exportSessionKey(sessionKey);

    const recipientKeys: Record<string, string> = {};
    for (const rid of uniqueRecipients) {
      const pem = await this.getPublicKey(rid);
      const pub = await importKeyFromPEM(pem, 'public');
      recipientKeys[rid] = await rsaEncrypt(rawSessionKey, pub);
    }

    const packet: GroupEncryptPacket = {
      v: 1,
      type: 'group_sender_key',
      sender_id: this.userId || '',
      group_id: groupId,
      timestamp: Date.now(),
      ciphertext,
      iv,
      recipient_keys: recipientKeys
    };
    return JSON.stringify(packet);
  }

  /**
   * Decrypt a packet produced by `encryptGroupMessage`.
   */
  async decryptGroupMessage(packetJson: string): Promise<string> {
    this.ensureAuthenticated();
    if (!this.privateKey || !this.userId) {
      throw new Error('Private key not available. Is user logged in?');
    }

    let packet: GroupEncryptPacket;
    try {
      packet = JSON.parse(packetJson);
    } catch {
      throw new ValidationError('Invalid group packet format');
    }

    if (packet.type !== 'group_sender_key' || !packet.recipient_keys || !packet.ciphertext || !packet.iv) {
      throw new ValidationError('Invalid group packet structure');
    }

    const wrappedKey = packet.recipient_keys[this.userId];
    if (!wrappedKey) {
      throw new PermissionDeniedError('You are not a recipient of this group message');
    }

    const rawSessionKey = await rsaDecrypt(wrappedKey, this.privateKey);
    const sessionKey = await importSessionKey(rawSessionKey);
    return decryptData(packet.ciphertext, packet.iv, sessionKey);
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

// ============================================================================
// WolfronixAdmin — Enterprise Client Management
// ============================================================================

/**
 * Admin client for managing enterprise clients.
 * Uses X-Admin-Key authentication (not user auth).
 * 
 * @example
 * ```typescript
 * import { WolfronixAdmin } from '@wolfronix/sdk';
 * 
 * const admin = new WolfronixAdmin({
 *   baseUrl: 'https://wolfronix-server:9443',
 *   adminKey: 'your-admin-api-key'
 * });
 * 
 * // Register a client with managed Supabase connector
 * const result = await admin.registerClient({
 *   client_id: 'acme_corp',
 *   client_name: 'Acme Corporation',
 *   db_type: 'supabase',
 *   db_config: JSON.stringify({
 *     supabase_url: 'https://xxx.supabase.co',
 *     supabase_service_key: 'eyJ...'
 *   })
 * });
 * console.log('Wolfronix key:', result.wolfronix_key);
 * ```
 */
export class WolfronixAdmin {
  private readonly baseUrl: string;
  private readonly adminKey: string;
  private readonly timeout: number;
  private readonly insecure: boolean;

  constructor(config: WolfronixAdminConfig) {
    this.baseUrl = config.baseUrl.replace(/\/$/, '');
    this.adminKey = config.adminKey;
    this.timeout = config.timeout || 30000;
    this.insecure = config.insecure || false;
  }

  private async request<T>(
    method: string,
    endpoint: string,
    body?: unknown
  ): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`;
    const headers: Record<string, string> = {
      'X-Admin-Key': this.adminKey,
      'Accept': 'application/json'
    };

    if (body) {
      headers['Content-Type'] = 'application/json';
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    const fetchOptions: RequestInit = {
      method,
      headers,
      signal: controller.signal
    };

    // Support self-signed certs in Node.js (insecure mode)
    if (this.insecure && typeof process !== 'undefined' && process.env) {
      process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
    }

    if (body) {
      fetchOptions.body = JSON.stringify(body);
    }

    const response = await fetch(url, fetchOptions);
    clearTimeout(timeoutId);

    if (!response.ok) {
      const errorBody = await response.json().catch(() => ({}));
      throw new WolfronixError(
        (errorBody as any).error || `Request failed with status ${response.status}`,
        'ADMIN_REQUEST_ERROR',
        response.status,
        errorBody as Record<string, unknown>
      );
    }

    return await response.json() as T;
  }

  /**
   * Register a new enterprise client.
   * For managed connectors (supabase, mongodb, mysql, firebase, postgresql),
   * provide db_type + db_config. For custom APIs, use db_type: 'custom_api' + api_endpoint.
   */
  async registerClient(params: RegisterClientRequest): Promise<RegisterClientResponse> {
    return this.request<RegisterClientResponse>('POST', '/api/v1/enterprise/register', params);
  }

  /**
   * List all registered enterprise clients.
   */
  async listClients(): Promise<ListClientsResponse> {
    return this.request<ListClientsResponse>('GET', '/api/v1/enterprise/clients');
  }

  /**
   * Get details for a specific client.
   */
  async getClient(clientId: string): Promise<EnterpriseClient> {
    return this.request<EnterpriseClient>('GET', `/api/v1/enterprise/clients/${encodeURIComponent(clientId)}`);
  }

  /**
   * Update a client's configuration (api_endpoint, db_type, db_config).
   */
  async updateClient(clientId: string, params: UpdateClientRequest): Promise<UpdateClientResponse> {
    return this.request<UpdateClientResponse>('PUT', `/api/v1/enterprise/clients/${encodeURIComponent(clientId)}`, params);
  }

  /**
   * Deactivate (soft-delete) a client. Their wolfronix_key will stop working.
   */
  async deactivateClient(clientId: string): Promise<DeactivateClientResponse> {
    return this.request<DeactivateClientResponse>('DELETE', `/api/v1/enterprise/clients/${encodeURIComponent(clientId)}`);
  }

  /**
   * Check server health.
   */
  async healthCheck(): Promise<boolean> {
    try {
      await this.request<{ status: string }>('GET', '/health');
      return true;
    } catch {
      return false;
    }
  }
}

export default Wolfronix;
