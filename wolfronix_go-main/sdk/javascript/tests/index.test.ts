/// <reference types="vitest" />
import { describe, it, expect, beforeEach } from 'vitest';
import Wolfronix, {
  WolfronixError,
  AuthenticationError,
  ValidationError,
  KeyPartResponse,
  createClient
} from '../src/index';

describe('Wolfronix SDK', () => {
  let client: Wolfronix;

  beforeEach(() => {
    client = new Wolfronix({
      baseUrl: 'https://localhost:5002',
      clientId: 'test-client',
      wolfronixKey: 'test-api-key'
    });
  });

  describe('Constructor', () => {
    it('should create client with config object', () => {
      const wfx = new Wolfronix({
        baseUrl: 'https://server:5002',
        clientId: 'my-client',
        wolfronixKey: 'my-api-key',
        timeout: 60000,
        retries: 5
      });
      expect(wfx).toBeInstanceOf(Wolfronix);
    });

    it('should create client with string URL', () => {
      const wfx = new Wolfronix('https://server:5002');
      expect(wfx).toBeInstanceOf(Wolfronix);
    });

    it('should remove trailing slash from baseUrl', () => {
      const wfx = new Wolfronix('https://server:5002/');
      expect(wfx).toBeInstanceOf(Wolfronix);
    });
  });

  describe('createClient factory', () => {
    it('should create client using factory function', () => {
      const wfx = createClient('https://server:5002');
      expect(wfx).toBeInstanceOf(Wolfronix);
    });
  });

  describe('Authentication', () => {
    it('should not be authenticated initially', () => {
      expect(client.isAuthenticated()).toBe(false);
    });

    it('should return null for userId when not authenticated', () => {
      expect(client.getUserId()).toBeNull();
    });

    it('should set token directly', () => {
      client.setToken('test-token', 'user-123');
      expect(client.isAuthenticated()).toBe(true);
      expect(client.getUserId()).toBe('user-123');
    });

    it('should clear auth on logout', () => {
      client.setToken('test-token', 'user-123');
      client.logout();
      expect(client.isAuthenticated()).toBe(false);
      expect(client.getUserId()).toBeNull();
    });

    it('should throw ValidationError for empty email', async () => {
      await expect(client.login('', 'password')).rejects.toThrow(ValidationError);
    });

    it('should throw ValidationError for empty password', async () => {
      await expect(client.login('user@example.com', '')).rejects.toThrow(ValidationError);
    });
  });

  describe('File Operations (without auth)', () => {
    it('should throw AuthenticationError when not logged in', async () => {
      await expect(client.encrypt(new Blob(['test']))).rejects.toThrow(AuthenticationError);
    });

    it('should throw AuthenticationError for decrypt when not logged in', async () => {
      await expect(client.decrypt('file-id')).rejects.toThrow(AuthenticationError);
    });

    it('should throw AuthenticationError for getFileKey when not logged in', async () => {
      await expect(client.getFileKey('file-id')).rejects.toThrow(AuthenticationError);
    });

    it('should throw AuthenticationError for listFiles when not logged in', async () => {
      await expect(client.listFiles()).rejects.toThrow(AuthenticationError);
    });

    it('should throw AuthenticationError for deleteFile when not logged in', async () => {
      await expect(client.deleteFile('file-id')).rejects.toThrow(AuthenticationError);
    });
  });

  describe('Validation', () => {
    beforeEach(() => {
      client.setToken('test-token', 'user-123');
    });

    it('should throw ValidationError for empty file ID in decrypt', async () => {
      await expect(client.decrypt('')).rejects.toThrow(ValidationError);
    });

    it('should throw ValidationError for empty file ID in getFileKey', async () => {
      await expect(client.getFileKey('')).rejects.toThrow(ValidationError);
    });

    it('should throw ValidationError for empty file ID in delete', async () => {
      await expect(client.deleteFile('')).rejects.toThrow(ValidationError);
    });
  });

  describe('Error Classes', () => {
    it('WolfronixError should have correct properties', () => {
      const error = new WolfronixError('Test error', 'TEST_CODE', 500, { extra: 'data' });
      expect(error.message).toBe('Test error');
      expect(error.code).toBe('TEST_CODE');
      expect(error.statusCode).toBe(500);
      expect(error.details).toEqual({ extra: 'data' });
      expect(error.name).toBe('WolfronixError');
    });

    it('AuthenticationError should have 401 status', () => {
      const error = new AuthenticationError();
      expect(error.statusCode).toBe(401);
      expect(error.code).toBe('AUTH_ERROR');
    });

    it('ValidationError should have 400 status', () => {
      const error = new ValidationError('Invalid input');
      expect(error.statusCode).toBe(400);
      expect(error.code).toBe('VALIDATION_ERROR');
    });
  });
});

describe('Integration Tests (requires running server)', () => {
  // These tests require a running Wolfronix server
  // Skip by default, run with: npm test -- --run integration

  const TEST_SERVER = process.env.WOLFRONIX_TEST_SERVER || 'https://localhost:5002';
  const TEST_EMAIL = 'test@example.com';
  const TEST_PASSWORD = 'testpassword123';

  it.skip('should register a new user', async () => {
    const client = new Wolfronix({ baseUrl: TEST_SERVER, insecure: true });
    const result = await client.register(TEST_EMAIL, TEST_PASSWORD);
    expect(result.success).toBe(true);
    expect(result.token).toBeDefined();
    expect(result.user_id).toBeDefined();
  });

  it.skip('should login existing user', async () => {
    const client = new Wolfronix({ baseUrl: TEST_SERVER, insecure: true });
    const result = await client.login(TEST_EMAIL, TEST_PASSWORD);
    expect(result.success).toBe(true);
    expect(client.isAuthenticated()).toBe(true);
  });

  it.skip('should encrypt and decrypt a file', async () => {
    const client = new Wolfronix({ baseUrl: TEST_SERVER, wolfronixKey: 'test-key', insecure: true });
    await client.login(TEST_EMAIL, TEST_PASSWORD);

    const testData = 'Hello, Wolfronix!';
    const blob = new Blob([testData], { type: 'text/plain' });

    // Encrypt
    const { file_id } = await client.encrypt(blob, 'test.txt');
    expect(file_id).toBeDefined();

    // Decrypt (zero-knowledge: fetches key_part_a, decrypts client-side, sends decrypted_key_a)
    const decrypted = await client.decrypt(file_id);
    const text = await decrypted.text();
    expect(text).toBe(testData);

    // Cleanup
    await client.deleteFile(file_id);
  });
});
