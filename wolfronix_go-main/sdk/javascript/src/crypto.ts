/**
 * Cryptographic utilities for client-side key management
 * Uses Web Crypto API (supported in modern browsers and Node.js 16+)
 */

// Universal crypto access (works in both Browser and Node.js 16+)
const getCrypto = (): Crypto => {
    if (typeof globalThis.crypto !== 'undefined') {
        return globalThis.crypto;
    }
    throw new Error(
        'Web Crypto API not available. Requires a modern browser or Node.js 16+.'
    );
};

// Key constants
const RSA_ALG = {
    name: "RSA-OAEP",
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: "SHA-256",
};

const WRAP_ALG = "AES-GCM";
const PBKDF2_ITERATIONS = 100000;

/**
 * Generate a new RSA Key Pair (2048-bit)
 */
export async function generateKeyPair(): Promise<CryptoKeyPair> {
    return await getCrypto().subtle.generateKey(
        RSA_ALG,
        true, // extractable
        ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
    );
}

/**
 * Export a key to PEM format
 */
export async function exportKeyToPEM(key: CryptoKey, type: "public" | "private"): Promise<string> {
    const format = type === "public" ? "spki" : "pkcs8";
    const exported = await getCrypto().subtle.exportKey(format, key);
    const exportedAsBase64 = arrayBufferToBase64(exported);
    const pemHeader = type === "public" ? "-----BEGIN PUBLIC KEY-----" : "-----BEGIN PRIVATE KEY-----";
    const pemFooter = type === "public" ? "-----END PUBLIC KEY-----" : "-----END PRIVATE KEY-----";

    return `${pemHeader}\n${exportedAsBase64}\n${pemFooter}`;
}

/**
 * Import a key from PEM format
 */
export async function importKeyFromPEM(pem: string, type: "public" | "private"): Promise<CryptoKey> {
    const pemHeader = type === "public" ? "-----BEGIN PUBLIC KEY-----" : "-----BEGIN PRIVATE KEY-----";
    const pemFooter = type === "public" ? "-----END PUBLIC KEY-----" : "-----END PRIVATE KEY-----";

    const pemContents = pem.replace(pemHeader, "").replace(pemFooter, "").replace(/\s/g, "");
    const binaryDer = base64ToArrayBuffer(pemContents);

    const format = type === "public" ? "spki" : "pkcs8";
    const usage: KeyUsage[] = type === "public" ? ["encrypt", "wrapKey"] : ["decrypt", "unwrapKey"];

    return await getCrypto().subtle.importKey(
        format,
        binaryDer,
        RSA_ALG,
        true,
        usage
    );
}

/**
 * Derive a wrapping key from a password and salt using PBKDF2
 */
async function deriveWrappingKey(password: string, saltHex: string): Promise<CryptoKey> {
    const enc = new TextEncoder();
    const passwordKey = await getCrypto().subtle.importKey(
        "raw",
        enc.encode(password),
        "PBKDF2",
        false,
        ["deriveKey"]
    );

    const salt = hexToArrayBuffer(saltHex);

    return await getCrypto().subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: PBKDF2_ITERATIONS,
            hash: "SHA-256",
        },
        passwordKey,
        { name: WRAP_ALG, length: 256 },
        false,
        ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
    );
}

/**
 * Wrap (encrypt) a private key with a password-derived key
 */
export async function wrapPrivateKey(privateKey: CryptoKey, password: string): Promise<{ encryptedKey: string, salt: string }> {
    const crypto = getCrypto();

    // Generate random salt
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const saltHex = arrayBufferToHex(salt.buffer);

    // Derive wrapping key
    const wrappingKey = await deriveWrappingKey(password, saltHex);

    // Export private key to PKCS8
    const exportedKey = await crypto.subtle.exportKey("pkcs8", privateKey);

    // Encrypt the exported key data
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const encryptedContent = await crypto.subtle.encrypt(
        {
            name: WRAP_ALG,
            iv: iv,
        },
        wrappingKey,
        exportedKey
    );

    // Combine IV + Encrypted Data
    const combined = new Uint8Array(iv.length + encryptedContent.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(encryptedContent), iv.length);

    return {
        encryptedKey: arrayBufferToBase64(combined.buffer),
        salt: saltHex
    };
}

/**
 * Unwrap (decrypt) a private key with a password-derived key
 */
export async function unwrapPrivateKey(encryptedKeyBase64: string, password: string, saltHex: string): Promise<CryptoKey> {
    const combined = base64ToArrayBuffer(encryptedKeyBase64);
    const combinedArray = new Uint8Array(combined);

    // Extract IV (first 12 bytes)
    const iv = combinedArray.slice(0, 12);
    const data = combinedArray.slice(12);

    const wrappingKey = await deriveWrappingKey(password, saltHex);

    const decryptedKeyData = await getCrypto().subtle.decrypt(
        {
            name: WRAP_ALG,
            iv: iv,
        },
        wrappingKey,
        data
    );

    return await getCrypto().subtle.importKey(
        "pkcs8",
        decryptedKeyData,
        RSA_ALG,
        true,
        ["decrypt", "unwrapKey"]
    );
}

// === UTILITIES (Universal: Browser + Node.js) ===

function arrayBufferToBase64(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    // Use Buffer in Node.js, btoa in browser
    if (typeof Buffer !== 'undefined') {
        return Buffer.from(bytes).toString('base64');
    }
    let binary = "";
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
    // Use Buffer in Node.js, atob in browser
    if (typeof Buffer !== 'undefined') {
        const buf = Buffer.from(base64, 'base64');
        return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
    }
    const binary_string = atob(base64);
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
}

function arrayBufferToHex(buffer: ArrayBuffer): string {
    return [...new Uint8Array(buffer)]
        .map(x => x.toString(16).padStart(2, '0'))
        .join('');
}

function hexToArrayBuffer(hex: string): ArrayBuffer {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes.buffer;
}
