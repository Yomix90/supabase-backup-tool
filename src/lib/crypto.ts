import { createCipheriv, createDecipheriv, randomBytes, scrypt } from 'node:crypto';
import { promisify } from 'node:util';

const asyncScrypt = promisify(scrypt);

// Lazy-load the master key to avoid import-time errors
function getMasterKey(): string {
  const MASTER_KEY = process.env.ENCRYPTION_MASTER_KEY;
  
  if (!MASTER_KEY) {
    throw new Error('ENCRYPTION_MASTER_KEY environment variable is required');
  }
  
  return MASTER_KEY;
}

/**
 * Derives a 32-byte encryption key from the master key using PBKDF2-like scrypt
 */
async function deriveKey(salt: Buffer): Promise<Buffer> {
  const masterKey = getMasterKey();
  return (await asyncScrypt(masterKey, salt, 32)) as Buffer;
}

/**
 * Encrypts sensitive data using AES-256-GCM
 * @param plaintext - The data to encrypt
 * @returns Object containing encrypted data, IV, salt, and auth tag
 */
export async function encryptSensitiveData(plaintext: string): Promise<{
  encrypted: string;
  iv: string;
  salt: string;
  authTag: string;
}> {
  try {
    // Generate random salt and IV
    const salt = randomBytes(16);
    const iv = randomBytes(12); // 12 bytes for GCM mode
    
    // Derive encryption key from master key + salt
    const key = await deriveKey(salt);
    
    // Create cipher using AES-256-GCM
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    
    // Explicitly allocate a new buffer to avoid detached ArrayBuffer issues
    const plaintextBuffer = Buffer.alloc(Buffer.byteLength(plaintext, 'utf8'));
    plaintextBuffer.write(plaintext, 'utf8');
    
    // Encrypt the data with explicit buffer handling
    const encryptedChunk1 = cipher.update(plaintextBuffer);
    const encryptedChunk2 = cipher.final();
    
    // Concatenate encrypted chunks into a single buffer, then convert to hex
    const encryptedBuffer = Buffer.concat([encryptedChunk1, encryptedChunk2]);
    const encrypted = encryptedBuffer.toString('hex');
    
    // Get the authentication tag
    const authTag = cipher.getAuthTag();
    
    return {
      encrypted,
      iv: iv.toString('hex'),
      salt: salt.toString('hex'),
      authTag: authTag.toString('hex'),
    };
  } catch (error) {
    throw new Error(`Encryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Decrypts sensitive data that was encrypted with encryptSensitiveData
 * @param encryptedData - Object containing encrypted data and metadata
 * @returns The decrypted plaintext
 */
export async function decryptSensitiveData(encryptedData: {
  encrypted: string;
  iv: string;
  salt: string;
  authTag: string;
}): Promise<string> {
  try {
    const { encrypted, iv, salt, authTag } = encryptedData;
    
    // Convert hex strings back to buffers
    const ivBuffer = Buffer.from(iv, 'hex');
    const saltBuffer = Buffer.from(salt, 'hex');
    const authTagBuffer = Buffer.from(authTag, 'hex');
    const encryptedBuffer = Buffer.from(encrypted, 'hex');
    
    // Derive the same encryption key
    const key = await deriveKey(saltBuffer);
    
    // Create decipher using AES-256-GCM
    const decipher = createDecipheriv('aes-256-gcm', key, ivBuffer);
    decipher.setAuthTag(authTagBuffer);
    
    // Decrypt the data with explicit buffer handling
    const decryptedChunk1 = decipher.update(encryptedBuffer);
    const decryptedChunk2 = decipher.final();
    
    // Concatenate decrypted chunks into a single buffer, then convert to string
    const decryptedBuffer = Buffer.concat([decryptedChunk1, decryptedChunk2]);
    const decrypted = decryptedBuffer.toString('utf8');
    
    return decrypted;
  } catch (error) {
    throw new Error(`Decryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Generates a cryptographically secure master key for first-time setup
 * This should be run once and the result stored securely in environment variables
 */
export function generateMasterKey(): string {
  return randomBytes(32).toString('hex');
}

/**
 * Utility to check if data appears to be encrypted (has the expected structure)
 */
export function isEncrypted(data: string): boolean {
  try {
    const parsed = JSON.parse(data);
    return (
      typeof parsed === 'object' &&
      parsed !== null &&
      'encrypted' in parsed &&
      'iv' in parsed &&
      'salt' in parsed &&
      'authTag' in parsed
    );
  } catch {
    return false;
  }
}

/**
 * Helper to safely encrypt data for database storage
 */
export async function encryptForDatabase(plaintext: string | null): Promise<string | null> {
  if (!plaintext || plaintext.trim() === '') {
    return null;
  }
  
  const encrypted = await encryptSensitiveData(plaintext);
  return JSON.stringify(encrypted);
}

/**
 * Helper to safely decrypt data from database
 */
export async function decryptFromDatabase(encryptedJson: string | null): Promise<string | null> {
  if (!encryptedJson) {
    return null;
  }
  
  try {
    const encryptedData = JSON.parse(encryptedJson);
    return await decryptSensitiveData(encryptedData);
  } catch (error) {
    throw new Error(`Failed to decrypt database field: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}