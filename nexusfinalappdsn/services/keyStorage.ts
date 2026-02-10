/**
 * Key Storage Service - Encrypted FROST key persistence
 *
 * Uses WASM encrypt_key_for_backup/decrypt_key_from_backup for encryption.
 * Stores encrypted keys in IndexedDB with localStorage fallback.
 *
 * Storage structure:
 * - IndexedDB: nexus-keys/keys/{escrowId} -> EncryptedKeyEntry
 * - localStorage fallback: nexus_key_{escrowId} -> JSON string
 */

import {
  encryptKeyForBackupAsync,
  decryptKeyFromBackupAsync,
  deriveBackupIdAsync,
  verifyBackupPasswordAsync,
  deriveBackupId,
  initWasm,
  isWasmReady,
} from './wasmService';

// Storage constants
const DB_NAME = 'nexus-keys';
const DB_VERSION = 2; // Bumped to force object store creation
const STORE_NAME = 'keys';
const STORAGE_PREFIX = 'nexus_key_';

// Key entry structure
export interface EncryptedKeyEntry {
  escrowId: string;
  role: string;
  encryptedKeyPackage: string;
  backupId: string;
  createdAt: number;
  lastAccessedAt: number;
}

// Key metadata (without encrypted data)
export interface KeyMetadata {
  escrowId: string;
  role: string;
  backupId: string;
  createdAt: number;
  lastAccessedAt: number;
}

// ============================================================================
// IndexedDB Helpers
// ============================================================================

let dbPromise: Promise<IDBDatabase> | null = null;

async function getDb(): Promise<IDBDatabase> {
  if (dbPromise !== null) {
    return dbPromise;
  }

  dbPromise = new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onerror = () => {
      console.error('[KeyStorage] IndexedDB error:', request.error);
      dbPromise = null;
      reject(request.error);
    };

    request.onsuccess = () => {
      resolve(request.result);
    };

    request.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result;

      // Create object store with escrowId as key
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        const store = db.createObjectStore(STORE_NAME, { keyPath: 'escrowId' });
        store.createIndex('backupId', 'backupId', { unique: true });
        store.createIndex('role', 'role', { unique: false });
        store.createIndex('createdAt', 'createdAt', { unique: false });
      }
    };
  });

  return dbPromise;
}

// Check if IndexedDB is available
function isIndexedDBAvailable(): boolean {
  try {
    return 'indexedDB' in window && indexedDB !== null;
  } catch {
    return false;
  }
}

// ============================================================================
// Public API
// ============================================================================

/**
 * Store an encrypted FROST key package
 *
 * @param escrowId - Escrow identifier
 * @param role - User's role (buyer/vendor/arbiter)
 * @param keyPackageHex - The FROST key_package to encrypt (hex encoded)
 * @param password - User-provided encryption password
 */
export async function storeKey(
  escrowId: string,
  role: string,
  keyPackageHex: string,
  password: string
): Promise<void> {
  // Ensure WASM is initialized (for other operations)
  if (!isWasmReady()) {
    await initWasm();
  }

  // Encrypt the key package using Web Crypto API
  const encryptedKeyPackage = await encryptKeyForBackupAsync(keyPackageHex, password);
  const backupId = deriveBackupId(keyPackageHex); // Sync version is fine for ID

  const entry: EncryptedKeyEntry = {
    escrowId,
    role: role.toLowerCase(),
    encryptedKeyPackage,
    backupId,
    createdAt: Date.now(),
    lastAccessedAt: Date.now(),
  };

  if (isIndexedDBAvailable()) {
    try {
      const db = await getDb();
      return new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_NAME, 'readwrite');
        const store = tx.objectStore(STORE_NAME);

        const request = store.put(entry);
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
      });
    } catch (error) {
      console.warn('[KeyStorage] IndexedDB failed, falling back to localStorage:', error);
    }
  }

  // Fallback to localStorage
  localStorage.setItem(`${STORAGE_PREFIX}${escrowId}`, JSON.stringify(entry));
}

/**
 * Load and decrypt a FROST key package
 *
 * @param escrowId - Escrow identifier
 * @param password - User-provided decryption password
 * @returns Decrypted key_package (hex) or null if not found
 */
export async function loadKey(
  escrowId: string,
  password: string
): Promise<string | null> {
  // Ensure WASM is initialized
  if (!isWasmReady()) {
    await initWasm();
  }

  let entry: EncryptedKeyEntry | null = null;

  if (isIndexedDBAvailable()) {
    try {
      const db = await getDb();
      entry = await new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_NAME, 'readonly');
        const store = tx.objectStore(STORE_NAME);

        const request = store.get(escrowId);
        request.onsuccess = () => resolve(request.result || null);
        request.onerror = () => reject(request.error);
      });
    } catch (error) {
      console.warn('[KeyStorage] IndexedDB read failed, trying localStorage:', error);
    }
  }

  // Fallback to localStorage
  if (!entry) {
    const stored = localStorage.getItem(`${STORAGE_PREFIX}${escrowId}`);
    if (stored) {
      try {
        entry = JSON.parse(stored) as EncryptedKeyEntry;
      } catch {
        return null;
      }
    }
  }

  if (!entry) {
    return null;
  }

  // Decrypt the key package using Web Crypto API
  try {
    const decrypted = await decryptKeyFromBackupAsync(entry.encryptedKeyPackage, password);

    // Update last accessed time
    entry.lastAccessedAt = Date.now();
    await updateEntryAccessTime(escrowId, entry);

    return decrypted;
  } catch (error) {
    console.error('[KeyStorage] Decryption failed (wrong password?):', error);
    return null;
  }
}

/**
 * Check if a key exists for the given escrow
 */
export async function hasKey(escrowId: string): Promise<boolean> {
  if (isIndexedDBAvailable()) {
    try {
      const db = await getDb();
      return new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_NAME, 'readonly');
        const store = tx.objectStore(STORE_NAME);

        const request = store.count(escrowId);
        request.onsuccess = () => resolve(request.result > 0);
        request.onerror = () => reject(request.error);
      });
    } catch {
      // Fall through to localStorage check
    }
  }

  return localStorage.getItem(`${STORAGE_PREFIX}${escrowId}`) !== null;
}

/**
 * Verify password without decrypting the full key
 */
export async function verifyKeyPassword(
  escrowId: string,
  password: string
): Promise<boolean> {
  // Ensure WASM is initialized
  if (!isWasmReady()) {
    await initWasm();
  }

  let entry: EncryptedKeyEntry | null = null;

  if (isIndexedDBAvailable()) {
    try {
      const db = await getDb();
      entry = await new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_NAME, 'readonly');
        const store = tx.objectStore(STORE_NAME);

        const request = store.get(escrowId);
        request.onsuccess = () => resolve(request.result || null);
        request.onerror = () => reject(request.error);
      });
    } catch {
      // Fall through to localStorage
    }
  }

  if (!entry) {
    const stored = localStorage.getItem(`${STORAGE_PREFIX}${escrowId}`);
    if (stored) {
      try {
        entry = JSON.parse(stored) as EncryptedKeyEntry;
      } catch {
        return false;
      }
    }
  }

  if (!entry) {
    return false;
  }

  return verifyBackupPasswordAsync(entry.encryptedKeyPackage, password);
}

/**
 * Delete a key from storage
 */
export async function deleteKey(escrowId: string): Promise<void> {
  if (isIndexedDBAvailable()) {
    try {
      const db = await getDb();
      await new Promise<void>((resolve, reject) => {
        const tx = db.transaction(STORE_NAME, 'readwrite');
        const store = tx.objectStore(STORE_NAME);

        const request = store.delete(escrowId);
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
      });
    } catch (error) {
      console.warn('[KeyStorage] IndexedDB delete failed:', error);
    }
  }

  // Always try to remove from localStorage too
  localStorage.removeItem(`${STORAGE_PREFIX}${escrowId}`);
}

/**
 * Get metadata for a stored key (without encrypted data)
 */
export async function getKeyMetadata(escrowId: string): Promise<KeyMetadata | null> {
  let entry: EncryptedKeyEntry | null = null;

  if (isIndexedDBAvailable()) {
    try {
      const db = await getDb();
      entry = await new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_NAME, 'readonly');
        const store = tx.objectStore(STORE_NAME);

        const request = store.get(escrowId);
        request.onsuccess = () => resolve(request.result || null);
        request.onerror = () => reject(request.error);
      });
    } catch {
      // Fall through to localStorage
    }
  }

  if (!entry) {
    const stored = localStorage.getItem(`${STORAGE_PREFIX}${escrowId}`);
    if (stored) {
      try {
        entry = JSON.parse(stored) as EncryptedKeyEntry;
      } catch {
        return null;
      }
    }
  }

  if (!entry) {
    return null;
  }

  return {
    escrowId: entry.escrowId,
    role: entry.role,
    backupId: entry.backupId,
    createdAt: entry.createdAt,
    lastAccessedAt: entry.lastAccessedAt,
  };
}

/**
 * List all stored keys (metadata only)
 */
export async function listKeys(): Promise<KeyMetadata[]> {
  const results: KeyMetadata[] = [];

  if (isIndexedDBAvailable()) {
    try {
      const db = await getDb();
      const entries: EncryptedKeyEntry[] = await new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_NAME, 'readonly');
        const store = tx.objectStore(STORE_NAME);

        const request = store.getAll();
        request.onsuccess = () => resolve(request.result || []);
        request.onerror = () => reject(request.error);
      });

      for (const entry of entries) {
        results.push({
          escrowId: entry.escrowId,
          role: entry.role,
          backupId: entry.backupId,
          createdAt: entry.createdAt,
          lastAccessedAt: entry.lastAccessedAt,
        });
      }

      return results;
    } catch {
      // Fall through to localStorage
    }
  }

  // Scan localStorage for keys
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    if (key && key.startsWith(STORAGE_PREFIX)) {
      try {
        const entry = JSON.parse(localStorage.getItem(key)!) as EncryptedKeyEntry;
        results.push({
          escrowId: entry.escrowId,
          role: entry.role,
          backupId: entry.backupId,
          createdAt: entry.createdAt,
          lastAccessedAt: entry.lastAccessedAt,
        });
      } catch {
        // Skip malformed entries
      }
    }
  }

  return results;
}

/**
 * Get the encrypted key package directly (for QR backup export)
 */
export async function getEncryptedKey(escrowId: string): Promise<string | null> {
  let entry: EncryptedKeyEntry | null = null;

  if (isIndexedDBAvailable()) {
    try {
      const db = await getDb();
      entry = await new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_NAME, 'readonly');
        const store = tx.objectStore(STORE_NAME);

        const request = store.get(escrowId);
        request.onsuccess = () => resolve(request.result || null);
        request.onerror = () => reject(request.error);
      });
    } catch {
      // Fall through
    }
  }

  if (!entry) {
    const stored = localStorage.getItem(`${STORAGE_PREFIX}${escrowId}`);
    if (stored) {
      try {
        entry = JSON.parse(stored) as EncryptedKeyEntry;
      } catch {
        return null;
      }
    }
  }

  return entry?.encryptedKeyPackage || null;
}

/**
 * Import an encrypted key from QR backup
 *
 * @param escrowId - Escrow identifier
 * @param role - User's role
 * @param encryptedKeyPackage - The encrypted backup from QR code
 * @param password - Password to verify the backup
 */
export async function importEncryptedKey(
  escrowId: string,
  role: string,
  encryptedKeyPackage: string,
  password: string
): Promise<boolean> {
  // Ensure WASM is initialized
  if (!isWasmReady()) {
    await initWasm();
  }

  // Verify password first
  const isValid = await verifyBackupPasswordAsync(encryptedKeyPackage, password);
  if (!isValid) {
    return false;
  }

  // Decrypt to get the backup ID
  const keyPackageHex = await decryptKeyFromBackupAsync(encryptedKeyPackage, password);
  const backupId = deriveBackupId(keyPackageHex);

  const entry: EncryptedKeyEntry = {
    escrowId,
    role: role.toLowerCase(),
    encryptedKeyPackage,
    backupId,
    createdAt: Date.now(),
    lastAccessedAt: Date.now(),
  };

  if (isIndexedDBAvailable()) {
    try {
      const db = await getDb();
      await new Promise<void>((resolve, reject) => {
        const tx = db.transaction(STORE_NAME, 'readwrite');
        const store = tx.objectStore(STORE_NAME);

        const request = store.put(entry);
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
      });
      return true;
    } catch (error) {
      console.warn('[KeyStorage] IndexedDB import failed, using localStorage:', error);
    }
  }

  localStorage.setItem(`${STORAGE_PREFIX}${escrowId}`, JSON.stringify(entry));
  return true;
}

// ============================================================================
// Internal Helpers
// ============================================================================

async function updateEntryAccessTime(escrowId: string, entry: EncryptedKeyEntry): Promise<void> {
  if (isIndexedDBAvailable()) {
    try {
      const db = await getDb();
      await new Promise<void>((resolve, reject) => {
        const tx = db.transaction(STORE_NAME, 'readwrite');
        const store = tx.objectStore(STORE_NAME);

        const request = store.put(entry);
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
      });
      return;
    } catch {
      // Fall through to localStorage
    }
  }

  localStorage.setItem(`${STORAGE_PREFIX}${escrowId}`, JSON.stringify(entry));
}
