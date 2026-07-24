/**
 * Profile Key Secure Storage Abstraction
 *
 * Provides a platform-agnostic interface for storing profile keys.
 * - Expo/React Native: Uses `expo-secure-store`
 * - Web fallback: Uses JavaScript-accessible localStorage with an explicit warning
 *
 * This abstraction enables the profile-key module to work in both
 * React Native and web environments.
 */

// ============================================================================
// Interface
// ============================================================================

/**
 * Secure storage interface for profile keys
 */
export {};
export interface ProfileKeyStorage {
  /**
   * Get a stored value
   * @param key - Storage key
   * @returns Stored value or null if not found
   */
  getItem(key: string): Promise<string | null>;

  /**
   * Set a value
   * @param key - Storage key
   * @param value - Value to store
   */
  setItem(key: string, value: string): Promise<void>;

  /**
   * Delete a value
   * @param key - Storage key
   */
  deleteItem(key: string): Promise<void>;
}

// ============================================================================
// Implementations
// ============================================================================

/**
 * Expo SecureStore implementation (React Native)
 *
 * Uses the platform storage selected by Expo SecureStore:
 * - iOS: Keychain Services
 * - Android: encrypted SharedPreferences backed by Android Keystore
 *
 * Hardware protection, biometric access, backup, and migration behavior depend
 * on platform capabilities and application configuration.
 */
class ExpoSecureStorage implements ProfileKeyStorage {
  private secureStore: typeof import('expo-secure-store') | null = null;

  private async getSecureStore() {
    if (!this.secureStore) {
      this.secureStore = await import('expo-secure-store');
    }
    return this.secureStore;
  }

  async getItem(key: string): Promise<string | null> {
    const store = await this.getSecureStore();
    return store.getItemAsync(key, {
      keychainAccessible: store.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
    });
  }

  async setItem(key: string, value: string): Promise<void> {
    const store = await this.getSecureStore();
    await store.setItemAsync(key, value, {
      keychainAccessible: store.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
    });
  }

  async deleteItem(key: string): Promise<void> {
    const store = await this.getSecureStore();
    await store.deleteItemAsync(key, {
      keychainAccessible: store.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
    });
  }
}

/**
 * Web localStorage implementation
 *
 * WARNING: localStorage is NOT as secure as native secure storage.
 * Data is stored in plaintext and accessible to any JS on the page.
 * Use only for local development or when native storage is unavailable.
 */
class WebLocalStorage implements ProfileKeyStorage {
  private prefix = 'signal_profile_';

  async getItem(key: string): Promise<string | null> {
    if (typeof window === 'undefined' || !window.localStorage) {
      return null;
    }
    return window.localStorage.getItem(this.prefix + key);
  }

  async setItem(key: string, value: string): Promise<void> {
    if (typeof window === 'undefined' || !window.localStorage) {
      console.warn('[ProfileKeyStorage] localStorage not available');
      return;
    }
    window.localStorage.setItem(this.prefix + key, value);
  }

  async deleteItem(key: string): Promise<void> {
    if (typeof window === 'undefined' || !window.localStorage) {
      return;
    }
    window.localStorage.removeItem(this.prefix + key);
  }
}

/**
 * In-memory storage for local development
 */
class MemoryStorage implements ProfileKeyStorage {
  private store = new Map<string, string>();

  async getItem(key: string): Promise<string | null> {
    return this.store.get(key) ?? null;
  }

  async setItem(key: string, value: string): Promise<void> {
    this.store.set(key, value);
  }

  async deleteItem(key: string): Promise<void> {
    this.store.delete(key);
  }

  /** Clear all stored values (for testing) */
  clear(): void {
    this.store.clear();
  }
}

// ============================================================================
// Factory
// ============================================================================

let storageInstance: ProfileKeyStorage | null = null;

/**
 * Detect if running in React Native
 */
function isReactNative(): boolean {
  return typeof navigator !== 'undefined' && navigator.product === 'ReactNative';
}

/**
 * Get the appropriate storage implementation for the current platform
 */
export function getProfileKeyStorage(): ProfileKeyStorage {
  if (storageInstance) {
    return storageInstance;
  }

  if (isReactNative()) {
    storageInstance = new ExpoSecureStorage();
  } else {
    // Web environment - use localStorage with warning
    console.warn(
      '[ProfileKeyStorage] Using localStorage - not as secure as native storage. ' +
        'For production web apps, consider using IndexedDB with encryption.'
    );
    storageInstance = new WebLocalStorage();
  }

  return storageInstance;
}

/**
 * Set a custom storage implementation.
 */
export function setProfileKeyStorage(storage: ProfileKeyStorage): void {
  storageInstance = storage;
}

/**
 * Create a memory storage instance for local development.
 */
export function createMemoryStorage(): MemoryStorage {
  return new MemoryStorage();
}

/**
 * Reset the storage instance for controlled local teardown.
 */
export function resetProfileKeyStorage(): void {
  storageInstance = null;
}
