/**
 * Device Constants
 *
 * Shared persistence keys and limits for device lifecycle operations.
 *
 * ## Secure-storage persistence
 *
 * Platform secure-storage items and application sandbox data can have different
 * uninstall, restore, and backup lifecycles. The ownership sentinel lives in the
 * application sandbox so lifecycle code can reject retained secure-storage
 * state when the current installation cannot prove ownership. Host applications
 * must perform this check before reusing stored ownership data.
 *
 * ## iOS Simulator Caveat
 *
 * Simulator uninstall behavior does not reliably match a physical device.
 * Integration environments should explicitly reset simulator state when
 * validating reinstall behavior.
 */

/**
 * SecureStore key for persisting the device ID.
 * Its lifecycle is platform-dependent. See the module boundary above.
 */
export {};
export const DEVICE_ID_KEY = 'signal_device_id';

/**
 * SecureStore key for persisting the device name.
 * Its lifecycle is platform-dependent. See the module boundary above.
 */
export const DEVICE_NAME_KEY = 'signal_device_name';

/**
 * SecureStore key for the local ACI identity public key.
 *
 * Used by device verification to distinguish verified return vs reinstall vs
 * key mismatch without depending on the SQLite store surviving reinstall.
 */
export const LOCAL_IDENTITY_KEY = 'signal_identity_public_key';

/**
 * SecureStore key for tracking which user registered this device.
 * Its lifecycle is platform-dependent. See the module boundary above.
 *
 * Used to detect when a different account signs into a device with existing
 * encrypted data. A missing ownership sentinel means retained secure-storage
 * data must not be trusted as belonging to the current installation.
 */
export const DEVICE_REGISTERED_USER_ID_KEY = 'device_registered_user_id';

/**
 * Sentinel filename written to the app sandbox (Documents/) after a successful
 * device ownership claim. Used to detect retained secure-storage data whose
 * ownership cannot be established for the current installation.
 *
 * The sentinel must be written only after a successful ownership claim and
 * removed when local ownership is reset.
 */
export const DEVICE_OWNER_SENTINEL = '.device-owner';

/**
 * Default device ID for primary device
 */
export const DEFAULT_DEVICE_ID = 1;

/**
 * Maximum number of devices per user (1 primary + 4 linked)
 */
export const MAX_DEVICES = 5;

/**
 * Provisioning session QR code expires after 5 minutes.
 * The short TTL blocks reuse of a QR code after the linking window.
 */
export const PROVISIONING_SESSION_TTL_MS = 5 * 60 * 1000;
