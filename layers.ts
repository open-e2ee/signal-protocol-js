/**
 * Architecture Layer Definitions
 *
 * This file defines the layered architecture of the Signal Protocol implementation.
 * It follows Clean Architecture principles with numbered layers for easy reference.
 *
 * ## Architecture Model
 * ```
 * Layer 0: EXTERNAL          - Your application (React Native, Node, etc.)
 * Layer 1: API               - client/ (SignalProtocolClient, ISignalProtocolClient)
 * Layer 2: ORCHESTRATION     - manager/, sesame/, groups/ (SignalProtocolManager, SesameManager, GroupManager)
 * Layer 3: DOMAIN/SESSION    - session/, safety/ (establishment, cipher, handshake, safety numbers)
 * Layer 4: DOMAIN/ALGORITHMS - protocol/ (X3DH, PQXDH, Double Ratchet, SPQR, Sender Keys, Sealed Sender, ZK proofs)
 * Layer 5: DOMAIN/KEYS       - keys/ (types, generation, branded types)
 * Layer 6: DOMAIN/CRYPTO     - crypto/ (X25519, Ed25519, Kyber, AES, HKDF)
 *
 * INFRASTRUCTURE (no layer number) - local/, remote/, device/
 *   Implements or composes ports used at the API/orchestration boundary.
 * ```
 *
 * ## Layer Rule
 * Layer N can only import from Layer N+1 or higher (dependencies point inward toward domain).
 *
 * ## Infrastructure Exception
 * local/, remote/, and device/ are outside the numbered hierarchy. They are
 * adapter/integration packages and can depend on public contracts plus the
 * domain logic they need to persist, relay, or provision.
 *
 * @see ARCHITECTURE.md for full documentation
 * @module
 */

// =============================================================================
// Layer Constants
// =============================================================================

/**
 * Layer number constants for architecture validation and documentation.
 *
 * Usage in code comments:
 * ```typescript
 * // @layer 4 - Domain/Algorithms
 * ```
 *
 * Usage for validation:
 * ```typescript
 * if (!canImport(LAYERS.DOMAIN_SESSION, LAYERS.DOMAIN_ALGORITHMS)) {
 *   throw new Error('Invalid layer dependency');
 * }
 * ```
 */
export {};
export const LAYERS = {
  /** Layer 1: API boundary - client/ */
  API: 1,
  /** Layer 2: Orchestration - manager/, sesame/ */
  ORCHESTRATION: 2,
  /** Layer 3: Domain/Session - session/ */
  DOMAIN_SESSION: 3,
  /** Layer 4: Domain/Algorithms - protocol/ */
  DOMAIN_ALGORITHMS: 4,
  /** Layer 5: Domain/Keys - keys/ */
  DOMAIN_KEYS: 5,
  /** Layer 6: Domain/Crypto - crypto/ */
  DOMAIN_CRYPTO: 6,
} as const;

/**
 * Layer number type derived from LAYERS constant.
 */
export type Layer = (typeof LAYERS)[keyof typeof LAYERS];

/**
 * Layer name string literals.
 */
export type LayerName =
  | 'API'
  | 'ORCHESTRATION'
  | 'DOMAIN_SESSION'
  | 'DOMAIN_ALGORITHMS'
  | 'DOMAIN_KEYS'
  | 'DOMAIN_CRYPTO';

// =============================================================================
// Layer Metadata
// =============================================================================

/**
 * Layer definition with metadata for documentation and validation.
 */
export interface LayerDefinition {
  /** Layer number (1 = API, 6 = foundation) */
  readonly level: Layer;
  /** Layer name for display */
  readonly displayName: string;
  /** Directories belonging to this layer */
  readonly directories: readonly string[];
  /** Layers this layer is allowed to depend on (by number) */
  readonly dependsOn: readonly Layer[];
  /** Signal Protocol specification reference */
  readonly spec: string;
  /** Brief description */
  readonly description: string;
  /** Key interfaces/contracts at this boundary */
  readonly interfaces?: readonly string[];
}

/**
 * Complete layer architecture definitions.
 */
export const LAYER_DEFINITIONS: Record<Layer, LayerDefinition> = {
  [LAYERS.API]: {
    level: LAYERS.API,
    displayName: 'API',
    directories: ['client'],
    dependsOn: [LAYERS.ORCHESTRATION],
    spec: 'N/A (application boundary)',
    description: 'Public API boundary - SignalProtocolClient implements ISignalProtocolClient',
    interfaces: ['ISignalProtocolClient'],
  },
  [LAYERS.ORCHESTRATION]: {
    level: LAYERS.ORCHESTRATION,
    displayName: 'Orchestration',
    directories: ['manager', 'sesame', 'groups'],
    dependsOn: [
      LAYERS.DOMAIN_SESSION,
      LAYERS.DOMAIN_ALGORITHMS,
      LAYERS.DOMAIN_KEYS,
      LAYERS.DOMAIN_CRYPTO,
    ],
    spec: 'SESAME §1-8, Signal Private Group System',
    description: 'Orchestration layer - coordinates domain, uses ports for I/O',
    interfaces: [
      'ISignalProtocolManager',
      'ISesameManager',
      'IGroupStateStore',
      'IGroupServer',
      'ISignalProtocolRelayServer',
      'ISignalProtocolLocalStore',
    ],
  },
  [LAYERS.DOMAIN_SESSION]: {
    level: LAYERS.DOMAIN_SESSION,
    displayName: 'Domain/Session',
    directories: ['session', 'safety'],
    dependsOn: [LAYERS.DOMAIN_ALGORITHMS, LAYERS.DOMAIN_KEYS, LAYERS.DOMAIN_CRYPTO],
    spec: 'X3DH §3, Double Ratchet §3.3',
    description: 'Session establishment, cipher, handshake, and safety numbers',
  },
  [LAYERS.DOMAIN_ALGORITHMS]: {
    level: LAYERS.DOMAIN_ALGORITHMS,
    displayName: 'Domain/Algorithms',
    directories: ['protocol'],
    dependsOn: [LAYERS.DOMAIN_KEYS, LAYERS.DOMAIN_CRYPTO],
    spec: 'X3DH §1-4, PQXDH §1-4, Double Ratchet §2-6, Sender Keys, Signal Private Group System (poksho, zkcredential, zkgroup)',
    description:
      'Key agreement (X3DH, PQXDH), ratcheting (Double, SPQR, Triple), group messaging (Sender Keys), and Ristretto255 ZK proofs',
  },
  [LAYERS.DOMAIN_KEYS]: {
    level: LAYERS.DOMAIN_KEYS,
    displayName: 'Domain/Keys',
    directories: ['keys'],
    dependsOn: [LAYERS.DOMAIN_CRYPTO],
    spec: 'X3DH §2, PQXDH §3',
    description: 'Key types, generation, and branded TypeScript types',
  },
  [LAYERS.DOMAIN_CRYPTO]: {
    level: LAYERS.DOMAIN_CRYPTO,
    displayName: 'Domain/Crypto',
    directories: ['crypto'],
    dependsOn: [],
    spec: 'RFC 7748, RFC 8032, NIST FIPS 203',
    description: 'Cryptographic primitives: X25519, Ed25519, ML-KEM-1024, AES, HKDF',
  },
};

/**
 * Infrastructure modules (no layer number - implement ports).
 */
export const INFRASTRUCTURE_MODULES = {
  local: {
    directories: ['local'],
    implementsPorts: ['ISignalProtocolLocalStore'],
    description: 'Local persistence and secret vault adapters: Expo, Node, Memory, Web, React Native',
  },
  remote: {
    directories: ['remote'],
    implementsPorts: ['ISignalProtocolRelayServer', 'SignalProtocolRemoteObjectStore'],
    description: 'Remote relay and object-store adapters: Convex, Memory, R2, S3',
  },
  device: {
    directories: ['device'],
    implementsPorts: [],
    description: 'Device transfer extension: secure device-to-device key migration',
  },
} as const;

/**
 * Meta directories (not part of architecture layers).
 * These provide cross-cutting concerns or internal tooling.
 */
export const META_DIRECTORIES = {
  types: {
    directories: ['types'],
    description: 'Shared type definitions used across all layers',
  },
  internal: {
    directories: ['internal'],
    description: 'Internal exports for testing (not public API)',
  },
  utils: {
    directories: ['utils'],
    description: 'Shared utility functions',
  },
} as const;

/**
 * Public feature directories that sit at the package boundary but are not part
 * of the protocol dependency hierarchy.
 */
export const PUBLIC_SURFACE_DIRECTORIES = [
  'blocking',
  'encoding',
  'files',
  'groups',
  'hooks',
  'media',
  'profile',
  'sealed-sender',
  'username',
  'zk',
] as const;

/**
 * Public root modules that are files rather than directories.
 */
export const PUBLIC_SURFACE_FILES = ['logger.ts', 'server-clock.ts', 'versions.ts'] as const;

// =============================================================================
// Directory Mapping
// =============================================================================

/**
 * Directory to layer mapping for validation.
 */
export const DIRECTORY_TO_LAYER: Record<string, Layer> = {
  client: LAYERS.API,
  manager: LAYERS.ORCHESTRATION,
  sesame: LAYERS.ORCHESTRATION,
  'groups': LAYERS.ORCHESTRATION,
  session: LAYERS.DOMAIN_SESSION,
  safety: LAYERS.DOMAIN_SESSION,
  protocol: LAYERS.DOMAIN_ALGORITHMS,
  keys: LAYERS.DOMAIN_KEYS,
  crypto: LAYERS.DOMAIN_CRYPTO,
};

/**
 * Infrastructure directories (not part of numbered layers).
 */
export const INFRASTRUCTURE_DIRECTORIES = ['local', 'remote', 'device'] as const;

/**
 * Meta directories (cross-cutting, not part of layer hierarchy).
 */
export const META_DIRECTORY_NAMES = ['types', 'internal', 'utils'] as const;

// =============================================================================
// Validation Functions
// =============================================================================

/**
 * Validate that a source layer can import from a target layer.
 *
 * The dependency rule: Layer N can only import from Layer N+1 or higher.
 * This ensures dependencies always point inward toward the domain core.
 *
 * @param sourceLayer - The layer doing the importing
 * @param targetLayer - The layer being imported from
 * @returns true if the import is valid according to architecture rules
 *
 * @example
 * ```typescript
 * // Valid: Layer 3 importing from Layer 4
 * canImport(LAYERS.DOMAIN_SESSION, LAYERS.DOMAIN_ALGORITHMS); // true
 *
 * // Invalid: Layer 4 importing from Layer 3
 * canImport(LAYERS.DOMAIN_ALGORITHMS, LAYERS.DOMAIN_SESSION); // false
 * ```
 */
export function canImport(sourceLayer: Layer, targetLayer: Layer): boolean {
  // Same layer is always allowed
  if (sourceLayer === targetLayer) {
    return true;
  }

  // Target layer must be >= source layer (deeper toward domain)
  return targetLayer >= sourceLayer;
}

/**
 * Get the layer for a given directory path.
 *
 * @param directory - Directory name (e.g., 'crypto', 'session')
 * @returns Layer number or undefined if not a recognized layer directory
 */
export function getLayerForDirectory(directory: string): Layer | undefined {
  return DIRECTORY_TO_LAYER[directory];
}

/**
 * Check if a directory is an infrastructure module.
 *
 * @param directory - Directory name to check
 * @returns true if the directory is an infrastructure module
 */
export function isInfrastructure(directory: string): boolean {
  return INFRASTRUCTURE_DIRECTORIES.includes(
    directory as (typeof INFRASTRUCTURE_DIRECTORIES)[number]
  );
}

/**
 * Get the layer definition by layer number.
 *
 * @param layer - Layer number
 * @returns Layer definition
 */
export function getLayerDefinition(layer: Layer): LayerDefinition {
  return LAYER_DEFINITIONS[layer];
}

/**
 * Get the human-readable display name for a layer.
 *
 * @param layer - Layer number
 * @returns Human-readable layer name
 */
export function getLayerDisplayName(layer: Layer): string {
  return LAYER_DEFINITIONS[layer].displayName;
}

/**
 * Validate that a layer's imports are valid according to the architecture.
 * This can be used in lint rules or CI checks.
 *
 * @param sourceDirectory - The directory doing the import
 * @param targetDirectory - The directory being imported
 * @returns Object with valid flag and error message if invalid
 *
 * @example
 * ```typescript
 * validateImport('ratchet', 'crypto');
 * // { valid: true }
 *
 * validateImport('crypto', 'session');
 * // { valid: false, error: 'Layer 6 (Domain/Crypto) cannot import from Layer 3 (Domain/Session)' }
 * ```
 */
export function validateImport(
  sourceDirectory: string,
  targetDirectory: string
): { valid: boolean; error?: string } {
  // Infrastructure can import from anything
  if (isInfrastructure(sourceDirectory)) {
    return { valid: true };
  }

  // Infrastructure can be imported by the API/composition boundary and Layer 2 orchestration.
  if (isInfrastructure(targetDirectory)) {
    const sourceLayer = getLayerForDirectory(sourceDirectory);
    if (sourceLayer === LAYERS.API || sourceLayer === LAYERS.ORCHESTRATION) {
      return { valid: true };
    }
    return {
      valid: false,
      error: `Only Layer 1 (API) and Layer 2 (Orchestration) can import from infrastructure. ${sourceDirectory} is Layer ${sourceLayer}.`,
    };
  }

  const sourceLayer = getLayerForDirectory(sourceDirectory);
  const targetLayer = getLayerForDirectory(targetDirectory);

  if (sourceLayer === undefined) {
    return {
      valid: false,
      error: `Unknown source directory: ${sourceDirectory}`,
    };
  }

  if (targetLayer === undefined) {
    return {
      valid: false,
      error: `Unknown target directory: ${targetDirectory}`,
    };
  }

  if (canImport(sourceLayer, targetLayer)) {
    return { valid: true };
  }

  const sourceDef = getLayerDefinition(sourceLayer);
  const targetDef = getLayerDefinition(targetLayer);

  return {
    valid: false,
    error: `Layer ${sourceLayer} (${sourceDef.displayName}) cannot import from Layer ${targetLayer} (${targetDef.displayName}). Dependencies must point inward (toward higher layer numbers).`,
  };
}

/**
 * Get all layers that a given layer is allowed to depend on.
 *
 * @param layer - Layer number to check
 * @returns Array of layer numbers this layer can import from
 */
export function getAllowedDependencies(layer: Layer): readonly Layer[] {
  return LAYER_DEFINITIONS[layer].dependsOn;
}
