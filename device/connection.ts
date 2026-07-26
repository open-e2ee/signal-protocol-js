/**
 * Encrypted device-transfer relay.
 *
 * The connection moves only transfer packets that the device-transfer layer
 * has already encrypted. Applications own the relay operations, access policy,
 * retention, and cleanup behavior.
 */

import { getErrorMessage } from '../utils/errors';
import { resolveSignalProtocolLogger, type ILogger } from '../logger';
import type {
  LocalConnection,
  ConnectionStatus,
  ConnectionRole,
  TransferPacket,
  ProgressCallback,
  RetryConfig,
  RelayConfig,
} from './types';
import { DEFAULT_RETRY_CONFIG } from './types';

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Calculate SHA-256 checksum of data
 */
export {};
async function calculateChecksum(data: string): Promise<string> {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);
  const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Verify checksum matches data
 */
async function verifyChecksum(data: string, expectedChecksum: string): Promise<boolean> {
  const actualChecksum = await calculateChecksum(data);
  return actualChecksum === expectedChecksum;
}

/**
 * Execute function with retry logic and exponential backoff
 */
async function withRetry<T>(
  fn: () => Promise<T>,
  config: RetryConfig,
  errorMessage: string = 'Operation failed'
): Promise<T> {
  let lastError: Error | undefined;
  let delay = config.initialDelay;

  for (let attempt = 0; attempt <= config.maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));

      // Don't retry on last attempt
      if (attempt === config.maxRetries) {
        break;
      }

      // Wait before retry with exponential backoff
      await new Promise((resolve) => setTimeout(resolve, delay));
      delay = Math.min(delay * config.backoffMultiplier, config.maxDelay);
    }
  }

  throw new Error(`${errorMessage} after ${config.maxRetries + 1} attempts: ${lastError?.message}`);
}

/**
 * Application-provided relay connection.
 *
 * Both devices use a short-lived channel. The sender uploads an encrypted
 * transfer packet; the receiver validates it, marks the channel complete, and
 * cleanup removes the channel. The configured operations determine the
 * backend provider and policy.
 */
export class RelayConnection implements LocalConnection {
  role: ConnectionRole;
  status: ConnectionStatus = 'idle';
  error?: string;

  private config: RelayConfig;
  private channelId?: string;
  private progressCallback?: ProgressCallback;
  private logger: Required<ILogger>;

  constructor(config: RelayConfig) {
    this.role = config.role;
    this.config = config;
    this.logger = resolveSignalProtocolLogger(config.logger);
  }

  async connect(): Promise<void> {
    try {
      this.status = this.role === 'receiver' ? 'advertising' : 'discovering';
      this.channelId = this.config.deviceId;

      // Receiver creates the channel
      if (this.role === 'receiver') {
        await this.config.createChannel(this.channelId);
      }

      this.status = 'connected';

      this.logger.debug('Device Connection: Connected to relay', {
        category: 'Device',
        data: {
          operation: 'relay-connect',
          role: this.role,
          channelId: this.channelId,
        },
      });
    } catch (error) {
      this.status = 'error';
      this.error = 'Failed to connect';
      throw error;
    }
  }

  async disconnect(): Promise<void> {
    try {
      if (this.channelId) {
        await this.config.deleteChannel(this.channelId);
      }
      this.status = 'closed';

      this.logger.debug('Device Connection: Disconnected from relay', {
        category: 'Device',
        data: {
          operation: 'relay-disconnect',
          channelId: this.channelId,
        },
      });
    } catch (error) {
      this.logger.error('Device Connection: Failed to disconnect', {
        category: 'Device',
        error: error as Error,
      });
      this.status = 'closed';
    }
  }

  async sendData(data: TransferPacket): Promise<void> {
    if (!this.channelId) {
      throw new Error('Not connected');
    }

    this.status = 'transferring';

    try {
      // Calculate checksum
      const backupString = JSON.stringify(data.encryptedBackup);
      const checksum = await calculateChecksum(backupString);

      // Create final packet with checksum
      const finalPacket: TransferPacket = {
        ...data,
        checksum,
        totalSize: backupString.length,
      };

      const dataString = JSON.stringify(finalPacket);

      // Upload to Convex relay channel with retry logic
      const retryConfig = this.config.retryConfig || DEFAULT_RETRY_CONFIG;

      this.progressCallback?.(10);

      await withRetry(
        async () => {
          await this.config.uploadData(this.channelId!, dataString);
        },
        retryConfig,
        'Failed to upload transfer data'
      );

      this.progressCallback?.(100);
      this.status = 'complete';

      this.logger.info('Device Connection: Data uploaded to relay', {
        category: 'Device',
        data: {
          operation: 'relay-upload',
          channelId: this.channelId,
          size: dataString.length,
        },
      });
    } catch (error) {
      this.status = 'error';
      this.error = getErrorMessage(error);
      throw new Error(
        `Transfer upload failed: ${getErrorMessage(error)}. Please check your internet connection and try again.`
      );
    }
  }

  async receiveData(): Promise<TransferPacket> {
    if (!this.channelId) {
      throw new Error('Not connected');
    }

    this.status = 'transferring';

    try {
      const timeout = this.config.timeout || 300000; // 5 minutes default
      const startTime = Date.now();
      const pollInterval = 2000; // 2 seconds
      const retryConfig = this.config.retryConfig || DEFAULT_RETRY_CONFIG;

      while (Date.now() - startTime < timeout) {
        const elapsed = Date.now() - startTime;
        const timeProgress = (elapsed / timeout) * 60;
        this.progressCallback?.(timeProgress);

        // Download with retry logic
        const result = await withRetry(
          async () => await this.config.downloadData(this.channelId!),
          retryConfig,
          'Failed to download transfer data'
        );

        if (result.status === 'ready' && result.data) {
          this.progressCallback?.(70);

          const packet = JSON.parse(result.data) as TransferPacket;

          // Verify checksum
          this.progressCallback?.(80);
          const backupString = JSON.stringify(packet.encryptedBackup);
          const isValid = await verifyChecksum(backupString, packet.checksum);

          if (!isValid) {
            throw new Error('Data integrity check failed. Transfer may be corrupted.');
          }

          // Mark transfer as complete
          this.progressCallback?.(90);
          await withRetry(
            async () => await this.config.completeChannel(this.channelId!),
            retryConfig,
            'Failed to mark transfer complete'
          );

          this.progressCallback?.(100);
          this.status = 'complete';

          this.logger.info('Device Connection: Data received from relay', {
            category: 'Device',
            data: {
              operation: 'relay-download',
              channelId: this.channelId,
            },
          });

          return packet;
        }

        if (result.status === 'expired') {
          throw new Error('Transfer expired. Please start a new transfer within 5 minutes.');
        }

        if (result.status === 'not_found') {
          throw new Error('Transfer not found. Make sure both devices are ready.');
        }

        // Wait before polling again
        await new Promise((resolve) => setTimeout(resolve, pollInterval));
      }

      throw new Error(
        'Transfer timed out after 5 minutes. Please ensure both devices have a stable internet connection and try again.'
      );
    } catch (error) {
      this.status = 'error';
      this.error = getErrorMessage(error);

      if (error instanceof Error) {
        if (error.message.includes('network') || error.message.includes('fetch')) {
          throw new Error('Network error. Please check your internet connection and try again.');
        }
        throw error;
      }

      throw new Error('Transfer failed. Please check your connection and try again.');
    }
  }

  onProgress(callback: ProgressCallback): void {
    this.progressCallback = callback;
  }
}

/**
 * Create a connection over application-provided relay operations.
 */
export function createRelayConnection(config: RelayConfig): LocalConnection {
  return new RelayConnection(config);
}

/**
 * Generate unique device ID for connection.
 * Uses Web Crypto CSPRNG for the random component.
 * Connection IDs are for routing uniqueness (not security-critical).
 */
export function generateConnectionId(): string {
  const bytes = new Uint8Array(6);
  // Web Crypto API is always available in React Native and Node 19+
  globalThis.crypto.getRandomValues(bytes);
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  return `device_${Date.now()}_${hex}`;
}
