/**
 * Unified Presence Tracking Hook
 *
 * Handles both WebSocket connection state and app lifecycle state
 * to provide accurate, immediate presence updates with no duplicate calls.
 *
 * Routes presence operations through the Signal Protocol relay for architectural
 * consistency with other device operations.
 *
 * Behavior:
 * - WebSocket connects (app active) → mark online + start heartbeat
 * - WebSocket disconnects → mark offline + stop heartbeat
 * - App backgrounds → immediately mark offline + stop heartbeat
 * - App foregrounds → wait for WebSocket reconnect (which marks online)
 * - Heartbeat every 10 seconds keeps device "alive" on server
 *
 * Server-side:
 * - Server schedules 30-second timeout on state transitions (offline → online)
 * - Heartbeat writes to heartbeats table (triggers 0 query reruns)
 * - If client crashes (no graceful disconnect), 30s timeout marks offline
 *
 * Benefits:
 * - Immediate offline on app background
 * - 30-second server timeout catches crashes
 * - Periodic heartbeat keeps presence accurate
 * - Single hook, no duplicate calls
 *
 * @example
 * ```typescript
 * const relay = new ConvexSignalProtocolRelayServer(convex, signalApi, {
 *   currentUserId: userId,
 *   getAuthToken,
 * });
 * useConnectionPresence({
 *   relay,
 *   deviceId,
 *   enabled: isSignedIn && !!deviceId,
 * });
 * ```
 */

import { useEffect, useRef, useCallback } from 'react';
import { AppState, AppStateStatus } from 'react-native';
import { useConvex } from 'convex/react';
import type { ISignalProtocolRelayServer } from '../remote/relay/types';
import { useSingleFlight } from './use-single-flight';
import { resolveSignalProtocolLogger, type ILogger } from '../logger';

/**
 * Heartbeat interval for presence keep-alive.
 * Server has 30-second timeout, so we send heartbeat every 10 seconds
 * to ensure we refresh `lastSeen` before the timeout fires.
 */
export {};
const HEARTBEAT_INTERVAL_MS = 10 * 1000;

export interface UseConnectionPresenceOptions {
  /** Signal Protocol relay server instance */
  relay: ISignalProtocolRelayServer;
  /** Current device ID (1-5) */
  deviceId: number | null;
  /** Enable/disable presence tracking (default: true) */
  enabled?: boolean;
  /** Optional logger for presence operations */
  logger?: ILogger;
}

/**
 * Hook that manages device presence via connection state and app lifecycle events.
 *
 * Combines WebSocket state tracking with AppState tracking for immediate,
 * accurate presence updates without duplicate server calls.
 *
 * Uses single-flighting to prevent request spam during rapid state changes.
 */
export function useConnectionPresence({
  relay,
  deviceId,
  enabled = true,
  logger: providedLogger,
}: UseConnectionPresenceOptions): void {
  const convex = useConvex();
  const relayRef = useRef(relay);
  relayRef.current = relay;

  const loggerRef = useRef(resolveSignalProtocolLogger(providedLogger));
  loggerRef.current = resolveSignalProtocolLogger(providedLogger);

  // Wrap relay methods with callbacks for single-flight
  const markConnectedRaw = useCallback(
    (currentDeviceId: number) => relayRef.current.markDeviceConnected(currentDeviceId),
    []
  );
  const markDisconnectedRaw = useCallback(
    (currentDeviceId: number) => relayRef.current.markDeviceDisconnected(currentDeviceId),
    []
  );

  // Single-flight to handle rapid connect/disconnect cycles
  const markConnected = useSingleFlight(markConnectedRaw);
  const markDisconnected = useSingleFlight(markDisconnectedRaw);

  // Track states
  const wasConnectedRef = useRef(false);
  const isInBackgroundRef = useRef(AppState.currentState !== 'active');
  const deviceIdRef = useRef(deviceId);
  deviceIdRef.current = deviceId;

  // WebSocket state handler
  const handleConnectionChange = useCallback(
    (isConnected: boolean) => {
      const logger = loggerRef.current;
      const currentDeviceId = deviceIdRef.current;
      if (!currentDeviceId) return;

      // Only act when state actually changes
      if (isConnected && !wasConnectedRef.current) {
        // WebSocket just connected
        wasConnectedRef.current = true;
        // Only mark online if app is in foreground
        if (!isInBackgroundRef.current) {
          logger.breadcrumb('WebSocket connected, marking device online', {
            category: 'Device',
            level: 'debug',
            data: { deviceId: currentDeviceId },
          });
          markConnected(currentDeviceId).catch((err) => {
            logger.warn('Failed to mark device connected', {
              category: 'Device',
              error: err as Error,
            });
          });
        }
      } else if (!isConnected && wasConnectedRef.current) {
        // WebSocket just disconnected
        wasConnectedRef.current = false;
        logger.breadcrumb('WebSocket disconnected, marking device offline', {
          category: 'Device',
          level: 'debug',
          data: { deviceId: currentDeviceId },
        });
        // May fail if network is down - that's OK, server timeout will catch it
        markDisconnected(currentDeviceId).catch(() => {
          logger.warn('Failed to mark disconnected', {
            category: 'E2EE',
            data: { deviceId: currentDeviceId },
          });
        });
      }
    },
    [markConnected, markDisconnected]
  );

  // App state handler
  const handleAppStateChange = useCallback(
    (nextAppState: AppStateStatus, forceConnectionCheck?: () => boolean) => {
      const logger = loggerRef.current;
      const currentDeviceId = deviceIdRef.current;
      if (!currentDeviceId) return;

      const wasInBackground = isInBackgroundRef.current;
      isInBackgroundRef.current = nextAppState !== 'active';

      // App going to background → immediately mark offline
      if (!wasInBackground && nextAppState !== 'active') {
        logger.debug(
          `[Presence] App → ${nextAppState}, marking offline (device ${currentDeviceId})`,
          {
            category: 'Device',
          }
        );
        logger.breadcrumb('App backgrounded, marking device offline', {
          category: 'Device',
          level: 'debug',
          data: { deviceId: currentDeviceId },
        });
        markDisconnected(currentDeviceId).catch(() => {
          logger.warn('Failed to mark disconnected', {
            category: 'E2EE',
            data: { deviceId: currentDeviceId },
          });
        });
      }

      // App returning to foreground
      if (wasInBackground && nextAppState === 'active') {
        // Query ACTUAL connection state, not the potentially stale ref
        // After long background, WebSocket may have reconnected but ref wasn't updated
        const actuallyConnected = forceConnectionCheck?.() ?? wasConnectedRef.current;

        // Log to native logger (visible in Console.app)
        logger.debug(
          `[Presence] App → active, ref=${wasConnectedRef.current}, actual=${actuallyConnected}, device=${currentDeviceId}`,
          {
            category: 'Device',
          }
        );
        logger.breadcrumb('App foregrounded, checking WebSocket state', {
          category: 'Device',
          level: 'debug',
          data: {
            deviceId: currentDeviceId,
            wasConnected: wasConnectedRef.current,
            actuallyConnected,
          },
        });

        // Sync the ref with actual state
        wasConnectedRef.current = actuallyConnected;

        // If WebSocket is connected (either ref or actual), mark online now
        if (actuallyConnected) {
          logger.debug(`[Presence] Calling markConnected for device ${currentDeviceId}`, {
            category: 'Device',
          });
          markConnected(currentDeviceId).catch((err) => {
            logger.warn('Failed to mark device connected on foreground', {
              category: 'Device',
              error: err as Error,
            });
          });
        } else {
          logger.debug(
            `[Presence] Skipping markConnected - not connected (device ${currentDeviceId})`,
            { category: 'Device' }
          );
        }
      }
    },
    [markConnected, markDisconnected]
  );

  useEffect(() => {
    const logger = loggerRef.current;

    if (!enabled || !deviceId) {
      logger.debug('Presence effect skipped', {
        category: 'Device',
        data: { enabled, deviceId, reason: !enabled ? 'disabled' : 'no deviceId' },
      });
      return;
    }

    logger.debug('Presence effect starting', {
      category: 'Device',
      data: { enabled, deviceId },
    });

    // CRITICAL: Re-check current app state when effect enables
    // AppState.currentState may have been stale during component mount
    const currentAppState = AppState.currentState;
    isInBackgroundRef.current = currentAppState !== 'active';

    // Heartbeat interval reference
    let heartbeatInterval: ReturnType<typeof setInterval> | null = null;

    // Start heartbeat when connected and in foreground
    const startHeartbeat = () => {
      if (heartbeatInterval) return; // Already running

      heartbeatInterval = setInterval(() => {
        const currentDeviceId = deviceIdRef.current;
        if (!currentDeviceId || isInBackgroundRef.current || !wasConnectedRef.current) {
          return;
        }

        // Lightweight heartbeat — writes only to heartbeats table, triggers 0 query reruns
        relayRef.current.heartbeat(currentDeviceId).catch((err) => {
          logger.warn('Failed to send presence heartbeat', {
            category: 'Device',
            error: err as Error,
          });
        });
      }, HEARTBEAT_INTERVAL_MS);
    };

    // Stop heartbeat when backgrounded or disconnected
    const stopHeartbeat = () => {
      if (heartbeatInterval) {
        clearInterval(heartbeatInterval);
        heartbeatInterval = null;
      }
    };

    // Track last known connection state from Convex itself.
    // We seed this synchronously because the subscription callback may not fire
    // immediately when the hook enables while the socket is already connected.
    const initialConnectionState = convex.connectionState().isWebSocketConnected;
    let lastKnownConnectionState = initialConnectionState;

    // Subscribe to WebSocket connection state changes
    const unsubscribeConnection = convex.subscribeToConnectionState((state) => {
      // Update tracking variable for AppState handler
      const wasConnected = lastKnownConnectionState;
      lastKnownConnectionState = state.isWebSocketConnected;

      // Only log when state actually changes (reduces noise from repeated true → true)
      if (wasConnected !== state.isWebSocketConnected) {
        logger.debug(
          `[Presence] WebSocket: ${wasConnected} → ${state.isWebSocketConnected}, bg=${isInBackgroundRef.current}`,
          {
            category: 'Device',
          }
        );
      }

      handleConnectionChange(state.isWebSocketConnected);

      // Manage heartbeat based on connection state
      if (state.isWebSocketConnected && !isInBackgroundRef.current) {
        startHeartbeat();
      } else {
        stopHeartbeat();
      }
    });

    // Subscribe to app lifecycle state changes
    const appStateSubscription = AppState.addEventListener('change', (nextState) => {
      // Pass a function that returns the actual connection state
      // This is critical after long background - the ref may be stale but
      // lastKnownConnectionState is updated by the subscription callback
      handleAppStateChange(nextState, () => lastKnownConnectionState);

      // Manage heartbeat based on app state
      // Use lastKnownConnectionState instead of wasConnectedRef for reliability
      if (nextState === 'active' && lastKnownConnectionState) {
        startHeartbeat();
      } else if (nextState !== 'active') {
        stopHeartbeat();
      }
    });

    // When the effect enables (for example after unlock), seed presence from the
    // actual socket state instead of assuming "enabled" means "online".
    const freshAppState = AppState.currentState;
    const inBackground = freshAppState !== 'active';
    isInBackgroundRef.current = inBackground;

    wasConnectedRef.current = initialConnectionState;
    if (!inBackground && initialConnectionState) {
      markConnected(deviceId).catch((err) => {
        logger.warn('Failed to mark device connected on effect enable', {
          category: 'Device',
          error: err as Error,
        });
      });
      startHeartbeat();
    }

    return () => {
      stopHeartbeat();
      unsubscribeConnection();
      appStateSubscription.remove();
      // Try to mark disconnected on unmount (component cleanup)
      if (wasConnectedRef.current && deviceIdRef.current) {
        markDisconnected(deviceIdRef.current).catch(() => {
          logger.warn('Failed to mark disconnected', {
            category: 'E2EE',
            data: { deviceId: deviceIdRef.current },
          });
        });
        wasConnectedRef.current = false;
      }
    };
  }, [
    convex,
    deviceId,
    enabled,
    handleConnectionChange,
    handleAppStateChange,
    markConnected,
    markDisconnected,
  ]);
}
