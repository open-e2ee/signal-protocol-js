import { mkdir, open } from "node:fs/promises";
import { createRequire } from "node:module";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import { setTimeout } from "node:timers/promises";

const require = createRequire(import.meta.url);
export const NODE_DATABASE_LOCK_FILE = ".database.lock";

interface NativeFileLock {
  tryLock(fd: number): boolean;
  unlock(fd: number): void;
}

/**
 * The persistent inode coordinates every handle, including directory aliases.
 * Never unlink this file during reset. An unlinked lock can admit another writer.
 * Process exit releases the kernel lock. No timestamp authorizes a takeover.
 */
export async function withNodeDatabaseLock<T>(
  dataDir: string,
  operation: () => Promise<T>,
  timeoutMs = 30_000,
): Promise<T> {
  let native: NativeFileLock;
  try {
    native = require("fs-native-extensions") as NativeFileLock;
  } catch {
    throw new Error(
      "Node storage requires fs-native-extensions. Install it before opening the store.",
    );
  }
  await mkdir(dataDir, { recursive: true, mode: 0o700 });
  const handle = await open(
    join(dataDir, NODE_DATABASE_LOCK_FILE),
    "a+",
    0o600,
  );
  let locked = false;
  const deadline = performance.now() + timeoutMs;
  try {
    while (!(locked = native.tryLock(handle.fd))) {
      if (performance.now() >= deadline)
        throw new Error("Node database is busy. Retry the operation.");
      // Blocking native waits can exhaust the thread pool needed by the lock owner.
      await setTimeout(10);
    }
    return await operation();
  } finally {
    try {
      if (locked) native.unlock(handle.fd);
    } finally {
      await handle.close();
    }
  }
}
