import { randomUUID } from "node:crypto";
import { open, readdir, rename, unlink } from "node:fs/promises";
import { dirname, join } from "node:path";

export function isNodeDatabaseRecord(name: string): boolean {
  return /^(?:protocol_security_state_v1|(?:identity_keys|signed_prekeys|kyber_prekeys)_[a-zA-Z0-9_-]+)\.json$/.test(
    name,
  );
}

function isPendingNodeDatabaseFile(name: string): boolean {
  const base = name.match(
    /^(.+)\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.pending$/,
  )?.[1];
  return (
    base !== undefined &&
    (base === "db.key" ||
      base === ".database.reset" ||
      isNodeDatabaseRecord(base))
  );
}

export function isNodeDatabaseDataEntry(name: string): boolean {
  return (
    name === "db.key" ||
    name === ".database.reset" ||
    name === "sessions" ||
    isNodeDatabaseRecord(name) ||
    isPendingNodeDatabaseFile(name)
  );
}

/** Remove interrupted writes only while the same persistent lock excludes writers. */
export async function clearPendingNodeDatabaseFiles(
  directory: string,
): Promise<void> {
  const pending = (await readdir(directory)).filter(isPendingNodeDatabaseFile);
  for (const name of pending) await unlink(join(directory, name));
  if (pending.length) await syncNodeDatabaseDirectory(directory);
}

export async function syncNodeDatabaseDirectory(
  directory: string,
): Promise<void> {
  if (process.platform === "win32") return;
  const handle = await open(directory, "r");
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

/** Call only while the database lock excludes readers, writers, and reset. */
export async function commitNodeDatabaseFile(
  path: string,
  value: string | Uint8Array,
): Promise<void> {
  const temporary = `${path}.${randomUUID()}.pending`;
  const handle = await open(temporary, "wx", 0o600);
  try {
    try {
      await handle.writeFile(value);
      await handle.sync();
    } finally {
      await handle.close();
    }
    await rename(temporary, path);
    await syncNodeDatabaseDirectory(dirname(path));
  } finally {
    await unlink(temporary).catch((error: NodeJS.ErrnoException) => {
      if (error.code !== "ENOENT") throw error;
    });
  }
}
