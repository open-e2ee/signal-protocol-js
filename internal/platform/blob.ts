/**
 * The runtime's `Blob`, when it holds bytes.
 *
 * React Native's `Blob` rejects binary parts and has no `arrayBuffer()` or
 * `text()`. `binaryBlob` returns the runtime's `Blob` constructor only when a
 * probe shows that it holds bytes and reads them back.
 */

let checkedConstructor: unknown;
let binaryBlobConstructor: typeof Blob | undefined;

/** The runtime's `Blob` constructor, or `undefined` when it cannot hold bytes. */
export function binaryBlob(): typeof Blob | undefined {
  const Constructor = (globalThis as { Blob?: typeof Blob }).Blob;
  if (Constructor !== checkedConstructor) {
    checkedConstructor = Constructor;
    binaryBlobConstructor = undefined;
    try {
      const probe = new Constructor!([new Uint8Array(1)]);
      if (
        probe.size === 1 &&
        typeof probe.arrayBuffer === 'function' &&
        typeof probe.text === 'function'
      ) {
        binaryBlobConstructor = Constructor;
      }
    } catch {
      // A Blob that rejects binary parts, or no Blob.
    }
  }
  return binaryBlobConstructor;
}
