import { cbc, gcm } from '@noble/ciphers/aes.js';

type AesMode = 'AES-CBC' | 'AES-GCM';

/** Use Web Crypto when available. Hermes uses the existing Noble AES implementation. */
async function transform(
  operation: 'encrypt' | 'decrypt',
  mode: AesMode,
  key: Uint8Array,
  iv: Uint8Array,
  data: Uint8Array,
  additionalData?: Uint8Array
): Promise<Uint8Array> {
  const subtle = globalThis.crypto?.subtle;
  if (subtle) {
    const cryptoKey = await subtle.importKey('raw', key as Uint8Array<ArrayBuffer>, { name: mode }, false, [operation]);
    const params = {
      name: mode,
      iv: iv as Uint8Array<ArrayBuffer>,
      ...(mode === 'AES-GCM' ? {
        tagLength: 128,
        ...(additionalData === undefined ? {} : { additionalData: additionalData as Uint8Array<ArrayBuffer> }),
      } : {}),
    };
    return new Uint8Array(await subtle[operation](params, cryptoKey, data as Uint8Array<ArrayBuffer>));
  }

  const cipher = mode === 'AES-GCM' ? gcm(key, iv, additionalData) : cbc(key, iv);
  return cipher[operation](data);
}

export function encryptAes(mode: AesMode, key: Uint8Array, iv: Uint8Array, plaintext: Uint8Array, additionalData?: Uint8Array): Promise<Uint8Array> {
  return transform('encrypt', mode, key, iv, plaintext, additionalData);
}

export function decryptAes(mode: AesMode, key: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array, additionalData?: Uint8Array): Promise<Uint8Array> {
  return transform('decrypt', mode, key, iv, ciphertext, additionalData);
}
