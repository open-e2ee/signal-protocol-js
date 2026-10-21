import { utf8Decode } from "../internal/platform";
import {
  base64ToBytes,
  bytesToUrlSafeBase64,
  concatBytes,
  sha256,
  stringToBytes,
  urlSafeToBase64,
} from "../internal/crypto";
import type { Base64 } from "../types";

type AssertionPurpose = "register" | "recover" | "refresh";
const nativeLabel = stringToBytes("OpenE2EE Relay native assertion v1\0");

function invalid(): never {
  throw new Error("Identity provider returned an invalid assertion");
}

function prefixed(value: string): Uint8Array {
  const bytes = stringToBytes(value);
  const length = new Uint8Array(4);
  new DataView(length.buffer).setUint32(0, bytes.length, false);
  return concatBytes(length, bytes);
}

/** Bind a challenge candidate. Relay alone verifies identity authority. */
export async function nativeAssertionBindingId(
  assertion: string,
  purpose: AssertionPurpose,
  operationId: string,
): Promise<string> {
  if (
    stringToBytes(assertion).length > 65_536 ||
    !["register", "recover", "refresh"].includes(purpose) ||
    !operationId ||
    operationId.length > 128 ||
    operationId.includes("\0")
  )
    invalid();
  return bytesToUrlSafeBase64(
    await sha256(
      concatBytes(
        nativeLabel,
        prefixed(assertion),
        prefixed(purpose),
        prefixed(operationId),
      ),
    ),
  );
}

/** Preserve present jti. Missing jti supplies no provider authentication. */
export async function hostedAssertionIdentifier(
  assertion: string,
  purpose: AssertionPurpose,
  operationId: string,
): Promise<string> {
  if (stringToBytes(assertion).length > 65_536) invalid();
  const parts = assertion.split(".");
  if (parts.length !== 3) invalid();
  let claims: unknown;
  try {
    const encoded = parts[1]!;
    const bytes = base64ToBytes(urlSafeToBase64(encoded) as Base64);
    if (bytesToUrlSafeBase64(bytes) !== encoded) invalid();
    claims = JSON.parse(utf8Decode(bytes));
  } catch {
    return invalid();
  }
  if (typeof claims !== "object" || claims === null || Array.isArray(claims))
    invalid();
  if (Object.hasOwn(claims, "jti")) {
    const jti: unknown = (claims as Record<string, unknown>).jti;
    if (typeof jti !== "string" || !jti) invalid();
    return jti;
  }
  return nativeAssertionBindingId(assertion, purpose, operationId);
}
