/**
 * UTF-8 decoding on every runtime the SDK supports.
 *
 * Bare React Native on Hermes has no guaranteed `TextDecoder`. `utf8Decode`
 * uses the runtime's `TextDecoder` when that decoder passes a WHATWG
 * conformance probe, and the portable decoder below otherwise. Both follow
 * the WHATWG Encoding Standard UTF-8 decoder, so both give the same result for
 * the same bytes:
 *
 * - Each maximal invalid subsequence becomes one U+FFFD, or a `TypeError`
 *   when `fatal` is set.
 * - A leading UTF-8 byte order mark is removed, as `TextDecoder` removes it by
 *   default.
 */

export interface Utf8DecodeOptions {
  /** Throw a `TypeError` on invalid UTF-8 instead of writing U+FFFD. */
  readonly fatal?: boolean;
}

interface Decoder {
  decode(input: Uint8Array): string;
}

type DecoderConstructor = new (
  label?: string,
  options?: { fatal?: boolean },
) => Decoder;

const INVALID_UTF8 = 'The encoded data is not valid UTF-8';
const REPLACEMENT = 0xfffd;
const CHUNK = 0x2000;

let checkedConstructor: unknown;
let nativeLenient: Decoder | undefined;
let nativeFatal: Decoder | undefined;

/**
 * Does the runtime's decoder replace, reject, and strip the BOM as WHATWG
 * says? A polyfill that ignores `fatal` or keeps the BOM would silently change
 * what the SDK accepts, so the portable decoder replaces it.
 */
function probeNativeDecoders(Constructor: DecoderConstructor): void {
  checkedConstructor = Constructor;
  nativeLenient = undefined;
  nativeFatal = undefined;
  try {
    const lenient = new Constructor('utf-8');
    const fatal = new Constructor('utf-8', { fatal: true });
    const sample = new Uint8Array([0xef, 0xbb, 0xbf, 0x41, 0xf0, 0x9f, 0x98, 0x80, 0xed, 0xa0, 0x80]);
    if (lenient.decode(sample) !== 'A\u{1f600}���') return;
    if (fatal.decode(sample.subarray(0, 8)) !== 'A\u{1f600}') return;
    try {
      fatal.decode(sample);
      return;
    } catch {
      // A conforming fatal decoder throws here.
    }
    nativeLenient = lenient;
    nativeFatal = fatal;
  } catch {
    nativeLenient = undefined;
    nativeFatal = undefined;
  }
}

function nativeDecoder(fatal: boolean): Decoder | undefined {
  const Constructor = (globalThis as { TextDecoder?: DecoderConstructor }).TextDecoder;
  if (typeof Constructor !== 'function') return undefined;
  if (Constructor !== checkedConstructor) probeNativeDecoders(Constructor);
  return fatal ? nativeFatal : nativeLenient;
}

/** Decode UTF-8 bytes with the runtime's `TextDecoder`, or the portable decoder. */
export function utf8Decode(bytes: Uint8Array, options: Utf8DecodeOptions = {}): string {
  const fatal = options.fatal === true;
  const decoder = nativeDecoder(fatal);
  if (!decoder) return utf8DecodePortable(bytes, options);
  if (!fatal) return decoder.decode(bytes);
  try {
    return decoder.decode(bytes);
  } catch {
    throw new TypeError(INVALID_UTF8);
  }
}

/**
 * The WHATWG Encoding Standard UTF-8 decoder in plain JavaScript.
 *
 * Exported so that tests can run it beside the runtime's `TextDecoder`.
 * Production code calls `utf8Decode`.
 */
export function utf8DecodePortable(bytes: Uint8Array, options: Utf8DecodeOptions = {}): string {
  const fatal = options.fatal === true;
  const start =
    bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf ? 3 : 0;
  let output = '';
  const units: number[] = [];
  const emit = (codePoint: number): void => {
    if (codePoint > 0xffff) {
      const offset = codePoint - 0x10000;
      units.push(0xd800 | (offset >> 10), 0xdc00 | (offset & 0x3ff));
    } else {
      units.push(codePoint);
    }
    if (units.length >= CHUNK) {
      output += String.fromCharCode(...units);
      units.length = 0;
    }
  };
  const invalid = (): void => {
    if (fatal) throw new TypeError(INVALID_UTF8);
    emit(REPLACEMENT);
  };

  let codePoint = 0;
  let needed = 0;
  let seen = 0;
  let lower = 0x80;
  let upper = 0xbf;
  for (let index = start; index < bytes.length; index += 1) {
    const byte = bytes[index]!;
    if (needed === 0) {
      if (byte <= 0x7f) {
        emit(byte);
      } else if (byte >= 0xc2 && byte <= 0xdf) {
        needed = 1;
        codePoint = byte & 0x1f;
      } else if (byte >= 0xe0 && byte <= 0xef) {
        if (byte === 0xe0) lower = 0xa0;
        if (byte === 0xed) upper = 0x9f;
        needed = 2;
        codePoint = byte & 0x0f;
      } else if (byte >= 0xf0 && byte <= 0xf4) {
        if (byte === 0xf0) lower = 0x90;
        if (byte === 0xf4) upper = 0x8f;
        needed = 3;
        codePoint = byte & 0x07;
      } else {
        invalid();
      }
      continue;
    }
    if (byte < lower || byte > upper) {
      // The byte ends the invalid sequence and starts the next one.
      codePoint = 0;
      needed = 0;
      seen = 0;
      lower = 0x80;
      upper = 0xbf;
      invalid();
      index -= 1;
      continue;
    }
    lower = 0x80;
    upper = 0xbf;
    codePoint = (codePoint << 6) | (byte & 0x3f);
    seen += 1;
    if (seen === needed) {
      emit(codePoint);
      codePoint = 0;
      needed = 0;
      seen = 0;
    }
  }
  if (needed !== 0) invalid();
  return units.length > 0 ? output + String.fromCharCode(...units) : output;
}
