/**
 * URL parsing and building on every runtime the SDK supports.
 *
 * React Native's global `URL` is not a WHATWG URL. It has no setters, it reads
 * the host and the path only for `http` and `https`, and its `URLSearchParams`
 * splits a value on every `=`. This module never reads the global `URL`.
 *
 * `parseUrl` accepts only the URL forms that the SDK uses. For each input that
 * it accepts, it gives the same fields as a WHATWG `URL`. It rejects every
 * other input with `TypeError('Invalid URL')`, which includes:
 *
 * - credentials, a fragment, an empty query, and a dot segment;
 * - whitespace, control characters, backslashes, and non-ASCII characters;
 * - a malformed percent escape;
 * - a host that a WHATWG parser would rewrite: an IDNA label, an empty label,
 *   or an IPv4 or IPv6 address in a non-canonical form;
 * - a port with a leading zero or above 65535;
 * - the `file` and `ftp` schemes, and any URL without `//` after the scheme.
 */

import { utf8Decode } from './utf8';

/** The fields of an accepted URL. Each has the value that a WHATWG `URL` gives. */
export interface ParsedUrl {
  readonly href: string;
  /** The scheme in lowercase, with the trailing `:`. */
  readonly protocol: string;
  readonly hostname: string;
  /** Empty when the URL has no port or has the default port of its scheme. */
  readonly port: string;
  readonly host: string;
  /** `'null'` for a scheme that is not `http`, `https`, `ws`, or `wss`. */
  readonly origin: string;
  readonly pathname: string;
  /** Empty, or `?` and a query that is not empty. */
  readonly search: string;
}

/** The special schemes that this module parses, with their default ports. */
const DEFAULT_PORTS: Readonly<Record<string, string>> = {
  'http:': '80',
  'https:': '443',
  'ws:': '80',
  'wss:': '443',
};

const SCHEME = /^([A-Za-z][A-Za-z0-9+.-]*):\/\//u;
const SCHEME_PREFIX = /^[A-Za-z][A-Za-z0-9+.-]*:/u;
const PRINTABLE_ASCII = /^[\x21-\x7e]*$/u;
const AUTHORITY = /^(\[[^\]]*\]|[^:[\]]*)(?::(.*))?$/u;
const PATH = /^(?:\/(?:[A-Za-z0-9\-._~!$&'()*+,;=:@]|%[0-9A-Fa-f]{2})*)*$/u;
const QUERY = /^(?:[A-Za-z0-9\-._~!$&()*+,;=:@/?]|%[0-9A-Fa-f]{2})+$/u;
const DOMAIN_LABEL = /^[a-z0-9_-]+$/u;
const NUMERIC_LABEL = /^(?:[0-9]+|0x[0-9a-f]*)$/u;
const IPV4_PART = /^(?:0|[1-9][0-9]{0,2})$/u;
const IPV6_PIECE = /^[0-9a-f]{1,4}$/u;
const OPAQUE_HOST = /^[A-Za-z0-9._~-]+$/u;
const PORT = /^(?:0|[1-9][0-9]{0,4})$/u;
const DOT_SEGMENT = /^(?:\.|%2e){1,2}$/iu;

function invalid(): never {
  throw new TypeError('Invalid URL');
}

/**
 * Parse an absolute URL of the form `scheme://host[:port][/path][?query]`.
 *
 * @throws TypeError when the input is not a form that the SDK uses.
 */
export function parseUrl(input: string): ParsedUrl {
  if (!PRINTABLE_ASCII.test(input) || input.includes('#') || input.includes('\\')) invalid();
  const scheme = SCHEME.exec(input);
  if (!scheme) invalid();
  const protocol = `${scheme[1]!.toLowerCase()}:`;
  if (protocol === 'file:' || protocol === 'ftp:') invalid();
  const special = protocol in DEFAULT_PORTS;

  const rest = input.slice(scheme[0].length);
  const authorityEnd = rest.search(/[/?]/u);
  const authority = authorityEnd === -1 ? rest : rest.slice(0, authorityEnd);
  const afterAuthority = authorityEnd === -1 ? '' : rest.slice(authorityEnd);
  const queryStart = afterAuthority.indexOf('?');
  const path = queryStart === -1 ? afterAuthority : afterAuthority.slice(0, queryStart);
  const query = queryStart === -1 ? undefined : afterAuthority.slice(queryStart + 1);

  const parts = AUTHORITY.exec(authority);
  if (!parts || parts[1] === '') invalid();
  const hostname = special ? specialHost(parts[1]!) : opaqueHost(parts[1]!);
  const port = parsePort(parts[2], protocol);

  if (!PATH.test(path)) invalid();
  if (path.split('/').some((segment) => DOT_SEGMENT.test(segment))) invalid();
  const pathname = special && path === '' ? '/' : path;
  if (query !== undefined && !QUERY.test(query)) invalid();
  const search = query === undefined ? '' : `?${query}`;

  const host = port === '' ? hostname : `${hostname}:${port}`;
  return {
    href: `${protocol}//${host}${pathname}${search}`,
    protocol,
    hostname,
    port,
    host,
    origin: special ? `${protocol}//${host}` : 'null',
    pathname,
    search,
  };
}

function specialHost(raw: string): string {
  if (raw.startsWith('[')) return ipv6Host(raw);
  const host = raw.toLowerCase();
  const labels = host.split('.');
  if (labels.some((label) => !DOMAIN_LABEL.test(label) || label.startsWith('xn--'))) invalid();
  // WHATWG reads a host whose last label is a number as an IPv4 address.
  if (NUMERIC_LABEL.test(labels[labels.length - 1]!)) {
    if (labels.length !== 4 || !labels.every((label) => IPV4_PART.test(label) && Number(label) <= 255)) {
      invalid();
    }
  }
  return host;
}

/** Accept an IPv6 address only in the form that WHATWG serializes. */
function ipv6Host(raw: string): string {
  const text = raw.slice(1, -1);
  const halves = text.split('::');
  if (halves.length > 2) invalid();
  const pieces = (part: string): number[] =>
    part === ''
      ? []
      : part.split(':').map((piece) => (IPV6_PIECE.test(piece) ? Number.parseInt(piece, 16) : invalid()));
  const head = pieces(halves[0]!);
  let address = head;
  if (halves.length === 2) {
    const tail = pieces(halves[1]!);
    const zeros = 8 - head.length - tail.length;
    if (zeros < 1) invalid();
    address = [...head, ...new Array<number>(zeros).fill(0), ...tail];
  }
  if (address.length !== 8 || serializeIpv6(address) !== text) invalid();
  return raw;
}

function serializeIpv6(address: readonly number[]): string {
  let compressStart = -1;
  let compressLength = 1;
  for (let index = 0; index < 8; ) {
    let end = index;
    while (end < 8 && address[end] === 0) end += 1;
    if (end - index > compressLength) {
      compressStart = index;
      compressLength = end - index;
    }
    index = end === index ? index + 1 : end;
  }
  let output = '';
  for (let index = 0; index < 8; index += 1) {
    if (index === compressStart) {
      output += index === 0 ? '::' : ':';
      index += compressLength - 1;
      continue;
    }
    output += address[index]!.toString(16);
    if (index !== 7) output += ':';
  }
  return output;
}

function opaqueHost(raw: string): string {
  return OPAQUE_HOST.test(raw) ? raw : invalid();
}

function parsePort(raw: string | undefined, protocol: string): string {
  if (raw === undefined) return '';
  if (!PORT.test(raw) || Number(raw) > 65_535) invalid();
  return raw === DEFAULT_PORTS[protocol] ? '' : raw;
}

/**
 * The values of one query parameter, decoded as WHATWG
 * application/x-www-form-urlencoded. Unlike WHATWG, a name or a value that is
 * not valid UTF-8 or starts with a byte order mark is an error.
 *
 * @throws TypeError when a name or a value does not decode.
 */
export function queryValues(url: ParsedUrl, name: string): string[] {
  const values: string[] = [];
  for (const pair of url.search.slice(1).split('&')) {
    if (pair === '') continue;
    const separator = pair.indexOf('=');
    const key = decodeFormComponent(separator === -1 ? pair : pair.slice(0, separator));
    const value = decodeFormComponent(separator === -1 ? '' : pair.slice(separator + 1));
    if (key === name) values.push(value);
  }
  return values;
}

function decodeFormComponent(text: string): string {
  const bytes: number[] = [];
  for (let index = 0; index < text.length; index += 1) {
    const code = text.charCodeAt(index);
    if (code === 0x25) {
      bytes.push(Number.parseInt(text.slice(index + 1, index + 3), 16));
      index += 2;
    } else {
      bytes.push(code === 0x2b ? 0x20 : code);
    }
  }
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) invalid();
  try {
    return utf8Decode(Uint8Array.from(bytes), { fatal: true });
  } catch {
    return invalid();
  }
}

/**
 * Serialize query parameters as WHATWG `URLSearchParams.toString()` does,
 * without the leading `?`.
 */
export function encodeQuery(entries: ReadonlyArray<readonly [string, string]>): string {
  return entries
    .map(([name, value]) => `${encodeFormComponent(name)}=${encodeFormComponent(value)}`)
    .join('&');
}

function encodeFormComponent(text: string): string {
  return encodeURIComponent(wellFormed(text))
    .replace(/%20/gu, '+')
    .replace(/[!'()~]/gu, (character) => `%${character.charCodeAt(0).toString(16).toUpperCase()}`);
}

/** Replace each lone surrogate with U+FFFD, as UTF-8 encoding does. */
function wellFormed(text: string): string {
  let output = '';
  for (let index = 0; index < text.length; index += 1) {
    const code = text.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = text.charCodeAt(index + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        output += text.slice(index, index + 2);
        index += 1;
        continue;
      }
      output += '�';
    } else {
      output += code >= 0xdc00 && code <= 0xdfff ? '�' : text[index];
    }
  }
  return output;
}

/**
 * Resolve a URL reference against an `http` or `https` base URL.
 *
 * The reference can be an absolute URL, a path that starts with `/`, or a
 * relative path. A reference that starts with `//`, `?`, or `#` is an error.
 *
 * @throws TypeError when the reference, the base, or the result is not a form
 * that `parseUrl` accepts.
 */
export function resolveUrl(reference: string, base: string): string {
  if (SCHEME_PREFIX.test(reference)) return parseUrl(reference).href;
  const baseUrl = parseUrl(base);
  if (baseUrl.protocol !== 'https:' && baseUrl.protocol !== 'http:') invalid();
  if (reference === '' || reference.startsWith('//') || reference.startsWith('?')) invalid();
  const directory = reference.startsWith('/')
    ? ''
    : baseUrl.pathname.slice(0, baseUrl.pathname.lastIndexOf('/') + 1);
  return parseUrl(`${baseUrl.origin}${directory}${reference}`).href;
}

/**
 * The WebSocket URL for an `http` or `https` endpoint: `https` becomes `wss`,
 * `http` becomes `ws`, and the query is replaced.
 *
 * @throws TypeError when the endpoint is not an `http` or `https` URL that
 * `parseUrl` accepts.
 */
export function websocketUrl(
  endpoint: string,
  query: ReadonlyArray<readonly [string, string]>,
): string {
  const url = parseUrl(endpoint);
  const protocol = url.protocol === 'https:' ? 'wss:' : url.protocol === 'http:' ? 'ws:' : invalid();
  const search = encodeQuery(query);
  // http and ws share the default port 80, and https and wss share 443.
  return `${protocol}//${url.host}${url.pathname}${search === '' ? '' : `?${search}`}`;
}
