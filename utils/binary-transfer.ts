/**
 * SDK-local binary upload/download helpers.
 *
 * Uses the platform's global `fetch` by default (Node 18+, modern React Native,
 * browsers), so the profile subpath works without an Expo runtime. Consumers may
 * inject a custom implementation (e.g. Expo's streaming `fetch`) via `fetchImpl`.
 */
export {};

type FetchLike = typeof globalThis.fetch;

function resolveFetch(fetchImpl?: FetchLike): FetchLike {
  const impl = fetchImpl ?? globalThis.fetch;
  if (typeof impl !== 'function') {
    throw new Error(
      'No fetch implementation available. Pass options.fetchImpl, or run on a ' +
        'platform that provides a global fetch (Node 18+, React Native, browsers).'
    );
  }
  return impl;
}

export async function uploadBinary(
  url: string,
  data: Uint8Array,
  options: {
    method?: 'PUT' | 'POST';
    headers?: Record<string, string>;
    fetchImpl?: FetchLike;
  } = {}
): Promise<Response> {
  const { method = 'PUT', headers = {}, fetchImpl } = options;

  return resolveFetch(fetchImpl)(url, {
    method,
    headers: {
      'Content-Type': 'application/octet-stream',
      ...headers,
    },
    body: data as unknown as BodyInit,
  });
}

export async function downloadBinary(
  url: string,
  options: { fetchImpl?: FetchLike } = {}
): Promise<Uint8Array> {
  const response = await resolveFetch(options.fetchImpl)(url);
  if (!response.ok) {
    throw new Error(`Download failed: ${response.status} ${response.statusText}`);
  }

  return new Uint8Array(await response.arrayBuffer());
}
