/**
 * The environment variables that the SDK reads.
 *
 * Bundlers replace only a literal `process.env.NAME` member expression at
 * build time, so each variable has its own reader with that literal read. A
 * browser that loads the SDK without a bundler `define` has no `process`, and
 * each reader then returns `undefined`.
 */

/** `NODE_ENV`, which a test runner sets to "test". */
export function nodeEnv(): string | undefined {
  return typeof process === 'undefined' ? undefined : process.env.NODE_ENV;
}

/** `EXPO_PUBLIC_CONVEX_URL`, which Expo inlines at build time. */
export function expoPublicConvexUrl(): string | undefined {
  return typeof process === 'undefined' ? undefined : process.env.EXPO_PUBLIC_CONVEX_URL;
}
