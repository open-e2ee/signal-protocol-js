/* eslint-disable */
/**
 * Generated `api` utility.
 *
 * THIS CODE IS AUTOMATICALLY GENERATED.
 *
 * To regenerate, run `npx convex dev`.
 * @module
 */

import type * as accounts from "../accounts.js";
import type * as certificates from "../certificates.js";
import type * as cleanup from "../cleanup.js";
import type * as crons from "../crons.js";
import type * as devices from "../devices.js";
import type * as errors from "../errors.js";
import type * as groups from "../groups.js";
import type * as keys from "../keys.js";
import type * as messages from "../messages.js";
import type * as provisioning from "../provisioning.js";
import type * as runtime from "../runtime.js";
import type * as zkAuth from "../zkAuth.js";

import type {
  ApiFromModules,
  FilterApi,
  FunctionReference,
} from "convex/server";
import { anyApi, componentsGeneric } from "convex/server";

const fullApi: ApiFromModules<{
  accounts: typeof accounts;
  certificates: typeof certificates;
  cleanup: typeof cleanup;
  crons: typeof crons;
  devices: typeof devices;
  errors: typeof errors;
  groups: typeof groups;
  keys: typeof keys;
  messages: typeof messages;
  provisioning: typeof provisioning;
  runtime: typeof runtime;
  zkAuth: typeof zkAuth;
}> = anyApi as any;

/**
 * A utility for referencing Convex functions in your app's public API.
 *
 * Usage:
 * ```js
 * const myFunctionReference = api.myModule.myFunction;
 * ```
 */
export const api: FilterApi<
  typeof fullApi,
  FunctionReference<any, "public">
> = anyApi as any;

/**
 * A utility for referencing Convex functions in your app's internal API.
 *
 * Usage:
 * ```js
 * const myFunctionReference = internal.myModule.myFunction;
 * ```
 */
export const internal: FilterApi<
  typeof fullApi,
  FunctionReference<any, "internal">
> = anyApi as any;

export const components = componentsGeneric() as unknown as {
  rateLimiter: import("@convex-dev/rate-limiter/_generated/component.js").ComponentApi<"rateLimiter">;
};
