import { defineComponent } from 'convex/server';
import { v } from 'convex/values';
import rateLimiter from '@convex-dev/rate-limiter/convex.config';

// Components are isolated from the app's environment variables. An
// undeclared variable is invisible to component functions in a real
// deployment, no matter what the app's deployment env contains. The group
// server secret must therefore be declared here and forwarded by the app:
//
// ```ts
//   app.use(signalProtocol, {
//     env: { OE_GROUPS_SERVER_SECRET: app.env.OE_GROUPS_SERVER_SECRET },
//   });
// ```
//
// Optional because the messaging/device/key namespaces work without it.
// Group, credential-issuance, and sender-certificate paths enforce its
// presence at runtime with a precise remediation error.
const component = defineComponent('signalProtocol', {
  env: { OE_GROUPS_SERVER_SECRET: v.optional(v.string()) },
});
// Convex supplies this marker when it resolves an imported component
// definition. It is intentionally absent when package-surface tests import
// this config as an ordinary Node module.
//
// Known failure mode: the marker is a Convex internal. If a future convex
// release renames it, this mount is silently skipped and the deploy still
// succeeds. The first symptom is every fetchPreKeyBundle failing at runtime.
// The rate limiter's function references resolve to a missing child
// component. If prekey fetches start erroring after a convex upgrade, check
// this guard first.
if (
  typeof (
    rateLimiter as typeof rateLimiter & {
      componentDefinitionPath?: string;
    }
  ).componentDefinitionPath === 'string'
) {
  component.use(rateLimiter);
}

export default component;
