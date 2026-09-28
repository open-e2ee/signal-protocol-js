import { flows, installInProcessNetwork, runSteps } from 'hermes-gate';

// Hide the random provider for one flow. The SDK reads `globalThis.crypto` on
// each call, so the flow sees the app as if it installed no provider.
async function withoutRandomProvider(run: () => Promise<void>): Promise<void> {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
  if (!descriptor?.configurable) throw new Error('The app cannot remove its crypto global for the no-provider flow.');
  delete (globalThis as { crypto?: unknown }).crypto;
  try {
    await run();
  } finally {
    Object.defineProperty(globalThis, 'crypto', descriptor);
  }
}

/**
 * Run each flow of the Hermes gate in this app, with the gate's own cases.
 * Each step logs one `CASE PASS` or `CASE FAIL` line. The flows reach
 * in-process services through `fetch` and `WebSocket`, so the app puts its own
 * back after the last flow.
 */
export async function runGateFlows(log: (line: string) => void): Promise<void> {
  if (flows.length === 0) {
    log('The Hermes gate flows run only in the private repository.');
    return;
  }
  const { fetch, WebSocket } = globalThis;
  let failed = 0;
  let total = 0;
  const report = (line: string) => {
    total += 1;
    if (line.startsWith('CASE FAIL')) failed += 1;
    log(line);
  };
  installInProcessNetwork();
  try {
    for (const flow of flows) {
      const run = () => runSteps(flow.name, flow.steps, flow.load, report);
      await (flow.provider === false ? withoutRandomProvider(run) : run());
    }
  } finally {
    Object.assign(globalThis, { fetch, WebSocket });
  }
  if (failed > 0) throw new Error(`${failed} of ${total} gate cases failed.`);
  log(`Gate flows: ${total} cases passed in ${flows.length} flows.`);
}
