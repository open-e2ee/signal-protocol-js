/**
 * The `hermes-gate` module when the checkout has no Hermes gate. The public
 * repository has none, so `metro.config.js` resolves `hermes-gate` here and the
 * app runs no gate flows. The type checker reads this file for every build.
 */

export interface GateFlowModule {
  readonly default: unknown;
}

export interface GateFlow {
  readonly name: string;
  readonly steps: readonly string[];
  /** False when the flow must run with no random provider installed. */
  readonly provider?: false;
  readonly load: () => Promise<GateFlowModule>;
}

export const flows: readonly GateFlow[] = [];

export declare function runSteps(
  prefix: string,
  names: readonly string[],
  load: () => Promise<GateFlowModule>,
  reportLine: (line: string) => void
): Promise<void>;

export declare function installInProcessNetwork(): void;
