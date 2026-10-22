/**
 * The runner of the local store conformance kit. It runs each case on a
 * fresh store from the application, and it reports each case as passed,
 * skipped, or failed.
 *
 * The runner has no framework or platform dependencies, and avoids class
 * syntax. It runs unchanged under jest, Node, a browser, or Hermes.
 */

import type { LocalStoreProtection, SignalProtocolLocalStore } from '../../../types/api';
import { errorMessage } from './checks';
import { ciphertextCases } from './cases/ciphertext';
import { durabilityCases } from './cases/durability';
import { identityCases } from './cases/identity';
import { metadataCases } from './cases/metadata';
import { protectionCases } from './cases/protection';
import { receiveWorkCases } from './cases/receive-work';
import { senderKeyCases } from './cases/sender-key';
import { sessionTrustCases } from './cases/session-trust';
import type {
  LocalStoreConformanceCase,
  LocalStoreConformanceContext,
  LocalStoreConformanceOptions,
  LocalStoreConformanceResult,
} from './types';

const CASES: readonly LocalStoreConformanceCase[] = [
  ...identityCases,
  ...sessionTrustCases,
  ...senderKeyCases,
  ...metadataCases,
  ...receiveWorkCases,
  ...durabilityCases,
  ...ciphertextCases,
  ...protectionCases,
];

/** The name of the case that reads the protection declaration. */
const PROTECTION_CASE = protectionCases[0].name;

function missingOption(option: string): never {
  throw new Error('The case needs the ' + option + ' option.');
}

/** The outcome of one case. A failed case carries its message. */
type CaseOutcome = { outcome: 'passed' | 'skipped' } | { outcome: 'failed'; message: string };

/** Run one case on a fresh store, and close that store after the case. */
async function runCase(
  conformanceCase: LocalStoreConformanceCase,
  options: LocalStoreConformanceOptions,
  report: (protection: LocalStoreProtection) => void
): Promise<CaseOutcome> {
  let current: SignalProtocolLocalStore;
  try {
    current = await options.createStore();
  } catch (error) {
    return { outcome: 'failed', message: 'createStore failed: ' + errorMessage(error) };
  }
  const context: LocalStoreConformanceContext = {
    get store() {
      return current;
    },
    reopen: async function reopen() {
      if (!options.reopen) missingOption('reopen');
      current = await options.reopen(current);
      return current;
    },
    armWriteFailure: function armWriteFailure() {
      if (!options.armWriteFailure) missingOption('armWriteFailure');
      options.armWriteFailure(current);
    },
    readRawBytes: function readRawBytes() {
      if (!options.readRawBytes) missingOption('readRawBytes');
      return options.readRawBytes(current);
    },
    reportProtection: report,
  };
  let outcome: CaseOutcome;
  try {
    if (conformanceCase.applies && !conformanceCase.applies(current)) {
      outcome = { outcome: 'skipped' };
    } else {
      await conformanceCase.run(context);
      outcome = { outcome: 'passed' };
    }
  } catch (error) {
    outcome = { outcome: 'failed', message: errorMessage(error) };
  }
  if (options.closeStore) {
    try {
      await options.closeStore(current);
    } catch (error) {
      if (outcome.outcome !== 'failed') {
        outcome = { outcome: 'failed', message: 'closeStore failed: ' + errorMessage(error) };
      }
    }
  }
  return outcome;
}

/**
 * Run every case of the kit on stores from `options.createStore`, and report
 * the outcome without throwing. A case that needs an option that is not
 * given is skipped, and so is the ciphertext case on a store that declares
 * no cipher.
 */
export async function runLocalStoreConformance(
  options: LocalStoreConformanceOptions
): Promise<LocalStoreConformanceResult> {
  const result: LocalStoreConformanceResult = {
    total: CASES.length,
    passed: [],
    skipped: [],
    failures: [],
    protection: null,
  };
  for (const conformanceCase of CASES) {
    if (conformanceCase.needs && !options[conformanceCase.needs]) {
      result.skipped.push(conformanceCase.name);
      continue;
    }
    let reported: LocalStoreProtection | null = null;
    const outcome = await runCase(conformanceCase, options, function report(protection) {
      reported = protection;
    });
    if (outcome.outcome === 'failed') {
      result.failures.push({ name: conformanceCase.name, message: outcome.message });
    } else if (outcome.outcome === 'skipped') {
      result.skipped.push(conformanceCase.name);
    } else {
      result.passed.push(conformanceCase.name);
      if (conformanceCase.name === PROTECTION_CASE) result.protection = reported;
    }
  }
  return result;
}

/**
 * Run the kit, and throw with every problem listed when the store does not
 * conform. A failed case is a problem. A skipped rollback case is also a
 * problem, because a store must prove that its atomic commits roll back.
 * This is the form for the automated checks of an application.
 */
export async function assertLocalStoreConformance(
  options: LocalStoreConformanceOptions
): Promise<LocalStoreConformanceResult> {
  const result = await runLocalStoreConformance(options);
  const lines: string[] = [];
  for (const failure of result.failures) {
    lines.push('- ' + failure.name + ': ' + failure.message);
  }
  for (const conformanceCase of CASES) {
    if (
      conformanceCase.needs === 'armWriteFailure' &&
      result.skipped.indexOf(conformanceCase.name) !== -1
    ) {
      lines.push(
        '- ' +
          conformanceCase.name +
          ': skipped. Give armWriteFailure, so that the rollback of an atomic commit can run.'
      );
    }
  }
  if (lines.length > 0) {
    throw new Error(
      'Local store conformance failed (' +
        lines.length +
        ' of ' +
        result.total +
        ' cases):\n' +
        lines.join('\n')
    );
  }
  return result;
}
