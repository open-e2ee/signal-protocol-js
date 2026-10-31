/**
 * Request admission: the check that each repeat request of a relay post
 * meets before it starts, the count of each repeat that starts, and the mark
 * on an answer that followed a repeat.
 *
 * One post can make more than one request. A transport repeats a request
 * once after an uncertain answer, and once after a refused device token. The
 * owner of a post registers a check under the client message ID that its
 * envelope carries, and the transport awaits each check of that ID before a
 * repeat starts. A check that rejects stops the repeat. When every check
 * admits the repeat, each registration gets the repeat with its device, so
 * the owner of that device post counts the request.
 *
 * After an uncertain answer, the first request can have stored the post. So
 * the answer to its repeat tells nothing about the post, and the transport
 * marks the error of that answer. No package entry exports this module. The
 * registration and the mark are internal to the SDK.
 */

/** A repeat request of one device post, and the answer that it follows. */
export interface RepeatRequest {
  readonly userId: string;
  readonly deviceId: number;
  /**
   * `uncertain` after a DELIVERY_UNCERTAIN answer, `token` after a refused
   * credential: a device token, or a group endorsement that the direct route
   * refused.
   */
  readonly after: 'uncertain' | 'token';
}

interface Admission {
  readonly check: (request: RepeatRequest) => Promise<void>;
  readonly admitted?: (request: RepeatRequest) => void;
}

const admissions = new WeakMap<object, Map<string, Admission[]>>();
const afterRepeat = new WeakSet<object>();

/**
 * Register a check for each repeat request of the posts with this client
 * message ID on this relay. `admitted` runs for each repeat that every check
 * admitted. Each registration counts once, and the returned function
 * releases it.
 */
export function admitRequestsFor(
  relay: object,
  clientMessageId: string,
  check: (request: RepeatRequest) => Promise<void>,
  admitted?: (request: RepeatRequest) => void
): () => void {
  let checks = admissions.get(relay);
  if (!checks) {
    checks = new Map();
    admissions.set(relay, checks);
  }
  const registered = checks;
  const admission: Admission = { check, ...(admitted && { admitted }) };
  registered.set(clientMessageId, [...(registered.get(clientMessageId) ?? []), admission]);
  let released = false;
  return () => {
    if (released) return;
    released = true;
    const current = registered.get(clientMessageId) ?? [];
    const index = current.indexOf(admission);
    const remaining = index < 0 ? current : current.filter((_, at) => at !== index);
    if (remaining.length === 0) registered.delete(clientMessageId);
    else registered.set(clientMessageId, remaining);
  };
}

/**
 * Run each check that is registered for this client message ID on this
 * relay, in turn, with the repeat request. A check that refuses rejects, and
 * the repeat does not start. When every check admits it, each registration
 * gets the repeat request. A message ID with no registration admits the
 * request.
 */
export async function admitRepeatRequest(
  relay: object,
  clientMessageId: string,
  request: RepeatRequest
): Promise<void> {
  const registered = [...(admissions.get(relay)?.get(clientMessageId) ?? [])];
  for (const { check } of registered) await check(request);
  for (const { admitted } of registered) admitted?.(request);
}

/** Mark an error as the answer to a repeat request. Returns the same error. */
export function markAfterRepeatedRequest<T>(error: T): T {
  if (error !== null && typeof error === 'object') afterRepeat.add(error);
  return error;
}

/** True when the error is the answer to a repeat request. */
export function followedRepeatedRequest(error: unknown): boolean {
  return error !== null && typeof error === 'object' && afterRepeat.has(error);
}
