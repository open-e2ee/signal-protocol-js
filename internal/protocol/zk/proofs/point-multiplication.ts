/**
 * Constant-time scalar multiplication for the proof engine
 *
 * A proof calculates sums of products `s_1*P_1 + ... + s_n*P_n`, and a
 * scalar can be secret: a proof nonce, a witness, or a server key. One
 * multiscalar multiplication calculates such a sum with two methods:
 *
 * - A generator table. A constant generator keeps a table of its multiples
 *   for each window of the scalar, so a product on it needs no doublings. The
 *   generator also keeps its encoding, which a proof transcript reads.
 * - Straus's method for the other points. Their products share one series of
 *   doublings.
 *
 * Both methods are constant time in the same way as noble's `fixedWindowCT`,
 * which `multiply` uses for a point without a table: the sequence of point
 * operations does not depend on the scalars, no array index is a scalar
 * digit, and the select of a table entry reads all of the table. They do not
 * use noble's precomputed tables: that path branches on each digit to add to
 * a real or a fake sum.
 */

import { RistrettoPoint } from './sho';
export {};

/** The stored encoding of each constant generator, and of the base point. */
const generatorEncodings = new WeakMap<RistrettoPoint, Uint8Array>([
  [RistrettoPoint.BASE, RistrettoPoint.BASE.toBytes()],
]);

/**
 * The table of each constant generator, and of the base point. The value is
 * null until the first multiplication builds the table.
 */
const generatorTables = new WeakMap<RistrettoPoint, RistrettoPoint[][] | null>([
  [RistrettoPoint.BASE, null],
]);

/** Bits of the largest scalar, which is the group order minus 1. */
const SCALAR_BITS = RistrettoPoint.Fn.ORDER.toString(2).length;

/** Bits of scalar that one window of a generator table reads. */
const GENERATOR_WINDOW = 5;
const GENERATOR_TABLE_SIZE = 1 << GENERATOR_WINDOW;
const GENERATOR_DIGIT_MASK = BigInt(GENERATOR_TABLE_SIZE - 1);
/** 51 windows of 5 bits read 255 bits, which include each scalar below the group order. */
const GENERATOR_WINDOWS = Math.ceil(SCALAR_BITS / GENERATOR_WINDOW);

/** Bits of scalar that one window of Straus's method reads. */
const MULTISCALAR_WINDOW = 4;
const MULTISCALAR_TABLE_SIZE = 1 << MULTISCALAR_WINDOW;
const MULTISCALAR_DIGIT_MASK = BigInt(MULTISCALAR_TABLE_SIZE - 1);
/** 64 windows of 4 bits read 256 bits, which include each scalar below the group order. */
const MULTISCALAR_WINDOWS = Math.ceil(SCALAR_BITS / MULTISCALAR_WINDOW);

/**
 * Give a constant generator, such as a system parameter, a table and a stored
 * encoding. Use it only for a point that stays in use for the life of the
 * process. The first multiplication on the point builds its table, which
 * holds 51 x 32 points, about 0.5 MB of heap in Node. After that, a product
 * on the point costs about a fifth of an untabled product.
 *
 * @returns The same point.
 */
export function withGeneratorTable(point: RistrettoPoint): RistrettoPoint {
  generatorEncodings.set(point, point.toBytes());
  if (!generatorTables.has(point)) generatorTables.set(point, null);
  return point;
}

/**
 * Encode `point` as 32 bytes. A generator gives a copy of its stored encoding.
 * Other points calculate their encoding.
 */
export function encodePoint(point: RistrettoPoint): Uint8Array {
  return generatorEncodings.get(point)?.slice() ?? point.toBytes();
}

/**
 * Calculate `scalars[0]*points[0] + ... + scalars[n-1]*points[n-1]` in constant time.
 *
 * A point with a generator table adds one table entry for each 5-bit window
 * of its scalar. The other points use Straus's method with fixed 4-bit
 * windows: each point gets a table of its multiples 0 to 15, and for each
 * window, from the most significant, the sum doubles 4 times, then adds one
 * table entry for each point. An add occurs also for a zero digit.
 *
 * Each scalar must be in the range 1 to the group order minus 1, the same
 * range that `multiply` accepts.
 *
 * @throws RangeError when a scalar is out of range.
 */
export function multiscalarMultiply(
  scalars: readonly bigint[],
  points: readonly RistrettoPoint[]
): RistrettoPoint {
  if (scalars.length !== points.length) {
    throw new Error('multiscalarMultiply: scalars and points differ in length');
  }
  for (const scalar of scalars) {
    if (scalar < 1n || scalar >= RistrettoPoint.Fn.ORDER) {
      throw new RangeError('invalid scalar: expected 1 <= sc < curve.n');
    }
  }

  // The split depends only on the points, which are public.
  let sum = RistrettoPoint.ZERO;
  const otherScalars: bigint[] = [];
  const otherPoints: RistrettoPoint[] = [];
  for (let j = 0; j < points.length; j++) {
    const table = generatorTable(points[j]);
    if (table === undefined) {
      otherScalars.push(scalars[j]);
      otherPoints.push(points[j]);
      continue;
    }
    for (let window = 0; window < GENERATOR_WINDOWS; window++) {
      const shift = BigInt(window * GENERATOR_WINDOW);
      const digit = Number((scalars[j] >> shift) & GENERATOR_DIGIT_MASK);
      sum = sum.add(selectEntry(table[window], digit));
    }
  }
  if (otherPoints.length > 0) sum = sum.add(strausMultiply(otherScalars, otherPoints));
  return sum;
}

/** Give the table of a generator, and build it at the first use. */
function generatorTable(point: RistrettoPoint): RistrettoPoint[][] | undefined {
  const table = generatorTables.get(point);
  if (table !== null) return table;
  // Window w holds i * 32^w * point for i from 0 to 31.
  const built: RistrettoPoint[][] = [];
  let base = point;
  for (let window = 0; window < GENERATOR_WINDOWS; window++) {
    const entries = [RistrettoPoint.ZERO];
    for (let i = 1; i < GENERATOR_TABLE_SIZE; i++) entries.push(entries[i - 1].add(base));
    built.push(entries);
    base = entries[GENERATOR_TABLE_SIZE - 1].add(base);
  }
  generatorTables.set(point, built);
  return built;
}

/** Straus's method with fixed 4-bit windows. */
function strausMultiply(scalars: bigint[], points: RistrettoPoint[]): RistrettoPoint {
  const zero = RistrettoPoint.ZERO;
  const tables = points.map((point) => {
    const table: RistrettoPoint[] = [zero];
    for (let i = 1; i < MULTISCALAR_TABLE_SIZE; i++) {
      table.push(table[i - 1].add(point));
    }
    return table;
  });

  let sum = zero;
  for (let window = MULTISCALAR_WINDOWS - 1; window >= 0; window--) {
    // The first window skips the doublings: the sum is still zero. The skip
    // depends only on the loop index.
    if (window !== MULTISCALAR_WINDOWS - 1) {
      for (let d = 0; d < MULTISCALAR_WINDOW; d++) sum = sum.double();
    }
    const shift = BigInt(window * MULTISCALAR_WINDOW);
    for (let j = 0; j < tables.length; j++) {
      const digit = Number((scalars[j] >> shift) & MULTISCALAR_DIGIT_MASK);
      sum = sum.add(selectEntry(tables[j], digit));
    }
  }
  return sum;
}

/** Data-oblivious select: read each entry of the table, and use no digit as an index. */
function selectEntry(table: readonly RistrettoPoint[], digit: number): RistrettoPoint {
  let entry = table[0];
  for (let i = 1; i < table.length; i++) entry = i === digit ? table[i] : entry;
  return entry;
}
