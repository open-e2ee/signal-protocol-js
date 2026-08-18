/**
 * Polynomial Operations over Galois Fields
 *
 * Implements polynomial representation and operations for Reed-Solomon
 * systematic encoding. A polynomial takes the form of an array of coefficients
 * where coefficients[i] is the coefficient of x^i.
 *
 * @module rs/polynomial
 * @see BBC WHP-031 Section 4
 */

import type { GaloisField } from './galois';

/**
 * Polynomial over a Galois field
 *
 * Coefficients sit in ascending order: [c0, c1, c2, ...] represents
 * c0 + c1*x + c2*x^2 + ...
 *
 * All arithmetic runs in the associated Galois field.
 */
export {};
export class Polynomial {
  private readonly coeffs: number[];

  /**
   * Create a polynomial with given coefficients
   *
   * @param coefficients - Array of field elements [c0, c1, c2, ...] for c0 + c1*x + c2*x^2 + ...
   * @param field - Galois field for arithmetic operations
   */
  constructor(
    coefficients: number[],
    private readonly field: GaloisField
  ) {
    // Remove trailing zeros to normalize representation
    this.coeffs = this.normalize(coefficients);
  }

  /**
   * Remove trailing zero coefficients
   */
  private normalize(coeffs: number[]): number[] {
    let len = coeffs.length;
    while (len > 1 && coeffs[len - 1] === 0) {
      len--;
    }
    return coeffs.slice(0, len);
  }

  /**
   * Get polynomial coefficients
   */
  get coefficients(): readonly number[] {
    return this.coeffs;
  }

  /**
   * Get polynomial degree
   * Returns -1 for zero polynomial
   */
  get degree(): number {
    if (this.coeffs.length === 1 && this.coeffs[0] === 0) {
      return -1;
    }
    return this.coeffs.length - 1;
  }

  /**
   * Check if polynomial is zero
   */
  isZero(): boolean {
    return this.coeffs.length === 1 && this.coeffs[0] === 0;
  }

  /**
   * Get coefficient at given degree
   */
  at(degree: number): number {
    if (degree < 0 || degree >= this.coeffs.length) {
      return 0;
    }
    return this.coeffs[degree];
  }

  /**
   * Evaluate polynomial at point x using Horner's method
   *
   * f(x) = c0 + c1*x + c2*x^2 + ... + cn*x^n
   *      = c0 + x*(c1 + x*(c2 + ... + x*cn))
   *
   * @param x - Field element to evaluate at
   * @returns f(x) as a field element
   */
  evaluate(x: number): number {
    if (this.coeffs.length === 0) {
      return 0;
    }

    // Horner's method: evaluate from highest degree down
    let result = this.coeffs[this.coeffs.length - 1];
    for (let i = this.coeffs.length - 2; i >= 0; i--) {
      result = this.field.add(this.field.mul(result, x), this.coeffs[i]);
    }
    return result;
  }

  /**
   * Add two polynomials
   *
   * In GF(2^n), addition is XOR at each coefficient
   */
  add(other: Polynomial): Polynomial {
    const maxLen = Math.max(this.coeffs.length, other.coeffs.length);
    const result = new Array(maxLen);

    for (let i = 0; i < maxLen; i++) {
      const a = i < this.coeffs.length ? this.coeffs[i] : 0;
      const b = i < other.coeffs.length ? other.coeffs[i] : 0;
      result[i] = this.field.add(a, b);
    }

    return new Polynomial(result, this.field);
  }

  /**
   * Subtract two polynomials
   *
   * In GF(2^n), subtraction is identical to addition (XOR)
   */
  subtract(other: Polynomial): Polynomial {
    return this.add(other);
  }

  /**
   * Multiply two polynomials
   *
   * Standard polynomial multiplication with field arithmetic
   */
  multiply(other: Polynomial): Polynomial {
    if (this.isZero() || other.isZero()) {
      return new Polynomial([0], this.field);
    }

    const result = new Array(this.coeffs.length + other.coeffs.length - 1).fill(0);

    for (let i = 0; i < this.coeffs.length; i++) {
      if (this.coeffs[i] === 0) continue;

      for (let j = 0; j < other.coeffs.length; j++) {
        if (other.coeffs[j] === 0) continue;

        const product = this.field.mul(this.coeffs[i], other.coeffs[j]);
        result[i + j] = this.field.add(result[i + j], product);
      }
    }

    return new Polynomial(result, this.field);
  }

  /**
   * Multiply polynomial by a scalar
   */
  scale(scalar: number): Polynomial {
    if (scalar === 0) {
      return new Polynomial([0], this.field);
    }

    const result = this.coeffs.map((c) => this.field.mul(c, scalar));
    return new Polynomial(result, this.field);
  }

  /**
   * Divide two polynomials, returning quotient and remainder
   *
   * Uses polynomial long division in the field.
   *
   * @returns [quotient, remainder] such that this = quotient * other + remainder
   */
  divmod(other: Polynomial): [Polynomial, Polynomial] {
    if (other.isZero()) {
      throw new Error('Division by zero polynomial');
    }

    if (this.degree < other.degree) {
      return [new Polynomial([0], this.field), this];
    }

    // Copy coefficients for in-place modification
    const remainder = [...this.coeffs];
    const divisorLeadCoeff = other.coeffs[other.coeffs.length - 1];
    const quotientLen = this.coeffs.length - other.coeffs.length + 1;
    const quotient = new Array(quotientLen).fill(0);

    for (let i = quotientLen - 1; i >= 0; i--) {
      const remainderIdx = i + other.coeffs.length - 1;
      if (remainder[remainderIdx] === 0) continue;

      const coeff = this.field.div(remainder[remainderIdx], divisorLeadCoeff);
      quotient[i] = coeff;

      // Subtract coeff * other from remainder (subtraction = addition in GF(2^n))
      for (let j = 0; j < other.coeffs.length; j++) {
        const product = this.field.mul(coeff, other.coeffs[j]);
        remainder[i + j] = this.field.add(remainder[i + j], product);
      }
    }

    return [
      new Polynomial(quotient, this.field),
      new Polynomial(remainder.slice(0, other.coeffs.length - 1), this.field),
    ];
  }

  /**
   * Create string representation
   */
  toString(): string {
    if (this.isZero()) {
      return '0';
    }

    const terms: string[] = [];
    for (let i = this.coeffs.length - 1; i >= 0; i--) {
      if (this.coeffs[i] === 0) continue;

      if (i === 0) {
        terms.push(`${this.coeffs[i]}`);
      } else if (i === 1) {
        terms.push(this.coeffs[i] === 1 ? 'x' : `${this.coeffs[i]}x`);
      } else {
        terms.push(this.coeffs[i] === 1 ? `x^${i}` : `${this.coeffs[i]}x^${i}`);
      }
    }

    return terms.length > 0 ? terms.join(' + ') : '0';
  }
}
