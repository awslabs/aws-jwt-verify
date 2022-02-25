// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Utilities to assert that supplied values match with expected values

import { AssertionErrorConstructor, FailedAssertionError } from "./error.js";

/**
 * Assert value is a non-empty string and equal to the expected value,
 * or throw an error otherwise
 *
 * @param name - Name for the value being checked
 * @param actual - The value to check
 * @param expected - The expected value
 * @param errorConstructor - Constructor for the concrete error to be thrown
 */
export function assertStringEquals<T extends string>(
  name: string,
  actual: unknown,
  expected: T,
  errorConstructor: AssertionErrorConstructor = FailedAssertionError
): asserts actual is T {
  if (!actual) {
    throw new errorConstructor(
      `Missing ${name}. Expected: ${expected}`,
      actual,
      expected
    );
  }
  if (typeof actual !== "string") {
    throw new errorConstructor(
      `${name} is not of type string`,
      actual,
      expected
    );
  }
  if (expected !== actual) {
    throw new errorConstructor(
      `${name} not allowed: ${actual}. Expected: ${expected}`,
      actual,
      expected
    );
  }
}

/**
 * Assert value is a non-empty string and is indeed one of the expected values,
 * or throw an error otherwise
 *
 * @param name - Name for the value being checked
 * @param actual - The value to check
 * @param expected - The array of expected values. For your convenience you can provide
 * @param errorConstructor - Constructor for the concrete error to be thrown
 * a string here as well, which will mean an array with just that string
 */
export function assertStringArrayContainsString<
  T extends string | Readonly<string[]>
>(
  name: string,
  actual: unknown,
  expected: T,
  errorConstructor: AssertionErrorConstructor = FailedAssertionError
): asserts actual is T extends Readonly<string[]> ? T[number] : T {
  if (!actual) {
    throw new errorConstructor(
      `Missing ${name}. ${expectationMessage(expected)}`,

      actual,
      expected
    );
  }
  if (typeof actual !== "string") {
    throw new errorConstructor(
      `${name} is not of type string`,

      actual,
      expected
    );
  }
  return assertStringArraysOverlap(name, actual, expected, errorConstructor);
}

/**
 * Assert value is an array of strings, where at least one of the strings is indeed one of the expected values,
 * or throw an error otherwise
 *
 * @param name - Name for the value being checked
 * @param actual - The value to check, must be an array of strings, or a single string (which will be treated
 * as an array with just that string)
 * @param expected - The array of expected values. For your convenience you can provide
 * a string here as well, which will mean an array with just that string
 * @param errorConstructor - Constructor for the concrete error to be thrown
 */
export function assertStringArraysOverlap(
  name: string,
  actual: unknown,
  expected: string | Readonly<string[]>,
  errorConstructor: AssertionErrorConstructor = FailedAssertionError
): asserts actual is string | Readonly<string[]> {
  if (!actual) {
    throw new errorConstructor(
      `Missing ${name}. ${expectationMessage(expected)}`,
      actual,
      expected
    );
  }
  const expectedAsSet = new Set(
    Array.isArray(expected) ? expected : [expected]
  );
  if (typeof actual === "string") {
    actual = [actual];
  }
  if (!Array.isArray(actual)) {
    throw new errorConstructor(`${name} is not an array`, actual, expected);
  }
  const overlaps = actual.some((actualItem) => {
    if (typeof actualItem !== "string") {
      throw new errorConstructor(
        `${name} includes elements that are not of type string`,
        actual,
        expected
      );
    }
    return expectedAsSet.has(actualItem);
  });
  if (!overlaps) {
    throw new errorConstructor(
      `${name} not allowed: ${actual.join(", ")}. ${expectationMessage(
        expected
      )}`,
      actual,
      expected
    );
  }
}

/**
 * Get a nicely readable message regarding an expectation
 *
 * @param expected - The expected value.
 */
function expectationMessage(expected: string | Readonly<string[]>) {
  if (Array.isArray(expected)) {
    if (expected.length > 1) {
      return `Expected one of: ${expected.join(", ")}`;
    }
    return `Expected: ${expected[0]}`;
  }
  return `Expected: ${expected}`;
}

/**
 * Assert value is not a promise, or throw an error otherwise
 *
 * @param actual - The value to check
 * @param errorFactory - Function that returns the error to be thrown
 */
export function assertIsNotPromise(
  actual: unknown,
  errorFactory: () => Error
): void {
  if (actual && typeof (actual as { then?: unknown }).then === "function") {
    throw errorFactory();
  }
}
