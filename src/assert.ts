// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Utilities to assert that supplied values match with expected values

import { AssertionError } from "./error.js";

/**
 * Assert value is a non-empty string and equal to the expected value,
 * or throw an error otherwise
 *
 * @param name - Name for the value being checked
 * @param actual - The value to check
 * @param expected - The expected value
 */
export function assertStringEquals(
  name: string,
  actual: unknown,
  expected: string
): void {
  if (!actual) {
    throw new AssertionError(`Missing ${name}. Expected: ${expected}`);
  }
  if (typeof actual !== "string") {
    throw new AssertionError(`${name} is not of type string`);
  }
  if (expected !== actual) {
    throw new AssertionError(
      `${name} not allowed: ${actual}. Expected: ${expected}`
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
 * a string here as well, which will mean an array with just that string
 */
export function assertStringArrayContainsString(
  name: string,
  actual: unknown,
  expected: string | string[]
): void {
  if (!actual) {
    throw new AssertionError(
      `Missing ${name}. ${expectationMessage(expected)}`
    );
  }
  if (typeof actual !== "string") {
    throw new AssertionError(`${name} is not of type string`);
  }
  return assertStringArraysOverlap(name, actual, expected);
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
 */
export function assertStringArraysOverlap(
  name: string,
  actual: unknown,
  expected: string | string[]
): void {
  if (!actual) {
    throw new AssertionError(
      `Missing ${name}. ${expectationMessage(expected)}`
    );
  }
  const expectedAsSet = new Set(
    Array.isArray(expected) ? expected : [expected]
  );
  if (typeof actual === "string") {
    actual = [actual];
  }
  if (!Array.isArray(actual)) {
    throw new AssertionError(`${name} is not an array`);
  }
  const overlaps = actual.some((actualItem) => {
    if (typeof actualItem !== "string") {
      throw new AssertionError(
        `${name} includes elements that are not of type string`
      );
    }
    return expectedAsSet.has(actualItem);
  });
  if (!overlaps) {
    throw new AssertionError(
      `${name} not allowed: ${actual.join(", ")}. ${expectationMessage(
        expected
      )}`
    );
  }
}

/**
 * Get a nicely readable message regarding an expectation
 *
 * @param expected - The expected value.
 */
function expectationMessage(expected: string | string[]) {
  if (Array.isArray(expected)) {
    if (expected.length > 1) {
      return `Expected one of: ${expected.join(", ")}`;
    }
    return `Expected: ${expected[0]}`;
  }
  return `Expected: ${expected}`;
}
