import {
  assertStringEquals,
  assertStringArrayContainsString,
  assertStringArraysOverlap,
} from "../../src/assert";

class AssertionError extends Error {}

describe("unit tests assert", () => {
  test("assert equals requires non-empty value", () => {
    const statement = () =>
      assertStringEquals(AssertionError, "test", "", "two");
    expect(statement).toThrow(AssertionError);
    expect(statement).toThrow("Missing test. Expected: two");
  });

  test("assert equals requires strings", () => {
    const statement = () =>
      assertStringEquals(AssertionError, "test", 123 as any, "two");
    expect(statement).toThrow(AssertionError);
    expect(statement).toThrow("test is not of type string");
  });

  test("assert contains requires strings", () => {
    const statement = () =>
      assertStringArrayContainsString(AssertionError, "test", 123 as any, [
        "two",
      ]);
    expect(statement).toThrow(AssertionError);
    expect(statement).toThrow("test is not of type string");
  });

  test("assert overlaps requires array", () => {
    const statement = () =>
      assertStringArraysOverlap(AssertionError, "test", 123 as any, ["two"]);
    expect(statement).toThrow(AssertionError);
    expect(statement).toThrow("test is not an array");
  });

  test("assert overlaps requires array of strings", () => {
    const statement = () =>
      assertStringArraysOverlap(AssertionError, "test", [123 as any], ["two"]);
    expect(statement).toThrow(AssertionError);
    expect(statement).toThrow(
      "test includes elements that are not of type string"
    );
  });
});
