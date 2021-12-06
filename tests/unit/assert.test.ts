import { FailedAssertionError } from "../../src/error";
import {
  assertStringEquals,
  assertStringArrayContainsString,
  assertStringArraysOverlap,
} from "../../src/assert";

class CustomError extends FailedAssertionError {}

describe("unit tests assert", () => {
  test("assert equals requires non-empty value", () => {
    const actual = "";
    const expected = "two";
    const statement = () => assertStringEquals("Test", actual, expected);
    expect.assertions(3);
    expect(statement).toThrow(FailedAssertionError);
    expect(statement).toThrow("Missing Test. Expected: two");
    try {
      statement();
    } catch (err) {
      if (err instanceof FailedAssertionError) {
        expect(err.failedAssertion).toMatchObject({
          actual,
          expected,
        });
      }
    }
  });

  test("assert equals requires strings", () => {
    const actual = 123 as any;
    const expected = "two";
    const statement = () =>
      assertStringEquals("Test", actual, expected, CustomError);
    expect.assertions(3);
    expect(statement).toThrow(CustomError);
    expect(statement).toThrow("Test is not of type string");
    try {
      statement();
    } catch (err) {
      if (err instanceof CustomError) {
        expect(err.failedAssertion).toMatchObject({
          actual,
          expected,
        });
      }
    }
  });

  test("assert contains requires strings", () => {
    const statement = () =>
      assertStringArrayContainsString("Test", 123 as any, ["two"], CustomError);
    expect(statement).toThrow(CustomError);
    expect(statement).toThrow("Test is not of type string");
  });

  test("assert contains requires strings - with default error", () => {
    const statement = () =>
      assertStringArrayContainsString("Test", 123 as any, ["two"]);
    expect(statement).toThrow(FailedAssertionError);
    expect(statement).toThrow("Test is not of type string");
  });

  test("assert overlaps requires array", () => {
    const statement = () =>
      assertStringArraysOverlap("Test", 123 as any, ["two"], CustomError);
    expect(statement).toThrow(CustomError);
    expect(statement).toThrow("Test is not an array");
  });

  test("assert overlaps requires array of strings", () => {
    const statement = () =>
      assertStringArraysOverlap("Test", [123 as any], ["two"], CustomError);
    expect(statement).toThrow(CustomError);
    expect(statement).toThrow(
      "Test includes elements that are not of type string"
    );
  });

  test("assert overlaps requires array of strings - with default error", () => {
    const statement = () =>
      assertStringArraysOverlap("Test", [123 as any], ["two"]);
    expect(statement).toThrow(FailedAssertionError);
    expect(statement).toThrow(
      "Test includes elements that are not of type string"
    );
  });
});
