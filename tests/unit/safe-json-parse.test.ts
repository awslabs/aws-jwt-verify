import { safeJsonParse, JsonObject } from "../../src/safe-json-parse";

describe("unit tests safe JSON parse", () => {
  test("safeJsonParse works like JSON parse", () => {
    const stringified = JSON.stringify({ hello: "world" });
    expect(JSON.stringify(JSON.parse(stringified))).toEqual(
      JSON.stringify(safeJsonParse(stringified))
    );
  });

  test("safeJsonParse removes __proto__ and constructor", () => {
    const stringified = `{
      "hello": "world",
      "__proto__": { "isAdmin": true },
      "constructor": "foo",
      "nested": {
        "__proto__": { "isAdmin": true },
        "constructor": "bar",
        "test": "value"
      }
    }`;
    expect(JSON.stringify(safeJsonParse(stringified))).toEqual(
      `{"hello":"world","nested":{"test":"value"}}`
    );
  });

  test("safeJsonParse prevents prototype pollution", () => {
    const danger = '{"__proto__":{"danger":true}}';
    const parsed = safeJsonParse(danger) as JsonObject;
    expect(parsed.danger).toEqual(undefined);
    const oops = Object.assign({}, parsed);
    expect(oops.danger).toEqual(undefined); // If we had used JSON.parse on danger this would now be true
  });
});
