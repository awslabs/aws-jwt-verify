// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Utility to parse JSON safely

/** JSON type */
export type Json = null | string | number | boolean | Json[] | JsonObject;

/** JSON Object type */
export type JsonObject = { [name: string]: Json };

/**
 * Check if a piece of JSON is a JSON object, and not e.g. a mere string or null
 *
 * @param j - the JSON
 */
export function isJsonObject(j: Json): j is JsonObject {
  // It is not enough to check that `typeof j === "object"`
  // because in JS `typeof null` is also "object", and so is `typeof []`.
  // So we need to check that j is an object, and not null, and not an array
  return typeof j === "object" && !Array.isArray(j) && j !== null;
}

/**
 * Parse a string as JSON, while removing __proto__ and constructor, so JS prototype pollution is prevented
 *
 * @param s - the string to JSON parse
 */
export function safeJsonParse(s: string): Json {
  return JSON.parse(s, (_, value) => {
    if (typeof value === "object" && !Array.isArray(value) && value !== null) {
      delete value.__proto__;
      delete value.constructor;
    }
    return value;
  });
}
