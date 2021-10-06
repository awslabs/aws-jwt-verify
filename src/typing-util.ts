// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Utilities for creating special TypeScript types

/**
 * Type that returns the list of fields in Base, that are not part of Provided
 *
 * @param Base The base object
 * @param Provided The object whose fields should be omitted from the field list of base
 */
export type StillToProvideVerifyKeys<Base, Provided> = keyof Omit<
  Base,
  keyof Provided
>;

/**
 * Type that returns the Base type, with only those properties, that are not part of Provided
 *
 * @param Base The base object
 * @param Provided The object whose fields should be omitted from base
 */
export type StillToProvideVerifyProps<Base, Provided> = {
  [key in StillToProvideVerifyKeys<Base, Provided>]: Base[key];
};

/**
 * Type that returns all optional fields of the input type
 *
 * @param T The type to extract optional fields from
 */
export type ExtractOptionalFields<T> = {
  [P in keyof T]-?: undefined extends T[P] ? P : never;
}[keyof T];

/**
 * Type that is similar to the input type, but only contains its mandatory properties
 *
 * @param T The type to return without optional fields
 */
export type WithoutOptionalFields<T> = Omit<T, ExtractOptionalFields<T>>;
