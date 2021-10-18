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
type StillToProvideVerifyKeys<Base, Provided> = keyof Omit<
  Base,
  keyof Provided
>;

/**
 * Type that returns the Base type, with only those properties, that are not part of Provided
 *
 * @param Base The base object
 * @param Provided The object whose fields should be omitted from base
 */
type StillToProvideProperties<Base, Provided> = {
  [key in StillToProvideVerifyKeys<
    WithoutOptionalFields<Base>,
    WithoutOptionalFields<Provided>
  >]: Base[key];
};

/**
 * Type that returns all optional fields of the input type
 *
 * @param T The type to extract optional fields from
 */
type ExtractOptionalFields<T> = {
  [P in keyof T]-?: undefined extends T[P] ? P : never;
}[keyof T];

/**
 * Type that is similar to the input type, but only contains its mandatory properties
 *
 * @param T The type to return without optional fields
 */
type WithoutOptionalFields<T> = Omit<T, ExtractOptionalFields<T>>;

/**
 * Type that returns merged properties as follows:
 * - Properties in Base that are not in Provided, are mandatory
 * - Properties in Base that are in Provided, are optional
 */
export type Properties<Base, Provided> = StillToProvideProperties<
  Base,
  Provided
> &
  Partial<Base>;
