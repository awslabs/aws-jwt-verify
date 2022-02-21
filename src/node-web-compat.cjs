"use strict";
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Compatibility layer, to make this lib work in both Node.js and Web
/* eslint-disable @typescript-eslint/no-var-requires */

Object.defineProperty(exports, "__esModule", { value: true });
const concatUint8Arrays = (...arrays) => Buffer.concat(arrays);
const numberFromUint8ArrayBE = (uint8Array, length) =>
  Buffer.from(uint8Array).readUIntBE(0, length);
const uint8ArrayFromString = (uint8Array, encoding) =>
  Buffer.from(uint8Array, encoding);
const { createVerify, createPublicKey } = require("crypto");
const { join } = require("path");
const { fetchJson } = require("./https-node.js");

module.exports = {
  concatUint8Arrays,
  numberFromUint8ArrayBE,
  uint8ArrayFromString,
  createVerify,
  createPublicKey,
  join,
  fetchJson,
};
