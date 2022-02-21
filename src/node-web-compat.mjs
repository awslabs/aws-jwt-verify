// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Compatibility layer, to make this lib work in both Node.js and Web

const runningInNode = (function () {
  try {
    return (
      typeof process !== undefined &&
      process.versions != null &&
      process.versions.node != null
    );
  } catch {
    return false;
  }
})();
const runningInBrowser = (function () {
  try {
    // eslint-disable-next-line no-undef
    return typeof window !== undefined && typeof window.document !== undefined;
  } catch {
    return false;
  }
})();

export let createVerify,
  createPublicKey,
  join,
  concatUint8Arrays,
  numberFromUint8ArrayBE,
  uint8ArrayFromB64String,
  fetchJson,
  utf8StringFromB64String;

if (runningInNode) {
  concatUint8Arrays = (...arrays) => Buffer.concat(arrays);
  numberFromUint8ArrayBE = (uint8Array, length) =>
    Buffer.from(uint8Array).readUIntBE(0, length);
  uint8ArrayFromB64String = (b64) => Buffer.from(b64, "base64");
  ({ createVerify, createPublicKey } = await import("crypto"));
  ({ join } = await import("path"));
  ({ fetchJson } = await import("./https-node.js"));
  utf8StringFromB64String = (b64) =>
    Buffer.from(b64, "base64").toString("utf8");
} else if (runningInBrowser) {
  concatUint8Arrays = (...arrays) => {
    const concatenatedLength = arrays.reduce(
      (length, array) => length + array.length,
      0
    );
    const concatenated = new Uint8Array(concatenatedLength);
    arrays.reduce((currentLength, array) => {
      concatenated.set(array, currentLength);
      return currentLength + array.length;
    }, 0);
    return concatenated;
  };
  fetchJson = (uri, requestOptions, data) =>
    // eslint-disable-next-line no-undef
    fetch(uri, { ...requestOptions, body: data }).then((res) => res.json());
  join = (args) => args.map((arg) => arg.replace("/$", "")).join("/");
  // eslint-disable-next-line no-undef
  utf8StringFromB64String = (b64) => window.atob(b64);
  uint8ArrayFromB64String = (b64) => {
    throw new Error("Not yet implemented");
  };
} else {
  throw new Error(
    "Unknown environment: only Node.js and Browser are supported"
  );
}
