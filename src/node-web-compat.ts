/* eslint-disable @typescript-eslint/no-var-requires */

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
    return typeof window !== undefined && typeof window.document !== undefined;
  } catch {
    return false;
  }
})();

export let createVerify: (algorithm: string) => {
  update: (payload: string) => {
    verify: (
      keyObject: KeyObject,
      signature: string,
      encoding: "base64"
    ) => boolean;
  };
};

export let createPublicKey: (_: {
  key: Uint8Array;
  format: "der";
  type: "spki";
}) => KeyObject;

export type KeyObject = {
  export: (_: { format: "der"; type: "spki" }) => unknown;
};

export let join: (...segments: string[]) => string;

export let concatUint8Arrays: (...arrays: Uint8Array[]) => Uint8Array;
export let numberFromUint8ArrayBE: (_: Uint8Array, length: number) => number;
export let uint8ArrayFromString: (_: string, encoding: "base64") => Uint8Array;

if (runningInNode) {
  ({ createVerify, createPublicKey } = require("crypto"));
  ({ join } = require("path"));
  concatUint8Arrays = (...arrays) => Buffer.concat(arrays);
  numberFromUint8ArrayBE = (uint8Array, length) =>
    Buffer.from(uint8Array).readUIntBE(0, length);
  uint8ArrayFromString = (uint8Array, encoding) =>
    Buffer.from(uint8Array, encoding);
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
  throw new Error("Not implemented");
} else {
  throw new Error(
    "Unknown environment: only Node.js and Browser are supported"
  );
}
