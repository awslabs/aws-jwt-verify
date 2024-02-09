import {
  constructPublicKeyInDerFormat,
  deconstructPublicKeyInDerFormat,
} from "../../src/asn1";
import { Asn1DecodingError } from "../../src/error";
import { readFileSync } from "fs";
import { join } from "path";
import { generateKeyPair } from "./test-util";

describe("unit tests asn1", () => {
  test("Construct and deconstruct are eachothers inverse", () => {
    const n = Buffer.from("SOMEVEEEEEEEEEEEEEEEEEEERYLONGMODULUS");
    const e = Buffer.from("SOMEVEEEEEEEEEEEEEEEEEEERYLONGEXPONENT");
    const publicKey = constructPublicKeyInDerFormat(n, e);
    const { n: nCheck, e: eCheck } = deconstructPublicKeyInDerFormat(publicKey);
    expect(n).toEqual(nCheck);
    expect(e).toEqual(eCheck);
  });

  test("Constructing public key works", () => {
    const priorGeneratedPublicKey = readFileSync(
      join(__dirname, "pubkey-test.der")
    );
    const n = Buffer.from(
      "00BB1C23F80CC5EFB81F76C24F920D4D192331E36CC2C82EEEE1E8DBC7B4C7784886156D4E2D754F8B4913435408BB238CD3672DA6937816716E3B2387AA526E69C8D6AD7D193BA8E56FB0A80B04F5F72EF78DB589EC43AD561E9BD9B10BE98DC5A27EB094FB9E8424B53DEB5C28A0F91A92871636758A6F0FF0463F2683F710F40B14C551AB20A69ACDC2FD002E79A2E1DF3CA1DA8229FAFFBEC85EF7D02E55A482B014D237D5D78BE4791AAF5904436D77D7E7B34C52F348345B7D97CEDDA9623BAE9A6311AC299B704CE14DA682413707E4BD2B023CC1A20067E396DD6BEBD9060D943898A120BF77A2A1438C34475A3D8C84A99A49521E21C0B1D5BD9A4C0DC8FB75942659EC781DBD0032D981CE27A808AADCCF9D584728228314176D547E47B67DE4D73326F474F4230E0829A359769FE0FDEC3A13532925CB60897005020F41BB3105D418C9C3D29DC2852538037F151DF1EB8CBC662AB085F6B7560B345A5E56D97CF2C9ED09D6F8146FA7E0817D439B1135845A1958CDC3043925F2642AFF82E7E9FE7BDCEF1CF706A780DC8B3CEFCF93DBFD71C1B7CA574738BAB83F19A7AF5939D7CE494B73014DC59BDE35261704CFC6F764A550F5F5F4866989143C50C2FF76321506087D6B98F637BFE34F87C4198AE9F8D4EB7A17D914340B63500B33DA6EA70B50E88E88FD51FF5CC3C4507FFA11513A364CB3AB5FFC6E5407",
      "hex"
    );
    const e = Buffer.from("AQAB", "base64");
    const publicKey = constructPublicKeyInDerFormat(n, e);
    expect(publicKey).toEqual(priorGeneratedPublicKey);
  });

  test("Prepends 0 byte only if MSB is 1", () => {
    const n = Buffer.from([0b10000000]); // MSB 1
    const e = Buffer.from([0b01000000]); // MSB 0
    const publicKeyDer = constructPublicKeyInDerFormat(n, e);
    expect(publicKeyDer).toEqual(
      Buffer.from([
        48,
        27,
        48,
        13,
        6,
        9,
        42,
        134,
        72,
        134,
        247,
        13,
        1,
        1,
        1,
        5,
        0,
        3,
        10,
        0,
        48,
        7,
        2,
        2,
        0, // here is the leading 0
        128, // prepended with leading 0
        2,
        1,
        64, // not prepended with leading 0
      ])
    );
  });

  test("Deconstructing public key works", () => {
    const priorGeneratedPublicKey = readFileSync(
      join(__dirname, "pubkey-test.der")
    );
    const { n, e } = deconstructPublicKeyInDerFormat(priorGeneratedPublicKey);
    expect(n).toEqual(
      Buffer.from(
        "00BB1C23F80CC5EFB81F76C24F920D4D192331E36CC2C82EEEE1E8DBC7B4C7784886156D4E2D754F8B4913435408BB238CD3672DA6937816716E3B2387AA526E69C8D6AD7D193BA8E56FB0A80B04F5F72EF78DB589EC43AD561E9BD9B10BE98DC5A27EB094FB9E8424B53DEB5C28A0F91A92871636758A6F0FF0463F2683F710F40B14C551AB20A69ACDC2FD002E79A2E1DF3CA1DA8229FAFFBEC85EF7D02E55A482B014D237D5D78BE4791AAF5904436D77D7E7B34C52F348345B7D97CEDDA9623BAE9A6311AC299B704CE14DA682413707E4BD2B023CC1A20067E396DD6BEBD9060D943898A120BF77A2A1438C34475A3D8C84A99A49521E21C0B1D5BD9A4C0DC8FB75942659EC781DBD0032D981CE27A808AADCCF9D584728228314176D547E47B67DE4D73326F474F4230E0829A359769FE0FDEC3A13532925CB60897005020F41BB3105D418C9C3D29DC2852538037F151DF1EB8CBC662AB085F6B7560B345A5E56D97CF2C9ED09D6F8146FA7E0817D439B1135845A1958CDC3043925F2642AFF82E7E9FE7BDCEF1CF706A780DC8B3CEFCF93DBFD71C1B7CA574738BAB83F19A7AF5939D7CE494B73014DC59BDE35261704CFC6F764A550F5F5F4866989143C50C2FF76321506087D6B98F637BFE34F87C4198AE9F8D4EB7A17D914340B63500B33DA6EA70B50E88E88FD51FF5CC3C4507FFA11513A364CB3AB5FFC6E5407",
        "hex"
      )
    );
    expect(e).toEqual(Buffer.from("AQAB", "base64"));
  });

  test("decode corrupt pubkey", () => {
    expect(() =>
      deconstructPublicKeyInDerFormat(Buffer.from("foobar"))
    ).toThrow(Asn1DecodingError);
  });

  test("decode identifier with tag > 30", () => {
    expect(() => deconstructPublicKeyInDerFormat(Buffer.from([255]))).toThrow(
      Asn1DecodingError
    );
  });
});

describe("speed tests asn1", () => {
  test("Constructing public key from n and e runs within 0.05 milliseconds", () => {
    const keypair = generateKeyPair();
    const maxAllowedDurationMilliSecs = 0.05; // 50 microseconds
    const testCount = 10000;
    const start = Date.now();
    for (let i = 0; i < testCount; i++) {
      constructPublicKeyInDerFormat(keypair.nBuffer, keypair.eBuffer);
    }
    expect(Date.now() - start).toBeLessThanOrEqual(
      testCount * maxAllowedDurationMilliSecs
    );
  });
});
