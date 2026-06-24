// Interop test — the TS SDK must unwrap / decrypt / verify the canonical .mjs golden vectors
// byte-for-byte. The fixtures are emitted by ce-secrets (the canonical JavaScript impl); if any
// of the five interop traps drifts, one of these assertions fails.

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import {
  unwrapMaster,
  decryptSecret,
  deviceId,
  verifyRecord,
  hex,
  utf8,
} from "../src/index.js";
import { makeNonce, checkNonce, verifyAuth } from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const vectorsPath = resolve(here, "../../ce-secrets/fixtures/vectors.json");
const V = JSON.parse(readFileSync(vectorsPath, "utf8"));

describe("interop with canonical .mjs golden vectors", () => {
  it("derives the same deviceId (sha256 of the 4-element JWK-coordinate array)", async () => {
    const id = await deviceId(V.device.ecdhPub, V.device.ecdsaPub);
    expect(id).toBe(V.device.deviceId);
    // Pin the exact pre-image string the .mjs hashes.
    const preimage = JSON.stringify([
      V.device.ecdhPub.x,
      V.device.ecdhPub.y,
      V.device.ecdsaPub.x,
      V.device.ecdsaPub.y,
    ]);
    expect(preimage).toBe(V.device.deviceIdInput);
  });

  it("unwraps the ECIES-wrapped master key (trap 1: HKDF empty salt + exact info)", async () => {
    const master = await unwrapMaster(V.masterWrap.wrapped, V.masterWrap.recipientEcdhPriv);
    expect(hex.enc(master)).toBe(V.masterWrap.expectMasterHex);
  });

  it("decrypts a secret sealed under the master (trap 2: AES-GCM 12-byte nonce)", async () => {
    const master = hex.dec(V.secret.masterHex);
    const pt = await decryptSecret(master, V.secret.sealed);
    expect(utf8.dec(pt)).toBe(V.secret.expectPlaintext);
    expect(hex.enc(pt)).toBe(V.secret.plaintextHex);
  });

  it("verifies the auth signature (traps 3+4+5: raw P1363, base64url no-pad, sorted-key JSON)", async () => {
    const { aud, deviceId: did, nonce, ts } = V.auth.body;
    const ok = await verifyAuth(V.auth.ecdsaPub, { aud, deviceId: did, nonce, ts }, V.auth.sig);
    expect(ok).toBe(V.auth.expectVerify);
  });

  it("verifies via the lower-level verifyRecord over the canonical body too", async () => {
    const ok = await verifyRecord(V.auth.ecdsaPub, V.auth.body, V.auth.sig);
    expect(ok).toBe(true);
  });

  it("reproduces the stateless HMAC nonce (trap 5 family: HMAC-SHA256(secret, ts) hex)", async () => {
    const n = await makeNonce(V.nonce.serverSecret, V.nonce.ts);
    expect(n).toBe(V.nonce.nonce);
  });

  it("checkNonce accepts the golden nonce within TTL (faked clock to ts)", async () => {
    const realNow = Date.now;
    try {
      Date.now = () => Date.parse(V.nonce.ts) + 1000; // 1s after ts, well inside 300s
      const ok = await checkNonce(V.nonce.serverSecret, V.nonce.ts, V.nonce.nonce, V.nonce.ttlSecs);
      expect(ok).toBe(true);
    } finally {
      Date.now = realNow;
    }
  });

  it("checkNonce rejects an expired ts (outside TTL)", async () => {
    const realNow = Date.now;
    try {
      Date.now = () => Date.parse(V.nonce.ts) + (V.nonce.ttlSecs + 60) * 1000;
      const ok = await checkNonce(V.nonce.serverSecret, V.nonce.ts, V.nonce.nonce, V.nonce.ttlSecs);
      expect(ok).toBe(false);
    } finally {
      Date.now = realNow;
    }
  });
});
