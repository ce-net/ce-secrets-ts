// The five interop traps, pinned with controlled inputs (independent of the golden vectors).
// Each assertion locks one byte-level decision that the Rust + JS + TS SDKs must agree on.

import { describe, it, expect } from "vitest";
import {
  generateDeviceKey,
  generateMaster,
  wrapMaster,
  unwrapMaster,
  encryptSecret,
  decryptSecret,
  signChallenge,
  verifyAuth,
  makeNonce,
  MASTER_WRAP_INFO,
  b64,
  hex,
  utf8,
  stableStringify,
  authBody,
} from "../src/index.js";

describe("trap (1) — HKDF empty salt + exact info string", () => {
  it("the master-wrap info string is exactly 'ce-secrets/master-wrap/v1'", () => {
    expect(MASTER_WRAP_INFO).toBe("ce-secrets/master-wrap/v1");
  });

  it("ECIES wrap/unwrap round-trips (proves the HKDF params line up on both sides)", async () => {
    const dk = await generateDeviceKey();
    const master = generateMaster();
    const wrapped = await wrapMaster(master, dk.ecdhPub);
    const back = await unwrapMaster(wrapped, dk.ecdhPriv);
    expect(hex.enc(back)).toBe(hex.enc(master));
  });
});

describe("trap (2) — AES-GCM 12-byte nonce, 16-byte tag appended", () => {
  it("a sealed secret's iv decodes to exactly 12 bytes", async () => {
    const master = generateMaster();
    const sealed = await encryptSecret(master, utf8.enc("hello"));
    expect(b64.dec(sealed.iv).length).toBe(12);
  });

  it("ciphertext is plaintext length + 16 (GCM tag) bytes", async () => {
    const master = generateMaster();
    const pt = utf8.enc("0123456789"); // 10 bytes
    const sealed = await encryptSecret(master, pt);
    expect(b64.dec(sealed.ct).length).toBe(pt.length + 16);
  });

  it("seal/open round-trips", async () => {
    const master = generateMaster();
    const pt = utf8.enc("sk-roundtrip-0001");
    const sealed = await encryptSecret(master, pt);
    const back = await decryptSecret(master, sealed);
    expect(utf8.dec(back)).toBe("sk-roundtrip-0001");
  });
});

describe("trap (3) — ECDSA raw P1363 64-byte sig (NOT DER)", () => {
  it("a challenge signature decodes to exactly 64 bytes", async () => {
    const dk = await generateDeviceKey();
    const ts = "2026-06-24T00:00:00.000Z";
    const sig = await signChallenge(dk, { aud: "ce-watch", nonce: "n0", ts });
    const raw = b64.dec(sig);
    expect(raw.length).toBe(64);
    // A DER ECDSA sig starts with 0x30 (SEQUENCE) and is typically 70-72 bytes — assert NOT that.
    expect(raw.length).not.toBe(70);
    expect(raw.length).not.toBe(71);
    expect(raw.length).not.toBe(72);
  });

  it("sign/verify round-trips through the public JWK", async () => {
    const dk = await generateDeviceKey();
    const ts = "2026-06-24T00:00:00.000Z";
    const sig = await signChallenge(dk, { aud: "ce-watch", nonce: "n0", ts });
    const ok = await verifyAuth(
      dk.ecdsaPub,
      { aud: "ce-watch", deviceId: dk.id, nonce: "n0", ts },
      sig,
    );
    expect(ok).toBe(true);
  });

  it("a tampered body fails verification", async () => {
    const dk = await generateDeviceKey();
    const ts = "2026-06-24T00:00:00.000Z";
    const sig = await signChallenge(dk, { aud: "ce-watch", nonce: "n0", ts });
    const ok = await verifyAuth(
      dk.ecdsaPub,
      { aud: "ce-watch", deviceId: dk.id, nonce: "TAMPERED", ts },
      sig,
    );
    expect(ok).toBe(false);
  });
});

describe("trap (4) — base64url, NO padding", () => {
  it("never emits '=' padding and uses url-safe alphabet", () => {
    // 1 byte -> base64 'AA==' normally; base64url-no-pad -> 'AA'.
    expect(b64.enc(new Uint8Array([0]))).toBe("AA");
    // 0xff 0xff 0xff -> '////' -> '____'.
    expect(b64.enc(new Uint8Array([0xff, 0xff, 0xff]))).toBe("____");
    // 0xfb 0xff 0xbf exercises both '-' and '_'.
    const s = b64.enc(new Uint8Array([0xfb, 0xff, 0xbf]));
    expect(s).not.toContain("+");
    expect(s).not.toContain("/");
    expect(s).not.toContain("=");
  });

  it("decode tolerates missing padding and round-trips", () => {
    const bytes = new Uint8Array([1, 2, 3, 4, 5]);
    const s = b64.enc(bytes);
    expect(s).not.toContain("=");
    expect(hex.enc(b64.dec(s))).toBe(hex.enc(bytes));
  });
});

describe("trap (5) — top-level-sorted-key JSON canonicalization, no whitespace", () => {
  it("sorts top-level keys and emits no whitespace", () => {
    expect(stableStringify({ b: 2, a: 1, c: 3 })).toBe('{"a":1,"b":2,"c":3}');
  });

  it("matches the canonical auth-body ordering aud<deviceId<nonce<ts", () => {
    const body = authBody({ ts: "T", nonce: "N", deviceId: "D", aud: "A" });
    expect(stableStringify(body)).toBe('{"aud":"A","deviceId":"D","nonce":"N","ts":"T"}');
  });

  it("is exactly JSON.stringify(o, Object.keys(o).sort()) — same as the canonical .mjs", () => {
    // The replacer is the top-level key array; JSON.stringify applies it recursively as a
    // key-allowlist, so nested keys not present at the top level are dropped. The auth body is
    // always FLAT, so this is irrelevant in practice, but the TS output must match the .mjs
    // byte-for-byte for whatever it is fed. Lock that identity here.
    const o = { z: { b: 1, a: 2 }, a: 1 };
    expect(stableStringify(o)).toBe(JSON.stringify(o, Object.keys(o).sort()));
    expect(stableStringify(o)).toBe('{"a":1,"z":{"a":2}}');
  });
});

describe("nonce — HMAC-SHA256(serverSecret, ts) hex", () => {
  it("is deterministic and lowercase-hex of length 64", async () => {
    const n1 = await makeNonce("secret", "2026-06-24T00:00:00.000Z");
    const n2 = await makeNonce("secret", "2026-06-24T00:00:00.000Z");
    expect(n1).toBe(n2);
    expect(n1).toMatch(/^[0-9a-f]{64}$/);
  });

  it("a string secret and its UTF-8 bytes produce the same nonce", async () => {
    const a = await makeNonce("secret", "ts");
    const b = await makeNonce(utf8.enc("secret"), "ts");
    expect(a).toBe(b);
  });
});
