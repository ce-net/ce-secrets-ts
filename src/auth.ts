// ce-secrets auth — challenge-response over the enrolled device key. Byte-exact mirror of
// ce-secrets/src/auth.mjs.
//
// A relying party (an app) issues a fresh nonce; the device SIGNS a flat canonical body
// { aud, deviceId, nonce, ts }; the app VERIFIES that the signer is an ENROLLED device of the
// operator's vault. No bearer tokens are ever delivered — only single-use, time-bound,
// nonce-bound proofs.
//
// INTEROP CONTRACT (the five traps the Rust + TS SDKs reproduce byte-for-byte):
//   1. Signature is ECDSA P-256 / SHA-256, RAW IEEE-P1363 r||s (64 bytes), NEVER DER.
//   2. The 64-byte signature is base64url, NO padding.
//   3. Canonicalization is top-level-sorted-key JSON, no whitespace, nested values untouched.
//   4. The signed body is FLAT — exactly { aud, deviceId, nonce, ts }, all strings.
//   5. The stateless nonce is HMAC-SHA256(serverSecret, ts), hex; TTL 300s on `ts`.

import { utf8, hex, toBytes } from "./encoding.js";
import { stableStringify } from "./canonical.js";
import { signRecord, verifyRecord, type DeviceKey, type JwkPublic } from "./crypto.js";

const subtle = globalThis.crypto.subtle;

/** Default replay/skew window, in seconds. Mirrors the hub's SIG_TTL_SECS. */
export const AUTH_TTL_SECS = 300;

/** The flat, canonical auth body that gets signed and verified. */
export interface AuthBody {
  aud: string;
  deviceId: string;
  nonce: string;
  ts: string;
}

/** A server secret may be a string or raw bytes. */
export type ServerSecret = string | Uint8Array;

/** Re-export of the canonical stable-stringify so apps/tests use the EXACT same bytes. */
export { stableStringify as stable_stringify };

// ---- nonce (stateless, HMAC-SHA256(serverSecret, ts)) -----------------------

function hmacKey(serverSecret: ServerSecret): Promise<CryptoKey> {
  const raw = typeof serverSecret === "string" ? utf8.enc(serverSecret) : toBytes(serverSecret);
  return subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
}

/** makeNonce(serverSecret, ts) -> hex string. `ts` is the ISO-8601 string used in the body. */
export async function makeNonce(serverSecret: ServerSecret, ts: string): Promise<string> {
  const key = await hmacKey(serverSecret);
  const mac = new Uint8Array(await subtle.sign("HMAC", key, utf8.enc(String(ts))));
  return hex.enc(mac);
}

/**
 * checkNonce(serverSecret, ts, nonce) -> bool. Recomputes the HMAC, constant-time compares,
 * and enforces the TTL on `ts` (within ±ttlSecs of now). Stateless: no nonce cache required.
 */
export async function checkNonce(
  serverSecret: ServerSecret,
  ts: string,
  nonce: string,
  ttlSecs: number = AUTH_TTL_SECS,
): Promise<boolean> {
  const tms = Date.parse(ts);
  if (Number.isNaN(tms)) return false;
  if (Math.abs(Date.now() - tms) > ttlSecs * 1000) return false;
  const expected = await makeNonce(serverSecret, ts);
  return constantTimeEqualHex(expected, String(nonce));
}

function constantTimeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// ---- sign / verify ----------------------------------------------------------

/** Build the flat canonical auth body. One place so signer and verifier always agree. */
export function authBody({ aud, deviceId, nonce, ts }: AuthBody): AuthBody {
  return {
    aud: String(aud),
    deviceId: String(deviceId),
    nonce: String(nonce),
    ts: String(ts),
  };
}

/**
 * signChallenge(device, { aud, nonce, ts }) -> base64url(P1363 sig).
 * `device` is a full device key; its `.id` is the deviceId. Signs
 * UTF8(stableStringify({aud,deviceId,nonce,ts})) with ECDSA P-256/SHA-256, raw P1363.
 */
export function signChallenge(
  device: DeviceKey,
  { aud, nonce, ts }: { aud: string; nonce: string; ts: string },
): Promise<string> {
  const body = authBody({ aud, deviceId: device.id, nonce, ts });
  return signRecord(device, body);
}

/**
 * verifyAuth(enrolledDevicePubJwk, { aud, deviceId, nonce, ts }, sig) -> bool. The PURE crypto
 * check: verifies the raw-P1363 base64url signature over the canonical flat body. Freshness +
 * enrollment policy lives in {@link verifyAuthFull}.
 */
export function verifyAuth(
  enrolledDevicePubJwk: JwkPublic,
  { aud, deviceId, nonce, ts }: AuthBody,
  sig: string,
): Promise<boolean> {
  const body = authBody({ aud, deviceId, nonce, ts });
  return verifyRecord(enrolledDevicePubJwk, body, sig);
}

/** An enrolled device record, as stored in the vault's `d.<deviceId>`. */
export interface EnrolledDevice {
  ecdsaPub: JwkPublic;
  label?: string;
}

/** The proof an app receives from a device. */
export interface AuthProof extends AuthBody {
  sig: string;
}

/** Options for {@link verifyAuthFull}. */
export interface VerifyAuthFullOptions {
  expectedAud?: string;
  serverSecret?: ServerSecret;
  lookupDevice?: (deviceId: string) => EnrolledDevice | null | Promise<EnrolledDevice | null>;
  ttlSecs?: number;
}

/** The result of a full relying-party verification. */
export type VerifyAuthFullResult =
  | { ok: true; deviceId: string; label?: string }
  | { ok: false; reason: string };

/**
 * Full relying-party verification with freshness + identity binding. `lookupDevice(deviceId)`
 * returns the enrolled `d.<id>` record (with `.ecdsaPub`) or null.
 */
export async function verifyAuthFull(
  { aud, deviceId, nonce, ts, sig }: AuthProof,
  { expectedAud, serverSecret, lookupDevice, ttlSecs = AUTH_TTL_SECS }: VerifyAuthFullOptions = {},
): Promise<VerifyAuthFullResult> {
  if (expectedAud != null && aud !== String(expectedAud)) {
    return { ok: false, reason: "aud-mismatch" };
  }
  if (serverSecret != null && !(await checkNonce(serverSecret, ts, nonce, ttlSecs))) {
    return { ok: false, reason: "bad-nonce-or-expired" };
  }
  const rec = lookupDevice ? await lookupDevice(deviceId) : null;
  if (!rec) return { ok: false, reason: "not-enrolled" };
  if (!(await verifyAuth(rec.ecdsaPub, { aud, deviceId, nonce, ts }, sig))) {
    return { ok: false, reason: "bad-signature" };
  }
  return rec.label != null
    ? { ok: true, deviceId, label: rec.label }
    : { ok: true, deviceId };
}

/** Current time as an ISO-8601 string (the `ts` field). */
export function nowISO(): string {
  return new Date().toISOString();
}
