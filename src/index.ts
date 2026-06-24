// @ce-net/secrets — the TypeScript SDK for ce-net encrypted multi-device secrets + auth.
//
// Runtime-agnostic: built on WebCrypto subtle (crypto.subtle, getRandomValues), so the same
// bundle runs on Node 20+, Deno, Bun, browsers, and edge Workers. Byte-exact interop with the
// canonical JavaScript impl (ce-secrets/src/crypto.mjs + auth.mjs) and the Rust SDK.
//
// The crypto layer:
//   - generateDeviceKey / devicePublic / deviceId  — ECDH + ECDSA P-256 device keys.
//   - generateMaster / wrapMaster / unwrapMaster    — ECIES master-key wrapping.
//   - encryptSecret / decryptSecret (sealSecret / openSecret) — AES-256-GCM under the master.
//   - signRecord / verifyRecord                     — ECDSA P-256 record tamper-evidence.
//
// The auth layer (challenge-response login):
//   - signChallenge / verifyAuth / verifyAuthFull   — device proves it is enrolled.
//   - makeNonce / checkNonce                         — stateless HMAC nonce.
//   - stable_stringify / authBody / nowISO           — canonicalization helpers.

export {
  // device keys
  generateDeviceKey,
  devicePublic,
  deviceId,
  // master key + ECIES
  generateMaster,
  wrapMaster,
  unwrapMaster,
  MASTER_WRAP_INFO,
  // secret encryption
  encryptSecret,
  decryptSecret,
  sealSecret,
  openSecret,
  // record signing
  signRecord,
  verifyRecord,
  // misc
  fingerprint,
  // encoding (re-exported for convenience)
  b64,
  hex,
  utf8,
  randomBytes,
  enc,
} from "./crypto.js";

export type {
  DeviceKey,
  DevicePublic,
  JwkPublic,
  JwkPrivate,
  Wrapped,
  Sealed,
} from "./crypto.js";

export { stableStringify, stable_stringify } from "./canonical.js";

export {
  AUTH_TTL_SECS,
  makeNonce,
  checkNonce,
  authBody,
  signChallenge,
  verifyAuth,
  verifyAuthFull,
  nowISO,
} from "./auth.js";

export type {
  AuthBody,
  AuthProof,
  ServerSecret,
  EnrolledDevice,
  VerifyAuthFullOptions,
  VerifyAuthFullResult,
} from "./auth.js";
