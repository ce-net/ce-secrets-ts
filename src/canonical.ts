// Canonical JSON — interop trap (5).
//
// The single source of truth for what gets signed/verified. Top-level keys sorted, no
// whitespace. Byte-exact with the canonical .mjs:
//   stableStringify(o) = JSON.stringify(o, Object.keys(o).sort())
//
// NOTE: the second argument is a replacer KEY-ALLOWLIST that JSON.stringify applies
// recursively — so nested keys absent from the top-level key set are DROPPED, not "left
// untouched". The signed auth body is always flat ({ aud, deviceId, nonce, ts }, all strings),
// so this never matters in practice. Do not "improve" this into a deep canonicalizer: it must
// match the .mjs and Rust SDKs exactly, including this quirk.

/** Stable-stringify an object: top-level keys sorted, no whitespace. */
export function stableStringify(obj: object): string {
  return JSON.stringify(obj, Object.keys(obj).sort());
}

/** snake_case alias matching the canonical .mjs / Rust export name. */
export const stable_stringify = stableStringify;
