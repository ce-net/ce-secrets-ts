// Encoding helpers — byte-exact mirror of ce-secrets/src/crypto.mjs `b64` / `hex` / `utf8`.
//
// These are the wire encodings the canonical .mjs and Rust SDKs all agree on. They are
// deliberately the same algorithms (not just "compatible"): base64url with NO padding,
// lowercase hex, UTF-8. Runtime-agnostic (no Node Buffer): works in browsers, Node 20+,
// Deno, Bun, and edge Workers.
//
// All byte producers return `Uint8Array<ArrayBuffer>` (never a SharedArrayBuffer-backed view),
// so the buffers feed straight into WebCrypto's `BufferSource` parameters without casts.

/** A plain, non-shared byte buffer view — the concrete shape WebCrypto's BufferSource accepts. */
export type Bytes = Uint8Array<ArrayBuffer>;

/** base64url, NO padding. Trap (4). */
export const b64 = {
  /** Encode bytes to base64url, no padding. */
  enc(bytes: Uint8Array | ArrayBuffer): string {
    const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    let s = "";
    for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]!);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  },
  /** Decode base64url (padding optional/absent) to bytes. */
  dec(str: string): Bytes {
    const s = str.replace(/-/g, "+").replace(/_/g, "/");
    const bin = atob(s + "===".slice((s.length + 3) % 4));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  },
};

/** lowercase hex. */
export const hex = {
  /** Encode bytes to a lowercase hex string. */
  enc(bytes: Uint8Array | ArrayBuffer): string {
    const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    let out = "";
    for (let i = 0; i < b.length; i++) out += b[i]!.toString(16).padStart(2, "0");
    return out;
  },
  /** Decode a hex string to bytes. */
  dec(str: string): Bytes {
    const out = new Uint8Array(str.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(str.substr(i * 2, 2), 16);
    return out;
  },
};

/** UTF-8 codec. */
export const utf8 = {
  enc: (s: string): Bytes => {
    // TextEncoder.encode() is typed as Uint8Array<ArrayBufferLike>; copy into a plain
    // ArrayBuffer-backed view so it satisfies WebCrypto's BufferSource without a cast.
    const e = new TextEncoder().encode(s);
    const out = new Uint8Array(e.length);
    out.set(e);
    return out;
  },
  dec: (b: Uint8Array): string => new TextDecoder().decode(b),
};

/** Cryptographically-strong random bytes. */
export function randomBytes(n: number): Bytes {
  return globalThis.crypto.getRandomValues(new Uint8Array(n));
}

/**
 * Normalize any byte view into a plain ArrayBuffer-backed `Uint8Array<ArrayBuffer>`, copying
 * only when the input is shared-buffer-backed. Used at WebCrypto boundaries so callers may pass
 * an ordinary `Uint8Array` while `subtle.*` still receives a concrete `BufferSource`.
 */
export function toBytes(b: Uint8Array): Bytes {
  if (b.buffer instanceof ArrayBuffer) return b as Bytes;
  const out = new Uint8Array(b.length);
  out.set(b);
  return out;
}

export const enc = { b64, hex, utf8 };
