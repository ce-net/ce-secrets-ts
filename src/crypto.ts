// ce-secrets crypto — isomorphic WebCrypto, byte-exact mirror of ce-secrets/src/crypto.mjs.
//
// Model (identical to the canonical .mjs):
//   - Each DEVICE holds an ECDH P-256 keypair (wrap/unwrap) and an ECDSA P-256 keypair
//     (sign/verify), both serialized as JWKs. The private halves never leave the device.
//   - One VAULT MASTER KEY (random 32 bytes) encrypts every secret with AES-256-GCM.
//   - The master is WRAPPED to each authorized device via ECIES: ephemeral ECDH P-256 ->
//     HKDF(SHA-256, salt=EMPTY, info="ce-secrets/master-wrap/v1") -> AES-256-GCM.
//   - Records are SIGNED (ECDSA P-256 / SHA-256) by the writing device. WebCrypto's ECDSA
//     produces/consumes RAW IEEE-P1363 r||s (64 bytes), NEVER DER — interop trap (3).
//
// The five interop traps reproduced here exactly:
//   (1) HKDF salt = EMPTY (zero-length, not absent) + info "ce-secrets/master-wrap/v1".
//   (2) AES-GCM 12-byte nonce, 16-byte tag appended to ciphertext (WebCrypto default).
//   (3) ECDSA raw P1363 64-byte signature, NOT DER.
//   (4) base64url, NO padding (see ./encoding).
//   (5) top-level-sorted-key JSON canonicalization, no whitespace (see ./canonical).

import { b64, hex, utf8, randomBytes, toBytes, enc } from "./encoding.js";
import { stableStringify } from "./canonical.js";

const subtle = globalThis.crypto.subtle;

/** A P-256 public key in JWK form (the public coordinates only). */
export interface JwkPublic {
  kty: "EC";
  crv: "P-256";
  x: string;
  y: string;
  key_ops?: string[];
  ext?: boolean;
}

/** A P-256 private key in JWK form (adds the scalar `d`). */
export interface JwkPrivate extends JwkPublic {
  d: string;
}

/**
 * A full device key: an ECDH keypair (wrap/unwrap) plus an ECDSA keypair (sign/verify),
 * both P-256, serialized as JWKs, with a stable derived id.
 */
export interface DeviceKey {
  ecdhPriv: JwkPrivate;
  ecdhPub: JwkPublic;
  ecdsaPriv: JwkPrivate;
  ecdsaPub: JwkPublic;
  id: string;
}

/** The public half of a device key — safe to publish/share. */
export interface DevicePublic {
  id: string;
  ecdhPub: JwkPublic;
  ecdsaPub: JwkPublic;
}

/** An ECIES-wrapped master key. */
export interface Wrapped {
  eph: JwkPublic;
  iv: string;
  ct: string;
}

/** An AES-256-GCM sealed secret. */
export interface Sealed {
  iv: string;
  ct: string;
}

// ---- device keys ------------------------------------------------------------

/** Generate a fresh device key (ECDH + ECDSA P-256), with a derived stable id. */
export async function generateDeviceKey(): Promise<DeviceKey> {
  const ecdh = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
    "deriveBits",
  ]);
  const ecdsa = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ]);
  const ecdhPriv = (await subtle.exportKey("jwk", ecdh.privateKey)) as JwkPrivate;
  const ecdhPub = (await subtle.exportKey("jwk", ecdh.publicKey)) as JwkPublic;
  const ecdsaPriv = (await subtle.exportKey("jwk", ecdsa.privateKey)) as JwkPrivate;
  const ecdsaPub = (await subtle.exportKey("jwk", ecdsa.publicKey)) as JwkPublic;
  const id = await deviceId(ecdhPub, ecdsaPub);
  return { ecdhPriv, ecdhPub, ecdsaPriv, ecdsaPub, id };
}

/** The public half of a device key (safe to share). */
export function devicePublic(dk: DeviceKey): DevicePublic {
  return { id: dk.id, ecdhPub: dk.ecdhPub, ecdsaPub: dk.ecdsaPub };
}

/**
 * Derive the stable device id: hex(sha256(utf8(JSON.stringify([
 *   ecdhPub.x, ecdhPub.y, ecdsaPub.x, ecdsaPub.y ]))))[..16].
 * Byte-exact with the canonical .mjs (plain JSON.stringify of a 4-element array).
 */
export async function deviceId(ecdhPub: JwkPublic, ecdsaPub: JwkPublic): Promise<string> {
  const data = utf8.enc(JSON.stringify([ecdhPub.x, ecdhPub.y, ecdsaPub.x, ecdsaPub.y]));
  return hex.enc(new Uint8Array(await subtle.digest("SHA-256", data))).slice(0, 16);
}

function importEcdhPriv(jwk: JwkPrivate): Promise<CryptoKey> {
  return subtle.importKey("jwk", jwk, { name: "ECDH", namedCurve: "P-256" }, false, [
    "deriveBits",
  ]);
}
function importEcdhPub(jwk: JwkPublic): Promise<CryptoKey> {
  return subtle.importKey("jwk", jwk, { name: "ECDH", namedCurve: "P-256" }, false, []);
}
function importEcdsaPriv(jwk: JwkPrivate): Promise<CryptoKey> {
  return subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
}
function importEcdsaPub(jwk: JwkPublic): Promise<CryptoKey> {
  return subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
}

// ---- master key + ECIES wrap ------------------------------------------------

/** Generate a fresh 32-byte vault master key. */
export function generateMaster(): Uint8Array {
  return randomBytes(32);
}

// Derive an AES-256-GCM key from ECDH shared bits via HKDF-SHA-256 with an EMPTY salt
// (zero-length, not absent — trap 1) and the exact info string.
async function hkdfAesKey(sharedBits: ArrayBuffer, info: string): Promise<CryptoKey> {
  const base = await subtle.importKey("raw", sharedBits, "HKDF", false, ["deriveKey"]);
  return subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: utf8.enc(info) },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/** The exact ECIES HKDF info string. Exported so callers/tests can pin trap (1). */
export const MASTER_WRAP_INFO = "ce-secrets/master-wrap/v1";

/** Wrap the master key to a recipient device's ECDH public key (ECIES). */
export async function wrapMaster(
  masterRaw: Uint8Array,
  recipientEcdhPubJwk: JwkPublic,
): Promise<Wrapped> {
  const eph = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
    "deriveBits",
  ]);
  const recip = await importEcdhPub(recipientEcdhPubJwk);
  const shared = await subtle.deriveBits({ name: "ECDH", public: recip }, eph.privateKey, 256);
  const aes = await hkdfAesKey(shared, MASTER_WRAP_INFO);
  const iv = randomBytes(12);
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv }, aes, toBytes(masterRaw)));
  return {
    eph: (await subtle.exportKey("jwk", eph.publicKey)) as JwkPublic,
    iv: b64.enc(iv),
    ct: b64.enc(ct),
  };
}

/** Unwrap the master key with this device's ECDH private key. */
export async function unwrapMaster(
  wrapped: Wrapped,
  deviceEcdhPrivJwk: JwkPrivate,
): Promise<Uint8Array> {
  const priv = await importEcdhPriv(deviceEcdhPrivJwk);
  const eph = await importEcdhPub(wrapped.eph);
  const shared = await subtle.deriveBits({ name: "ECDH", public: eph }, priv, 256);
  const aes = await hkdfAesKey(shared, MASTER_WRAP_INFO);
  const pt = await subtle.decrypt(
    { name: "AES-GCM", iv: b64.dec(wrapped.iv) },
    aes,
    b64.dec(wrapped.ct),
  );
  return new Uint8Array(pt);
}

// ---- secret encryption (AES-256-GCM under the master key) -------------------

function masterAesKey(masterRaw: Uint8Array): Promise<CryptoKey> {
  return subtle.importKey("raw", toBytes(masterRaw), "AES-GCM", false, ["encrypt", "decrypt"]);
}

/** Encrypt a secret under the master key (AES-256-GCM, 12-byte nonce, no AAD). */
export async function encryptSecret(
  masterRaw: Uint8Array,
  plaintextBytes: Uint8Array,
): Promise<Sealed> {
  const aes = await masterAesKey(masterRaw);
  const iv = randomBytes(12);
  const ct = new Uint8Array(
    await subtle.encrypt({ name: "AES-GCM", iv }, aes, toBytes(plaintextBytes)),
  );
  return { iv: b64.enc(iv), ct: b64.enc(ct) };
}

/** Decrypt a secret sealed under the master key. */
export async function decryptSecret(masterRaw: Uint8Array, sealed: Sealed): Promise<Uint8Array> {
  const aes = await masterAesKey(masterRaw);
  const pt = await subtle.decrypt(
    { name: "AES-GCM", iv: b64.dec(sealed.iv) },
    aes,
    b64.dec(sealed.ct),
  );
  return new Uint8Array(pt);
}

// Aliases matching the canonical .mjs verb names (seal/open).
export { encryptSecret as sealSecret, decryptSecret as openSecret };

// ---- record signing (tamper-evidence) ---------------------------------------

/**
 * Sign `obj` with the device's ECDSA key: ECDSA P-256 / SHA-256 over
 * UTF8(stableStringify(obj)) -> raw P1363 64-byte sig -> base64url no-pad.
 */
export async function signRecord(dk: DeviceKey, obj: object): Promise<string> {
  const priv = await importEcdsaPriv(dk.ecdsaPriv);
  const data = utf8.enc(stableStringify(obj));
  const sig = new Uint8Array(await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, priv, data));
  return b64.enc(sig);
}

/** Verify a base64url raw-P1363 signature over stableStringify(obj). */
export async function verifyRecord(
  ecdsaPubJwk: JwkPublic,
  obj: object,
  sigB64: string,
): Promise<boolean> {
  const pub = await importEcdsaPub(ecdsaPubJwk);
  const data = utf8.enc(stableStringify(obj));
  return subtle.verify({ name: "ECDSA", hash: "SHA-256" }, pub, b64.dec(sigB64), data);
}

// ---- fingerprint (safe to display) ------------------------------------------

/** A short, display-safe fingerprint: hex(sha256(bytes))[..16]. */
export async function fingerprint(bytes: Uint8Array): Promise<string> {
  const h = new Uint8Array(await subtle.digest("SHA-256", toBytes(bytes)));
  return hex.enc(h).slice(0, 16);
}

export { b64, hex, utf8, randomBytes, enc };
