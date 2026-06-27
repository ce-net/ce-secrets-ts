# @ce-net/secrets

Runtime-agnostic TypeScript SDK for ce-net **encrypted multi-device secrets + challenge-response
auth**. Built on WebCrypto (`crypto.subtle`, `getRandomValues`), so the same bundle runs on Node
20+, Deno, Bun, browsers, and edge Workers.

Byte-exact interop with the canonical JavaScript impl (`ce-secrets/src/crypto.mjs` + `auth.mjs`)
and the Rust SDK (`ce-secrets-rs`) — a record sealed by one can be opened by any of the three.

> **Status: primitive / interop layer.** This is the low-level crypto + auth toolkit, not a vault
> product. The forward path for a full multi-device vault is [`@ce-net/iam`](../ce-iam-ts) (which
> wraps `ce-iam-core`); this package mirrors `ce-secrets-rs` for code that needs the raw primitives
> or cross-impl interop.

## Install

```bash
npm i @ce-net/secrets
```

Ships ESM + CJS with type declarations for both. Everything is exported from the package root.

## Crypto layer

```ts
import {
  generateDeviceKey, devicePublic, deviceId,
  generateMaster, wrapMaster, unwrapMaster, MASTER_WRAP_INFO,
  encryptSecret, decryptSecret, sealSecret, openSecret,
  signRecord, verifyRecord, fingerprint,
} from "@ce-net/secrets";
```

- **Device keys** — `generateDeviceKey()` (ECDH + ECDSA P-256 bundle), `devicePublic(key)`,
  `deviceId(pub)`.
- **Master key + ECIES** — `generateMaster()`, `wrapMaster()` / `unwrapMaster()` (`MASTER_WRAP_INFO`
  is the HKDF info string), so the per-vault master is wrapped to each enrolled device.
- **Secret encryption** — `encryptSecret` / `decryptSecret` and the `sealSecret` / `openSecret`
  convenience pair (AES-256-GCM under the master).
- **Record signing** — `signRecord` / `verifyRecord` (ECDSA P-256 tamper-evidence).
- Types: `DeviceKey`, `DevicePublic`, `JwkPublic`, `JwkPrivate`, `Wrapped`, `Sealed`.

Encoding helpers are re-exported for convenience: `b64`, `hex`, `utf8`, `randomBytes`, `enc`.

## Canonicalization

```ts
import { stableStringify, stable_stringify } from "@ce-net/secrets";
```

Deterministic top-level-sorted-key JSON — the exact byte layout the signatures are computed over
(both the camelCase and snake_case names are exported).

## Auth layer (challenge-response login)

```ts
import {
  signChallenge, verifyAuth, verifyAuthFull,
  makeNonce, checkNonce, authBody, nowISO, AUTH_TTL_SECS,
} from "@ce-net/secrets";
```

A device proves it is enrolled without a password: `makeNonce` / `checkNonce` is the stateless
HMAC nonce, `signChallenge` signs it, and `verifyAuth` / `verifyAuthFull` verify the proof
server-side. Types: `AuthBody`, `AuthProof`, `ServerSecret`, `EnrolledDevice`,
`VerifyAuthFullOptions`, `VerifyAuthFullResult`.

## Login client

```ts
import { loginHeaders, verifyViaAuth, ensureDevice, DEVICE_STORAGE_KEY } from "@ce-net/secrets";
```

Adopt ce-auth device-auth in a few lines: `ensureDevice(storage)` load-or-generates a `DeviceKey`
from a storage shim, `loginHeaders(...)` does `GET /challenge` → sign → returns the `x-ce-*`
request headers, and `verifyViaAuth(...)` does `POST /verify` and returns the `{ ok, role }`
verdict (server side). Types: `FetchLike`, `LoginOptions`, `Challenge`, `LoginHeaders`,
`VerifyVerdict`, `DeviceStorage`.

## Interop traps

To stay byte-exact with `ce-secrets-rs` and the JS reference: HKDF with an empty salt and info
`ce-secrets/master-wrap/v1`, a 12-byte GCM nonce, raw P1363 (64-byte) ECDSA signatures, base64url
with no padding, and top-level-sorted-key JSON for signed records.

## License

AGPL-3.0-only. A commercial license is also available — see [`LICENSING.md`](./LICENSING.md)
and [`COMMERCIAL-LICENSE.md`](./COMMERCIAL-LICENSE.md).
