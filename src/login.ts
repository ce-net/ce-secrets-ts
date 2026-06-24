// ce-secrets login — the tiny reusable client helpers an app uses to adopt ce-auth's
// challenge-response device-auth in a few lines.
//
// The ce-auth HTTP contract (the interface every app shares):
//   GET  {authBase}/challenge?aud=<appId>
//        -> { aud, nonce, ts }      (nonce = HMAC-SHA256(server_secret, aud+"|"+ts) hex; 300s TTL)
//   POST {authBase}/verify { aud, deviceId, sig, nonce, ts }
//        -> { ok, role, deviceId }  (ok == signature valid AND role=="admin")
//
// A device enrolled in ce-auth == the operator == trusted by every app. These helpers are
// runtime-agnostic: `fetch` is injectable (defaults to globalThis.fetch) so they run unchanged
// on Node 20+, Deno, Bun, browsers, and edge Workers. Persistence (ensureDevice) goes through a
// minimal storage shim — pass localStorage in a browser, or any { getItem,setItem }.

import { generateDeviceKey, type DeviceKey } from "./crypto.js";
import { signChallenge } from "./auth.js";

/** The minimal `fetch` shape these helpers need. Defaults to `globalThis.fetch`. */
export type FetchLike = (
  input: string,
  init?: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
  },
) => Promise<{
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
  text(): Promise<string>;
}>;

/** Common options: an injectable fetch. */
export interface LoginOptions {
  /** Override the global fetch (e.g. a test double or a Worker-bound fetch). */
  fetch?: FetchLike;
}

function resolveFetch(opts?: LoginOptions): FetchLike {
  const f = opts?.fetch ?? (globalThis.fetch as unknown as FetchLike | undefined);
  if (!f) throw new Error("no fetch available; pass { fetch } in LoginOptions");
  return f;
}

/** Trim a trailing slash so `{authBase}/challenge` never doubles up. */
function joinBase(authBase: string, path: string): string {
  return authBase.replace(/\/+$/, "") + path;
}

/** The shape ce-auth's GET /challenge returns. */
export interface Challenge {
  aud: string;
  nonce: string;
  ts: string;
}

/** The HTTP headers an app forwards to its backend (which re-checks them via ce-auth). */
export interface LoginHeaders extends Record<string, string> {
  "x-ce-device-id": string;
  "x-ce-auth": string;
  "x-ce-aud": string;
  "x-ce-nonce": string;
  "x-ce-ts": string;
}

/** The verdict ce-auth's POST /verify returns. */
export interface VerifyVerdict {
  ok: boolean;
  role: string;
}

/**
 * loginHeaders — fetch a fresh challenge from ce-auth, sign it with `device`, and return the
 * five headers an app attaches to its requests:
 *   { 'x-ce-device-id', 'x-ce-auth', 'x-ce-aud', 'x-ce-nonce', 'x-ce-ts' }.
 * `x-ce-auth` is the base64url raw-P1363 signature over the canonical { aud, deviceId, nonce, ts }.
 * The app's backend re-derives the same body and verifies it (via {@link verifyViaAuth} or the
 * SDK's verifyAuth/verifyAuthFull).
 */
export async function loginHeaders(
  authBase: string,
  aud: string,
  device: DeviceKey,
  opts?: LoginOptions,
): Promise<LoginHeaders> {
  const fetch = resolveFetch(opts);
  const url = joinBase(authBase, `/challenge?aud=${encodeURIComponent(aud)}`);
  const res = await fetch(url, { method: "GET" });
  if (!res.ok) {
    throw new Error(`ce-auth /challenge failed: ${res.status} ${await safeText(res)}`);
  }
  const ch = (await res.json()) as Challenge;
  if (!ch || typeof ch.nonce !== "string" || typeof ch.ts !== "string") {
    throw new Error("ce-auth /challenge returned a malformed challenge");
  }
  // The challenge carries its own aud; sign exactly what the server will re-derive. Prefer the
  // server's echoed aud (it is the authority on what the nonce is bound to).
  const boundAud = typeof ch.aud === "string" && ch.aud.length > 0 ? ch.aud : aud;
  const sig = await signChallenge(device, { aud: boundAud, nonce: ch.nonce, ts: ch.ts });
  return {
    "x-ce-device-id": device.id,
    "x-ce-auth": sig,
    "x-ce-aud": boundAud,
    "x-ce-nonce": ch.nonce,
    "x-ce-ts": ch.ts,
  };
}

/**
 * verifyViaAuth — the server-side one-liner. POST the login headers to ce-auth's /verify and
 * return its verdict { ok, role }. `headers` may be the {@link LoginHeaders} object produced by
 * {@link loginHeaders}, or any object carrying the same `x-ce-*` keys (case-insensitive), which
 * is what a backend reads off an incoming request.
 */
export async function verifyViaAuth(
  authBase: string,
  aud: string,
  headers: Record<string, string>,
  opts?: LoginOptions,
): Promise<VerifyVerdict> {
  const fetch = resolveFetch(opts);
  const h = lowerKeys(headers);
  const body = {
    aud: h["x-ce-aud"] ?? aud,
    deviceId: h["x-ce-device-id"] ?? "",
    sig: h["x-ce-auth"] ?? "",
    nonce: h["x-ce-nonce"] ?? "",
    ts: h["x-ce-ts"] ?? "",
  };
  const url = joinBase(authBase, "/verify");
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    // A non-2xx from /verify is a hard "no": surface a closed verdict rather than throwing,
    // so callers can treat it as an auth failure uniformly.
    return { ok: false, role: "none" };
  }
  const v = (await res.json()) as Partial<VerifyVerdict>;
  return { ok: v?.ok === true, role: typeof v?.role === "string" ? v.role : "none" };
}

function lowerKeys(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) out[k.toLowerCase()] = v;
  return out;
}

async function safeText(res: { text(): Promise<string> }): Promise<string> {
  try {
    return await res.text();
  } catch {
    return "";
  }
}

// ---- device persistence -----------------------------------------------------

/**
 * The minimal storage shim ensureDevice needs. `localStorage` satisfies it directly (in the
 * browser the one-liner is `ensureDevice(localStorage)`); on the server pass any object with
 * `getItem`/`setItem`. Async stores are supported (return a Promise).
 */
export interface DeviceStorage {
  getItem(key: string): string | null | Promise<string | null>;
  setItem(key: string, value: string): void | Promise<void>;
}

/** The storage key ensureDevice reads/writes under. */
export const DEVICE_STORAGE_KEY = "ce-secrets/device";

/**
 * ensureDevice — load a persisted DeviceKey from `storage`, or generate a fresh one and persist
 * it. The one-liner a browser app uses to get a stable identity:
 *   const device = await ensureDevice(localStorage);
 * Stores the DeviceKey as JSON under {@link DEVICE_STORAGE_KEY}. A malformed/partial stored value
 * is discarded and regenerated.
 */
export async function ensureDevice(
  storage: DeviceStorage,
  key: string = DEVICE_STORAGE_KEY,
): Promise<DeviceKey> {
  const raw = await storage.getItem(key);
  if (raw) {
    const dk = parseDevice(raw);
    if (dk) return dk;
  }
  const device = await generateDeviceKey();
  await storage.setItem(key, JSON.stringify(device));
  return device;
}

/** Parse + shape-check a stored DeviceKey JSON string; returns null if it is not a valid key. */
function parseDevice(raw: string): DeviceKey | null {
  let v: unknown;
  try {
    v = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!v || typeof v !== "object") return null;
  const d = v as Record<string, unknown>;
  if (
    typeof d.id === "string" &&
    isObj(d.ecdhPriv) &&
    isObj(d.ecdhPub) &&
    isObj(d.ecdsaPriv) &&
    isObj(d.ecdsaPub)
  ) {
    return v as DeviceKey;
  }
  return null;
}

function isObj(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object";
}
