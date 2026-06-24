// Login helper tests — the reusable client an app uses to adopt ce-auth device-auth.
//
//   1. loginHeaders against a MOCK /challenge produces signed x-ce-* headers whose signature
//      the existing SDK verifyAuth (and a mock /verify driven by verifyViaAuth) accepts.
//   2. verifyViaAuth posts the right body and surfaces the verdict (and closes on non-2xx).
//   3. ensureDevice persists a fresh key, then reloads the SAME key on a second call.

import { describe, it, expect } from "vitest";
import {
  loginHeaders,
  verifyViaAuth,
  ensureDevice,
  DEVICE_STORAGE_KEY,
  generateDeviceKey,
  verifyAuth,
  makeNonce,
  type FetchLike,
  type DeviceStorage,
  type DeviceKey,
} from "../src/index.js";

const SERVER_SECRET = "test-server-secret";

// A mock ce-auth server: stateless HMAC nonce bound to aud (aud+"|"+ts), like the real one.
// /challenge issues a fresh nonce; /verify re-derives, checks signature via the SDK verifyAuth,
// and gates ok on role=="admin" with the device looked up in a tiny registry.
function mockAuth(registry: Map<string, DeviceKey>): { fetch: FetchLike; calls: string[] } {
  const calls: string[] = [];
  const fetch: FetchLike = async (input, init) => {
    const url = new URL(input);
    calls.push(`${init?.method ?? "GET"} ${url.pathname}`);

    if (url.pathname === "/challenge") {
      const aud = url.searchParams.get("aud") ?? "";
      const ts = new Date().toISOString();
      const nonce = await makeNonce(SERVER_SECRET, `${aud}|${ts}`);
      return jsonRes({ aud, nonce, ts });
    }

    if (url.pathname === "/verify") {
      const body = JSON.parse(init?.body ?? "{}") as {
        aud: string;
        deviceId: string;
        sig: string;
        nonce: string;
        ts: string;
      };
      const dev = registry.get(body.deviceId);
      if (!dev) return jsonRes({ ok: false, role: "none", deviceId: body.deviceId });
      const sigOk = await verifyAuth(
        dev.ecdsaPub,
        { aud: body.aud, deviceId: body.deviceId, nonce: body.nonce, ts: body.ts },
        body.sig,
      );
      const role = sigOk ? "admin" : "none";
      return jsonRes({ ok: sigOk && role === "admin", role, deviceId: body.deviceId });
    }

    return jsonRes({ error: "not-found" }, 404);
  };
  return { fetch, calls };
}

function jsonRes(obj: unknown, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async json() {
      return obj;
    },
    async text() {
      return JSON.stringify(obj);
    },
  };
}

// An in-memory localStorage-shaped shim.
function memStore(): DeviceStorage & { map: Map<string, string> } {
  const map = new Map<string, string>();
  return {
    map,
    getItem: (k) => (map.has(k) ? map.get(k)! : null),
    setItem: (k, v) => {
      map.set(k, v);
    },
  };
}

describe("loginHeaders", () => {
  it("produces signed x-ce-* headers that verifyAuth accepts", async () => {
    const device = await generateDeviceKey();
    const { fetch } = mockAuth(new Map([[device.id, device]]));

    const headers = await loginHeaders("https://auth.example", "my-app", device, { fetch });

    expect(headers["x-ce-device-id"]).toBe(device.id);
    expect(headers["x-ce-aud"]).toBe("my-app");
    expect(typeof headers["x-ce-auth"]).toBe("string");
    expect(headers["x-ce-auth"].length).toBeGreaterThan(0);
    expect(headers["x-ce-nonce"]).toMatch(/^[0-9a-f]+$/);
    expect(typeof headers["x-ce-ts"]).toBe("string");

    // The existing SDK verifyAuth accepts the signature over the canonical body.
    const ok = await verifyAuth(
      device.ecdsaPub,
      {
        aud: headers["x-ce-aud"],
        deviceId: headers["x-ce-device-id"],
        nonce: headers["x-ce-nonce"],
        ts: headers["x-ce-ts"],
      },
      headers["x-ce-auth"],
    );
    expect(ok).toBe(true);
  });

  it("tolerates a trailing slash on authBase", async () => {
    const device = await generateDeviceKey();
    const { fetch, calls } = mockAuth(new Map([[device.id, device]]));
    const headers = await loginHeaders("https://auth.example/", "app2", device, { fetch });
    expect(headers["x-ce-aud"]).toBe("app2");
    expect(calls[0]).toBe("GET /challenge");
  });

  it("throws on a non-2xx /challenge", async () => {
    const device = await generateDeviceKey();
    const fetch: FetchLike = async () => jsonRes({ error: "boom" }, 500);
    await expect(loginHeaders("https://auth.example", "app", device, { fetch })).rejects.toThrow(
      /challenge failed: 500/,
    );
  });
});

describe("verifyViaAuth", () => {
  it("round-trips: headers from loginHeaders verify ok=true role=admin", async () => {
    const device = await generateDeviceKey();
    const { fetch, calls } = mockAuth(new Map([[device.id, device]]));

    const headers = await loginHeaders("https://auth.example", "app", device, { fetch });
    const verdict = await verifyViaAuth("https://auth.example", "app", headers, { fetch });

    expect(verdict).toEqual({ ok: true, role: "admin" });
    expect(calls).toContain("POST /verify");
  });

  it("reads x-ce-* case-insensitively (as a backend reads incoming request headers)", async () => {
    const device = await generateDeviceKey();
    const { fetch } = mockAuth(new Map([[device.id, device]]));
    const headers = await loginHeaders("https://auth.example", "app", device, { fetch });
    const upper: Record<string, string> = {};
    for (const [k, v] of Object.entries(headers)) upper[k.toUpperCase()] = v;

    const verdict = await verifyViaAuth("https://auth.example", "app", upper, { fetch });
    expect(verdict.ok).toBe(true);
  });

  it("rejects an unenrolled device (ok=false role=none)", async () => {
    const enrolled = await generateDeviceKey();
    const stranger = await generateDeviceKey();
    const { fetch } = mockAuth(new Map([[enrolled.id, enrolled]]));

    const headers = await loginHeaders("https://auth.example", "app", stranger, { fetch });
    const verdict = await verifyViaAuth("https://auth.example", "app", headers, { fetch });
    expect(verdict).toEqual({ ok: false, role: "none" });
  });

  it("surfaces a closed verdict on a non-2xx /verify", async () => {
    const fetch: FetchLike = async () => jsonRes({}, 503);
    const verdict = await verifyViaAuth("https://auth.example", "app", {}, { fetch });
    expect(verdict).toEqual({ ok: false, role: "none" });
  });
});

describe("ensureDevice", () => {
  it("generates + persists on first call, reloads the SAME key on the second", async () => {
    const store = memStore();
    const first = await ensureDevice(store);
    expect(store.map.has(DEVICE_STORAGE_KEY)).toBe(true);

    const second = await ensureDevice(store);
    expect(second.id).toBe(first.id);
    expect(second.ecdsaPriv.d).toBe(first.ecdsaPriv.d);

    // The reloaded key is usable: a fresh login still verifies.
    const { fetch } = mockAuth(new Map([[second.id, second]]));
    const headers = await loginHeaders("https://auth.example", "app", second, { fetch });
    const ok = await verifyAuth(
      second.ecdsaPub,
      {
        aud: headers["x-ce-aud"],
        deviceId: headers["x-ce-device-id"],
        nonce: headers["x-ce-nonce"],
        ts: headers["x-ce-ts"],
      },
      headers["x-ce-auth"],
    );
    expect(ok).toBe(true);
  });

  it("regenerates when the stored value is malformed", async () => {
    const store = memStore();
    store.map.set(DEVICE_STORAGE_KEY, "{not valid json");
    const dk = await ensureDevice(store);
    expect(typeof dk.id).toBe("string");
    // Persisted a valid key now.
    const reloaded = await ensureDevice(store);
    expect(reloaded.id).toBe(dk.id);
  });

  it("supports async storage shims", async () => {
    const map = new Map<string, string>();
    const asyncStore: DeviceStorage = {
      getItem: async (k) => (map.has(k) ? map.get(k)! : null),
      setItem: async (k, v) => {
        map.set(k, v);
      },
    };
    const a = await ensureDevice(asyncStore);
    const b = await ensureDevice(asyncStore);
    expect(b.id).toBe(a.id);
  });
});
