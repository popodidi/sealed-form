// What this device keeps to open sealed messages without the passphrase:
// reply keys wrapped to a passkey (WebAuthn PRF, see sealed.js). Storage is
// any async {get, put, delete, keys}; the page uses IndexedDB, the tests a Map.
// An entry is {v, cred, prfSalt, iv, wrapped, created}, keyed by the reply
// key id, and holds neither the reply key nor the PRF output.
import { b64urlDecode, b64urlEncode, wrapReplyKey, unwrapReplyKey } from "./sealed.js";

export const ENTRY_VERSION = 1;

/** A message header's reply key id: a new reply key has a new salt. */
export const keyId = (header) => header.salt + ":" + header.iter;

/** A fresh PRF input for a new passkey entry. */
export const newPrfSalt = () => globalThis.crypto.getRandomValues(new Uint8Array(32));

/** Wraps the reply key `raw` (32 bytes) to the passkey `cred` and stores it. */
export async function saveWrapped(store, header, raw, cred, prfSalt, prf) {
  const id = keyId(header);
  const entry = {
    v: ENTRY_VERSION,
    cred,
    prfSalt: b64urlEncode(prfSalt),
    ...(await wrapReplyKey(prf, prfSalt, raw, id)),
    created: new Date().toISOString(),
  };
  await store.put(id, entry);
  return entry;
}

/**
 * "ready" when this device has a passkey entry for the header's reply key,
 * "stale" when it had entries only for other reply keys (the reply key was
 * changed; they are deleted), else "none".
 */
export async function passkeyState(store, header) {
  const id = keyId(header);
  const keys = await store.keys();
  if (keys.includes(id)) {
    const e = await store.get(id);
    if (e && e.v === ENTRY_VERSION) return "ready";
  }
  if (keys.length === 0) return "none";
  for (const k of keys) await store.delete(k);
  return "stale";
}

/**
 * Asks the passkey (`passkey.get(cred, prfSalt)` -> PRF output) and unwraps
 * the reply key. Returns the key, or null when there is no entry or it no
 * longer opens (the entry is deleted). Passkey errors, such as the owner
 * cancelling, are thrown and keep the entry.
 */
export async function unlock(store, header, passkey) {
  const id = keyId(header);
  const entry = await store.get(id);
  if (!entry) return null;
  const prfSalt = b64urlDecode(entry.prfSalt);
  const prf = await passkey.get(entry.cred, prfSalt);
  try {
    return await unwrapReplyKey(prf, prfSalt, entry, id);
  } catch (_) {
    await store.delete(id);
    return null;
  }
}

/** Drops the entry for the header's reply key (it unwrapped but did not open the message). */
export async function discard(store, header) {
  await store.delete(keyId(header));
}

/** Forget this device: deletes every entry in every store; returns how many. */
export async function forget(...stores) {
  let n = 0;
  for (const s of stores) {
    for (const k of await s.keys()) {
      await s.delete(k);
      n++;
    }
  }
  return n;
}

/** An in-memory store (tests, and the page when IndexedDB is unavailable). */
export function memoryStore() {
  const m = new Map();
  return {
    get: async (k) => m.get(k) ?? null,
    put: async (k, v) => void m.set(k, v),
    delete: async (k) => void m.delete(k),
    keys: async () => [...m.keys()],
  };
}
