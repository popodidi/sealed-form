// Sealed form crypto: verifies a signed form spec and seals values to the
// form's public key. Plain WebCrypto, no dependencies; runs in browsers and
// in Node 20+ (globalThis.crypto).
//
// Spec link fragment: f=<base64url spec JSON>.<base64url ECDSA P-256 SHA-256
// signature (r||s)> over the exact spec bytes.
// Sealed reply: sealed.v1.<form>.<base64url(ephemeral public key (65) | iv (12)
// | AES-256-GCM ciphertext and tag)>. The AES key is HKDF-SHA256 of the ECDH
// P-256 shared secret, salt = ephemeral public key | form public key,
// info = "sealed-form v1"; associated data = "<form>|<dispatcher>|<expires>".

export const PREFIX = "sealed.v1.";
export const VERSION = 1;
const INFO = new TextEncoder().encode("sealed-form v1");
const subtle = globalThis.crypto.subtle;

export function b64urlDecode(s) {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new Error("not base64url");
  const pad = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
  const bin = atob(pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function b64urlEncode(bytes) {
  return b64Encode(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64Encode(bytes) {
  let bin = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(bin);
}

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

/** The `f=` token from a URL's fragment or, as a fallback, its query. */
export function tokenFrom(hash, search) {
  for (const src of [hash || "", search || ""]) {
    for (const part of src.replace(/^[#?]/, "").split(/[#&]/)) {
      if (part.startsWith("f=")) return decodeURIComponent(part.slice(2));
    }
  }
  return null;
}

/** SHA256: and the first 16 bytes of the key's SHA-256, in groups of four hex digits. */
export async function fingerprint(rawKey) {
  const d = new Uint8Array(await subtle.digest("SHA-256", rawKey)).slice(0, 16);
  const groups = [];
  for (let i = 0; i < 16; i += 2) {
    groups.push(((d[i] << 8) | d[i + 1]).toString(16).padStart(4, "0"));
  }
  return "SHA256:" + groups.join(" ");
}

const KINDS = ["secret", "text", "code", "choice", "file"];

/**
 * Checks the token's signature against the key it names and the form's
 * shape; returns {spec, rawKey, fingerprint}. Throws on any mismatch.
 */
export async function openSpec(token, now = Date.now()) {
  const dot = token.indexOf(".");
  if (dot < 0) throw new Error("the link has no signature");
  const bytes = b64urlDecode(token.slice(0, dot));
  const sig = b64urlDecode(token.slice(dot + 1));
  const spec = JSON.parse(new TextDecoder().decode(bytes));
  if (spec.v !== VERSION) throw new Error("unsupported form version " + spec.v);
  if (!/^[0-9a-f]{32}$/.test(spec.form)) throw new Error("invalid form id");
  const rawKey = b64urlDecode(spec.pubkey);
  const verifyKey = await subtle.importKey(
    "raw", rawKey, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  const ok = await subtle.verify({ name: "ECDSA", hash: "SHA-256" }, verifyKey, sig, bytes);
  if (!ok) throw new Error("the form's signature does not match its key");
  const expires = Date.parse(spec.expires);
  if (!Number.isFinite(expires)) throw new Error("invalid expiry");
  if (now > expires) throw new Error("this form expired at " + spec.expires);
  if (!Array.isArray(spec.fields) || spec.fields.length === 0) throw new Error("the form has no fields");
  for (const f of spec.fields) {
    if (!/^[a-z][a-z0-9_]{0,31}$/.test(f.name) || !KINDS.includes(f.type)) {
      throw new Error("invalid field " + JSON.stringify(f.name));
    }
  }
  return { spec, rawKey, fingerprint: await fingerprint(rawKey), expires };
}

/** Encrypts `values` (an object) to the spec; returns the sealed reply text. */
export async function seal(spec, rawKey, values) {
  const recipient = await subtle.importKey(
    "raw", rawKey, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const eph = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  const ephRaw = new Uint8Array(await subtle.exportKey("raw", eph.publicKey));
  const shared = await subtle.deriveBits({ name: "ECDH", public: recipient }, eph.privateKey, 256);
  const ikm = await subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  const key = await subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: concat(ephRaw, rawKey), info: INFO },
    ikm, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const aad = new TextEncoder().encode(`${spec.form}|${spec.dispatcher}|${spec.expires}`);
  const plain = new TextEncoder().encode(JSON.stringify(values));
  const ct = new Uint8Array(await subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aad }, key, plain));
  return PREFIX + spec.form + "." + b64urlEncode(concat(ephRaw, iv, ct));
}

/** Checks values against the fields before sealing; returns an error or null. */
export function checkValues(spec, values) {
  const enc = new TextEncoder();
  for (const f of spec.fields) {
    const v = values[f.name];
    const empty = v === undefined || v === null || v === "";
    if (empty) {
      if (f.required) return `${f.label || f.name} is required`;
      continue;
    }
    const max = f.max ?? { secret: 4096, text: 1024, code: 64, choice: 64, file: 2048 }[f.type];
    const size = f.type === "file" ? v.size : enc.encode(v).length;
    if (size > max) return `${f.label || f.name} is over ${max} bytes`;
    if (f.type === "choice" && !f.choices.includes(v)) return `${f.label || f.name}: pick a choice`;
    if (f.type !== "text" && f.type !== "file" && /[\r\n\0]/.test(v)) {
      return `${f.label || f.name}: one line only`;
    }
  }
  return null;
}

// ---------------------------------------------------------------- messages
//
// Sealed messages go the other way: a dispatcher sends the owner a secret,
// a link or a small file. Link fragment: m=<base64url header JSON>.<base64url
// iv (12) | AES-256-GCM ciphertext and tag>. The AES key is PBKDF2-HMAC-SHA256
// of the owner's passphrase with the header's salt and iteration count; the
// associated data is the header's base64url text exactly as in the link.

export const MESSAGE_VERSION = 1;
const KINDS_OUT = ["secret", "link", "file"];

/** The `m=` message text from a URL's fragment, or null. */
export function messageFrom(hash) {
  for (const part of (hash || "").replace(/^#/, "").split(/[#&]/)) {
    if (part.startsWith("m=")) return decodeURIComponent(part.slice(2));
  }
  return null;
}

/** Splits and checks a message's header (authenticated only on opening). */
export function parseMessage(text) {
  const dot = text.indexOf(".");
  if (dot < 0) throw new Error("not a sealed message");
  const aad = text.slice(0, dot);
  const data = b64urlDecode(text.slice(dot + 1));
  const header = JSON.parse(new TextDecoder().decode(b64urlDecode(aad)));
  if (header.v !== MESSAGE_VERSION) throw new Error("unsupported message version " + header.v);
  if (!/^[0-9a-f]{32}$/.test(header.id)) throw new Error("invalid message id");
  if (!/^[A-Za-z0-9_-]{16,64}$/.test(header.salt)) throw new Error("invalid key salt");
  if (!Number.isInteger(header.iter) || header.iter < 1 || header.iter > 10000000) {
    throw new Error("invalid key iteration count");
  }
  const expires = Date.parse(header.expires);
  if (!Number.isFinite(expires)) throw new Error("invalid expiry");
  if (data.length <= 12 + 16) throw new Error("truncated message");
  return { header, aad, data, expires };
}

/** The AES key from the passphrase (non-extractable, decrypt only). */
export async function replyKey(passphrase, salt, iter) {
  return importReplyKey(await replyKeyBits(passphrase, salt, iter));
}

/** The reply key's 32 bytes from the passphrase, for wrapping to a passkey. */
export async function replyKeyBits(passphrase, salt, iter) {
  const base = await subtle.importKey(
    "raw", new TextEncoder().encode(passphrase), "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: b64urlDecode(salt), iterations: iter }, base, 256));
}

/** The reply key's bytes as a non-extractable, decrypt-only AES key. */
export function importReplyKey(raw) {
  return subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["decrypt"]);
}

// Passkey unlock: a passkey's WebAuthn PRF output (32 bytes, never stored)
// wraps the reply key on this device. Wrapping key: HKDF-SHA256(PRF output,
// salt = the entry's PRF input, info WRAP_INFO); the reply key is
// AES-256-GCM encrypted under it, the key id ("<salt>:<iter>" of the
// message header) as associated data, so a wrapped key opens only for the
// reply key it was made for.

const WRAP_INFO = new TextEncoder().encode("sealed-form passkey v1");

async function wrappingKey(prf, prfSalt, usage) {
  const ikm = await subtle.importKey("raw", prf, "HKDF", false, ["deriveKey"]);
  return subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: prfSalt, info: WRAP_INFO },
    ikm, { name: "AES-GCM", length: 256 }, false, [usage]);
}

/** Wraps the reply key `raw` under a PRF output; returns {iv, wrapped} (base64url). */
export async function wrapReplyKey(prf, prfSalt, raw, keyId) {
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const ct = await subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: new TextEncoder().encode(keyId) },
    await wrappingKey(prf, prfSalt, "encrypt"), raw);
  return { iv: b64urlEncode(iv), wrapped: b64urlEncode(new Uint8Array(ct)) };
}

/** Unwraps to the non-extractable reply key; throws on a wrong PRF output or key id. */
export async function unwrapReplyKey(prf, prfSalt, entry, keyId) {
  let raw;
  try {
    raw = await subtle.decrypt(
      { name: "AES-GCM", iv: b64urlDecode(entry.iv), additionalData: new TextEncoder().encode(keyId) },
      await wrappingKey(prf, prfSalt, "decrypt"), b64urlDecode(entry.wrapped));
  } catch (_) {
    throw new Error("this passkey does not open this reply key");
  }
  return importReplyKey(new Uint8Array(raw));
}

/**
 * Opens a parsed message with `key`; returns the body {purpose, kind, ...}.
 * Throws past the expiry or when the key or any byte is wrong.
 */
export async function openMessage(msg, key, now = Date.now()) {
  if (now > msg.expires) throw new Error("this message expired at " + msg.header.expires);
  let plain;
  try {
    plain = await subtle.decrypt(
      { name: "AES-GCM", iv: msg.data.subarray(0, 12), additionalData: new TextEncoder().encode(msg.aad) },
      key, msg.data.subarray(12));
  } catch (_) {
    throw new Error("wrong passphrase, or the message was altered");
  }
  const body = JSON.parse(new TextDecoder().decode(plain));
  if (!KINDS_OUT.includes(body.kind)) throw new Error("unknown message kind");
  if (body.kind === "link" && !/^https?:\/\//.test(body.link)) throw new Error("not a web link");
  return body;
}
