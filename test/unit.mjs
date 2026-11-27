// Unit checks that need no dispatcher: node test/unit.mjs
import assert from "node:assert/strict";
import { tokenFrom, b64urlEncode, b64urlDecode, openSpec, checkValues, fingerprint } from "../sealed.js";

assert.equal(tokenFrom("#f=abc.def", ""), "abc.def");
assert.equal(tokenFrom("#f=abc.def&tgWebAppData=x", ""), "abc.def");
assert.equal(tokenFrom("#f=abc.def#tgWebAppData=x", ""), "abc.def");
assert.equal(tokenFrom("#tgWebAppVersion=9&f=abc.def", ""), "abc.def");
assert.equal(tokenFrom("#tgWebAppData=x", "?f=q.r"), "q.r");
assert.equal(tokenFrom("", ""), null);
const bytes = new Uint8Array([0, 1, 2, 250, 251, 255]);
assert.deepEqual(b64urlDecode(b64urlEncode(bytes)), bytes);
assert.throws(() => b64urlDecode("a+b"));

// A spec signed by a fresh key, then tampered with.
const s = globalThis.crypto.subtle;
const kp = await s.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
const raw = new Uint8Array(await s.exportKey("raw", kp.publicKey));
const spec = {
  v: 1, form: "0123456789abcdef0123456789abcdef", dispatcher: "d", pubkey: b64urlEncode(raw),
  expires: new Date(Date.now() + 60000).toISOString().replace(/\.\d+Z$/, "Z"), purpose: "p",
  target: { kind: "task", task: 1 },
  fields: [{ name: "token", type: "secret", required: true }, { name: "plan", type: "choice", choices: ["a"] }],
};
const enc = new TextEncoder().encode(JSON.stringify(spec));
const sig = new Uint8Array(await s.sign({ name: "ECDSA", hash: "SHA-256" }, kp.privateKey, enc));
const token = b64urlEncode(enc) + "." + b64urlEncode(sig);
const opened = await openSpec(token);
assert.equal(opened.fingerprint, await fingerprint(raw));
const forged = JSON.stringify({ ...spec, target: { kind: "task", task: 2 } });
await assert.rejects(openSpec(b64urlEncode(new TextEncoder().encode(forged)) + "." + b64urlEncode(sig)), /signature/);
await assert.rejects(openSpec(token, Date.now() + 120000), /expired/);
assert.match(checkValues(spec, {}), /required/);
assert.match(checkValues(spec, { token: "a\nb" }), /one line/);
assert.match(checkValues(spec, { token: "x", plan: "b" }), /choice/);
assert.equal(checkValues(spec, { token: "x", plan: "a" }), null);
console.log("unit: ok");

// Sealed messages: the vector axe seals (crates/axe/tests/fixtures/
// sealed-message-vector.txt; passphrase "correct horse battery", 1000
// iterations, expires 2096).
import { readFileSync } from "node:fs";
import { messageFrom, parseMessage, replyKey, openMessage } from "../sealed.js";
const vector = readFileSync(new URL("./message-vector.txt", import.meta.url), "utf8").trim();
assert.equal(messageFrom("#m=" + vector + "&tgWebAppData=x"), vector);
assert.equal(messageFrom("#f=abc.def"), null);
const msg = parseMessage(vector);
assert.equal(msg.header.from, "task 7");
const key = await replyKey("correct horse battery", msg.header.salt, msg.header.iter);
const now = Date.parse("2090-01-01T00:00:00Z");
const body = await openMessage(msg, key, now);
assert.deepEqual(body, { purpose: "Web login", kind: "link", link: "http://axe.example/login?code=vector" });
await assert.rejects(openMessage(msg, key, Date.parse("2097-01-01T00:00:00Z")), /expired/);
const wrong = await replyKey("wrong horse battery", msg.header.salt, msg.header.iter);
await assert.rejects(openMessage(msg, wrong, now), /wrong passphrase/);
// A header edit (a later expiry) fails the tag.
const hdr = { ...msg.header, expires: "2099-01-01T00:00:00Z" };
const forgedMsg = parseMessage(b64urlEncode(new TextEncoder().encode(JSON.stringify(hdr))) + vector.slice(vector.indexOf(".")));
await assert.rejects(openMessage(forgedMsg, key, now), /altered/);
assert.throws(() => parseMessage("nodot"));
console.log("messages: ok");

// Passkey unlock (device.js): a fake passkey whose PRF output is
// HMAC-SHA256(secret, PRF input), as an authenticator's hmac-secret.
import { replyKeyBits, importReplyKey, wrapReplyKey, unwrapReplyKey } from "../sealed.js";
import { keyId, newPrfSalt, saveWrapped, passkeyState, unlock, discard, forget, memoryStore } from "../device.js";
const fakePasskey = async (secret) => {
  const k = await s.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const calls = [];
  return {
    calls,
    get: async (cred, prfSalt) => {
      calls.push(cred);
      return new Uint8Array(await s.sign("HMAC", k, prfSalt));
    },
  };
};
const replyRaw = await replyKeyBits("correct horse battery", msg.header.salt, msg.header.iter);
assert.equal(replyRaw.length, 32);
assert.deepEqual(await openMessage(msg, await importReplyKey(replyRaw), now), body);
// Wrap/unwrap: the wrapped blob is not the key, and needs the same PRF output and key id.
const prfSalt = newPrfSalt();
const pk = await fakePasskey("device secret");
const prf = await pk.get("c1", prfSalt);
const w = await wrapReplyKey(prf, prfSalt, replyRaw, keyId(msg.header));
assert.ok(!b64urlDecode(w.wrapped).join().includes(replyRaw.join()));
assert.deepEqual(await openMessage(msg, await unwrapReplyKey(prf, prfSalt, w, keyId(msg.header)), now), body);
await assert.rejects(unwrapReplyKey(new Uint8Array(32), prfSalt, w, keyId(msg.header)), /does not open/);
await assert.rejects(unwrapReplyKey(prf, prfSalt, w, "other:1000"), /does not open/);
// The reply key stays non-extractable.
await assert.rejects(s.exportKey("raw", await unwrapReplyKey(prf, prfSalt, w, keyId(msg.header))));

// Store flow: none -> save -> ready -> unlock -> opens.
const passkeys = memoryStore();
assert.equal(await passkeyState(passkeys, msg.header), "none");
assert.equal(await unlock(passkeys, msg.header, pk), null);
const entry = await saveWrapped(passkeys, msg.header, replyRaw, "c1", prfSalt, prf);
assert.equal(JSON.stringify(entry).includes(b64urlEncode(replyRaw)), false);
assert.equal(JSON.stringify(entry).includes(b64urlEncode(prf)), false);
assert.equal(await passkeyState(passkeys, msg.header), "ready");
assert.deepEqual(await openMessage(msg, await unlock(passkeys, msg.header, pk), now), body);
assert.deepEqual(pk.calls.slice(-1), ["c1"]);
// A different passkey (wrong PRF output): no key, the entry is dropped, passphrase next.
const other = await fakePasskey("another device");
assert.equal(await unlock(passkeys, msg.header, other), null);
assert.equal(await passkeyState(passkeys, msg.header), "none");
// A cancelled prompt keeps the entry.
await saveWrapped(passkeys, msg.header, replyRaw, "c1", prfSalt, prf);
const cancel = { get: async () => { throw Object.assign(new Error("cancelled"), { name: "NotAllowedError" }); } };
await assert.rejects(unlock(passkeys, msg.header, cancel), /cancelled/);
assert.equal(await passkeyState(passkeys, msg.header), "ready");
// A changed reply key (new salt): the old entry is stale and deleted.
const rotated = { ...msg.header, salt: "QUFBQUFBQUFBQUFBQUFBQQ" };
assert.equal(await passkeyState(passkeys, rotated), "stale");
assert.deepEqual(await passkeys.keys(), []);
assert.equal(await unlock(passkeys, rotated, pk), null);
// Unwrapped but the message does not open: discard drops it.
await saveWrapped(passkeys, msg.header, replyRaw, "c1", prfSalt, prf);
await discard(passkeys, msg.header);
assert.equal(await passkeyState(passkeys, msg.header), "none");
// Forget this device: every saved key in every store.
const saved = memoryStore();
await saved.put(keyId(msg.header), await importReplyKey(replyRaw));
await saveWrapped(passkeys, msg.header, replyRaw, "c1", prfSalt, prf);
assert.equal(await forget(saved, passkeys), 2);
assert.deepEqual([...(await saved.keys()), ...(await passkeys.keys())], []);
assert.equal(await unlock(passkeys, msg.header, pk), null);
assert.equal(await forget(saved, passkeys), 0);
console.log("passkeys: ok");
