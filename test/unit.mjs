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
// Format checks: the same words as the dispatcher's (axe sealed.rs
// `field_checks_name_the_problem`), never the value.
import { formatProblem, fieldProblem } from "../sealed.js";
const c = { prefix: "sk-", min: 10, max: 20, chars: "nospace" };
assert.equal(formatProblem(c, "sk-abcdefgh"), null);
assert.equal(formatProblem(c, "sk-abc  defgh"), "contains 2 spaces: likely a wrapped line");
assert.equal(formatProblem(c, "sk-abc\ndefgh"), "contains 1 line break: likely a wrapped line");
assert.equal(formatProblem(c, " sk-abcdefgh"), "contains 1 space at the start or end");
assert.equal(formatProblem(c, "sk-ab\tc defgh"), "contains 2 whitespace characters: likely a wrapped line");
assert.equal(formatProblem(c, "pk-abcdefgh"), "must start with sk-");
assert.equal(formatProblem(c, "sk-a"), "is too short (4 characters; expected at least 10)");
assert.equal(formatProblem(c, "sk-" + "a".repeat(30)), "is too long (33 characters; expected at most 20)");
const digits = { min: 6, max: 6, chars: "digits" };
assert.equal(formatProblem(digits, "123456"), null);
assert.equal(formatProblem(digits, "12a456"), "must be digits only");
assert.equal(formatProblem(digits, "12345"), "is 5 characters; expected 6");
assert.equal(formatProblem(digits, "123 456"), "contains 1 space: likely a wrapped line");
// Without chars, whitespace is fine (a passphrase); no check, no problem.
assert.equal(formatProblem({ min: 3 }, "a b c"), null);
assert.equal(formatProblem(undefined, " x "), null);
// Length counts characters, not bytes or UTF-16 units.
assert.equal(formatProblem({ min: 2, max: 2 }, "\u{1F600}\u{1F600}"), null);
// A setup-token from a wrapped terminal line: the field's label leads.
const tok = { name: "secret", label: "setup-token token", type: "secret", required: true,
  check: { prefix: "sk-ant-oat01-", min: 90, max: 256, chars: "nospace" } };
const good = "sk-ant-oat01-" + "x".repeat(95);
assert.equal(fieldProblem(tok, good), null);
assert.equal(fieldProblem(tok, good.slice(0, 50) + " " + good.slice(50, 90) + " " + good.slice(90)),
  "setup-token token contains 2 spaces: likely a wrapped line");
assert.equal(fieldProblem(tok, ""), "setup-token token is required");
assert.match(checkValues({ fields: [tok] }, { secret: "sk-ant-api03-" + "x".repeat(95) }), /must start with sk-ant-oat01-$/);
// The size and one-line checks still apply; a check never fires on an empty optional field.
assert.equal(fieldProblem({ name: "n", type: "code", check: { chars: "digits" } }, ""), null);
assert.equal(fieldProblem({ name: "n", type: "code" }, "a\nb"), "n: one line only");
// A spec with a malformed check is refused.
const badSpec = { ...spec, fields: [{ name: "t", type: "secret", check: { regex: "x" } }] };
const badEnc = new TextEncoder().encode(JSON.stringify(badSpec));
const badSig = new Uint8Array(await s.sign({ name: "ECDSA", hash: "SHA-256" }, kp.privateKey, badEnc));
await assert.rejects(openSpec(b64urlEncode(badEnc) + "." + b64urlEncode(badSig)), /invalid check/);
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
