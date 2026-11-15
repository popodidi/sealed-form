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
