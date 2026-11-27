// The browser's passkey (WebAuthn) with the PRF extension, for device.js.
// There is no server: the challenge is random and unchecked, because the
// page uses only the PRF output, which the authenticator gives after user
// verification (Face ID, Touch ID or the device PIN). The passkey's relying
// party is this page's host.
import { b64urlDecode, b64urlEncode } from "./sealed.js";

const rand = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));

/** True when this browser offers a platform passkey and does not rule out PRF. */
export async function passkeySupported() {
  const P = globalThis.PublicKeyCredential;
  if (!P || !globalThis.navigator || !navigator.credentials) return false;
  try {
    if (typeof P.getClientCapabilities === "function") {
      const c = await P.getClientCapabilities();
      if (c["extension:prf"] === false || c.userVerifyingPlatformAuthenticator === false) return false;
    }
    return await P.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch (_) {
    return false;
  }
}

function prfFirst(cred) {
  const r = cred.getClientExtensionResults().prf;
  return r && r.results && r.results.first ? new Uint8Array(r.results.first) : null;
}

/**
 * Registers a passkey asking for PRF on `prfSalt`. Returns {cred, prf}; `prf`
 * is null when the browser gives PRF output only on sign-in (then call get).
 */
export async function createPasskey(prfSalt) {
  const cred = await navigator.credentials.create({
    publicKey: {
      rp: { name: "Sealed messages" },
      user: { id: rand(16), name: "Sealed messages", displayName: "Sealed messages" },
      challenge: rand(32),
      pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
      authenticatorSelection: {
        authenticatorAttachment: "platform", residentKey: "preferred", userVerification: "required",
      },
      attestation: "none",
      extensions: { prf: { eval: { first: prfSalt } } },
    },
  });
  const ext = cred.getClientExtensionResults().prf;
  if (!ext || ext.enabled === false) {
    throw new Error("This passkey cannot derive a key here (no PRF support). Keep using the passphrase.");
  }
  return { cred: b64urlEncode(new Uint8Array(cred.rawId)), prf: prfFirst(cred) };
}

/** Asks the passkey `cred` for its PRF output on `prfSalt`. */
export async function passkeyPrf(cred, prfSalt) {
  const a = await navigator.credentials.get({
    publicKey: {
      challenge: rand(32),
      allowCredentials: [{ type: "public-key", id: b64urlDecode(cred) }],
      userVerification: "required",
      extensions: { prf: { eval: { first: prfSalt } } },
    },
  });
  const prf = prfFirst(a);
  if (!prf) throw new Error("The passkey gave no key (no PRF support here). Use the passphrase.");
  return prf;
}

export const passkey = { get: passkeyPrf };
