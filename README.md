# sealed-form

A static page that encrypts form input in the browser to a public key named
in the link, so the server, the chat and this page's host relay only
ciphertext. Any tool that can sign a form spec and decrypt the reply can use
it; [axe](https://github.com/popodidi/axe) (`axe form ask`) does.

- **Link.** `https://popodidi.github.io/sealed-form/#f=<spec>.<sig>`: a base64url
  JSON spec and its ECDSA P-256 SHA-256 signature (r||s) by the key in the
  spec. The fragment is never sent to the page's host.
- **Checks.** The signature, the expiry and each field's shape. The page shows
  the key's fingerprint and remembers it per issuer, warning if it changes.
- **Sealing.** Ephemeral ECDH P-256, HKDF-SHA256 (salt: ephemeral then
  recipient public key, info `sealed-form v1`), AES-256-GCM with
  `<form>|<dispatcher>|<expires>` as associated data. The reply is
  `sealed.v1.<form>.<base64url(ephemeral key | iv | ciphertext)>`.
- **Return.** Opened from a Telegram reply-keyboard Mini App button, it sends
  the reply as `web_app_data` (up to 4096 bytes) through the client's bridge.
  Anywhere else it shows the reply to copy, or to download as a `.sealed` file.

- **Messages.** The reverse: `#m=<header>.<iv | ciphertext>` opens a message
  a dispatcher sealed to the owner (a secret, a link to open with one tap, or
  a small file). The page asks for the owner's passphrase, derives the key
  (PBKDF2-HMAC-SHA256 with the header's salt and count) and decrypts with
  AES-256-GCM, the header as associated data. It refuses a message past its
  expiry, can remember the derived key (non-extractable, IndexedDB) and warns
  when a message was opened on this device before.
- **Passkey unlock.** After a passphrase unlock, where the browser has a
  platform passkey with the WebAuthn PRF extension (Safari on iOS 18+), the
  page offers "Use Face ID next time": it registers a passkey for this host,
  derives a wrapping key from the passkey's PRF output (HKDF-SHA256, info
  `sealed-form passkey v1`) and stores only the key wrapped under it
  (AES-256-GCM, the reply key id `<salt>:<iter>` as associated data) in
  IndexedDB ([`device.js`](device.js), [`passkey.js`](passkey.js)). Later
  opens take one passkey prompt. The PRF output and the key never leave the
  device. A new reply key (new salt) makes the stored entry stale: the page
  deletes it and asks for the passphrase, which always stays the recovery
  path. "Forget this device" deletes every saved key (the passkey itself stays
  in the device's password manager). In-app browsers without passkeys (the
  Telegram Mini App on iOS) offer to open the message in the system browser.

Everything is in [`sealed.js`](sealed.js) (crypto) and [`app.js`](app.js)
(page). There is no build step and no third-party script, and the CSP allows
no network connections.

`node test/unit.mjs` runs the checks that need no issuer.

Licensed under MIT or Apache-2.0, at your option.
