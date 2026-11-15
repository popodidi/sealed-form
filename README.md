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

Everything is in [`sealed.js`](sealed.js) (crypto) and [`app.js`](app.js)
(page). There is no build step and no third-party script, and the CSP allows
no network connections.

`node test/unit.mjs` runs the checks that need no issuer.

Licensed under MIT or Apache-2.0, at your option.
