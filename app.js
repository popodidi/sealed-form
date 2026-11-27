// The form page: reads the signed spec from the link, renders its fields,
// seals the values in this browser and hands back only the sealed reply.
// No third-party script runs here: the Telegram return path uses the
// client's own bridge (web_app_data_send) directly.
import {
  tokenFrom, openSpec, seal, checkValues, b64Encode, b64urlDecode,
  messageFrom, parseMessage, replyKeyBits, importReplyKey, openMessage,
} from "./sealed.js";
import { keyId, newPrfSalt, saveWrapped, passkeyState, unlock, discard, forget, memoryStore } from "./device.js";
import { passkeySupported, createPasskey, passkey } from "./passkey.js";

const TG_LIMIT = 4096;
const $ = (id) => document.getElementById(id);

function show(id) {
  for (const s of document.querySelectorAll("main > section")) s.hidden = s.id !== id;
}

function fail(msg) {
  $("error-text").textContent = msg;
  show("error");
}

/** The Telegram client bridge, when this page runs as a Mini App. */
function telegram() {
  const w = window;
  const inApp = /tgWebApp(Data|Version|Platform)=/.test(location.hash + location.search);
  if (w.TelegramWebviewProxy && typeof w.TelegramWebviewProxy.postEvent === "function") {
    return (type, data) => w.TelegramWebviewProxy.postEvent(type, JSON.stringify(data));
  }
  if (w.external && "notify" in w.external) {
    return (type, data) => w.external.notify(JSON.stringify({ eventType: type, eventData: data }));
  }
  if (inApp && w.parent !== w) {
    return (type, data) =>
      w.parent.postMessage(JSON.stringify({ eventType: type, eventData: data }), "https://web.telegram.org");
  }
  return null;
}

/** Remembers each dispatcher's key; returns "new", "same" or the old fingerprint. */
function trust(dispatcher, fp) {
  const k = "sealed-form:key:" + dispatcher;
  let old = null;
  try {
    old = localStorage.getItem(k);
    if (!old) localStorage.setItem(k, fp);
  } catch (_) {
    return "unknown";
  }
  if (!old) return "new";
  return old === fp ? "same" : old;
}

function input(f) {
  let el;
  if (f.type === "text") {
    el = document.createElement("textarea");
    el.rows = 3;
  } else if (f.type === "choice") {
    el = document.createElement("select");
    const none = document.createElement("option");
    none.value = "";
    none.textContent = f.required ? "Choose" : "None";
    el.append(none);
    for (const c of f.choices) {
      const o = document.createElement("option");
      o.value = c;
      o.textContent = c;
      el.append(o);
    }
  } else {
    el = document.createElement("input");
    el.type = f.type === "secret" ? "password" : f.type === "file" ? "file" : "text";
    if (f.type === "code") {
      el.autocomplete = "one-time-code";
      el.inputMode = "text";
    } else if (f.type === "secret") {
      el.autocomplete = "off";
    }
    el.spellcheck = false;
    el.autocapitalize = "off";
  }
  el.id = "field-" + f.name;
  el.name = f.name;
  el.required = !!f.required;
  return el;
}

async function readFile(file) {
  const buf = new Uint8Array(await file.arrayBuffer());
  return { name: file.name, data: b64Encode(buf) };
}

// --- sealed messages: decrypt a message from the dispatcher (#m=) ---

const KEY_DB = "sealed-form";
const STORES = ["keys", "passkeys"];

/**
 * An IndexedDB object store as an async {get, put, delete, keys}: "keys"
 * holds remembered (non-extractable) reply keys, "passkeys" reply keys
 * wrapped to a passkey (device.js), both by reply key id.
 */
function idbStore(name) {
  const run = (mode, fn) => new Promise((resolve, reject) => {
    let req;
    try {
      req = indexedDB.open(KEY_DB, 2);
    } catch (e) {
      return reject(e);
    }
    req.onupgradeneeded = () => {
      for (const s of STORES) if (!req.result.objectStoreNames.contains(s)) req.result.createObjectStore(s);
    };
    req.onerror = () => reject(req.error);
    req.onsuccess = () => {
      try {
        const tx = req.result.transaction(name, mode);
        const r = fn(tx.objectStore(name));
        tx.oncomplete = () => resolve(r && "result" in r ? r.result : undefined);
        tx.onerror = () => reject(tx.error);
      } catch (e) {
        reject(e);
      }
    };
  });
  return {
    get: (k) => run("readonly", (s) => s.get(k)).then((v) => v ?? null),
    put: (k, v) => run("readwrite", (s) => s.put(v, k)),
    delete: (k) => run("readwrite", (s) => s.delete(k)),
    keys: () => run("readonly", (s) => s.getAllKeys()).then((v) => v || []),
  };
}

/** The store, or an in-memory one when this browser keeps no IndexedDB. */
async function deviceStore(name) {
  const s = idbStore(name);
  try {
    await s.keys();
    return s;
  } catch (_) {
    return memoryStore();
  }
}

/** Records an opened message id; returns when it was opened before, or null. */
function seen(id) {
  const k = "sealed-form:opened:" + id;
  try {
    const before = localStorage.getItem(k);
    if (!before) localStorage.setItem(k, new Date().toISOString());
    return before;
  } catch (_) {
    return null;
  }
}

function showBody(header, body, tg) {
  $("shown-purpose").textContent = body.purpose || "Sealed message";
  $("shown-from").textContent = "From " + header.from;
  const before = seen(header.id);
  $("shown-note").textContent = before
    ? `You opened this message on this device before (${new Date(before).toLocaleString()}).`
    : "";
  if (body.kind === "secret") {
    const v = $("secret-value");
    v.value = body.secret;
    $("secret-show").addEventListener("click", () => {
      v.type = v.type === "password" ? "text" : "password";
      $("secret-show").textContent = v.type === "password" ? "Show" : "Hide";
    });
    $("secret-copy").addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(v.value);
        $("secret-copy").textContent = "Copied";
      } catch (_) {
        v.type = "text";
        v.select();
      }
    });
    $("shown-secret").hidden = false;
  } else if (body.kind === "link") {
    const a = $("link-open");
    a.href = body.link;
    if (tg) {
      a.addEventListener("click", (ev) => {
        ev.preventDefault();
        tg("web_app_open_link", { url: body.link });
      });
    }
    $("shown-link").hidden = false;
  } else {
    const bytes = b64urlDecode(body.file.data.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""));
    const a = $("file-download");
    a.href = URL.createObjectURL(new Blob([bytes], { type: "application/octet-stream" }));
    a.download = body.file.name || "file";
    a.textContent = "Download " + a.download;
    $("shown-file").hidden = false;
  }
  show("shown");
}

/** After a passphrase unlock: offers to wrap the reply key `raw` to a passkey. */
function offerPasskey(passkeys, header, raw) {
  const btn = $("enroll-button");
  const note = $("enroll-note");
  let pending = null; // {cred, prfSalt} when the passkey exists but gave no PRF output yet
  const done = async (cred, prfSalt, prf) => {
    await saveWrapped(passkeys, header, raw, cred, prfSalt, prf);
    raw.fill(0);
    btn.hidden = true;
    note.textContent = "Done. Next time, open with Face ID; the passphrase still works.";
    $("forget-device").hidden = false;
  };
  btn.addEventListener("click", async () => {
    btn.disabled = true;
    note.textContent = "";
    try {
      if (pending) {
        await done(pending.cred, pending.prfSalt, await passkey.get(pending.cred, pending.prfSalt));
        return;
      }
      const prfSalt = newPrfSalt();
      const { cred, prf } = await createPasskey(prfSalt);
      if (prf) return await done(cred, prfSalt, prf);
      pending = { cred, prfSalt };
      try {
        await done(cred, prfSalt, await passkey.get(cred, prfSalt));
      } catch (e) {
        if (e.name !== "NotAllowedError") throw e;
        btn.textContent = "Confirm with Face ID";
        note.textContent = "Passkey made. Confirm once to finish.";
      }
    } catch (e) {
      note.textContent = e.name === "NotAllowedError" ? "Cancelled." : e.message;
    } finally {
      btn.disabled = false;
    }
  });
  $("enroll").hidden = false;
}

async function messageMain(text, tg) {
  let msg;
  try {
    msg = parseMessage(text);
  } catch (e) {
    return fail(e.message);
  }
  const { header } = msg;
  if (Date.now() > msg.expires) return fail("This message expired at " + new Date(msg.expires).toLocaleString() + ".");
  if (tg) {
    tg("web_app_ready", {});
    tg("web_app_expand", {});
  }
  // Mini App webviews (Telegram) lack passkeys for this host even where the
  // API is present: send the owner to the system browser instead.
  const [keys, passkeys, supported] = await Promise.all([
    deviceStore("keys"), deviceStore("passkeys"), tg ? false : passkeySupported(),
  ]);
  $("forget-device").addEventListener("click", async () => {
    const n = await forget(keys, passkeys);
    $("forget-device").hidden = true;
    $("enroll").hidden = true;
    $("msg-passkey").hidden = true;
    const out = n
      ? "This device forgot its saved keys. The passkey itself stays in your passwords app; delete it there if you like."
      : "Nothing was saved on this device.";
    $("shown-note").textContent = out;
    $("msg-note").textContent = out;
  });
  const showForget = async () => {
    $("forget-device").hidden = (await keys.keys()).length + (await passkeys.keys()).length === 0;
  };
  const open = async (key) => showBody(header, await openMessage(msg, key), tg);

  const remembered = await keys.get(keyId(header));
  if (remembered) {
    try {
      await open(remembered);
      return showForget();
    } catch (_) {
      await keys.delete(keyId(header)); // a replaced reply key
    }
  }
  const state = await passkeyState(passkeys, header);
  $("msg-from").textContent = "From " + header.from;
  $("msg-expires").textContent = new Date(msg.expires).toLocaleString();
  show("message");
  await showForget();
  if (state === "stale") {
    $("msg-passkey-note").textContent = "Your reply key changed since Face ID was set up here. Enter the passphrase.";
  } else if (state === "none" && tg) {
    const b = $("msg-browser");
    b.hidden = false;
    b.addEventListener("click", () => {
      tg("web_app_open_link", { url: location.origin + location.pathname + "#m=" + text });
    });
  }
  if (state === "ready") {
    const b = $("msg-passkey");
    b.hidden = false;
    b.focus();
    b.addEventListener("click", async () => {
      $("msg-error").textContent = "";
      b.disabled = true;
      try {
        const key = await unlock(passkeys, header, passkey);
        if (key) {
          try {
            return await open(key);
          } catch (_) {
            await discard(passkeys, header);
          }
        }
        b.hidden = true;
        $("msg-passkey-note").textContent = "Face ID no longer opens this reply key. Enter the passphrase.";
        await showForget();
      } catch (e) {
        $("msg-error").textContent = e.name === "NotAllowedError" ? "Face ID was cancelled. Try again or use the passphrase." : e.message;
      } finally {
        b.disabled = false;
      }
    });
  } else {
    $("msg-pass").focus();
  }
  $("msg-open").addEventListener("click", async (ev) => {
    ev.preventDefault();
    $("msg-error").textContent = "";
    $("msg-open").disabled = true;
    $("msg-note").textContent = "Opening...";
    try {
      const raw = await replyKeyBits($("msg-pass").value, header.salt, header.iter);
      $("msg-pass").value = "";
      const key = await importReplyKey(raw);
      const body = await openMessage(msg, key);
      if ($("msg-remember").checked) await keys.put(keyId(header), key);
      showBody(header, body, tg);
      if (supported && state !== "ready" && !$("msg-remember").checked) offerPasskey(passkeys, header, raw);
      else raw.fill(0);
      await showForget();
    } catch (e) {
      $("msg-error").textContent = e.message;
    } finally {
      $("msg-open").disabled = false;
      $("msg-note").textContent = "";
    }
  });
}

async function main() {
  const message = messageFrom(location.hash);
  if (message) {
    const tg = telegram();
    // The ciphertext stays out of history.
    history.replaceState(null, "", location.pathname);
    return messageMain(message, tg);
  }
  const token = tokenFrom(location.hash, location.search);
  // The spec stays out of history and any later navigation.
  if (location.hash) history.replaceState(null, "", location.pathname);
  if (!token) return fail("This page opens from a sealed form link.");
  let opened;
  try {
    opened = await openSpec(token);
  } catch (e) {
    return fail(e.message);
  }
  const { spec, rawKey, fingerprint } = opened;
  $("purpose").textContent = spec.purpose;
  $("from").textContent = spec.from ? "Asked by " + spec.from : "";
  $("fingerprint").textContent = fingerprint;
  $("expires").textContent = new Date(opened.expires).toLocaleString();
  const t = trust(spec.dispatcher, fingerprint);
  const note = $("key-note");
  if (t === "new") {
    note.textContent = "First form from this dispatcher on this device. Compare the key once with the one your dispatcher shows.";
  } else if (t === "same") {
    note.textContent = "Same key as before.";
  } else if (t === "unknown") {
    note.textContent = "This browser cannot remember keys; compare the key with the one your dispatcher shows.";
  } else {
    note.textContent = `Warning: this dispatcher's key changed (it was ${t}). Do not continue unless you replaced the key.`;
    note.classList.add("warn");
  }
  const form = $("fields");
  for (const f of spec.fields) {
    const row = document.createElement("div");
    row.className = "field";
    const label = document.createElement("label");
    label.htmlFor = "field-" + f.name;
    label.textContent = (f.label || f.name) + (f.required ? "" : " (optional)");
    row.append(label, input(f));
    form.append(row);
  }
  show("ask");
  const tg = telegram();
  if (tg) {
    tg("web_app_ready", {});
    tg("web_app_expand", {});
  }
  $("seal").addEventListener("click", async (ev) => {
    ev.preventDefault();
    $("ask-error").textContent = "";
    const raw = {};
    const values = {};
    for (const f of spec.fields) {
      const el = $("field-" + f.name);
      if (f.type === "file") {
        const file = el.files && el.files[0];
        raw[f.name] = file ? { size: file.size } : null;
        if (file) values[f.name] = file;
      } else {
        raw[f.name] = el.value;
        if (el.value !== "") values[f.name] = el.value;
      }
    }
    const problem = checkValues(spec, raw);
    if (problem) {
      $("ask-error").textContent = problem;
      return;
    }
    try {
      for (const f of spec.fields) {
        if (f.type === "file" && values[f.name]) values[f.name] = await readFile(values[f.name]);
      }
      if (Date.now() > opened.expires) return fail("This form expired.");
      const sealed = await seal(spec, rawKey, values);
      for (const f of spec.fields) {
        const el = $("field-" + f.name);
        if (f.type === "file") el.value = "";
        else el.value = "";
      }
      if (tg && sealed.length <= TG_LIMIT) {
        tg("web_app_data_send", { data: sealed });
        $("sent-text").textContent = "Sent. Only your dispatcher can read it.";
        show("sent");
        return;
      }
      $("sealed").value = sealed;
      $("download").href = URL.createObjectURL(new Blob([sealed], { type: "text/plain" }));
      $("download").download = spec.form + ".sealed";
      show("copy");
    } catch (e) {
      $("ask-error").textContent = "Could not seal: " + e.message;
    }
  });
  $("copy-button").addEventListener("click", async () => {
    const text = $("sealed").value;
    try {
      await navigator.clipboard.writeText(text);
      $("copy-button").textContent = "Copied";
    } catch (_) {
      $("sealed").select();
    }
  });
}

main().catch((e) => fail(e.message));
