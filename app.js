// The form page: reads the signed spec from the link, renders its fields,
// seals the values in this browser and hands back only the sealed reply.
// No third-party script runs here: the Telegram return path uses the
// client's own bridge (web_app_data_send) directly.
import {
  tokenFrom, openSpec, seal, checkValues, b64Encode, b64urlDecode,
  messageFrom, parseMessage, replyKey, openMessage,
} from "./sealed.js";

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

/** IndexedDB holding remembered (non-extractable) reply keys by salt. */
function keyStore(mode, fn) {
  return new Promise((resolve) => {
    let req;
    try {
      req = indexedDB.open(KEY_DB, 1);
    } catch (_) {
      return resolve(null);
    }
    req.onupgradeneeded = () => req.result.createObjectStore("keys");
    req.onerror = () => resolve(null);
    req.onsuccess = () => {
      try {
        const tx = req.result.transaction("keys", mode);
        const r = fn(tx.objectStore("keys"));
        tx.oncomplete = () => resolve(r && "result" in r ? r.result : null);
        tx.onerror = () => resolve(null);
      } catch (_) {
        resolve(null);
      }
    };
  });
}

const keyId = (h) => h.salt + ":" + h.iter;

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
  const open = async (key) => showBody(header, await openMessage(msg, key), tg);
  const remembered = await keyStore("readonly", (s) => s.get(keyId(header)));
  if (remembered) {
    try {
      return await open(remembered);
    } catch (_) {
      // A replaced key: ask for the passphrase.
    }
  }
  $("msg-from").textContent = "From " + header.from;
  $("msg-expires").textContent = new Date(msg.expires).toLocaleString();
  show("message");
  $("msg-pass").focus();
  $("msg-open").addEventListener("click", async (ev) => {
    ev.preventDefault();
    $("msg-error").textContent = "";
    $("msg-open").disabled = true;
    $("msg-note").textContent = "Opening...";
    try {
      const key = await replyKey($("msg-pass").value, header.salt, header.iter);
      $("msg-pass").value = "";
      const body = await openMessage(msg, key);
      if ($("msg-remember").checked) await keyStore("readwrite", (s) => s.put(key, keyId(header)));
      showBody(header, body, tg);
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
