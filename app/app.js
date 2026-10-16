/*
 * 2FA Keyring app.
 * Depends on /assets/totp.js (TOTP core), /assets/migration.js (Google Authenticator export decoder)
 * and /assets/vendor/jsQR.js (QR decoding). Everything runs in this page.
 *
 * Storage (this browser only):
 *   keyring.vault.v1  encrypted envelope {app,v:1,kdf,iter,salt,iv,ct}. The ciphertext holds
 *                     {accounts:[...], savedAt}. Accounts may carry optional "group" and "fav".
 *   keyring.prefs.v1  non-secret settings: auto-lock, last backup time, changes since backup.
 * Keys are encrypted with AES-256-GCM using a key derived from the passphrase
 * (PBKDF2-SHA256, 600,000 iterations). The demo vault lives in memory only and never writes storage.
 */
(function () {
  "use strict";
  var $ = function (s, r) { return (r || document).querySelector(s); };

  function blocked(title, text) {
    $("#blockedTitle").textContent = title;
    $("#blockedText").textContent = text;
    $("#blocked").hidden = false;
  }
  if (window.top !== window.self) {
    blocked("Open 2FA Keyring in its own tab",
      "This page was loaded inside another website's frame, which could be used to trick you into clicking. For your safety it won't run here.");
    return;
  }
  if (!window.isSecureContext || !window.crypto || !crypto.subtle) {
    blocked("This page needs a secure connection",
      "Your browser only allows encryption on pages served over HTTPS (or from localhost). Open the HTTPS address of this site.");
    return;
  }
  var C = 94.2478;
  var HERO_KEY = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
  var LS_VAULT = "keyring.vault.v1", LS_PREFS = "keyring.prefs.v1";
  var MIN_PASS = 12;
  var PBKDF_ITER = 600000;
  var enc = new TextEncoder(), dec = new TextDecoder();

  /* Public test keys for the demo: RFC 6238 seeds and the widely used example key. */
  var DEMO_ACCOUNTS = [
    { issuer: "Example Mail", label: "demo@example.com", secret: "JBSWY3DPEHPK3PXP", group: "Personal", fav: true },
    { issuer: "Example Code Host", label: "demo-developer", secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", group: "Work", fav: true },
    { issuer: "Example Cloud", label: "admin@example.com", secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA", algo: "SHA256", digits: 8, group: "Work" },
    { issuer: "Example Chat", label: "demo#0001", secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA", algo: "SHA512", group: "Personal" },
    { issuer: "Example Bank", label: "Checking ••42", secret: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", digits: 8, period: 60, group: "Finance" },
    { issuer: "Example Shop", label: "demo shopper", secret: "KRSXG5BAMV4GC3LQNRSSA23FPEQGM33SEBSGK3LP" }
  ];

  /* ---------- storage ---------- */
  var storageOK = true, damaged = false;
  function lsGet(k) { try { return localStorage.getItem(k); } catch (e) { storageOK = false; return null; } }
  function lsSet(k, v) { try { localStorage.setItem(k, v); return true; } catch (e) { storageOK = false; return false; } }
  function lsDel(k) { try { localStorage.removeItem(k); } catch (e) {} }

  var S = { key: null, salt: null, iter: PBKDF_ITER, accounts: [], demo: false, open: false };
  var envelope = null;
  var prefs = { autolock: 5, lastBackup: 0, lockHidden: false, changes: 0, nudgeHiddenAt: -1 };
  var lastActive = Date.now();
  var rows = new Map();
  var keyCache = new Map();
  var filter = "all";

  function checkEnvelope(e) {
    if (!e || e.app !== "keyring" || e.v !== 1 || typeof e.salt !== "string" || typeof e.iv !== "string" ||
        typeof e.ct !== "string" || !Number.isInteger(e.iter) || e.iter < 100000 || e.iter > 2000000) {
      throw new Error("bad envelope");
    }
    return e;
  }

  function loadStored() {
    var raw = lsGet(LS_VAULT);
    envelope = null; damaged = false;
    if (raw) {
      try { envelope = checkEnvelope(JSON.parse(raw)); } catch (e) { damaged = true; }
    }
    var p = lsGet(LS_PREFS);
    if (p) {
      try {
        var o = JSON.parse(p);
        if ([0, 1, 5, 15].indexOf(o.autolock) >= 0) prefs.autolock = o.autolock;
        if (Number.isFinite(o.lastBackup)) prefs.lastBackup = o.lastBackup;
        if (typeof o.lockHidden === "boolean") prefs.lockHidden = o.lockHidden;
        if (Number.isInteger(o.changes) && o.changes >= 0) prefs.changes = o.changes;
        if (Number.isInteger(o.nudgeHiddenAt)) prefs.nudgeHiddenAt = o.nudgeHiddenAt;
      } catch (e) {}
    }
  }
  function savePrefs() { if (!S.demo) lsSet(LS_PREFS, JSON.stringify(prefs)); }

  /* ---------- crypto ---------- */
  function b64e(buf) {
    var b = new Uint8Array(buf), s = "";
    for (var i = 0; i < b.length; i += 0x8000) s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000));
    return btoa(s);
  }
  function b64d(str) {
    var s = atob(str), b = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) b[i] = s.charCodeAt(i);
    return b;
  }
  async function deriveKey(pass, salt, iter) {
    var base = await crypto.subtle.importKey("raw", enc.encode(pass), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: salt, iterations: iter, hash: "SHA-256" },
      base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
    );
  }
  async function seal(key, salt, iter, data) {
    var iv = crypto.getRandomValues(new Uint8Array(12));
    var ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, key, enc.encode(JSON.stringify(data)));
    return { app: "keyring", v: 1, kdf: "PBKDF2-SHA256", iter: iter, salt: b64e(salt), iv: b64e(iv), ct: b64e(ct) };
  }
  async function openEnvelope(env, pass) {
    checkEnvelope(env);
    var salt = b64d(env.salt);
    var key = await deriveKey(pass, salt, env.iter);
    var pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64d(env.iv) }, key, b64d(env.ct));
    return { key: key, salt: salt, iter: env.iter, data: JSON.parse(dec.decode(pt)) };
  }

  var saveChain = Promise.resolve();
  /* Writes the encrypted vault. Never runs in the demo. */
  function persist() {
    if (S.demo) return Promise.resolve();
    saveChain = saveChain.then(async function () {
      if (!S.key || S.demo) return;
      var env = await seal(S.key, S.salt, S.iter, { accounts: S.accounts, savedAt: Date.now() });
      envelope = env;
      damaged = false;
      var ok = lsSet(LS_VAULT, JSON.stringify(env));
      updateStorageNote(!ok);
    }).catch(function () {});
    return saveChain;
  }
  /* Records that the vault changed since the last backup. */
  function noteChange(n) {
    if (S.demo) return;
    prefs.changes += n || 1;
    savePrefs();
    renderNudge();
  }
  function updateStorageNote(show) {
    document.querySelectorAll(".storageNote").forEach(function (n) { n.hidden = !(show || !storageOK); });
  }

  /* ---------- accounts ---------- */
  function cleanGroup(g) { return String(g || "").replace(/\s+/g, " ").trim().slice(0, 40); }
  function makeAccount(o) {
    var secret = normSecret(o.secret);
    if (secret.length < 8) throw uerr("The setup key is too short. It is usually 16 or more letters and digits.");
    try { base32Decode(secret); } catch (e) { throw uerr("The setup key can only contain the letters A to Z and the digits 2 to 7."); }
    var algo = String(o.algo || "SHA1").toUpperCase();
    if (!ALGS[algo]) throw uerr("That algorithm isn't supported. Use SHA1, SHA256 or SHA512.");
    var digits = Number(o.digits || 6);
    if ([6, 7, 8].indexOf(digits) < 0) throw uerr("Digits must be 6, 7 or 8.");
    var period = Number(o.period || 30);
    if (!Number.isInteger(period) || period < 1 || period > 300) throw uerr("The period must be a whole number of seconds from 1 to 300.");
    var issuer = String(o.issuer || "").trim().slice(0, 80);
    var label = String(o.label || "").trim().slice(0, 120);
    if (!issuer && !label) throw uerr("Enter a service name or an account.");
    var a = {
      id: typeof o.id === "string" && o.id ? o.id : crypto.randomUUID(),
      issuer: issuer, label: label, secret: secret, algo: algo, digits: digits, period: period,
      added: Number.isFinite(o.added) ? o.added : Date.now()
    };
    var g = cleanGroup(o.group);
    if (g) a.group = g;
    if (o.fav === true) a.fav = true;
    return a;
  }
  function sanitizeAccounts(arr) {
    var out = [];
    if (!Array.isArray(arr)) return out;
    arr.forEach(function (o) { try { out.push(makeAccount(o)); } catch (e) {} });
    return out;
  }
  function sameKey(x, a) { return x.secret === a.secret && x.algo === a.algo && x.digits === a.digits && x.period === a.period; }
  function isDup(a) { return S.accounts.some(function (x) { return sameKey(x, a); }); }
  async function keyFor(a) {
    var sig = a.secret + "|" + a.algo;
    var c = keyCache.get(a.id);
    if (!c || c.sig !== sig) {
      c = { sig: sig, key: await hmacKey(base32Decode(a.secret), a.algo) };
      keyCache.set(a.id, c);
    }
    return c.key;
  }
  function nameOf(a) { return a.issuer || a.label; }
  function hue(str) {
    var h = 0;
    for (var i = 0; i < str.length; i++) h = (h * 31 + str.charCodeAt(i)) >>> 0;
    return h % 360;
  }
  function groupsInUse() {
    var set = new Set();
    S.accounts.forEach(function (a) { if (a.group) set.add(a.group); });
    return Array.from(set).sort(function (x, y) { return x.localeCompare(y); });
  }

  /* ---------- small helpers ---------- */
  function h(tag, attrs) {
    var el = document.createElement(tag);
    var a = attrs || {};
    Object.keys(a).forEach(function (k) {
      var v = a[k];
      if (v == null || v === false) return;
      if (k === "class") el.className = v;
      else if (k === "text") el.textContent = v;
      else if (k.indexOf("on") === 0) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? "" : v);
    });
    for (var i = 2; i < arguments.length; i++) {
      var kid = arguments[i];
      if (kid == null || kid === false) continue;
      el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
    }
    return el;
  }
  var toastTimer = 0;
  function toast(msg) {
    var t = $("#toast");
    t.textContent = msg;
    t.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { t.classList.remove("show"); }, 2600);
  }
  function fmtDate(ts) {
    return new Date(ts).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
  }
  function plural(n, one, many) { return n + " " + (n === 1 ? one : many); }
  function openDlg(d) { if (!d.open) d.showModal(); }
  document.querySelectorAll("dialog").forEach(function (d) {
    d.addEventListener("click", function (ev) { if (ev.target === d) d.close(); });
  });
  document.querySelectorAll("[data-close]").forEach(function (b) {
    b.addEventListener("click", function () { $("#" + b.getAttribute("data-close")).close(); });
  });
  function readBackupText(text) {
    try { return checkEnvelope(JSON.parse(text)); } catch (e) { return null; }
  }

  /* ---------- passphrase strength ---------- */
  var COMMON = ["password", "passphrase", "123456", "qwerty", "letmein", "welcome", "iloveyou", "admin", "monkey", "dragon", "abc123", "111111", "keyring", "authenticator"];
  function strengthOf(p) {
    if (!p) return { level: 0, bits: 0 };
    var pool = 0;
    if (/[a-z]/.test(p)) pool += 26;
    if (/[A-Z]/.test(p)) pool += 26;
    if (/[0-9]/.test(p)) pool += 10;
    if (/[^A-Za-z0-9]/.test(p)) pool += 33;
    var bits = p.length * Math.log2(Math.max(pool, 2));
    var uniq = new Set(p.toLowerCase()).size;
    if (uniq < p.length / 3) bits *= 0.5;
    var low = p.toLowerCase();
    if (COMMON.some(function (w) { return low.indexOf(w) >= 0; })) bits = Math.min(bits, 40);
    if (/^(.)\1*$/.test(p) || /^(0123456789|abcdefghij|qwertyuiop)/i.test(p)) bits = 10;
    var level = bits < 50 ? 1 : bits < 65 ? 2 : bits < 85 ? 3 : 4;
    return { level: level, bits: bits };
  }
  var STRENGTH_TEXT = ["", "Too weak. Add more words or characters.", "Fair. Another word or two would help.", "Good.", "Strong."];
  function showStrength() {
    var p = $("#pass").value, s = strengthOf(p);
    $("#meter").setAttribute("data-level", String(s.level));
    $("#meter span").style.width = Math.min(100, s.level * 25) + "%";
    $("#strength").textContent = !p ? "Tip: four or more random words make a strong, memorable passphrase."
      : p.length < MIN_PASS ? (MIN_PASS - p.length) + " more characters needed." : STRENGTH_TEXT[s.level];
  }
  function checkNewPass(p, p2) {
    if (p.length < MIN_PASS) throw uerr("Use at least " + MIN_PASS + " characters.");
    if (strengthOf(p).level < 2) throw uerr("That passphrase is too easy to guess. Add more words or characters.");
    if (p !== p2) throw uerr("The two passphrases don't match.");
  }
  $("#pass").addEventListener("input", function () { if (mode === "create") showStrength(); });

  /* ---------- views ---------- */
  var lockView = $("#lockView"), appView = $("#appView");
  var mode = "create";

  function setVaultState(state) {
    var st = $("#vaultState");
    st.setAttribute("data-state", state);
    st.textContent = state === "unlocked" ? "Vault unlocked" : state === "demo" ? "Demo vault" : "Vault locked";
    $("#leaveNote").hidden = state !== "unlocked";
  }

  function showLock(note) {
    appView.hidden = true;
    lockView.hidden = false;
    setVaultState("locked");
    mode = damaged ? "damaged" : envelope ? "unlock" : "create";
    $("#lockErr").textContent = "";
    $("#lockNote").textContent = note || "";
    $("#pass").value = ""; $("#pass2").value = "";
    var create = mode === "create", unlock = mode === "unlock", dmg = mode === "damaged";
    $("#lockForm").hidden = dmg;
    $("#pass2Wrap").hidden = !create;
    $("#strengthWrap").hidden = !create;
    if (create) showStrength();
    $("#pass").autocomplete = create ? "new-password" : "current-password";
    $("#pass2").required = create;
    $("#lockTitle").textContent = create ? "Create your vault" : dmg ? "Vault can't be read" : "Unlock your vault";
    $("#lockHelp").textContent = create
      ? "Choose a passphrase of at least " + MIN_PASS + " characters. It encrypts your keys in this browser. Nobody, including the makers of this app, can recover it for you."
      : dmg ? "The vault stored in this browser is damaged. Restore it from an encrypted backup." : "Enter your passphrase to see your codes.";
    $("#lockBtn").textContent = create ? "Create vault" : "Unlock";
    $("#restoreBox").hidden = unlock;
    $("#restoreForm").hidden = !dmg;
    $("#restoreToggle").hidden = dmg;
    $("#damagedBox").hidden = !dmg;
    updateStorageNote(false);
    setTimeout(function () { if (!dmg) $("#pass").focus(); }, 0);
  }

  function enterApp() {
    S.open = true;
    lockView.hidden = true;
    appView.hidden = false;
    setVaultState(S.demo ? "demo" : "unlocked");
    $("#demoBar").hidden = !S.demo;
    lastActive = Date.now();
    $("#q").value = "";
    filter = "all";
    render();
    renderNudge();
    updateStorageNote(false);
  }

  function wipeMemory() {
    S.key = null; S.salt = null; S.accounts = []; S.open = false; S.demo = false;
    keyCache.clear(); rows.clear();
    $("#list").replaceChildren();
    document.querySelectorAll("dialog").forEach(function (d) { if (d.open) d.close(); });
    $("#entries").replaceChildren();
    resetMigration();
    ["#lLinks", "#eSecret", "#bText", "#iText", "#iPass", "#cText", "#cPass", "#sNew", "#sNew2", "#migText"].forEach(function (s) {
      var el = $(s); if (!el) return;
      if ("value" in el) el.value = ""; else el.textContent = "";
    });
    $("#cResult").hidden = true; $("#cResult").replaceChildren();
    $("#demoBar").hidden = true;
  }

  function lock(note) {
    wipeMemory();
    loadStored();
    showLock(note);
  }

  function setBusy(b) {
    $("#lockBtn").disabled = b;
    if (b) $("#lockBtn").textContent = mode === "create" ? "Creating…" : "Unlocking…";
    else $("#lockBtn").textContent = mode === "create" ? "Create vault" : "Unlock";
  }

  $("#lockForm").addEventListener("submit", async function (ev) {
    ev.preventDefault();
    $("#lockErr").textContent = "";
    var pass = $("#pass").value;
    setBusy(true);
    try {
      if (mode === "create") {
        checkNewPass(pass, $("#pass2").value);
        var salt = crypto.getRandomValues(new Uint8Array(16));
        var key = await deriveKey(pass, salt, PBKDF_ITER);
        S.demo = false;
        S.key = key; S.salt = salt; S.iter = PBKDF_ITER; S.accounts = [];
        prefs.changes = 0; prefs.lastBackup = 0; prefs.nudgeHiddenAt = -1; savePrefs();
        await persist();
      } else {
        var r = await openEnvelope(envelope, pass);
        S.demo = false;
        S.key = r.key; S.salt = r.salt; S.iter = r.iter; S.accounts = sanitizeAccounts(r.data.accounts);
      }
      mode = "unlock";
      enterApp();
    } catch (e) {
      $("#lockErr").textContent = e.user ? e.message
        : mode === "unlock" ? "That passphrase didn't open the vault." : "Something went wrong. Try again.";
    } finally {
      setBusy(false);
    }
  });

  $("#restoreToggle").addEventListener("click", function () {
    var f = $("#restoreForm");
    f.hidden = !f.hidden;
  });
  $("#rFile").addEventListener("change", async function (ev) {
    var f = ev.target.files[0];
    if (f) $("#rText").value = await f.text();
  });
  $("#restoreForm").addEventListener("submit", async function (ev) {
    ev.preventDefault();
    var err = $("#rErr"); err.textContent = "";
    var env = readBackupText($("#rText").value);
    if (!env) { err.textContent = "That doesn't look like a 2FA Keyring backup."; return; }
    $("#rBtn").disabled = true;
    try {
      var r = await openEnvelope(env, $("#rPass").value);
      S.demo = false;
      S.key = r.key; S.salt = r.salt; S.iter = r.iter; S.accounts = sanitizeAccounts(r.data.accounts);
      await persist();
      prefs.changes = 0; prefs.nudgeHiddenAt = -1; savePrefs();
      $("#rPass").value = ""; $("#rText").value = "";
      mode = "unlock";
      enterApp();
      toast("Vault restored with " + plural(S.accounts.length, "key", "keys"));
    } catch (e) {
      err.textContent = "That passphrase doesn't open this backup.";
    } finally { $("#rBtn").disabled = false; }
  });
  $("#discardBtn").addEventListener("click", function () {
    lsDel(LS_VAULT); envelope = null; damaged = false;
    showLock("Starting fresh. Create a new vault.");
  });

  /* ---------- demo ---------- */
  function enterDemo() {
    wipeMemory();
    S.demo = true;
    S.key = null;
    S.accounts = DEMO_ACCOUNTS.map(function (o, i) {
      return makeAccount(Object.assign({ id: "demo-" + i, added: Date.UTC(2026, 0, 1) }, o));
    });
    enterApp();
    toast("Demo vault opened. Nothing here is saved.");
  }
  function exitDemo(note) {
    wipeMemory();
    try { if (location.hash === "#demo") history.replaceState(null, "", location.pathname); } catch (e) {}
    loadStored();
    showLock(note);
  }
  $("#demoBtn").addEventListener("click", enterDemo);
  $("#demoExit").addEventListener("click", function () { exitDemo("You left the demo. Nothing from it was saved."); });
  $("#demoCreate").addEventListener("click", function () {
    exitDemo(envelope ? "This browser already has a vault. Unlock it with your passphrase." : "");
  });

  /* ---------- backup reminder ---------- */
  function backupStatusText() {
    if (prefs.changes > 0 && prefs.lastBackup) return plural(prefs.changes, "change", "changes") + " since your last backup on " + fmtDate(prefs.lastBackup) + ".";
    if (prefs.changes > 0) return "You haven't backed up this vault yet.";
    if (prefs.lastBackup) return "Backed up on " + fmtDate(prefs.lastBackup) + ". No changes since then.";
    return "You haven't backed up this vault yet.";
  }
  function renderNudge() {
    var show = !S.demo && S.open && prefs.changes > 0 && S.accounts.length > 0 && prefs.nudgeHiddenAt !== prefs.changes;
    $("#nudge").hidden = !show;
    if (show) $("#nudgeText").textContent = backupStatusText() + " Save a fresh backup so you don't lose these keys if this browser's data is cleared.";
  }
  $("#nudgeBackup").addEventListener("click", function () { openBackup(); });
  $("#nudgeLater").addEventListener("click", function () { prefs.nudgeHiddenAt = prefs.changes; savePrefs(); renderNudge(); });

  /* ---------- list ---------- */
  var STAR = '<svg viewBox="0 0 20 20" width="18" height="18" aria-hidden="true"><path d="M10 2.8l2.2 4.6 5 .6-3.7 3.5 1 5L10 14l-4.5 2.5 1-5L2.8 8l5-.6z" fill="currentColor" stroke="currentColor" stroke-width="1.2" stroke-linejoin="round"/></svg>';
  function buildRow(a) {
    var name = nameOf(a);
    var initial = (name.match(/[A-Za-z0-9]/) || ["?"])[0].toUpperCase();
    var ring = h("div", { class: "ringwrap" });
    ring.innerHTML = '<svg class="ring" viewBox="0 0 36 36" aria-hidden="true"><circle class="trk" cx="18" cy="18" r="15"/><circle class="arc" cx="18" cy="18" r="15" transform="rotate(-90 18 18)"/></svg>';
    var sec = h("span", { class: "sec", text: "" });
    ring.append(sec);
    var digits = h("span", { class: "digits", text: "••• •••" });
    var next = h("span", { class: "next", hidden: true });
    var btn = h("button", { class: "code", type: "button", "aria-label": "Copy code for " + name }, digits, next);
    var star = h("button", { class: "icon star" + (a.fav ? " on" : ""), type: "button", "aria-pressed": a.fav ? "true" : "false", "aria-label": "Favorite " + name });
    star.innerHTML = STAR;
    var edit = h("button", { class: "icon edit", type: "button", "aria-label": "Edit " + name });
    edit.innerHTML = '<svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true"><path d="M4 20h4L19 9l-4-4L4 16v4z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/></svg>';
    var mono = h("span", { class: "mono", "aria-hidden": "true" }, initial);
    mono.style.setProperty("--h", String(hue(name)));
    var who = h("div", { class: "who" }, h("span", { class: "issuer", text: name }));
    var sub = [];
    if (a.issuer && a.label) sub.push(h("span", { class: "label", text: a.label }));
    if (a.group) sub.push(h("span", { class: "tag", text: a.group }));
    if (sub.length) who.append(h("span", { class: "sub" }, sub[0], sub[1] || null));
    var el = h("li", { class: "row" }, mono, who, btn, ring, star, edit);
    var r = {
      el: el, a: a, counter: -1, nextCounter: -1, code: "", urgent: false,
      digits: digits, next: next, sec: sec, arc: ring.querySelector(".arc")
    };
    btn.addEventListener("click", function () { copyCode(r); });
    star.addEventListener("click", function () { toggleFav(a.id); });
    edit.addEventListener("click", function () { openEdit(a.id); });
    return r;
  }

  async function toggleFav(id) {
    var a = S.accounts.find(function (x) { return x.id === id; });
    if (!a) return;
    if (a.fav) delete a.fav; else a.fav = true;
    await persist();
    noteChange();
    render();
    var btn = document.querySelector('.row .star[aria-label="Favorite ' + CSS.escape(nameOf(a)) + '"]');
    if (btn) btn.focus();
    toast(a.fav ? nameOf(a) + " added to favorites" : nameOf(a) + " removed from favorites");
  }

  function matches(a, q) {
    if (filter === "fav" && !a.fav) return false;
    if (filter.indexOf("g:") === 0 && a.group !== filter.slice(2)) return false;
    return !q || (a.issuer + " " + a.label + " " + (a.group || "")).toLowerCase().indexOf(q) >= 0;
  }

  function renderChips() {
    var box = $("#chips");
    var groups = groupsInUse();
    var favs = S.accounts.some(function (a) { return a.fav; });
    if (filter === "fav" && !favs) filter = "all";
    if (filter.indexOf("g:") === 0 && groups.indexOf(filter.slice(2)) < 0) filter = "all";
    box.replaceChildren();
    if (!groups.length && !favs) { box.hidden = true; return; }
    var make = function (id, text) {
      var b = h("button", { class: "chip", type: "button", "aria-pressed": filter === id ? "true" : "false", text: text });
      b.addEventListener("click", function () { filter = id; render(); var again = box.querySelector('[aria-pressed="true"]'); if (again) again.focus(); });
      box.append(b);
    };
    make("all", "All");
    if (favs) make("fav", "★ Favorites");
    groups.forEach(function (g) { make("g:" + g, g); });
    box.hidden = false;
  }

  function render() {
    var q = $("#q").value.trim().toLowerCase();
    renderChips();
    var all = S.accounts.slice().sort(function (x, y) {
      return (y.fav ? 1 : 0) - (x.fav ? 1 : 0) ||
        nameOf(x).toLowerCase().localeCompare(nameOf(y).toLowerCase()) || x.label.toLowerCase().localeCompare(y.label.toLowerCase());
    });
    var list = all.filter(function (a) { return matches(a, q); });
    var ul = $("#list");
    ul.replaceChildren();
    rows.clear();
    list.forEach(function (a) { var r = buildRow(a); rows.set(a.id, r); ul.append(r.el); });
    ul.hidden = list.length === 0;
    $("#empty").hidden = S.accounts.length > 0;
    $("#noMatch").hidden = !(S.accounts.length > 0 && list.length === 0);
    $("#count").textContent = plural(S.accounts.length, "key", "keys") + (S.accounts.length ? " · click a code to copy it" : "");
    $("#btnBackup").disabled = S.demo;
    $("#btnBackup").title = S.demo ? "Backups are off in the demo" : "";
    renderFoot();
    tick();
  }

  function renderFoot() {
    var foot = $("#foot");
    foot.replaceChildren();
    if (S.demo) {
      foot.append(h("span", { text: "Demo vault: public test keys, kept in memory only." }));
      return;
    }
    foot.append(h("span", { text: "Codes are calculated on this device. Your keys stay here, encrypted." }));
    var b = h("button", { class: "linkbtn", type: "button", text: prefs.changes > 0 ? (prefs.lastBackup ? plural(prefs.changes, "change", "changes") + " since last backup" : "No backup yet. Make one") : prefs.lastBackup ? "Last backup " + fmtDate(prefs.lastBackup) : "No backup yet. Make one" });
    b.addEventListener("click", openBackup);
    foot.append(b);
  }

  async function copyCode(r) {
    if (!r.code) return;
    try {
      await navigator.clipboard.writeText(r.code);
      toast("Copied " + groupCode(r.code) + " for " + nameOf(r.a));
    } catch (e) {
      var rg = document.createRange();
      rg.selectNodeContents(r.digits);
      var sel = getSelection();
      sel.removeAllRanges(); sel.addRange(rg);
      toast("Selected. Press Ctrl+C or ⌘C to copy.");
    }
    r.el.classList.add("flash");
    setTimeout(function () { r.el.classList.remove("flash"); }, 500);
  }

  $("#q").addEventListener("input", render);
  $("#q").addEventListener("keydown", function (ev) {
    if (ev.key === "Escape" && $("#q").value) { ev.preventDefault(); $("#q").value = ""; render(); }
  });
  document.addEventListener("keydown", function (ev) {
    if (ev.key !== "/" || ev.ctrlKey || ev.metaKey || ev.altKey || appView.hidden) return;
    var t = ev.target;
    if (t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName))) return;
    if (document.querySelector("dialog[open]")) return;
    ev.preventDefault();
    $("#q").focus();
  });

  /* ---------- ticking ---------- */
  var heroKey = null, heroCounter = -1;
  async function heroTick(now) {
    if (lockView.hidden) return;
    var sec = now / 1000, rem = 30 - (sec % 30);
    $("#heroArc").style.strokeDashoffset = String(C * (1 - rem / 30));
    $("#heroSec").textContent = String(Math.ceil(rem));
    var counter = Math.floor(sec / 30);
    if (heroCounter !== counter) {
      heroCounter = counter;
      if (!heroKey) heroKey = await hmacKey(base32Decode(HERO_KEY), "SHA1");
      $("#heroCode").textContent = groupCode(await hotpFromKey(heroKey, counter, 6));
    }
  }

  async function updateRow(r, now) {
    var a = r.a, sec = now / 1000, period = a.period;
    var rem = period - (sec % period);
    var counter = Math.floor(sec / period);
    r.arc.style.strokeDashoffset = String(C * (1 - rem / period));
    r.sec.textContent = String(Math.ceil(rem));
    var urgent = rem <= 5;
    if (urgent !== r.urgent) { r.urgent = urgent; r.el.classList.toggle("urgent", urgent); }
    var key;
    if (r.counter !== counter) {
      r.counter = counter;
      key = await keyFor(a);
      var code = await hotpFromKey(key, counter, a.digits);
      if (!S.open || r.counter !== counter) return;
      r.code = code;
      r.digits.textContent = groupCode(code);
    }
    if (rem > 7) {
      if (!r.next.hidden) r.next.hidden = true;
      r.nextCounter = -1;
    } else if (r.nextCounter !== counter + 1) {
      r.nextCounter = counter + 1;
      key = key || await keyFor(a);
      var nc = await hotpFromKey(key, counter + 1, a.digits);
      if (!S.open) return;
      r.next.textContent = "next " + groupCode(nc);
      r.next.hidden = false;
    }
  }

  async function previewEntry(li, now) {
    var out = fld(li, ".prev");
    var raw = fld(li, ".k-secret").value;
    var secret = normSecret(raw);
    if (/^otpauth/i.test(raw.trim()) || secret.length < 8) { out.hidden = true; return; }
    var algo = fld(li, ".k-algo").value;
    var c = prevCache.get(li);
    try {
      if (!c || c.sig !== secret + algo) {
        c = { sig: secret + algo, key: await hmacKey(base32Decode(secret), algo) };
        prevCache.set(li, c);
      }
    } catch (e) {
      prevCache.delete(li);
      out.textContent = "The setup key has characters outside A to Z and 2 to 7.";
      out.classList.add("bad");
      out.hidden = false;
      return;
    }
    var period = Math.max(1, Math.min(300, parseInt(fld(li, ".k-period").value, 10) || 30));
    var code = await hotpFromKey(c.key, Math.floor(now / 1000 / period), Number(fld(li, ".k-digits").value));
    out.classList.remove("bad");
    out.textContent = "Code right now: " + groupCode(code) + ". It should match the service's own app.";
    out.hidden = false;
  }
  async function previewTick(now) {
    await Promise.all(entries().map(function (li) { return previewEntry(li, now); }));
  }

  var ticking = false;
  async function tick() {
    if (ticking) return;
    ticking = true;
    try {
      var now = Date.now();
      await heroTick(now);
      if (!S.open) return;
      if (prefs.autolock > 0 && now - lastActive > prefs.autolock * 60000) {
        var wasDemo = S.demo;
        if (wasDemo) exitDemo("The demo closed after " + plural(prefs.autolock, "minute", "minutes") + " without activity.");
        else lock("Locked after " + plural(prefs.autolock, "minute", "minutes") + " without activity.");
        return;
      }
      var all = [];
      rows.forEach(function (r) { all.push(updateRow(r, now)); });
      await Promise.all(all);
      if ($("#addDlg").open) await previewTick(now);
    } catch (e) {
    } finally { ticking = false; }
  }
  ["pointerdown", "keydown", "touchstart", "wheel"].forEach(function (t) {
    addEventListener(t, function () { lastActive = Date.now(); }, { passive: true });
  });

  /* ---------- add ---------- */
  var TABS = { key: ["#tabKey", "#keyForm"], link: ["#tabLink", "#linkForm"], mig: ["#tabMig", "#migPanel"] };
  function setTab(which) {
    Object.keys(TABS).forEach(function (k) {
      $(TABS[k][0]).setAttribute("aria-selected", String(k === which));
      $(TABS[k][0]).tabIndex = k === which ? 0 : -1;
      $(TABS[k][1]).hidden = k !== which;
    });
  }
  $("#tabKey").addEventListener("click", function () { setTab("key"); });
  $("#tabLink").addEventListener("click", function () { setTab("link"); });
  $("#tabMig").addEventListener("click", function () { setTab("mig"); });
  $(".tabs").addEventListener("keydown", function (ev) {
    if (ev.key !== "ArrowRight" && ev.key !== "ArrowLeft") return;
    var order = ["key", "link", "mig"];
    var cur = order.findIndex(function (k) { return $(TABS[k][0]).getAttribute("aria-selected") === "true"; });
    var nxt = order[(cur + (ev.key === "ArrowRight" ? 1 : order.length - 1)) % order.length];
    setTab(nxt); $(TABS[nxt][0]).focus(); ev.preventDefault();
  });

  var entrySeq = 0, prevCache = new WeakMap();
  function entries() { return Array.prototype.slice.call($("#entries").children); }
  function fld(li, c) { return li.querySelector(c); }
  function isBlank(li) {
    return !fld(li, ".k-issuer").value.trim() && !fld(li, ".k-label").value.trim() && !fld(li, ".k-secret").value.trim();
  }
  function buildEntry() {
    var n = ++entrySeq;
    var id = function (s) { return "k" + n + s; };
    var li = document.createElement("li");
    li.className = "entry";
    li.innerHTML =
      '<div class="entry-head"><span class="entry-no"></span><button class="icon rm" type="button">×</button></div>' +
      '<div class="entry-grid">' +
        '<div class="field"><label for="' + id("i") + '">Service</label><input id="' + id("i") + '" class="k-issuer" maxlength="80" placeholder="GitHub" spellcheck="false" autocorrect="off" autocapitalize="off"></div>' +
        '<div class="field"><label for="' + id("l") + '">Account</label><input id="' + id("l") + '" class="k-label" maxlength="120" placeholder="you@example.com" spellcheck="false" autocorrect="off" autocapitalize="off"></div>' +
      '</div>' +
      '<div class="field"><label for="' + id("s") + '">Setup key</label><input id="' + id("s") + '" class="k-secret mono-in" spellcheck="false" autocorrect="off" autocapitalize="off" autocomplete="off" placeholder="JBSW Y3DP EHPK 3PXP or an otpauth:// link"></div>' +
      '<p class="prev" hidden></p>' +
      '<details><summary>Advanced</summary><div class="row2">' +
        '<div class="field"><label for="' + id("a") + '">Algorithm</label><select id="' + id("a") + '" class="k-algo"><option>SHA1</option><option>SHA256</option><option>SHA512</option></select></div>' +
        '<div class="field"><label for="' + id("d") + '">Digits</label><select id="' + id("d") + '" class="k-digits"><option>6</option><option>7</option><option>8</option></select></div>' +
        '<div class="field"><label for="' + id("p") + '">Seconds</label><input id="' + id("p") + '" class="k-period" type="number" min="1" max="300" value="30" inputmode="numeric"></div>' +
      '</div>' +
      '<div class="field"><label for="' + id("g") + '">Group (optional)</label><input id="' + id("g") + '" class="k-group" maxlength="40" list="groupList" spellcheck="false" autocorrect="off" autocapitalize="off" placeholder="Work, Personal…"></div>' +
      '</details>' +
      '<p class="err entry-err" role="alert"></p>';
    fld(li, ".rm").addEventListener("click", function () { removeEntry(li); });
    fld(li, ".k-secret").addEventListener("input", function () {
      fld(li, ".entry-err").textContent = "";
      fillFromLink(li);
      previewEntry(li, Date.now());
    });
    [".k-algo", ".k-digits", ".k-period"].forEach(function (c) {
      fld(li, c).addEventListener("input", function () { previewEntry(li, Date.now()); });
    });
    li.addEventListener("input", updateEntryUi);
    return li;
  }
  function updateEntryUi() {
    var list = entries(), many = list.length > 1;
    list.forEach(function (li, i) {
      fld(li, ".entry-head").hidden = !many;
      fld(li, ".entry-no").textContent = "Key " + (i + 1);
      fld(li, ".rm").setAttribute("aria-label", "Remove key " + (i + 1));
    });
    var filled = list.filter(function (li) { return !isBlank(li); }).length;
    $("#keySubmit").textContent = filled > 1 ? "Save " + filled + " keys" : "Save key";
  }
  function addEntry() {
    var li = buildEntry();
    $("#entries").append(li);
    updateEntryUi();
    fld(li, ".k-issuer").focus();
  }
  function removeEntry(li) {
    var list = entries();
    var i = list.indexOf(li);
    li.remove();
    if (!entries().length) $("#entries").append(buildEntry());
    updateEntryUi();
    var rest = entries();
    fld(rest[Math.min(i, rest.length - 1)], ".k-issuer").focus();
  }
  function resetEntries() {
    $("#entries").replaceChildren(buildEntry());
    updateEntryUi();
  }
  function fillFromLink(li) {
    var inp = fld(li, ".k-secret"), raw = inp.value.trim();
    if (isMigrationUri(raw)) {
      inp.value = "";
      openAdd("mig");
      $("#migText").value = raw;
      $("#migText").closest("details").open = true;
      readMigrationText();
      return;
    }
    if (!/^otpauth:\/\//i.test(raw)) return;
    try {
      var p = parseOtpauth(raw);
      inp.value = normSecret(p.secret);
      if (!fld(li, ".k-issuer").value.trim()) fld(li, ".k-issuer").value = p.issuer;
      if (!fld(li, ".k-label").value.trim()) fld(li, ".k-label").value = p.label;
      var algo = String(p.algo).toUpperCase(), digits = String(p.digits), period = String(parseInt(p.period, 10) || 30);
      if (ALGS[algo]) fld(li, ".k-algo").value = algo;
      if (["6", "7", "8"].indexOf(digits) >= 0) fld(li, ".k-digits").value = digits;
      fld(li, ".k-period").value = period;
      if (algo !== "SHA1" || digits !== "6" || period !== "30") fld(li, "details").open = true;
    } catch (x) {
      fld(li, ".entry-err").textContent = x.user ? x.message : "That link couldn't be read.";
    }
  }

  function fillGroupList() {
    var dl = $("#groupList");
    dl.replaceChildren();
    groupsInUse().forEach(function (g) { dl.append(h("option", { value: g })); });
  }

  function openAdd(tab) {
    $("#linkForm").reset();
    $("#keyErr").textContent = ""; $("#linkErr").textContent = "";
    resetEntries();
    resetMigration();
    fillGroupList();
    setTab(tab || "key");
    openDlg($("#addDlg"));
    if (!tab || tab === "key") setTimeout(function () { var f = $("#entries .k-issuer"); if (f) f.focus(); }, 0);
  }
  $("#btnAdd").addEventListener("click", function () { openAdd("key"); });
  $("#emptyAdd").addEventListener("click", function () { openAdd("key"); });
  $("#emptyImport").addEventListener("click", function () { openAdd("mig"); });
  $("#addClose").addEventListener("click", function () { $("#addDlg").close(); });
  $("#addEntry").addEventListener("click", addEntry);

  async function addAccounts(batch) {
    Array.prototype.push.apply(S.accounts, batch);
    await persist();
    noteChange(batch.length);
    render();
  }

  $("#keyForm").addEventListener("submit", async function (ev) {
    ev.preventDefault();
    var err = $("#keyErr");
    err.textContent = "";
    var list = entries(), batch = [], firstBad = null;
    list.forEach(function (li) {
      var e = fld(li, ".entry-err");
      e.textContent = "";
      if (isBlank(li)) return;
      try {
        var raw = fld(li, ".k-secret").value.trim();
        if (/^otpauth:/i.test(raw)) parseOtpauth(raw);
        var a = makeAccount({
          issuer: fld(li, ".k-issuer").value, label: fld(li, ".k-label").value, secret: raw,
          algo: fld(li, ".k-algo").value, digits: fld(li, ".k-digits").value, period: fld(li, ".k-period").value,
          group: fld(li, ".k-group").value
        });
        if (isDup(a)) throw uerr("This key is already in your vault.");
        if (batch.some(function (b) { return sameKey(b, a); })) throw uerr("This key is entered twice above.");
        batch.push(a);
      } catch (x) {
        e.textContent = x.user ? x.message : "This key couldn't be read.";
        if (!firstBad) firstBad = li;
      }
    });
    if (firstBad) {
      var n = list.filter(function (li) { return fld(li, ".entry-err").textContent; }).length;
      err.textContent = (n === 1 ? "Fix the key marked above." : "Fix the " + n + " keys marked above.") + " Nothing has been saved yet.";
      fld(firstBad, ".k-secret").focus();
      return;
    }
    if (!batch.length) { err.textContent = "Enter a setup key to save."; return; }
    await addAccounts(batch);
    $("#addDlg").close();
    toast(batch.length === 1 ? "Added " + nameOf(batch[0]) : "Added " + batch.length + " keys");
  });

  $("#linkForm").addEventListener("submit", async function (ev) {
    ev.preventDefault();
    var err = $("#linkErr"); err.textContent = "";
    var lines = $("#lLinks").value.split(/\r?\n/).map(function (s) { return s.trim(); }).filter(Boolean);
    if (!lines.length) { err.textContent = "Paste at least one otpauth:// link."; return; }
    var mig = lines.filter(isMigrationUri);
    if (mig.length) {
      $("#migText").value = mig.join("\n");
      $("#lLinks").value = lines.filter(function (l) { return !isMigrationUri(l); }).join("\n");
      setTab("mig");
      $("#migText").closest("details").open = true;
      readMigrationText();
      return;
    }
    var batch = [], dups = 0, problems = [];
    lines.forEach(function (ln) {
      try {
        var a = makeAccount(parseOtpauth(ln));
        if (isDup(a) || batch.some(function (b) { return sameKey(b, a); })) { dups++; return; }
        batch.push(a);
      } catch (e) {
        var m = e.user ? e.message : "One link could not be read.";
        if (problems.indexOf(m) < 0) problems.push(m);
      }
    });
    if (batch.length) { await addAccounts(batch); toast("Added " + plural(batch.length, "key", "keys")); }
    if (dups) problems.unshift(plural(dups, "key is", "keys are") + " already in your vault.");
    if (problems.length) err.textContent = problems.join(" ");
    else $("#addDlg").close();
  });

  function decodeQr(file) {
    return new Promise(function (resolve, reject) {
      if (typeof jsQR !== "function") { reject(uerr("QR reading isn't available here. Paste the link instead.")); return; }
      var img = new Image();
      var url = URL.createObjectURL(file);
      img.onload = function () {
        var sc = Math.min(1, 1600 / Math.max(img.width, img.height));
        var w = Math.max(1, Math.round(img.width * sc)), hh = Math.max(1, Math.round(img.height * sc));
        var cv = document.createElement("canvas");
        cv.width = w; cv.height = hh;
        var ctx = cv.getContext("2d", { willReadFrequently: true });
        ctx.drawImage(img, 0, 0, w, hh);
        var res = jsQR(ctx.getImageData(0, 0, w, hh).data, w, hh, { inversionAttempts: "attemptBoth" });
        cv.width = cv.height = 0;
        URL.revokeObjectURL(url);
        if (res && res.data) resolve(res.data); else reject(uerr("No QR code found in that image. Try a sharper, closer picture."));
      };
      img.onerror = function () { URL.revokeObjectURL(url); reject(uerr("That file couldn't be opened as an image.")); };
      img.src = url;
    });
  }
  $("#lFile").addEventListener("change", async function (ev) {
    var files = Array.prototype.slice.call(ev.target.files || []);
    ev.target.value = "";
    if (!files.length) return;
    var err = $("#linkErr");
    err.textContent = "";
    if (typeof jsQR !== "function") { err.textContent = "QR reading isn't available here. Paste the otpauth:// links instead."; return; }
    var found = [], missed = [];
    for (var i = 0; i < files.length; i++) {
      try { found.push(await decodeQr(files[i])); } catch (e) { missed.push(files[i].name); }
    }
    var mig = found.filter(isMigrationUri);
    if (mig.length) {
      setTab("mig");
      mig.forEach(function (u) { addMigrationUri(u); });
      showMigrationReview();
      found = found.filter(function (u) { return !isMigrationUri(u); });
    }
    if (found.length) {
      var ta = $("#lLinks");
      ta.value = (ta.value.trim() ? ta.value.trim() + "\n" : "") + found.join("\n");
    }
    if (missed.length) err.textContent = "No QR code found in " + missed.join(", ") + ". Try a sharper, closer picture.";
  });

  /* ---------- Google Authenticator import ---------- */
  var mig = MigrationCollector();
  var migPlan = [];
  function resetMigration() {
    mig.clear(); migPlan = [];
    $("#migStart").hidden = false; $("#migReview").hidden = true; $("#migDone").hidden = true;
    $("#migErr").textContent = ""; $("#migParts").textContent = "";
    $("#migRows").replaceChildren();
    var f = $("#migFile"); if (f) f.value = "";
  }
  function addMigrationUri(u) {
    try {
      var r = mig.add(u);
      return { ok: true, r: r };
    } catch (e) {
      return { ok: false, msg: e.user ? e.message : "That export couldn't be read." };
    }
  }
  function partsSummary() {
    var singles = 0, parts = [];
    mig.batches().forEach(function (b) {
      if (b.batchSize === 1) { singles++; return; }
      var got = b.batchSize - b.missing.length;
      parts.push("read " + got + " of " + b.batchSize + " codes from a multi-code export" + (b.missing.length ? " (missing code " + b.missing.map(function (i) { return i + 1; }).join(", ") + ")" : ""));
    });
    if (singles) parts.unshift("read " + plural(singles, "single-code export", "single-code exports"));
    var t = parts.join("; ");
    return t.charAt(0).toUpperCase() + t.slice(1);
  }
  $("#migFile").addEventListener("change", async function (ev) {
    var files = Array.prototype.slice.call(ev.target.files || []);
    ev.target.value = "";
    if (!files.length) return;
    var err = $("#migErr"); err.textContent = "";
    var problems = [];
    for (var i = 0; i < files.length; i++) {
      var text;
      try { text = await decodeQr(files[i]); }
      catch (e) { problems.push(files[i].name + ": " + (e.user ? e.message : "couldn't be read")); continue; }
      if (!isMigrationUri(text)) {
        problems.push(files[i].name + ": this QR code isn't a Google Authenticator export. Use the \"Links or QR images\" tab for single accounts.");
        continue;
      }
      var res = addMigrationUri(text);
      if (!res.ok) problems.push(files[i].name + ": " + res.msg);
    }
    if (problems.length) err.textContent = problems.join(" ");
    if (mig.size) showMigrationReview();
  });
  function readMigrationText() {
    var err = $("#migErr"); err.textContent = "";
    var lines = $("#migText").value.split(/\s+/).map(function (s) { return s.trim(); }).filter(Boolean);
    if (!lines.length) { err.textContent = "Paste at least one otpauth-migration:// link."; return; }
    var problems = [];
    lines.forEach(function (l, i) {
      if (!isMigrationUri(l)) { problems.push("Line " + (i + 1) + " isn't a Google Authenticator export link."); return; }
      var r = addMigrationUri(l);
      if (!r.ok) problems.push("Line " + (i + 1) + ": " + r.msg);
    });
    if (problems.length) err.textContent = problems.join(" ");
    if (mig.size) showMigrationReview();
  }
  $("#migRead").addEventListener("click", readMigrationText);

  function showMigrationReview() {
    var list = mig.entries();
    var seen = [];
    migPlan = list.map(function (e, idx) {
      var item = { e: e, idx: idx, status: "", ok: false, account: null };
      if (!e.supported) { item.status = "Not supported: " + e.reason + ". It won't be imported."; return item; }
      var a;
      try { a = makeAccount({ issuer: e.issuer, label: e.label, secret: e.secret, algo: e.algo, digits: e.digits, period: e.period }); }
      catch (x) { item.status = "Can't import: " + (x.user ? x.message : "invalid key"); return item; }
      if (isDup(a)) { item.status = "Already in your vault"; return item; }
      if (seen.some(function (b) { return sameKey(b, a); })) { item.status = "Appears twice in this export"; return item; }
      seen.push(a);
      item.ok = true; item.account = a;
      item.status = "Ready" + (a.algo !== "SHA1" || a.digits !== 6 ? " (" + a.algo + ", " + a.digits + " digits)" : "");
      return item;
    });
    var tbody = $("#migRows");
    tbody.replaceChildren();
    migPlan.forEach(function (it) {
      var cb = h("input", { type: "checkbox", id: "mig" + it.idx, "aria-label": "Import " + (it.e.issuer || it.e.label) });
      cb.checked = it.ok; cb.disabled = !it.ok;
      cb.addEventListener("change", updateMigButton);
      it.cb = cb;
      tbody.append(h("tr", { class: it.ok ? "" : "skipped" },
        h("td", null, cb),
        h("td", null, h("label", { for: "mig" + it.idx, text: it.e.issuer || "—" })),
        h("td", { text: it.e.label || "—" }),
        h("td", { class: "st", text: it.status })));
    });
    var ready = migPlan.filter(function (i) { return i.ok; }).length;
    var skipped = migPlan.length - ready;
    $("#migSummary").textContent = partsSummary() + ". Found " + plural(migPlan.length, "account", "accounts") + ": " + ready + " ready to import" + (skipped ? ", " + skipped + " will be skipped" : "") + ". Nothing has been saved yet.";
    var missing = mig.batches().filter(function (b) { return b.missing.length; });
    $("#migMissing").hidden = !missing.length;
    if (missing.length) $("#migMissing").textContent = "Some export codes haven't been read yet, so some accounts may be missing. Choose \"Scan more codes\" to add them, or import these now and the rest later. Accounts you've already imported won't be added twice.";
    $("#migStart").hidden = true; $("#migReview").hidden = false; $("#migDone").hidden = true;
    updateMigButton();
    $("#migReviewTitle").focus();
  }
  function updateMigButton() {
    var n = migPlan.filter(function (i) { return i.ok && i.cb && i.cb.checked; }).length;
    $("#migImport").textContent = n ? "Import " + plural(n, "account", "accounts") : "Nothing selected";
    $("#migImport").disabled = !n;
  }
  $("#migMore").addEventListener("click", function () {
    $("#migReview").hidden = true; $("#migStart").hidden = false;
    $("#migParts").textContent = partsSummary() + ".";
    $("#migFile").focus();
  });
  $("#migCancel").addEventListener("click", function () { resetMigration(); $("#addDlg").close(); });
  $("#migImport").addEventListener("click", async function () {
    var batch = migPlan.filter(function (i) { return i.ok && i.cb.checked; }).map(function (i) { return i.account; })
      .filter(function (a) { return !isDup(a); });
    if (!batch.length) return;
    await addAccounts(batch);
    mig.clear(); migPlan = [];
    $("#migDoneText").textContent = "Added " + plural(batch.length, "account", "accounts") + " to your vault" + (S.demo ? " (demo only, not saved)" : "") + ".";
    $("#migReview").hidden = true; $("#migDone").hidden = false;
    $("#migDoneClose").focus();
  });
  $("#migDoneClose").addEventListener("click", function () { $("#addDlg").close(); });
  $("#migDoneBackup").addEventListener("click", function () { $("#addDlg").close(); if (!S.demo) openBackup(); });

  /* ---------- edit ---------- */
  var editId = null;
  function openEdit(id) {
    var a = S.accounts.find(function (x) { return x.id === id; });
    if (!a) return;
    editId = id;
    fillGroupList();
    $("#eIssuer").value = a.issuer; $("#eLabel").value = a.label;
    $("#eGroup").value = a.group || ""; $("#eFav").checked = !!a.fav;
    $("#eSpec").textContent = a.algo + " · " + a.digits + " digits · " + a.period + " second window · added " + fmtDate(a.added);
    $("#eSecret").hidden = true; $("#eSecret").textContent = "";
    $("#eReveal").textContent = "Show setup key";
    $("#editErr").textContent = "";
    $("#delBox").hidden = true;
    openDlg($("#editDlg"));
  }
  $("#eReveal").addEventListener("click", function () {
    var a = S.accounts.find(function (x) { return x.id === editId; });
    if (!a) return;
    var el = $("#eSecret");
    if (el.hidden) { el.textContent = a.secret.replace(/(.{4})/g, "$1 ").trim(); el.hidden = false; $("#eReveal").textContent = "Hide setup key"; }
    else { el.hidden = true; el.textContent = ""; $("#eReveal").textContent = "Show setup key"; }
  });
  $("#editForm").addEventListener("submit", async function (ev) {
    ev.preventDefault();
    var a = S.accounts.find(function (x) { return x.id === editId; });
    if (!a) return;
    var issuer = $("#eIssuer").value.trim(), label = $("#eLabel").value.trim();
    if (!issuer && !label) { $("#editErr").textContent = "Enter a service name or an account."; return; }
    var group = cleanGroup($("#eGroup").value), fav = $("#eFav").checked;
    var changed = a.issuer !== issuer || a.label !== label || (a.group || "") !== group || !!a.fav !== fav;
    a.issuer = issuer; a.label = label;
    if (group) a.group = group; else delete a.group;
    if (fav) a.fav = true; else delete a.fav;
    if (changed) { await persist(); noteChange(); }
    render();
    $("#editDlg").close();
  });
  $("#eDelete").addEventListener("click", function () { $("#delBox").hidden = false; });
  $("#eDeleteNo").addEventListener("click", function () { $("#delBox").hidden = true; });
  $("#eDeleteYes").addEventListener("click", async function () {
    S.accounts = S.accounts.filter(function (x) { return x.id !== editId; });
    keyCache.delete(editId);
    await persist();
    noteChange();
    render();
    $("#editDlg").close();
    toast("Key deleted");
  });

  /* ---------- settings ---------- */
  $("#btnSettings").addEventListener("click", function () {
    $("#sLock").value = String(prefs.autolock);
    $("#sHidden").checked = prefs.lockHidden;
    $("#sErr").textContent = ""; $("#sOk").textContent = "";
    $("#sNew").value = ""; $("#sNew2").value = ""; $("#sErase").value = ""; $("#sEraseBtn").disabled = true;
    $("#setDemoNote").hidden = !S.demo;
    $("#setPass").hidden = S.demo;
    $("#setErase").hidden = S.demo;
    openDlg($("#settingsDlg"));
  });
  $("#sLock").addEventListener("change", function () { prefs.autolock = Number($("#sLock").value); savePrefs(); lastActive = Date.now(); });
  $("#sHidden").addEventListener("change", function () { prefs.lockHidden = $("#sHidden").checked; savePrefs(); });
  document.addEventListener("visibilitychange", function () {
    if (!document.hidden || !prefs.lockHidden || !S.open) return;
    if (S.demo) exitDemo("The demo closed when you switched away.");
    else lock("Locked when you switched away.");
  });
  $("#passForm").addEventListener("submit", async function (ev) {
    ev.preventDefault();
    if (S.demo) return;
    var err = $("#sErr"), ok = $("#sOk");
    err.textContent = ""; ok.textContent = "";
    var p1 = $("#sNew").value;
    try { checkNewPass(p1, $("#sNew2").value); } catch (x) { err.textContent = x.message; return; }
    try {
      var salt = crypto.getRandomValues(new Uint8Array(16));
      S.key = await deriveKey(p1, salt, PBKDF_ITER);
      S.salt = salt; S.iter = PBKDF_ITER;
      await persist();
      noteChange();
      $("#sNew").value = ""; $("#sNew2").value = "";
      ok.textContent = "Passphrase changed. Save a new backup: older backups still need the old passphrase.";
    } catch (e) { err.textContent = "Couldn't change the passphrase. Try again."; }
  });
  $("#sErase").addEventListener("input", function () { $("#sEraseBtn").disabled = S.demo || $("#sErase").value !== "ERASE"; });
  $("#sEraseBtn").addEventListener("click", function () {
    if (S.demo) return;
    lsDel(LS_VAULT);
    envelope = null; damaged = false;
    prefs.changes = 0; prefs.lastBackup = 0; prefs.nudgeHiddenAt = -1; savePrefs();
    lock("Vault erased. Create a new one when you're ready.");
  });

  /* ---------- backup ---------- */
  function openBackup() {
    if (S.demo) { toast("Backups are off in the demo. Create your vault to use them."); return; }
    $("#bText").value = envelope ? JSON.stringify(envelope, null, 2) : "";
    ["#bErr", "#iErr", "#iOk", "#cErr"].forEach(function (s) { $(s).textContent = ""; });
    ["#iText", "#iPass", "#iFile", "#cText", "#cPass", "#cFile"].forEach(function (s) { $(s).value = ""; });
    $("#cResult").hidden = true; $("#cResult").replaceChildren();
    renderBackupStatus();
    openDlg($("#backupDlg"));
  }
  function renderBackupStatus() {
    var el = $("#bkStatus");
    var stale = prefs.changes > 0 || !prefs.lastBackup;
    el.className = "bk-status " + (stale ? "stale" : "fresh");
    el.textContent = backupStatusText();
  }
  function markBackup() {
    prefs.lastBackup = Date.now(); prefs.changes = 0; prefs.nudgeHiddenAt = -1;
    savePrefs(); renderFoot(); renderNudge(); renderBackupStatus();
  }
  $("#btnBackup").addEventListener("click", openBackup);
  $("#bSave").addEventListener("click", async function () {
    var text = $("#bText").value;
    if (!text) { $("#bErr").textContent = "There is nothing to back up yet."; return; }
    $("#bErr").textContent = "";
    var d = new Date(), pad = function (n) { return String(n).padStart(2, "0"); };
    var name = "keyring-backup-" + d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate()) + ".json";
    try {
      var url = URL.createObjectURL(new Blob([text], { type: "application/json" }));
      var a = document.createElement("a");
      a.href = url; a.download = name;
      document.body.append(a); a.click(); a.remove();
      setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
      markBackup();
      toast("Backup downloaded. Check it below to be sure it opens.");
    } catch (e) {
      $("#bErr").textContent = "Your browser blocked the download. Use Copy backup text and keep it somewhere safe.";
    }
  });
  $("#bCopy").addEventListener("click", async function () {
    var ta = $("#bText");
    if (!ta.value) { $("#bErr").textContent = "There is nothing to back up yet."; return; }
    $("#bErr").textContent = "";
    try { await navigator.clipboard.writeText(ta.value); markBackup(); toast("Backup text copied. Paste it somewhere safe."); }
    catch (e) { ta.closest("details").open = true; ta.focus(); ta.select(); $("#bErr").textContent = "Selected. Press Ctrl+C or ⌘C to copy it."; }
  });
  function fileInto(input, textarea) {
    $(input).addEventListener("change", async function (ev) {
      var f = ev.target.files[0];
      if (f) $(textarea).value = await f.text();
    });
  }
  fileInto("#iFile", "#iText");
  fileInto("#cFile", "#cText");

  /* Check a backup: decrypt in memory and compare. Never changes the vault or storage. */
  $("#checkForm").addEventListener("submit", async function (ev) {
    ev.preventDefault();
    var err = $("#cErr"), out = $("#cResult");
    err.textContent = ""; out.hidden = true; out.replaceChildren();
    var env = readBackupText($("#cText").value);
    if (!env) { err.textContent = "That doesn't look like a 2FA Keyring backup. Choose the .json file you downloaded, or paste its full text."; return; }
    var r;
    try { r = await openEnvelope(env, $("#cPass").value); }
    catch (e) { err.textContent = "That passphrase doesn't open this backup. Try the passphrase you had when you made it."; return; }
    var inBackup = sanitizeAccounts(r.data && r.data.accounts);
    var notHere = inBackup.filter(function (a) { return !isDup(a); });
    var notInBackup = S.accounts.filter(function (a) { return !inBackup.some(function (b) { return sameKey(b, a); }); });
    var items = [h("p", { class: "good", text: "This backup opens with that passphrase and contains " + plural(inBackup.length, "key", "keys") + "." })];
    if (r.data && Number.isFinite(r.data.savedAt)) items.push(h("p", { text: "It was made from a vault saved on " + fmtDate(r.data.savedAt) + "." }));
    if (!notHere.length && !notInBackup.length) items.push(h("p", { text: "It matches your vault exactly." }));
    if (notInBackup.length) items.push(h("p", { class: "warnline", text: plural(notInBackup.length, "key in your vault is", "keys in your vault are") + " not in this backup: " + notInBackup.map(nameOf).slice(0, 8).join(", ") + (notInBackup.length > 8 ? "…" : "") + ". Save a fresh backup to include them." }));
    if (notHere.length) items.push(h("p", { text: plural(notHere.length, "key in this backup isn't", "keys in this backup aren't") + " in your vault: " + notHere.map(nameOf).slice(0, 8).join(", ") + (notHere.length > 8 ? "…" : "") + ". Use Merge below to add them." }));
    items.push(h("p", { class: "muted", text: "Your vault wasn't changed." }));
    items.forEach(function (n) { out.append(n); });
    out.hidden = false;
    $("#cPass").value = "";
  });

  $("#importForm").addEventListener("submit", async function (ev) {
    ev.preventDefault();
    if (S.demo) return;
    var err = $("#iErr"), ok = $("#iOk");
    err.textContent = ""; ok.textContent = "";
    var env = readBackupText($("#iText").value);
    if (!env) { err.textContent = "That doesn't look like a 2FA Keyring backup."; return; }
    var r;
    try { r = await openEnvelope(env, $("#iPass").value); }
    catch (e) { err.textContent = "That passphrase doesn't open this backup."; return; }
    var incoming = sanitizeAccounts(r.data.accounts), batch = [];
    incoming.forEach(function (a) { if (!isDup(a) && !batch.some(function (b) { return sameKey(b, a); })) batch.push(a); });
    if (batch.length) { await addAccounts(batch); $("#bText").value = envelope ? JSON.stringify(envelope, null, 2) : ""; renderBackupStatus(); }
    ok.textContent = batch.length ? "Merged " + plural(batch.length, "key", "keys") + "." + (incoming.length - batch.length ? " " + (incoming.length - batch.length) + " were already here." : "")
      : "Nothing new to add. Every key in that backup is already in your vault.";
    $("#iPass").value = "";
  });

  $("#btnLock").addEventListener("click", function () {
    if (S.demo) exitDemo("You left the demo. Nothing from it was saved.");
    else lock("Vault locked.");
  });

  /* ---------- boot ---------- */
  loadStored();
  showLock("");
  updateStorageNote(!storageOK);
  if (location.hash === "#demo") enterDemo();
  addEventListener("hashchange", function () { if (location.hash === "#demo" && !S.open) enterDemo(); });
  setInterval(tick, 250);
  tick();
})();
