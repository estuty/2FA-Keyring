/*
 * 2FA Keyring app.
 * Depends on ../assets/totp.js (TOTP core) and ../assets/vendor/jsQR.js (QR decoding).
 * Keys are encrypted with AES-256-GCM using a key derived from your passphrase
 * (PBKDF2-SHA256, 600,000 iterations) and stored in this browser's localStorage.
 * The page's Content-Security-Policy forbids all network connections (connect-src 'none').
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
  var DEMO = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
  var LS_VAULT = "keyring.vault.v1", LS_PREFS = "keyring.prefs.v1";
  var MIN_PASS = 12;
  var PBKDF_ITER = 600000;
  var enc = new TextEncoder(), dec = new TextDecoder();

  /* ---------- storage ---------- */
  var storageOK = true, memVault = null, damaged = false;
  function lsGet(k) { try { return localStorage.getItem(k); } catch (e) { storageOK = false; return null; } }
  function lsSet(k, v) { try { localStorage.setItem(k, v); return true; } catch (e) { storageOK = false; return false; } }
  function lsDel(k) { try { localStorage.removeItem(k); } catch (e) {} }

  var S = { key: null, salt: null, iter: PBKDF_ITER, accounts: [] };
  var envelope = null;
  var prefs = { autolock: 5, lastBackup: 0, lockHidden: false };
  var lastActive = Date.now();
  var rows = new Map();
  var keyCache = new Map();

  function checkEnvelope(e) {
    if (!e || e.app !== "keyring" || e.v !== 1 || typeof e.salt !== "string" || typeof e.iv !== "string" ||
        typeof e.ct !== "string" || !Number.isInteger(e.iter) || e.iter < 100000 || e.iter > 2000000) {
      throw new Error("bad envelope");
    }
    return e;
  }

  function loadStored() {
    var raw = lsGet(LS_VAULT);
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
      } catch (e) {}
    }
  }
  function savePrefs() { lsSet(LS_PREFS, JSON.stringify(prefs)); }

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
  function persist() {
    saveChain = saveChain.then(async function () {
      if (!S.key) return;
      var env = await seal(S.key, S.salt, S.iter, { accounts: S.accounts });
      envelope = env;
      damaged = false;
      var ok = lsSet(LS_VAULT, JSON.stringify(env));
      updateStorageNote(!ok);
    }).catch(function () {});
    return saveChain;
  }
  function updateStorageNote(show) {
    document.querySelectorAll(".storageNote").forEach(function (n) { n.hidden = !(show || !storageOK); });
  }

  /* ---------- accounts ---------- */
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
    return {
      id: typeof o.id === "string" && o.id ? o.id : crypto.randomUUID(),
      issuer: issuer, label: label, secret: secret, algo: algo, digits: digits, period: period,
      added: Number.isFinite(o.added) ? o.added : Date.now()
    };
  }
  function sanitizeAccounts(arr) {
    var out = [];
    if (!Array.isArray(arr)) return out;
    arr.forEach(function (o) { try { out.push(makeAccount(o)); } catch (e) {} });
    return out;
  }
  function isDup(a) {
    return S.accounts.some(function (x) {
      return x.secret === a.secret && x.algo === a.algo && x.digits === a.digits && x.period === a.period;
    });
  }
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
    toastTimer = setTimeout(function () { t.classList.remove("show"); }, 2200);
  }
  function fmtDate(ts) {
    return new Date(ts).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
  }
  function openDlg(d) { if (!d.open) d.showModal(); }
  document.querySelectorAll("dialog").forEach(function (d) {
    d.addEventListener("click", function (ev) { if (ev.target === d) d.close(); });
  });
  document.querySelectorAll("[data-close]").forEach(function (b) {
    b.addEventListener("click", function () { $("#" + b.getAttribute("data-close")).close(); });
  });

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

  function setVaultState(open) {
    var st = $("#vaultState");
    st.setAttribute("data-state", open ? "unlocked" : "locked");
    st.textContent = open ? "Vault unlocked" : "Vault locked";
    $("#leaveNote").hidden = !open;
  }

  function showLock(note) {
    appView.hidden = true;
    lockView.hidden = false;
    setVaultState(false);
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
    lockView.hidden = true;
    appView.hidden = false;
    setVaultState(true);
    lastActive = Date.now();
    $("#q").value = "";
    render();
    updateStorageNote(false);
  }

  function lock(note) {
    S.key = null; S.salt = null; S.accounts = [];
    keyCache.clear(); rows.clear();
    $("#list").replaceChildren();
    document.querySelectorAll("dialog").forEach(function (d) { if (d.open) d.close(); });
    $("#entries").replaceChildren();
    ["#lLinks", "#eSecret", "#bText", "#iText", "#iPass", "#sNew", "#sNew2"].forEach(function (s) {
      var el = $(s); if (!el) return;
      if ("value" in el) el.value = ""; else el.textContent = "";
    });
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
        S.key = key; S.salt = salt; S.iter = PBKDF_ITER; S.accounts = [];
        await persist();
      } else {
        var r = await openEnvelope(envelope, pass);
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
    var env;
    try { env = checkEnvelope(JSON.parse($("#rText").value)); }
    catch (e) { err.textContent = "That doesn't look like a 2FA Keyring backup."; return; }
    $("#rBtn").disabled = true;
    try {
      var r = await openEnvelope(env, $("#rPass").value);
      S.key = r.key; S.salt = r.salt; S.iter = r.iter; S.accounts = sanitizeAccounts(r.data.accounts);
      await persist();
      $("#rPass").value = ""; $("#rText").value = "";
      mode = "unlock";
      enterApp();
    } catch (e) {
      err.textContent = "That passphrase doesn't open this backup.";
    } finally { $("#rBtn").disabled = false; }
  });
  $("#discardBtn").addEventListener("click", function () {
    lsDel(LS_VAULT); envelope = null; damaged = false;
    showLock("Starting fresh. Create a new vault.");
  });

  /* ---------- list ---------- */
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
    var edit = h("button", { class: "icon edit", type: "button", "aria-label": "Edit " + name });
    edit.innerHTML = '<svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true"><path d="M4 20h4L19 9l-4-4L4 16v4z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/></svg>';
    var mono = h("span", { class: "mono", "aria-hidden": "true" }, initial);
    mono.style.setProperty("--h", String(hue(name)));
    var el = h("li", { class: "row" },
      mono,
      h("div", { class: "who" }, h("span", { class: "issuer", text: name }), a.issuer && a.label ? h("span", { class: "label", text: a.label }) : null),
      btn, ring, edit);
    var r = {
      el: el, a: a, counter: -1, nextCounter: -1, code: "", urgent: false,
      digits: digits, next: next, sec: sec, arc: ring.querySelector(".arc")
    };
    btn.addEventListener("click", function () { copyCode(r); });
    edit.addEventListener("click", function () { openEdit(a.id); });
    return r;
  }

  function render() {
    var q = $("#q").value.trim().toLowerCase();
    var all = S.accounts.slice().sort(function (x, y) {
      return nameOf(x).toLowerCase().localeCompare(nameOf(y).toLowerCase()) || x.label.toLowerCase().localeCompare(y.label.toLowerCase());
    });
    var list = all.filter(function (a) { return !q || (a.issuer + " " + a.label).toLowerCase().indexOf(q) >= 0; });
    var ul = $("#list");
    ul.replaceChildren();
    rows.clear();
    list.forEach(function (a) { var r = buildRow(a); rows.set(a.id, r); ul.append(r.el); });
    ul.hidden = list.length === 0;
    $("#empty").hidden = S.accounts.length > 0;
    $("#noMatch").hidden = !(S.accounts.length > 0 && list.length === 0);
    $("#count").textContent = S.accounts.length + (S.accounts.length === 1 ? " key" : " keys") + " · click a code to copy it";
    renderFoot();
    tick();
  }

  function renderFoot() {
    var foot = $("#foot");
    foot.replaceChildren();
    foot.append(h("span", { text: "Codes are calculated on this device. Your keys stay here, encrypted." }));
    var b = h("button", { class: "linkbtn", type: "button", text: prefs.lastBackup ? "Last backup " + fmtDate(prefs.lastBackup) : "No backup yet. Make one" });
    b.addEventListener("click", openBackup);
    foot.append(b);
  }

  async function copyCode(r) {
    if (!r.code) return;
    try {
      await navigator.clipboard.writeText(r.code);
      toast("Copied " + groupCode(r.code));
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
      if (!heroKey) heroKey = await hmacKey(base32Decode(DEMO), "SHA1");
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
      if (!S.key || r.counter !== counter) return;
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
      if (!S.key) return;
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
      if (!S.key) return;
      if (prefs.autolock > 0 && now - lastActive > prefs.autolock * 60000) {
        lock("Locked after " + prefs.autolock + (prefs.autolock === 1 ? " minute" : " minutes") + " of inactivity.");
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
  function setTab(which) {
    var key = which === "key";
    $("#tabKey").setAttribute("aria-selected", String(key));
    $("#tabLink").setAttribute("aria-selected", String(!key));
    $("#keyForm").hidden = !key;
    $("#linkForm").hidden = key;
  }
  $("#tabKey").addEventListener("click", function () { setTab("key"); });
  $("#tabLink").addEventListener("click", function () { setTab("link"); });

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
      '<div class="field"><label for="' + id("s") + '">Setup key</label><input id="' + id("s") + '" class="k-secret mono-in" spellcheck="false" autocapitalize="off" autocomplete="off" placeholder="JBSW Y3DP EHPK 3PXP or an otpauth:// link"></div>' +
      '<p class="prev" hidden></p>' +
      '<details><summary>Advanced</summary><div class="row2">' +
        '<div class="field"><label for="' + id("a") + '">Algorithm</label><select id="' + id("a") + '" class="k-algo"><option>SHA1</option><option>SHA256</option><option>SHA512</option></select></div>' +
        '<div class="field"><label for="' + id("d") + '">Digits</label><select id="' + id("d") + '" class="k-digits"><option>6</option><option>7</option><option>8</option></select></div>' +
        '<div class="field"><label for="' + id("p") + '">Seconds</label><input id="' + id("p") + '" class="k-period" type="number" min="1" max="300" value="30" inputmode="numeric"></div>' +
      '</div></details>' +
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
    if (!/^otpauth(-migration)?:\/\//i.test(raw)) return;
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

  function openAdd() {
    $("#linkForm").reset();
    $("#keyErr").textContent = ""; $("#linkErr").textContent = "";
    resetEntries();
    setTab("key");
    openDlg($("#addDlg"));
    setTimeout(function () { var f = $("#entries .k-issuer"); if (f) f.focus(); }, 0);
  }
  $("#btnAdd").addEventListener("click", openAdd);
  $("#emptyAdd").addEventListener("click", openAdd);
  $("#addClose").addEventListener("click", function () { $("#addDlg").close(); });
  $("#addEntry").addEventListener("click", addEntry);

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
        if (/^otpauth/i.test(raw)) parseOtpauth(raw);
        var a = makeAccount({
          issuer: fld(li, ".k-issuer").value, label: fld(li, ".k-label").value, secret: raw,
          algo: fld(li, ".k-algo").value, digits: fld(li, ".k-digits").value, period: fld(li, ".k-period").value
        });
        if (isDup(a)) throw uerr("This key is already in your vault.");
        var twice = batch.some(function (b) {
          return b.secret === a.secret && b.algo === a.algo && b.digits === a.digits && b.period === a.period;
        });
        if (twice) throw uerr("This key is entered twice above.");
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
    Array.prototype.push.apply(S.accounts, batch);
    await persist();
    render();
    $("#addDlg").close();
    toast(batch.length === 1 ? "Added " + nameOf(batch[0]) : "Added " + batch.length + " keys");
  });

  $("#linkForm").addEventListener("submit", async function (ev) {
    ev.preventDefault();
    var err = $("#linkErr"); err.textContent = "";
    var lines = $("#lLinks").value.split(/\r?\n/).map(function (s) { return s.trim(); }).filter(Boolean);
    if (!lines.length) { err.textContent = "Paste at least one otpauth:// link."; return; }
    var added = 0, dups = 0, problems = [];
    lines.forEach(function (ln) {
      try {
        var a = makeAccount(parseOtpauth(ln));
        if (isDup(a)) { dups++; return; }
        S.accounts.push(a); added++;
      } catch (e) {
        var m = e.user ? e.message : "One link could not be read.";
        if (problems.indexOf(m) < 0) problems.push(m);
      }
    });
    if (added) { await persist(); render(); toast("Added " + added + (added === 1 ? " key" : " keys")); }
    if (dups) problems.unshift(dups + (dups === 1 ? " key is" : " keys are") + " already in your vault.");
    if (problems.length) err.textContent = problems.join(" ");
    else $("#addDlg").close();
  });

  function decodeQr(file) {
    return new Promise(function (resolve, reject) {
      if (typeof jsQR !== "function") { reject(uerr("QR reading isn't available here. Paste the otpauth:// link instead.")); return; }
      var img = new Image();
      var url = URL.createObjectURL(file);
      img.onload = function () {
        var sc = Math.min(1, 1400 / Math.max(img.width, img.height));
        var w = Math.max(1, Math.round(img.width * sc)), hh = Math.max(1, Math.round(img.height * sc));
        var cv = document.createElement("canvas");
        cv.width = w; cv.height = hh;
        var ctx = cv.getContext("2d", { willReadFrequently: true });
        ctx.drawImage(img, 0, 0, w, hh);
        var res = jsQR(ctx.getImageData(0, 0, w, hh).data, w, hh, { inversionAttempts: "attemptBoth" });
        URL.revokeObjectURL(url);
        if (res && res.data) resolve(res.data); else reject(uerr("No QR code found in that image. Try a sharper, closer screenshot."));
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
    if (found.length) {
      var ta = $("#lLinks");
      ta.value = (ta.value.trim() ? ta.value.trim() + "\n" : "") + found.join("\n");
    }
    if (missed.length) err.textContent = "No QR code found in " + missed.join(", ") + ". Try a sharper, closer screenshot.";
  });

  $("#emptyDemo").addEventListener("click", async function () {
    var a = makeAccount({ issuer: "Example", label: "RFC 6238 test key (safe to delete)", secret: DEMO });
    if (!isDup(a)) { S.accounts.push(a); await persist(); render(); }
  });

  /* ---------- edit ---------- */
  var editId = null;
  function openEdit(id) {
    var a = S.accounts.find(function (x) { return x.id === id; });
    if (!a) return;
    editId = id;
    $("#eIssuer").value = a.issuer; $("#eLabel").value = a.label;
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
    a.issuer = issuer; a.label = label;
    await persist();
    render();
    $("#editDlg").close();
  });
  $("#eDelete").addEventListener("click", function () { $("#delBox").hidden = false; });
  $("#eDeleteNo").addEventListener("click", function () { $("#delBox").hidden = true; });
  $("#eDeleteYes").addEventListener("click", async function () {
    S.accounts = S.accounts.filter(function (x) { return x.id !== editId; });
    keyCache.delete(editId);
    await persist();
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
    openDlg($("#settingsDlg"));
  });
  $("#sLock").addEventListener("change", function () { prefs.autolock = Number($("#sLock").value); savePrefs(); lastActive = Date.now(); });
  $("#sHidden").addEventListener("change", function () { prefs.lockHidden = $("#sHidden").checked; savePrefs(); });
  document.addEventListener("visibilitychange", function () {
    if (document.hidden && prefs.lockHidden && S.key) lock("Locked when you switched away.");
  });
  $("#passForm").addEventListener("submit", async function (ev) {
    ev.preventDefault();
    var err = $("#sErr"), ok = $("#sOk");
    err.textContent = ""; ok.textContent = "";
    var p1 = $("#sNew").value;
    try { checkNewPass(p1, $("#sNew2").value); } catch (x) { err.textContent = x.message; return; }
    try {
      var salt = crypto.getRandomValues(new Uint8Array(16));
      S.key = await deriveKey(p1, salt, PBKDF_ITER);
      S.salt = salt; S.iter = PBKDF_ITER;
      await persist();
      $("#sNew").value = ""; $("#sNew2").value = "";
      ok.textContent = "Passphrase changed. Make a new backup so it matches.";
    } catch (e) { err.textContent = "Couldn't change the passphrase. Try again."; }
  });
  $("#sErase").addEventListener("input", function () { $("#sEraseBtn").disabled = $("#sErase").value !== "ERASE"; });
  $("#sEraseBtn").addEventListener("click", function () {
    lsDel(LS_VAULT);
    envelope = null; damaged = false;
    lock("Vault erased. Create a new one when you're ready.");
  });

  /* ---------- backup ---------- */
  function openBackup() {
    $("#bText").value = envelope ? JSON.stringify(envelope, null, 2) : "";
    $("#bErr").textContent = ""; $("#iErr").textContent = ""; $("#iOk").textContent = "";
    $("#iText").value = ""; $("#iPass").value = ""; $("#iFile").value = "";
    $("#bLast").textContent = prefs.lastBackup ? "Last backup: " + fmtDate(prefs.lastBackup) + "." : "You haven't made a backup yet.";
    openDlg($("#backupDlg"));
  }
  function markBackup() { prefs.lastBackup = Date.now(); savePrefs(); renderFoot(); $("#bLast").textContent = "Last backup: " + fmtDate(prefs.lastBackup) + "."; }
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
      toast("Backup saved");
    } catch (e) {
      $("#bErr").textContent = "Your browser blocked the download. Use Copy text and keep it somewhere safe.";
    }
  });
  $("#bCopy").addEventListener("click", async function () {
    var ta = $("#bText");
    if (!ta.value) { $("#bErr").textContent = "There is nothing to back up yet."; return; }
    $("#bErr").textContent = "";
    try { await navigator.clipboard.writeText(ta.value); markBackup(); toast("Backup text copied"); }
    catch (e) { ta.focus(); ta.select(); $("#bErr").textContent = "Selected. Press Ctrl+C or ⌘C to copy it."; }
  });
  $("#iFile").addEventListener("change", async function (ev) {
    var f = ev.target.files[0];
    if (f) $("#iText").value = await f.text();
  });
  $("#importForm").addEventListener("submit", async function (ev) {
    ev.preventDefault();
    var err = $("#iErr"), ok = $("#iOk");
    err.textContent = ""; ok.textContent = "";
    var env;
    try { env = checkEnvelope(JSON.parse($("#iText").value)); }
    catch (e) { err.textContent = "That doesn't look like a 2FA Keyring backup."; return; }
    var r;
    try { r = await openEnvelope(env, $("#iPass").value); }
    catch (e) { err.textContent = "That passphrase doesn't open this backup."; return; }
    var incoming = sanitizeAccounts(r.data.accounts), added = 0;
    incoming.forEach(function (a) { if (!isDup(a)) { S.accounts.push(a); added++; } });
    if (added) { await persist(); render(); $("#bText").value = envelope ? JSON.stringify(envelope, null, 2) : ""; }
    ok.textContent = added ? "Merged " + added + (added === 1 ? " key." : " keys.") + (incoming.length - added ? " " + (incoming.length - added) + " were already here." : "")
      : "Nothing new to add. Every key in that backup is already in your vault.";
    $("#iPass").value = "";
  });

  $("#btnLock").addEventListener("click", function () { lock("Vault locked."); });

  /* ---------- boot ---------- */
  loadStored();
  showLock("");
  updateStorageNote(!storageOK);
  setInterval(tick, 250);
  tick();
})();
