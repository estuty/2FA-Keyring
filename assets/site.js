/*
 * 2FA Keyring website: live sample codes on the home page.
 * Uses the same TOTP core as the app (assets/totp.js) with public test keys only.
 * The sample vault on this page is in memory; nothing is stored or sent.
 */
(function () {
  "use strict";
  if (!window.crypto || !crypto.subtle) return;
  var C = 94.2478;
  function rowsOf(sel, extra) {
    return Array.prototype.slice.call(document.querySelectorAll(sel)).map(function (el) {
      var r = {
        el: el,
        secret: el.getAttribute("data-secret"),
        algo: el.getAttribute("data-algo") || "SHA1",
        digits: Number(el.getAttribute("data-digits") || 6),
        period: Number(el.getAttribute("data-period") || 30),
        digitsEl: el.querySelector(".digits"),
        arc: el.querySelector(".arc"),
        sec: el.querySelector(".sec") || el.querySelector(".left"),
        counter: -1, key: null, code: ""
      };
      if (extra) extra(r);
      return r;
    });
  }
  var hero = rowsOf("#heroDemo .demo-row");
  var trial = rowsOf("#tryList .try-row");
  var all = hero.concat(trial);
  if (!all.length) return;

  async function update(r, now) {
    var t = now / 1000, rem = r.period - (t % r.period), counter = Math.floor(t / r.period);
    if (r.arc) r.arc.style.strokeDashoffset = String(C * (1 - rem / r.period));
    if (r.sec) r.sec.textContent = Math.ceil(rem) + (r.arc ? "" : "s");
    r.el.classList.toggle("urgent", rem <= 5);
    if (r.counter === counter) return;
    r.counter = counter;
    if (!r.key) r.key = await hmacKey(base32Decode(r.secret), r.algo);
    r.code = await hotpFromKey(r.key, counter, r.digits);
    r.digitsEl.textContent = groupCode(r.code);
  }
  var busy = false;
  async function tick() {
    if (busy) return;
    busy = true;
    try {
      var now = Date.now();
      await Promise.all(all.map(function (r) { return update(r, now); }));
    } catch (e) {
    } finally { busy = false; }
  }

  /* Interactive sample vault */
  var q = document.getElementById("tryQ");
  var status = document.getElementById("tryStatus");
  var empty = document.getElementById("tryEmpty");
  var filter = "all";
  function apply() {
    var text = q ? q.value.trim().toLowerCase() : "";
    var shown = 0;
    trial.forEach(function (r) {
      var el = r.el;
      var okF = filter === "all" || (filter === "fav" ? el.getAttribute("data-fav") === "1" : el.getAttribute("data-group") === filter);
      var okQ = !text || (el.getAttribute("data-name") || "").toLowerCase().indexOf(text) >= 0;
      el.hidden = !(okF && okQ);
      if (!el.hidden) shown++;
    });
    if (empty) empty.hidden = shown > 0;
  }
  if (q) q.addEventListener("input", apply);
  document.querySelectorAll(".try-chips .chip").forEach(function (b) {
    b.addEventListener("click", function () {
      filter = b.getAttribute("data-f");
      document.querySelectorAll(".try-chips .chip").forEach(function (o) { o.setAttribute("aria-pressed", String(o === b)); });
      apply();
    });
  });
  trial.forEach(function (r) {
    var btn = r.el.querySelector(".try-code");
    var name = r.el.querySelector(".who b").textContent.replace("★", "").trim();
    btn.setAttribute("aria-label", "Copy sample code for " + name);
    btn.addEventListener("click", async function () {
      if (!r.code) return;
      var msg;
      try { await navigator.clipboard.writeText(r.code); msg = "Copied " + groupCode(r.code) + " for " + name + ". It's a sample code, so it won't sign you in anywhere."; }
      catch (e) { msg = "Your browser didn't allow copying here. In the app, clicking a code copies it."; }
      if (status) status.textContent = msg;
      r.el.classList.add("flash");
      setTimeout(function () { r.el.classList.remove("flash"); }, 500);
    });
  });

  tick();
  setInterval(tick, 250);
})();
