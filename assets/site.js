/*
 * 2FA Keyring website: live example codes in the hero.
 * Uses the same TOTP core as the app (assets/totp.js) with the public RFC 6238 test keys.
 */
(function () {
  "use strict";
  if (!window.crypto || !crypto.subtle) return;
  var C = 94.2478;
  var rows = Array.prototype.slice.call(document.querySelectorAll(".demo-row")).map(function (el) {
    return {
      el: el,
      secret: el.getAttribute("data-secret"),
      algo: el.getAttribute("data-algo"),
      digits: Number(el.getAttribute("data-digits")),
      period: Number(el.getAttribute("data-period")),
      digitsEl: el.querySelector(".digits"),
      arc: el.querySelector(".arc"),
      sec: el.querySelector(".sec"),
      counter: -1,
      key: null
    };
  });
  if (!rows.length) return;

  async function update(r, now) {
    var t = now / 1000, rem = r.period - (t % r.period), counter = Math.floor(t / r.period);
    r.arc.style.strokeDashoffset = String(C * (1 - rem / r.period));
    r.sec.textContent = String(Math.ceil(rem));
    r.el.classList.toggle("urgent", rem <= 5);
    if (r.counter === counter) return;
    r.counter = counter;
    if (!r.key) r.key = await hmacKey(base32Decode(r.secret), r.algo);
    r.digitsEl.textContent = groupCode(await hotpFromKey(r.key, counter, r.digits));
  }
  var busy = false;
  async function tick() {
    if (busy) return;
    busy = true;
    try {
      var now = Date.now();
      await Promise.all(rows.map(function (r) { return update(r, now); }));
    } catch (e) {
    } finally { busy = false; }
  }
  tick();
  setInterval(tick, 250);
})();
