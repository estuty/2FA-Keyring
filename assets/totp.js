/*
 * 2FA Keyring: TOTP core (RFC 4226 / RFC 6238).
 * Shared by the app and the website's live example.
 * Pure functions plus the browser's Web Crypto API. No network access.
 */
"use strict";
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const ALGS = { SHA1: "SHA-1", SHA256: "SHA-256", SHA512: "SHA-512" };
const uerr = (m) => Object.assign(new Error(m), { user: true });

function normSecret(s) {
  return String(s || "").toUpperCase().replace(/[\s\-_=]/g, "");
}

function base32Decode(input) {
  const s = normSecret(input);
  if (!s || /[^A-Z2-7]/.test(s)) throw new Error("bad base32");
  let bits = 0, val = 0;
  const out = [];
  for (const ch of s) {
    val = (val << 5) | B32.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      out.push((val >> (bits - 8)) & 255);
      bits -= 8;
      val &= (1 << bits) - 1;
    }
  }
  return new Uint8Array(out);
}

async function hmacKey(bytes, algo) {
  return crypto.subtle.importKey("raw", bytes, { name: "HMAC", hash: ALGS[algo] }, false, ["sign"]);
}

async function hotpFromKey(key, counter, digits) {
  const buf = new ArrayBuffer(8);
  const dv = new DataView(buf);
  dv.setUint32(0, Math.floor(counter / 4294967296));
  dv.setUint32(4, counter >>> 0);
  const h = new Uint8Array(await crypto.subtle.sign("HMAC", key, buf));
  const o = h[h.length - 1] & 15;
  const bin = ((h[o] & 127) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(bin % Math.pow(10, digits)).padStart(digits, "0");
}

async function totpAt(secret, opts, nowMs) {
  const o = Object.assign({ algo: "SHA1", digits: 6, period: 30 }, opts);
  const key = await hmacKey(base32Decode(secret), o.algo);
  return hotpFromKey(key, Math.floor(nowMs / 1000 / o.period), o.digits);
}

function groupCode(code) {
  const k = Math.ceil(code.length / 2);
  return code.slice(0, k) + " " + code.slice(k);
}

function parseOtpauth(uri) {
  const s = String(uri || "").trim();
  if (/^otpauth-migration:\/\//i.test(s)) {
    throw uerr("That is a Google Authenticator export code. Add each service with its own setup key or link instead.");
  }
  const m = /^otpauth:\/\/(totp|hotp)\/([^?]*)\??(.*)$/i.exec(s);
  if (!m) throw uerr("That isn't an otpauth:// link.");
  if (m[1].toLowerCase() === "hotp") throw uerr("Counter-based (HOTP) keys aren't supported. Only time-based keys are.");
  let label = m[2];
  try { label = decodeURIComponent(label); } catch (e) {}
  const q = new URLSearchParams(m[3]);
  const secret = q.get("secret") || "";
  if (!secret) throw uerr("That link has no secret in it.");
  let issuer = q.get("issuer") || "";
  let account = label;
  const i = label.indexOf(":");
  if (i >= 0) {
    const pre = label.slice(0, i).trim();
    account = label.slice(i + 1).trim();
    if (!issuer) issuer = pre;
  }
  return {
    issuer: issuer.trim(),
    label: account.trim(),
    secret,
    algo: (q.get("algorithm") || "SHA1").toUpperCase(),
    digits: q.get("digits") || 6,
    period: q.get("period") || 30
  };
}

function base32Encode(bytes) {
  let bits = 0, val = 0, out = "";
  for (const b of bytes) {
    val = (val << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += B32[(val >>> (bits - 5)) & 31];
      bits -= 5;
    }
    val &= (1 << bits) - 1;
  }
  if (bits > 0) out += B32[(val << (5 - bits)) & 31];
  return out;
}
