/*
 * 2FA Keyring: Google Authenticator export ("otpauth-migration://offline?data=...") decoder.
 * Runs entirely in the browser. The data is a base64-encoded protobuf MigrationPayload:
 *   1 otp_parameters (repeated message): 1 secret (bytes), 2 name, 3 issuer,
 *       4 algorithm (0 unspecified, 1 SHA1, 2 SHA256, 3 SHA512, 4 MD5),
 *       5 digits (0 unspecified, 1 six, 2 eight), 6 type (0 unspecified, 1 HOTP, 2 TOTP), 7 counter
 *   2 version, 3 batch_size, 4 batch_index, 5 batch_id
 * Depends on totp.js (uerr, base32Encode). Nothing here touches storage or the network.
 */
"use strict";

const MIGRATION_PREFIX = /^otpauth-migration:\/\/offline\?/i;

function isMigrationUri(s) {
  return MIGRATION_PREFIX.test(String(s || "").trim());
}

function migB64ToBytes(s) {
  let t = s.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  if (!t || /[^A-Za-z0-9+/=]/.test(t)) throw uerr("The export data contains characters that aren't valid.");
  while (t.length % 4) t += "=";
  let bin;
  try { bin = atob(t); } catch (e) { throw uerr("The export data couldn't be decoded."); }
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/* Minimal protobuf reader: returns [{field, wire, value}] for one message. */
function pbFields(buf) {
  const fields = [];
  let i = 0;
  const bad = () => uerr("The export data is incomplete or damaged. Scan the QR code again.");
  function varint() {
    let result = 0, mul = 1, b;
    for (let n = 0; n < 10; n++) {
      if (i >= buf.length) throw bad();
      b = buf[i++];
      result += (b & 0x7f) * mul;
      if (!(b & 0x80)) return result;
      mul *= 128;
    }
    throw bad();
  }
  while (i < buf.length) {
    const tag = varint();
    const field = Math.floor(tag / 8), wire = tag % 8;
    if (field === 0) throw bad();
    if (wire === 0) fields.push({ field, wire, value: varint() });
    else if (wire === 2) {
      const len = varint();
      if (i + len > buf.length) throw bad();
      fields.push({ field, wire, value: buf.subarray(i, i + len) });
      i += len;
    } else if (wire === 1) { if (i + 8 > buf.length) throw bad(); i += 8; }
    else if (wire === 5) { if (i + 4 > buf.length) throw bad(); i += 4; }
    else throw bad();
  }
  return fields;
}

const MIG_ALGOS = { 0: "SHA1", 1: "SHA1", 2: "SHA256", 3: "SHA512" };
const MIG_DIGITS = { 0: 6, 1: 6, 2: 8 };

function migText(bytes) {
  try { return new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
  catch (e) { return ""; }
}

/*
 * Parse one otpauth-migration URI.
 * Returns { batchSize, batchIndex, batchId, entries: [...] }.
 * Each entry: { issuer, label, secret, algo, digits, period, supported, reason }
 * Unsupported entries (HOTP, MD5, unknown types) are returned with supported=false and a reason,
 * never converted into something else.
 */
function parseMigrationUri(uri) {
  const s = String(uri || "").trim();
  if (!isMigrationUri(s)) throw uerr("That isn't a Google Authenticator export link.");
  const query = s.slice(s.indexOf("?") + 1);
  let data = null;
  for (const part of query.split("&")) {
    const eq = part.indexOf("=");
    if (eq > 0 && part.slice(0, eq) === "data") {
      try { data = decodeURIComponent(part.slice(eq + 1).replace(/\+/g, "%2B")); }
      catch (e) { throw uerr("The export link is damaged. Scan the QR code again."); }
    }
  }
  if (!data) throw uerr("The export link has no account data in it.");
  const top = pbFields(migB64ToBytes(data));
  const res = { version: 0, batchSize: 1, batchIndex: 0, batchId: 0, entries: [] };
  for (const f of top) {
    if (f.field === 1 && f.wire === 2) res.entries.push(parseOtpParams(f.value));
    else if (f.field === 2 && f.wire === 0) res.version = f.value;
    else if (f.field === 3 && f.wire === 0) res.batchSize = f.value || 1;
    else if (f.field === 4 && f.wire === 0) res.batchIndex = f.value;
    else if (f.field === 5 && f.wire === 0) res.batchId = f.value;
  }
  if (res.batchSize < 1 || res.batchSize > 100 || res.batchIndex >= res.batchSize) {
    throw uerr("The export's part numbers don't make sense. Scan the QR code again.");
  }
  if (!res.entries.length) throw uerr("This export doesn't contain any accounts.");
  return res;
}

function parseOtpParams(buf) {
  const e = { secretBytes: null, name: "", issuer: "", algorithm: 0, digitCode: 0, type: 0 };
  for (const f of pbFields(buf)) {
    if (f.field === 1 && f.wire === 2) e.secretBytes = f.value;
    else if (f.field === 2 && f.wire === 2) e.name = migText(f.value);
    else if (f.field === 3 && f.wire === 2) e.issuer = migText(f.value);
    else if (f.field === 4 && f.wire === 0) e.algorithm = f.value;
    else if (f.field === 5 && f.wire === 0) e.digitCode = f.value;
    else if (f.field === 6 && f.wire === 0) e.type = f.value;
  }
  let issuer = e.issuer.trim(), label = e.name.trim();
  const colon = label.indexOf(":");
  if (colon >= 0) {
    const pre = label.slice(0, colon).trim();
    if (!issuer) { issuer = pre; label = label.slice(colon + 1).trim(); }
    else if (pre.toLowerCase() === issuer.toLowerCase()) label = label.slice(colon + 1).trim();
  }
  const out = {
    issuer: issuer.slice(0, 80), label: label.slice(0, 120),
    secret: e.secretBytes && e.secretBytes.length ? base32Encode(e.secretBytes) : "",
    algo: MIG_ALGOS[e.algorithm] || null,
    digits: MIG_DIGITS[e.digitCode] || null,
    period: 30, supported: true, reason: ""
  };
  if (e.type === 1) { out.supported = false; out.reason = "Counter-based (HOTP) codes aren't supported"; }
  else if (e.type !== 2) { out.supported = false; out.reason = "Unknown code type"; }
  else if (e.algorithm === 4) { out.supported = false; out.reason = "MD5 codes aren't supported"; }
  else if (!out.algo) { out.supported = false; out.reason = "Unknown algorithm"; }
  else if (!out.digits) { out.supported = false; out.reason = "Unknown number of digits"; }
  else if (!out.secret || e.secretBytes.length < 5) { out.supported = false; out.reason = "Missing or too-short key"; }
  if (!out.issuer && !out.label) out.label = "Unnamed account";
  return out;
}

/*
 * Collects scanned parts of one or more exports.
 * add(uri) -> { batchId, batchIndex, batchSize, isNew }
 * batches() -> [{ batchId, batchSize, parts: Map(index -> entries), missing: [indexes] }]
 */
function MigrationCollector() {
  const groups = new Map();
  return {
    add(uri) {
      const p = parseMigrationUri(uri);
      const key = p.batchSize > 1 ? "b" + p.batchId + "/" + p.batchSize : "single:" + uri.trim();
      let g = groups.get(key);
      if (!g) { g = { batchId: p.batchId, batchSize: p.batchSize, parts: new Map() }; groups.set(key, g); }
      const isNew = !g.parts.has(p.batchIndex);
      g.parts.set(p.batchIndex, p.entries);
      return { batchId: p.batchId, batchIndex: p.batchIndex, batchSize: p.batchSize, isNew };
    },
    batches() {
      return Array.from(groups.values()).map(g => {
        const missing = [];
        for (let i = 0; i < g.batchSize; i++) if (!g.parts.has(i)) missing.push(i);
        return { batchId: g.batchId, batchSize: g.batchSize, parts: g.parts, missing };
      });
    },
    entries() {
      const out = [];
      for (const g of groups.values()) {
        const idx = Array.from(g.parts.keys()).sort((a, b) => a - b);
        for (const i of idx) for (const e of g.parts.get(i)) out.push(Object.assign({ part: i + 1, of: g.batchSize }, e));
      }
      return out;
    },
    clear() { groups.clear(); },
    get size() { return groups.size; }
  };
}
