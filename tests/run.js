/*
 * 2FA Keyring unit tests. No dependencies: run with `node tests/run.js`.
 * Covers the TOTP core (RFC 6238 vectors, base32) and the Google Authenticator export decoder
 * with synthetic test data only.
 */
"use strict";
const fs = require("fs"), path = require("path"), vm = require("vm");
const A = path.join(__dirname, "..", "assets");
vm.runInThisContext(fs.readFileSync(path.join(A, "totp.js"), "utf8") + "\n" + fs.readFileSync(path.join(A, "migration.js"), "utf8") +
  "\nglobalThis.K={totpAt,base32Encode,base32Decode,parseOtpauth,parseMigrationUri,MigrationCollector,isMigrationUri};");
const K = globalThis.K;
let pass = 0, fail = 0;
function ok(c, msg) { if (c) pass++; else { fail++; console.log("FAIL:", msg); } }
function throwsUser(fn, msg) { try { fn(); ok(false, msg + " (no error)"); } catch (e) { ok(e.user === true, msg + " (" + e.message + ")"); } }

/* --- synthetic Google Authenticator export builder --- */
function varint(n) { const o = []; do { let b = n & 0x7f; n = Math.floor(n / 128); o.push(n ? b | 0x80 : b); } while (n); return o; }
function field(num, wire, val) {
  const tag = varint(num * 8 + wire);
  if (wire === 0) return tag.concat(varint(val));
  const bytes = typeof val === "string" ? Array.from(Buffer.from(val)) : Array.from(val);
  return tag.concat(varint(bytes.length), bytes);
}
function otp(o) {
  let b = field(1, 2, o.secret).concat(field(2, 2, o.name));
  if (o.issuer) b = b.concat(field(3, 2, o.issuer));
  return b.concat(field(4, 0, o.algo ?? 1), field(5, 0, o.digits ?? 1), field(6, 0, o.type ?? 2));
}
function exportUri(entries, size = 1, index = 0, id = 4242) {
  let b = [];
  entries.forEach(e => { b = b.concat(field(1, 2, otp(e))); });
  b = b.concat(field(2, 0, 1), field(3, 0, size), field(4, 0, index), field(5, 0, id));
  return "otpauth-migration://offline?data=" + encodeURIComponent(Buffer.from(b).toString("base64"));
}
const S1 = Buffer.from("48656c6c6f21deadbeef", "hex");        // JBSWY3DPEHPK3PXP
const S2 = Buffer.from("12345678901234567890");                // RFC 6238 SHA-1 seed
const S3 = Buffer.from("12345678901234567890123456789012");    // RFC 6238 SHA-256 seed

(async () => {
  /* RFC 6238 appendix B */
  const seeds = { SHA1: S2, SHA256: S3, SHA512: Buffer.from("1234567890123456789012345678901234567890123456789012345678901234") };
  const vectors = [[59, "94287082", "46119246", "90693936"], [1111111109, "07081804", "68084774", "25091201"], [1111111111, "14050471", "67062674", "99943326"],
    [1234567890, "89005924", "91819424", "93441116"], [2000000000, "69279037", "90698825", "38618901"], [20000000000, "65353130", "77737706", "47863826"]];
  for (const [t, a, b, c] of vectors) {
    const exp = { SHA1: a, SHA256: b, SHA512: c };
    for (const alg of Object.keys(exp)) ok(await K.totpAt(K.base32Encode(seeds[alg]), { algo: alg, digits: 8 }, t * 1000) === exp[alg], `RFC 6238 ${alg} @${t}`);
  }
  /* base32 */
  ok(K.base32Encode(S1) === "JBSWY3DPEHPK3PXP", "base32 known value");
  for (const hex of ["00", "ff00ff", "48656c6c6f21deadbeef", "3132333435363738393031323334353637383930"]) {
    ok(Buffer.from(K.base32Decode(K.base32Encode(Buffer.from(hex, "hex")))).toString("hex") === hex, "base32 round trip " + hex);
  }
  /* otpauth links */
  const p = K.parseOtpauth("otpauth://totp/GitHub:you%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA256&digits=8&period=60");
  ok(p.issuer === "GitHub" && p.label === "you@example.com" && p.algo === "SHA256", "otpauth link parsed");
  throwsUser(() => K.parseOtpauth("otpauth://hotp/x?secret=AAAA"), "HOTP link rejected");

  /* Google Authenticator export: public sample */
  const pub = K.parseMigrationUri("otpauth-migration://offline?data=CjEKCkhlbGxvId6tvu8SGEV4YW1wbGU6YWxpY2VAZ29vZ2xlLmNvbRoHRXhhbXBsZTAC");
  ok(pub.entries[0].secret === "JBSWY3DPEHPK3PXP" && pub.entries[0].issuer === "Example" && pub.entries[0].label === "alice@google.com", "public export sample");
  /* single export with mixed settings */
  const single = K.parseMigrationUri(exportUri([{ secret: S1, name: "Example:alice@example.com", issuer: "Example" },
    { secret: S2, name: "bob@example.com", issuer: "Example Cloud", algo: 2, digits: 2 }]));
  ok(single.entries.length === 2 && single.entries[1].algo === "SHA256" && single.entries[1].digits === 8, "single export decoded");
  ok(single.entries[0].label === "alice@example.com", "issuer prefix stripped from name");
  ok(await K.totpAt(single.entries[1].secret, { algo: "SHA1", digits: 8 }, 59000) === "94287082", "decoded secret produces the RFC code");
  /* multi-part export */
  const c = K.MigrationCollector();
  const r1 = c.add(exportUri([{ secret: S1, name: "a@example.com", issuer: "Part One" }], 2, 0, 77));
  ok(r1.isNew && c.batches()[0].missing.join() === "1", "first part tracked, second missing");
  ok(c.add(exportUri([{ secret: S1, name: "a@example.com", issuer: "Part One" }], 2, 0, 77)).isNew === false, "re-scanning a part isn't new");
  c.add(exportUri([{ secret: S3, name: "b@example.com", issuer: "Part Two", algo: 3 }], 2, 1, 77));
  ok(c.batches()[0].missing.length === 0 && c.entries().length === 2 && c.entries()[1].part === 2, "multi-part export complete");
  /* unsupported entries are flagged, never converted */
  const u = K.parseMigrationUri(exportUri([{ secret: S1, name: "h@example.com", issuer: "Counter", type: 1 },
    { secret: S2, name: "m@example.com", issuer: "Legacy", algo: 4 }, { secret: S3, name: "x@example.com", issuer: "Unknown", type: 0 },
    { secret: S3, name: "ok@example.com", issuer: "Fine" }])).entries;
  ok(!u[0].supported && /HOTP/.test(u[0].reason), "HOTP flagged unsupported");
  ok(!u[1].supported && /MD5/.test(u[1].reason), "MD5 flagged unsupported");
  ok(!u[2].supported, "unknown type flagged unsupported");
  ok(u[3].supported, "supported entry kept");
  /* malformed input */
  const good = Buffer.from(decodeURIComponent(exportUri([{ secret: S1, name: "a@example.com", issuer: "A" }]).split("data=")[1]), "base64");
  throwsUser(() => K.parseMigrationUri("otpauth-migration://offline?data=" + encodeURIComponent(good.subarray(0, 12).toString("base64"))), "truncated export");
  throwsUser(() => K.parseMigrationUri("otpauth-migration://offline?data=%%%%"), "invalid encoding");
  throwsUser(() => K.parseMigrationUri("otpauth-migration://offline?foo=bar"), "missing data");
  throwsUser(() => K.parseMigrationUri(exportUri([{ secret: S1, name: "a", issuer: "A" }], 2, 5)), "impossible part number");
  throwsUser(() => K.parseMigrationUri("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"), "single-account link isn't an export");

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();
