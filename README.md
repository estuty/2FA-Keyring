# 2FA Keyring

A free, open-source authenticator that runs in your browser. It shows live two-factor (TOTP) codes for all your accounts and keeps every key encrypted on your own device, behind a passphrase only you know. There's no account and no tracking, and your keys never leave your device.

- **Live site:** <https://2fa-keyring.com> · **Try the demo:** <https://2fa-keyring.com/app/#demo>
- **Guides:** <https://2fa-keyring.com/guides/>
- **Security model:** <https://2fa-keyring.com/security/> · **Reporting:** [`SECURITY.md`](SECURITY.md) · **Changes:** [`CHANGELOG.md`](CHANGELOG.md)

## Features

- **Demo mode:** explore a sample vault of public test keys without a passphrase. It's kept in memory and never touches a saved vault.
- **Import from Google Authenticator:** read its export QR codes (including multi-part exports) on the device, review every account, then confirm.
- **Add several keys at once:** type setup keys (pasting an `otpauth://` link into a setup-key field fills in the rest), paste a list of `otpauth://` links, or pick several QR code screenshots. QR codes are decoded on your device.
- **Live codes:** click a code to copy it. The next code appears a few seconds before the current one expires.
- **Supported formats:** SHA-1, SHA-256 and SHA-512, with 6, 7 or 8 digits and any period from 1 to 300 seconds.
- **Manage keys:** search (press `/`), favorites, groups, rename, reveal a key's setup key, or delete it.
- **Encrypted backups:** download or copy, check a backup without changing anything, restore on another device, or merge into an existing vault. The app counts changes since your last backup and reminds you.
- **Auto-lock:** after 1, 5 or 15 minutes of inactivity, and optionally as soon as you switch tabs.

## Security at a glance

- **Encryption:** AES-256-GCM with a key derived by PBKDF2-SHA256 (600,000 iterations, random 16-byte salt), using the browser's Web Crypto API. Only the encrypted vault is stored, in `localStorage`.
- **Passphrases:** at least 12 characters, and easily guessed ones are rejected.
- **Network connections blocked:** every page sets a strict Content Security Policy. The app's policy includes `connect-src 'none'`, and scripts, styles and fonts load from this site only.
- **No third-party services:** the one bundled library, the QR decoder [jsQR](https://github.com/cozmo/jsQR) (Apache-2.0), and the fonts (Bricolage Grotesque and JetBrains Mono, SIL OFL 1.1) are stored in `assets/` and served from the site. There are no CDNs, analytics or cookies.
- **Defensive checks:** the app refuses to run inside a frame (clickjacking) or outside a secure context (HTTPS or localhost).

The [security page](https://2fa-keyring.com/security/) covers the full threat model, its limits, and how to verify each claim yourself.

## Project layout

```
index.html               Home page
app/                     The app (index.html, app.js, app.css)
guides/                  Guides (each in its own folder)
security/ privacy/ terms/  Security model, Privacy Policy, Terms of Use
404.html                 Not-found page
assets/totp.js           TOTP core shared by the app and the home page
assets/migration.js      Google Authenticator export decoder
assets/site.css, site.js Website styles and the home page's sample vault
assets/chrome.css        Shared header and footer
assets/og.png            Social preview image
assets/fonts/, vendor/   Self-hosted fonts and jsQR, with their licenses
tests/run.js             Unit tests (node tests/run.js)
_headers, _redirects     Security headers and old-URL redirects for Cloudflare
sitemap.xml, robots.txt  Search engine files
.well-known/             security.txt (RFC 9116)
wrangler.jsonc           Cloudflare Workers static-assets config
.assetsignore            Repository files that aren't deployed
.github/workflows/       Tests on every PR; verified deploy from main
VERSION, CHANGELOG.md    Release version and history
```

## Publishing

The site is plain static files. The official copy runs on Cloudflare, which gives the app its own origin and real security headers.

### Cloudflare Workers: `https://2fa-keyring.com` (the official site)

`wrangler.jsonc`, `_headers` and a GitHub Actions workflow (`.github/workflows/deploy-cloudflare.yml`) are already in the repository. To turn on automatic deploys:

1. **Create an API token.** In Cloudflare, go to **My Profile → API Tokens → Create Token**, choose the **Edit Cloudflare Workers** template, limit it to your account, and create it.
2. **Find your account ID.** It's shown on the **Workers & Pages** overview page.
3. **Add both as secrets.** In GitHub, go to **Settings → Secrets and variables → Actions → New repository secret**. Add `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`.
4. **Run the workflow.** Go to **Actions → Deploy to Cloudflare → Run workflow**, or push to `main`.

Each run deploys the site, then checks the live site: the security headers are present, repository files like the README return 404, and every page loads. If any check fails, the run fails. Until the secrets exist, the workflow skips the deploy instead of failing.

If you also connected the repository through Cloudflare's own **Workers Builds**, disconnect it (Worker → Settings → Build), so there's only one way the site gets deployed.

Cloudflare then sends the headers in `_headers` with every file:

- **Content Security Policy:** the full policy, including `frame-ancestors 'none'`
- **HSTS** (`Strict-Transport-Security`)
- **`X-Frame-Options: DENY`** and **`X-Content-Type-Options: nosniff`**
- **A Permissions-Policy** that turns off camera, microphone, location and similar features
- **Cross-origin isolation headers** (`Cross-Origin-Opener-Policy` and `Cross-Origin-Resource-Policy`)

`2fa-keyring.com` is used only by this app, so no other site shares its storage. `wrangler.jsonc` keeps the `workers.dev` address turned off, and `www.2fa-keyring.com` should redirect to the apex domain (Cloudflare → Rules → Redirect Rules), so every user has exactly one vault location.

You can also deploy from your computer with `npx wrangler deploy` in the repository folder.

### Hosting your own copy

Serve the folder from a domain or subdomain used for nothing else, and send the headers in `_headers`. Avoid shared origins such as `username.github.io`: every project site of that account shares one origin, and GitHub Pages can't send security headers. GitHub Pages is turned off for this repository for that reason.

### Private vulnerability reporting

Turn it on under Settings → Code security, so the "Report a vulnerability" links work.

## Running locally

```
npx wrangler dev
```

Then open <http://localhost:8787/>. This serves the site the way Cloudflare does, with the security headers, redirects and folder URLs. `python3 -m http.server 8000` also works for a quick look, without the headers and redirects. The app needs HTTPS or `localhost`, because the browser's Web Crypto API only works in a secure context.

Run the tests with `node tests/run.js`.

## Verification

`tests/run.js` checks `assets/totp.js` against all 18 RFC 6238 test vectors (SHA-1, SHA-256 and SHA-512 at six timestamps) and the Google Authenticator import against synthetic single, multi-part, duplicate, unsupported and malformed exports. The demo and the home page use public or synthetic test keys only.

## License

[MIT](LICENSE) © 2026 estuty. Bundled third-party components keep their own licenses: jsQR (Apache-2.0, `assets/vendor/LICENSE-jsQR.txt`), Bricolage Grotesque and JetBrains Mono (SIL OFL 1.1, `assets/fonts/`).
