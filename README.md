# 2FA Keyring

A free, open-source authenticator that runs in your browser. It shows live two-factor (TOTP) codes for all your accounts and keeps every key encrypted on your own device, behind a passphrase only you know. There's no account, no server and no tracking.

- **Website:** `index.html`
- **App:** `app/`
- **Security model:** [`security.html`](security.html) · **Reporting:** [`SECURITY.md`](SECURITY.md)

## Features

- **Add several keys at once:** type setup keys (pasting an `otpauth://` link into a setup-key field fills in the rest), paste a list of `otpauth://` links, or pick several QR code screenshots. QR codes are decoded on your device.
- **Live codes:** click a code to copy it. The next code appears a few seconds before the current one expires.
- **Supported formats:** SHA-1, SHA-256 and SHA-512, with 6, 7 or 8 digits and any period from 1 to 300 seconds.
- **Manage keys:** search, rename, reveal a key's setup key, or delete it.
- **Encrypted backups:** export to a file or as text, restore on another device, or merge into an existing vault.
- **Auto-lock:** after 1, 5 or 15 minutes of inactivity, and optionally as soon as you switch tabs.

## Security at a glance

- **Encryption:** AES-256-GCM with a key derived by PBKDF2-SHA256 (600,000 iterations, random 16-byte salt), using the browser's Web Crypto API. Only the encrypted vault is stored, in `localStorage`.
- **Passphrases:** at least 12 characters, and easily guessed ones are rejected.
- **Network connections blocked:** every page sets a strict Content Security Policy. The app's policy includes `connect-src 'none'`, and scripts, styles and fonts load from this site only.
- **No third parties:** the QR decoder ([jsQR](https://github.com/cozmo/jsQR), Apache-2.0) and fonts (Bricolage Grotesque and JetBrains Mono, SIL OFL 1.1) are stored in `assets/`. There are no CDNs, analytics or cookies.
- **Defensive checks:** the app refuses to run inside a frame (clickjacking) or outside a secure context (HTTPS or localhost).

The [security page](security.html) covers the full threat model, its limits, and how to verify each claim yourself.

## Project layout

```
index.html          Website landing page
security.html       Security model
app/                The app (index.html, app.js, app.css)
assets/totp.js      TOTP core shared by the app and the website's live example
assets/site.css     Website styles
assets/site.js      Website live example codes
assets/fonts/       Self-hosted fonts and their licenses
assets/vendor/      jsQR 1.4.0 and its license
_headers            Security headers for Cloudflare hosting
wrangler.jsonc      Cloudflare Workers static-assets config
.assetsignore       Repository files that aren't deployed to Cloudflare
```

## Publishing

The site is plain static files, so it can be hosted in two ways. Cloudflare is recommended because it gives the app its own origin and real security headers.

### Cloudflare Workers (recommended): `https://2fa-keyring.estuty777.workers.dev`

`wrangler.jsonc` and `_headers` are already in the repository.

1. In the Cloudflare dashboard, go to **Workers & Pages → Create → Import a repository**.
2. Connect GitHub and choose `estuty/2FA-Keyring`.
3. Leave the build command empty, keep the deploy command `npx wrangler deploy`, and make sure the project name is `2fa-keyring`.
4. Deploy. Every later push to `main` redeploys automatically.

Cloudflare then sends the headers in `_headers` with every file:

- **Content Security Policy:** the full policy, including `frame-ancestors 'none'`
- **HSTS** (`Strict-Transport-Security`)
- **`X-Frame-Options: DENY`** and **`X-Content-Type-Options: nosniff`**
- **A Permissions-Policy** that turns off camera, microphone, location and similar features
- **Cross-origin isolation headers** (`Cross-Origin-Opener-Policy` and `Cross-Origin-Resource-Policy`)

The `2fa-keyring.` subdomain is used only by this app, so no other site shares its storage.

You can also deploy from your computer with `npx wrangler deploy` in the repository folder.

### GitHub Pages: `https://estuty.github.io/2FA-Keyring/`

Settings → Pages → **Deploy from a branch**, with branch `main` and folder `/ (root)`. Tick **Enforce HTTPS**.

- **No custom domain field:** leave the Custom domain field empty unless you own the domain and can add a DNS record for it. A `workers.dev` name can't be used there, because only Cloudflare controls its DNS.
- **No security headers:** GitHub Pages can't send them, so the site relies on each page's `<meta>` policy and the app's own anti-framing check.
- **Shared origin:** all GitHub Pages sites under `estuty.github.io` share one origin.

### Private vulnerability reporting

Turn it on under Settings → Code security, so the "Report a vulnerability" links work.

## Running locally

```
python3 -m http.server 8000
```

Then open <http://localhost:8000/>. The app needs HTTPS or `localhost`, because the browser's Web Crypto API only works in a secure context.

## Verification

`assets/totp.js` matches all 18 RFC 6238 test vectors (SHA-1, SHA-256 and SHA-512 at six timestamps). The website's live example uses the RFC's public test keys.
