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
- **No network access:** every page sets a strict Content Security Policy. The app's policy includes `connect-src 'none'`, and scripts, styles and fonts load from this site only.
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
```

## Publishing with GitHub Pages

1. **Make the repository public:** GitHub Pages on a free plan needs a public repository, and people can then check the code they're running.
2. **Turn on Pages:** go to **Settings → Pages**, then under *Build and deployment* choose **Deploy from a branch**, with branch `main` and folder `/ (root)`.
3. **Enforce HTTPS:** tick **Enforce HTTPS** once it's available.
4. **Turn on private vulnerability reporting:** go to **Settings → Code security** (*Advanced Security* on some accounts) → **Private vulnerability reporting**.

The site will be at `https://estuty.github.io/2FA-Keyring/`, with the app at `/app/`.

**Use a custom domain for real users.** All GitHub Pages project sites under `estuty.github.io` share one origin, and so one storage area. Serving the app from its own domain or subdomain (Settings → Pages → Custom domain) isolates each user's vault from any other site published from this account.

## Running locally

```
python3 -m http.server 8000
```

Then open <http://localhost:8000/>. The app needs HTTPS or `localhost`, because the browser's Web Crypto API only works in a secure context.

## Verification

`assets/totp.js` matches all 18 RFC 6238 test vectors (SHA-1, SHA-256 and SHA-512 at six timestamps). The website's live example uses the RFC's public test keys.
