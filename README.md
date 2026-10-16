# 2FA Keyring

A single-page web app for managing several two-factor (TOTP) keys. It shows a live code with a countdown for each account, and keeps every key encrypted in your browser behind a passphrase.

## Features

- **Add keys three ways:** type the setup key, paste one or more `otpauth://` links, or upload a screenshot of the QR code.
- **Live codes:** click a code to copy it. The next code appears a few seconds before the current one expires.
- **Supported formats:** SHA-1, SHA-256 and SHA-512, with 6, 7 or 8 digits and any period from 1 to 300 seconds.
- **Manage keys:** search, rename, reveal a key's setup key, or delete it.
- **Encrypted vault:** keys are encrypted with AES-256-GCM, using a key derived from your passphrase with PBKDF2-SHA256 (600,000 iterations), and stored in `localStorage`.
- **Auto-lock:** the vault locks after 1, 5 or 15 minutes of inactivity, or never.
- **Encrypted backups:** export a backup as a file or as text, restore it on another device, or merge it into an existing vault.

Codes are calculated on your device with the Web Crypto API. The app makes no network requests apart from loading two fonts from Google Fonts and the QR reader ([jsQR](https://github.com/cozmo/jsQR)) from cdnjs.

## Running it

It's one static file with no build step.

- **Locally:** open `index.html` in a browser. Some browsers restrict the Web Crypto API on `file://` pages. If that happens, serve the folder instead, for example with `python3 -m http.server`, and open `http://localhost:8000`.
- **GitHub Pages:** go to Settings → Pages, choose "Deploy from a branch", then pick `main` and `/ (root)`. The app will be served at `https://<user>.github.io/2FA-Keyring/`.

The Web Crypto API needs a secure context, so the app must be served over HTTPS or from `localhost`.

## Important

- **Back up after you add keys.** The vault lives in this browser's storage only, so clearing site data, using a private window or switching browsers starts you with an empty vault.
- **Your passphrase can't be recovered.** Without it, neither the vault nor any backup can be opened.
- **Keep each service's recovery codes** somewhere separate. They're your way back in if you lose access to the vault.
- **Use a hardware key where you can.** For your most important accounts (email, banking), a hardware security key gives stronger protection than any TOTP app.

## Verification

The code generator matches all 18 RFC 6238 test vectors (SHA-1, SHA-256 and SHA-512 at six timestamps). The lock screen's example code uses the RFC's SHA-1 test secret.
