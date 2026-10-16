# Security policy

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Report them privately through GitHub: on this repository, go to **Security → Report a vulnerability**, or open
<https://github.com/estuty/2FA-Keyring/security/advisories/new>.

Please include:

- what an attacker could do, and what they need first (for example, access to the device or a backup file)
- steps to reproduce
- the browser and version you used

Reports are acknowledged as soon as possible. Once a fix ships, you'll be credited in the advisory if you'd like.

## Scope

In scope:

- anything that exposes setup keys, decrypted vault contents, or the passphrase
- weaknesses in key derivation, encryption, or how the vault and backups are handled
- ways around the Content Security Policy, the anti-framing check, or auto-lock
- code generation that's wrong for a valid key

Out of scope, because the app can't defend against these (see [security.html](security.html#threats)):

- attacks that need malware, a malicious extension, or control of an unlocked device
- brute-forcing a weak passphrase that was accepted before the current strength rules
- social engineering

## Supported versions

Only the current version on the `main` branch, as served by the website, receives fixes.

## Design summary

The full model is on the website's security page ([security.html](security.html)). In short:

- Keys are encrypted with AES-256-GCM under a key derived with PBKDF2-SHA256 (600,000 iterations, 16-byte random salt). Only the encrypted vault is stored, in the browser's `localStorage`.
- Each page's Content Security Policy forbids network connections (`connect-src 'none'`) and allows scripts, styles and fonts only from the site itself.
- There's no server-side code, no cookies, and no third-party scripts, fonts or analytics. The host only sees ordinary requests for the site's files.
