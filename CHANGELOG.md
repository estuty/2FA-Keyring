# Changelog

All notable changes to 2FA Keyring. Versions follow [semantic versioning](https://semver.org/). The site footer shows the exact version and commit that is deployed.

## 1.1.0 (unreleased)

### Added
- **Demo mode** (`/app/#demo`): a sample vault of clearly labelled public test keys, kept in memory only. It never reads or writes a saved vault.
- **Google Authenticator import:** decodes `otpauth-migration://` export QR codes and links on the device, including exports split across several codes. Shows a review list with duplicates and unsupported entries (HOTP, MD5) before anything is saved, and reminds you to verify codes before removing the originals.
- **Backup confidence:** counts changes since the last backup and reminds you after adding, editing or deleting keys or changing the passphrase. A new "Check a backup" step opens a backup in memory and compares it with the vault without changing anything. Backups now record when the vault was saved.
- **Favorites and groups** stored inside the encrypted vault, with filter chips. Press `/` to search.
- **Guides:** getting started, Google Authenticator migration, backup and restore, setting up popular services, self-hosting.
- Sitemap, robots.txt, canonical URLs, social preview image and structured data. A 404 page.
- Unit tests (`node tests/run.js`) for the TOTP core and the import decoder, run on every pull request.

### Changed
- New home page: clearer value, "Create your vault" and "Try a demo" actions, an interactive sample vault, migration and backup sections, verifiable trust information and project status.
- Pages moved to folder URLs (`/security/`, `/privacy/`, `/terms/`). Old `.html` addresses redirect permanently.
- Accuracy: describes the bundled jsQR library as a locally hosted dependency, explains the risk of a compromised deployment, states the real auto-lock defaults, separates "codes work offline once open" from reopening offline, and describes the Content Security Policy as a defense layer.

### Compatibility
- Existing vaults and backups open unchanged. The envelope format is the same; new optional fields (`group`, `fav`, `savedAt`) are ignored by older versions.

## 1.0.0 (2026-10-16)

First public release at 2fa-keyring.com: encrypted local vault, TOTP codes, several keys at once, QR images, encrypted backups, auto-lock, strict security headers.
