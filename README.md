# Budget

A passphrase-gated budget dashboard. Static, self-contained, no backend.

- `index.html` — the page: a passphrase prompt that renders the dashboard once unlocked
- `payload.json` — the budget figures, encrypted with AES-256-GCM

The figures are **encrypted at rest**. The passphrase is never stored here and never
transmitted; key derivation (PBKDF2-SHA256, 600,000 iterations) and decryption both
happen in the browser. Without the passphrase this repository contains only ciphertext.

Published via GitHub Pages.
