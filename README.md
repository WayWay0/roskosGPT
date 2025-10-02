# Local Key Manager (GitHub Pages)

A client-only encrypted manager for your own API keys. Uses Web Crypto API (PBKDF2 + AES-GCM). Nothing is sent to any server.

## How to use
1. Create a new GitHub repo, push these files to the repo.
2. In GitHub: Settings → Pages → choose `main` (or `gh-pages`) branch and root. Save.
3. Visit `<username>.github.io/<repo>` to open the page.
4. Choose a **strong passphrase** → Unlock. Add keys. Use Export Encrypted Backup to save an encrypted copy.
5. Never commit plain keys or passphrases to git.

## Security notes
- This is a convenient local tool — not a production secret manager.
- For production: use server-side secret stores (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault).
- Do not use weak passphrases. If you forget the passphrase you cannot recover the secrets.
