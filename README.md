# jkey

Cross-platform command-line password manager and TOTP verifier.

All data is encrypted with AES-256-CBC + HMAC-SHA256 and stored per data type under `~/.config/jkey/`. Pure Python — no OpenSSL or libsodium required.

## Install

```bash
pipx install jkey
```

Or with plain pip:

```bash
pip install --user jkey
```

Or run without installing:

```bash
pipx run jkey --help
```

## Quick Start

```bash
# Initialize vault (set master password)
jkey pv init

# Add a 2FA account from QR code image
jkey 2fa add ./github.jpg

# List TOTP codes (optional keyword filter)
jkey 2fa ls
jkey 2fa ls github

# Generate a random password
jkey pm get -L 24

# Store a password
jkey pm add my-site

# List all stored passwords
jkey pm ls

# Encrypt/decrypt any file
jkey pv encrypt secret.pdf
jkey pv decrypt secret.pdf.jkey -o secret.pdf
```

## Commands

| Command | Description |
|---------|-------------|
| `jkey 2fa ls [keyword]` | List TOTP accounts and codes |
| `jkey 2fa add <image>` | Import from QR code image |
| `jkey 2fa rm <account>` | Remove a TOTP account |
| `jkey rc add <file>` | Import recovery codes from file |
| `jkey rc ls [keyword]` | List recovery codes |
| `jkey rc rm <account>` | Remove recovery codes |
| `jkey pm ls [keyword]` | List stored passwords |
| `jkey pm get [-L N]` | Generate a random password |
| `jkey pm add <name>` | Store a password (prompts for input) |
| `jkey pm edit <name>` | Update an existing password |
| `jkey pm rm <name>` | Delete a stored password |
| `jkey pm import <file.csv>` | Import passwords from a browser CSV export |
| `jkey pv init` | Initialize the encrypted vault |
| `jkey pv unlock` | Unlock the vault |
| `jkey pv lock` | Lock the vault |
| `jkey pv status` | Show vault status |
| `jkey pv set-pw` | Change master password |
| `jkey pv encrypt <file>` | Encrypt a file |
| `jkey pv decrypt <file>` | Decrypt a `.jkey` file |
| `jkey pv export totp` | Export TOTP secrets (re-enters master password) |
| `jkey pv export passwords` | Export passwords as CSV |
| `jkey pv export recovery` | Export recovery codes |
| `jkey pv export qr -o <dir>` | Export QR code images |
| `jkey pv export all -o <dir>` | Export everything |
| `jkey remote add <name> <url>` | Configure a local, S3, or rclone backend |
| `jkey remote ls` | List configured backends |
| `jkey remote rm <name>` | Remove a backend configuration |
| `jkey backup <name>` | Upload the encrypted vault |
| `jkey restore <name>` | Restore the latest backup; keep local conflicts as `.bak` |


Set `JKEY_PASS` environment variable to skip the password prompt. Set `JKEY_SESSION_TIMEOUT` to change the session cache lifetime (default: 300 seconds).

Sessions use per-terminal tickets: unlocking in one terminal window does **not** unlock other windows. The master password is cached only in a native OS credential store (Linux Secret Service, macOS Keychain, or Windows Credential Manager). Disk tickets contain only expiry and vault fingerprint metadata; decrypted records are never cached on disk. Old plaintext tickets are removed on first use. If no supported, unlocked credential store is available, commands work normally but each new command requires authentication. `jkey pv lock` invalidates every terminal's ticket and removes its cached credential.

## Backup & Restore

Configure a backend once, then upload and restore with one command each:

```bash
jkey remote add s3 s3://my-bucket/jkey
jkey backup s3
jkey restore s3
```

The name is your choice. Local directories, NAS mounts and USB drives work too:

```bash
jkey remote add nas /mnt/nas/jkey
jkey backup nas
jkey restore nas
```

Or reuse an existing rclone remote directly, with no jkey configuration:

```bash
jkey backup rclone:r2
jkey restore rclone:r2
```

Both commands transfer encrypted data and need no master password. Restore asks for confirmation. Identical files are skipped; differing local files are kept as `filename.jkey.bak` before replacement. Existing `.bak` files are preserved with timestamped names for subsequent conflicts. Files present only locally are left alone. Nothing is merged automatically.

Use `jkey restore s3 -o ./restored` to restore to a different directory. See [backend configuration and conflict handling](docs/backup.md) for details.

## How It Works

Data is encrypted with AES-256-CBC + HMAC-SHA256 and stored in `~/.config/jkey/`:

```
~/.config/jkey/
├── sessions/         # Per-terminal session tickets (sudo-style, 5 min activity timeout)
├── remotes.json      # Backup remote configs (mode 600; never contains vault data)
├── totp.jkey         # Encrypted TOTP secrets
├── passwords.jkey    # Encrypted passwords
├── recovery.jkey     # Encrypted recovery codes
└── qr/               # Encrypted QR images
```

For machine migration use `jkey backup <remote>` + `jkey restore <remote>`, or manually back up `~/.config/jkey/` (excluding `sessions/`).

## Dependencies

Runtime dependencies:

- `portalocker` — cross-platform vault file locking
- `keyring` — native OS credential storage for session passwords (no file-based fallback)
- `opencv-python-headless` — optional, needed only for `jkey 2fa add` QR scanning. Install with `pip install jkey[qr]`.
- `boto3` — optional, needed only for native `s3://` backends. Install with `pip install jkey[s3]`.
- `rclone` executable — optional, needed only for `rclone:` backends. Uses your existing rclone configuration.

Pure Python, no OpenSSL or libsodium required.
