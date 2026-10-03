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
| `jkey backup add <name> <url>` | Configure a backup remote (`s3://bucket/prefix` or local path) |
| `jkey backup ls` | List backup remotes (credentials masked) |
| `jkey backup rm <name>` | Remove a backup remote |
| `jkey backup cred <name>` | Set or clear inline S3 credentials |
| `jkey backup test <name>` | Test remote connectivity (write → read → delete) |
| `jkey backup run [name]` | Back up now (omit name = all remotes) |
| `jkey backup snaps <name>` | List snapshots on a remote |
| `jkey backup restore <name>` | Restore a snapshot (default: latest) |
| `jkey backup verify <name>` | Verify snapshot checksums on the remote |

Set `JKEY_PASS` environment variable to skip the password prompt. Set `JKEY_SESSION_TIMEOUT` to change the session cache lifetime (default: 300 seconds).

## Backup & Restore

Backups copy the **already-encrypted** vault files (`.jkey`) to a remote as timestamped tar.gz snapshots — no master password is needed, nothing plaintext ever leaves the machine. `.session` is never backed up.

```bash
pip install "jkey[s3]"   # S3 support (local-path remotes need no extra dependency)

# AWS S3 — credentials come from the standard AWS chain (~/.aws, env vars, IAM role)
jkey backup add aws s3://my-bucket/jkey --region ap-east-1

# S3-compatible providers (Aliyun OSS, Tencent COS, MinIO, Cloudflare R2, Backblaze B2)
jkey backup add oss s3://my-bucket/jkey \
    --endpoint https://oss-cn-hangzhou.aliyuncs.com \
    --region cn-hangzhou --access-key LTAI... --secret-key ***

# Local path (NAS mount, USB drive) — no credentials involved
jkey backup add nas /mnt/nas/jkey-backup -k 10

jkey backup test aws              # PUT → GET → DELETE probe
jkey backup run                   # back up to all remotes
jkey backup run aws -k 5          # keep the last 5 snapshots on this remote
jkey backup snaps aws             # list remote snapshots
jkey backup verify aws            # sha256-check remote snapshots

# Restore to a directory (safe mode; never touches the live vault)
jkey backup restore aws
jkey backup restore aws -d 20250611-143022 -o ./restored

# Restore directly into the vault (asks for confirmation, transactional)
jkey backup restore aws --into-vault
jkey pv status                       # then unlock once to verify the restored vault
```

Snapshots are pruned automatically: `-k/--keep` or the remote's configured `keep` (default 5) — only the newest N snapshots stay on the remote.

Credentials resolve in two steps: inline `--access-key`/`--secret-key` stored in `~/.config/jkey/remotes.json` (mode 600) win; otherwise boto3's default chain applies (env vars → `~/.aws/credentials` → IAM role). Manage inline credentials with `jkey backup cred <name>` / `--clear`; `ls` output is always masked.

## How It Works

Data is encrypted with AES-256-CBC + HMAC-SHA256 and stored in `~/.config/jkey/`:

```
~/.config/jkey/
├── .session          # Session cache (5 min timeout)
├── remotes.json      # Backup remote configs (mode 600; never contains vault data)
├── totp.jkey         # Encrypted TOTP secrets
├── passwords.jkey    # Encrypted passwords
├── recovery.jkey     # Encrypted recovery codes
└── qr/               # Encrypted QR images
```

For machine migration use `jkey backup run` + `jkey backup restore --into-vault`, or manually back up `~/.config/jkey/` (excluding `.session`).

## Dependencies

Runtime dependencies:

- `portalocker` — cross-platform vault file locking
- `opencv-python-headless` — optional, needed only for `jkey 2fa add` QR scanning. Install with `pip install jkey[qr]`.
- `boto3` — optional, needed only for `s3://` backup remotes. Install with `pip install jkey[s3]`.

Pure Python, no OpenSSL or libsodium required.
