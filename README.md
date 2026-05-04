# jkey

Python library for password management and TOTP verification.

## Install

```bash
uv tool install jkey
```

Or run without installing:

```bash
uv run jkey --help
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
| `jkey pm ls [keyword]` | List stored passwords |
| `jkey pm get [-L N]` | Generate a random password |
| `jkey pm add <name>` | Store a password (prompts for input) |
| `jkey pm rm <name>` | Delete a stored password |
| `jkey pv init` | Initialize the encrypted vault |
| `jkey pv unlock` | Unlock the vault |
| `jkey pv lock` | Lock the vault |
| `jkey pv set-pw` | Change master password |
| `jkey pv encrypt <file>` | Encrypt a file |
| `jkey pv decrypt <file>` | Decrypt a `.jkey` file |
| `jkey pv export totp` | Export TOTP secrets (re-enters master password) |
| `jkey pv export passwords` | Export passwords as CSV |
| `jkey pv export recovery` | Export recovery codes |
| `jkey pv export qr -o <dir>` | Export QR code images |
| `jkey pv export all -o <dir>` | Export everything |

Set `JKEY_PASS` environment variable to skip the password prompt.

## How It Works

Data is encrypted with AES-256-CBC + HMAC-SHA256 and stored in `~/.config/jkey/`:

```
~/.config/jkey/
├── .session          # Session cache (5 min timeout)
├── totp.jkey         # Encrypted TOTP secrets
├── passwords.jkey    # Encrypted passwords
├── recovery.jkey     # Encrypted recovery codes
└── qr/               # Encrypted QR images
```

Back up `~/.config/jkey/` (excluding `.session`) to migrate to another machine.

## Dependencies

- `opencv-python-headless` — QR code scanning

Pure Python, no OpenSSL or libsodium required.
