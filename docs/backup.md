# Storage backends

Configure a name once, then use `jkey backup <name>` and `jkey restore <name>`.

```bash
# Local directory / NAS / USB
jkey remote add nas /mnt/nas/jkey

# Native S3 (the bucket must already exist)
pip install "jkey[s3]"
jkey remote add cloud s3://my-bucket/jkey --region ap-east-1

# S3-compatible storage
jkey remote add cloud s3://my-bucket/jkey \
    --endpoint https://your-s3-endpoint --region your-region

jkey remote ls
jkey remote rm nas
```

Native S3 uses the normal AWS credential chain. Inline credentials can also be set with `jkey remote cred cloud`; they are stored in `remotes.json` with restrictive file permissions and masked in listing output. `jkey remote init` creates a commented configuration template if you prefer editing the file.

## Existing rclone configuration

Install rclone and configure your remote with `rclone config`. Then:

```bash
jkey backup rclone:r2
jkey restore rclone:r2

# Specify a bucket or directory when the remote does not already point to one
jkey backup rclone:r2:my-bucket/jkey
jkey restore rclone:r2:my-bucket/jkey

# Optionally give that target a shorter jkey alias
jkey remote add cloud rclone:r2:my-bucket/jkey
jkey backup cloud
jkey restore cloud
```

jkey invokes the installed rclone executable, using its existing configuration and environment (including `RCLONE_CONFIG`). It never imports or copies rclone credentials. Transfers use [rclone copyto](https://rclone.org/commands/rclone_copyto/).

## Conflicts

Restore copies encrypted files, with no decryption or automatic merge:

- Identical bytes: skip the file.
- Different bytes: save the local version as `filename.jkey.bak`, then write the restored version.
- An existing `.bak`: keep it; the next backup uses `filename.jkey.<timestamp>-<id>.bak`.
- Local-only files: keep them.

A `.bak` is still encrypted. To compare versions, decrypt each with the password that belongs to it. Decrypting a file does not require unlocking the current vault:

```bash
jkey pv decrypt ~/.config/jkey/passwords.jkey.bak -o old.json
jkey pv decrypt ~/.config/jkey/passwords.jkey -o new.json
# Compare and edit the JSON files into merged.json yourself.
jkey pv encrypt --json merged.json -o ~/.config/jkey/passwords.jkey
```

`--json` preserves the native vault dictionary format. It asks for the password for the merged file if no current session or `JKEY_PASS` supplies one. Replacing an existing encrypted output also preserves it as `.bak`. Plaintext exports remain on disk until you remove them. Conflict copies are not included in subsequent uploads; only the active `.jkey` files are backed up.

## Optional history and verification

Uploads capture one consistent generation of encrypted files in a snapshot. Uploads are read back and verified before old history is pruned. The default keeps five snapshots; configure `keep` per backend or pass `jkey backup cloud --keep 10`. `0` keeps all snapshots.

```bash
jkey remote snaps cloud
jkey restore cloud --date <snapshot-id>
jkey restore cloud -o ./restored
jkey remote verify cloud
jkey remote verify cloud --decrypt  # Optional manual decryption check
jkey remote test cloud
```

Checksums and allowed file paths are checked automatically on restore. Restoring files is independent per file: if interrupted, completed replacements and their `.bak` files remain, and the operation can be run again. The master-password change operation separately uses a recoverable transaction and includes QR images.
