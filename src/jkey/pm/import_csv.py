import csv
import io
import os
import sys
from urllib.parse import urlparse

from jkey.pm.core import load_passwords, save_passwords

_COLUMN_ALIASES = {
    "name": ["name", "title", "site", "account"],
    "url": [
        "url",
        "website",
        "website address",
        "login_uri",
        "login url",
        "web site",
        "site",
    ],
    "username": [
        "username",
        "login",
        "email",
        "login_username",
        "user",
        "user name",
        "e-mail",
    ],
    "password": [
        "password",
        "login_password",
        "pass",
        "login pass",
        "secret",
    ],
}


def _detect_format(headers: list[str]) -> dict[str, int]:
    mapping: dict[str, int] = {}
    for i, h in enumerate(headers):
        h = h.strip().lower()
        for canonical, aliases in _COLUMN_ALIASES.items():
            if h in aliases and canonical not in mapping:
                mapping[canonical] = i
                break
    return mapping


def _extract_name(row: list[str], mapping: dict[str, int], index: int) -> str:
    base = ""
    if "name" in mapping:
        base = row[mapping["name"]].strip()

    if not base and "url" in mapping:
        url = row[mapping["url"]].strip()
        if url:
            if "://" not in url:
                url = "https://" + url
            try:
                parsed = urlparse(url)
                base = parsed.hostname or ""
            except ValueError:
                pass
            if not base:
                base = url.removeprefix("https://").removeprefix("http://").rstrip("/")

    if not base and "username" in mapping:
        base = row[mapping["username"]].strip()

    if not base:
        base = f"entry-{index + 1}"

    username = ""
    if "username" in mapping:
        username = row[mapping["username"]].strip()

    if username and username != base:
        return f"{base} ({username})"
    return base


def _resolve_duplicate(name: str, data: dict, mode: str) -> tuple[str, bool]:
    if name not in data:
        return name, True

    if mode == "skip":
        return name, False
    elif mode == "overwrite":
        return name, True
    elif mode == "rename":
        n = 2
        while f"{name}-{n}" in data:
            n += 1
        return f"{name}-{n}", True
    return name, False


def _process_row(row: list[str], mapping: dict[str, int], data: dict, mode: str, index: int, max_idx: int) -> dict:
    if len(row) <= max_idx:
        return {"action": "skip", "reason": "short_row"}

    password = row[mapping["password"]].strip()
    name = _extract_name(row, mapping, index)

    username = ""
    if "username" in mapping:
        username = row[mapping["username"]].strip()

    if not password:
        return {"action": "skip", "reason": "empty_pw", "name": name, "username": username}

    final_name, should_import = _resolve_duplicate(name, data, mode)
    if not should_import:
        return {"action": "skip", "reason": "duplicate", "name": name, "final_name": final_name,
                "username": username, "password": password}

    if final_name in data:
        return {"action": "overwrite", "name": name, "final_name": final_name,
                "username": username, "password": password}
    return {"action": "new", "name": name, "final_name": final_name,
            "username": username, "password": password}


def _detect_encoding_and_read(file_path: str) -> tuple[str | None, str | None]:
    """Try common encodings and return (encoding, content) or (None, None)."""
    for encoding in ("utf-8-sig", "utf-8", "utf-16", "latin-1"):
        try:
            with open(file_path, encoding=encoding) as f:
                return encoding, f.read()
        except (UnicodeDecodeError, UnicodeError):
            continue
    return None, None


def import_csv(
    file_path: str,
    dry_run: bool = False,
    duplicates: str = "skip",
    verbose: bool = False,
    replace: bool = False,
) -> None:
    if not os.path.exists(file_path):
        print(f"Error: File not found: {file_path}", file=sys.stderr)
        return

    encoding, content = _detect_encoding_and_read(file_path)
    if content is None:
        print(f"Error: Cannot read '{file_path}' — unsupported encoding.", file=sys.stderr)
        return

    try:
        reader = csv.reader(io.StringIO(content))
        rows = list(reader)
    except csv.Error as e:
        print(f"Error: Cannot parse CSV: {e}", file=sys.stderr)
        return

    if not rows:
        print("Error: CSV file is empty.", file=sys.stderr)
        return

    headers = rows[0]
    data_rows = rows[1:]

    mapping = _detect_format(headers)
    if "password" not in mapping:
        print(
            "Error: Could not detect a password column. "
            "Supported column names: " + ", ".join(_COLUMN_ALIASES["password"]),
            file=sys.stderr,
        )
        return

    if not data_rows:
        print("CSV has headers but no data rows.", file=sys.stderr)
        return

    data = load_passwords()
    if data is None:
        return

    if replace and not dry_run:
        data.clear()

    if dry_run:
        _print_dry_run(data_rows, mapping, data, duplicates)
        return

    imported: list[tuple[str, str, str]] = []
    overwritten: list[tuple[str, str, str]] = []
    skipped_empty_pw: list[str] = []
    skipped_short = 0
    skipped_dup: list[str] = []

    max_idx = max(mapping.values())
    for i, row in enumerate(data_rows):
        result = _process_row(row, mapping, data, duplicates, i, max_idx)

        if result["action"] == "skip":
            if result["reason"] == "short_row":
                skipped_short += 1
                if verbose:
                    print(f"  skip short-row {i + 2}: {','.join(row)[:60]}", file=sys.stderr)
            elif result["reason"] == "empty_pw":
                skipped_empty_pw.append(result["name"])
                if verbose:
                    print(f"  skip empty-pw: {result['name']}", file=sys.stderr)
            elif result["reason"] == "duplicate":
                skipped_dup.append(result["name"])
                if verbose:
                    print(f"  skip duplicate: {result['name']}", file=sys.stderr)
            continue

        final_name = result["final_name"]
        username = result["username"]
        password = result["password"]

        if result["action"] == "overwrite":
            overwritten.append((final_name, username, password))
        else:
            imported.append((final_name, username, password))

        data[final_name] = password

    if not imported and not overwritten:
        parts = []
        if skipped_short:
            parts.append(f"{skipped_short} short row")
        if skipped_empty_pw:
            parts.append(f"{len(skipped_empty_pw)} empty password")
        if skipped_dup:
            parts.append(f"{len(skipped_dup)} duplicate")
        if parts:
            print(f"No new entries ({', '.join(parts)}).")
            if verbose:
                for n in skipped_empty_pw:
                    print(f"  - {n}")
                for n in skipped_dup:
                    print(f"  - {n}")
        else:
            print("No new entries to import.")
        return

    save_passwords(data)

    if imported:
        print(f"\n  + Imported {len(imported)}:")
        _print_entries(imported)
    if overwritten:
        print(f"\n  ~ Overwritten {len(overwritten)}:")
        _print_entries(overwritten)

    total_skip = len(skipped_empty_pw) + skipped_short + len(skipped_dup)
    if total_skip:
        reasons = []
        if skipped_short:
            reasons.append(f"{skipped_short} short row")
        if skipped_empty_pw:
            reasons.append(f"{len(skipped_empty_pw)} empty password")
        if skipped_dup:
            reasons.append(f"{len(skipped_dup)} duplicate")
        print(f"\n  Skipped {total_skip} ({', '.join(reasons)}).")
        if verbose and skipped_empty_pw:
            for n in skipped_empty_pw:
                print(f"    - {n}")
        if verbose and skipped_dup:
            for n in skipped_dup:
                print(f"    - {n}")


def _print_entries(entries: list[tuple[str, str, str]]) -> None:
    for name, username, password in entries:
        masked = password[:3] + "***"
        print(f"  {name}: {masked}")


def _print_dry_run(
    data_rows: list[list[str]], mapping: dict[str, int], existing: dict, mode: str
) -> None:
    new_count = 0
    overwrite_count = 0
    skip_count = 0
    empty_count = 0

    print(f"\n  Preview ({len(data_rows)} rows, duplicates: {mode}):\n")
    print(f"    {'STATUS':<12} {'NAME':<48} {'USERNAME':<32} {'PASSWORD':<12}")
    print(f"    {'─' * 12} {'─' * 48} {'─' * 32} {'─' * 12}")

    max_idx = max(mapping.values())
    for i, row in enumerate(data_rows):
        result = _process_row(row, mapping, existing, mode, i, max_idx)

        if result["action"] == "skip":
            if result["reason"] == "short_row":
                skip_count += 1
                continue
            elif result["reason"] == "empty_pw":
                empty_count += 1
                print(f"    {'[NO PW]':<12} {result['name']:<48} {result['username']:<32} {'':<12}")
            elif result["reason"] == "duplicate":
                skip_count += 1
                status = "[SKIP]"
                masked = result["password"][:3] + "***"
                print(f"    {status:<12} {result['final_name']:<48} {result['username']:<32} {masked:<12}")
            continue

        if result["action"] == "overwrite":
            overwrite_count += 1
            status = "[OVERWRITE]"
        else:
            new_count += 1
            status = "[NEW]"

        masked = result["password"][:3] + "***"
        print(f"    {status:<12} {result['final_name']:<48} {result['username']:<32} {masked:<12}")

    print(f"    {'─' * 12} {'─' * 48} {'─' * 32} {'─' * 12}")
    parts = []
    if new_count:
        parts.append(f"{new_count} new")
    if overwrite_count:
        parts.append(f"{overwrite_count} overwrite")
    if skip_count:
        parts.append(f"{skip_count} skip")
    if empty_count:
        parts.append(f"{empty_count} empty password")
    print(f"    {', '.join(parts)}\n")
