from jkey.pm.core import load_passwords


def list_passwords(keyword: str | None = None) -> dict[str, str] | None:
    data = load_passwords()
    if data is None:
        return None
    if not data:
        return {}
    keys = sorted(data.keys())
    if keyword:
        keys = [k for k in keys if keyword.lower() in k.lower()]
    return {k: data[k] for k in keys}
