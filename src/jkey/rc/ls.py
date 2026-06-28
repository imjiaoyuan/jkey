from jkey.pv.core import load_recovery


def rc_list(keyword: str | None = None) -> dict[str, list[str]] | None:
    data = load_recovery()
    if data is None:
        return None
    if not data:
        return {}
    keys = sorted(data.keys())
    if keyword:
        keys = [k for k in keys if keyword.lower() in k.lower()]
    return {k: data[k] for k in keys}
