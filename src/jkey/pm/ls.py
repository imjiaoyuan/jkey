from jkey.pv.core import filter_keys, load_passwords


def list_passwords(keyword: str | None = None) -> dict[str, str]:
    data = load_passwords()
    return {k: data[k] for k in filter_keys(data, keyword)}
