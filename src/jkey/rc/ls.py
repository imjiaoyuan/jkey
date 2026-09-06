from jkey.pv.core import filter_keys, load_recovery


def rc_list(keyword: str | None = None) -> dict[str, list[str]]:
    data = load_recovery()
    return {k: data[k] for k in filter_keys(data, keyword)}
