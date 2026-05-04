from jkey.pv.core import load_recovery


def rc_list(keyword: str | None = None):
    data = load_recovery()
    if data is None:
        return
    if not data:
        print("No recovery codes found.")
        return
    keys = sorted(data.keys())
    if keyword:
        keys = [k for k in keys if keyword.lower() in k.lower()]
        if not keys:
            print(f"No recovery codes matching '{keyword}'.")
            return
    for name in keys:
        codes = data[name]
        print(f"{name}:")
        for code in codes:
            print(f"  {code}")
