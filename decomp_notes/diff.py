def _index(conn):
    rows = conn.execute("select addr, name, body_hash, external from functions")
    return [dict(r) for r in rows]


def diff_dbs(old, new):
    old_fns = {f["name"]: f for f in _index(old)}
    new_fns = {f["name"]: f for f in _index(new)}

    changed = [
        {"name": n, "old_address": old_fns[n]["addr"], "new_address": new_fns[n]["addr"]}
        for n in sorted(old_fns.keys() & new_fns.keys())
        if old_fns[n]["body_hash"] != new_fns[n]["body_hash"]
    ]

    gone = [old_fns[n] for n in old_fns.keys() - new_fns.keys()]
    fresh = {n: new_fns[n] for n in new_fns.keys() - old_fns.keys()}
    by_hash = {}
    for f in fresh.values():
        if not f["external"]:
            by_hash.setdefault(f["body_hash"], []).append(f)

    renamed = []
    removed = []
    for f in sorted(gone, key=lambda f: f["addr"]):
        match = None if f["external"] else by_hash.get(f["body_hash"])
        if match:
            target = match.pop(0)
            fresh.pop(target["name"])
            renamed.append(
                {
                    "old_name": f["name"],
                    "new_name": target["name"],
                    "old_address": f["addr"],
                    "new_address": target["addr"],
                }
            )
        else:
            removed.append({"name": f["name"], "address": f["addr"]})

    added = [
        {"name": f["name"], "address": f["addr"]}
        for f in sorted(fresh.values(), key=lambda f: f["addr"])
    ]
    return {"added": added, "removed": removed, "changed": changed, "renamed": renamed}


def format_diff(result):
    lines = []
    for f in result["added"]:
        lines.append(f"+ {f['name']} {f['address']}")
    for f in result["removed"]:
        lines.append(f"- {f['name']} {f['address']}")
    for f in result["changed"]:
        lines.append(f"~ {f['name']} {f['old_address']} -> {f['new_address']}")
    for f in result["renamed"]:
        lines.append(
            f"> {f['old_name']} -> {f['new_name']} {f['old_address']} -> {f['new_address']}"
        )
    return "\n".join(lines) if lines else "no differences"
