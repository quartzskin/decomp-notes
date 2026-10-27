import json
import re

FORMAT = 1
_HEX = re.compile(r"^(0x)?[0-9a-fA-F]+$")


class ExportError(ValueError):
    pass


def norm_addr(value):
    if isinstance(value, bool):
        raise ExportError(f"bad address: {value!r}")
    if isinstance(value, int):
        n = value
    elif isinstance(value, str) and _HEX.match(value.strip()):
        n = int(value.strip(), 16)
    else:
        raise ExportError(f"bad address: {value!r}")
    if n < 0:
        raise ExportError(f"negative address: {value!r}")
    return f"0x{n:08x}"


def _need(obj, key, kind, where):
    if key not in obj:
        raise ExportError(f"{where}: missing '{key}'")
    if not isinstance(obj[key], kind) or isinstance(obj[key], bool) and kind is not bool:
        raise ExportError(f"{where}: '{key}' should be {kind.__name__}")
    return obj[key]


def _opt(obj, key, kind, default, where):
    return _need(obj, key, kind, where) if key in obj else default


def _list(obj, key, where):
    items = _opt(obj, key, list, [], where)
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            raise ExportError(f"{where}.{key}[{i}]: expected an object")
    return items


def parse_export(data):
    if not isinstance(data, dict):
        raise ExportError("top level must be an object")
    if data.get("format") != FORMAT:
        raise ExportError(f"unsupported format {data.get('format')!r}, expected {FORMAT}")
    program = _opt(data, "program", dict, {}, "export")

    functions = []
    seen = set()
    for i, f in enumerate(_list(data, "functions", "export")):
        where = f"functions[{i}]"
        addr = norm_addr(_need(f, "address", (str, int), where))
        if addr in seen:
            raise ExportError(f"{where}: duplicate address {addr}")
        seen.add(addr)
        name = _need(f, "name", str, where)
        if not name:
            raise ExportError(f"{where}: empty name")
        functions.append(
            {
                "address": addr,
                "name": name,
                "size": _opt(f, "size", int, 0, where),
                "signature": _opt(f, "signature", str, "", where),
                "decompiled": _opt(f, "decompiled", str, "", where),
                "external": _opt(f, "external", bool, False, where),
            }
        )

    calls = []
    for i, c in enumerate(_list(data, "calls", "export")):
        where = f"calls[{i}]"
        src = norm_addr(_need(c, "from", (str, int), where))
        dst = norm_addr(_need(c, "to", (str, int), where))
        for end in (src, dst):
            if end not in seen:
                raise ExportError(f"{where}: unknown function {end}")
        site = norm_addr(c["site"]) if "site" in c else None
        calls.append({"from": src, "to": dst, "site": site})

    strings = []
    str_seen = set()
    for i, s in enumerate(_list(data, "strings", "export")):
        where = f"strings[{i}]"
        addr = norm_addr(_need(s, "address", (str, int), where))
        if addr in str_seen:
            raise ExportError(f"{where}: duplicate address {addr}")
        str_seen.add(addr)
        refs = []
        for j, r in enumerate(_list(s, "refs", where)):
            fn = norm_addr(_need(r, "function", (str, int), f"{where}.refs[{j}]"))
            if fn not in seen:
                raise ExportError(f"{where}.refs[{j}]: unknown function {fn}")
            site = norm_addr(r["site"]) if "site" in r else None
            refs.append({"function": fn, "site": site})
        strings.append({"address": addr, "value": _need(s, "value", str, where), "refs": refs})

    return {"program": program, "functions": functions, "calls": calls, "strings": strings}


def load_export(path):
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as e:
        raise ExportError(f"{path}: invalid JSON: {e}") from e
    except UnicodeDecodeError as e:
        raise ExportError(f"{path}: not UTF-8 text") from e
    return parse_export(data)
