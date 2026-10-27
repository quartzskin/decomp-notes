import hashlib
import re
import sqlite3

from .exportfmt import ExportError, norm_addr

SCHEMA = """
create table meta(key text primary key, value text);
create table functions(
    addr text primary key, name text not null, size integer, signature text,
    body text, body_hash text, external integer
);
create index functions_name on functions(name);
create table calls(src text, dst text, site text);
create index calls_src on calls(src);
create index calls_dst on calls(dst);
create table strings(addr text primary key, value text);
create table string_refs(string_addr text, func text, site text);
create index string_refs_func on string_refs(func);
"""

_AUTO_NAME = re.compile(r"\b(FUN|DAT|LAB|PTR|SUB|UNK)_[0-9a-fA-F]+\b")
_BIG_HEX = re.compile(r"0x[0-9a-fA-F]{6,}")


def body_hash(name, body, external=False):
    if external or not body.strip():
        return hashlib.sha256(f"extern:{name}".encode()).hexdigest()
    text = _AUTO_NAME.sub(lambda m: m.group(1) + "_", body)
    text = _BIG_HEX.sub("0xADDR", text)
    return hashlib.sha256(" ".join(text.split()).encode()).hexdigest()


def build(export, path=":memory:"):
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    for table in ("meta", "functions", "calls", "strings", "string_refs"):
        conn.execute(f"drop table if exists {table}")
    conn.executescript(SCHEMA)
    prog = export["program"]
    conn.executemany("insert into meta values (?, ?)", [(k, str(v)) for k, v in prog.items()])
    conn.executemany(
        "insert into functions values (?,?,?,?,?,?,?)",
        [
            (
                f["address"],
                f["name"],
                f["size"],
                f["signature"],
                f["decompiled"],
                body_hash(f["name"], f["decompiled"], f["external"]),
                int(f["external"]),
            )
            for f in export["functions"]
        ],
    )
    conn.executemany(
        "insert into calls values (?,?,?)",
        [(c["from"], c["to"], c["site"]) for c in export["calls"]],
    )
    for s in export["strings"]:
        conn.execute("insert into strings values (?,?)", (s["address"], s["value"]))
        conn.executemany(
            "insert into string_refs values (?,?,?)",
            [(s["address"], r["function"], r["site"]) for r in s["refs"]],
        )
    conn.commit()
    return conn


def open_db(path):
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("select count(*) from functions").fetchone()
    except sqlite3.DatabaseError as e:
        conn.close()
        raise ExportError(f"{path}: not a decomp-notes database") from e
    return conn


def _brief(row):
    return {"name": row["name"], "address": row["addr"]}


def find_function(conn, key):
    try:
        row = conn.execute("select * from functions where addr = ?", (norm_addr(key),)).fetchone()
        if row:
            return row
    except ExportError:
        pass
    return conn.execute(
        "select * from functions where name = ? order by addr limit 1", (key,)
    ).fetchone()


def list_functions(conn, query=""):
    rows = conn.execute(
        "select addr, name, size, external from functions "
        "where name like ? escape '\\' or addr like ? escape '\\' order by addr",
        (f"%{_like(query)}%", f"%{_like(query.lower())}%"),
    )
    return [
        {
            "name": r["name"],
            "address": r["addr"],
            "size": r["size"],
            "external": bool(r["external"]),
        }
        for r in rows
    ]


def _like(text):
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def callers(conn, addr):
    rows = conn.execute(
        "select distinct f.addr, f.name from calls c join functions f on f.addr = c.src "
        "where c.dst = ? order by f.addr",
        (addr,),
    )
    return [_brief(r) for r in rows]


def callees(conn, addr):
    rows = conn.execute(
        "select distinct f.addr, f.name from calls c join functions f on f.addr = c.dst "
        "where c.src = ? order by f.addr",
        (addr,),
    )
    return [_brief(r) for r in rows]


def strings_of(conn, addr):
    rows = conn.execute(
        "select s.addr, s.value, min(r.site) as site from string_refs r "
        "join strings s on s.addr = r.string_addr where r.func = ? group by s.addr order by s.addr",
        (addr,),
    )
    return [{"address": r["addr"], "value": r["value"], "site": r["site"]} for r in rows]


def function_detail(conn, key):
    row = find_function(conn, key)
    if row is None:
        return None
    return {
        "name": row["name"],
        "address": row["addr"],
        "size": row["size"],
        "signature": row["signature"],
        "decompiled": row["body"],
        "external": bool(row["external"]),
        "body_hash": row["body_hash"],
        "callers": callers(conn, row["addr"]),
        "callees": callees(conn, row["addr"]),
        "strings": strings_of(conn, row["addr"]),
    }


def search(conn, query):
    rows = conn.execute(
        "select addr, value from strings where value like ? escape '\\' order by addr",
        (f"%{_like(query)}%",),
    ).fetchall()
    found = []
    for r in rows:
        users = conn.execute(
            "select distinct f.addr, f.name from string_refs s join functions f on f.addr = s.func "
            "where s.string_addr = ? order by f.addr",
            (r["addr"],),
        )
        found.append(
            {"address": r["addr"], "value": r["value"], "functions": [_brief(u) for u in users]}
        )
    return {"functions": list_functions(conn, query), "strings": found}


def known_addresses(conn):
    out = set()
    for sql in (
        "select addr from functions",
        "select addr from strings",
        "select site from calls where site is not null",
        "select site from string_refs where site is not null",
    ):
        out.update(r[0] for r in conn.execute(sql))
    return out


def function_names(conn):
    return {r[0] for r in conn.execute("select name from functions")}
