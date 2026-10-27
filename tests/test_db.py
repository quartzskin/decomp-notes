from decomp_notes import db
from decomp_notes.db import body_hash


def test_lookup_by_name_and_address(conn):
    a = db.function_detail(conn, "beacon")
    b = db.function_detail(conn, "401240")
    assert a["address"] == b["address"] == "0x00401240"


def test_unknown_function(conn):
    assert db.function_detail(conn, "nothing") is None


def test_call_graph_navigation(conn):
    main = db.function_detail(conn, "main")
    assert [c["name"] for c in main["callees"]] == [
        "load_config",
        "check_license",
        "beacon",
        "printf",
    ]
    beacon = db.function_detail(conn, "beacon")
    assert [c["name"] for c in beacon["callers"]] == ["main"]
    assert "FUN_00401300" in [c["name"] for c in beacon["callees"]]


def test_strings_per_function(conn):
    d = db.function_detail(conn, "check_license")
    assert [s["value"] for s in d["strings"]] == ["TOY-1234-ABCD"]
    assert d["strings"][0]["site"] == "0x004011ae"


def test_search_strings_reports_users(conn):
    hits = db.search(conn, "198.51")["strings"]
    assert len(hits) == 1
    assert hits[0]["functions"] == [{"name": "beacon", "address": "0x00401240"}]


def test_search_functions_by_name_fragment(conn):
    names = [f["name"] for f in db.list_functions(conn, "load")]
    assert names == ["load_config"]


def test_like_wildcards_are_literal(conn):
    assert db.search(conn, "%")["strings"] == [
        s for s in db.search(conn, "%")["strings"] if "%" in s["value"]
    ]
    assert db.list_functions(conn, "_") == [
        f for f in db.list_functions(conn, "_") if "_" in f["name"] or "_" in f["address"]
    ]


def test_hash_ignores_auto_names_and_addresses():
    a = "x = FUN_00401300(0x401000);"
    b = "x = FUN_00401340(0x402000);"
    assert body_hash("f", a) == body_hash("f", b)
    assert body_hash("f", a) != body_hash("f", "x = FUN_00401300(7);")


def test_hash_ignores_whitespace():
    assert body_hash("f", "a  b\n c") == body_hash("f", "a b c")


def test_open_db_rejects_other_files(tmp_path):
    import pytest

    from decomp_notes.exportfmt import ExportError

    p = tmp_path / "x.db"
    p.write_text("hello", encoding="utf-8")
    with pytest.raises(ExportError):
        db.open_db(p)
