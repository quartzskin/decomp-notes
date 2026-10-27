from decomp_notes import db
from decomp_notes.diff import diff_dbs, format_diff
from decomp_notes.exportfmt import load_export


def test_identical_exports(v1_path):
    a = db.build(load_export(v1_path))
    b = db.build(load_export(v1_path))
    assert format_diff(diff_dbs(a, b)) == "no differences"


def test_sample_versions(v1_path, v2_path):
    r = diff_dbs(db.build(load_export(v1_path)), db.build(load_export(v2_path)))
    assert [f["name"] for f in r["added"]] == ["self_delete", "DeleteFileA"]
    assert r["removed"] == []
    assert [f["name"] for f in r["changed"]] == ["check_license", "main", "xor_decode"]
    assert r["renamed"] == [
        {
            "old_name": "FUN_00401300",
            "new_name": "FUN_00401340",
            "old_address": "0x00401300",
            "new_address": "0x00401340",
        }
    ]


def test_removed_function(v1_path, v2_path):
    r = diff_dbs(db.build(load_export(v2_path)), db.build(load_export(v1_path)))
    assert [f["name"] for f in r["removed"]] == ["self_delete", "DeleteFileA"]
    assert r["added"] == []


def test_moved_but_unchanged_is_not_changed(raw):
    from decomp_notes.exportfmt import parse_export

    old = db.build(parse_export(raw))
    raw["functions"][2]["address"] = "0x401999"
    raw["calls"] = [c for c in raw["calls"] if "0x401120" not in (c["from"], c["to"])]
    new = db.build(parse_export(raw))
    assert diff_dbs(old, new)["changed"] == []
