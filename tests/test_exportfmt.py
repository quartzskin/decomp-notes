import pytest

from decomp_notes.exportfmt import ExportError, load_export, norm_addr, parse_export


def test_loads_sample(v1_path):
    export = load_export(v1_path)
    assert len(export["functions"]) == 14
    assert export["functions"][0]["address"] == "0x00401000"


def test_norm_addr_forms():
    assert norm_addr("0x401000") == norm_addr("401000") == norm_addr(0x401000) == "0x00401000"


@pytest.mark.parametrize("bad", ["", "zz", "0x", None, True, -1, 1.5, [1]])
def test_norm_addr_rejects(bad):
    with pytest.raises(ExportError):
        norm_addr(bad)


def test_invalid_json(tmp_path):
    p = tmp_path / "x.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(ExportError, match="invalid JSON"):
        load_export(p)


def test_not_utf8(tmp_path):
    p = tmp_path / "x.json"
    p.write_bytes(b"\xff\xfe\x00")
    with pytest.raises(ExportError):
        load_export(p)


@pytest.mark.parametrize("data", [[], "x", 3, None])
def test_top_level_must_be_object(data):
    with pytest.raises(ExportError):
        parse_export(data)


def test_wrong_format_version(mutate):
    with pytest.raises(ExportError, match="format"):
        load_export(mutate(lambda d: d.update(format=2)))


def test_function_without_name(mutate):
    with pytest.raises(ExportError, match="missing 'name'"):
        load_export(mutate(lambda d: d["functions"][0].pop("name")))


def test_function_bad_size_type(mutate):
    with pytest.raises(ExportError, match="size"):
        load_export(mutate(lambda d: d["functions"][0].update(size="big")))


def test_duplicate_function_address(mutate):
    with pytest.raises(ExportError, match="duplicate"):
        load_export(mutate(lambda d: d["functions"][1].update(address="0x401000")))


def test_call_to_unknown_function(mutate):
    with pytest.raises(ExportError, match="unknown function"):
        load_export(mutate(lambda d: d["calls"][0].update(to="0x999999")))


def test_string_ref_to_unknown_function(mutate):
    with pytest.raises(ExportError, match="unknown function"):
        load_export(mutate(lambda d: d["strings"][0]["refs"][0].update(function="0x1")))


def test_functions_not_a_list(mutate):
    with pytest.raises(ExportError):
        load_export(mutate(lambda d: d.update(functions={"a": 1})))


def test_function_entry_not_object(mutate):
    with pytest.raises(ExportError, match="expected an object"):
        load_export(mutate(lambda d: d["functions"].append(5)))


def test_string_value_must_be_text(mutate):
    with pytest.raises(ExportError, match="value"):
        load_export(mutate(lambda d: d["strings"][0].update(value=12)))


def test_bad_site_address(mutate):
    with pytest.raises(ExportError, match="bad address"):
        load_export(mutate(lambda d: d["calls"][0].update(site="nope")))
