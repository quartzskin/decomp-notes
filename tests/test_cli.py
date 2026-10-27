import pytest

from decomp_notes.cli import main
from decomp_notes.exportfmt import ExportError


def test_import_then_explain(v1_path, tmp_path, capsys):
    db_path = str(tmp_path / "a.db")
    main(["import", str(v1_path), "--db", db_path])
    assert "14 functions, 9 strings" in capsys.readouterr().out
    main(["explain", db_path, "check_license"])
    out = capsys.readouterr().out
    assert "[template]" in out and "TOY-1234-ABCD" in out


def test_diff_command(v1_path, v2_path, capsys):
    main(["diff", str(v1_path), str(v2_path)])
    out = capsys.readouterr().out
    assert "+ self_delete" in out and "~ check_license" in out and "> FUN_00401300" in out


def test_bad_export_exits_with_message(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("[]", encoding="utf-8")
    with pytest.raises(SystemExit) as e:
        main(["import", str(p), "--db", str(tmp_path / "x.db")])
    assert "error:" in str(e.value)


def test_unknown_function_exits(v1_path):
    with pytest.raises(SystemExit):
        main(["explain", str(v1_path), "nope"])


def test_export_error_is_value_error():
    assert issubclass(ExportError, ValueError)


def test_remote_ollama_url_refused_without_flag(v1_path):
    argv = [
        "explain",
        str(v1_path),
        "main",
        "--ollama-model",
        "m",
        "--ollama-url",
        "http://example.com:11434",
    ]
    with pytest.raises(SystemExit, match="non-local"):
        main(argv)


def test_remote_ollama_url_allowed_with_flag(v1_path, capsys):
    argv = [
        "explain",
        str(v1_path),
        "main",
        "--ollama-model",
        "m",
        "--ollama-url",
        "http://192.0.2.1:1",
        "--allow-remote",
    ]
    main(argv)
    assert "[template]" in capsys.readouterr().out
