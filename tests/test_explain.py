import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from decomp_notes import db
from decomp_notes.explain import (
    OllamaClient,
    ValidationError,
    explain,
    template_explanation,
    validate_claims,
)


def test_template_claims_all_cite_and_validate(conn):
    for f in db.list_functions(conn):
        detail = db.function_detail(conn, f["address"])
        claims = template_explanation(detail)
        assert all(c["cites"] for c in claims)
        validate_claims(conn, claims)


def test_template_for_beacon_mentions_network_and_string(conn):
    claims = explain(conn, "beacon")["claims"]
    text = " ".join(c["text"] for c in claims)
    assert "network I/O" in text
    assert "198.51.100.7" in text
    assert "0x00406048" in text


def test_template_survives_hostile_string(tmp_path, raw):
    from decomp_notes.exportfmt import parse_export

    raw["strings"][0]["value"] = "`evil` 0xdeadbeef"
    c = db.build(parse_export(raw))
    result = explain(c, "main")
    assert result["source"] == "template"


def test_unknown_function_raises(conn):
    with pytest.raises(KeyError):
        explain(conn, "nope")


@pytest.mark.parametrize(
    "claims, msg",
    [
        ([], "no claims"),
        ([{"text": "x", "cites": []}], "no citations"),
        ([{"cites": ["main"]}], "missing text"),
        ([{"text": "fine", "cites": ["0x00deadbe"]}], "does not exist"),
        ([{"text": "fine", "cites": ["ghost_fn"]}], "does not exist"),
        ([{"text": "see 0x00123456", "cites": ["main"]}], "address 0x00123456"),
        ([{"text": "`ghost_fn` runs", "cites": ["main"]}], "function `ghost_fn`"),
        ([{"text": "ok", "cites": [5]}], "bad citation"),
        ("not a list", "no claims"),
        ([{"text": "this is malware", "cites": ["main"]}], "verdict wording"),
        ([{"text": "main calls ghost_fn next", "cites": ["main"]}], "function ghost_fn"),
        ([{"text": "main calls ghost(1)", "cites": ["main"]}], "function ghost"),
    ],
)
def test_validator_rejects(conn, claims, msg):
    with pytest.raises(ValidationError, match=msg):
        validate_claims(conn, claims)


def test_validator_ignores_quoted_strings_and_known_bare_names(conn):
    ok = [{"text": 'main calls check_license and prints "safe_mode on"', "cites": ["main"]}]
    assert validate_claims(conn, ok) == ok


def test_validator_accepts_names_and_unpadded_addresses(conn):
    ok = [{"text": "`main` at 0x401000", "cites": ["main", "0x401000", "40100a"]}]
    assert validate_claims(conn, ok) == ok


class FakeOllama:
    def __init__(self, reply, status=200):
        outer = self
        self.requests = []

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers["Content-Length"])
                outer.requests.append((self.path, json.loads(self.rfile.read(n))))
                body = json.dumps({"response": reply}).encode()
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.httpd = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_port}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def fake():
    made = []

    def make(reply, **kw):
        f = FakeOllama(reply, **kw)
        made.append(f)
        return f

    yield make
    for f in made:
        f.close()


def test_ollama_good_answer_is_used(conn, fake):
    reply = json.dumps(
        {
            "claims": [
                {
                    "text": "`check_license` (0x004011a0) compares input",
                    "cites": ["0x004011a0", "strcmp"],
                }
            ]
        }
    )
    srv = fake(reply)
    result = explain(conn, "check_license", OllamaClient("m", srv.url))
    assert result["source"] == "ollama"
    assert result["note"] is None
    path, body = srv.requests[0]
    assert path == "/api/generate"
    assert body["model"] == "m" and body["stream"] is False
    assert "TOY-1234-ABCD" in body["prompt"]


def test_ollama_fenced_json_is_accepted(conn, fake):
    reply = "```json\n" + json.dumps({"claims": [{"text": "x", "cites": ["main"]}]}) + "\n```"
    result = explain(conn, "main", OllamaClient("m", fake(reply).url))
    assert result["source"] == "ollama"


@pytest.mark.parametrize(
    "reply",
    [
        json.dumps({"claims": [{"text": "calls it", "cites": ["0x00bad000"]}]}),
        json.dumps({"claims": [{"text": "`made_up` is called", "cites": ["main"]}]}),
        json.dumps({"claims": [{"text": "no cite", "cites": []}]}),
        json.dumps({"claims": []}),
        json.dumps(["claims"]),
        "this is prose, not json",
    ],
)
def test_ollama_bad_answers_fall_back(conn, fake, reply):
    result = explain(conn, "main", OllamaClient("m", fake(reply).url))
    assert result["source"] == "template"
    assert result["note"].startswith("model answer not used")
    validate_claims(conn, result["claims"])


def test_ollama_unreachable_falls_back(conn):
    result = explain(conn, "main", OllamaClient("m", "http://127.0.0.1:1", timeout=2))
    assert result["source"] == "template"
    assert "ollama request failed" in result["note"]


def test_ollama_http_error_falls_back(conn, fake):
    result = explain(conn, "main", OllamaClient("m", fake("{}", status=500).url))
    assert result["source"] == "template"
