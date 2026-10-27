import json
import threading
import urllib.error
import urllib.request

import pytest

from decomp_notes.server import make_server


@pytest.fixture
def base(conn):
    httpd = make_server(conn, port=0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_port}"
    httpd.shutdown()
    httpd.server_close()


def get(url):
    with urllib.request.urlopen(url, timeout=5) as r:
        return r.status, r.read()


def test_index_page(base):
    status, body = get(base + "/")
    assert status == 200 and b"decomp-notes" in body


def test_function_list_and_detail(base):
    funcs = json.loads(get(base + "/api/functions?q=beacon")[1])
    assert [f["name"] for f in funcs] == ["beacon"]
    detail = json.loads(get(base + "/api/function?id=0x00401240")[1])
    assert detail["name"] == "beacon"


def test_search_and_explain(base):
    found = json.loads(get(base + "/api/search?q=TOY-")[1])
    assert found["strings"][0]["functions"][0]["name"] == "check_license"
    ex = json.loads(get(base + "/api/explain?id=check_license")[1])
    assert ex["source"] == "template" and ex["claims"]


def test_missing_function_is_404(base):
    for path in ("/api/function?id=nope", "/api/explain?id=nope", "/api/other"):
        with pytest.raises(urllib.error.HTTPError) as e:
            get(base + path)
        assert e.value.code == 404


def raw_request(base, method, path, headers):
    req = urllib.request.Request(
        base + path, method=method, headers=headers, data=b"{}" if method == "POST" else None
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def test_foreign_host_rejected(base):
    assert raw_request(base, "GET", "/api/functions", {"Host": "evil.example"}) == 403
    assert raw_request(base, "GET", "/api/functions", {"Host": "localhost:8765"}) == 200


def test_foreign_origin_rejected(base):
    assert raw_request(base, "GET", "/api/functions", {"Origin": "http://evil.example"}) == 403
    assert raw_request(base, "GET", "/api/functions", {"Origin": "http://localhost:8765"}) == 200


def test_post_requires_json_content_type(base):
    assert raw_request(base, "POST", "/api/x", {"Content-Type": "text/plain"}) == 415
    assert raw_request(base, "POST", "/api/x", {"Content-Type": "application/json"}) == 404
    ct = {"Content-Type": "application/json", "Origin": "http://evil.example"}
    assert raw_request(base, "POST", "/api/x", ct) == 403
