import argparse
import json
import sys
from urllib.parse import urlparse

from . import db
from .diff import diff_dbs, format_diff
from .explain import OllamaClient, explain
from .exportfmt import ExportError, load_export
from .server import make_server


def _open(path):
    if path.endswith(".json"):
        return db.build(load_export(path))
    return db.open_db(path)


LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}


def _client(args):
    if getattr(args, "ollama_model", None):
        host = urlparse(args.ollama_url).hostname
        if host not in LOCAL_HOSTS and not args.allow_remote:
            sys.exit(
                f"error: refusing non-local ollama endpoint {host} (pass --allow-remote to override)"
            )
        return OllamaClient(args.ollama_model, args.ollama_url)
    return None


def cmd_import(args):
    conn = db.build(load_export(args.export), args.db)
    n = conn.execute("select count(*) from functions").fetchone()[0]
    s = conn.execute("select count(*) from strings").fetchone()[0]
    print(f"{args.db}: {n} functions, {s} strings")


def cmd_serve(args):
    server = make_server(_open(args.source), args.host, args.port, _client(args))
    print(f"http://{args.host}:{server.server_port}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


def cmd_explain(args):
    try:
        result = explain(_open(args.source), args.function, _client(args))
    except KeyError:
        sys.exit(f"no such function: {args.function}")
    fn = result["function"]
    print(f"{fn['name']} {fn['address']}  [{result['source']}]")
    if result["note"]:
        print(f"note: {result['note']}")
    for c in result["claims"]:
        print(f"- {c['text']}  [{', '.join(c['cites'])}]")


def cmd_diff(args):
    result = diff_dbs(_open(args.old), _open(args.new))
    print(json.dumps(result, indent=2) if args.json else format_diff(result))


def _add_ollama(p):
    p.add_argument("--ollama-model")
    p.add_argument("--ollama-url", default="http://127.0.0.1:11434")
    p.add_argument("--allow-remote", action="store_true", help="permit a non-loopback --ollama-url")


def main(argv=None):
    parser = argparse.ArgumentParser(prog="decomp-notes")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("import", help="build a SQLite index from an export")
    p.add_argument("export")
    p.add_argument("--db", default="analysis.db")
    p.set_defaults(fn=cmd_import)

    p = sub.add_parser("serve", help="local web UI; source is an export .json or an index")
    p.add_argument("source")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8765)
    _add_ollama(p)
    p.set_defaults(fn=cmd_serve)

    p = sub.add_parser("explain", help="print an explanation of one function")
    p.add_argument("source")
    p.add_argument("function", help="name or address")
    _add_ollama(p)
    p.set_defaults(fn=cmd_explain)

    p = sub.add_parser("diff", help="compare two exports or indexes")
    p.add_argument("old")
    p.add_argument("new")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_diff)

    args = parser.parse_args(argv)
    try:
        args.fn(args)
    except (ExportError, OSError) as e:
        sys.exit(f"error: {e}")
