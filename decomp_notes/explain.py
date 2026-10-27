import json
import re
import urllib.error
import urllib.request

from . import db
from .exportfmt import ExportError, norm_addr

_HEX_TOKEN = re.compile(r"\b0x[0-9a-fA-F]+\b")
_TICKED = re.compile(r"`([^`]+)`")
_QUOTED = re.compile(r'"(?:[^"\\]|\\.)*"')
# identifiers written without backticks: snake_case, or a name followed by "("
_BARE_NAME = re.compile(r"\b([A-Za-z]\w*_\w*|[A-Za-z]\w*(?=\())")
# the export holds no evidence for a verdict like these
_VERDICT = re.compile(
    r"\b(malicious|malware|benign|harmless|trojan|backdoor|ransomware|virus|spyware|"
    r"rootkit|botnet|exploit|safe|unsafe|dangerous)\b",
    re.IGNORECASE,
)

# substring of an imported/callee name -> what calling it suggests
BEHAVIOURS = [
    (
        ("socket", "connect", "send", "recv", "WSAStartup", "InternetOpen", "HttpSend"),
        "network I/O",
    ),
    (("fopen", "fread", "fwrite", "CreateFile", "ReadFile", "WriteFile"), "file access"),
    (("strcmp", "strncmp", "memcmp", "lstrcmp"), "string comparison"),
    (("CreateProcess", "WinExec", "system", "ShellExecute"), "process execution"),
    (("RegOpenKey", "RegSetValue", "RegCreateKey"), "registry access"),
    (("VirtualAlloc", "VirtualProtect", "WriteProcessMemory"), "memory manipulation"),
    (("printf", "puts", "MessageBox"), "console or UI output"),
    (("DeleteFile", "unlink", "remove"), "file deletion"),
]


class ValidationError(ValueError):
    pass


def _ref(item):
    return f"`{item['name']}` ({item['address']})"


def gather(conn, key):
    detail = db.function_detail(conn, key)
    if detail is None:
        raise KeyError(key)
    return detail


def template_explanation(detail):
    me = detail["address"]
    name = detail["name"]
    claims = []

    def claim(text, *cites):
        claims.append({"text": text, "cites": list(cites)})

    if detail["external"]:
        claim(f"`{name}` ({me}) is an external function with no decompiled body.", me)
    else:
        lines = len([ln for ln in detail["decompiled"].splitlines() if ln.strip()])
        claim(
            f"`{name}` ({me}) is {detail['size']} bytes and decompiles to {lines} non-empty "
            f"lines; signature: {detail['signature'] or 'not exported'}.",
            me,
        )

    callees = detail["callees"]
    if callees:
        names = ", ".join(_ref(c) for c in callees)
        claim(f"`{name}` ({me}) calls {names}.", me, *[c["address"] for c in callees])
        for label_names, label in BEHAVIOURS:
            hits = [c for c in callees if any(n.lower() in c["name"].lower() for n in label_names)]
            if hits:
                claim(
                    f"Calls to {', '.join(_ref(h) for h in hits)} suggest {label}.",
                    *[h["address"] for h in hits],
                )
    else:
        claim(f"`{name}` ({me}) has no recorded outgoing calls.", me)

    callers = detail["callers"]
    if callers:
        claim(
            f"`{name}` ({me}) is called from {', '.join(_ref(c) for c in callers)}.",
            me,
            *[c["address"] for c in callers],
        )
    else:
        claim(f"No caller of `{name}` ({me}) is recorded in the export.", me)

    for s in detail["strings"]:
        value = s["value"] if len(s["value"]) <= 60 else s["value"][:57] + "..."
        site = f" at {s['site']}" if s["site"] else ""
        cites = [me, s["address"]] + ([s["site"]] if s["site"] else [])
        claim(
            f"`{name}` ({me}) references the string {json.dumps(value)} stored at {s['address']}{site}.",
            *cites,
        )

    return claims


def validate_claims(conn, claims):
    if not isinstance(claims, list) or not claims:
        raise ValidationError("no claims")
    addrs = db.known_addresses(conn)
    names = db.function_names(conn)
    for i, c in enumerate(claims):
        if not isinstance(c, dict) or not isinstance(c.get("text"), str) or not c["text"].strip():
            raise ValidationError(f"claim {i}: missing text")
        cites = c.get("cites")
        if not isinstance(cites, list) or not cites:
            raise ValidationError(f"claim {i}: no citations")
        for cite in cites:
            if not isinstance(cite, str):
                raise ValidationError(f"claim {i}: bad citation {cite!r}")
            if cite in names:
                continue
            try:
                ok = norm_addr(cite) in addrs
            except ExportError:
                ok = False
            if not ok:
                raise ValidationError(f"claim {i}: citation {cite!r} does not exist in the export")
        for tok in _HEX_TOKEN.findall(c["text"]):
            if norm_addr(tok) not in addrs:
                raise ValidationError(f"claim {i}: address {tok} does not exist in the export")
        for tok in _TICKED.findall(c["text"]):
            if tok not in names:
                raise ValidationError(f"claim {i}: function `{tok}` does not exist in the export")
        prose = _QUOTED.sub("", _TICKED.sub("", c["text"]))
        verdict = _VERDICT.search(prose)
        if verdict:
            raise ValidationError(
                f"claim {i}: verdict wording {verdict.group(0)!r} is not backed by the export"
            )
        for tok in _BARE_NAME.findall(prose):
            if tok not in names:
                raise ValidationError(f"claim {i}: function {tok} does not exist in the export")
    return claims


class OllamaClient:
    def __init__(self, model, url="http://127.0.0.1:11434", timeout=120):
        self.model = model
        self.url = url.rstrip("/")
        self.timeout = timeout

    def complete(self, prompt):
        body = json.dumps(
            {"model": self.model, "prompt": prompt, "stream": False, "format": "json"}
        ).encode()
        req = urllib.request.Request(
            self.url + "/api/generate", body, {"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.load(resp)["response"]
        except (urllib.error.URLError, OSError, ValueError, KeyError) as e:
            raise ConnectionError(f"ollama request failed: {e}") from e


def build_prompt(detail):
    evidence = {
        "function": {k: detail[k] for k in ("name", "address", "signature")},
        "decompiled": detail["decompiled"][:6000],
        "callees": detail["callees"],
        "callers": detail["callers"],
        "strings": detail["strings"],
    }
    return (
        "You are helping reverse-engineer a binary. Explain what the function below does, "
        "using only the evidence given.\n"
        'Reply with JSON: {"claims": [{"text": "...", "cites": ["0x00401000", ...]}]}.\n'
        "Every claim needs at least one citation: an address or function name that appears in "
        "the evidence. Write function names in backticks and addresses as 0x%08x. "
        "Do not mention any function or address that is not in the evidence.\n\n"
        + json.dumps(evidence, indent=1)
    )


def parse_reply(text):
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`").removeprefix("json").strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValidationError(f"reply is not JSON: {e}") from e
    if not isinstance(data, dict):
        raise ValidationError("reply is not an object")
    return data.get("claims")


def explain(conn, key, client=None):
    detail = gather(conn, key)
    result = {
        "function": {"name": detail["name"], "address": detail["address"]},
        "source": "template",
        "claims": None,
        "note": None,
    }
    if client is not None:
        try:
            claims = parse_reply(client.complete(build_prompt(detail)))
            result["claims"] = validate_claims(conn, claims)
            result["source"] = "ollama"
            return result
        except (ConnectionError, ValidationError) as e:
            result["note"] = f"model answer not used: {e}"
    result["claims"] = template_explanation(detail)
    return result
