# decomp-notes

Browse a Ghidra analysis offline and get per-function explanations where every
claim cites a function name or address from the export. Local web UI, SQLite
index, standard library only (Python 3.11+; developed on 3.14).

## Usage

Export from Ghidra with `ghidra/ExportAnalysis.py` (Script Manager, open and
analysed program; it asks where to save the JSON). Then:

    python -m decomp_notes import examples/toy_v1.json --db toy.db
    python -m decomp_notes serve toy.db            # http://127.0.0.1:8765/
    python -m decomp_notes explain toy.db beacon
    python -m decomp_notes diff examples/toy_v1.json examples/toy_v2.json

`serve`, `explain` and `diff` take either an export `.json` or an index built by
`import`. The UI has a function list, a search box (function names, addresses,
string contents), and a function page with the decompiled code, clickable
callers/callees, referenced strings and the explanation.

`examples/` has a hand-written export of a toy program in two versions.

## Explanations

The default is a template: size, callees, callers and string references, plus a
few keyword rules (a call to `socket` is reported as network I/O, and so on).
Each claim carries a list of citations. With `--ollama-model NAME` the function
data is sent to a local Ollama server and the reply is requested as JSON claims.
A reply is rejected if any claim has no citation, cites an address or function
that is not in the export, or mentions an unknown address or backticked name in
its text; the template is used instead and the UI/CLI says why.

The validator checks that references exist, not that the claim is true. A model
can cite a real function and still say something wrong.

## Diff

Functions are matched by name and compared by a hash of the decompiled body, with
auto-generated names (`FUN_...`) and long hex constants normalised. A function
that disappears under one name and reappears with an identical hash is reported
as renamed rather than removed plus added.

## Limitations

- `ghidra/ExportAnalysis.py` has never been run. Ghidra is not installed here; it
  was written from the API docs and may need fixes. Only the hand-written sample
  exports have been exercised. It is Jython (Python 2 syntax), not Ghidra 12's
  PyGhidra.
- The Ollama adapter was only tested against a fake local HTTP server, not a real
  Ollama.
- Diff matches by name, so if a stripped binary's names are all `FUN_<addr>`
  and shift between builds, most functions show up as added/removed/renamed.
- Decompiled bodies are shown as text; no syntax highlighting, no call graph drawing.
- No disassembly or per-instruction xrefs, only function-level call edges and
  string references.

## Development

    pip install pytest ruff
    pytest
    ruff check .
    ruff format --check .
