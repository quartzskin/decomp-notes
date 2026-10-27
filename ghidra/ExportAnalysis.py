# Dump functions, decompiled C, strings, xrefs and call edges to JSON for decomp-notes.
# Run from Ghidra's Script Manager (Jython) with a program open and analysed.
# @category DecompNotes
# NOTE: written against the Ghidra API docs, not run against a real Ghidra install.
import json

from ghidra.app.decompiler import DecompInterface
from ghidra.program.util import DefinedDataIterator
from ghidra.util.task import ConsoleTaskMonitor

DECOMPILE_TIMEOUT = 60

prog = currentProgram
fm = prog.getFunctionManager()
listing = prog.getListing()
monitor = ConsoleTaskMonitor()


def addr(a):
    return "0x%08x" % a.getOffset()


def resolve(fn):
    # follow thunks so calls to imports land on the external function
    seen = 0
    while fn is not None and fn.isThunk() and seen < 8:
        target = fn.getThunkedFunction(False)
        if target is None:
            break
        fn = target
        seen += 1
    return fn


ifc = DecompInterface()
ifc.openProgram(prog)

functions = []
known = {}
for fn in list(fm.getFunctions(True)) + list(fm.getExternalFunctions()):
    external = fn.isExternal()
    entry = fn.getEntryPoint()
    known[entry.getOffset()] = fn
    rec = {
        "name": fn.getName(),
        "address": addr(entry),
        "size": 0 if external else int(fn.getBody().getNumAddresses()),
        "external": external,
        "signature": fn.getPrototypeString(False, False),
        "decompiled": "",
    }
    if not external:
        res = ifc.decompileFunction(fn, DECOMPILE_TIMEOUT, monitor)
        if res.decompileCompleted():
            rec["decompiled"] = res.getDecompiledFunction().getC()
    functions.append(rec)

calls = []
for fn in fm.getFunctions(True):
    for ins in listing.getInstructions(fn.getBody(), True):
        if not ins.getFlowType().isCall():
            continue
        for ref in ins.getReferencesFrom():
            if not ref.getReferenceType().isCall():
                continue
            target = resolve(fm.getFunctionAt(ref.getToAddress()))
            if target is None or target.getEntryPoint().getOffset() not in known:
                continue
            calls.append(
                {
                    "from": addr(fn.getEntryPoint()),
                    "to": addr(target.getEntryPoint()),
                    "site": addr(ins.getAddress()),
                }
            )

strings = []
for data in DefinedDataIterator.definedStrings(prog):
    refs = []
    for ref in prog.getReferenceManager().getReferencesTo(data.getAddress()):
        owner = fm.getFunctionContaining(ref.getFromAddress())
        if owner is not None:
            refs.append({"function": addr(owner.getEntryPoint()), "site": addr(ref.getFromAddress())})
    strings.append({"address": addr(data.getAddress()), "value": unicode(data.getValue()), "refs": refs})

out = {
    "format": 1,
    "program": {
        "name": prog.getName(),
        "arch": str(prog.getLanguageID()),
        "image_base": str(prog.getImageBase()),
        "exporter": "ExportAnalysis.py",
    },
    "functions": functions,
    "calls": calls,
    "strings": strings,
}

path = str(askFile("Export JSON", "Save"))
with open(path, "w") as fh:
    json.dump(out, fh, indent=1)
print("wrote %d functions, %d calls, %d strings to %s" % (len(functions), len(calls), len(strings), path))
