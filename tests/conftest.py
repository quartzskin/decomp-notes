import copy
import json
from pathlib import Path

import pytest

from decomp_notes import db
from decomp_notes.exportfmt import load_export

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


@pytest.fixture
def v1_path():
    return EXAMPLES / "toy_v1.json"


@pytest.fixture
def v2_path():
    return EXAMPLES / "toy_v2.json"


@pytest.fixture
def raw():
    return json.loads((EXAMPLES / "toy_v1.json").read_text(encoding="utf-8"))


@pytest.fixture
def mutate(raw, tmp_path):
    def apply(fn):
        data = copy.deepcopy(raw)
        fn(data)
        path = tmp_path / "bad.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    return apply


@pytest.fixture
def conn(v1_path):
    return db.build(load_export(v1_path))
