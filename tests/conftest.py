import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))


@pytest.fixture(scope="session")
def corpus_root() -> Path:
    return REPO / "corpus" / "samples"


@pytest.fixture(scope="session")
def samples(corpus_root):
    from divergence.bench.corpus import load_corpus

    return load_corpus(corpus_root)
