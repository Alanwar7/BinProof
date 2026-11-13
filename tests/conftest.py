import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from fixture import make_export  # noqa: E402


@pytest.fixture
def export(tmp_path):
    root = tmp_path / "export"
    addrs = make_export(root)
    return root, addrs
