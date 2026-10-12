"""Fixtures des tests du paquet (le monde factice est dans `monde.py`)."""

import sys
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from monde import Monde  # noqa: E402


@pytest.fixture
def monde(monkeypatch):
    m = Monde()
    monkeypatch.setattr(urllib.request, "urlopen", m.urlopen)
    return m


@pytest.fixture
def dossier(tmp_path):
    return tmp_path / "proveit-mcp"
