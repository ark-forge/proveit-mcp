"""Le wheel et le sdist ne contiennent que le paquet : ni corpus, ni sel, ni clé, ni code du scorer, ni tests.

Construction hors réseau : `python -m build --no-isolation` (setuptools déjà installé), sur l'arbre que le script de
publication exporte : tout `participant/`, tests compris, sans filtre."""

import re
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

import proveit_mcp

PARTICIPANT = Path(proveit_mcp.__file__).resolve().parents[1]
INTERDIT = re.compile(r"(scorer|corpus|validation|cible|cle-reponses|\.pem|\.key|sel|salt|secret|\.env|saison\.json"
                      r"|decisions-goal|taches\.json|bareme)", re.I)


@pytest.fixture(scope="module")
def construit(tmp_path_factory):
    pytest.importorskip("build")
    src = tmp_path_factory.mktemp("src") / "participant"
    shutil.copytree(PARTICIPANT, src, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache",
                                                                    "dist", "build", "*.egg-info"))
    assert (src / "tests").is_dir() and (src / "README.md").is_file()
    sortie = tmp_path_factory.mktemp("dist")
    r = subprocess.run([sys.executable, "-m", "build", "--no-isolation", "--wheel", "--sdist", "--outdir", str(sortie),
                        str(src)], capture_output=True, text=True, timeout=300)
    assert r.returncode == 0, r.stdout[-2000:] + r.stderr[-2000:]
    return sortie


def test_wheel_ne_contient_que_le_paquet(construit):
    [wheel] = construit.glob("*.whl")
    noms = zipfile.ZipFile(wheel).namelist()
    assert wheel.name == f"proveit_mcp-{proveit_mcp.__version__}-py3-none-any.whl"
    for n in noms:
        assert n.startswith("proveit_mcp/") or re.match(r"proveit_mcp-[\d.]+\.dist-info/", n), n
    sources = {n.split("/")[1] for n in noms if n.startswith("proveit_mcp/") and n.endswith(".py")}
    assert sources == {"__init__.py", "__main__.py", "client.py", "cles.py", "outils.py", "serveur.py"}
    for n in noms:
        assert not INTERDIT.search(n.split("/", 1)[1] if n.startswith("proveit_mcp/") else ""), n


def test_sdist_ne_contient_que_le_paquet(construit):
    [sdist] = construit.glob("*.tar.gz")
    racine = sdist.name[:-len(".tar.gz")]
    noms = [m.name for m in tarfile.open(sdist).getmembers() if m.isfile()]
    for n in noms:
        reste = n[len(racine) + 1:]
        assert reste.split("/")[0] in {"proveit_mcp", "pyproject.toml", "README.md", "LICENSE", "PKG-INFO", "setup.cfg", "MANIFEST.in",
                                       "proveit_mcp.egg-info"}, n
        assert not INTERDIT.search(reste.split("/", 1)[1] if reste.startswith("proveit_mcp/") else ""), n


def test_sdist_ne_contient_pas_les_tests(construit):
    """Les tests ont besoin de `conftest.py` et de `monde.py` : publiés seuls, ils seraient cassés."""
    [sdist] = construit.glob("*.tar.gz")
    assert not [m.name for m in tarfile.open(sdist).getmembers() if "/tests/" in m.name]


def test_wheel_declare_le_script_console_la_version_et_la_licence(construit):
    [wheel] = construit.glob("*.whl")
    z = zipfile.ZipFile(wheel)
    meta = z.read(f"proveit_mcp-{proveit_mcp.__version__}.dist-info/METADATA").decode()
    assert f"Name: proveit-mcp\nVersion: {proveit_mcp.__version__}\n" in meta
    assert re.search(r"^(License-Expression: MIT|License: MIT)", meta, re.M)
    assert set(re.search(r"^Requires-Python: (.+)$", meta, re.M).group(1).split(",")) == {">=3.10", "<3.15"}
    assert "proveit-mcp = proveit_mcp.__main__:main" in z.read(
        f"proveit_mcp-{proveit_mcp.__version__}.dist-info/entry_points.txt").decode()


def test_toutes_les_dependances_sont_epinglees_a_la_version_exacte(construit):
    [wheel] = construit.glob("*.whl")
    meta = zipfile.ZipFile(wheel).read(f"proveit_mcp-{proveit_mcp.__version__}.dist-info/METADATA").decode()
    exigences = re.findall(r"^Requires-Dist: (.+)$", meta, re.M)
    assert exigences
    for e in exigences:
        assert re.match(r"^[A-Za-z0-9_.\-]+(\[[a-z,]+\])?==[0-9][\w.]*(\s*;.*)?$", e), e
    noms = {re.split(r"[=\[; ]", e)[0].lower() for e in exigences}
    assert {"mcp", "cryptography"} <= noms
