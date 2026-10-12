"""Manifestes de publication du paquet `proveit-mcp`.

Ce fichier est exporté tel quel vers le miroir public : il ne cite aucun chemin ni marqueur interne. Les
contrôles qui ont besoin de documents du dépôt prove-it (copie hors ligne du schéma du registre, mention IA)
se marquent `skip`, avec la raison, quand ils tournent dans le miroir où ces documents n'existent pas.
"""

import asyncio
import json
import re
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from proveit_mcp import serveur

PAQUET = Path(__file__).resolve().parents[1]
RACINE = PAQUET.parent  # racine de prove-it ; dans le miroir, c'est le parent du clone, sans docs/
SCHEMA = RACINE / "docs" / "ref" / "mcp-server.schema-2025-12-11.json"
MENTION_IA = RACINE / "docs" / "juridique" / "05-mention-ia-art50.md"
WORKFLOW = PAQUET / ".github" / "workflows" / "publish.yml"

VERSION = "0.1.0"
DESCRIPTION_PO = ("Free public benchmark for AI agents: compliance tasks, every claim checked against "
                  "signed receipts")
OUTILS = tuple(t.name for t in asyncio.run(serveur.creer().list_tools()))  # lus sur le serveur, pas retapés


def _json(nom):
    return json.loads((PAQUET / nom).read_text(encoding="utf-8"))


def _readme():
    return (PAQUET / "README.md").read_text(encoding="utf-8")


def _workflow():
    return WORKFLOW.read_text(encoding="utf-8")


def _sans_commentaires(texte):
    return "\n".join(l for l in texte.splitlines() if not l.lstrip().startswith("#"))


# -- server.json ---------------------------------------------------------------------------------------------

def test_server_json_valide_contre_le_schema():
    jsonschema = pytest.importorskip("jsonschema")
    if not SCHEMA.exists():
        pytest.skip("copie hors ligne du schéma du registre absente (miroir : seul prove-it la porte)")
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    serveur = _json("server.json")
    assert serveur["$schema"] == schema["$id"]
    jsonschema.validate(serveur, schema)


def test_server_json_champs_convenus():
    s = _json("server.json")
    assert s["$schema"] == "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json"
    assert s["name"] == "io.github.ark-forge/prove-it"
    assert s["description"] == DESCRIPTION_PO
    assert s["version"] == VERSION
    assert s["repository"] == {"url": "https://github.com/ark-forge/proveit-mcp", "source": "github"}
    assert s["websiteUrl"] == "https://proveit.arkforge.tech"
    assert len(s["packages"]) == 1
    p = s["packages"][0]
    assert (p["registryType"], p["identifier"], p["version"]) == ("pypi", "proveit-mcp", VERSION)
    assert p["runtimeHint"] == "uvx"
    assert p["transport"] == {"type": "stdio"}
    variables = p["environmentVariables"]
    assert [v["name"] for v in variables] == ["PROVEIT_MCP_HOME"]
    assert variables[0]["isRequired"] is False and variables[0]["isSecret"] is False


def test_description_registre_100_caracteres_max():
    description = _json("server.json")["description"]
    assert 0 < len(description) <= 100, len(description)


def test_versions_concordent():
    s = _json("server.json")
    assert s["version"] == s["packages"][0]["version"] == VERSION
    init, pyproject = PAQUET / "proveit_mcp" / "__init__.py", PAQUET / "pyproject.toml"
    assert init.exists() and pyproject.exists()
    dans_init = re.search(r'^__version__\s*=\s*"([^"]+)"', init.read_text(encoding="utf-8"), re.M)
    assert dans_init, "version introuvable"
    # pyproject.toml ne porte pas de version : il la lit dans __version__, source unique.
    assert 'dynamic = ["version"]' in pyproject.read_text(encoding="utf-8")
    assert 'version = {attr = "proveit_mcp.__version__"}' in pyproject.read_text(encoding="utf-8")
    assert dans_init.group(1) == s["version"] == s["packages"][0]["version"]


def test_glama_json():
    """Indexation du miroir sans revendication de fiche : pas de `maintainers`."""
    assert _json("glama.json") == {"$schema": "https://glama.ai/mcp/schemas/server.json"}


def _pyproject():
    return (PAQUET / "pyproject.toml").read_text(encoding="utf-8")


def test_paquet_declare_posix_seulement_et_dit_les_pythons_verifies():
    p = _pyproject()
    assert "Operating System :: POSIX" in p and "Operating System :: MacOS" in p
    assert "OS Independent" not in p
    assert 'requires-python = ">=3.10,<3.15"' in p
    assert "POSIX" in _readme() and "Windows" in _readme()


def test_aucun_renvoi_a_un_document_interne_dans_ce_qui_est_publie():
    """Tout ce dossier part sur PyPI et sur le miroir : rien ne renvoie à un document qui n'y est pas.
    (Les motifs sont écrits en morceaux pour que ce fichier ne se désigne pas lui-même.)"""
    interdits = [r"note du " + r"tech" + r" lead", r"note " + "§", r"QUESTIONS" + r"\.md", r"exigences" + r"\.lock",
                 r"\bD1\d\d\b", r"\bC\d\d\b", r"\blot L\d\b", r"validation" + "/"]
    trouves = []
    for chemin in sorted(PAQUET.rglob("*")):
        if not chemin.is_file() or {"__pycache__", ".pytest_cache"} & set(chemin.parts) or chemin.suffix == ".pyc":
            continue
        for numero, ligne in enumerate(chemin.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            trouves += [f"{chemin.relative_to(PAQUET)}:{numero}: {m}" for m in interdits if re.search(m, ligne)]
    assert not trouves, trouves


def test_licence_mit_arkforge():
    texte = (PAQUET / "LICENSE").read_text(encoding="utf-8")
    assert texte.startswith("MIT License")
    assert "Copyright (c) 2026 ArkForge" in texte
    assert "Permission is hereby granted, free of charge" in texte
    assert 'THE SOFTWARE IS PROVIDED "AS IS"' in texte


# -- README --------------------------------------------------------------------------------------------------

def _mention_courte():
    """La version courte anglaise du document 05 §3 bis, lue dans le fichier (jamais retapée)."""
    texte = MENTION_IA.read_text(encoding="utf-8")
    bloc = texte.split("### Short version (English)", 1)[1].split("###", 1)[0]
    lignes = [l[1:].strip() for l in bloc.splitlines() if l.startswith(">")]
    assert lignes, "mention courte introuvable dans le document 05"
    return " ".join(lignes)


def _plat(texte):
    return " ".join(texte.replace("*", " ").replace(">", " ").split())


def test_readme_porte_mcp_name_et_la_mention_ia_courte():
    readme = _readme()
    premiere = next(l for l in readme.splitlines() if l.strip())
    assert premiere.strip() == "mcp-name: io.github.ark-forge/prove-it"
    # la propriété du paquet est vérifiée par cette ligne : le nom doit être celui de server.json
    assert premiere.split(": ", 1)[1] == _json("server.json")["name"]
    if not MENTION_IA.exists():
        pytest.skip("document 05 absent (miroir) : la mention n'est comparée que dans prove-it")
    assert _plat(_mention_courte()) in _plat(readme)


def test_readme_dit_ce_que_l_outil_fait_et_ne_fait_pas():
    readme = _readme()
    for outil in OUTILS:
        assert f"`{outil}`" in readme, outil
    assert "uvx proveit-mcp" in readme
    assert '"command": "uvx"' in readme and '"proveit-mcp"' in readme  # exemple de configuration stdio
    assert "PROVEIT_MCP_HOME" in readme and "~/.config/proveit-mcp" in readme
    assert "0700" in readme and "0600" in readme
    assert "ask your human first" in readme  # l'attestation est une déclaration, à demander d'abord
    # neutralité : ce que l'outil ne fait pas
    for non_fait in ("never writes", "never checks", "no cache", "never posts"):
        assert non_fait in readme, non_fait
    assert "https://proveit.arkforge.tech/skill.md" in readme
    assert "Submission format" not in readme  # le §5 n'est pas paraphrasé : on renvoie à sa source servie


def _ligne_du_readme(outil):
    [ligne] = [l for l in _readme().splitlines() if l.startswith(f"| `{outil}`")]
    return ligne


def test_readme_decrit_les_outils_du_serveur_et_rien_de_plus():
    noms = set(re.findall(r"`(proveit_\w+)`", _readme()))
    assert noms == set(OUTILS), noms ^ set(OUTILS)


MOT_DE_COMPORTEMENT = {"proveit_status": "season", "proveit_setup_identity": "binding", "proveit_enroll": "bound",
                       "proveit_read": "proxy", "proveit_submit": "dry_run", "proveit_progress": "local",
                       "proveit_report": "clos"}


def test_chaque_outil_est_decrit_pareil_dans_le_readme_et_dans_sa_description_mcp():
    descriptions = {t.name: t.description for t in asyncio.run(serveur.creer().list_tools())}
    assert set(MOT_DE_COMPORTEMENT) == set(OUTILS)
    for outil, mot in MOT_DE_COMPORTEMENT.items():
        assert mot in _ligne_du_readme(outil).lower(), (outil, "README")
        assert mot in descriptions[outil].lower(), (outil, "description MCP")


def test_readme_progress_est_local_et_ne_prete_pas_de_verdict_au_service():
    ligne = _ligne_du_readme("proveit_progress")
    assert "Local only" in ligne and "this machine" in ligne and "says nothing about how well you are doing" in ligne
    assert "season service" not in ligne


def test_readme_dit_ou_va_chaque_secret_et_ou_commencer():
    readme = _readme()
    assert "never leave it" not in readme and "stored only on this machine" not in readme
    assert "also emails it to your human" in readme and "trust.arkforge.tech" in readme
    assert "getting a key and enrolling accept the participation terms" in " ".join(readme.lower().split())
    assert "https://proveit.arkforge.tech/challenges/prove-it/saisons/1/conditions/" in readme
    assert "Call `proveit_status` first" in readme
    assert "before or after the close" not in readme and "before the close" in readme
    assert "`origin`" in readme and "`origine`" not in readme
    assert "$XDG_CONFIG_HOME/proveit-mcp" in readme
    assert "season service says" not in readme


INTERDITS = (
    r"\bscor(?:e|es|ed|ing)\b", r"\brank(?:s|ed|ing)?\b", r"\bleaderboard\b", r"\bprice[sd]?\b", r"\bpricing\b",
    r"\bbadges?\b", r"\bcertif\w*", r"\bli(?:e|es|ed|ar|ars)\b", r"\blying\b", r"\bcheat\w*", r"\bfraud\w*",
    r"mensonge", r"mentir", r"menteur", r"triche\w*", r"fraude", r"frauduleux",
)


def test_readme_sans_vocabulaire_interdit():
    # « No score before the close » est la phrase du texte PO §5 : la seule occurrence admise, et négative.
    texte = re.sub(r"No score before the close", "", _readme())
    for motif in INTERDITS:
        trouve = re.search(motif, texte, re.I)
        assert not trouve, f"{motif!r} : {trouve.group(0)!r}"
    assert "No score before the close" in _readme()


# -- workflow ------------------------------------------------------------------------------------------------

SHA_CHECKOUT = "3d3c42e5aac5ba805825da76410c181273ba90b1"
SHA_SETUP_PYTHON = "5fda3b95a4ea91299a34e894583c3862153e4b97"
SHA256_PUBLISHER = "a06c9096dcb9727c13555b6be26c7effa707b01f06a4c561ba7a3635443cf2cc"
URL_PUBLISHER = ("https://github.com/modelcontextprotocol/registry/releases/download/v1.8.1/"
                 "mcp-publisher_linux_amd64.tar.gz")


def _jobs(texte):
    """Découpe le YAML en jobs sans bibliothèque YAML : `jobs:` puis chaque clé à 2 espaces."""
    corps = texte.split("\njobs:\n", 1)[1]
    morceaux = re.split(r"^  ([a-z_-]+):\s*$", corps, flags=re.M)
    return {morceaux[i]: morceaux[i + 1] for i in range(1, len(morceaux), 2)}


def test_workflow_actions_epinglees_par_sha_et_id_token_write():
    wf = _workflow()
    utilisations = re.findall(r"^\s*-?\s*uses:\s*(\S+)", wf, re.M)
    assert utilisations, "aucune action utilisée"
    for u in utilisations:
        assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", u), f"action non épinglée par SHA : {u}"
    assert f"actions/checkout@{SHA_CHECKOUT}" in utilisations
    assert f"actions/setup-python@{SHA_SETUP_PYTHON}" in utilisations
    # déclenchement : push de main (le script attend ce job vert avant PyPI) et tag v*, rien d'autre
    assert re.search(r"on:\s*\n\s+push:\s*\n\s+branches:\s*\n\s+- ['\"]?main['\"]?\s*\n\s+tags:\s*\n\s+- ['\"]?v\*['\"]?", wf)
    assert not re.search(r"pull_request|workflow_dispatch", wf)
    # permissions : lecture du contenu partout ; id-token: write seulement là où le login OIDC en a besoin
    assert re.search(r"^permissions:\s*\n\s+contents: read\s*$", wf, re.M)
    jobs = _jobs(wf)
    assert set(jobs) == {"tests", "registre"}
    assert "id-token: write" in jobs["registre"]
    assert "id-token: write" not in jobs["tests"]
    assert "id-token: write" not in wf.split("\njobs:\n", 1)[0]
    assert "contents: read" in wf
    # le registre ne tourne que sur un tag
    assert re.search(r"if:\s*startsWith\(github\.ref, 'refs/tags/v'\)", jobs["registre"])
    assert "if:" not in jobs["tests"].split("steps:")[0]


def test_workflow_ne_publie_pas_sur_pypi():
    wf = _sans_commentaires(_workflow()).lower()
    for interdit in ("twine", "gh-action-pypi-publish", "upload.pypi.org", "pypi_token", "pypi-api-token",
                     "trusted publishing", "environment: pypi"):
        assert interdit not in wf, interdit


def test_workflow_verifie_le_sha256_de_mcp_publisher():
    wf = _sans_commentaires(_workflow())
    assert URL_PUBLISHER in wf
    assert SHA256_PUBLISHER in wf
    assert "releases/latest" not in wf and "/latest/" not in wf
    ordre = [wf.index(x) for x in (URL_PUBLISHER, "sha256sum -c", "tar ", "mcp-publisher login github-oidc",
                                   "mcp-publisher publish")]
    assert ordre == sorted(ordre), "la vérification du sha256 doit précéder l'extraction et l'usage"
    # le sha256 est comparé à la valeur épinglée dans le workflow, pas à un fichier servi avec l'archive
    assert not re.search(r"checksums?\.txt|\.sha256", wf)


def test_workflow_scalaires_simples_sans_deux_points():
    # « clé: a : b » en scalaire simple est une erreur de syntaxe YAML : GitHub refuse le fichier sans lancer un job
    # (premier envoi du 12/10, nom d'étape). Les blocs `run: |` sont du shell, pas du YAML : on les saute.
    bloc = None
    for numero, ligne in enumerate(_workflow().splitlines(), 1):
        retrait = len(ligne) - len(ligne.lstrip())
        if bloc is not None and (not ligne.strip() or retrait > bloc):
            continue
        bloc = None
        m = re.match(r"^\s*(?:- )?[\w.-]+:\s+(.*)$", ligne)
        if not m or ligne.lstrip().startswith("#"):
            continue
        valeur = re.sub(r"\s+#.*$", "", m.group(1)).rstrip()
        if re.fullmatch(r"[|>][-+]?", valeur):
            bloc = retrait
            continue
        if valeur[:1] in "\"'[{&*":
            continue
        assert ": " not in valeur and not valeur.endswith(":"), f"ligne {numero} : scalaire à mettre entre guillemets"


def test_workflow_installe_build_pour_test_wheel():
    # Sans `build` installé, `pip install .` laisse un dossier build/ qui se fait passer pour le module : test_wheel
    # ne se saute pas, il échoue (premier envoi du 12/10). Avec lui, il tourne vraiment en CI.
    tests = _jobs(_workflow())["tests"]
    assert re.search(r"pip install [^\n]*\bbuild==[\d.]+", tests)
    assert re.search(r"pip install [^\n]*\bsetuptools==[\d.]+", tests)  # --no-isolation : le backend vient de l'env


def _minors_de_requires_python():
    m = re.search(r'requires-python = ">=3\.(\d+),<3\.(\d+)"', _pyproject())
    assert m, "requires-python doit être un intervalle fermé"
    return [f"3.{n}" for n in range(int(m.group(1)), int(m.group(2)))]


def test_workflow_tests_toute_la_plage_de_requires_python():
    tests = _jobs(_workflow())["tests"]
    matrice = re.search(r"python-version:\s*\[([^\]]*)\]", tests).group(1)
    assert re.findall(r"3\.\d+", matrice) == _minors_de_requires_python() == ["3.10", "3.11", "3.12", "3.13", "3.14"]


def test_workflow_tests_installe_le_paquet_avec_ses_dependances_et_lance_pytest():
    tests = _jobs(_workflow())["tests"]
    assert "--no-deps" not in tests and "pip install ." in tests
    assert "pytest" in tests and "tests" in tests


def _controle_des_versions():
    """Le Python du pas « Version du tag = __version__ = server.json », extrait du workflow et exécuté."""
    m = re.search(r"python3 - <<'PY'\n(.*?)\n\s*PY\n", _jobs(_workflow())["tests"], re.S)
    assert m, "contrôle des versions introuvable"
    return textwrap.dedent(m.group(1))


def _lancer_le_controle(dossier, ref, type_ref="tag"):
    env = {"PATH": "/usr/bin:/bin", "GITHUB_REF_NAME": ref, "GITHUB_REF_TYPE": type_ref}
    return subprocess.run([sys.executable, "-c", _controle_des_versions()], cwd=dossier, env=env, capture_output=True,
                          text=True)


def test_le_controle_des_versions_du_workflow_passe_et_echoue_pour_de_bon(tmp_path):
    copie = tmp_path / "p"
    (copie / "proveit_mcp").mkdir(parents=True)
    for nom in ("server.json", "pyproject.toml", "proveit_mcp/__init__.py"):
        (copie / nom).write_text((PAQUET / nom).read_text(encoding="utf-8"), encoding="utf-8")
    assert _lancer_le_controle(copie, f"v{VERSION}").returncode == 0
    assert _lancer_le_controle(copie, "v9.9.9").returncode != 0
    assert _lancer_le_controle(copie, "main", "branch").returncode == 0  # push de main : pas de tag à comparer
    serveur_json = json.loads((copie / "server.json").read_text())
    serveur_json["packages"][0]["version"] = "0.0.1"
    (copie / "server.json").write_text(json.dumps(serveur_json))
    r = _lancer_le_controle(copie, f"v{VERSION}")
    assert r.returncode != 0 and "discordantes" in r.stderr
    assert _lancer_le_controle(copie, "main", "branch").returncode != 0  # sur main aussi, les versions doivent concorder


def test_workflow_registre_attend_pypi_puis_publie_de_facon_idempotente():
    jobs = _jobs(_workflow())
    registre = jobs["registre"]
    assert re.search(r"needs:\s*\[?\s*tests\s*\]?", registre)
    attente = registre.index("proveit-mcp==")
    assert re.search(r"for \w+ in \$\(seq|for \w+ in \{1\.\.|range\(", registre[:registre.index("mcp-publisher")]), \
        "boucle d'attente non bornée"
    assert attente < registre.index("mcp-publisher login github-oidc") < registre.index("mcp-publisher publish")
    assert 'output=$(mcp-publisher publish 2>&1)' in registre
    assert "already exists|duplicate|already published|conflict" in registre
