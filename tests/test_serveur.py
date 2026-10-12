"""Serveur MCP (SDK officiel, FastMCP) : conformité par le client officiel, sorties, descriptions."""

import asyncio
import json
import os
import re
import signal
import subprocess
import sys
import time
from datetime import timedelta
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.shared.memory import create_connected_server_and_client_session

from proveit_mcp import __version__, serveur
from proveit_mcp.cles import Cles
from proveit_mcp.outils import Outils

from monde import CLE_API, JETON, champs_de_score, cles_recursives as _cles_recursives

RACINE = Path(serveur.__file__).resolve().parents[1]
OUTILS = ["proveit_status", "proveit_setup_identity", "proveit_enroll", "proveit_read", "proveit_submit",
          "proveit_progress", "proveit_report"]
CONDITIONS = "https://proveit.arkforge.tech/challenges/prove-it/saisons/1/conditions/"
SECTION_5 = "https://proveit.arkforge.tech/challenges/prove-it/specification/section-5.txt"
# Vocabulaire du barème (§5) : les descriptions renvoient au texte gelé, elles ne le reformulent pas.
TERMES_DU_BAREME = ["overclaim", "supported", "unsupported", "trap", "tempting", "precedence", "own resource",
                    "task graph", "penal", "weight", "score", "success", "rate of", "per cent", "percent"]


def _sous_processus(env_extra=None, code=None, home=None):
    env = {"PYTHONPATH": str(RACINE), "HOME": str(home or "/nonexistent-home"), **(env_extra or {})}
    argv = [sys.executable, "-c", code] if code else [sys.executable, "-m", "proveit_mcp"]
    return StdioServerParameters(command=argv[0], args=argv[1:], env=env)


SANS_RESEAU = ("import socket\n"
               "def boom(*a, **k): raise AssertionError('accès réseau interdit')\n"
               "socket.socket.connect = boom; socket.getaddrinfo = boom; socket.create_connection = boom\n"
               "import runpy; runpy.run_module('proveit_mcp', run_name='__main__')\n")


async def _session(params, errlog, action):
    async with stdio_client(params, errlog=errlog) as (lire, ecrire):
        async with ClientSession(lire, ecrire, read_timeout_seconds=timedelta(seconds=60)) as s:
            init = await s.initialize()
            return await action(s, init)


def test_conformite_stdio_avec_le_client_officiel_mcp(tmp_path):
    """`python -m proveit_mcp` en sous-processus, piloté par le client du SDK officiel."""
    async def action(s, init):
        return init, await s.list_tools(), await s.send_ping()

    with open(tmp_path / "stderr", "w") as err:
        init, outils, _ = asyncio.run(_session(_sous_processus(), err, action))
    assert init.serverInfo.name == "proveit-mcp" and init.serverInfo.version == __version__
    assert sorted(t.name for t in outils.tools) == sorted(OUTILS)
    for t in outils.tools:
        Draft202012Validator.check_schema(t.inputSchema)
        assert t.description and len(t.description) > 40
        assert t.inputSchema["type"] == "object"


def test_tools_list_sans_reseau_ni_cle_ni_dossier(tmp_path):
    """Introspection (registre, Glama) : ni socket, ni clé, ni dossier ; rien n'est créé."""
    home = tmp_path / "home-inexistant"

    async def action(s, init):
        return await s.list_tools()

    with open(tmp_path / "stderr", "w") as err:
        outils = asyncio.run(_session(_sous_processus(code=SANS_RESEAU, home=home), err, action))
    assert len(outils.tools) == 7
    assert not home.exists() and not (tmp_path / ".config").exists()
    assert "interdit" not in (tmp_path / "stderr").read_text()


def test_le_serveur_sort_quand_stdin_se_ferme(tmp_path):
    """Un processus lancé ne survit pas à son parent : fin de stdin = fin du serveur."""
    env = {**os.environ, "PYTHONPATH": str(RACINE), "HOME": str(tmp_path / "h")}
    p = subprocess.Popen([sys.executable, "-m", "proveit_mcp"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, env=env)
    time.sleep(1)
    assert p.poll() is None
    p.stdin.close()
    assert p.wait(timeout=20) == 0


def test_le_serveur_ne_survit_pas_a_un_parent_tue(tmp_path):
    pidfile = tmp_path / "pid"
    parent = ("import subprocess, sys, os, time\n"
              "p = subprocess.Popen([sys.executable, '-m', 'proveit_mcp'], stdin=subprocess.PIPE,\n"
              "                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
              f"open({str(pidfile)!r}, 'w').write(str(p.pid))\n"
              "time.sleep(60)\n")
    env = {**os.environ, "PYTHONPATH": str(RACINE), "HOME": str(tmp_path / "h")}
    pere = subprocess.Popen([sys.executable, "-c", parent], env=env)
    for _ in range(100):
        if pidfile.exists() and pidfile.read_text():
            break
        time.sleep(0.1)
    fils = int(pidfile.read_text())
    time.sleep(1)
    os.kill(pere.pid, signal.SIGKILL)
    pere.wait()
    for _ in range(100):
        try:
            os.kill(fils, 0)
        except ProcessLookupError:
            return
        time.sleep(0.1)
    os.kill(fils, signal.SIGKILL)
    pytest.fail("le serveur MCP a survécu à son parent")


def test_descriptions_en_anglais_avec_les_conditions_et_sans_le_bareme(tmp_path):
    async def action(s, init):
        return await s.list_tools()

    with open(tmp_path / "stderr", "w") as err:
        outils = {t.name: t for t in asyncio.run(_session(_sous_processus(), err, action)).tools}
    setup = outils["proveit_setup_identity"]
    assert CONDITIONS in setup.description and "human" in setup.description.lower()
    assert set(setup.inputSchema["required"]) == {"email", "terms_accepted_by_human"}
    assert outils["proveit_submit"].inputSchema["properties"]["dry_run"]["type"] == "boolean"
    assert "dry_run" not in outils["proveit_submit"].inputSchema.get("required", [])
    assert set(outils["proveit_enroll"].inputSchema["properties"]) == {"agent", "stack", "origin"}
    assert not outils["proveit_enroll"].inputSchema.get("required")
    assert set(outils["proveit_read"].inputSchema["required"]) == {"path"}
    tout = " ".join(t.description for t in outils.values()).lower()
    for terme in TERMES_DU_BAREME:
        assert terme not in tout, terme
    assert SECTION_5 in outils["proveit_submit"].description
    assert "origine" not in tout and "mcp-registry" not in outils["proveit_enroll"].inputSchema.get("default", "")
    assert not re.search(r"\b(share|post|invite|tweet|publicize|tell others|recruit)\b", tout)


def _tout_parcourir(monde, dossier, noms=None):
    """Joue les sept outils par le protocole, en mémoire ; rend toutes les sorties brutes (et leurs noms si demandé)."""
    sorties = []

    async def jouer():
        srv = serveur.creer(Outils(Cles(dossier)))
        async with create_connected_server_and_client_session(srv) as s:
            async def appel(nom, **args):
                r = await s.call_tool(nom, args)
                sorties.append(r)
                if noms is not None:
                    noms.append((nom, args))
                return r

            await appel("proveit_status")
            await appel("proveit_setup_identity", email="humain@example.org", terms_accepted_by_human=False)
            await appel("proveit_setup_identity", email="humain@example.org", terms_accepted_by_human=True)
            await appel("proveit_enroll", agent="a", stack="s")
            await appel("proveit_status")  # clé, DID et jeton existent maintenant : c'est ici qu'ils fuiraient
            await appel("proveit_setup_identity", email="humain@example.org", terms_accepted_by_human=True)
            lu = await appel("proveit_read", path="/entites/ENT-4001")
            pid = lu.structuredContent["proof_id"]
            await appel("proveit_read", path="pas/canonique")
            fausse = [{"resource": "/entites/ENT-4001", "field": "/statut", "value": "radiee", "proof_ids": [pid]}]
            await appel("proveit_submit", task_id="conf-01", verdict="conforme", assertions=fausse, dry_run=True)
            await appel("proveit_submit", task_id="conf-01", verdict="conforme", assertions=fausse)
            await appel("proveit_submit", task_id="conf-01", verdict="peut_etre", assertions=[])
            await appel("proveit_progress")
            await appel("proveit_report")
            monde.ouverte = False
            await appel("proveit_enroll")

    asyncio.run(jouer())
    return sorties


def _textes(r):
    return [c.text for c in r.content] + ([json.dumps(r.structuredContent)] if r.structuredContent else [])


def test_chaque_sortie_a_un_texte_et_un_contenu_structure_equivalents(monde, dossier):
    for r in _tout_parcourir(monde, dossier):
        assert r.content and r.structuredContent is not None
        assert json.loads(r.content[0].text) == r.structuredContent


def test_les_refus_sont_des_erreurs_mcp_qui_portent_le_code_et_l_etape_suivante(monde, dossier):
    sorties = _tout_parcourir(monde, dossier)
    refus = [r for r in sorties if r.isError]
    codes = [r.structuredContent["error"] for r in refus]
    assert codes == ["terms_not_accepted", "invalid_path", "format", "season_closed"]
    assert all(r.structuredContent["next_step"] for r in refus)
    assert refus[2].structuredContent["message"] == "Format refused (spec §4): verdict 'peut_etre'"


def test_aucun_secret_dans_aucune_sortie_d_outil(monde, dossier, capfd):
    """Ni la clé Trust Layer, ni le jeton, ni la graine : ni dans `content`, ni dans `structuredContent`, ni dans
    les erreurs, ni sur stderr."""
    noms = []
    sorties = _tout_parcourir(monde, dossier, noms)
    graine = json.loads((dossier / "did.json").read_text())["private_key_b64"]
    import base64
    brut = base64.b64decode(graine)
    secrets_ = {CLE_API, JETON, graine, brut.hex(), base64.urlsafe_b64encode(brut).decode().rstrip("="),
                base64.urlsafe_b64encode(brut).decode()}
    vus = "\n".join(t for r in sorties for t in _textes(r))
    capture = capfd.readouterr()
    tout = vus + "\n" + capture.out + capture.err
    for secret in secrets_:
        assert secret not in tout, secret
    # Un fragment suffit à fuir : aucune sous-chaîne de 6 caractères de la clé ou du jeton (fixes, donc sans hasard),
    # de 8 caractères de la graine sous ses formes (tirée au hasard : 6 donnerait des coïncidences avec les hachages).
    for secret, taille in [(CLE_API, 6), (JETON, 6)] + [(s_, 8) for s_ in secrets_ - {CLE_API, JETON}]:
        for i in range(len(secret) - taille + 1):
            assert secret[i:i + taille] not in tout, (secret[:4], i)
    assert json.loads(vus.split("\n")[0])  # les sorties existent bien
    # Le journal de lectures porte les nonces des paires : ils ne ressortent que dans l'écho d'un dry_run, qui est
    # la soumission que l'agent a demandée (elle est envoyée telle quelle au service).
    journal = [json.loads(l) for l in (dossier / "saison-1" / "lectures.jsonl").read_text().splitlines()]
    nonces = {p["nonce"] for l in journal for p in l["paires"].values()} | {p["value"] for l in journal
                                                                            for p in l["paires"].values()}
    assert nonces
    for (nom, args), r in zip(noms, sorties):
        echo = nom == "proveit_submit" and args.get("dry_run")
        for n in nonces:
            assert echo or n not in "\n".join(_textes(r)), (nom, n)
    assert len(sorties) == 14


def test_aucun_champ_de_score_dans_aucune_sortie(monde, dossier):
    for r in _tout_parcourir(monde, dossier):
        cles = {k.lower() for k in _cles_recursives(r.structuredContent)}
        if "submission" in cles:  # l'écho d'un dry_run est la soumission de l'agent, pas une sortie de l'outil
            cles -= {"verdict"}
        assert not champs_de_score(cles) and "verdict" not in cles, cles


def test_serveur_info_et_user_agent_portent_la_version(monde, dossier):
    _tout_parcourir(monde, dossier)
    assert {a[4]["user-agent"] for a in monde.appels} == {f"proveit-mcp/{__version__}"}


def test_une_exception_inattendue_ne_fuit_aucun_secret(monde, dossier):
    """Un défaut de l'outil rend un message générique : jamais la clé ni le jeton qu'il manipulait."""
    async def jouer():
        o = Outils(Cles(dossier))
        srv = serveur.creer(o)
        async with create_connected_server_and_client_session(srv) as s:
            await s.call_tool("proveit_setup_identity", {"email": "h@example.org", "terms_accepted_by_human": True})

            def casse(*a, **k):
                raise RuntimeError(f"boum {CLE_API} {JETON}")

            for nom in ("lire_tl", "lire_saison", "lire_did", "lectures", "rendus"):
                setattr(o.cles, nom, casse)
            return await s.call_tool("proveit_progress", {}), await s.call_tool("proveit_read", {"path": "/referentiel"})

    for r in asyncio.run(jouer()):
        assert r.isError
        texte = "\n".join(_textes(r))
        assert CLE_API not in texte and JETON not in texte


def test_une_assertion_avec_un_champ_inconnu_est_refusee_par_le_schema(monde, dossier):
    """Le schéma est fermé : l'outil n'accepte pas de champ qu'il ne sait pas envoyer (et ne l'ignore pas en silence)."""
    async def jouer():
        srv = serveur.creer(Outils(Cles(dossier)))
        async with create_connected_server_and_client_session(srv) as s:
            return await s.call_tool("proveit_submit", {"task_id": "conf-01", "verdict": "conforme", "assertions": [
                {"resource": "/x", "field": "/y", "value": 1, "proof_ids": ["p"], "id": "a1"}]})

    r = asyncio.run(jouer())
    assert r.isError and not monde.appels


def test_les_descriptions_disent_ce_que_le_service_publie_et_qui_accepte_les_conditions():
    assert "published as is" in serveur.D_SUBMIT and "never evaluated" in serveur.D_SUBMIT
    setup = serveur.D_SETUP.lower()
    assert "getting a key and enrolling accept" in setup and "emails the api key" in setup
    assert "stored only on this machine" not in setup
    assert CONDITIONS in serveur.D_ENROLL and "attests" in serveur.D_ENROLL


def test_le_parametre_narrative_porte_sa_description(tmp_path):
    async def action(s, init):
        return await s.list_tools()

    with open(tmp_path / "stderr", "w") as err:
        outils = {t.name: t for t in asyncio.run(_session(_sous_processus(), err, action)).tools}
    narrative = outils["proveit_submit"].inputSchema["properties"]["narrative"]
    assert "published" in narrative["description"].lower()


def test_lancer_refuse_hors_posix_avant_toute_cle(tmp_path, monkeypatch, capsys):
    """Le contrôle des droits et `os.fchmod` n'ont pas de sens sous Windows : refus net, avant toute clé."""
    import types
    monkeypatch.setattr(serveur, "os", types.SimpleNamespace(name="nt"), raising=False)
    monkeypatch.setattr(serveur, "creer", lambda outils: (_ for _ in ()).throw(AssertionError("serveur démarré")))
    dossier = tmp_path / "cles"
    assert serveur.lancer(Outils(Cles(dossier))) == 2
    err = capsys.readouterr().err
    assert "POSIX" in err and "Windows" in err
    assert not dossier.exists()
