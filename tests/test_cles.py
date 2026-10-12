"""Clés locales : un fichier par secret, 0600 créé avant écriture, dossier 0700."""

import base64
import json
import os
import stat
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proveit_mcp import cles as modcles
from proveit_mcp.cles import Cles, ErreurCles
from proveit_mcp.client import did_key

from monde import CLE_API, JETON


def _mode(chemin):
    return stat.S_IMODE(os.stat(chemin).st_mode)


def _ecrire_tout(c):
    c.ecrire_did(Ed25519PrivateKey.generate())
    c.ecrire_tl(CLE_API, "free")
    c.ecrire_saison({"jeton": JETON, "inscription": "i-1", "participant": "i-1", "classe": True, "taches": []})
    c.ajouter_lecture({"proof_id": "prf_1", "path": "/x", "paires": {}, "lu_le": "2026-10-12T10:00:00+00:00"})
    c.ajouter_rendu({"task_id": "conf-01", "recu_le": "2026-10-12T10:00:00+00:00"})


FICHIERS = ["did.json", "trust_layer.json", "saison-1.json", "saison-1/lectures.jsonl", "saison-1/rendus.jsonl"]


def test_dossier_cree_en_0700_fichiers_en_0600_avant_ecriture(dossier, monkeypatch):
    ancien = os.umask(0)  # un umask permissif ne doit rien changer
    try:
        modes = []
        vrai_write = os.write

        def write_espion(fd, data):
            if stat.S_ISREG(os.fstat(fd).st_mode):
                modes.append((os.fstat(fd).st_ino, _mode_fd(fd)))
            return vrai_write(fd, data)

        monkeypatch.setattr(modcles.os, "write", write_espion)
        c = Cles(dossier)
        _ecrire_tout(c)
    finally:
        os.umask(ancien)
    assert _mode(dossier) == 0o700 and _mode(dossier / "saison-1") == 0o700
    for f in FICHIERS:
        assert _mode(dossier / f) == 0o600, f
    inodes = {os.stat(dossier / f).st_ino for f in FICHIERS}
    ecrits = [(i, m) for i, m in modes if i in inodes]
    assert len(ecrits) >= len(FICHIERS)
    assert all(m == 0o600 for _, m in ecrits), "un fichier de secret a existé avec d'autres droits avant son contenu"
    c.verifier()


def _mode_fd(fd):
    return stat.S_IMODE(os.fstat(fd).st_mode)


def test_aucun_fichier_temporaire_ne_reste(dossier):
    c = Cles(dossier)
    _ecrire_tout(c)
    assert sorted(p.name for p in dossier.iterdir()) == ["did.json", "saison-1", "saison-1.json", "trust_layer.json"]


@pytest.mark.parametrize("chemin", ["", "did.json", "trust_layer.json", "saison-1.json", "saison-1",
                                    "saison-1/lectures.jsonl", "saison-1/rendus.jsonl"])
@pytest.mark.parametrize("mode", [0o644, 0o640, 0o660, 0o755])
def test_refus_au_demarrage_si_permissions_trop_ouvertes(dossier, chemin, mode):
    c = Cles(dossier)
    _ecrire_tout(c)
    cible = dossier / chemin if chemin else dossier
    cible.chmod(mode if cible.is_file() else mode | 0o700)
    with pytest.raises(ErreurCles) as e:
        c.verifier()
    assert "chmod" in str(e.value) and str(cible) in str(e.value)


def test_refus_nomme_le_chmod_a_jouer(dossier):
    c = Cles(dossier)
    c.ecrire_tl(CLE_API)
    (dossier / "trust_layer.json").chmod(0o644)
    with pytest.raises(ErreurCles, match=r"chmod 600 .*trust_layer\.json"):
        c.verifier()


def test_dossier_absent_n_est_pas_une_erreur_et_n_est_pas_cree(dossier):
    c = Cles(dossier)
    c.verifier()
    assert c.lire_did() is None and c.lire_tl() is None and c.lire_saison() is None
    assert c.lectures() == [] and c.rendus() == []
    assert not dossier.exists()


def test_did_json_incoherent_refuse(dossier):
    c = Cles(dossier)
    c.ecrire_did(Ed25519PrivateKey.generate())
    autre = did_key(Ed25519PrivateKey.generate().public_key().public_bytes_raw())
    d = json.loads((dossier / "did.json").read_text())
    d["did"] = autre
    (dossier / "did.json").write_text(json.dumps(d))
    with pytest.raises(ErreurCles, match="did.json"):
        c.verifier()
    with pytest.raises(ErreurCles, match="did.json"):
        c.lire_did()


@pytest.mark.parametrize("contenu", ["", "pas du json", "[]", '{"did": "x"}',
                                     '{"did": "x", "private_key_b64": "!!!"}',
                                     '{"did": "x", "private_key_b64": "AAAA"}'])
def test_did_json_illisible_refuse(dossier, contenu):
    c = Cles(dossier)
    c.ecrire_tl(CLE_API)  # crée le dossier en 0700
    (dossier / "did.json").write_text(contenu)
    (dossier / "did.json").chmod(0o600)
    with pytest.raises(ErreurCles):
        c.lire_did()


def test_import_de_cles_existantes_au_meme_format(dossier):
    """Le participant dépose `did.json` et `trust_layer.json` : ils sont repris sans rien régénérer."""
    cle = Ed25519PrivateKey.generate()
    did = did_key(cle.public_key().public_bytes_raw())
    dossier.mkdir(mode=0o700)
    for nom, objet in (("did.json", {"did": did, "private_key_b64": base64.b64encode(cle.private_bytes_raw()).decode()}),
                       ("trust_layer.json", {"api_key": CLE_API, "plan": "free"})):
        (dossier / nom).touch(mode=0o600)
        (dossier / nom).write_text(json.dumps(objet))
    c = Cles(dossier)
    c.verifier()
    cle_lue, did_lu = c.lire_did()
    assert did_lu == did and cle_lue.private_bytes_raw() == cle.private_bytes_raw()
    assert c.lire_tl() == {"api_key": CLE_API, "plan": "free"}


def test_format_des_fichiers_ecrits(dossier):
    c = Cles(dossier)
    cle = Ed25519PrivateKey.generate()
    did = c.ecrire_did(cle)
    c.ecrire_tl(CLE_API)
    c.ecrire_saison({"jeton": JETON, "inscription": "i", "participant": "p", "classe": True, "taches": [1]})
    assert json.loads((dossier / "did.json").read_text()) == {
        "did": did, "private_key_b64": base64.b64encode(cle.private_bytes_raw()).decode()}
    assert json.loads((dossier / "trust_layer.json").read_text()) == {"api_key": CLE_API, "plan": "free"}
    assert set(json.loads((dossier / "saison-1.json").read_text())) == {
        "jeton", "inscription", "participant", "classe", "taches"}


def test_ecriture_atomique_pas_de_fichier_tronque(dossier, monkeypatch):
    """Interruption entre l'écriture et le `replace` : l'ancien contenu reste intact, jamais un fichier tronqué."""
    c = Cles(dossier)
    c.ecrire_tl("ancienne-cle")

    def coupe(src, dst):
        raise KeyboardInterrupt

    monkeypatch.setattr(modcles.os, "replace", coupe)
    with pytest.raises(KeyboardInterrupt):
        c.ecrire_tl(CLE_API)
    monkeypatch.undo()
    assert json.loads((dossier / "trust_layer.json").read_text())["api_key"] == "ancienne-cle"
    assert _mode(dossier / "trust_layer.json") == 0o600


def test_ecriture_interrompue_ne_laisse_pas_un_secret_lisible(dossier, monkeypatch):
    c = Cles(dossier)
    c.ecrire_tl("ancienne-cle")
    monkeypatch.setattr(modcles.os, "replace", lambda s, d: (_ for _ in ()).throw(KeyboardInterrupt))
    with pytest.raises(KeyboardInterrupt):
        c.ecrire_tl(CLE_API)
    monkeypatch.undo()
    for p in dossier.iterdir():
        assert _mode(p) & 0o077 == 0, p


def test_journal_de_lectures_en_ajout(dossier):
    c = Cles(dossier)
    c.ajouter_lecture({"proof_id": "a", "path": "/x", "paires": {}, "lu_le": "t1"})
    c.ajouter_lecture({"proof_id": "b", "path": "/y", "paires": {}, "lu_le": "t2"})
    assert [l["proof_id"] for l in c.lectures()] == ["a", "b"]
    assert (dossier / "saison-1" / "lectures.jsonl").read_text().count("\n") == 2


def test_dossier_choisi_par_proveit_mcp_home_puis_xdg_puis_home(tmp_path):
    env = {"PROVEIT_MCP_HOME": str(tmp_path / "a"), "XDG_CONFIG_HOME": str(tmp_path / "x"), "HOME": str(tmp_path / "h")}
    assert modcles.dossier_par_defaut(env) == tmp_path / "a"
    del env["PROVEIT_MCP_HOME"]
    assert modcles.dossier_par_defaut(env) == tmp_path / "x" / "proveit-mcp"
    del env["XDG_CONFIG_HOME"]
    assert modcles.dossier_par_defaut(env) == tmp_path / "h" / ".config" / "proveit-mcp"


def test_demarrage_refuse_sur_permissions_ouvertes_et_ne_parle_pas_sur_stdout(dossier, tmp_path):
    c = Cles(dossier)
    c.ecrire_tl(CLE_API)
    dossier.chmod(0o755)
    env = {**os.environ, "PROVEIT_MCP_HOME": str(dossier), "PYTHONPATH": os.path.dirname(os.path.dirname(modcles.__file__))}
    r = subprocess.run([sys.executable, "-m", "proveit_mcp"], env=env, capture_output=True, text=True,
                       stdin=subprocess.DEVNULL, timeout=60)
    assert r.returncode == 2 and r.stdout == ""
    assert "chmod 700" in r.stderr and CLE_API not in r.stderr


@pytest.mark.parametrize("nom", ["did.json", "trust_layer.json", "saison-1.json"])
def test_les_erreurs_ne_reprennent_jamais_le_contenu_d_un_fichier(dossier, nom):
    """Un message d'erreur est écrit dans un contexte de modèle : il ne cite jamais ce que le fichier contient."""
    c = Cles(dossier)
    c.ecrire_tl(CLE_API)
    secret = "SECRET-" + CLE_API
    for contenu in (secret, json.dumps({"api_key": secret, "did": secret, "private_key_b64": secret, "jeton": [secret]})):
        (dossier / nom).write_text(contenu)
        (dossier / nom).chmod(0o600)
        for lire in (c.lire_did, c.lire_tl, c.lire_saison, c.verifier):
            try:
                lire()
            except ErreurCles as e:
                assert secret not in str(e) and CLE_API not in str(e)


def test_un_lien_symbolique_dans_le_dossier_est_refuse(dossier, tmp_path):
    c = Cles(dossier)
    c.ecrire_tl(CLE_API)
    ailleurs = tmp_path / "ailleurs.json"
    ailleurs.write_text("{}")
    ailleurs.chmod(0o600)
    (dossier / "did.json").symlink_to(ailleurs)
    with pytest.raises(ErreurCles, match="symbolic link"):
        c.verifier()


def test_les_fichiers_temporaires_sont_dans_le_dossier_des_cles(dossier, monkeypatch, tmp_path):
    """Le fichier voisin d'un secret ne passe jamais par le `/tmp` du système, lisible de tous les processus."""
    appels = []
    vrai = modcles.tempfile.mkstemp

    def espion(*a, **k):
        appels.append(k.get("dir"))
        return vrai(*a, **k)

    monkeypatch.setattr(modcles.tempfile, "mkstemp", espion)
    monkeypatch.setenv("TMPDIR", str(tmp_path / "inexistant"))
    _ecrire_tout(Cles(dossier))
    assert len(appels) == 3 and all(d is not None and str(d).startswith(str(dossier)) for d in appels), appels


def test_une_erreur_disque_pendant_l_ecriture_est_une_erreur_de_cles_sans_secret(dossier, monkeypatch):
    def plein(fd, data):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(modcles.os, "write", plein)
    with pytest.raises(ErreurCles) as e:
        Cles(dossier).ecrire_tl(CLE_API)
    assert CLE_API not in str(e.value)
    assert not [f for f in dossier.iterdir()], "aucun fichier temporaire ne reste"


def test_une_erreur_disque_pendant_un_ajout_est_une_erreur_de_cles(dossier, monkeypatch):
    def plein(fd, data):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(modcles.os, "write", plein)
    with pytest.raises(ErreurCles) as e:
        Cles(dossier).ajouter_rendu({"task_id": "conf-01", "recu_le": "x"})
    assert "conf-01" not in str(e.value)
