"""Clés locales du participant : un fichier par secret, dossier en 0700, fichiers en 0600.

    did.json                  {"did", "private_key_b64"}   clé Ed25519 du did:key (la graine, 32 octets)
    trust_layer.json          {"api_key", "plan"}          clé Trust Layer (l'email n'est jamais stocké)
    saison-1.json             {"jeton", "inscription", "participant", "classe", "taches"}
    saison-1/lectures.jsonl   {"proof_id", "path", "paires", "lu_le"} par lecture
    saison-1/rendus.jsonl     {"task_id", "recu_le"} par rendu accepté

Chaque fichier est créé en 0600 AVANT d'y écrire, et remplacé atomiquement (fichier voisin puis `os.replace`) : une
interruption laisse l'ancien contenu, jamais un fichier tronqué. Aucun message d'erreur ne reprend le contenu d'un
fichier. Le seul accès à l'environnement du paquet est ici : où est le dossier (jamais une URL).
"""

import base64
import json
import os
import stat
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proveit_mcp.client import cle_publique, did_key

DID, TRUST_LAYER, SAISON = "did.json", "trust_layer.json", "saison-1.json"
SOUS_DOSSIER = "saison-1"
LECTURES, RENDUS = "lectures.jsonl", "rendus.jsonl"
CHAMPS_SAISON = ("jeton", "inscription", "participant", "classe", "taches")


class ErreurCles(RuntimeError):
    pass


def dossier_par_defaut(env=None):
    """`$PROVEIT_MCP_HOME`, sinon `$XDG_CONFIG_HOME/proveit-mcp`, sinon `~/.config/proveit-mcp`."""
    env = os.environ if env is None else env
    if env.get("PROVEIT_MCP_HOME"):
        return Path(env["PROVEIT_MCP_HOME"])
    if env.get("XDG_CONFIG_HOME"):
        return Path(env["XDG_CONFIG_HOME"]) / "proveit-mcp"
    return Path(env.get("HOME") or Path.home()) / ".config" / "proveit-mcp"


def _erreur_disque(chemin, exc):
    """Le disque local, dit sans le contenu du fichier ni le texte de l'exception."""
    return ErreurCles(f"{chemin} could not be written ({os.strerror(exc.errno) if exc.errno else 'I/O error'}).")


def _mode(chemin):
    return stat.S_IMODE(os.lstat(chemin).st_mode)


class Cles:
    def __init__(self, racine):
        self.racine = Path(racine)

    # --- Permissions ---------------------------------------------------------------------------

    def verifier(self):
        """Refuse un dossier ou un fichier lisible par le groupe ou les autres, et un `did.json` incohérent.
        Un dossier absent n'est pas une erreur : rien n'est encore créé."""
        if not self.racine.exists():
            return
        for chemin in [self.racine, *sorted(self.racine.rglob("*"))]:
            if chemin.is_symlink():
                raise ErreurCles(f"{chemin} is a symbolic link: replace it with a real file.")
            if _mode(chemin) & 0o077:
                voulu = "700" if chemin.is_dir() else "600"
                raise ErreurCles(f"{chemin} is readable by other users (mode {_mode(chemin):o}). "
                                 f"Run: chmod {voulu} {chemin}")
        if (self.racine / DID).exists():
            self.lire_did()

    def _exiger_dossier(self, dossier):
        if dossier.exists():
            if _mode(dossier) & 0o077:
                raise ErreurCles(f"{dossier} is readable by other users (mode {_mode(dossier):o}). "
                                 f"Run: chmod 700 {dossier}")
        else:
            dossier.mkdir(parents=True, mode=0o700)
            os.chmod(dossier, 0o700)  # l'umask ne doit rien ouvrir

    # --- Lecture -------------------------------------------------------------------------------

    def _lire(self, nom):
        chemin = self.racine / nom
        if not chemin.exists():
            return None
        try:
            return json.loads(chemin.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            raise ErreurCles(f"{chemin} is not readable JSON.") from None

    def lire_did(self):
        """(clé privée, did) ou `None`. Refuse un fichier dont la clé ne donne pas le DID qu'il déclare."""
        d = self._lire(DID)
        if d is None:
            return None
        try:
            cle = Ed25519PrivateKey.from_private_bytes(base64.b64decode(d["private_key_b64"], validate=True))
            did = d["did"]
        except (KeyError, TypeError, ValueError):
            raise ErreurCles(f"{self.racine / DID} is unreadable: expected "
                             '{"did": ..., "private_key_b64": <32-byte seed>}.') from None
        if did_key(cle_publique(cle)) != did:
            raise ErreurCles(f"{self.racine / DID} is inconsistent: its private key does not give the DID it declares.")
        return cle, did

    def lire_tl(self):
        d = self._lire(TRUST_LAYER)
        if d is None:
            return None
        if not isinstance(d, dict) or not isinstance(d.get("api_key"), str) or not d["api_key"]:
            raise ErreurCles(f'{self.racine / TRUST_LAYER} is unreadable: expected {{"api_key": ..., "plan": "free"}}.')
        return d

    def lire_saison(self):
        d = self._lire(SAISON)
        if d is not None and not isinstance(d, dict):
            raise ErreurCles(f"{self.racine / SAISON} is unreadable.")
        return d

    def _lignes(self, nom):
        chemin = self.racine / SOUS_DOSSIER / nom
        if not chemin.exists():
            return []
        try:
            return [json.loads(l) for l in chemin.read_text(encoding="utf-8").splitlines() if l.strip()]
        except (ValueError, OSError):
            raise ErreurCles(f"{chemin} is not readable JSON lines.") from None

    def lectures(self):
        return self._lignes(LECTURES)

    def rendus(self):
        return self._lignes(RENDUS)

    # --- Écriture ------------------------------------------------------------------------------

    def _ecrire(self, chemin, objet):
        """0600 avant le contenu, fichier voisin puis `os.replace` : jamais un fichier tronqué, jamais ouvert."""
        try:
            self._exiger_dossier(self.racine)
            self._exiger_dossier(chemin.parent)
            fd, tmp = tempfile.mkstemp(dir=chemin.parent, prefix=f".{chemin.name}.")
            try:
                try:
                    os.fchmod(fd, 0o600)
                    reste = memoryview(json.dumps(objet, indent=2).encode("utf-8"))
                    while reste:
                        reste = reste[os.write(fd, reste):]
                    os.fsync(fd)
                finally:
                    os.close(fd)
                os.replace(tmp, chemin)
            except BaseException:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise
        except OSError as exc:
            raise _erreur_disque(chemin, exc) from None

    def _ajouter(self, nom, ligne):
        dossier = self.racine / SOUS_DOSSIER
        try:
            self._exiger_dossier(self.racine)
            self._exiger_dossier(dossier)
            fd = os.open(dossier / nom, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.fchmod(fd, 0o600)
                os.write(fd, (json.dumps(ligne) + "\n").encode("utf-8"))
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError as exc:
            raise _erreur_disque(dossier / nom, exc) from None

    def ecrire_did(self, cle):
        did = did_key(cle_publique(cle))
        self._ecrire(self.racine / DID, {"did": did, "private_key_b64": base64.b64encode(cle.private_bytes_raw()).decode()})
        return did

    def ecrire_tl(self, api_key, plan="free"):
        self._ecrire(self.racine / TRUST_LAYER, {"api_key": api_key, "plan": plan})

    def ecrire_saison(self, inscription):
        self._ecrire(self.racine / SAISON, {c: inscription.get(c) for c in CHAMPS_SAISON})

    def ajouter_lecture(self, ligne):
        self._ajouter(LECTURES, ligne)

    def ajouter_rendu(self, ligne):
        self._ajouter(RENDUS, ligne)
