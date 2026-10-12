"""Monde factice des tests du paquet : Trust Layer, service de saison et corpus en mémoire, branchés sur
`urllib.request.urlopen`. Le vrai transport du paquet tourne donc, de la requête HTTP jusqu'à l'octet.

Ces tests n'importent rien de prove-it : ils sont exportés tels quels vers le miroir public.
"""

import base64
import hashlib
import io
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

TL, SAISON, CORPUS = "trust.arkforge.tech", "proveit.arkforge.tech", "corpus.arkforge.tech"
CLE_API = "tlk_SECRET_0123456789abcdef0123456789abcdef"
JETON = "jeton_SECRET_9876543210fedcba9876543210fedcba"
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
NARRATIVE = {"publie": True, "score": False,
             "message": "Published as is next to the result, never read by the scorer or by a language model (spec §4)."}
TACHES = [{"id": f"conf-{n:02d}", "question": f"Question {n}"} for n in range(1, 11)]


def _pub_du_did(did):
    n = 0
    for c in did[len("did:key:z"):]:
        n = n * 58 + _B58.index(c)
    brut = n.to_bytes((n.bit_length() + 7) // 8, "big")
    assert brut[:2] == b"\xed\x01"
    return brut[2:]


class Reponse:
    def __init__(self, statut, corps):
        self.status, self._corps = statut, corps

    def read(self):
        return self._corps

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class Monde:
    def __init__(self):
        self.appels = []  # (methode, hote, chemin, corps JSON ou None, en-têtes)
        self.ouverte, self.lie_a, self.email_pris = True, None, False
        self.hors_service = set()  # hôtes qui ne répondent pas du tout
        self.etat_illisible = False
        self.refus_proxy = None  # (statut, code) rendu par le proxy
        self.refus_full = None  # (statut, code) rendu par /v1/proof/<id>/full
        self.refus_enroll = None  # (statut, code) rendu par POST /enroll
        self.did_inscrit = None  # DID que le service dit avoir inscrit, s'il diffère de celui de la clé
        self.corpus = {"/referentiel": {"regles": ["R1", "R2"]},
                       "/entites/ENT-4001": {"existe": True, "statut": "active"},
                       "/agrements/AGR-4001": {"existe": True, "statut": "actif"}}
        self.soumissions, self.challenges, self.n_preuves, self.preuves = [], {}, 0, set()
        self.inscriptions = []

    # --- Outils d'assertion --------------------------------------------------------------------
    def posts(self, chemin_fin):
        return [a for a in self.appels if a[0] == "POST" and a[2].endswith(chemin_fin)]

    def hotes(self):
        return {a[1] for a in self.appels}

    # --- Branchement ---------------------------------------------------------------------------
    def urlopen(self, req, timeout=None, **kw):
        u = urlsplit(req.full_url)
        corps = json.loads(req.data) if req.data else None
        en_tetes = {k.lower(): v for k, v in req.header_items()}
        self.appels.append((req.get_method(), u.netloc, u.path, corps, en_tetes))
        if u.netloc in self.hors_service:
            raise urllib.error.URLError("connection refused")
        statut, rep = self._router(req.get_method(), u.netloc, u.path, corps, en_tetes)
        octets = rep if isinstance(rep, bytes) else json.dumps(rep).encode()
        if statut >= 400:
            raise urllib.error.HTTPError(req.full_url, statut, "err", {}, io.BytesIO(octets))
        return Reponse(statut, octets)

    def _router(self, methode, hote, chemin, corps, h):
        if hote == TL:
            return self._tl(methode, chemin, corps, h)
        if hote == SAISON:
            return self._saison(methode, chemin, corps, h)
        return 404, {"erreur": "hote_inattendu"}

    @staticmethod
    def _erreur(statut, code, message):
        return statut, {"error": {"code": code, "message": message, "status": statut}}

    def _tl(self, methode, chemin, corps, h):
        if chemin == "/v1/keys/free-signup":
            if self.email_pris:
                return self._erreur(409, "already_exists", "A free API key already exists for this email.")
            return 200, {"api_key": CLE_API, "plan": "free", "email": corps["email"], "limit": "500 proofs/month"}
        if h.get("x-api-key") != CLE_API:
            return self._erreur(401, "invalid_api_key", "Invalid or inactive API key")
        if chemin == "/v1/keys/identity":
            return 200, {"verified_did": self.lie_a, "verified_did_history": [],
                         "verified_did_method": "challenge_response" if self.lie_a else None}
        if chemin == "/v1/keys/bind-did":
            self.challenges["c" * 64] = corps["did"]
            return 200, {"challenge": "c" * 64, "expires_in": 300}
        if chemin == "/v1/keys/bind-did/confirm":
            did = self.challenges.pop(corps["challenge"])
            assert "=" not in corps["signature"], "signature base64url sans padding"
            signature = base64.urlsafe_b64decode(corps["signature"] + "=" * (-len(corps["signature"]) % 4))
            Ed25519PublicKey.from_public_bytes(_pub_du_did(did)).verify(signature, corps["challenge"].encode())
            self.lie_a = did
            return 200, {"verified_did": did, "method": "challenge_response"}
        if chemin == "/v1/proxy":
            if self.refus_proxy:
                return self._erreur(self.refus_proxy[0], self.refus_proxy[1], "Refused by the proxy.")
            cible = urlsplit(corps["target"])
            self.n_preuves += 1
            pid = f"prf_{self.n_preuves:04d}"
            self.preuves.add(pid)
            return 200, {"proof": {"proof_id": pid},
                         "service_response": {"status_code": 200,
                                              "body": self.corpus.get(cible.path, {"existe": False})}}
        if chemin.startswith("/v1/proof/") and chemin.endswith("/full"):
            pid = chemin.split("/")[3]
            if self.refus_full:
                return self._erreur(self.refus_full[0], self.refus_full[1], "Refused by /full.")
            if pid not in self.preuves:  # une preuve qui n'est pas à cette clé : le vrai Trust Layer ne la rend pas
                return self._erreur(404, "proof_not_found", pid)
            h2 = lambda s: hashlib.sha256((pid + s).encode()).hexdigest()  # noqa: E731
            return 200, {"commitment_nonces": {"request_hash": h2("n1"), "response_hash": h2("n2")},
                         "chain_data": {"request_hash": h2("v1"), "response_hash": h2("v2")}}
        return self._erreur(404, "not_found", chemin)

    def _saison(self, methode, chemin, corps, h):
        if chemin == "/v1/season/1":
            if self.etat_illisible:
                return 200, b"<html>maintenance</html>"
            return 200, {"saison": 1, "piste": "conformite", "ouverte": self.ouverte,
                         "ouverture": "2026-10-06T08:00:00+00:00", "cloture": "2026-11-03T20:00:00+00:00"}
        if chemin == "/v1/season/1/enroll":
            if not self.ouverte:
                return 403, {"erreur": "saison_fermee", "message": "Season 1 is closed."}
            if h.get("x-api-key") != CLE_API:
                return 401, {"erreur": "cle_invalide", "message": "Trust Layer key invalid or inactive."}
            if self.lie_a is None:
                return 403, {"erreur": "did_non_lie", "message": "No DID bound to this key."}
            if self.refus_enroll:
                return self.refus_enroll[0], {"erreur": self.refus_enroll[1], "message": "Refused by the season service."}
            self.inscriptions.append(corps)
            return 201, {"inscription": "i-0001", "participant": "i-0001", "classe": True, "did": self.did_inscrit or self.lie_a,
                         "agent": (corps or {}).get("agent"), "stack": (corps or {}).get("stack"),
                         "origine": (corps or {}).get("origine"), "jeton": JETON, "taches": TACHES,
                         "message": "Enrollment recorded. Keep the token: it is not stored and is needed to submit."}
        if chemin == "/v1/season/1/submit":
            if not self.ouverte:
                return 403, {"erreur": "saison_fermee", "message": "Season 1 is closed."}
            if h.get("authorization") != f"Bearer {JETON}":
                return 401, {"erreur": "jeton_invalide", "message": "Season token unknown or renewed."}
            if corps.get("verdict") not in ("conforme", "non_conforme", "indeterminable"):
                return 422, {"erreur": "format", "message": f"Format refused (spec §4): verdict {corps.get('verdict')!r}"}
            remplace = any(s["task_id"] == corps["task_id"] for s in self.soumissions)
            self.soumissions.append(corps)
            return 202, {"task_id": corps["task_id"], "recue_le": "2026-10-12T10:00:00+00:00", "remplace": remplace,
                         "narrative": NARRATIVE,
                         "message": "Submission recorded. The last one for a task counts; no score before the close."}
        if "/resultats/" in chemin:
            return 404, b"<html>404 Not Found</html>"
        return 404, {"erreur": "introuvable", "message": "Routes"}


# Les noms de clés d'une sortie d'outil ne disent rien du barème : une regex sur les racines, pas une liste de mots
# entiers (`ranked` passait quand seuls `rank` et `ranking` étaient listés).
MOTIF_DE_SCORE = re.compile(r"score|rank|rate|overclaim|reussite|success|accuracy|exactitude|taux|points|correct|"
                            r"supported", re.I)


def champs_de_score(cles):
    return {k for k in cles if MOTIF_DE_SCORE.search(k)}


def cles_recursives(x):
    """Toutes les clés imbriquées. Sous `narrative`, on ne descend pas : c'est l'avertissement du service
    (`score: false`), pas un champ de score de l'outil."""
    if isinstance(x, dict):
        for k, v in x.items():
            yield k
            if k != "narrative":
                yield from cles_recursives(v)
    elif isinstance(x, list):
        for v in x:
            yield from cles_recursives(v)
