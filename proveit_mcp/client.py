"""Client du challenge PROVE IT : identité (did:key), liaison, inscription, lecture par le proxy, rendu.

Aucune URL n'est lue dans l'environnement : les bases sont des paramètres (une variable mal posée enverrait la clé
d'un participant à un tiers). Rien ici ne dépend du scorer, du corpus ni du service de saison.
"""

import base64
import json
import re
import urllib.error
import urllib.request
from typing import NamedTuple

from cryptography.hazmat.primitives import serialization

from proveit_mcp import SAISON as NUMERO
from proveit_mcp import __version__

UA = f"proveit-mcp/{__version__}"
TRUST_LAYER = "https://trust.arkforge.tech"
SAISON = "https://proveit.arkforge.tech"
CORPUS = "https://corpus.arkforge.tech"
CHAMPS_PAIRES = ("request_hash", "response_hash")
CHEMIN_CANONIQUE = re.compile(r"/[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*")

CH_SAISON = f"/v1/season/{NUMERO}"
CH_INSCRIPTION = CH_SAISON + "/enroll"
CH_RENDU = CH_SAISON + "/submit"
CH_CLE = "/v1/keys/free-signup"
CH_LIAISON = "/v1/keys/bind-did"
CH_CONFIRMATION = CH_LIAISON + "/confirm"
CH_IDENTITE = "/v1/keys/identity"
CH_PROXY = "/v1/proxy"
CH_RAPPORTS = f"/challenges/prove-it/saisons/{NUMERO}/resultats/"

# Les routes de `participer.json`, comparées à lui par test : elles ne sont retapées nulle part ailleurs.
ROUTES = {
    "cle": f"POST {TRUST_LAYER}{CH_CLE}",
    "liaison_did": f"POST {TRUST_LAYER}{CH_LIAISON}",
    "liaison_did_confirmation": f"POST {TRUST_LAYER}{CH_CONFIRMATION}",
    "inscription": f"POST {SAISON}{CH_INSCRIPTION}",
    "proxy": f"POST {TRUST_LAYER}{CH_PROXY}",
    "rendu": f"POST {SAISON}{CH_RENDU}",
}

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


class Bases(NamedTuple):
    trust_layer: str = TRUST_LAYER
    saison: str = SAISON
    corpus: str = CORPUS


class Echec(RuntimeError):
    """Un refus ou une réponse inattendue d'un service. `statut` et `reponse` portent ce qu'il a dit."""

    def __init__(self, message, statut=None, reponse=None):
        super().__init__(message)
        self.statut, self.reponse = statut, reponse


class ErreurInstrument(RuntimeError):
    def __init__(self, message, statut=None, reponse=None):
        super().__init__(message)
        self.statut, self.reponse = statut, reponse


# --- Identité --------------------------------------------------------------------------------

def did_key(pub):
    """`did:key` d'une clé publique Ed25519 brute : multicodec 0xed01, multibase base58btc."""
    donnees = b"\xed\x01" + pub
    n, texte = int.from_bytes(donnees, "big"), ""
    while n:
        n, r = divmod(n, 58)
        texte = _B58[r] + texte
    return "did:key:z" + "1" * (len(donnees) - len(donnees.lstrip(b"\0"))) + texte


def cle_publique(cle):
    return cle.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def segment_did(did):
    """Le segment d'URL du rapport individuel d'un DID : la casse est conservée (base58)."""
    return re.sub(r"[^A-Za-z0-9.-]+", "-", did).strip("-")


# --- Transport -------------------------------------------------------------------------------

def appel(methode, url, corps=None, entetes=None, ua=UA, delai=60):
    """Un appel HTTP : (statut, objet JSON, `{}` si le corps d'une erreur n'est pas du JSON).

    Un défaut réseau (URLError, OSError, délai) n'est pas rattrapé ici : l'appelant ne confond pas panne et refus.
    """
    # User-Agent explicite : la façade rend un 403 nu à Python-urllib.
    req = urllib.request.Request(url, method=methode, data=corps, headers={"User-Agent": ua, **(entetes or {})})
    try:
        with urllib.request.urlopen(req, timeout=delai) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except ValueError:
            return e.code, {}


def transport(cle_api, base, ua=UA):
    """Un appelant `(méthode, chemin, corps JSON) -> (statut, objet)` vers `base`, avec la clé si elle est donnée."""
    entetes = {"Content-Type": "application/json", **({"X-Api-Key": cle_api} if cle_api else {})}

    def appeler(methode, chemin, corps=None):
        return appel(methode, base + chemin, None if corps is None else json.dumps(corps).encode(), entetes, ua)
    return appeler


def exiger(tl, methode, chemin, corps=None):
    statut, reponse = tl(methode, chemin, corps)
    if statut != 200:
        raise Echec(f"{methode} {chemin} : HTTP {statut} {reponse}", statut, reponse)
    return reponse


# --- Trust Layer -----------------------------------------------------------------------------

def creer_cle(tl, email):
    """`POST /v1/keys/free-signup` : la clé `free`, montrée une seule fois (app.py de Trust Layer)."""
    statut, reponse = tl("POST", CH_CLE, {"email": email})
    cle = reponse.get("api_key") if isinstance(reponse, dict) else None
    if statut != 200 or not cle:
        raise Echec(f"POST {CH_CLE} : HTTP {statut}", statut, reponse)
    return cle


def lier(tl, cle, did):
    challenge = exiger(tl, "POST", CH_LIAISON, {"did": did})["challenge"]
    signature = base64.urlsafe_b64encode(cle.sign(challenge.encode())).rstrip(b"=").decode()
    exiger(tl, "POST", CH_CONFIRMATION, {"challenge": challenge, "signature": signature})


def identite(tl):
    """`GET /v1/keys/identity` : le DID lié à la clé et son historique ; `None` si la clé est refusée."""
    statut, reponse = tl("GET", CH_IDENTITE)
    if statut == 200:
        return reponse
    if statut in (401, 403):
        return None
    raise Echec(f"GET {CH_IDENTITE} : HTTP {statut}", statut, reponse)


class Instrument:
    """`POST /v1/proxy` vers le corpus, paires lues sur `GET /v1/proof/{id}/full` avec la clé. Un appel au proxy
    par lecture, sans cache : rendre un corps déjà lu sans nouvelle preuve changerait ce que mesure `appels`."""

    def __init__(self, tl, corpus=CORPUS):
        self.tl, self.corpus, self._paires = tl, corpus, {}

    def consulter(self, chemin):
        statut, r = self.tl("POST", CH_PROXY, {"target": self.corpus + chemin, "method": "GET", "payload": {}})
        if statut != 200 or not (r.get("proof") or {}).get("proof_id"):
            raise ErreurInstrument(f"proxy HTTP {statut}", statut, r)
        pid = r["proof"]["proof_id"]
        self._paires[pid] = self.lire_paires(pid)
        # Le proxy enveloppe la réponse amont : {status_code, body}. L'agent lit le corps servi.
        return pid, (r.get("service_response") or {}).get("body")

    def lire_paires(self, proof_id):
        statut, complet = self.tl("GET", f"/v1/proof/{proof_id}/full")
        if statut != 200:
            raise ErreurInstrument(f"GET /v1/proof/{proof_id}/full : HTTP {statut}", statut, complet)
        return {c: {"nonce": complet["commitment_nonces"][c], "value": complet["chain_data"][c]}
                for c in CHAMPS_PAIRES}

    def paires(self, proof_id):
        if proof_id not in self._paires:
            self._paires[proof_id] = self.lire_paires(proof_id)
        return self._paires[proof_id]


# --- Service de saison -----------------------------------------------------------------------

def url_etat(base_saison=SAISON):
    return base_saison + CH_SAISON


def etat(base_saison=SAISON):
    """`GET /v1/season/1`. Illisible = `Echec` : l'appelant agit comme si la saison était fermée."""
    try:
        statut, reponse = appel("GET", url_etat(base_saison))
    except ValueError:
        raise Echec("GET " + CH_SAISON + " : réponse illisible") from None
    if statut != 200 or not isinstance(reponse, dict) or not isinstance(reponse.get("ouverte"), bool):
        raise Echec(f"GET {CH_SAISON} : HTTP {statut}", statut, reponse)
    return reponse


def inscrire(cle_api, declares, *, lier_si_besoin, base_saison=SAISON, appeler=appel):
    """`POST /enroll`. Sur `did_non_lie` : `lier_si_besoin()` puis une seconde tentative. Les champs déclarés
    (`agent`, `stack`, `origine`) ne partent que s'il y en a ; sinon le corps est vide."""
    corps, entetes = b"", {"X-Api-Key": cle_api}
    if declares:
        corps, entetes = json.dumps(declares).encode(), {**entetes, "Content-Type": "application/json"}
    url = base_saison + CH_INSCRIPTION
    statut, reponse = appeler("POST", url, corps, entetes)
    if statut == 403 and reponse.get("erreur") == "did_non_lie":
        lier_si_besoin()
        statut, reponse = appeler("POST", url, corps, entetes)
    return statut, reponse


def soumission(saison, piste, task_id, rendu, did, paires):
    """Rendu de l'agent → soumission §4 ; paires jointes pour les seuls proof_id cités. Rien n'est ajouté ni
    corrigé : les assertions partent comme l'agent les a écrites."""
    assertions = []
    for i, a in enumerate(rendu["assertions"], start=1):
        ids = a["proof_ids"] if "proof_ids" in a else [a["proof_id"]]
        assertions.append({"id": f"a{i}", "claim": {"resource": a["resource"], "field": a["field"], "value": a["value"]},
                           "proof_ids": list(ids)})
    cites = sorted({p for a in assertions for p in a["proof_ids"]})
    soum = {"season": saison, "track": piste, "task_id": task_id, "agent_did": did, "verdict": rendu["verdict"],
            "assertions": assertions, "disclosures": {p: paires(p) for p in cites}}
    if rendu.get("narrative") is not None:
        soum["narrative"] = rendu["narrative"]
    return soum


def rendre(jeton, soum, base_saison=SAISON, appeler=appel):
    return appeler("POST", base_saison + CH_RENDU, json.dumps(soum).encode(),
                   {"Authorization": f"Bearer {jeton}", "Content-Type": "application/json"})


def lire_rapport(did, base_saison=SAISON):
    """`GET …/resultats/<segment>.json` : 404 tant que le rapport n'est pas publié."""
    return appel("GET", f"{base_saison}{CH_RAPPORTS}{segment_did(did)}.json")
