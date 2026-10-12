"""Les sept outils, sans protocole : `serveur.py` les expose.

L'outil est un instrument mis entre les mains du participant, pas un assistant :
  - il ne compare jamais une valeur au corps lu, ne refuse jamais une assertion parce qu'elle semble fausse, n'en
    propose ni n'en construit aucune ;
  - une lecture, un appel au proxy, sans cache ;
  - aucun score, aucune indication de score, aucun plafond de lectures ;
  - aucun secret dans une sortie : on rend une empreinte (sha256[:12]) de la clé API, jamais sa valeur.
Tout refus est un `Refus` : le code du service tel quel, son message, et l'étape suivante.
"""

import hashlib
import http.client
import os
from contextlib import contextmanager
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proveit_mcp import SAISON as NUMERO
from proveit_mcp import __version__, client
from proveit_mcp.cles import ErreurCles

CONDITIONS = f"https://proveit.arkforge.tech/challenges/prove-it/saisons/{NUMERO}/conditions/"
GUIDE = f"https://proveit.arkforge.tech/challenges/prove-it/saisons/{NUMERO}/participer.json"
TACHES_TOTAL = 10
RESEAU = (OSError, ValueError, http.client.HTTPException)  # URLError et les délais sont des OSError

# Ce que le service rend, avec l'étape suivante : la table d'erreurs de skill.md, en une ligne par code.
ETAPES = {
    "saison_fermee": "Read proveit_status and retry when the season is open.",
    "cle_invalide": "Trust Layer refused the key: check trust_layer.json in your keys folder.",
    "cle_absente": "Call proveit_setup_identity first.",
    "did_non_lie": "Call proveit_setup_identity, then proveit_enroll again.",
    "un_did_par_cle": "One DID per key and per season: use the DID already enrolled with this key.",
    "did_deja_inscrit": "This DID is enrolled with another key: use that key.",
    "trust_layer_indisponible": "Trust Layer did not answer: retry later.",
    "jeton_invalide": "Call proveit_enroll again to get a new season token.",
    "jeton_absent": "Call proveit_enroll first.",
    "format": "Fix the submission and call proveit_submit again.",
    "tache_inconnue": "Use a task id from the list returned by proveit_enroll.",
    "plafond_depasse": "Send fewer assertions for this task and call proveit_submit again.",
    "json_invalide": "Fix the submission and call proveit_submit again.",
    "rate_limited": "Wait a moment and retry.",
    "agent_refuse": "Shorten the declared text, drop emoji, do not impersonate anyone, then call proveit_enroll again.",
    "stack_refusee": "Shorten the declared text, drop emoji, do not impersonate anyone, then call proveit_enroll again.",
    "origine_refusee": "Shorten the declared text, drop emoji, do not impersonate anyone, then call proveit_enroll again.",
}
ETAPE_PAR_DEFAUT = f"See {GUIDE}"


class Refus(Exception):
    """Un refus (local ou du service) : jamais un secret dans `message`."""

    def __init__(self, code, message, next_step=None, status=None):
        super().__init__(message)
        self.code, self.message, self.next_step, self.status = code, message, next_step, status


def _empreinte(secret):
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()[:12]


def _maintenant():
    return datetime.now(timezone.utc).isoformat()


def _code_et_message(statut, reponse, defaut):
    """Le code et le message du service, tels quels : `{erreur, message}` (saison) ou `{error: {code, message}}`."""
    if isinstance(reponse, dict):
        if isinstance(reponse.get("erreur"), str):
            return reponse["erreur"], reponse.get("message") or defaut
        if isinstance(reponse.get("error"), dict) and isinstance(reponse["error"].get("code"), str):
            return reponse["error"]["code"], reponse["error"].get("message") or defaut
    return f"http_{statut}", defaut


def _refus_du_service(statut, reponse, defaut, etape=None):
    code, message = _code_et_message(statut, reponse, defaut)
    return Refus(code, message, etape or ETAPES.get(code, ETAPE_PAR_DEFAUT), statut)


@contextmanager
def _panne(code, quoi):
    """Une panne n'est pas un refus : on le dit, sans conclure, et on invite à réessayer."""
    try:
        yield
    except RESEAU:
        raise Refus(code, f"{quoi} is unreachable or answered something unreadable. Nothing was concluded: retry later.",
                    "Retry in a moment.") from None


def _canonique(valeur):
    return isinstance(valeur, str) and client.CHEMIN_CANONIQUE.fullmatch(valeur) is not None


def _chemin_refuse(quoi="path"):
    return Refus("invalid_path", f"The {quoi} must be a canonical corpus path: no host, no query string, no trailing "
                                 "slash, for example /entites/ENT-4001.", "Fix the path and call the tool again.")


def _garde(f):
    def appeler(self, *args, **kwargs):
        try:
            self.cles.verifier()  # un fichier de secret rendu lisible après le démarrage est refusé aussi
            return f(self, *args, **kwargs)
        except ErreurCles as exc:
            raise Refus("local_keys_unusable", str(exc), "Fix the file permissions or contents, then retry.") from None
        except OSError as exc:  # tout appel réseau est sous `_panne` ou rattrapé : ici, c'est le disque local
            raison = os.strerror(exc.errno) if exc.errno else "unknown error"
            raise Refus("local_keys_unusable", f"A file in your keys folder could not be read or written ({raison}). "
                                               "This is your machine, not a service.",
                        "Fix the folder (space, permissions), then retry.") from None
    appeler.__name__, appeler.__doc__ = f.__name__, f.__doc__
    return appeler


class Outils:
    def __init__(self, cles, *, bases=None):
        self.cles, self.bases = cles, bases or client.Bases()

    # --- Aides ---------------------------------------------------------------------------------

    def _tl(self, api_key=None):
        return client.transport(api_key, self.bases.trust_layer)

    def _etat_saison(self):
        try:
            return client.etat(self.bases.saison)
        except (client.Echec, *RESEAU):
            raise Refus("season_service_unreachable",
                        "The season service is unreachable or answered something unreadable, so its state is unknown "
                        "and nothing was done. This is not a closed season: retry later.",
                        "Retry in a moment.") from None

    def _saison_ouverte(self):
        """Relue à chaque appel qui agit, jamais mise en cache : l'ouverture se décide côté service de saison."""
        etat = self._etat_saison()
        if not etat["ouverte"]:
            raise Refus("season_closed",
                        f"Season {NUMERO} is closed: enrollment, reading and submission run from "
                        f"{etat.get('ouverture')} to {etat.get('cloture')}.",
                        "Call proveit_status to check the state again; this tool works again once the season is open.")
        return etat

    def _identite_locale(self):
        """(clé API ou None, (clé privée, did) ou None)."""
        tl = self.cles.lire_tl()
        return (tl["api_key"] if tl else None), self.cles.lire_did()

    def _exiger_identite(self, avec_did=True):
        api_key, did = self._identite_locale()
        if api_key is None or (avec_did and did is None):
            raise Refus("no_identity", "No key or DID found in your keys folder.",
                        "Call proveit_setup_identity first (ask your human for their email and consent once).")
        return api_key, did

    # --- proveit_status ------------------------------------------------------------------------

    @staticmethod
    def _etape_suivante(saison, local, lie):
        """L'outil à appeler ensuite, selon ce que la machine tient et ce que la saison permet (jamais un outil qui
        refuserait)."""
        if not (local["api_key_present"] and local["did"]):
            return "proveit_setup_identity (ask your human first: terms and email)"
        if lie is False:
            return "proveit_setup_identity (it binds your DID to your key)"
        if not saison["reachable"]:
            return "Call proveit_status again later."
        if not saison["open"]:
            if local["enrolled"]:
                return "proveit_report (published at most 72 hours after the close)"
            return "The season is closed: call proveit_status again later."
        if not local["enrolled"]:
            return "proveit_enroll"
        if local["tasks_submitted"] < local["tasks_total"]:
            return "proveit_read, then proveit_submit"
        return "All tasks submitted. A submission can be replaced until the close; then proveit_report."

    @_garde
    def status(self):
        try:
            e = client.etat(self.bases.saison)
            saison = {"reachable": True, "open": e["ouverte"], "opens_at": e.get("ouverture"),
                      "closes_at": e.get("cloture"), "track": e.get("piste")}
        except (client.Echec, *RESEAU):
            saison = {"reachable": False, "message": "The season service is unreachable or unreadable: its state is "
                                                     "unknown. Retry later; this is not a closed season."}
        api_key, did = self._identite_locale()
        lie = None
        if api_key and did:
            try:
                ident = client.identite(self._tl(api_key))
                lie = bool(ident and ident.get("verified_did") == did[1])
            except (client.Echec, *RESEAU):
                lie = None
        inscription = self.cles.lire_saison()
        rendus = {r["task_id"] for r in self.cles.rendus()}
        local = {"api_key_present": api_key is not None, "did": did[1] if did else None, "did_bound": lie,
                 "enrolled": inscription is not None, "tasks_submitted": len(rendus),
                 "tasks_total": len(inscription["taches"]) if inscription and inscription.get("taches") else TACHES_TOTAL}
        return {"package_version": __version__, "season": saison, "local": local,
                "next_step": self._etape_suivante(saison, local, lie)}

    # --- proveit_setup_identity ----------------------------------------------------------------

    def _etape_cle_refusee(self, statut):
        chemin = self.cles.racine / "trust_layer.json"
        if statut == 409:  # la clé n'existe que dans l'email reçu par l'humain : un agent seul ne peut pas la deviner
            return (f"A key was already created for this email and sent to it: ask your human for that key, then save it "
                    f'as {chemin} ({{"api_key": "...", "plan": "free"}}, mode 600) and call this tool again; or use '
                    "another email address of your human.")
        return (f"If you already have a key, save it as {chemin} "
                '({"api_key": "...", "plan": "free"}, mode 600) and call this tool again.')

    @_garde
    def setup_identity(self, email, terms_accepted_by_human):
        if terms_accepted_by_human is not True:
            raise Refus("terms_not_accepted",
                        "Getting a key and enrolling accept the participation terms, which is an act of the human who operates "
                        "you. "
                        f"Terms: {CONDITIONS}",
                        "Ask your human once: show them the terms, get their email address and their agreement, then "
                        "call again with terms_accepted_by_human=true. Never set it on your own initiative.")
        if not isinstance(email, str) or not email.strip() or "@" not in email.strip()[1:-1]:
            raise Refus("email_required", "The email address of your human is required to get a Trust Layer key.",
                        "Ask your human for their email address.")
        self.cles.verifier()
        api_key, did = self._identite_locale()
        cle_creee = False
        if api_key is None:
            with _panne("trust_layer_unreachable", "Trust Layer"):
                try:
                    api_key = client.creer_cle(self._tl(), email.strip())
                except client.Echec as e:
                    raise _refus_du_service(e.statut, e.reponse, "Trust Layer refused to create a key.",
                                            self._etape_cle_refusee(e.statut)) from None
            self.cles.ecrire_tl(api_key, "free")  # montrée une seule fois : sur disque avant toute autre étape
            cle_creee = True
        tl = self._tl(api_key)
        with _panne("trust_layer_unreachable", "Trust Layer"):
            try:
                ident = client.identite(tl)
            except client.Echec as e:
                raise _refus_du_service(e.statut, e.reponse, "Trust Layer could not read the key identity.") from None
        if ident is None:
            raise Refus("invalid_api_key", "Trust Layer says this key is invalid or inactive.",
                        f"Fix {self.cles.racine / 'trust_layer.json'}, or delete it to create a new key.")
        lie = ident.get("verified_did")
        did_cree = False
        if did is None:
            if lie:
                raise Refus("other_did_already_bound",
                            f"This key is already bound to {lie}, and no private key for it is in your keys folder. "
                            "Binding a second DID would split your history.",
                            f"Put the matching {self.cles.racine / 'did.json'} in place, or use another key.")
            cle = Ed25519PrivateKey.generate()
            did_cree = True
            did = (cle, self.cles.ecrire_did(cle))  # local : hors de `_panne`, un disque plein n'est pas une panne réseau
        elif lie and lie != did[1]:
            raise Refus("other_did_already_bound",
                        f"This key is already bound to {lie}, not to the DID of your keys folder ({did[1]}). "
                        "Binding a second DID would split your history.",
                        "Use the matching did.json for this key, or another key.")
        if lie != did[1]:
            with _panne("trust_layer_unreachable", "Trust Layer"):
                try:
                    client.lier(tl, did[0], did[1])
                    ident = client.identite(tl)
                except client.Echec as e:
                    raise _refus_du_service(e.statut, e.reponse, "Trust Layer refused the DID binding.") from None
            if not ident or ident.get("verified_did") != did[1]:
                raise Refus("binding_not_confirmed", "Trust Layer did not confirm the binding.", "Retry.")
        return {"verified": True, "did": did[1], "api_key_created": cle_creee, "did_created": did_cree,
                "api_key_fingerprint": _empreinte(api_key),
                "message": "Your key and DID are stored on this machine only and are never returned by any tool.",
                "next_step": "proveit_enroll"}

    # --- proveit_enroll ------------------------------------------------------------------------

    @_garde
    def enroll(self, agent=None, stack=None, origin=None):
        self._saison_ouverte()
        api_key, did = self._exiger_identite()
        declares = {k: v for k, v in (("agent", agent), ("stack", stack), ("origine", origin)) if v is not None}
        tl = self._tl(api_key)

        def lier_si_besoin():
            with _panne("trust_layer_unreachable", "Trust Layer"):
                try:
                    client.lier(tl, did[0], did[1])
                except client.Echec as e:
                    raise _refus_du_service(e.statut, e.reponse, "Trust Layer refused the DID binding.") from None

        with _panne("season_service_unreachable", "The season service"):
            statut, rep = client.inscrire(api_key, declares, lier_si_besoin=lier_si_besoin, base_saison=self.bases.saison)
        if statut not in (200, 201):
            raise _refus_du_service(statut, rep, f"The season service refused the enrollment (HTTP {statut}).")
        if rep.get("did") != did[1]:
            raise Refus("did_mismatch", "The season service enrolled a different DID than the one in your keys folder.",
                        "Check did.json.")
        self.cles.ecrire_saison(rep)
        return {"enrolled": True, "new": statut == 201, "did": did[1], "enrollment": rep.get("inscription"),
                "participant": rep.get("participant"), "counts_as_participant": rep.get("classe"), "tasks": rep.get("taches"),
                "message": rep.get("message"), "next_step": "proveit_read"}

    # --- proveit_read --------------------------------------------------------------------------

    @_garde
    def read(self, path):
        if not _canonique(path):
            raise _chemin_refuse()
        self._saison_ouverte()
        api_key, did = self._exiger_identite()
        tl = self._tl(api_key)
        # Une preuve émise par une clé dont le DID n'est pas lié rend l'assertion qui la cite non étayée : on ne la fabrique pas.
        with _panne("trust_layer_unreachable", "Trust Layer"):
            try:
                ident = client.identite(tl)
            except client.Echec as e:
                raise _refus_du_service(e.statut, e.reponse, "Trust Layer could not read the key identity.") from None
        if ident is None:
            raise Refus("invalid_api_key", "Trust Layer says this key is invalid or inactive.",
                        f"Fix {self.cles.racine / 'trust_layer.json'}, or delete it to create a new key.")
        if ident.get("verified_did") != did[1]:
            raise Refus("did_not_bound", "The DID of your keys folder is not bound to your Trust Layer key, so a receipt "
                                         "made now could not back an assertion.",
                        "Call proveit_setup_identity (or proveit_enroll, which binds), then read again.")
        instrument = client.Instrument(tl, corpus=self.bases.corpus)
        with _panne("trust_layer_unreachable", "Trust Layer"):
            try:
                pid, corps = instrument.consulter(path)
            except client.ErreurInstrument as e:
                raise _refus_du_service(e.statut, e.reponse, f"Trust Layer refused the lookup ({e}).") from None
        self.cles.ajouter_lecture({"proof_id": pid, "path": path, "paires": instrument.paires(pid), "lu_le": _maintenant()})
        return {"proof_id": pid, "body": corps}

    # --- proveit_submit ------------------------------------------------------------------------

    @staticmethod
    def _assertions(assertions):
        """La mécanique seule : de quoi construire le §4. Ni valeur comparée, ni assertion refusée pour son contenu."""
        if not isinstance(assertions, list):
            raise Refus("invalid_assertion", "assertions must be a list.", "Send a list, possibly empty.")
        propres = []
        for i, a in enumerate(assertions):
            ok = (isinstance(a, dict) and {"resource", "field", "value", "proof_ids"} <= set(a)
                  and isinstance(a["field"], str) and isinstance(a["proof_ids"], list) and a["proof_ids"]
                  and all(isinstance(p, str) for p in a["proof_ids"]))
            if not ok:
                raise Refus("invalid_assertion", f"Assertion {i + 1}: resource, field, value and a non-empty list "
                                                 "proof_ids are required.", "Fix the assertion and call again.")
            if not _canonique(a["resource"]):
                raise _chemin_refuse("resource")
            propres.append({"resource": a["resource"], "field": a["field"], "value": a["value"],
                            "proof_ids": list(a["proof_ids"])})
        return propres

    def _paires(self, api_key, ids):
        """Les paires du journal local ; relues sur /full avec la clé si elles manquent (preuve lue hors de ce serveur)."""
        connues = {l["proof_id"]: l["paires"] for l in self.cles.lectures()}
        instrument = client.Instrument(self._tl(api_key), corpus=self.bases.corpus)
        for pid in ids:
            if pid in connues:
                continue
            with _panne("trust_layer_unreachable", "Trust Layer"):
                try:
                    connues[pid] = instrument.lire_paires(pid)
                except client.ErreurInstrument as e:
                    if e.statut not in (403, 404):  # /full : 403 pas le propriétaire, 404 inconnue (app.py:851-880)
                        raise _refus_du_service(e.statut, e.reponse, f"Trust Layer refused the lookup ({e}).") from None
                    raise Refus("unknown_proof_id", f"{pid!r} is not a proof of this key: read the resource with "
                                                    "proveit_read first.", "Call proveit_read, then cite its proof_id.") from None
        return connues

    @_garde
    def submit(self, task_id, verdict, assertions, narrative=None, dry_run=False):
        if not isinstance(task_id, str) or not task_id:
            raise Refus("invalid_task", "task_id must be a task id such as conf-01.", "Use an id from proveit_enroll.")
        propres = self._assertions(assertions)
        etat = self._etat_saison() if dry_run else self._saison_ouverte()
        api_key, did = self._exiger_identite()
        inscription = self.cles.lire_saison()
        if not dry_run and inscription is None:
            raise Refus("not_enrolled", "This DID is not enrolled in the season.", "Call proveit_enroll first.")
        paires = self._paires(api_key, sorted({p for a in propres for p in a["proof_ids"]}))
        rendu = {"verdict": verdict, "assertions": propres, "narrative": narrative}
        soum = client.soumission(etat.get("saison", NUMERO), etat.get("piste"), task_id, rendu, did[1], paires.__getitem__)
        if dry_run:
            return {"dry_run": True, "sent": False, "submission": soum,
                    "message": "Nothing was sent. This is the submission as proveit_submit would send it."}
        with _panne("season_service_unreachable", "The season service"):
            statut, rep = client.rendre(inscription["jeton"], soum, self.bases.saison)
        if statut != 202:
            raise _refus_du_service(statut, rep, f"The season service refused the submission (HTTP {statut}).")
        self.cles.ajouter_rendu({"task_id": task_id, "recu_le": rep.get("recue_le")})
        return {"accepted": True, "task_id": task_id, "replaced": rep.get("remplace"), "received_at": rep.get("recue_le"),
                "message": rep.get("message"), "narrative": rep.get("narrative")}

    # --- proveit_progress ----------------------------------------------------------------------

    @_garde
    def progress(self):
        """Lecture locale : jamais un score, jamais une indication de score."""
        inscription = self.cles.lire_saison()
        dernier = {}
        for r in self.cles.rendus():
            dernier[r["task_id"]] = r["recu_le"]
        lectures = self.cles.lectures()
        did = self.cles.lire_did()
        return {"enrolled": inscription is not None, "did": did[1] if did else None,
                "tasks_submitted": len(dernier),
                "tasks_total": len(inscription["taches"]) if inscription and inscription.get("taches") else TACHES_TOTAL,
                "submitted": [{"task_id": t, "last_submitted_at": d} for t, d in sorted(dernier.items())],
                "proofs_read": len(lectures), "last_read_at": lectures[-1]["lu_le"] if lectures else None}

    # --- proveit_report ------------------------------------------------------------------------

    @_garde
    def report(self):
        _, did = self._exiger_identite(avec_did=True)
        with _panne("season_service_unreachable", "The season service"):
            statut, rep = client.lire_rapport(did[1], self.bases.saison)
        if statut == 200:
            return {"published": True, "report": rep}
        if statut == 404:
            return {"published": False,
                    "message": "Not published yet: reports appear at most 72 hours after the season closes."}
        if statut >= 500:
            raise Refus("season_service_unreachable", f"The season service answered HTTP {statut}. Nothing was "
                                                      "concluded: retry later.", "Retry in a moment.")
        raise _refus_du_service(statut, rep, f"The report could not be read (HTTP {statut}).")
