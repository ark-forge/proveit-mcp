"""Les sept outils, sans MCP : `Outils` appelé directement."""

import json

import pytest

from proveit_mcp import __version__
from proveit_mcp.cles import Cles
from proveit_mcp.outils import Outils, Refus

from monde import CLE_API, CORPUS, JETON, NARRATIVE, SAISON, TL, champs_de_score, cles_recursives as _cles_recursives

CONDITIONS = "https://proveit.arkforge.tech/challenges/prove-it/saisons/1/conditions/"


@pytest.fixture
def o(dossier):
    return Outils(Cles(dossier))


def _identite(o, email="humain@example.org"):
    return o.setup_identity(email=email, terms_accepted_by_human=True)


def _inscrit(o, **declares):
    _identite(o)
    return o.enroll(**declares)


def _assertion(pid, valeur="active", ressource="/entites/ENT-4001", champ="/statut"):
    return {"resource": ressource, "field": champ, "value": valeur, "proof_ids": [pid]}


def _actions(monde):
    """Les appels qui agissent : tout sauf la lecture de l'état de saison."""
    return [a for a in monde.appels if not (a[0] == "GET" and a[2] == "/v1/season/1")]


# --- proveit_status -------------------------------------------------------------------------------

def test_status_sans_cle_ni_dossier(o, monde, dossier):
    r = o.status()
    assert r["package_version"] == __version__
    assert r["season"]["open"] is True and r["season"]["reachable"] is True
    assert r["local"] == {"api_key_present": False, "did": None, "did_bound": None, "enrolled": False,
                          "tasks_submitted": 0, "tasks_total": 10}
    assert not dossier.exists()
    assert monde.hotes() == {SAISON}


def test_status_apres_inscription(o, monde):
    _inscrit(o)
    r = o.status()
    assert r["local"]["api_key_present"] and r["local"]["enrolled"] and r["local"]["did_bound"] is True
    assert r["local"]["did"].startswith("did:key:z6Mk")


def test_panne_reseau_n_est_pas_un_refus(o, monde):
    """Une panne se dit « injoignable, réessayer », jamais « saison fermée » ."""
    _identite(o)
    monde.hors_service = {SAISON}
    saison = o.status()["season"]
    assert saison["reachable"] is False and "open" not in saison and "retry" in saison["message"].lower()
    for appel in (lambda: o.enroll(), lambda: o.read("/referentiel"),
                  lambda: o.submit("conf-01", "conforme", [], dry_run=False)):
        with pytest.raises(Refus) as e:
            appel()
        assert e.value.code == "season_service_unreachable" and "retry" in e.value.message.lower()
        assert e.value.code != "season_closed"
    assert not monde.posts("/proxy") and not monde.posts("/enroll")


def test_trust_layer_injoignable_pendant_une_lecture(o, monde):
    _inscrit(o)
    monde.hors_service = {TL}
    with pytest.raises(Refus) as e:
        o.read("/referentiel")
    assert e.value.code == "trust_layer_unreachable"


# --- proveit_setup_identity -----------------------------------------------------------------------

@pytest.mark.parametrize("attestation", [False, None, "true", 1, "yes"])
def test_create_identity_exige_l_attestation_de_l_humain(o, monde, dossier, attestation):
    with pytest.raises(Refus) as e:
        o.setup_identity(email="humain@example.org", terms_accepted_by_human=attestation)
    assert e.value.code == "terms_not_accepted"
    assert CONDITIONS in e.value.message and "Getting a key and enrolling accept" in e.value.message
    assert monde.appels == [] and not dossier.exists()


@pytest.mark.parametrize("email", ["", "   ", "pas-un-email", None])
def test_setup_identity_exige_un_email(o, monde, dossier, email):
    with pytest.raises(Refus) as e:
        o.setup_identity(email=email, terms_accepted_by_human=True)
    assert e.value.code == "email_required"
    assert monde.appels == [] and not dossier.exists()


def test_setup_identity_cree_la_cle_le_did_et_la_liaison(o, monde, dossier):
    r = _identite(o)
    assert r["verified"] is True and r["did"].startswith("did:key:z6Mk") and monde.lie_a == r["did"]
    assert r["api_key_created"] is True and r["did_created"] is True
    assert len(r["api_key_fingerprint"]) == 12 and CLE_API not in json.dumps(r)
    assert json.loads((dossier / "trust_layer.json").read_text()) == {"api_key": CLE_API, "plan": "free"}
    assert monde.appels[0][2] == "/v1/keys/free-signup" and monde.appels[0][3] == {"email": "humain@example.org"}


def test_la_cle_est_ecrite_avant_toute_autre_etape(o, monde, dossier, monkeypatch):
    """Clé montrée une seule fois : si la suite échoue, elle est déjà sur disque."""
    monde.hors_service = set()
    original = monde._tl

    def casse(methode, chemin, corps, h):
        if chemin == "/v1/keys/identity":
            raise AssertionError("arrêt après le signup")
        return original(methode, chemin, corps, h)

    monde._tl = casse
    with pytest.raises(AssertionError):
        _identite(o)
    assert json.loads((dossier / "trust_layer.json").read_text())["api_key"] == CLE_API


def test_create_identity_idempotent(o, monde):
    premier = _identite(o)
    appels = len(monde.appels)
    second = _identite(o)
    assert second["did"] == premier["did"] and second["api_key_created"] is False and second["did_created"] is False
    assert [a[2] for a in monde.appels[appels:]] == ["/v1/keys/identity"]
    assert len(monde.posts("/free-signup")) == 1 and len(monde.posts("/bind-did")) == 1


def test_create_identity_refuse_un_autre_did_deja_lie(o, monde):
    monde.lie_a = "did:key:z6MkAutreDidDejaLieALaCle"
    # une clé importée, liée à un autre DID : on ne lie pas un second DID (le participant serait déclassé)
    o.cles.ecrire_tl(CLE_API)
    with pytest.raises(Refus) as e:
        _identite(o)
    assert e.value.code == "other_did_already_bound"
    assert monde.lie_a == "did:key:z6MkAutreDidDejaLieALaCle" and not monde.posts("/bind-did")


def test_create_identity_refuse_aussi_un_autre_did_quand_on_en_a_un_en_local(o, monde):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    local = o.cles.ecrire_did(Ed25519PrivateKey.generate())
    o.cles.ecrire_tl(CLE_API)
    monde.lie_a = "did:key:z6MkUnAutreDidDejaLie"
    with pytest.raises(Refus) as e:
        _identite(o)
    assert e.value.code == "other_did_already_bound" and local in e.value.message
    assert monde.lie_a == "did:key:z6MkUnAutreDidDejaLie" and not monde.posts("/bind-did")


def test_une_panne_ne_cite_pas_le_texte_de_l_exception_reseau(o, monde):
    """Le texte d'une exception réseau peut contenir une URL, un en-tête : il n'entre dans aucun refus."""
    import urllib.error
    _inscrit(o)
    original = monde.urlopen

    def casse(req, timeout=None, **kw):
        if req.full_url.endswith("/v1/proxy"):
            raise urllib.error.URLError(f"boum {CLE_API} {JETON}")
        return original(req, timeout)

    import urllib.request
    urllib.request.urlopen = casse
    try:
        with pytest.raises(Refus) as e:
            o.read("/referentiel")
    finally:
        urllib.request.urlopen = original
    assert CLE_API not in e.value.message + str(e.value.next_step) and JETON not in e.value.message


def test_create_identity_reprend_les_cles_importees(o, monde, dossier):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    cle = Ed25519PrivateKey.generate()
    did = o.cles.ecrire_did(cle)
    o.cles.ecrire_tl(CLE_API)
    r = _identite(o)
    assert r["did"] == did and r["api_key_created"] is False and r["did_created"] is False
    assert not monde.posts("/free-signup")


def test_signup_deja_pris_rend_le_code_du_service_et_dit_quoi_faire(o, monde, dossier):
    monde.email_pris = True
    with pytest.raises(Refus) as e:
        _identite(o)
    assert e.value.code == "already_exists" and "trust_layer.json" in e.value.next_step
    # La clé n'existe que dans l'email reçu par l'humain : un agent seul doit savoir qu'il faut la lui demander.
    assert "ask your human" in e.value.next_step.lower()
    assert not (dossier / "trust_layer.json").exists()


# --- proveit_enroll -------------------------------------------------------------------------------

def test_outils_qui_agissent_refusent_sans_appel_saison_fermee(o, monde):
    _identite(o)
    monde.ouverte = False
    avant = len(monde.appels)
    for appel in (lambda: o.enroll(), lambda: o.read("/referentiel"),
                  lambda: o.submit("conf-01", "conforme", [])):
        with pytest.raises(Refus) as e:
            appel()
        assert e.value.code == "season_closed" and "2026-10-06" in e.value.message
    nouveaux = monde.appels[avant:]
    assert [(a[0], a[2]) for a in nouveaux] == [("GET", "/v1/season/1")] * 3


def test_etat_illisible_vaut_saison_fermee_sans_appel_d_action(o, monde):
    _identite(o)
    monde.etat_illisible = True
    avant = len(monde.appels)
    for appel in (lambda: o.enroll(), lambda: o.read("/referentiel"), lambda: o.submit("conf-01", "conforme", [])):
        with pytest.raises(Refus) as e:
            appel()
        assert e.value.code == "season_service_unreachable"
    assert {(a[0], a[2]) for a in monde.appels[avant:]} == {("GET", "/v1/season/1")}


def test_l_etat_de_saison_est_relu_a_chaque_appel(o, monde):
    _identite(o)
    o.enroll()
    pid = o.read("/entites/ENT-4001")["proof_id"]
    monde.ouverte = False
    with pytest.raises(Refus):
        o.read("/entites/ENT-4001")
    monde.ouverte = True
    assert o.read("/entites/ENT-4001")["proof_id"] != pid
    assert len([a for a in monde.appels if a[2] == "/v1/season/1"]) == 4


def test_enroll_sans_identite_dit_de_commencer_par_setup(o, monde):
    with pytest.raises(Refus) as e:
        o.enroll()
    assert e.value.code == "no_identity" and "proveit_setup_identity" in e.value.next_step
    assert not monde.posts("/enroll")


def test_enroll_ecrit_le_jeton_localement_et_ne_le_rend_pas(o, monde, dossier):
    r = _inscrit(o)
    assert r["did"] == monde.lie_a and r["enrollment"] == "i-0001" and r["counts_as_participant"] is True
    assert "ranked" not in r
    assert len(r["tasks"]) == 10 and "Enrollment recorded" in r["message"]
    assert JETON not in json.dumps(r)
    saison = json.loads((dossier / "saison-1.json").read_text())
    assert saison["jeton"] == JETON and saison["inscription"] == "i-0001" and len(saison["taches"]) == 10


def test_enroll_lie_puis_reinscrit_sur_did_non_lie(o, monde):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    o.cles.ecrire_did(Ed25519PrivateKey.generate())
    o.cles.ecrire_tl(CLE_API)  # clé et DID importés, jamais liés
    r = o.enroll()
    assert [a[2] for a in monde.appels if a[0] == "POST"] == [
        "/v1/season/1/enroll", "/v1/keys/bind-did", "/v1/keys/bind-did/confirm", "/v1/season/1/enroll"]
    assert r["did"] == monde.lie_a


def test_origine_envoyee_seulement_si_fournie(o, monde):
    _identite(o)
    o.enroll()
    assert monde.inscriptions[-1] is None  # corps vide
    o.enroll(agent="mon-agent")
    assert monde.inscriptions[-1] == {"agent": "mon-agent"}
    o.enroll(origin="mcp-registry")
    assert monde.inscriptions[-1] == {"origine": "mcp-registry"}
    o.enroll(agent="a", stack="s", origin="o")
    assert monde.inscriptions[-1] == {"agent": "a", "stack": "s", "origine": "o"}


def test_enroll_rend_le_refus_du_service_tel_quel(o, monde):
    _identite(o)
    original = monde._saison

    def refuse(methode, chemin, corps, h):
        if chemin.endswith("/enroll"):
            return 409, {"erreur": "un_did_par_cle", "message": "This key already enrolled did:key:zX."}
        return original(methode, chemin, corps, h)

    monde._saison = refuse
    with pytest.raises(Refus) as e:
        o.enroll()
    assert e.value.code == "un_did_par_cle" and e.value.message == "This key already enrolled did:key:zX."
    assert e.value.status == 409


# --- proveit_read ---------------------------------------------------------------------------------

@pytest.mark.parametrize("chemin", ["entites/ENT-4001", "https://corpus.arkforge.tech/referentiel", "/entites/ENT-4001?x=1",
                                    "/entites/../x", "", "/", "/a b", "//x", "/entites/ENT-4001/", 7, None])
def test_read_resource_refuse_un_chemin_non_canonique_sans_appel(o, monde, chemin):
    _inscrit(o)
    avant = len(monde.appels)
    with pytest.raises(Refus) as e:
        o.read(chemin)
    assert e.value.code == "invalid_path"
    assert len(monde.appels) == avant


def test_read_resource_un_appel_proxy_par_lecture_sans_cache(o, monde, dossier):
    _inscrit(o)
    a = o.read("/entites/ENT-4001")
    b = o.read("/entites/ENT-4001")
    assert a["proof_id"] != b["proof_id"]
    assert len(monde.posts("/v1/proxy")) == 2
    assert a["body"] == b["body"] == {"existe": True, "statut": "active"}
    journal = o.cles.lectures()
    assert [l["proof_id"] for l in journal] == [a["proof_id"], b["proof_id"]]
    assert set(journal[0]) == {"proof_id", "path", "paires", "lu_le"} and journal[0]["path"] == "/entites/ENT-4001"
    assert set(journal[0]["paires"]) == {"request_hash", "response_hash"}


def test_read_rend_le_corps_amont_sans_le_retoucher(o, monde):
    _inscrit(o)
    monde.corpus["/referentiel"] = {"z": 1, "a": [1, 2, {"k": None}], "texte": "été ☃"}
    assert o.read("/referentiel")["body"] == {"z": 1, "a": [1, 2, {"k": None}], "texte": "été ☃"}
    assert list(o.read("/referentiel")["body"]) == ["z", "a", "texte"]


def test_read_rend_un_refus_du_proxy_tel_quel(o, monde):
    _inscrit(o)
    monde.refus_proxy = (429, "rate_limited")
    with pytest.raises(Refus) as e:
        o.read("/referentiel")
    assert e.value.code == "rate_limited" and e.value.message == "Refused by the proxy."
    assert o.cles.lectures() == []


# --- proveit_submit -------------------------------------------------------------------------------

def test_submit_task_ne_compare_jamais_la_valeur_au_corps_lu(o, monde):
    """Neutralité : une assertion fausse part telle quelle, l'outil n'en dit rien."""
    _inscrit(o)
    pid = o.read("/entites/ENT-4001")["proof_id"]  # le corps dit « active »
    fausse = _assertion(pid, valeur="radiee")
    r = o.submit("conf-01", "conforme", [fausse, _assertion(pid, valeur=False, champ="/existe")])
    envoye = monde.soumissions[-1]
    assert r["accepted"] is True
    assert [a["claim"]["value"] for a in envoye["assertions"]] == ["radiee", False]
    assert set(r) == {"accepted", "task_id", "replaced", "received_at", "message", "narrative"}


def test_submit_envoie_les_assertions_fausses_telles_quelles(o, monde):
    _inscrit(o)
    pid = o.read("/entites/ENT-4001")["proof_id"]
    assertions = [_assertion(pid, valeur=v) for v in ("faux", 12, None, ["a"], {"k": 1}, True)]
    o.submit("conf-02", "non_conforme", assertions, narrative="texte libre")
    envoye = monde.soumissions[-1]
    assert [a["claim"]["value"] for a in envoye["assertions"]] == ["faux", 12, None, ["a"], {"k": 1}, True]
    assert envoye["verdict"] == "non_conforme" and envoye["narrative"] == "texte libre"
    assert envoye["agent_did"] == monde.lie_a and (envoye["season"], envoye["track"]) == (1, "conformite")
    assert set(envoye["disclosures"]) == {pid}


def test_submit_n_ajoute_rien_a_ce_que_l_agent_a_ecrit(o, monde):
    _inscrit(o)
    pid = o.read("/entites/ENT-4001")["proof_id"]
    o.submit("conf-01", "indeterminable", [])
    envoye = monde.soumissions[-1]
    assert envoye["assertions"] == [] and envoye["disclosures"] == {} and "narrative" not in envoye


def test_submit_refuse_un_proof_id_inconnu_de_cette_cle(o, monde):
    _inscrit(o)
    with pytest.raises(Refus) as e:
        o.submit("conf-01", "conforme", [_assertion("prf_9999")])
    assert e.value.code == "unknown_proof_id" and "prf_9999" in e.value.message
    assert not monde.posts("/submit")


def test_submit_refuse_une_ressource_non_canonique(o, monde):
    _inscrit(o)
    pid = o.read("/entites/ENT-4001")["proof_id"]
    with pytest.raises(Refus) as e:
        o.submit("conf-01", "conforme", [_assertion(pid, ressource="https://x/entites/ENT-4001")])
    assert e.value.code == "invalid_path" and not monde.posts("/submit")


def test_submit_exige_une_inscription(o, monde):
    _identite(o)
    with pytest.raises(Refus) as e:
        o.submit("conf-01", "conforme", [])
    assert e.value.code == "not_enrolled" and "proveit_enroll" in e.value.next_step


def test_submit_task_rend_le_422_du_service_tel_quel(o, monde):
    _inscrit(o)
    with pytest.raises(Refus) as e:
        o.submit("conf-01", "peut_etre", [])
    assert e.value.code == "format"
    assert e.value.message == "Format refused (spec §4): verdict 'peut_etre'"
    assert e.value.status == 422


def test_submit_remplace_et_journalise_le_rendu(o, monde):
    _inscrit(o)
    a = o.submit("conf-01", "conforme", [])
    b = o.submit("conf-01", "non_conforme", [])
    assert (a["replaced"], b["replaced"]) == (False, True)
    assert [r["task_id"] for r in o.cles.rendus()] == ["conf-01", "conf-01"]


def test_dry_run_n_envoie_rien(o, monde):
    _inscrit(o)
    pid = o.read("/entites/ENT-4001")["proof_id"]
    avant = len(monde.appels)
    r = o.submit("conf-01", "conforme", [_assertion(pid, valeur="faux")], narrative="n", dry_run=True)
    assert monde.soumissions == [] and not monde.posts("/submit")
    assert not [a for a in monde.appels[avant:] if a[0] == "POST"]
    assert r["dry_run"] is True and r["sent"] is False
    soum = r["submission"]
    assert set(soum) == {"season", "track", "task_id", "agent_did", "verdict", "assertions", "disclosures", "narrative"}
    assert set(soum["disclosures"]) == {pid} and soum["assertions"][0]["claim"]["value"] == "faux"
    assert o.cles.rendus() == [] and o.progress()["tasks_submitted"] == 0


def test_dry_run_vaut_aussi_saison_fermee_et_ne_fait_aucune_action(o, monde):
    _inscrit(o)
    pid = o.read("/entites/ENT-4001")["proof_id"]
    monde.ouverte = False
    avant = len(monde.appels)
    r = o.submit("conf-01", "conforme", [_assertion(pid)], dry_run=True)
    assert r["sent"] is False and [(a[0], a[2]) for a in monde.appels[avant:]] == [("GET", "/v1/season/1")]


# --- proveit_progress, proveit_report -------------------------------------------------------------

def test_my_progress_ne_rend_aucun_champ_de_score(o, monde):
    _inscrit(o)
    pid = o.read("/entites/ENT-4001")["proof_id"]
    o.submit("conf-01", "conforme", [_assertion(pid, valeur="faux")])
    r = o.progress()
    assert r["tasks_submitted"] == 1 and r["tasks_total"] == 10 and r["proofs_read"] == 1
    assert r["submitted"] == [{"task_id": "conf-01", "last_submitted_at": "2026-10-12T10:00:00+00:00"}]
    assert not champs_de_score({k.lower() for k in _cles_recursives(r)})
    assert "verdict" not in set(_cles_recursives(r))
    assert o.progress() == r


def test_progress_est_local(o, monde):
    _inscrit(o)
    avant = len(monde.appels)
    o.progress()
    assert len(monde.appels) == avant


def test_report_avant_publication_le_dit_sans_conclure(o, monde):
    _identite(o)
    r = o.report()
    assert r["published"] is False and "72" in r["message"]
    appel = monde.appels[-1]
    assert appel[1] == SAISON and appel[2].startswith("/challenges/prove-it/saisons/1/resultats/did-key-z6Mk")
    assert appel[2].endswith(".json")


def test_report_sans_did_dit_de_commencer(o, monde):
    with pytest.raises(Refus) as e:
        o.report()
    assert e.value.code == "no_identity"


def test_report_rend_le_rapport_tel_que_publie(o, monde):
    _identite(o)
    publie = {"schema": "x", "reussite": [7, 10]}
    original = monde._saison
    monde._saison = lambda m, c, b, h: (200, publie) if "/resultats/" in c else original(m, c, b, h)
    assert o.report() == {"published": True, "report": publie}


def test_report_panne_n_est_pas_non_publie(o, monde):
    _identite(o)
    monde.hors_service = {SAISON}
    with pytest.raises(Refus) as e:
        o.report()
    assert e.value.code == "season_service_unreachable"


# --- Environnement --------------------------------------------------------------------------------

def test_url_de_base_non_surchargeable_par_l_environnement(monkeypatch, dossier, monde):
    """Une variable mal posée enverrait la clé d'un participant à un tiers : les hôtes sont fixes."""
    for nom in ("PROVEIT_TRUST_LAYER", "PROVEIT_SAISON", "PROVEIT_SAISON_URL", "PROVEIT_CORPUS", "TRUST_LAYER_BASE",
                "TRUST_LAYER_URL", "PROVEIT_BASE_URL", "PROVEIT_API", "HTTPS_PROXY", "https_proxy", "ALL_PROXY"):
        monkeypatch.setenv(nom, "http://evil.example")
    o = Outils(Cles(dossier))
    _inscrit(o)
    pid = o.read("/entites/ENT-4001")["proof_id"]
    o.submit("conf-01", "conforme", [_assertion(pid)])
    o.status()
    o.report()
    assert monde.hotes() == {TL, SAISON}
    cibles = [a[3]["target"] for a in monde.posts("/proxy")]
    assert cibles == [f"https://{CORPUS}/entites/ENT-4001"]


# --- Lot C1 : corrections après revue --------------------------------------------------------------------------

def _did_importe(o):
    """Clé et DID importés au format du paquet, jamais liés."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    o.cles.ecrire_tl(CLE_API)
    return o.cles.ecrire_did(Ed25519PrivateKey.generate())


def test_read_refuse_tant_que_le_did_n_est_pas_lie_a_la_cle(o, monde):
    """Une preuve émise par une clé sans DID lié rend l'assertion qui la cite non étayée : précondition mécanique."""
    _did_importe(o)
    with pytest.raises(Refus) as e:
        o.read("/referentiel")
    assert e.value.code == "did_not_bound" and "proveit_setup_identity" in e.value.next_step
    assert not monde.posts("/v1/proxy")
    assert o.cles.lectures() == []


def test_read_refuse_quand_la_cle_est_liee_a_un_autre_did(o, monde):
    _identite(o)
    monde.lie_a = "did:key:z6MkUnAutreDidDejaLie"
    with pytest.raises(Refus) as e:
        o.read("/referentiel")
    assert e.value.code == "did_not_bound"
    assert not monde.posts("/v1/proxy")


def test_read_refuse_sans_did_local(o, monde):
    o.cles.ecrire_tl(CLE_API)
    with pytest.raises(Refus) as e:
        o.read("/referentiel")
    assert e.value.code == "no_identity" and not monde.posts("/v1/proxy")


def test_read_lit_apres_la_liaison(o, monde):
    _inscrit(o)
    assert o.read("/referentiel")["proof_id"] == "prf_0001"


def _prets(o, monde, etat):
    """Met l'outil dans l'état d'une ligne de la table de `next_step`."""
    ouverte, inscrit, rendus = etat
    _identite(o)
    if inscrit:
        o.enroll()
    for n in range(rendus):
        o.cles.ajouter_rendu({"task_id": f"conf-{n + 1:02d}", "recu_le": "2026-10-12T10:00:00+00:00"})
    monde.ouverte = ouverte is True
    if ouverte is None:
        monde.hors_service = {SAISON}


TABLE_NEXT_STEP = [
    ((True, False, 0), "proveit_enroll"),
    ((True, True, 0), "proveit_read, then proveit_submit"),
    ((True, True, 9), "proveit_read, then proveit_submit"),
    ((True, True, 10), "All tasks submitted. A submission can be replaced until the close; then proveit_report."),
    ((False, True, 3), "proveit_report (published at most 72 hours after the close)"),
    ((False, False, 0), "The season is closed: call proveit_status again later."),
    ((None, True, 3), "Call proveit_status again later."),
    ((None, False, 0), "Call proveit_status again later."),
]


@pytest.mark.parametrize("etat,attendu", TABLE_NEXT_STEP)
def test_status_next_step_suit_l_etat_de_la_saison(o, monde, etat, attendu):
    _prets(o, monde, etat)
    assert o.status()["next_step"] == attendu


def test_status_next_step_sans_identite(o, monde):
    assert o.status()["next_step"] == "proveit_setup_identity (ask your human first: terms and email)"
    monde.ouverte = False
    assert o.status()["next_step"] == "proveit_setup_identity (ask your human first: terms and email)"


def test_status_did_non_lie_renvoie_vers_setup_identity(o, monde):
    _did_importe(o)
    r = o.status()
    assert r["local"]["did_bound"] is False and r["next_step"].startswith("proveit_setup_identity")


def test_status_did_lie_a_un_autre_did_n_est_pas_lie(o, monde):
    _identite(o)
    monde.lie_a = "did:key:z6MkUnAutreDidDejaLie"
    assert o.status()["local"]["did_bound"] is False


@pytest.mark.parametrize("code", ["agent_refuse", "stack_refusee", "origine_refusee"])
def test_enroll_refus_de_champ_declare_a_une_etape_utile(o, monde, code):
    _identite(o)
    monde.refus_enroll = (422, code)
    with pytest.raises(Refus) as e:
        o.enroll(agent="x")
    assert e.value.code == code and e.value.status == 422
    assert "Shorten the declared text" in e.value.next_step and "participer.json" not in e.value.next_step


def test_enroll_did_mismatch_n_ecrit_pas_le_jeton(o, monde, dossier):
    _identite(o)
    monde.did_inscrit = "did:key:z6MkUnAutreDidInscrit"
    with pytest.raises(Refus) as e:
        o.enroll()
    assert e.value.code == "did_mismatch"
    assert not (dossier / "saison-1.json").exists()


@pytest.mark.parametrize("statut", [403, 404])
def test_full_403_et_404_sont_une_preuve_inconnue(o, monde, statut):
    _inscrit(o)
    monde.refus_full = (statut, "proof_not_found")
    with pytest.raises(Refus) as e:
        o.submit("conf-01", "conforme", [_assertion("prf_9999")])
    assert e.value.code == "unknown_proof_id"


def test_submit_rend_l_avertissement_narrative_du_service_tel_quel(o, monde):
    _inscrit(o)
    r = o.submit("conf-01", "conforme", [], narrative="texte libre")
    assert r["narrative"] == NARRATIVE and r["narrative"]["publie"] is True


def test_dry_run_ne_porte_pas_d_avertissement_du_service(o, monde):
    _inscrit(o)
    assert "narrative" not in o.submit("conf-01", "conforme", [], narrative="n", dry_run=True)


def test_setup_identity_empreinte_exacte(o, monde):
    import hashlib
    r = _identite(o)
    assert r["api_key_fingerprint"] == hashlib.sha256(CLE_API.encode()).hexdigest()[:12]


def test_une_erreur_disque_locale_n_est_pas_une_panne_de_trust_layer(o, monde, monkeypatch, dossier):
    """Un disque plein sur la machine du participant ne se réessaie pas « plus tard » : ce n'est pas Trust Layer."""
    def disque_plein(self, cle):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(Cles, "ecrire_did", disque_plein)
    with pytest.raises(Refus) as e:
        _identite(o)
    assert e.value.code == "local_keys_unusable" and "unreachable" not in e.value.message
    assert CLE_API not in e.value.message + str(e.value.next_step)


@pytest.mark.parametrize("outil", ["status", "setup_identity", "enroll", "read", "submit", "progress", "report"])
def test_chaque_outil_refuse_un_fichier_de_secret_rendu_lisible(o, monde, dossier, outil):
    """Le contrôle des droits se rejoue à chaque appel, sur les sept outils et pas seulement certains."""
    _inscrit(o)
    (dossier / "trust_layer.json").chmod(0o644)
    appels = {"status": lambda: o.status(),
              "setup_identity": lambda: o.setup_identity("humain@example.org", True),
              "enroll": lambda: o.enroll(), "read": lambda: o.read("/referentiel"),
              "submit": lambda: o.submit("conf-01", "conforme", []), "progress": lambda: o.progress(),
              "report": lambda: o.report()}
    avant = len(monde.appels)
    with pytest.raises(Refus) as e:
        appels[outil]()
    assert e.value.code == "local_keys_unusable" and "chmod 600" in e.value.next_step + e.value.message
    assert len(monde.appels) == avant


def test_read_avec_une_cle_refusee_dit_cle_invalide_et_pas_did_non_lie(o, monde):
    _identite(o)
    o.cles.ecrire_tl("tlk_AUTRE_CLE_REFUSEE")
    with pytest.raises(Refus) as e:
        o.read("/referentiel")
    assert e.value.code == "invalid_api_key" and not monde.posts("/v1/proxy")
