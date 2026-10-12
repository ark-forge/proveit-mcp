"""Le client : identité, liaison, proxy, inscription, rendu."""

import ast
import base64
import json
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from monde import CLE_API, SAISON, _pub_du_did
from proveit_mcp import __version__, client

PAQUET = Path(client.__file__).resolve().parent
GRAINE = bytes(range(32))
VECTEUR_DID = "did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd"


def _brut(cle):
    return cle.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def test_client_did_key_egal_a_l_ancien():
    """Vecteur de référence (graine 0..31)."""
    cle = Ed25519PrivateKey.from_private_bytes(GRAINE)
    did = client.did_key(_brut(cle))
    assert did.startswith("did:key:z6Mk")
    assert _pub_du_did(did) == _brut(cle)
    assert did == VECTEUR_DID


def test_transport_envoie_un_user_agent_proveit_mcp(monde):
    client.transport(CLE_API, "https://trust.arkforge.tech")("GET", "/v1/keys/identity")
    client.transport(None, "https://proveit.arkforge.tech")("GET", "/v1/season/1")
    agents = [a[4]["user-agent"] for a in monde.appels]
    assert agents == [f"proveit-mcp/{__version__}"] * 2
    assert not any("urllib" in a.lower() for a in agents)
    assert client.UA == f"proveit-mcp/{__version__}"


def test_transport_n_envoie_la_cle_qu_a_l_hote_demande(monde):
    client.transport(None, "https://proveit.arkforge.tech")("GET", "/v1/season/1")
    assert "x-api-key" not in monde.appels[0][4]


def test_transport_rend_le_statut_et_le_corps_d_un_refus(monde):
    statut, corps = client.transport("mauvaise", "https://trust.arkforge.tech")("GET", "/v1/keys/identity")
    assert statut == 401 and corps["error"]["code"] == "invalid_api_key"


def test_transport_corps_non_json_sur_erreur_rend_un_dict_vide(monde):
    statut, corps = client.transport(None, "https://proveit.arkforge.tech")(
        "GET", "/challenges/prove-it/saisons/1/resultats/x.json")
    assert (statut, corps) == (404, {})


def test_lier_signe_en_base64url_sans_padding(monde):
    """La logique du faux Trust Layer (conftest) vérifie la signature Ed25519 et l'absence de `=`."""
    cle = Ed25519PrivateKey.generate()
    did = client.did_key(_brut(cle))
    client.lier(client.transport(CLE_API, "https://trust.arkforge.tech"), cle, did)
    assert monde.lie_a == did
    confirme = [a for a in monde.appels if a[2].endswith("/confirm")][0][3]
    assert set(confirme) == {"challenge", "signature"} and "=" not in confirme["signature"]
    assert len(base64.urlsafe_b64decode(confirme["signature"] + "==")) == 64


def test_lier_leve_echec_sur_refus(monde):
    cle = Ed25519PrivateKey.generate()
    with pytest.raises(client.Echec):
        client.lier(client.transport("mauvaise", "https://trust.arkforge.tech"), cle, client.did_key(_brut(cle)))


def test_consulter_lit_service_response_body_et_garde_les_paires():
    paire = {"nonce": "n" * 64, "value": "v" * 64}
    appels = []

    def tl(methode, chemin, corps=None):
        appels.append((methode, chemin, corps))
        if chemin == "/v1/proxy":
            return 200, {"proof": {"proof_id": "prf_20260914_173023_bb1bfc"},
                         "service_response": {"status_code": 200, "body": {"statut": "active"}}}
        return 200, {"commitment_nonces": {"request_hash": paire["nonce"], "response_hash": paire["nonce"]},
                     "chain_data": {"request_hash": paire["value"], "response_hash": paire["value"]}}

    instrument = client.Instrument(tl)
    pid, corps = instrument.consulter("/entites/ENT-4001")

    assert (pid, corps) == ("prf_20260914_173023_bb1bfc", {"statut": "active"})
    assert instrument.paires(pid) == {"request_hash": paire, "response_hash": paire}


def test_corps_proxy_est_la_forme_prouvee_en_prod():
    """Exactement {target, method, payload} : ni `extra_headers`, ni `currency`."""
    vus = []

    def tl(methode, chemin, corps=None):
        vus.append((methode, chemin, corps))
        return 200, {"proof": {"proof_id": "p"}, "service_response": {"body": {}},
                     "commitment_nonces": {"request_hash": "a", "response_hash": "b"},
                     "chain_data": {"request_hash": "c", "response_hash": "d"}}

    client.Instrument(tl).consulter("/entites/ENT-4001")
    assert vus[0] == ("POST", "/v1/proxy", {"target": "https://corpus.arkforge.tech/entites/ENT-4001",
                                            "method": "GET", "payload": {}})
    assert list(vus[0][2]) == ["target", "method", "payload"]


def test_instrument_prend_la_base_du_corpus_en_parametre():
    vus = []

    def tl(methode, chemin, corps=None):
        vus.append(corps)
        return 200, {"proof": {"proof_id": "p"}, "service_response": {"body": {}},
                     "commitment_nonces": {"request_hash": "a", "response_hash": "b"},
                     "chain_data": {"request_hash": "c", "response_hash": "d"}}

    client.Instrument(tl, corpus="http://127.0.0.1:9").consulter("/x")
    assert vus[0]["target"] == "http://127.0.0.1:9/x"


def test_instrument_porte_le_statut_et_le_corps_d_un_refus_du_proxy():
    def tl(methode, chemin, corps=None):
        return 429, {"error": {"code": "rate_limited", "message": "Too many requests."}}

    with pytest.raises(client.ErreurInstrument) as e:
        client.Instrument(tl).consulter("/x")
    assert e.value.statut == 429 and e.value.reponse["error"]["code"] == "rate_limited"


def test_soumission_ne_divulgue_que_les_proof_id_cites():
    paires = lambda p: {"request_hash": {"nonce": p, "value": p}, "response_hash": {"nonce": p, "value": p}}  # noqa: E731
    rendu = {"verdict": "conforme", "assertions": [
        {"resource": "/entites/ENT-4001", "field": "/statut", "value": "active", "proof_ids": ["prf_a"]},
        {"resource": "/agrements/AGR-4001", "field": "/statut", "value": "actif", "proof_ids": ["prf_b", "prf_a"]}]}

    soum = client.soumission(1, "conformite", "conf-01", rendu, "did:key:zX", paires)

    assert set(soum["disclosures"]) == {"prf_a", "prf_b"}
    assert [a["id"] for a in soum["assertions"]] == ["a1", "a2"]
    assert soum["assertions"][1]["claim"] == {"resource": "/agrements/AGR-4001", "field": "/statut", "value": "actif"}
    assert soum["assertions"][1]["proof_ids"] == ["prf_b", "prf_a"]
    assert (soum["season"], soum["track"], soum["agent_did"]) == (1, "conformite", "did:key:zX")


def test_soumission_porte_la_narrative_seulement_si_fournie():
    rendu = {"verdict": "conforme", "assertions": []}
    sans = client.soumission(1, "conformite", "conf-01", rendu, "d", lambda p: {})
    avec = client.soumission(1, "conformite", "conf-01", {**rendu, "narrative": "texte"}, "d", lambda p: {})
    assert "narrative" not in sans and avec["narrative"] == "texte"


def test_etat_lit_le_service_de_saison(monde):
    assert client.etat("https://proveit.arkforge.tech")["ouverte"] is True
    assert monde.appels[0][:3] == ("GET", SAISON, "/v1/season/1")


def test_identite_rend_none_sur_cle_invalide(monde):
    assert client.identite(client.transport("mauvaise", "https://trust.arkforge.tech")) is None
    assert client.identite(client.transport(CLE_API, "https://trust.arkforge.tech"))["verified_did"] is None


def test_inscrire_lie_puis_reinscrit_sur_did_non_lie(monde):
    liaisons = []

    def lier_si_besoin():
        liaisons.append(1)
        monde.lie_a = "did:key:zLie"

    statut, rep = client.inscrire(CLE_API, {"agent": "a"}, lier_si_besoin=lier_si_besoin,
                                  base_saison="https://proveit.arkforge.tech")
    assert (statut, liaisons) == (201, [1])
    assert [a[2] for a in monde.appels if a[0] == "POST"] == ["/v1/season/1/enroll"] * 2
    assert rep["jeton"]


def test_inscrire_sans_declaration_envoie_un_corps_vide(monde):
    monde.lie_a = "did:key:zLie"
    client.inscrire(CLE_API, {}, lier_si_besoin=lambda: None, base_saison="https://proveit.arkforge.tech")
    assert monde.appels[0][3] is None


def test_rendre_envoie_le_jeton_en_bearer(monde):
    from monde import JETON
    statut, rep = client.rendre(JETON, {"task_id": "conf-01", "verdict": "conforme"}, "https://proveit.arkforge.tech")
    assert statut == 202 and monde.appels[0][4]["authorization"] == f"Bearer {JETON}"


def test_segment_did_conserve_la_casse_et_remplace_les_separateurs():
    assert client.segment_did("did:key:z6MkAbC") == "did-key-z6MkAbC"
    assert client.segment_did("did:web:exemple.org:agents:x") == "did-web-exemple.org-agents-x"


def test_les_urls_de_base_sont_des_parametres_jamais_lues_dans_l_environnement():
    source = "\n".join(p.read_text() for p in PAQUET.glob("*.py") if p.name != "cles.py")
    arbre = ast.parse(source)
    noms = {n.attr for n in ast.walk(arbre) if isinstance(n, ast.Attribute)}
    assert not noms & {"environ", "getenv"}, "seul cles.py lit l'environnement (dossier des clés)"


def test_paquet_n_importe_ni_scorer_ni_validation_ni_cible():
    interdits = {"scorer", "validation", "cible", "site", "saison", "corpus", "public", "killswitch", "trust_layer"}
    for fichier in PAQUET.glob("*.py"):
        for n in ast.walk(ast.parse(fichier.read_text())):
            noms = [a.name for a in n.names] if isinstance(n, ast.Import) else (
                [n.module or ""] if isinstance(n, ast.ImportFrom) and n.level == 0 else [])
            assert not [x for x in noms if x.split(".")[0] in interdits], (fichier.name, noms)
    code = ("import sys; sys.path.insert(0, sys.argv[1]); import proveit_mcp.serveur, proveit_mcp.__main__;"
            "print(sorted(m for m in sys.modules if m.split('.')[0] in %r))" % (sorted(interdits - {'site'}),))
    sortie = subprocess.run([sys.executable, "-c", code, str(PAQUET.parent)], capture_output=True, text=True,
                            timeout=60)
    assert sortie.returncode == 0, sortie.stderr
    assert json.loads(sortie.stdout.replace("'", '"')) == []


def test_lier_signe_en_base64url_avec_une_signature_qui_porte_des_tirets_et_des_soulignes(monde):
    """Graine fixe : sa signature du challenge du faux monde contient `-` et `_` en base64url (`+` et `/` en base64
    standard). Une signature tirée au hasard ne distinguerait pas les deux alphabets une fois sur deux."""
    cle = Ed25519PrivateKey.from_private_bytes(bytes(32))
    client.lier(client.transport(CLE_API, "https://trust.arkforge.tech"), cle, client.did_key(_brut(cle)))
    signature = [a for a in monde.appels if a[2].endswith("/confirm")][0][3]["signature"]
    assert "-" in signature and "_" in signature and "+" not in signature and "/" not in signature


def test_etat_refuse_un_statut_d_erreur_meme_avec_un_corps_qui_ressemble_a_un_etat(monkeypatch):
    monkeypatch.setattr(client, "appel", lambda *a, **k: (503, {"ouverte": True}))
    with pytest.raises(client.Echec):
        client.etat("https://proveit.arkforge.tech")


def test_instrument_fait_un_appel_au_proxy_par_lecture_sans_cache():
    vus = []

    def tl(methode, chemin, corps=None):
        vus.append(chemin)
        return 200, {"proof": {"proof_id": f"p{len(vus)}"}, "service_response": {"body": {}},
                     "commitment_nonces": {"request_hash": "a", "response_hash": "b"},
                     "chain_data": {"request_hash": "c", "response_hash": "d"}}

    i = client.Instrument(tl)
    assert i.consulter("/x")[0] != i.consulter("/x")[0]
    assert vus.count("/v1/proxy") == 2
