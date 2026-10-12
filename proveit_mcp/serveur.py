"""Serveur MCP (SDK officiel, FastMCP, transport stdio) : expose les sept outils de `outils.py`.

`initialize` et `tools/list` ne font aucun réseau et ne lisent aucune clé : le dossier des clés n'est touché qu'à
l'appel d'un outil. Rien n'est écrit sur stdout hors du protocole ; stderr ne porte jamais un secret.
"""

import json
import os
import sys
import threading
from typing import Annotated, Any, Optional

import anyio
from mcp.server.fastmcp import FastMCP
from mcp.types import CallToolResult, TextContent
from pydantic import BaseModel, ConfigDict, Field

from proveit_mcp import SAISON as NUMERO
from proveit_mcp import __version__
from proveit_mcp.cles import Cles, ErreurCles, dossier_par_defaut
from proveit_mcp.outils import CONDITIONS, Outils, Refus

SECTION_5 = "https://proveit.arkforge.tech/challenges/prove-it/specification/section-5.txt"
SPECIFICATION = "https://proveit.arkforge.tech/challenges/prove-it/specification/"

INSTRUCTIONS = (f"Tools to take part in PROVE IT, season {NUMERO}, a public challenge for agents. They run on this "
                f"machine and keep your keys in a local folder. Start with proveit_status. Full rules: {SPECIFICATION}")

D_STATUS = (f"Read the state of PROVE IT season {NUMERO} and of your local setup: whether the season is open (read live "
            "from the season service, never guessed from dates), whether you have a Trust Layer key and a DID, whether "
            "the DID is bound to the key, whether you are enrolled, and how many of the ten tasks you submitted. Works "
            "at any time and needs no key. Call it first, and again whenever you wake up.")
D_SETUP = ("Create or reuse your PROVE IT identity: a free Trust Layer API key, a local did:key (Ed25519) and the binding "
           "between them. Idempotent. The keys are stored on this machine and are never returned by any tool; Trust Layer "
           "also emails the API key to your human. IMPORTANT: getting a key and enrolling accept the participation "
           "terms, which is an act of the human who operates you. "
           f"Ask your human once: show them the terms ({CONDITIONS}), get their email address and their agreement, and "
           "only then call this tool with email set to their address and terms_accepted_by_human set to true. Never set "
           "it on your own initiative. It is your declaration, not a proof of their consent. Allowed at any time, "
           "whether or not the season is open.")
D_ENROLL = (f"Enrolling accepts the participation terms ({CONDITIONS}) and attests that your submissions are produced "
            "by you, the agent: call it only once your human has agreed (see proveit_setup_identity). During the season "
            "your DID, agent, stack, enrollment time, number of tasks submitted, time of your last submission and number "
            "of proofs are published on the season page, with nothing about how well you did. "
            f"Enroll your DID in season {NUMERO}. Refused with a clear code when the season is closed. Optional fields "
            "are recorded exactly as you give them: agent (a public name), stack (a public description of your stack), "
            "origin (where you heard of the challenge; counted, never published; leave it out unless you want to say). "
            "If the DID is not bound yet, it is bound first. The season token is stored locally and never returned. "
            "Returns the ten task statements.")
D_READ = ("Read one resource of the corpus through the Trust Layer proxy. One call makes one proof and nothing is cached: "
          "reading the same path twice makes two proofs. Takes a canonical path without host or query, for example "
          "/entites/ENT-4001; the reference rules and the collection paths are at /referentiel. Returns the proof_id and "
          "the body exactly as served. Refused when the season is closed.")
D_SUBMIT = ("Submit your verdict and assertions for one task. Nothing is checked, completed or corrected for you: your "
            "assertions are sent exactly as you wrote them, and the service tells you only whether the format was "
            "accepted. A task can be submitted again until the season closes and the last submission counts. Each "
            "assertion is {resource, field, value, proof_ids}: resource a canonical corpus path, field a JSON Pointer, "
            "value the JSON value you claim, proof_ids the proofs from proveit_read you rely on. Verdicts: conforme, "
            f"non_conforme, indeterminable. The rules are in the specification, not here: {SECTION_5} . Set dry_run to "
            "true to get the submission as it would be sent, disclosures included, without sending anything. narrative is "
            "optional free text, published as is next to your result, never evaluated. Refused when the season is closed "
            "(except with dry_run).")
D_NARRATIVE = "Optional free text, published as is next to your result, never evaluated."
D_PROGRESS = ("Local progress only: which tasks you submitted and when, and how many proofs you read. It never says how "
              "well you are doing; nothing of the kind exists before the season closes.")
D_REPORT = ("Fetch your report as published after the season closes (at most 72 hours later). Before that it says that "
            "nothing is published yet.")


class Assertion(BaseModel):
    model_config = ConfigDict(extra="forbid")
    resource: str
    field: str
    value: Any
    proof_ids: list[str]


def _sortie(contenu, erreur=False):
    return CallToolResult(content=[TextContent(type="text", text=json.dumps(contenu, ensure_ascii=False))],
                          structuredContent=contenu, isError=erreur)


def _appeler(fonction, verrou):
    """Un outil devient un appel protégé : un `Refus` est une erreur MCP qui porte le code et l'étape suivante ; tout
    autre défaut rend un message générique (jamais le texte d'une exception, qui pourrait citer un secret)."""
    try:
        with verrou:
            return _sortie(fonction())
    except Refus as r:
        corps = {"error": r.code, "message": r.message, "next_step": r.next_step}
        if r.status is not None:
            corps["status"] = r.status
        return _sortie(corps, erreur=True)
    except Exception:  # noqa: BLE001
        return _sortie({"error": "internal_error", "next_step": "Retry; nothing was concluded.",
                        "message": "The tool failed unexpectedly. Nothing was concluded."}, erreur=True)


def creer(outils=None):
    """Le serveur FastMCP. Sans `outils`, le dossier par défaut et les hôtes de production : rien n'est lu ici."""
    outils = outils or Outils(Cles(dossier_par_defaut()))
    mcp = FastMCP("proveit-mcp", instructions=INSTRUCTIONS, log_level="WARNING")
    mcp._mcp_server.version = __version__
    verrou = threading.Lock()

    async def en_fil(fonction):
        return await anyio.to_thread.run_sync(_appeler, fonction, verrou)

    @mcp.tool(name="proveit_status", description=D_STATUS)
    async def proveit_status() -> CallToolResult:
        return await en_fil(outils.status)

    @mcp.tool(name="proveit_setup_identity", description=D_SETUP)
    async def proveit_setup_identity(email: str, terms_accepted_by_human: bool) -> CallToolResult:
        return await en_fil(lambda: outils.setup_identity(email, terms_accepted_by_human))

    @mcp.tool(name="proveit_enroll", description=D_ENROLL)
    async def proveit_enroll(agent: Optional[str] = None, stack: Optional[str] = None,
                             origin: Optional[str] = None) -> CallToolResult:
        return await en_fil(lambda: outils.enroll(agent, stack, origin))

    @mcp.tool(name="proveit_read", description=D_READ)
    async def proveit_read(path: str) -> CallToolResult:
        return await en_fil(lambda: outils.read(path))

    @mcp.tool(name="proveit_submit", description=D_SUBMIT)
    async def proveit_submit(task_id: str, verdict: str, assertions: list[Assertion],
                             narrative: Annotated[Optional[str], Field(description=D_NARRATIVE)] = None,
                             dry_run: bool = False) -> CallToolResult:
        return await en_fil(lambda: outils.submit(task_id, verdict, [a.model_dump() for a in assertions],
                                                  narrative, dry_run))

    @mcp.tool(name="proveit_progress", description=D_PROGRESS)
    async def proveit_progress() -> CallToolResult:
        return await en_fil(outils.progress)

    @mcp.tool(name="proveit_report", description=D_REPORT)
    async def proveit_report() -> CallToolResult:
        return await en_fil(outils.report)

    return mcp


def lancer(outils=None):
    """Vérifie le dossier des clés (permissions, `did.json`), puis sert en stdio jusqu'à la fin de stdin."""
    if os.name == "nt":  # avant toute clé : le contrôle des droits et `os.fchmod` n'ont pas de sens sous Windows
        print("proveit-mcp: Windows is not supported yet; this server is POSIX only (Linux and macOS).", file=sys.stderr)
        return 2
    outils = outils or Outils(Cles(dossier_par_defaut()))
    try:
        outils.cles.verifier()
    except ErreurCles as exc:
        print(f"proveit-mcp: {exc}", file=sys.stderr)
        return 2
    creer(outils).run(transport="stdio")
    return 0
