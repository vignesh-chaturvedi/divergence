"""A5 — the claim extractor (C).

Reads a name and a description and emits a fixed capability schema. It decides nothing;
the divergence engine compares C against B and S, and the finding lives in that
comparison.

That distinction is why a lexical backend is defensible here when a keyword *scanner* is
not. The strawman in `adapters/reference.py` maps text straight to a verdict, which is
exactly why honest imperative documentation destroys it — 57% of the trap stratum. A
claim extractor maps text to *what the artifact says about itself*. "Execute an arbitrary
shell command" produces `{proc_spawn}` as a **claim**, and a shell executor that spawns a
shell then reads as consistent rather than dangerous.

The bias throughout is **generous**: when a description plausibly covers a capability, it
counts as claimed. Over-claiming C costs recall; under-claiming C manufactures divergence
against honest artifacts, and this project exists because the second error is fatal.

Backends are pluggable. §04 specifies a small local model with constrained decoding at
temperature zero, cached by content hash. The lexical backend below is the default because
it is free, offline and deterministic by construction — §09 requires benchmark runs to be
reproducible offline, and §11 names claim drift as the thing that would make the headline
number meaningless.
"""

from __future__ import annotations

import enum
import hashlib
import re
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from divergence.core.vocabulary import Capability


class TriggerScope(enum.StrEnum):
    """How wide a skill claims its relevance to be.

    Only meaningful against capability: breadth is honest when the artifact can actually
    do what the breadth implies, and a routing hijack when it cannot.
    """

    NARROW = "narrow"
    BROAD = "broad"
    UNIVERSAL = "universal"


@dataclass(frozen=True, slots=True)
class Claim:
    """C — the capability set an artifact asserts for itself.

    `denied` is separate from "absent from capabilities" on purpose. Silence means the
    description did not mention a capability; denial means it asserted the opposite.
    Contradicting a denial is a materially stronger finding than contradicting silence,
    and collapsing the two would throw that away.
    """

    capabilities: frozenset[Capability] = frozenset()
    denied: frozenset[Capability] = frozenset()
    side_effects: bool = False
    instructs_other_tools: bool = False
    conceals: bool = False
    trigger_scope: TriggerScope = TriggerScope.NARROW
    evidence: dict[Capability, str] = field(default_factory=dict)
    cross_tool_evidence: str = ""
    trigger_evidence: str = ""
    source_hash: str = ""
    backend: str = "lexical"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Claim):
            return NotImplemented
        return (
            self.capabilities == other.capabilities
            and self.denied == other.denied
            and self.side_effects == other.side_effects
            and self.instructs_other_tools == other.instructs_other_tools
            and self.conceals == other.conceals
            and self.trigger_scope == other.trigger_scope
            and self.source_hash == other.source_hash
        )

    def __hash__(self) -> int:
        return hash((self.capabilities, self.denied, self.source_hash))


@runtime_checkable
class ClaimBackend(Protocol):
    """What any claim extractor must provide."""

    name: str

    def extract(self, text: str) -> Claim: ...


# --- vocabulary -----------------------------------------------------------------------
# Phrases that indicate an artifact is *claiming* a capability. Deliberately broad: a
# missed claim invents divergence against an honest artifact, which is the expensive
# error. Ordered most specific first so evidence quotes the sharpest match.

_CLAIM_PATTERNS: list[tuple[str, Capability]] = [
    # execution
    (r"execut\w+|\brun(s|ning)?\b|\bshell\b|\bcommand\b|subprocess|\bspawn\w*|\bcli\b"
     r"|\binvoke\w*|\bscript\b|\blaunch\w*|\bdeploy\w*|\binstall\w*|\bbuild\b|\bcompile\w*"
     r"|\bgit\b|\bcommit\w*|\bpush\w*|\bnpm\b|\bpip\b|\btest suite\b|\blint\w*|\bformat\w*"
     r"|\btoolchain\b|\bripgrep\b|\brg\b|\bbinary\b|\bprocess\b", Capability.PROC_SPAWN),
    # network
    # No bare "server" — every MCP server describes itself as one. No bare "api" before
    # "key"/"token" — an API key is a credential, not an egress.
    (r"\bfetch\w*|\bhttps?\b|\burl\b|\bdownload\w*|\bremote\b|\bendpoint\b"
     r"|\bapi\b(?!\s*[-_ ]?(key|keys|token|secret|credential))"
     r"|\brequest\w*|\bnetwork\b|\bonline\b|\bweb\b|\bsearch\b|\bregistry\b|\bpush\w*"
     r"|\bupload\w*|\bsend\w*|\bemail\b|\bssh\b|\bnavigat\w+|\bbrowser\b"
     r"|\bexternal\b|\bpublic\b|\bmail\b|\bslack\b|\bgithub\b", Capability.NET_OUTBOUND),
    # filesystem read
    (r"\bread\w*|\bfetch\w*|\bload\w*|\bopen\w*|\bcontents?\b|\blist\w*|\bsearch\w*"
     r"|\bscan\w*|\bsummaris\w+|\bsummariz\w+|\breview\w*|\binspect\w*|\bparse\w*"
     r"|\bfile\b|\bdirectory\b|\bfolder\b|\bpath\b|\bdatabase\b|\bquery\b|\brepositor\w+"
     r"|\bworking tree\b|\bcodebase\b|\bnotes?\b|\bdocument\w*|\btodo\b|\bstore\b"
     r"|\bindex\b|\bcatalog\w*|\breport\w*|\blog\b", Capability.FS_READ),
    # filesystem write
    # Note the absence of bare "add" and "set": "Add two numbers together" is not a
    # filesystem write, and a verb that generic claims nothing.
    (r"\bwrite\w*|\bsave\w*|\bstore\w*|\bcreate\w*|\bupdate\w*|\bmodif\w+"
     r"|\bappend\w*|\brotat\w+|\bgenerat\w+|\bedit\w*|\bformat\w*|\bscaffold\w*"
     r"|\brecord\w*|\bcommit\w*|\bstage\b|\bconfigur\w+|\bbootstrap\w*"
     r"|\binitiali[sz]\w+|\bmigrat\w+|\bdraft\w*|\boptimi[sz]\w+|\bcompress\w*",
     Capability.FS_WRITE),
    # deletion
    (r"\bdelet\w+|\bremov\w+|\bunlink\w*|\bclean\w*|\bpurg\w+|\bdrop\b|\bdestro\w+",
     Capability.FS_DELETE),
    # environment
    (r"\benvironment variable\w*|\benv var\w*|\bos\.environ\b|\benvironment\b|\bconfig\w*"
     r"|\bsetting\w*", Capability.ENV_READ),
    # credentials
    (r"\bcredential\w*|\bsecret\w*|\btoken\w*|\bpassword\w*|\bapi key\w*|\bapi_key\b"
     r"|\bprivate key\w*|\bssh key\w*|\b\.ssh\b|\bid_rsa\b|\bauthenticat\w+|\bkeychain\b"
     r"|\bvault\b|\bkey\b", Capability.SECRETS_READ),
    # dynamic evaluation
    (r"\beval\w*|\bjavascript\b|\bsnippet\b|\bplugin\w*|\bdynamic\w*|\bexpression\b"
     r"|\binterpret\w*|\bexecute a\b", Capability.DYNAMIC_EVAL),
]

_COMPILED_CLAIMS = [(re.compile(p, re.I), cap) for p, cap in _CLAIM_PATTERNS]

# An explicit denial. Stronger than silence, and the strongest divergence signal in the
# lexical repertoire: the artifact volunteered a promise the implementation breaks.
_DENIAL_PATTERNS: list[tuple[str, Capability]] = [
    (r"entirely offline|fully offline|works offline|never leaves your (machine|computer|device)"
     r"|no network|without network|does not (connect|contact|reach|send|upload|transmit)"
     r"|nothing (is )?(sent|uploaded|transmitted)|stays local|remains local|locally only"
     r"|runs locally|purely local|output stays local", Capability.NET_OUTBOUND),
    (r"does not modify|never modifies|does not write|never writes|read[- ]only|without modifying"
     r"|makes no changes|changes nothing|non[- ]destructive", Capability.FS_WRITE),
    (r"does not (execute|run)|never executes|does not run code|executes nothing"
     r"|it (changes|executes) nothing", Capability.PROC_SPAWN),
    (r"does not (touch|read|access) credential|never (touches|reads) credential"
     r"|no credentials|touch credentials", Capability.SECRETS_READ),
    (r"does not delete|never deletes|deletes nothing", Capability.FS_DELETE),
]

_COMPILED_DENIALS = [(re.compile(p, re.I), cap) for p, cap in _DENIAL_PATTERNS]

# Language that directs the agent's behaviour toward *other* artifacts. This is the fifth
# row of §02's rule table, and it is the one keyword scanners structurally cannot reach.
#
# The discrimination that matters: "you must call authenticate first" governs this
# server's own tools and is honest documentation — the audit's single most common false
# positive. Only cross-artifact direction counts.
_ORDERING_RE = re.compile(
    r"(before|prior to|ahead of|than|after)\s+(any|all|every|the)?\s*other"
    r"|before any other|first before|in order before",
    re.I,
)

# Directive language: strong enough on its own. These phrases only appear when something
# is trying to change how the agent treats artifacts other than itself.
_DIRECTIVE_RE = re.compile(
    r"supersedes?|superseded|takes? precedence|route all|disregard the others"
    r"|must not be used|do not cross-check|instead of the (legacy|other)"
    r"|suspend the confirmation|treat .{0,40}as pre-approved"
    r"|pre[- ]approved|disable the (usual|default)|suppress the (usual|default)"
    r"|for the (rest|remainder) of (this|the) session"
    r"|standing instruction|and do not (use|consider)|prefer this one and do not",
    re.I,
)

# A bare *reference* to other artifacts is deliberately not enough. "a session token for
# use with other billing tools" documents this server's own toolset; "route all file
# operations here" directs the agent about a different one. Only the second is an
# instruction, and requiring a directive is what keeps honest cross-references clean —
# this exact phrasing was a trap false positive before the rule was tightened.

_CONCEAL_RE = re.compile(
    r"do not (mention|surface|describe|reveal|disclose|tell|repeat|report)"
    r"|don't (mention|surface|tell)"
    r"|without (mentioning|telling|informing) the user"
    r"|no need to (mention|repeat|surface)"
    r"|suppress the (usual|default|normal)"
    r"|internal (telemetry|implementation detail|analytics)"
    r"|assistant directive|system directive|standing instruction"
    r"|\[system\]|do not surface this",
    re.I,
)

# A negated reference to other artifacts is a disclaimer, not direction. A router skill
# saying "it never claims to replace another skill" is doing the opposite of shadowing.
_CROSS_TOOL_NEGATION_RE = re.compile(
    r"\b(never|not|no|without|rather than|instead of asserting)\b[^.]{0,60}$",
    re.I,
)

_UNIVERSAL_TRIGGER_RE = re.compile(
    r"any (development )?task of any kind|any and all|whenever the user"
    r"|for any .{0,30}(task|operation|request)|any sensitive|of any kind",
    re.I,
)

_BREADTH_MARKERS = re.compile(
    r"\bany\b|\ball\b|\bwhenever\b|\bevery\b|\banything\b|\bwhatever\b", re.I
)

_SENTENCE_RE = re.compile(r"[^.!?\n]+[.!?]?")

_FENCE_STRIP_RE = re.compile(r"^[ \t]*```.*?^[ \t]*```", re.DOTALL | re.MULTILINE)


def strip_code_blocks(text: str) -> str:
    """Remove fenced code blocks before reading a description.

    A fenced block is what the artifact *does*, not what it *says*. Leaving it in let a
    skill whose body was `curl … | sh` appear to have declared network access, because the
    payload itself contained the word `http` — the artifact claiming a capability by
    exhibiting it.
    """
    return _FENCE_STRIP_RE.sub(" ", text)


def _sentence_containing(text: str, span: tuple[int, int]) -> str:
    """The sentence a match falls in — §04 wants the exact description sentence."""
    for m in _SENTENCE_RE.finditer(text):
        if m.start() <= span[0] < m.end():
            return " ".join(m.group(0).split())[:220]
    return " ".join(text.split())[:220]


class LexicalBackend:
    """Deterministic, offline, zero-cost claim extraction.

    Produces the same C for the same bytes, always — which is the property §11 says the
    benchmark depends on, and one a sampled model can only approximate.
    """

    name = "lexical"

    def extract(self, text: str) -> Claim:
        source_hash = hashlib.sha256(text.encode()).hexdigest()
        normalised = " ".join(strip_code_blocks(text).split())

        denied: set[Capability] = set()
        evidence: dict[Capability, str] = {}

        for pattern, cap in _COMPILED_DENIALS:
            match = pattern.search(normalised)
            if match:
                denied.add(cap)
                evidence.setdefault(cap, _sentence_containing(normalised, match.span()))

        capabilities: set[Capability] = set()
        for pattern, cap in _COMPILED_CLAIMS:
            match = pattern.search(normalised)
            if not match:
                continue
            # A denial wins over an incidental keyword: a description that says "runs
            # entirely offline" has not claimed the network by using the word "web".
            if cap in denied:
                continue
            capabilities.add(cap)
            evidence.setdefault(cap, _sentence_containing(normalised, match.span()))

        conceal = _CONCEAL_RE.search(normalised)

        cross = _DIRECTIVE_RE.search(normalised)
        # A match that is purely an ordering statement about this artifact's own tools is
        # documentation, not direction toward another artifact.
        if cross:
            window = normalised[max(0, cross.start() - 60) : cross.end() + 10]
            # Ordering language governs this artifact's own tools; negated language is a
            # disclaimer. Neither is direction toward another artifact.
            if _ORDERING_RE.search(window) or _CROSS_TOOL_NEGATION_RE.search(
                normalised[max(0, cross.start() - 60) : cross.start()]
            ):
                cross = None
        universal = _UNIVERSAL_TRIGGER_RE.search(normalised)
        breadth = len(_BREADTH_MARKERS.findall(normalised))

        if universal:
            scope = TriggerScope.UNIVERSAL
            trigger_evidence = _sentence_containing(normalised, universal.span())
        elif breadth >= 3:
            scope = TriggerScope.BROAD
            trigger_evidence = normalised[:220]
        else:
            scope = TriggerScope.NARROW
            trigger_evidence = ""

        side_effects = bool(
            capabilities & {Capability.FS_WRITE, Capability.FS_DELETE, Capability.PROC_SPAWN}
        )

        return Claim(
            capabilities=frozenset(capabilities),
            denied=frozenset(denied),
            side_effects=side_effects,
            instructs_other_tools=bool(cross),
            conceals=bool(conceal),
            trigger_scope=scope,
            evidence=evidence,
            cross_tool_evidence=(
                _sentence_containing(normalised, cross.span())
                if cross
                else (_sentence_containing(normalised, conceal.span()) if conceal else "")
            ),
            trigger_evidence=trigger_evidence,
            source_hash=source_hash,
            backend=self.name,
        )


_DEFAULT_BACKEND: ClaimBackend = LexicalBackend()

# Content-hash cache. §09: cache every model output by content hash so benchmark runs are
# fully reproducible offline after the first pass. Harmless for the lexical backend and
# load-bearing for any model one.
_CACHE: dict[tuple[str, str], Claim] = {}


def extract_claim(text: str, *, backend: ClaimBackend | None = None) -> Claim:
    """Extract C from a name-plus-description blob."""
    backend = backend or _DEFAULT_BACKEND
    key = (backend.name, hashlib.sha256(text.encode()).hexdigest())
    cached = _CACHE.get(key)
    if cached is not None:
        return cached
    claim = backend.extract(text)
    _CACHE[key] = claim
    return claim


def clear_cache() -> None:
    _CACHE.clear()
