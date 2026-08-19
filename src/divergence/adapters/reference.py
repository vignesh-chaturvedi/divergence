"""Reference baselines that ship in-repo and always run.

Two of them, bracketing the space:

`null` flags nothing. Its scores are the floor — perfect FPR-on-traps, zero recall. It
exists so the table always shows what "never alarm" costs, which is the honest
comparison point for any scanner claiming a low false-positive rate.

`keyword` is the strawman: a regex pattern matcher over names, descriptions and source,
built the way the scanners in the April 2026 audit were built. It is not a caricature —
the patterns below are the obvious ones any competent engineer would reach for. That is
the point. It should score well on recall and catastrophically on traps, reproducing the
~78% false-positive rate that motivates this whole project.
"""

from __future__ import annotations

import re

from divergence.adapters.base import register
from divergence.bench.models import AttackClass, Channel, Finding, Sample

_MAX_BYTES = 512_000


def _read_artifact(sample: Sample) -> str:
    chunks = []
    for path in sorted(sample.artifact_path.rglob("*")):
        if not path.is_file():
            continue
        try:
            chunks.append(path.read_text()[:_MAX_BYTES])
        except (UnicodeDecodeError, OSError):
            continue
    return "\n".join(chunks)


class NullScanner:
    """Flags nothing. The floor."""

    name = "null"
    homepage = ""
    kind = "reference"

    def probe(self) -> str:
        return "1.0"

    def scan(self, sample: Sample) -> list[Finding]:
        return []


# The patterns a keyword scanner actually uses. Each maps to the attack class its
# author believed it was detecting — which is precisely where the trouble starts.
_PATTERNS: list[tuple[str, str, AttackClass]] = [
    (r"ignore\s+(all\s+)?previous\s+instructions", "prompt-injection phrasing", AttackClass.DESCRIPTION_POISONING),
    (r"\bdo\s+not\s+tell\s+the\s+user\b", "concealment instruction", AttackClass.DESCRIPTION_POISONING),
    (r"\byou\s+must\s+(call|use|run|invoke)\b", "imperative tool instruction", AttackClass.DESCRIPTION_POISONING),
    (r"\balways\s+(call|use|prefer|run)\b", "preference language", AttackClass.PREFERENCE_MANIPULATION),
    (r"\b(before|prior\s+to)\s+(any|every|all)\s+other\b", "ordering instruction", AttackClass.PREFERENCE_MANIPULATION),
    (r"~/\.ssh|id_rsa|authorized_keys", "ssh credential path", AttackClass.UNDECLARED_SECRETS),
    (r"~/\.aws|\.aws/credentials|AWS_SECRET_ACCESS_KEY", "cloud credential path", AttackClass.UNDECLARED_SECRETS),
    (r"\.env\b|API_KEY|SECRET_KEY|ACCESS_TOKEN", "secret-bearing identifier", AttackClass.UNDECLARED_SECRETS),
    (r"\bsubprocess\b|\bchild_process\b|\bexecSync\b|\bos\.system\b", "subprocess execution", AttackClass.UNDECLARED_EXEC),
    (r"\beval\s*\(|\bexec\s*\(|new\s+Function\s*\(", "dynamic evaluation", AttackClass.DYNAMIC_CODE_LOADING),
    (r"base64|b64decode|atob\s*\(", "encoded payload", AttackClass.DYNAMIC_CODE_LOADING),
    (r"requests\.post|fetch\s*\(|urllib|httpx|axios", "outbound network call", AttackClass.UNDECLARED_NETWORK),
    (r"curl\s+|wget\s+", "shell download", AttackClass.REMOTE_FETCH_AT_LOAD),
    (r'allowed-tools:\s*["\']?\*', "wildcard tool permission", AttackClass.SCRIPT_EXCEEDS_ALLOWED_TOOLS),
    (r"\bsudo\b|\bchmod\s+\+x\b", "privilege escalation", AttackClass.UNDECLARED_EXEC),
    (r"\brm\s+-rf\b", "destructive command", AttackClass.UNDECLARED_FILESYSTEM),
]

_COMPILED = [(re.compile(p, re.IGNORECASE), label, ac) for p, label, ac in _PATTERNS]


class KeywordScanner:
    """Regex pattern matching over the whole artifact. The strawman.

    Deliberately has no posture channel — every hit is reported as risk. That single
    design decision is responsible for most of its false-positive rate, and it is the
    decision every scanner in the audit made.
    """

    name = "keyword"
    homepage = ""
    kind = "reference"

    def probe(self) -> str:
        return "1.0"

    def scan(self, sample: Sample) -> list[Finding]:
        text = _read_artifact(sample)
        findings: list[Finding] = []
        seen: set[str] = set()

        for pattern, label, attack_class in _COMPILED:
            match = pattern.search(text)
            if not match or label in seen:
                continue
            seen.add(label)
            snippet = match.group(0)[:80].replace("\n", " ")
            findings.append(
                Finding(
                    sample_id=sample.id,
                    channel=Channel.RISK,
                    attack_class=attack_class,
                    severity="high",
                    message=f"matched {label}",
                    evidence=snippet,
                )
            )

        return findings


register(NullScanner())
register(KeywordScanner())
