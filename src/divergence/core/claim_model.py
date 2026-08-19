"""A model-backed claim extractor — wired, gated, and not exercised here.

§04 specifies a small local model with constrained decoding at temperature zero, cached by
content hash. This is that backend. It is **off unless explicitly enabled**:

    DIVERGENCE_CLAIM_BACKEND=model divergence scan <target>

Three reasons it is not the default, all of them the project's own rules:

- §09 requires benchmark runs to be reproducible offline. A backend that needs a running
  model server cannot be that.
- §11 names claim drift as the risk that makes the headline number meaningless. Sampling
  at temperature zero is *nearly* deterministic; a lexical extractor is deterministic by
  construction.
- No local runtime exists on the machine this was built on, so shipping it as the default
  would mean shipping an untested path.

The contract below — a fixed JSON schema, temperature zero, content-hash caching — is what
matters, and it holds whichever backend answers.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from divergence.core.claims import Claim, LexicalBackend, TriggerScope
from divergence.core.vocabulary import Capability

BACKEND_ENV = "DIVERGENCE_CLAIM_BACKEND"
ENDPOINT_ENV = "DIVERGENCE_CLAIM_ENDPOINT"
MODEL_ENV = "DIVERGENCE_CLAIM_MODEL"

DEFAULT_ENDPOINT = "http://127.0.0.1:11434/api/chat"
DEFAULT_MODEL = "qwen2.5:3b-instruct"
TIMEOUT_S = 60

# The fixed output shape from §04. Constrained decoding against this schema is what keeps
# the extractor from emitting prose — the same description must always produce the same
# set or the benchmark stops being reproducible.
CLAIM_SCHEMA = {
    "type": "object",
    "properties": {
        "reads": {"type": "boolean"},
        "writes": {"type": "boolean"},
        "network": {"type": "boolean"},
        "exec": {"type": "boolean"},
        "secrets": {"type": "boolean"},
        "side_effects": {"type": "boolean"},
        "instructs_other_tools": {"type": "boolean"},
        "trigger_scope": {"type": "string", "enum": ["narrow", "broad", "universal"]},
    },
    "required": [
        "reads", "writes", "network", "exec", "secrets",
        "side_effects", "instructs_other_tools", "trigger_scope",
    ],
}

_SYSTEM = (
    "You extract capability claims from software descriptions. You never judge whether an "
    "artifact is safe. Report only what the description says the artifact does. If the "
    "description does not mention a capability, report false for it. Answer with JSON "
    "matching the schema and nothing else."
)

_FIELD_TO_CAPABILITY = {
    "reads": Capability.FS_READ,
    "writes": Capability.FS_WRITE,
    "network": Capability.NET_OUTBOUND,
    "exec": Capability.PROC_SPAWN,
    "secrets": Capability.SECRETS_READ,
}


class ModelUnavailable(Exception):
    """The configured model backend cannot be reached."""


class ModelBackend:
    """Local model over an Ollama-compatible chat endpoint, constrained to CLAIM_SCHEMA."""

    name = "model"

    def __init__(self, endpoint: str | None = None, model: str | None = None) -> None:
        self.endpoint = endpoint or os.environ.get(ENDPOINT_ENV, DEFAULT_ENDPOINT)
        self.model = model or os.environ.get(MODEL_ENV, DEFAULT_MODEL)

    def probe(self) -> str:
        try:
            with urllib.request.urlopen(
                self.endpoint.replace("/api/chat", "/api/tags"), timeout=5
            ) as response:
                json.loads(response.read())
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
            raise ModelUnavailable(
                f"no model server at {self.endpoint} ({exc}). "
                "Start one, or leave the default lexical backend in place."
            ) from None
        return self.model

    def extract(self, text: str) -> Claim:
        payload = {
            "model": self.model,
            "format": CLAIM_SCHEMA,  # constrained decoding
            "stream": False,
            "options": {"temperature": 0, "top_p": 1, "seed": 0},
            "messages": [
                {"role": "system", "content": _SYSTEM},
                {"role": "user", "content": text[:6000]},
            ],
        }

        request = urllib.request.Request(
            self.endpoint,
            data=json.dumps(payload).encode(),
            headers={"content-type": "application/json"},
        )

        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT_S) as response:
                body = json.loads(response.read())
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
            raise ModelUnavailable(f"claim extraction failed: {exc}") from None

        content = (body.get("message") or {}).get("content", "{}")
        return self.to_claim(content, text)

    @staticmethod
    def to_claim(content: str, source_text: str) -> Claim:
        """Parse a constrained-decode response into a Claim.

        Split out from the request so it is testable with no model present — the same
        reasoning as the third-party scanner adapters in P0.
        """
        import hashlib

        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            data = {}

        capabilities = {
            cap for field, cap in _FIELD_TO_CAPABILITY.items() if data.get(field) is True
        }

        try:
            scope = TriggerScope(str(data.get("trigger_scope", "narrow")))
        except ValueError:
            scope = TriggerScope.NARROW

        return Claim(
            capabilities=frozenset(capabilities),
            denied=frozenset(),
            side_effects=bool(data.get("side_effects")),
            instructs_other_tools=bool(data.get("instructs_other_tools")),
            trigger_scope=scope,
            evidence={},
            source_hash=hashlib.sha256(source_text.encode()).hexdigest(),
            backend="model",
        )


def configured_backend():
    """The backend named by the environment, defaulting to lexical.

    Falls back loudly rather than silently: a scan that quietly degraded to a different
    claim extractor would produce numbers that cannot be compared to any other run.
    """
    choice = os.environ.get(BACKEND_ENV, "lexical").strip().lower()
    if choice in ("", "lexical"):
        return LexicalBackend()
    if choice == "model":
        backend = ModelBackend()
        backend.probe()
        return backend
    raise ValueError(f"unknown claim backend {choice!r}; expected 'lexical' or 'model'")
