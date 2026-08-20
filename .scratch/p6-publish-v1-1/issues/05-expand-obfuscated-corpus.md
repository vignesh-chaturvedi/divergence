# Review the final corpus labels and obfuscated expansion

Status: ready-for-human

Independently review all 110 final corpus fixtures before v1.1 publication. Verify every
truth label, attack-class or trap-family rationale, expected static capability set, and
provenance record. Give the expanded 30-sample obfuscated stratum an additional design
review: it contains inert MCP-server and agent-skill evasions plus matched benign controls
that share the same encodings and indirection patterns. Any correction must trigger
regeneration and review of the tracked benchmark evidence.

## Comments

The full candidate contains 110 synthetic fixtures: 50 positive and 60 benign/control. The
design in `corpus/obfuscated-design.yaml` was frozen before the obfuscated stratum grew to
30 fixtures: 25 positive simulations and five matched benign controls. Automated
validation, capability extraction, and the final Linux sandbox run are recorded locally.
The remaining all-corpus label/rationale review is a social gate that the author or an
agent cannot self-certify.
