# Brand — Divergence

_Status: active_

Divergence is a precision-first security analyzer for MCP servers and agent skills. It
measures the gap between what an artifact claims to do and what its implementation can do.

## Identity

The primary mark is the selected **Measured Gap** concept: two nearly matching geometric
contours form a `D`, separated by a small coral discrepancy signal. The inner contour is the
claim; the outer contour is observed behaviour; the gap is the finding.

Canonical project assets live in `website/public/brand/`:

- `divergence-mark.svg` — preferred icon and favicon
- `divergence-mark.png` — generated high-resolution icon
- `divergence-lockup-light.png` — horizontal lockup for light surfaces
- `divergence-lockup-dark.png` — horizontal lockup for dark surfaces

Do not stretch, recolour, outline, rotate, or separate the coral gap from the mark.

## Palette — Measured Signal

The selected B palette is technical and premium: deep navy for trust, green-cyan for
observation, and coral only for a measured discrepancy. Canonical CSS values use OKLCH;
hex values are interoperability fallbacks.

| Token | OKLCH | Hex | Use |
|---|---|---|---|
| Paper | `oklch(0.985 0.006 180)` | `#F7FAF8` | Light background |
| Surface | `oklch(0.955 0.018 175)` | `#EAF4F0` | Elevated light surface |
| Ink | `oklch(0.205 0.052 251)` | `#06182D` | Primary text and dark background |
| Signal | `oklch(0.555 0.102 195)` | `#0A7D7E` | Primary action and focus |
| Signal bright | `oklch(0.78 0.132 183)` | `#18C4C2` | Diagram traces and icon |
| Signal soft | `oklch(0.91 0.076 170)` | `#B8F2E4` | Highlight panels |
| Divergence | `oklch(0.66 0.178 29)` | `#D94B45` | Small discrepancy marks only |
| Muted ink | `oklch(0.47 0.036 220)` | `#52656F` | Secondary copy |

Verified light-mode contrast pairs:

- Ink / Paper: `16.99:1`
- Muted ink / Paper: `5.79:1`
- White / Signal: `4.94:1`
- Ink / Signal soft: `14.33:1`

Coral is an accent, not a body-text background. It must not carry small white text.

Dark mode derives from the same seeds:

- Background: `#04101F`
- Surface: `#0A2136`
- Foreground: `#F1F7F5`
- Primary: `#63DDD2`
- Muted foreground: `#B0C2C6`
- Divergence accent: `#FF786E`

## Typography

- Display and UI: **Space Grotesk**, with `Arial` and `sans-serif` fallbacks
- Code, evidence, labels, and numbers: **IBM Plex Mono**, with `ui-monospace` fallback
- Large campaign headlines may mix the two families once to emphasize the measured gap.

Use sentence case for headings. Use uppercase mono labels sparingly for evidence types,
release status, and metrics. Never set paragraphs in monospaced type.

## Voice

Divergence sounds exact, calm, and evidence-led. It explains the contradiction before it
states the severity. It prefers denominators (`0/35`) over unqualified percentages and
distinguishes candidate evidence from real-world guarantees.

The voice is technical without being theatrical. Avoid fear language, hacker clichés, and
claims that a clean scan proves safety. Explain opt-ins and platform limits in the same place
as the capability they qualify.

Calls to action are direct: “Run from source”, “Copy command”, “View benchmark evidence”.
Avoid vague labels such as “Learn more” when a specific destination exists.

## Usage rules

Do:

- Keep generous clear space around the mark.
- Use navy, paper, and green-cyan as the dominant system.
- Reserve coral for the actual gap, mismatch, or warning.
- Show benchmark numerators and denominators together.
- Support both light and dark surfaces.

Do not:

- Add shields, locks, bugs, skulls, or AI sparkles.
- Use red or coral as decoration unrelated to divergence.
- Present posture as a risk verdict.
- Claim the release-candidate PyPI command works before publication.
- Describe the project as a hosted scanner or runtime firewall.
