from __future__ import annotations

import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WEBSITE = ROOT / "website"


def test_website_toolchain_is_pinned_and_vercel_ready() -> None:
    package = json.loads((WEBSITE / "package.json").read_text())
    lock = json.loads((WEBSITE / "package-lock.json").read_text())

    assert package["private"] is True
    assert package["engines"]["node"] == "22.x"
    assert package["devDependencies"] == {
        "@astrojs/check": "0.9.10",
        "astro": "7.2.4",
        "typescript": "6.0.3",
    }
    assert lock["packages"][""]["devDependencies"] == package["devDependencies"]
    assert package["scripts"]["build"] == "astro build"


def test_website_brand_assets_and_release_caveats_are_present() -> None:
    for asset in (
        "divergence-mark.svg",
        "divergence-mark-dark.svg",
        "divergence-mark.png",
        "divergence-lockup-light.png",
        "divergence-lockup-dark.png",
    ):
        path = WEBSITE / "public" / "brand" / asset
        assert path.is_file()
        assert path.stat().st_size > 0

    page_text = " ".join(
        "\n".join(path.read_text() for path in sorted((WEBSITE / "src").rglob("*.astro"))).split()
    )
    assert "release candidate" in page_text.lower()
    assert "not published yet" in page_text.lower()
    assert "0/35" in page_text
    assert "49/50" in page_text
    assert "project-authored synthetic corpus" in page_text


def test_dedicated_website_job_builds_the_site() -> None:
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "divergence.yml").read_text())
    website_job = workflow["jobs"]["website"]
    website_steps = website_job["steps"]

    assert website_job["timeout-minutes"] == 10
    setup_node = next(
        step
        for step in website_steps
        if str(step.get("uses", "")).startswith("actions/setup-node@")
    )
    assert setup_node["uses"] == "actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020"
    assert setup_node["with"]["node-version"] == "22"
    assert setup_node["with"]["cache-dependency-path"] == "website/package-lock.json"

    website_step = next(
        step for step in website_steps if step.get("name") == "Check production build"
    )
    assert website_step["working-directory"] == "website"
    assert website_step["run"].splitlines() == ["npm ci", "npm run check", "npm run build"]

    scan_steps = workflow["jobs"]["scan"]["steps"]
    assert not any(
        str(step.get("uses", "")).startswith("actions/setup-node@") for step in scan_steps
    )


def test_website_accessibility_and_security_contracts() -> None:
    hero = (WEBSITE / "src" / "components" / "Hero.astro").read_text()
    quickstart = (WEBSITE / "src" / "components" / "Quickstart.astro").read_text()
    styles = (WEBSITE / "src" / "styles" / "global.css").read_text()
    vercel = json.loads((WEBSITE / "vercel.json").read_text())

    assert hero.count('aria-hidden="true"') >= 5
    assert hero.index("hero__content") < hero.index("evidence-card--claim")
    copy_labels = (
        "Copy run-from-source command",
        "Copy SARIF command",
        "Copy post-release uvx command",
    )
    assert all(f'aria-label="{label}"' in quickstart for label in copy_labels)
    assert ".quickstart {\n  background: var(--paper);\n  color: var(--ink);\n}" in styles
    assert "background: var(--surface-soft);" in styles
    assert "background: #061524;" in styles

    headers = {item["key"]: item["value"] for item in vercel["headers"][0]["headers"]}
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
    assert "object-src 'none'" in headers["Content-Security-Policy"]
