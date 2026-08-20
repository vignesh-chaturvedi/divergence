"""Release wiring that unit tests can verify without publishing or using the network."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from types import SimpleNamespace

import yaml

import divergence.adapters.semgrep_scanner as semgrep_module
from divergence import __version__
from divergence.adapters.divergence import DivergenceScanner
from divergence.adapters.external import SNYK_AGENT_SCAN_SPEC
from divergence.adapters.mcp_shield import PACKAGE_SPEC
from divergence.adapters.semgrep_scanner import (
    RULESET_ENV,
    SEMGREP_SPEC,
    SemgrepAdapter,
    ruleset_sha256,
)
from divergence.bench.cli import DEFAULT_CORPUS

ROOT = Path(__file__).resolve().parents[1]


def test_distribution_identity_and_commands_are_stable():
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())
    project = pyproject["project"]
    assert project["name"] == "divergence-mcp"
    assert project["dynamic"] == ["version"]
    assert project["scripts"]["divergence"] == "divergence.cli:main"
    assert __version__ == "1.1.0"

    assert pyproject["build-system"]["requires"] == ["hatchling==1.32.0"]
    assert "hatchling==1.32.0" in project["optional-dependencies"]["dev"]
    assert set(project["dependencies"]) == {
        "pyyaml==6.0.3",
        "tree-sitter==0.26.0",
        "tree-sitter-bash==0.25.1",
        "tree-sitter-python==0.25.0",
        "tree-sitter-typescript==0.23.2",
    }

    force_include = pyproject["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"]
    assert force_include["LICENSE"] == "divergence/data/corpus/LICENSE"

    sdist = pyproject["tool"]["hatch"]["build"]["targets"]["sdist"]
    for excluded in (
        "/.coverage",
        "/.scratch",
        "/.superstack",
        "/build-plan/reports",
        "/website",
    ):
        assert excluded in sdist["exclude"]
    assert sdist["force-include"]["benchmarks/v1.1"] == "benchmarks/v1.1"


def test_default_benchmark_dataset_exists_outside_cwd(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    assert DEFAULT_CORPUS.is_absolute()
    assert (DEFAULT_CORPUS / "mcp_server" / "obfuscated").is_dir()
    manifest = yaml.safe_load((DEFAULT_CORPUS.parent / "dataset.yaml").read_text())
    assert manifest["provenance"]["origin"] == "synthetic"
    assert manifest["provenance"]["derived_samples"] == 0
    assert manifest["truth"] == {
        "total": 110,
        "malicious": 50,
        "benign_or_control": 60,
    }
    assert (DEFAULT_CORPUS.parent / "obfuscated-design.yaml").is_file()


def test_lock_matches_exact_release_runtime_and_build_backend():
    lock = tomllib.loads((ROOT / "uv.lock").read_text())
    packages = {package["name"]: package for package in lock["package"]}
    expected = {
        "hatchling": "1.32.0",
        "pyyaml": "6.0.3",
        "tree-sitter": "0.26.0",
        "tree-sitter-bash": "0.25.1",
        "tree-sitter-python": "0.25.0",
        "tree-sitter-typescript": "0.23.2",
    }
    assert {name: packages[name]["version"] for name in expected} == expected

    requires_dist = packages["divergence-mcp"]["metadata"]["requires-dist"]
    runtime = {
        requirement["name"]: requirement["specifier"]
        for requirement in requires_dist
        if "marker" not in requirement
    }
    assert runtime == {
        "pyyaml": "==6.0.3",
        "tree-sitter": "==0.26.0",
        "tree-sitter-bash": "==0.25.1",
        "tree-sitter-python": "==0.25.0",
        "tree-sitter-typescript": "==0.23.2",
    }
    assert {
        requirement["name"]: requirement["specifier"]
        for requirement in requires_dist
        if requirement.get("marker") == "extra == 'dev'"
    }["hatchling"] == "==1.32.0"


def test_external_package_specs_are_pinned():
    assert SNYK_AGENT_SCAN_SPEC == "snyk-agent-scan@0.6.0"
    assert PACKAGE_SPEC == "mcp-shield@1.0.4"
    assert SEMGREP_SPEC == "semgrep@1.173.0"
    pins = f"{SNYK_AGENT_SCAN_SPEC} {PACKAGE_SPEC} {SEMGREP_SPEC}"
    assert "latest" not in pins


def test_local_semgrep_ruleset_hash_is_path_independent(tmp_path):
    first, second = tmp_path / "first", tmp_path / "second"
    for root in (first, second):
        (root / "nested").mkdir(parents=True)
        (root / "rule.yml").write_text("rules: []\n")
        (root / "nested" / "extra.yml").write_text("rules: []\n")
    assert ruleset_sha256(first) == ruleset_sha256(second)


def test_semgrep_probe_uses_exact_package_and_local_rules(monkeypatch, tmp_path):
    rules = tmp_path / "rules.yml"
    rules.write_text("rules: []\n")
    monkeypatch.setenv("DIVERGENCE_ALLOW_EXTERNAL", "1")
    monkeypatch.setenv(RULESET_ENV, str(rules))
    monkeypatch.setattr(semgrep_module.shutil, "which", lambda command: "/usr/bin/uvx")
    calls: list[list[str]] = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout="1.173.0\n", stderr="")

    monkeypatch.setattr(semgrep_module.subprocess, "run", fake_run)
    adapter = SemgrepAdapter()

    assert adapter.probe().startswith("1.173.0; rules=")
    assert calls == [["uvx", SEMGREP_SPEC, "--version"]]
    provenance = adapter.provenance()
    assert provenance["package_spec"] == SEMGREP_SPEC
    assert provenance["scanner_command"][:3] == ["uvx", SEMGREP_SPEC, "scan"]
    assert provenance["ruleset_sha256"] == ruleset_sha256(rules)
    assert provenance["ruleset"] == rules.name
    assert str(tmp_path) not in str(provenance)


def test_reference_scanner_provenance_names_the_command():
    provenance = DivergenceScanner(fleet=True).provenance()
    assert provenance["distribution"] == "divergence-mcp"
    assert provenance["scanner_command"] == ["divergence", "fleet", "<artifact>"]


def test_composite_action_keeps_untrusted_inputs_out_of_shell_expressions():
    action = yaml.safe_load((ROOT / "action" / "action.yml").read_text())
    assert action["inputs"]["distribution"]["default"] == "divergence-mcp==1.1.0"
    scan = next(step for step in action["runs"]["steps"] if step.get("id") == "scan")
    script = scan["run"]

    assert "${{ inputs." not in script
    assert set(scan["env"]) == {
        "INPUT_ALLOW_PARTIAL",
        "INPUT_DISTRIBUTION",
        "INPUT_FAIL_ON_RISK",
        "INPUT_FLEET",
        "INPUT_SARIF_FILE",
        "INPUT_TARGET",
    }
    assert script.index('ARGS+=("--allow-partial")') < script.index('ARGS+=("$VERB"')
    assert script.index('ARGS+=("--fail-on-risk")') < script.index('ARGS+=("$VERB"')
    assert '"--sarif=$INPUT_SARIF_FILE"' in script
    assert 'uvx --from="$INPUT_DISTRIBUTION" divergence "${ARGS[@]}"' in script


def test_ci_actions_are_commit_pinned_and_release_candidate_cannot_publish():
    workflows = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
    external_uses: list[str] = []
    action_files = [*workflows, ROOT / "action" / "action.yml"]
    for action_file in action_files:
        for line in action_file.read_text().splitlines():
            stripped = line.strip()
            if stripped.startswith("uses:") and "uses: ./" not in stripped:
                external_uses.append(stripped.removeprefix("uses:").strip())

    assert external_uses
    assert all(re.fullmatch(r"[^@]+@[0-9a-f]{40}(?:\s+#.*)?", use) for use in external_uses)

    ci = (ROOT / ".github" / "workflows" / "divergence.yml").read_text()
    for required in (
        "ruff format --check",
        "pyright",
        "--cov-branch",
        "cargo fmt --check",
        "cargo clippy --locked",
        "cargo test --locked",
        "sandbox-gate --require-available",
    ):
        assert required in ci

    fleet_command = next(
        line.strip()
        for line in ci.splitlines()
        if "uv run divergence" in line and " fleet " in line
    )
    assert fleet_command.startswith("uv run divergence --allow-partial fleet ")

    candidate = (ROOT / ".github" / "workflows" / "release-candidate.yml").read_text()
    assert "id-token: write" not in candidate
    assert "pypa/gh-action-pypi-publish" not in candidate
    assert "uv publish" not in candidate
    assert "divergence-sandbox-1.1.0-linux-x86_64.binary.sha256" in candidate
    assert "DIVERGENCE_ALLOW_DYNAMIC" in candidate
    assert "out/bench-dynamic.json" in candidate
    assert "pip-audit@2.10.1" in candidate
    assert "cargo-audit --version 0.22.2 --locked" in candidate
    assert "twine@7.0.0 check dist/*" in candidate
    assert "dist && sha256sum *.whl *.tar.gz > SHA256SUMS" in candidate
    assert "persist-credentials: false" in candidate
    assert "install -m644 LICENSE" in candidate
    assert "Validate source-distribution contents" in candidate
    assert "Validate wheel dependency metadata" in candidate
    assert "Verify reproducible Python artifacts" in candidate
    assert candidate.count("uv build --clear --no-sources") == 2
    assert "/build-plan/reports/" in candidate
    assert "uv build --clear --no-sources" in candidate
    for deterministic_archive_token in (
        "SOURCE_DATE_EPOCH",
        "--sort=name",
        '--mtime="@$SOURCE_DATE_EPOCH"',
        "--owner=0 --group=0",
        "--numeric-owner",
        "gzip -n",
        "divergence-sandbox-repro.tar.gz",
        "cmp out/divergence-sandbox-1.1.0-linux-x86_64.tar.gz",
    ):
        assert deterministic_archive_token in candidate

    makefile = (ROOT / "Makefile").read_text()
    assert "uv build --clear --no-sources" in ci
    assert "uv build --clear --no-sources" in makefile


def test_scan_issue_template_accepts_successful_independent_candidate_runs():
    template = yaml.safe_load((ROOT / ".github" / "ISSUE_TEMPLATE" / "scan-report.yml").read_text())
    fields = {item.get("id"): item for item in template["body"] if item.get("id")}

    assert (
        "Successful independent candidate run / general feedback"
        in fields["result"]["attributes"]["options"]
    )
    for field in ("candidate_sha256", "environment", "target", "outcome"):
        assert fields[field]["validations"]["required"] is True

    config = yaml.safe_load((ROOT / ".github" / "ISSUE_TEMPLATE" / "config.yml").read_text())
    assert config["blank_issues_enabled"] is False
