"""A1 — target resolution.

Turns whatever the user points at into a list of artifacts to analyse.

P1 implements the offline sources: a directory, a skill bundle, and a local MCP client
config. The client config is the one that matters most in practice — "scan what I have
installed" is the product's actual entry point, and it is also the input the fleet
analyzers in P4 will need.

Remote specs (npm, PyPI, GitHub) raise rather than returning nothing. §10 makes
offline-by-default a feature: the configuration being asked about is itself sensitive,
so reaching the network is a decision the user makes explicitly, not a side effect of a
scan.
"""

from __future__ import annotations

import base64
import enum
import hashlib
import hmac
import json
import os
import re
import shutil
import stat
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from divergence.core.acquire import Artifact, acquire, register_trusted_provenance

# Keys used by the MCP client configs in circulation.
_SERVER_KEYS = ("mcpServers", "servers", "mcp_servers")

_REMOTE_SPEC = re.compile(r"^(npm|pypi|npx|uvx|github|https?|git\+https?):", re.I)
_CLIENT_CONFIG_NAMES = {"mcp.json", "mcp_config.json", "claude_desktop_config.json", "servers.json"}
_MAX_CONFIG_BYTES = 2_000_000
_MAX_REMOTE_METADATA = 5_000_000
_MAX_ARCHIVE_BYTES = 64_000_000
_MAX_EXTRACTED_BYTES = 256_000_000
_TRUSTED_REMOTE_HOSTS = {
    "registry.npmjs.org",
    "pypi.org",
    "files.pythonhosted.org",
    "api.github.com",
    "github.com",
    "codeload.github.com",
    "objects.githubusercontent.com",
}


class ResolutionError(Exception):
    """The target could not be turned into something analysable."""


class ResolutionStatus(enum.StrEnum):
    RESOLVED = "resolved"
    UNSUPPORTED = "unsupported"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class ResolvedTarget:
    """One artifact to analyse, plus how we got to it."""

    name: str
    source: str
    artifact: Artifact | None = None
    unresolved_reason: str = ""
    status: ResolutionStatus = ResolutionStatus.RESOLVED

    @property
    def resolved(self) -> bool:
        return self.artifact is not None


def _artifact_root_for_command(entry: dict, *, base: Path) -> Path | None:
    """Find a local directory for a configured server, if one exists.

    A config entry is a command line, not a path. When an argument points at a real file
    on disk, its directory is the artifact. When the command fetches from a registry at
    launch (`npx -y some-server`), there is nothing local to read and we say so instead
    of guessing.
    """
    raw_args = entry.get("args") or []
    if not isinstance(raw_args, list):
        return None
    for arg in raw_args:
        candidate = Path(os.path.expandvars(str(arg))).expanduser()
        if not candidate.is_absolute():
            candidate = base / candidate
        if candidate.is_file():
            return candidate.parent
        if candidate.is_dir():
            return candidate

    cwd = entry.get("cwd")
    if cwd:
        candidate = Path(os.path.expandvars(str(cwd))).expanduser()
        if not candidate.is_absolute():
            candidate = base / candidate
        if candidate.is_dir():
            return candidate

    command = str(entry.get("command", ""))
    if "/" in command or "\\" in command:
        candidate = Path(os.path.expandvars(command)).expanduser()
        if not candidate.is_absolute():
            candidate = base / candidate
        if candidate.is_file():
            return candidate.parent

    return None


def _server_block(data: dict) -> dict:
    """The server map from a client config, whichever key this client happens to use."""
    for key in _SERVER_KEYS:
        if isinstance(data.get(key), dict):
            return data[key]
    return {}


def _package_spec_for_command(entry: dict) -> str:
    """Translate only unambiguous package-launch command forms."""
    command = Path(str(entry.get("command", ""))).name.lower()
    raw_args = entry.get("args") or []
    if not isinstance(raw_args, list):
        return ""
    args = [str(arg) for arg in raw_args]
    scheme = ""
    if command == "npm":
        if not args or args.pop(0) not in {"exec", "x"}:
            return ""
        scheme = "npm"
    elif command in {"npx", "npmx"}:
        scheme = "npm"
    elif command == "uvx":
        scheme = "pypi"
    else:
        return ""

    harmless_flags = {"-y", "--yes", "--quiet", "-q", "--no-install"}
    while args and args[0] in harmless_flags:
        args.pop(0)
    if not args or args[0].startswith("-"):
        return ""
    package = args[0]
    if any(char.isspace() for char in package) or package.startswith((".", "/", "~")):
        return ""
    if scheme == "npm" and not re.fullmatch(
        r"(?:@[A-Za-z0-9_.-]+/)?[A-Za-z0-9_.-]+(?:@[A-Za-z0-9_.+~-]+)?", package
    ):
        return ""
    if scheme == "pypi" and not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_.-]*(?:==[A-Za-z0-9_.+~-]+)?", package
    ):
        return ""
    return f"{scheme}:{package}"


def _resolve_client_config(
    path: Path,
    data: dict,
    *,
    allow_remote: bool = False,
    cache_dir: Path | None = None,
) -> list[ResolvedTarget]:
    servers = _server_block(data)
    if not servers:
        raise ResolutionError(
            f"{path}: no MCP server block found (looked for {', '.join(_SERVER_KEYS)})"
        )

    targets: list[ResolvedTarget] = []
    for name, entry in sorted(servers.items()):
        if not isinstance(entry, dict):
            targets.append(
                ResolvedTarget(
                    name=str(name),
                    source=str(path),
                    unresolved_reason="client config entry must be an object",
                    status=ResolutionStatus.FAILED,
                )
            )
            continue

        root = _artifact_root_for_command(entry, base=path.parent)
        if root is None:
            command = " ".join(
                [str(entry.get("command", ""))] + [str(a) for a in entry.get("args") or []]
            )
            package_spec = _package_spec_for_command(entry)
            if allow_remote and package_spec:
                try:
                    remote = _resolve_remote(package_spec, cache_dir)
                except ResolutionError as exc:
                    targets.append(
                        ResolvedTarget(
                            name=str(name),
                            source=str(path),
                            unresolved_reason=str(exc),
                            status=ResolutionStatus.FAILED,
                        )
                    )
                    continue
                targets.append(
                    ResolvedTarget(
                        name=str(name),
                        source=str(path),
                        artifact=remote.artifact,
                    )
                )
                continue

            targets.append(
                ResolvedTarget(
                    name=name,
                    source=str(path),
                    unresolved_reason=(
                        f"no local artifact for `{command.strip()}` — the server is fetched "
                        "at launch; use --allow-network for an unambiguous npx/npm/uvx "
                        "package or provide a local artifact"
                    ),
                    status=ResolutionStatus.UNSUPPORTED,
                )
            )
            continue

        targets.append(ResolvedTarget(name=name, source=str(path), artifact=acquire(root)))

    return targets


def _read_client_config(path: Path) -> dict | None:
    """Parse a client config once, or return None when this is not one.

    Parsed here and handed to the resolver rather than re-read: the file is the user's
    real configuration, and reading it twice is both wasteful and a chance for the two
    reads to disagree.
    """
    if path.suffix != ".json":
        return None
    try:
        with path.open("rb") as handle:
            raw = handle.read(_MAX_CONFIG_BYTES + 1)
        if len(raw) > _MAX_CONFIG_BYTES:
            raise ResolutionError(f"{path}: config exceeds {_MAX_CONFIG_BYTES} bytes")
        data = json.loads(raw)
    except OSError:
        return None
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        if path.name.lower() in _CLIENT_CONFIG_NAMES:
            raise ResolutionError(f"{path}: malformed MCP client config ({exc})") from None
        return None
    if isinstance(data, dict) and any(k in data for k in _SERVER_KEYS):
        return data
    return None


def _validate_remote_url(url: str) -> None:
    parsed = urllib.parse.urlsplit(url)
    try:
        port = parsed.port
    except ValueError:
        raise ResolutionError(f"remote URL has an invalid port: {url}") from None
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or parsed.hostname.lower() not in _TRUSTED_REMOTE_HOSTS
    ):
        raise ResolutionError(f"remote URL is outside the trusted registry/CDN set: {url}")


class _ValidatingRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Validate Location before urllib opens the redirected connection."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        destination = urllib.parse.urljoin(req.full_url, newurl)
        _validate_remote_url(destination)
        return super().redirect_request(req, fp, code, msg, headers, destination)


def _fetch(url: str, *, limit: int, accept: str = "application/json") -> bytes:
    _validate_remote_url(url)
    request = urllib.request.Request(
        url,
        headers={"accept": accept, "user-agent": "divergence-static-acquirer/1"},
    )
    try:
        opener = urllib.request.build_opener(_ValidatingRedirectHandler())
        with opener.open(request, timeout=30) as response:
            _validate_remote_url(response.geturl())
            raw = response.read(limit + 1)
    except (urllib.error.URLError, OSError) as exc:
        raise ResolutionError(f"remote acquisition failed for {url}: {exc}") from None
    if len(raw) > limit:
        raise ResolutionError(f"remote response from {url} exceeds {limit} bytes")
    return raw


def _fetch_json(url: str) -> dict[str, Any]:
    try:
        data = json.loads(_fetch(url, limit=_MAX_REMOTE_METADATA))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ResolutionError(f"registry returned malformed JSON for {url}: {exc}") from None
    if not isinstance(data, dict):
        raise ResolutionError(f"registry returned a non-object response for {url}")
    return data


def _safe_extract(archive: Path, destination: Path) -> None:
    """Extract regular files only, with traversal, link, count and size guards."""
    destination.mkdir(parents=True, exist_ok=True)
    total = 0
    count = 0

    def target_for(name: str) -> Path:
        nonlocal count
        count += 1
        if count > 10_000:
            raise ResolutionError("remote archive contains more than 10000 entries")
        target = (destination / name).resolve()
        try:
            target.relative_to(destination.resolve())
        except ValueError:
            raise ResolutionError(f"remote archive contains unsafe path {name!r}") from None
        return target

    if tarfile.is_tarfile(archive):
        with tarfile.open(archive, "r:*") as bundle:
            for member in bundle:
                if member.issym() or member.islnk() or member.isdev():
                    continue
                target = target_for(member.name)
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile():
                    continue
                total += member.size
                if total > _MAX_EXTRACTED_BYTES:
                    raise ResolutionError("remote archive expands beyond the size limit")
                target.parent.mkdir(parents=True, exist_ok=True)
                source = bundle.extractfile(member)
                if source is None:
                    continue
                with source, target.open("wb") as output:
                    shutil.copyfileobj(source, output, length=128 * 1024)
        return

    try:
        with zipfile.ZipFile(archive) as bundle:
            for member in bundle.infolist():
                mode = member.external_attr >> 16
                if mode and (mode & 0o170000) == 0o120000:
                    continue
                target = target_for(member.filename)
                if member.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                total += member.file_size
                if total > _MAX_EXTRACTED_BYTES:
                    raise ResolutionError("remote archive expands beyond the size limit")
                target.parent.mkdir(parents=True, exist_ok=True)
                with bundle.open(member) as source, target.open("wb") as output:
                    shutil.copyfileobj(source, output, length=128 * 1024)
    except zipfile.BadZipFile:
        raise ResolutionError("remote package is not a supported tar or zip archive") from None


def _split_npm_spec(spec: str) -> tuple[str, str]:
    if spec.startswith("@"):
        marker = spec.rfind("@")
        return (spec[:marker], spec[marker + 1 :]) if marker > 0 else (spec, "")
    if "@" in spec:
        return tuple(spec.rsplit("@", 1))  # type: ignore[return-value]
    return spec, ""


def _github_spec_from_url(target: str) -> str:
    parsed = urllib.parse.urlsplit(target)
    if parsed.scheme != "https" or parsed.hostname not in {"github.com", "www.github.com"}:
        raise ResolutionError(
            "only https://github.com/owner/repository[/tree/ref] URLs are supported"
        )
    if parsed.query or parsed.fragment:
        raise ResolutionError("GitHub acquisition URLs must not contain a query or fragment")
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 2:
        raise ResolutionError("GitHub URL must include owner and repository")
    repo = parts[1].removesuffix(".git")
    spec = f"{parts[0]}/{repo}"
    if len(parts) >= 4 and parts[2] == "tree":
        spec += "@" + "/".join(parts[3:])
    elif len(parts) > 2:
        raise ResolutionError("unsupported GitHub URL path; expected /tree/<ref>")
    return "github:" + spec


def _tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ResolutionError(f"cache contains symbolic link {path}")
        mode = path.stat(follow_symlinks=False).st_mode
        relative = path.relative_to(root).as_posix().encode()
        digest.update(b"D" if stat.S_ISDIR(mode) else b"F")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            raise ResolutionError(f"cache contains special file {path}")
        size = path.stat(follow_symlinks=False).st_size
        digest.update(size.to_bytes(8, "big"))
        with path.open("rb") as handle:
            while chunk := handle.read(128 * 1024):
                digest.update(chunk)
    return digest.hexdigest()


def _remote_descriptor(target: str) -> tuple[str, dict[str, Any]]:
    scheme, spec = target.split(":", 1)
    scheme = scheme.lower()
    if scheme in {"npm", "npx"}:
        package, requested = _split_npm_spec(spec)
        doc = _fetch_json("https://registry.npmjs.org/" + urllib.parse.quote(package, safe="@"))
        version = requested or str((doc.get("dist-tags") or {}).get("latest", ""))
        release = (doc.get("versions") or {}).get(version)
        if not isinstance(release, dict):
            raise ResolutionError(f"npm package {package!r} has no version {version!r}")
        archive_url = str((release.get("dist") or {}).get("tarball", ""))
        author = release.get("author") or doc.get("author") or ""
        if isinstance(author, dict):
            author = author.get("name", "")
        metadata = {
            "name": package,
            "version": version,
            "author": str(author),
            "signed": True if (release.get("dist") or {}).get("signatures") else None,
            "first_published": str((doc.get("time") or {}).get("created", "")),
            "archive_integrity": str((release.get("dist") or {}).get("integrity", "")),
            "archive_shasum": str((release.get("dist") or {}).get("shasum", "")),
        }
        return archive_url, metadata

    if scheme in {"pypi", "uvx"}:
        package, _, requested = spec.partition("==")
        suffix = f"/{requested}" if requested else ""
        doc = _fetch_json(f"https://pypi.org/pypi/{urllib.parse.quote(package) + suffix}/json")
        info = doc.get("info") or {}
        version = str(info.get("version", requested))
        urls = doc.get("urls") or []
        candidate = next(
            (
                item
                for item in urls
                if isinstance(item, dict) and item.get("packagetype") == "sdist"
            ),
            next((item for item in urls if isinstance(item, dict)), {}),
        )
        metadata = {
            "name": str(info.get("name", package)),
            "version": version,
            "author": str(info.get("author", "")),
            "signed": None,
            "first_published": str(candidate.get("upload_time_iso_8601", "")),
            "archive_sha256": str((candidate.get("digests") or {}).get("sha256", "")),
        }
        return str(candidate.get("url", "")), metadata

    if scheme == "github":
        repo, marker, ref = spec.rpartition("@")
        if not marker:
            repo, ref = spec, "HEAD"
        if repo.count("/") != 1:
            raise ResolutionError("github target must be github:owner/repository[@ref]")
        api = "https://api.github.com/repos/" + repo
        doc = _fetch_json(api)
        metadata = {
            "name": str(doc.get("name", repo.rsplit("/", 1)[-1])),
            "version": ref,
            "author": str((doc.get("owner") or {}).get("login", "")),
            "signed": None,
            "first_published": str(doc.get("created_at", "")),
        }
        return f"{api}/tarball/{urllib.parse.quote(ref, safe='')}", metadata

    raise ResolutionError(
        f"remote scheme {scheme!r} is unsupported; use npm:, pypi:, uvx:, npx:, or github:"
    )


def _resolve_remote(target: str, cache_dir: Path | None) -> ResolvedTarget:
    archive_url, metadata = _remote_descriptor(target)
    _validate_remote_url(archive_url)
    archive_bytes = _fetch(archive_url, limit=_MAX_ARCHIVE_BYTES, accept="*/*")
    archive_digest = hashlib.sha256(archive_bytes).hexdigest()
    expected_digest = str(metadata.get("archive_sha256", ""))
    if expected_digest and expected_digest.lower() != archive_digest:
        raise ResolutionError("downloaded package does not match the registry SHA-256")
    integrity = str(metadata.get("archive_integrity", ""))
    if integrity:
        sha512_values = [
            token.partition("-")[2].split("?", 1)[0]
            for token in integrity.split()
            if token.lower().startswith("sha512-")
        ]
        if sha512_values:
            actual = base64.b64encode(hashlib.sha512(archive_bytes).digest()).decode()
            if not any(hmac.compare_digest(actual, expected) for expected in sha512_values):
                raise ResolutionError("downloaded npm package does not match dist.integrity")
        elif not metadata.get("archive_shasum"):
            raise ResolutionError("npm package uses an unsupported dist.integrity algorithm")
    shasum = str(metadata.get("archive_shasum", ""))
    if shasum and not hmac.compare_digest(hashlib.sha1(archive_bytes).hexdigest(), shasum.lower()):
        raise ResolutionError("downloaded npm package does not match dist.shasum")
    cache = (cache_dir or Path.home() / ".cache" / "divergence" / "acquired").expanduser()
    # Content-addressed: an unpinned ``latest`` target cannot reuse bytes from an older
    # version while receiving fresh provenance.
    key = archive_digest
    destination = cache / key
    metadata_path = cache / f"{key}.json"
    cache.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f"{key[:12]}-", dir=cache))
    try:
        archive = staging / "package.archive"
        archive.write_bytes(archive_bytes)
        extracted = staging / "extracted"
        _safe_extract(archive, extracted)
        candidates = [p for p in extracted.iterdir() if p.is_dir()]
        root = candidates[0] if len(candidates) == 1 else extracted
        fresh_tree_digest = _tree_digest(root)
        cache_record = {
            "archive_sha256": archive_digest,
            "archive_url": archive_url,
            "tree_sha256": fresh_tree_digest,
            "version": str(metadata.get("version", "")),
        }

        if destination.exists():
            if destination.is_symlink() or not destination.is_dir():
                raise ResolutionError("remote cache entry has an unsafe type")
            if metadata_path.is_symlink() or not metadata_path.is_file():
                raise ResolutionError("remote cache entry has no trusted validation record")
            try:
                cached_record = json.loads(metadata_path.read_text())
            except (OSError, json.JSONDecodeError, UnicodeDecodeError):
                raise ResolutionError("remote cache validation record is malformed") from None
            if cached_record != cache_record:
                raise ResolutionError("remote cache validation record does not match acquisition")
            if _tree_digest(destination) != fresh_tree_digest:
                raise ResolutionError(
                    "remote cache entry failed content validation; use a fresh cache directory"
                )
        else:
            os.replace(root, destination)
            metadata_path.write_text(json.dumps(cache_record, sort_keys=True))
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    register_trusted_provenance(destination, metadata)
    artifact = acquire(destination, registry_metadata=metadata)
    return ResolvedTarget(
        name=str(metadata.get("name") or target),
        source=target,
        artifact=artifact,
    )


def resolve(
    target: str,
    *,
    allow_remote: bool = False,
    cache_dir: Path | None = None,
) -> list[ResolvedTarget]:
    """Resolve a target string into artifacts. Never executes anything it resolves."""
    if target.startswith("https://"):
        target = _github_spec_from_url(target)

    if _REMOTE_SPEC.match(target):
        if not allow_remote:
            raise ResolutionError(
                f"remote target {target!r} requires explicit --allow-network opt-in"
            )
        return [_resolve_remote(target, cache_dir)]

    path = Path(target).expanduser()
    if not path.exists():
        raise ResolutionError(f"{target}: no such file or directory")

    if path.is_file():
        config = _read_client_config(path)
        if config is not None:
            return _resolve_client_config(
                path, config, allow_remote=allow_remote, cache_dir=cache_dir
            )
        # A lone file — analyse the bundle it sits in.
        path = path.parent

    return [ResolvedTarget(name=path.name, source=str(path), artifact=acquire(path))]
