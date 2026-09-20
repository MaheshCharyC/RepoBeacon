"""CodeQL bundle provisioning and local language planning."""

import hashlib
import json
import os
from pathlib import Path
import platform
import re
import tarfile
import tempfile
import time
from urllib.error import URLError
from urllib.request import Request, urlopen
import uuid

from .runner import ScannerError, execute


FAMILIES = {
    "python": "python", "javascript": "javascript", "typescript": "javascript",
    "c": "cpp", "cpp": "cpp", "csharp": "csharp", "java": "java",
    "kotlin": "java", "go": "go", "ruby": "ruby", "rust": "rust",
    "swift": "swift", "actions": "actions",
}
API = "https://api.github.com/repos/github/"


def installation_root():
    return Path.home() / ".cache" / "repobeacon" / "codeql"


def managed_executable(root=None):
    root = root or installation_root()
    try:
        entry = json.loads((root / "active.json").read_text())["directory"]
        if not isinstance(entry, str) or not re.fullmatch(r"bundle-[a-f0-9]{32}", entry):
            return None
        binary = root / entry / "codeql" / ("codeql.exe" if os.name == "nt" else "codeql")
        return str(binary) if binary.is_file() and os.access(binary, os.X_OK) else None
    except (OSError, ValueError, KeyError, TypeError):
        return None


def bundle_platform():
    system, machine = platform.system(), platform.machine().lower()
    if system == "Darwin" and machine in {"arm64", "aarch64", "x86_64", "amd64"}:
        return "osx64"
    if system == "Linux":
        if machine in {"arm64", "aarch64"}:
            return "linux-arm64"
        if machine in {"x86_64", "amd64"}:
            return "linux64"
    if system == "Windows" and machine in {"amd64", "x86_64"}:
        return "win64"
    raise ScannerError(f"No supported CodeQL bundle for {system}/{machine}.")


def release_json(url):
    request = Request(url, headers={"User-Agent": "RepoBeacon", "Accept": "application/vnd.github+json"})
    with urlopen(request, timeout=30) as response:
        data = response.read(4 * 1024 * 1024 + 1)
    if len(data) > 4 * 1024 * 1024:
        raise ScannerError("CodeQL release metadata exceeds the size limit.")
    result = json.loads(data)
    if not isinstance(result, dict):
        raise ScannerError("CodeQL release metadata is not an object.")
    return result


def latest_bundle():
    release = release_json(API + "codeql-cli-binaries/releases/latest")
    match = re.fullmatch(r"v(\d+\.\d+\.\d+)", release.get("tag_name", ""))
    if not match or release.get("draft") or release.get("prerelease"):
        raise ScannerError("GitHub did not return a stable CodeQL release.")
    version = match[1]
    tag = "codeql-bundle-v" + version
    bundle = release_json(API + "codeql-action/releases/tags/" + tag)
    if bundle.get("tag_name") != tag or bundle.get("draft") or bundle.get("prerelease"):
        raise ScannerError("The latest stable CodeQL bundle is not available yet.")
    filename = "codeql-bundle-" + bundle_platform() + ".tar.gz"
    url = f"https://github.com/github/codeql-action/releases/download/{tag}/{filename}"
    for asset in bundle.get("assets", []):
        if asset.get("name") == filename:
            checksum = asset.get("digest") or ""
            size = asset.get("size", 0)
            if asset.get("browser_download_url") != url or not re.fullmatch(r"sha256:[a-f0-9]{64}", checksum):
                raise ScannerError("CodeQL bundle URL or SHA-256 metadata is invalid.")
            if not isinstance(size, int) or not 0 < size <= 4 * 1024**3:
                raise ScannerError("CodeQL bundle size is invalid.")
            return version, {"url": url, "sha256": checksum[7:], "size": size}
    raise ScannerError("The latest CodeQL bundle is unavailable for this platform.")


def download_bundle(asset, destination):
    checksum = hashlib.sha256()
    received = 0
    deadline = time.monotonic() + 1800
    next_progress = time.monotonic() + 10
    request = Request(asset["url"], headers={"User-Agent": "RepoBeacon"})
    with urlopen(request, timeout=60) as response, destination.open("wb") as output:
        while chunk := response.read(1024 * 1024):
            received += len(chunk)
            if received > asset["size"] or time.monotonic() > deadline:
                raise ScannerError("CodeQL download exceeded its size or time limit.")
            checksum.update(chunk)
            output.write(chunk)
            if time.monotonic() >= next_progress:
                print(f"CodeQL download: {received * 100 // asset['size']}%", flush=True)
                next_progress = time.monotonic() + 10
    if received != asset["size"] or checksum.hexdigest() != asset["sha256"]:
        raise ScannerError("CodeQL bundle checksum or size verification failed.")


def extract_bundle(archive, destination):
    if not hasattr(tarfile, "data_filter"):
        raise ScannerError("Update Python to a current patch release for safe CodeQL archive extraction.")
    with tarfile.open(archive, "r:gz") as bundle:
        # The data filter prevents paths and links escaping the staging directory.
        bundle.extractall(destination, filter="data")


def verify_codeql(binary):
    with tempfile.TemporaryDirectory(prefix="repobeacon-codeql-check-") as directory:
        home = Path(directory)
        version = json.loads(execute([binary, "version", "--format=json"], home, home, 60))["version"]
        languages = json.loads(execute([binary, "resolve", "languages", "--format=json"], home, home, 60))
        packs = execute([binary, "resolve", "packs"], home, home, 60)
    if not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ScannerError("CodeQL returned an invalid version.")
    if not isinstance(languages, dict) or not languages:
        raise ScannerError("CodeQL has no usable language extractors.")
    available = {name for name, paths in languages.items() if isinstance(paths, list) and len(paths) == 1}
    expected = available.intersection(FAMILIES.values())
    query_packs = set(re.findall(r"codeql/([a-z]+)-queries\b", packs))
    if not expected or not expected.issubset(query_packs):
        raise ScannerError("CodeQL query packs are missing; a complete bundle is required.")
    return {"version": version, "languages": sorted(available)}


def ensure_codeql(binary=None, root=None, update=True):
    """Verify an existing CLI or atomically select a verified official bundle."""
    root = root or installation_root()
    binary = binary or managed_executable(root)
    current = None
    if binary:
        try:
            current = verify_codeql(binary)
        except (ScannerError, OSError, ValueError, KeyError, TypeError):
            if not update:
                raise ScannerError("CodeQL verification failed; rerun without --no-install-tools to repair it.")
    if not update:
        if current is None:
            raise ScannerError("CodeQL is missing; rerun without --no-install-tools to install it.")
        return binary, current
    print("Checking the latest stable CodeQL bundle...", flush=True)
    try:
        version, asset = latest_bundle()
        if current and current["version"] == version:
            print(f"CodeQL {version} verified and up to date.", flush=True)
            return binary, current
        root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".install-", dir=root) as directory:
            staging = Path(directory)
            archive = staging / "bundle.tar.gz"
            extracted = staging / "extracted"
            print(f"Installing CodeQL {version} and query packs ({asset['size'] // (1024 * 1024)} MiB)...", flush=True)
            download_bundle(asset, archive)
            print("CodeQL checksum verified; extracting and checking the bundle...", flush=True)
            extract_bundle(archive, extracted)
            relative = Path("codeql") / ("codeql.exe" if os.name == "nt" else "codeql")
            verified = verify_codeql(str(extracted / relative))
            if verified["version"] != version:
                raise ScannerError("Downloaded CodeQL version does not match the latest release.")
            directory_name = "bundle-" + uuid.uuid4().hex
            destination = root / directory_name
            extracted.rename(destination)
            pointer = staging / "active.json"
            pointer.write_text(json.dumps({"directory": directory_name, "version": version, "sha256": asset["sha256"]}))
            os.replace(pointer, root / "active.json")
            print(f"CodeQL {version} installed and verified.", flush=True)
            return str(destination / relative), verified
    except (URLError, OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        raise ScannerError("CodeQL setup failed. Check network access, disk space, and platform prerequisites. Use --no-install-tools to use an existing verified installation without checking for updates.") from error


def language_plan(languages):
    detected = set(languages)
    families = sorted({FAMILIES[name] for name in detected if name in FAMILIES})
    plan = []
    for family in families:
        mode = "autobuild" if family in {"go", "swift"} or (family == "java" and "kotlin" in detected) else "none"
        plan.append({"language": family, "build_mode": mode, "requires_build_permission": mode == "autobuild" or family == "rust"})
    return plan
