import hashlib
import json
import os
from pathlib import Path
import re
import stat


SEVERITIES = {"unknown": -1, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
LANGUAGES = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".go": "go",
    ".java": "java", ".cs": "csharp", ".rb": "ruby", ".rs": "rust",
    ".php": "php", ".swift": "swift", ".c": "c", ".cpp": "cpp",
    ".kt": "kotlin", ".scala": "scala", ".sh": "shell",
    ".pyw": "python", ".mjs": "javascript", ".cjs": "javascript",
    ".mts": "typescript", ".cts": "typescript", ".kts": "kotlin",
    ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hxx": "cpp",
    ".hh": "cpp", ".h": "c", ".rake": "ruby",
}
EXCLUDED_DIRS = {".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__", "security-report", ".cache", ".tools", "work", "build", "dist"}
SCANNER_CONFIGS = {".semgrepignore", ".gitleaks.toml", ".gitleaksignore", ".trivyignore", ".trivyignore.yaml", "trivy.yaml"}
MAX_FILE_SIZE = 10 * 1024 * 1024
MAX_TOTAL_SIZE = 512 * 1024 * 1024


def digest(value):
    return hashlib.sha256(value).hexdigest()


def clean(value):
    text = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", str(value))
    text = re.sub(r"(?i)(https?://)[^\s/@]+:[^\s/@]+@", r"\1[REDACTED]@", text)
    text = re.sub(r"(?i)\b(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*[\"']?[^\s\"',;]+", r"\1=[REDACTED]", text)
    return text[:4000]


def safe_location(raw, root):
    raw = str(raw).replace("\\", "/")
    if raw.startswith("file://"):
        from urllib.parse import unquote, urlparse
        raw = unquote(urlparse(raw).path)
    path = Path(raw)
    if path.is_absolute():
        try:
            raw = path.relative_to(root).as_posix()
        except ValueError:
            return "[external-location]"
    if ".." in Path(raw).parts:
        return "[external-location]"
    return clean(raw.removeprefix("./"))


def snapshot(target, destination, output):
    inventory = {"files": [], "languages": [], "exclusions": [], "bytes": 0}
    languages = set()
    for parent, directories, files in os.walk(target, followlinks=False):
        retained = []
        for name in sorted(directories):
            path = Path(parent) / name
            reason = None
            if path.is_symlink():
                reason = "symlink"
            elif name in EXCLUDED_DIRS or path == output or output in path.parents:
                reason = "excluded directory"
            if reason:
                inventory["exclusions"].append({"path": path.relative_to(target).as_posix(), "reason": reason})
            else:
                retained.append(name)
        directories[:] = retained
        for name in sorted(files):
            path = Path(parent) / name
            relative = path.relative_to(target)
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_SIZE or name in SCANNER_CONFIGS:
                inventory["exclusions"].append({"path": relative.as_posix(), "reason": "non-regular, oversized, or scanner configuration"})
                continue
            if len(inventory["files"]) >= 100000 or inventory["bytes"] + info.st_size > MAX_TOTAL_SIZE:
                raise ValueError("Repository exceeds snapshot limits (100,000 files / 512 MiB). Scan a smaller directory.")
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(descriptor, "rb") as handle:
                current = os.fstat(handle.fileno())
                if not stat.S_ISREG(current.st_mode) or (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
                    raise ValueError("Repository changed while creating snapshot.")
                data = handle.read(MAX_FILE_SIZE + 1)
            if len(data) > MAX_FILE_SIZE:
                raise ValueError("File changed size while creating snapshot.")
            copied = destination / relative
            copied.parent.mkdir(parents=True, exist_ok=True)
            copied.write_bytes(data)
            # Trusted CodeQL autobuilds may invoke scripts such as ./gradlew.
            # Retain executability without retaining group/world or special bits.
            copied.chmod(0o700 if info.st_mode & 0o111 else 0o600)
            inventory["bytes"] += len(data)
            inventory["files"].append({"path": relative.as_posix(), "sha256": digest(data)})
            if path.suffix in LANGUAGES:
                languages.add(LANGUAGES[path.suffix])
            if path.suffix == ".C":
                languages.add("cpp")
            if relative.parts[:2] == (".github", "workflows") and path.suffix in {".yml", ".yaml"}:
                languages.add("actions")
    inventory["languages"] = sorted(languages)
    inventory["snapshot_sha256"] = digest(json.dumps(inventory["files"], sort_keys=True).encode())
    return inventory


def finding(scanner, rule, title, severity, category, path, line=1, package=None, advisory=None, remediation="Review and remediate the reported condition.", instance=None):
    normalized = str(severity).lower()
    normalized = {"error": "high", "warning": "medium", "note": "info"}.get(normalized, normalized)
    if normalized not in SEVERITIES:
        normalized = "unknown"
    location = {"path": clean(path), "start_line": max(1, int(line or 1))}
    identity = [scanner, rule, category, location, package, advisory, instance]
    fingerprint = digest(json.dumps(identity, sort_keys=True).encode())
    return {
        "id": "RB-" + fingerprint[:16], "fingerprint": fingerprint, "fingerprint_version": "1",
        "title": clean(title), "description": clean(title), "category": category,
        "severity": normalized, "severity_basis": "native severity mapping v1",
        "confidence": "unknown", "locations": [location], "package": package,
        "identifiers": {"advisories": [clean(advisory)] if advisory else []},
        "observations": [{"scanner": scanner, "rule_id": clean(rule), "native_severity": clean(severity)}],
        "remediation": clean(remediation), "triage": {"state": "open"},
        "baseline_state": "new", "context": {"reachability": "unknown", "internet_exposure": "unknown"},
        "ai_enrichment": None,
    }


def unique_findings(findings):
    result = {}
    for item in findings:
        key = item["fingerprint"]
        if key in result:
            for observation in item["observations"]:
                if observation not in result[key]["observations"]:
                    result[key]["observations"].append(observation)
        else:
            result[key] = item
    return sorted(result.values(), key=lambda item: (-SEVERITIES[item["severity"]], item["id"]))


def evaluate(findings, runs, fail_on, new_only=False):
    failed = [item["id"] for item in findings if (item["severity"] == "unknown" or SEVERITIES[item["severity"]] >= SEVERITIES[fail_on]) and (not new_only or item["baseline_state"] == "new")]
    incomplete = any(run["required"] and run["status"] != "success" for run in runs)
    return {"execution_status": "incomplete" if incomplete else "complete", "policy_status": "fail" if failed else "pass", "failed_finding_ids": failed, "exit_code": 2 if incomplete else (1 if failed else 0)}
