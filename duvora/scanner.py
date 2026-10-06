"""Artifact scanning before deploy: OCI images (config and layers) and model files, checked for unsafe
deserialization (pickle opcodes that import code), Keras Lambda layers, embedded secrets and risky image
configuration. Pure standard library; scans run in a background thread and are kept as evidence.

`duvoractl scan --file` runs the same checks locally without contacting the server."""
import gzip
import io
import json
import os
import pickletools
import re
import secrets
import ssl
import tarfile
import threading
import time
import urllib.error
import urllib.request
import zipfile
from urllib.parse import urlsplit

from .common import Problem, canonical
from .inspection import SECRETS
from .netra import LOOPBACK, NoRedirect

SCHEMA = "CREATE TABLE IF NOT EXISTS scans(id TEXT PRIMARY KEY, target TEXT NOT NULL, created REAL NOT NULL, body TEXT NOT NULL);"
MODEL_EXT = (".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt", ".joblib", ".npy", ".npz", ".keras", ".h5", ".safetensors", ".gguf", ".onnx", ".mar")
TEXT_EXT = (".env", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".py", ".sh", ".txt", ".properties", ".pem", ".key")
TEXT_MAX = 1024 * 1024
MODEL_MAX = 256 * 1024 * 1024
SAFE_GLOBALS = {("collections", "OrderedDict"), ("torch._utils", "_rebuild_tensor_v2"), ("torch._utils", "_rebuild_parameter"),
                ("torch", "FloatStorage"), ("torch", "HalfStorage"), ("torch", "BFloat16Storage"), ("torch", "LongStorage"),
                ("torch", "IntStorage"), ("torch", "ByteStorage"), ("torch", "BoolStorage"), ("torch", "Size"),
                ("numpy.core.multiarray", "_reconstruct"), ("numpy", "ndarray"), ("numpy", "dtype"),
                ("numpy.core.multiarray", "scalar"), ("_codecs", "encode"), ("torch._utils", "_rebuild_tensor"),
                ("builtins", "set"), ("builtins", "frozenset"), ("builtins", "slice"), ("builtins", "complex")}
DANGEROUS_MODULES = {"os", "posix", "nt", "subprocess", "sys", "socket", "shutil", "runpy", "importlib", "pty", "webbrowser",
                     "ctypes", "code", "codeop", "commands", "pickle", "_pickle", "marshal", "multiprocessing", "asyncio",
                     "requests", "urllib", "http", "ftplib", "telnetlib", "smtplib", "pdb", "timeit", "platform", "tempfile"}
DANGEROUS_BUILTINS = {"eval", "exec", "compile", "open", "__import__", "getattr", "setattr", "delattr", "globals", "locals",
                      "vars", "input", "breakpoint", "memoryview"}
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def finding(severity, kind, detail, path=""):
    return {"severity": severity, "kind": kind, "detail": detail[:300], "path": path[:300]}


def pickle_globals(data):
    """(module, name) pairs a pickle would import, following GLOBAL and STACK_GLOBAL."""
    out, strings = [], []
    try:
        for op, arg, _ in pickletools.genops(io.BytesIO(data)):
            if op.name in {"SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE", "SHORT_BINSTRING", "BINSTRING", "STRING"}:
                strings.append(arg if isinstance(arg, str) else str(arg))
            elif op.name in {"GLOBAL", "INST"}:
                module, _, attr = str(arg).partition(" ")
                out.append((module, attr))
            elif op.name == "STACK_GLOBAL" and len(strings) >= 2:
                out.append((strings[-2], strings[-1]))
            elif op.name in {"MEMOIZE", "BINPUT", "LONG_BINPUT", "PUT", "BINGET", "LONG_BINGET", "GET"}:
                continue
    except Exception as exc:  # truncated or malformed: report what was seen
        out.append(("<parse-error>", type(exc).__name__))
    return out


def scan_pickle(data, path=""):
    findings = []
    for module, attr in pickle_globals(data):
        root = module.split(".")[0]
        if module == "<parse-error>":
            findings.append(finding("low", "malformed-pickle", f"Pickle stream could not be fully parsed ({attr})", path))
        elif (module, attr) in SAFE_GLOBALS or module.startswith("torch.") and attr.endswith("Storage"):
            continue
        elif root in DANGEROUS_MODULES or (module in {"builtins", "__builtin__"} and attr in DANGEROUS_BUILTINS):
            findings.append(finding("critical", "unsafe-deserialization", f"Pickle imports {module}.{attr} when loaded (code execution)", path))
        else:
            findings.append(finding("medium", "pickle-import", f"Pickle imports {module}.{attr}; review before loading", path))
    if not findings:
        findings.append(finding("info", "pickle-format", "Pickle format: loading runs code by design; prefer safetensors", path))
    return dedupe(findings)


def scan_secrets(text, path=""):
    out = []
    for regex, label in SECRETS:
        if regex.search(text):
            out.append(finding("high", "secret", f"{label} embedded in the artifact", path))
    return out


def scan_zip(data, path=""):
    findings = []
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return [finding("low", "malformed-archive", "Not a valid zip archive", path)]
    for info in z.infolist()[:2000]:
        inner = f"{path}!{info.filename}"
        if info.file_size > MODEL_MAX:
            findings.append(finding("info", "skipped", f"{info.filename} larger than the scan limit", inner))
            continue
        lower = info.filename.lower()
        if lower.endswith((".pkl", "data.pkl")) or lower.endswith(".pickle"):
            findings += scan_pickle(z.read(info), inner)
        elif lower.endswith("config.json") and path.lower().endswith(".keras"):
            try:
                config = z.read(info).decode("utf-8", "replace")
            except KeyError:
                continue
            if re.search(r'"class_name"\s*:\s*"Lambda"', config):
                findings.append(finding("high", "keras-lambda", "Keras model contains a Lambda layer (arbitrary Python on load)", inner))
        elif lower.endswith(TEXT_EXT) and info.file_size <= TEXT_MAX:
            findings += scan_secrets(z.read(info).decode("utf-8", "replace"), inner)
    return findings


def scan_bytes(path, data):
    """Findings for one artifact, by magic bytes first and extension second."""
    lower = path.lower()
    if data[:2] == b"PK":
        return scan_zip(data, path)
    if data[:1] == b"\x80" or lower.endswith((".pkl", ".pickle", ".joblib")):
        return scan_pickle(data, path)
    if data[:4] == b"GGUF":
        return [finding("info", "safe-format", "GGUF weights (no code on load)", path)]
    if lower.endswith(".safetensors"):
        try:
            size = int.from_bytes(data[:8], "little")
            header = json.loads(data[8:8 + size])
            if not isinstance(header, dict):
                raise ValueError
        except (ValueError, UnicodeDecodeError):
            return [finding("medium", "malformed-safetensors", "safetensors header does not parse", path)]
        return [finding("info", "safe-format", "safetensors weights (no code on load)", path)]
    if data[:8] == b"\x89HDF\r\n\x1a\n":
        text = data.decode("latin-1")
        if '"class_name": "Lambda"' in text or '"class_name":"Lambda"' in text:
            return [finding("high", "keras-lambda", "HDF5 Keras model contains a Lambda layer", path)]
        return [finding("info", "hdf5", "HDF5 model; Lambda layers would run code on load", path)]
    if lower.endswith(".npy") and b"'descr': '|O'" in data[:256]:
        return [finding("high", "numpy-object", "NumPy object array: loading with allow_pickle runs code", path)]
    if lower.endswith(TEXT_EXT) or lower.rsplit("/", 1)[-1] in {"dockerfile", ".env"}:
        return scan_secrets(data[:TEXT_MAX].decode("utf-8", "replace"), path)
    return []


def scan_tar(fileobj, findings, limit):
    """Scan an (optionally gzipped) tar stream: model files and small text files."""
    scanned = 0
    with tarfile.open(fileobj=fileobj, mode="r|*") as tar:
        for member in tar:
            if not member.isfile():
                continue
            path = member.name
            lower = path.lower()
            if member.mode & 0o4000 and member.uid == 0:
                findings.append(finding("low", "setuid", "setuid-root binary in the image", path))
            wanted = lower.endswith(MODEL_EXT) and member.size <= MODEL_MAX or (lower.endswith(TEXT_EXT) or lower.endswith("/.env")) and member.size <= TEXT_MAX
            if not wanted or "/site-packages/" in lower or "/dist-packages/" in lower or lower.startswith(("usr/share/", "usr/lib/")):
                continue
            if scanned + member.size > limit:
                findings.append(finding("info", "skipped", "Scan size limit reached; remaining files not scanned", path))
                break
            f = tar.extractfile(member)
            if f:
                data = f.read()
                scanned += len(data)
                findings += [x for x in scan_bytes(path, data) if not (x["kind"] == "pickle-format" and not lower.endswith(MODEL_EXT))]
    return scanned


def dedupe(findings):
    seen, out = set(), []
    for f in findings:
        key = (f["kind"], f["detail"], f["path"])
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def verdict(findings):
    worst = max((SEVERITY_RANK[f["severity"]] for f in findings), default=0)
    return "failed" if worst >= SEVERITY_RANK["high"] else "passed"


def parse_image(ref):
    """registry, repository, digest for a digest-pinned image reference."""
    m = re.fullmatch(r"(?:(?P<registry>[a-z0-9.-]+(?::\d+)?)/)?(?P<repo>[a-z0-9._/-]+?)(?::[\w.-]+)?@(?P<digest>sha256:[a-f0-9]{64})", ref or "")
    if not m:
        raise Problem("Image must be pinned to a sha256 digest, for example ghcr.io/org/svc@sha256:…")
    registry, repo = m.group("registry"), m.group("repo")
    if not registry or "." not in registry and ":" not in registry and registry != "localhost":
        registry, repo = "registry-1.docker.io", f"{registry}/{repo}" if registry else repo
        if "/" not in repo:
            repo = f"library/{repo}"
    return registry, repo, m.group("digest")


class Registry:
    """Anonymous (or DUVORA_REGISTRY_TOKEN) OCI distribution client: manifests and blobs."""

    ACCEPT = ("application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, "
              "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json")

    def __init__(self, registry, repo, insecure=False):
        self.base = f"{'http' if insecure else 'https'}://{registry}/v2/{repo}"
        self.repo, self.token = repo, os.environ.get("DUVORA_REGISTRY_TOKEN", "")
        ctx = ssl.create_default_context(cafile=os.environ.get("DUVORA_SCAN_CA_FILE") or None)
        self.opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))

    def _open(self, url, accept, retry=True):
        headers = {"Accept": accept}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        try:
            return self.opener.open(urllib.request.Request(url, headers=headers), timeout=60)
        except urllib.error.HTTPError as exc:
            challenge = exc.headers.get("WWW-Authenticate", "")
            exc.close()
            if exc.code == 401 and retry and challenge.lower().startswith("bearer "):
                params = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
                realm = params.pop("realm", "")
                if urlsplit(realm).scheme != "https":
                    raise
                q = "&".join(f"{k}={urllib.request.quote(v)}" for k, v in params.items())
                with self.opener.open(f"{realm}?{q}", timeout=30) as response:
                    body = json.loads(response.read(65536))
                self.token = body.get("token") or body.get("access_token") or ""
                return self._open(url, accept, retry=False)
            raise

    def manifest(self, digest):
        with self._open(f"{self.base}/manifests/{digest}", self.ACCEPT) as response:
            return json.loads(response.read(4 * 1024 * 1024))

    def blob(self, digest):
        return self._open(f"{self.base}/blobs/{digest}", "*/*")


def scan_image(ref, limit):
    registry, repo, digest = parse_image(ref)
    insecure = registry.split(":")[0] in LOOPBACK and os.environ.get("DUVORA_SCAN_ALLOW_HTTP") == "1"
    reg = Registry(registry, repo, insecure)
    manifest = reg.manifest(digest)
    findings, platform = [], None
    if manifest.get("manifests"):
        prefer = [m for m in manifest["manifests"] if (m.get("platform") or {}).get("architecture") == "arm64"] or \
                 [m for m in manifest["manifests"] if (m.get("platform") or {}).get("architecture") == "amd64"] or manifest["manifests"]
        platform = (prefer[0].get("platform") or {}).get("architecture")
        manifest = reg.manifest(prefer[0]["digest"])
    config_desc = manifest.get("config") or {}
    if config_desc.get("digest"):
        with reg.blob(config_desc["digest"]) as response:
            config = json.loads(response.read(4 * 1024 * 1024))
        c = config.get("config") or {}
        if not c.get("User") or c.get("User") in {"0", "root", "0:0"}:
            findings.append(finding("low", "runs-as-root", "Image runs as root (no USER)", "config"))
        for env in c.get("Env") or []:
            key = env.split("=", 1)[0].upper()
            if re.search(r"(SECRET|TOKEN|PASSWORD|API_?KEY|PRIVATE_KEY)", key) and "=" in env and env.split("=", 1)[1]:
                findings.append(finding("high", "secret-in-env", f"Environment variable {key} carries a value in the image config", "config"))
            findings += scan_secrets(env, "config.Env")
        for entry in config.get("history") or []:
            findings += scan_secrets(entry.get("created_by") or "", "history")
    scanned = 0
    for layer in manifest.get("layers") or []:
        if scanned >= limit:
            findings.append(finding("info", "skipped", "Scan size limit reached before all layers", layer.get("digest", "")))
            break
        with reg.blob(layer["digest"]) as response:
            scanned += scan_tar(response, findings, limit - scanned)
    return dedupe(findings), {"registry": registry, "repository": repo, "digest": digest, "platform": platform,
                              "layers": len(manifest.get("layers") or []), "bytes_scanned": scanned}


def scan_url(url, limit):
    parts = urlsplit(url)
    if parts.scheme != "https" and not (parts.hostname in LOOPBACK and os.environ.get("DUVORA_SCAN_ALLOW_HTTP") == "1"):
        raise Problem("Model URLs must use HTTPS")
    handlers = [NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=os.environ.get("DUVORA_SCAN_CA_FILE") or None))]
    with urllib.request.build_opener(*handlers).open(url, timeout=60) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"artifact larger than the scan limit ({limit // (1024 * 1024)} MB)")
    path = parts.path.rsplit("/", 1)[-1] or "artifact"
    if data[:2] == b"\x1f\x8b" or path.endswith((".tar", ".tar.gz", ".tgz")):
        findings = []
        scan_tar(io.BytesIO(data), findings, limit)
        return dedupe(findings), {"bytes_scanned": len(data), "name": path}
    return dedupe(scan_bytes(path, data)), {"bytes_scanned": len(data), "name": path}


def scan_file(path, limit=MODEL_MAX * 4):
    """Local scan for `duvoractl scan --file`."""
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        if tarfile.is_tarfile(path):
            findings = []
            scan_tar(f, findings, limit)
        else:
            if size > limit:
                raise ValueError("file larger than the scan limit")
            findings = scan_bytes(os.path.basename(path), f.read())
    findings = dedupe(findings)
    return {"target": path, "status": verdict(findings), "findings": findings, "bytes": size}


class ScannerMixin:
    def init_scanner(self):
        self.db.execute(SCHEMA)
        self.scan_limit = max(1, int(os.environ.get("DUVORA_SCAN_MAX_MB", "512") or 512)) * 1024 * 1024
        self.require_scan = os.environ.get("DUVORA_REQUIRE_SCAN") == "1"
        with self.transaction():
            for r in self.db.execute("SELECT id, body FROM scans").fetchall():
                body = json.loads(r["body"])
                if body["status"] == "running":
                    body.update(status="error", error="Interrupted by a restart", finished=time.time())
                    self.db.execute("UPDATE scans SET body=? WHERE id=?", (canonical(body), r["id"]))

    def start_scan(self, actor, body):
        if not isinstance(body, dict) or set(body) - {"image", "url"} or len(body) != 1:
            raise Problem("Scan one image (digest-pinned) or one model url")
        kind, target = next(iter(body.items()))
        if not isinstance(target, str) or len(target) > 1024:
            raise Problem("Invalid scan target")
        if kind == "image":
            parse_image(target)
        else:
            parts = urlsplit(target)
            if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username:
                raise Problem("Model url must be an https URL without credentials")
        scan = {"id": secrets.token_hex(8), "kind": kind, "target": target, "status": "running", "actor": actor,
                "started": time.time(), "finished": None, "findings": [], "meta": {}, "error": None}
        with self.transaction():
            self.db.execute("INSERT INTO scans VALUES(?,?,?,?)", (scan["id"], target, scan["started"], canonical(scan)))
            self.event(actor, "scan.started", {"id": scan["id"], "kind": kind, "target": target})
        threading.Thread(target=self._run_scan, args=(scan,), daemon=True).start()
        return scan

    def _run_scan(self, scan):
        try:
            findings, meta = (scan_image if scan["kind"] == "image" else scan_url)(scan["target"], self.scan_limit)
            scan.update(findings=findings, meta=meta, status=verdict(findings))
        except Problem as exc:
            scan.update(status="error", error=str(exc))
        except (urllib.error.URLError, OSError, ValueError, KeyError, tarfile.TarError, gzip.BadGzipFile, json.JSONDecodeError) as exc:
            scan.update(status="error", error=f"{type(exc).__name__}: {getattr(exc, 'reason', exc)}"[:300])
        scan["finished"] = time.time()
        with self.transaction():
            self.db.execute("UPDATE scans SET body=? WHERE id=?", (canonical(scan), scan["id"]))
            self.event("scanner", f"scan.{scan['status']}", {"id": scan["id"], "target": scan["target"],
                                                             "findings": sum(f["severity"] in ("high", "critical") for f in scan["findings"])})
        self.export_event("audit", {"time": scan["finished"], "actor": "scanner", "action": f"scan.{scan['status']}",
                                    "detail": {"target": scan["target"], "findings": scan["findings"][:20]}})

    def record_scan(self, scan):
        """Store a completed scan (tests and offline imports go through here)."""
        with self.transaction():
            self.db.execute("INSERT INTO scans VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body",
                            (scan["id"], scan["target"], scan.get("started", time.time()), canonical(scan)))
        return scan

    def scans(self, target=None, limit=100):
        with self.lock:
            rows = self.db.execute("SELECT body FROM scans" + (" WHERE target=?" if target else "") + " ORDER BY created DESC LIMIT ?",
                                   ((target,) if target else ()) + (max(1, min(500, int(limit))),))
            return [json.loads(r[0]) for r in rows]

    def scan(self, ident):
        row = self.db.execute("SELECT body FROM scans WHERE id=?", (ident,)).fetchone()
        if not row:
            raise Problem("Scan not found", 404)
        return json.loads(row[0])

    def image_scan_blockers(self, image):
        """Deploy blockers from scan history: a failed latest scan always blocks; no passed scan blocks under DUVORA_REQUIRE_SCAN=1."""
        history = [s for s in self.scans(image, 20) if s["status"] in ("passed", "failed")]
        if history and history[0]["status"] == "failed":
            worst = [f for f in history[0]["findings"] if f["severity"] in ("high", "critical")][:2]
            return [f"Image failed its artifact scan {history[0]['id']}: " + "; ".join(f["detail"] for f in worst)]
        if self.require_scan and not history:
            return ["This server requires a passed artifact scan before deploy (DUVORA_REQUIRE_SCAN=1); scan the image first"]
        return []

    def scanner_conditions(self):
        def failed(rule, now, firing):
            for s in self.scans(limit=50):
                if s["status"] == "failed" and now - (s.get("finished") or 0) <= 86400:
                    firing[f"{rule['id']}:{s['id']}"] = (rule, s["id"], f"Artifact scan failed: {s['target'][:80]}",
                                                         "; ".join(f["detail"] for f in s["findings"] if f["severity"] in ("high", "critical"))[:300])
        return {"scan-failed": failed}
