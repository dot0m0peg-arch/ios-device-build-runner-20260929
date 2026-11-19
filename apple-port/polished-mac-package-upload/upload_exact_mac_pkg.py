"""Validate and upload an already-accepted, unchanged Mac App Store installer."""
from hashlib import file_digest
import json
import os
from pathlib import Path
import re
import subprocess
from tempfile import TemporaryDirectory

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

REPOSITORY = "dot0m0peg-arch/ios-device-build-runner-20260929"
BRANCH = "refs/heads/codex/lastcar-fullscreen-v3-upload-20261119"
EXPECTED = {
    "LastCarUpright": (44524297483, 14528228959, "1.0.14", "14",
        "85c01794928992134295593572f5f9615f10423589c56f0be27e9c83d4440b52",
        "07881b9a343d9961acaa9690554df4e290871080f6e97f60748b346a3ba171e3"),
}

def require(condition, message):
    if not condition:
        raise RuntimeError(message)

def sha(path):
    with path.open("rb") as opened:
        return file_digest(opened, "sha256").hexdigest()

def run(command, log, cwd=None, env=None, timeout=600):
    with log.open("ab") as output:
        subprocess.run(command, cwd=cwd, stdout=output, stderr=output, env=env, check=True, timeout=timeout)

def authenticate_inputs(app, root):
    require(os.environ["GITHUB_REPOSITORY"] == REPOSITORY and os.environ["GITHUB_REF"] == BRANCH,
            "Unexpected Mac package upload repository or branch")
    run_id, artifact, version, build, expected_sha, source_sha = EXPECTED[app]
    require(os.environ["APPROVED_PACKAGE_SHA256"] == expected_sha,
            "Root acceptance did not name the unchanged, independently qualified Mac package hash")
    require(re.fullmatch(r"[0-9]{10,12}", os.environ["APPROVED_NATIVE_RUN"]) and
            re.fullmatch(r"[0-9a-f]{64}", os.environ["APPROVED_NATIVE_SHA256"]),
            "Missing exact native acceptance provenance")
    key = bytes.fromhex(os.environ.pop("IPA_KEY_HEX"))
    require(len(key) == 32, "Existing 256-bit artifact key required")
    crypto = AESGCM(key)
    downloads = root / "signed-encrypted"
    private = root / "apple-package-input"
    private.mkdir(mode=0o700)
    for name in (app + ".pkg", "source-and-package.json"):
        source = (downloads / (name + ".aesgcm")).read_bytes()
        target = private / name
        context = f"{app}:{run_id}:build:{name}".encode()
        with target.open("xb") as output:
            output.write(crypto.decrypt(source[:12], source[12:], context))
    package = private / (app + ".pkg")
    checked = json.loads((private / "source-and-package.json").read_bytes())
    require(sha(package) == expected_sha == checked["package"]["package_sha256"] and
            checked["app"] == app and checked["pins"]["source_sha256"] == source_sha,
            "Authenticated package does not match exact approved bytes")
    return package, {"app": app, "version": version, "build": build, "signed_run": run_id,
                     "signed_artifact": artifact, "source_sha256": source_sha, "package_sha256": expected_sha,
                     "approved_native_run": int(os.environ["APPROVED_NATIVE_RUN"]),
                     "approved_native_sha256": os.environ["APPROVED_NATIVE_SHA256"],
                     "validation_attempted": False, "validated": False, "upload_attempted": False, "uploaded": False}

def upload(app, root):
    package, state = authenticate_inputs(app, root)
    output = root / "apple-upload-report"
    output.mkdir(mode=0o700)
    log = output / "apple-upload.log"
    summary = output / "receipt.json"
    def save():
        summary.write_text(json.dumps(state, indent=2))
    save()
    run(["/usr/sbin/pkgutil", "--check-signature", str(package)], log, timeout=100)
    state["installer_signature_verified"] = True
    save()
    with TemporaryDirectory(prefix="asc-mac-upload-", dir=root) as directory:
        private = Path(directory)
        key_id = os.environ["APPLE_STORE_CONNECT_KEY_ID"]
        issuer = os.environ["APPLE_STORE_CONNECT_ISSUER_ID"]
        require(re.fullmatch(r"[A-Z0-9]{10}", key_id), "Unexpected approved API key identifier shape")
        keys = private / "private_keys"
        keys.mkdir(mode=0o700)
        key_file = keys / ("AuthKey_" + key_id + ".p8")
        with key_file.open("x") as handle:
            key_file.chmod(0o600)
            handle.write(os.environ["APPLE_STORE_CONNECT_PRIVATE_KEY"])
        environment = dict(os.environ, API_PRIVATE_KEYS_DIR=str(keys))
        environment.pop("APPLE_STORE_CONNECT_PRIVATE_KEY", None)
        command = ["xcrun", "altool", "-f", str(package), "--type", "macos",
                   "--apiKey", key_id, "--apiIssuer", issuer, "--output-format", "json"]
        state["validation_attempted"] = True
        save()
        run([*command, "--validate-app"], log, private, environment)
        state["validated"] = True
        save()
        require(sha(package) == state["package_sha256"], "Validated package changed before Apple upload")
        state["upload_attempted"] = True
        save()
        run([*command, "--upload-app"], log, private, environment, timeout=930)
        state["uploaded"] = True
        save()
    print(f"{app}: Apple validated and received the exact previously signed package. Processing remains pending.")

def preserve(app, root):
    report = root / "apple-upload-report"
    if not report.exists():
        return
    key = bytes.fromhex(os.environ["IPA_KEY_HEX"])
    require(len(key) == 32, "Existing 256-bit artifact key required")
    aes = AESGCM(key)
    destination = root / "apple-upload-encrypted"
    destination.mkdir()
    for filename in ("receipt.json", "apple-upload.log"):
        path = report / filename
        if path.is_file():
            nonce = os.urandom(12)
            proof = f"{app}:{os.environ['GITHUB_RUN_ID']}:upload:{filename}".encode()
            (destination / (filename + ".aesgcm")).write_bytes(nonce + aes.encrypt(nonce, path.read_bytes(), proof))

if __name__ == "__main__":
    import sys
    root = Path(os.environ["RUNNER_TEMP"])
    key = os.environ["APP_KEY"]
    require(key in EXPECTED, "Unexpected app")
    if sys.argv[1:] == ["upload"]:
        upload(key, root)
    elif sys.argv[1:] == ["preserve"]:
        preserve(key, root)
    else:
        raise SystemExit("Expected upload or preserve")
