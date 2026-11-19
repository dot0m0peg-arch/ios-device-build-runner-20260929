"""Compile and run only the Last Car audio diagnostic companion."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from urllib.request import urlopen
from zipfile import ZipFile

from artifacts import ROOT, REPOSITORY, cipher, context_file
from prepare_qa import build
from verify_release import digest, names_in, require

ORIGINAL_LAST_CAR_PKG = "3f6bb08ad580f37004327a3f091fe6e8c5095902f867417e8c518de9c0d2e04a"
ORIGINAL_SOURCE = "cbd3aa735d674688e090399f25d2f7fc2eb7410c5d8a6a090a06bd76cce213be"

def diagnostic_build():
    app, state_path = context_file()
    state = json.loads(state_path.read_bytes())
    require(app == state["app"] == "LastCarUpright" and state["pins"]["source_sha256"] == ORIGINAL_SOURCE,
            "Replay is limited to the original frozen Last Car package")
    kit = Path(__file__).parent
    frozen = json.loads((kit / "diagnostic-pins.json").read_bytes())
    raw_root = f"https://raw.githubusercontent.com/{REPOSITORY}/{os.environ['GITHUB_SHA']}/"
    full = raw_root + "apple-port/lastcar-native-replay/companion-overlay.aesgcm"
    transfer = ROOT / "mac-job-products"
    transfer.mkdir()
    with urlopen(full, timeout=75) as request:
        encrypted = request.read()
    packed = ROOT / "lastcar-diagnostic-overlay.zip"
    packed.write_bytes(cipher().decrypt(encrypted[:12], encrypted[12:], b"LastCarUpright:native-replay-companion:v1"))
    require(digest(packed) == frozen["overlay_sha256"], "Wrong exact diagnostic overlay")
    with ZipFile(packed) as archive:
        require(set(names_in(archive)) == {"capture-kit.zip", "DiagnosticGameSession.swift"}, "Wrong diagnostic inventory")
        archive.extractall(ROOT / "lastcar-diagnostic-overlay")
    overlay = ROOT / "lastcar-diagnostic-overlay"
    capture = overlay / "capture-kit.zip"
    handler = overlay / "DiagnosticGameSession.swift"
    require(digest(capture) == frozen["capture_kit_sha256"] and digest(handler) == frozen["handler_sha256"],
            "Diagnostic payload does not match approved tool pins")
    test_inputs = ROOT / "lastcar-capture-kit"
    with ZipFile(capture) as archive:
        names_in(archive)
        archive.extractall(test_inputs)
    shutil.copyfile(handler, test_inputs / "DiagnosticGameSession.swift")
    details = build(ROOT / "apple-source", test_inputs, state, transfer)
    (transfer / "qa-build.json").write_text(json.dumps({
        **details, "archive_sha256": digest(transfer / "qa-companion.zip"),
        "record_kind": "instrumented audio diagnostic companion, frozen Last Car game bytes",
    }, indent=2))
    shutil.copyfile(capture, transfer / "diagnostic-capture-kit.zip")

def qualify():
    inputs = ROOT / "original-package-products"
    replacement = ROOT / "diagnostic-companion-products"
    target = ROOT / "mac-job-products"
    target.mkdir()
    package = inputs / "LastCarUpright.pkg"
    require(digest(package) == ORIGINAL_LAST_CAR_PKG, "Original signed Last Car package hash mismatch")
    provenance = json.loads((inputs / "source-and-package.json").read_bytes())
    require(provenance["pins"]["source_sha256"] == ORIGINAL_SOURCE
            and provenance["package"]["package_sha256"] == ORIGINAL_LAST_CAR_PKG, "Original package receipt mismatch")
    for file in (package, inputs / "source-and-package.json", replacement / "qa-companion.zip", replacement / "qa-build.json"):
        shutil.move(file, target / file.name)
    diagnostic_capture = replacement / "diagnostic-capture-kit.zip"
    kit = Path(__file__).parent
    frozen = json.loads((kit / "diagnostic-pins.json").read_bytes())
    require(digest(diagnostic_capture) == frozen["capture_kit_sha256"], "Decrypted runtime capture code changed")
    shutil.move(diagnostic_capture, kit / "capture-kit.zip")
    subprocess.run([sys.executable, str(kit / "run_native_qa.py")], check=True, timeout=650)

if __name__ == "__main__":
    if sys.argv[1:] == ["build"]:
        diagnostic_build()
    elif sys.argv[1:] == ["qualify"]:
        qualify()
    else:
        raise SystemExit("Expected build or qualify")
