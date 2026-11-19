"""Prepare the exact Store installer and separately signed sandbox QA companion."""
import json
import os
from pathlib import Path
import subprocess
import sys
from zipfile import ZipFile

from verify_release import digest, names_in, require, verify_app, verify_package


def main():
    root = Path(os.environ["RUNNER_TEMP"])
    kit = Path(__file__).parent
    transfer = root / "mac-job-products"
    transfer.mkdir()
    source = root / "apple-source"
    state = json.loads((root / "polished-release.json").read_bytes())
    app = state["app"]
    require(app == os.environ["APP_KEY"], "Job source and app identifier disagree")
    capture = root / "capture-kit"
    with ZipFile(kit / "capture-kit.zip") as packed:
        names_in(packed)
        packed.extractall(capture)

    # Use the approved release script and credentials with the Apple upload
    # portion removed; its output is immutable before QA is run.
    support = root / "mac-sign-support.zip"
    with ZipFile(support) as packed:
        names = names_in(packed)
        require("release/build_release.py" in names and all(name.startswith("release/") for name in names),
                "Unexpected signed release support archive")
        packed.extractall(source)
    tool = source / "release/build_release.py"
    release_output = root / "release-output"
    try:
        with (transfer / "signing-console.log").open("w") as log:
            subprocess.run([sys.executable, str(tool)], check=True, timeout=780, stdout=log, stderr=log)
    finally:
        for path in release_output.glob("*"):
            if path.is_file():
                path.replace(transfer / path.name)
    packages = list(transfer.glob("*.pkg"))
    require(len(packages) == 1, "Unexpected export package inventory")
    package = packages[0]
    receipt = json.loads((transfer / "receipt.json").read_bytes())
    require(receipt["archive_verified"] and not receipt["uploaded"] and receipt["package_sha256"] == digest(package),
            "Signed released package did not match its signing receipt")
    archive = root / (app + ".xcarchive") / "Products" / "Applications" / (app + ".app")
    archived = verify_app(archive, app, state["pins"], state["game"], signed=True)
    _, exported = verify_package(package, root / "inspection", app, state["pins"], state["game"])
    require(archived["identity_and_toolchain"] == exported["identity_and_toolchain"],
            "Export changed the archived deployment or build metadata")
    (transfer / "source-and-package.json").write_text(json.dumps({
        "app": app, "pins": {key: value for key, value in state["pins"].items() if key != "source_files"},
        "game": state["game"], "archive": archived, "package": exported,
    }, indent=2))
    # Reconstruct the exact source from the two already authenticated local ZIPs.
    # The archive signer altered its working project configuration.
    from artifacts import materialize_source
    pristine = root / "pristine-qa-source"
    materialize_source(root / "baseline-mac-source.zip", root / "polished-source-overlay.zip",
                       pristine, state["pins"])
    with (transfer / "qa-build.log").open("w") as log:
        subprocess.run([sys.executable, str(kit / "prepare_qa.py"), str(pristine), str(capture), str(transfer)],
                       check=True, timeout=720, stdout=log, stderr=log)
    print(f"{app}: signed package verified and native companion built without contacting Apple.")


if __name__ == "__main__":
    main()
