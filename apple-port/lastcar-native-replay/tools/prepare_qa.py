"""Build the separate instrumented Mac acceptance app from frozen release inputs."""
from base64 import b64encode
import json
import os
from pathlib import Path
from shutil import copytree
import subprocess
import sys

from verify_release import digest, require, verify_app, verify_source_tree


def run(args, cwd=None, timeout=480):
    subprocess.run(args, cwd=cwd, timeout=timeout, check=True)


def build(frozen_source, kit, state, transfer):
    app = state["app"]
    root = Path(os.environ["RUNNER_TEMP"]) / "qa-source"
    copytree(frozen_source, root)
    verify_source_tree(root, app, state["pins"])
    scheme = app + "-Mac"
    audit = root / "audit"
    audit.mkdir()
    for name in ("RuntimeScreenshots.swift", "capture-runner.py", "screenshot-scenes.js",
                 "capture-acceptance.js", "native-game-probes.js"):
        (audit / name).write_bytes((kit / name).read_bytes())

    # Probe code is compiled into the QA companion only. Production game files and
    # the shipping GameSession URL/file bridge must retain the original bytes.
    js = audit / "capture-acceptance.js"
    with js.open("a", encoding="utf-8") as output:
        output.write("\n" + (audit / "native-game-probes.js").read_text(encoding="utf-8"))
    run(["python3", str(audit / "capture-runner.py"), "prepare", str(root), app, scheme])
    sources = root / "Sources"
    (sources / "NativeProbeHost.swift").write_bytes((kit / "NativeProbeHost.swift").read_bytes())
    observer = b64encode((kit / "native-observers.js").read_bytes()).decode("ascii")
    wrapper = sources / "AppleGameApp.swift"
    text = wrapper.read_text()
    initial = ".task { game.start(); await RuntimeScreenshots.run("
    require(text.count(initial) == 1, "Previously qualified test hook changed")
    boot = ('.task { NativeProbeHost.install(game.webView, script: String(decoding: Data(base64Encoded: "'
            + observer + '")!, as: UTF8.self)); game.start(); await RuntimeScreenshots.run(')
    wrapper.write_text(text.replace(initial, boot))

    # The accepted shipping source and host are verified above. This
    # diagnostic-only companion then adds read-only scheme request telemetry.
    (sources / "GameSession.swift").write_bytes((kit / "DiagnosticGameSession.swift").read_bytes())
    product_dir = root / "BuildProducts"
    run(["xcodegen", "generate", "--spec", "project.json"], cwd=root, timeout=90)
    run(["xcodebuild", "-project", "CharbejAppleGames.xcodeproj", "-scheme", scheme,
         "-configuration", "Release", "-destination", "generic/platform=macOS",
         "-derivedDataPath", str(root / "DerivedData"), "CONFIGURATION_BUILD_DIR=" + str(product_dir),
         "ARCHS=arm64 x86_64", "ONLY_ACTIVE_ARCH=NO", "CODE_SIGNING_ALLOWED=NO", "build"], cwd=root)
    product = product_dir / (app + ".app")
    run(["codesign", "--force", "--sign", "-", "--timestamp=none", "--entitlements",
         str(root / "Apps" / app / "Mac.entitlements"), str(product)], timeout=90)
    details = verify_app(product, app, state["pins"], state["game"], signed=False)
    require(product.is_dir(), "Missing test-only acceptance app")
    run(["ditto", "-c", "-k", "--sequesterRsrc", "--keepParent", str(product),
         str(transfer / "qa-companion.zip")], timeout=180)
    return details


if __name__ == "__main__":
    pristine, kit, transfer = (Path(path) for path in sys.argv[1:])
    state = json.loads((Path(os.environ["RUNNER_TEMP"]) / "polished-release.json").read_bytes())
    details = build(pristine, kit, state, transfer)
    (transfer / "qa-build.json").write_text(json.dumps({
        **details, "archive_sha256": digest(transfer / "qa-companion.zip"),
        "record_kind": "instrumented sandbox companion built with same SDK and exact game bytes",
    }, indent=2))
