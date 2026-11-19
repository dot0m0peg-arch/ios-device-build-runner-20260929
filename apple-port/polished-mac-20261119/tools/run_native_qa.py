"""Qualify native Mac actions, audio, frames, and fresh-process saves."""
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
from zipfile import ZIP_DEFLATED, ZipFile

from PIL import Image

from verify_release import digest, names_in, require, verify_app, verify_package

FRAMES = {"LastCarUpright": ["1-head-to-head.png", "2-garage.png"],
          "Miner3D": ["1-valley.png", "2-copper-order.png"]}


def run(command, timeout=120, **kwargs):
    return subprocess.run(command, check=True, timeout=timeout, **kwargs)


def receipt(path, information):
    path.write_text(json.dumps(information, indent=2))


def exact_pid(executable):
    processes = run(["/bin/ps", "-axo", "pid=,comm="], timeout=8, capture_output=True, text=True).stdout
    for row in processes.splitlines():
        parts = row.split(None, 1)
        if len(parts) == 2 and parts[1] == str(executable):
            return int(parts[0])
    return None


def signed_launch(app, title, log):
    executable = app / "Contents" / "MacOS" / title
    with log.open("w") as output:
        opened = subprocess.run(["/usr/bin/open", "-n", str(app)], stdout=output, stderr=output, timeout=15)
    if opened.returncode:
        return {"opened": False, "launchservices_return_code": opened.returncode}
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        time.sleep(.6)
    pid = exact_pid(executable)
    if pid and exact_pid(executable) == pid:
        os.kill(pid, signal.SIGTERM)
    return {"opened": bool(pid), "launchservices_return_code": opened.returncode,
            "interpretation": "Unmodified signed binary process was checked without receipt/signature overrides"}


def read_capture(run_root, title, log):
    captures = run_root / "captures"
    manifest_path = captures / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    require(not manifest["error"] and manifest["native_relaunch_acceptance"], "Native test or save restore failed")
    pid_records = re.findall(r"^APPLE_CAPTURE_PID ([0-9]+)$", log.read_text(), re.MULTILINE)
    require(len(pid_records) == 2 and len(set(pid_records)) == 2, "Persistence did not cross two independent native PIDs")
    frames = [item["path"] for item in manifest["native_frames"]]
    require(frames == FRAMES[title], "Missing expected native gameplay image")
    for meta in manifest["native_frames"]:
        file = captures / meta["path"]
        with Image.open(file) as image:
            require(image.size == (1440, 900) and image.mode == "RGB" and digest(file) == meta["sha256"],
                    "Invalid or altered native RGB capture")
    state = manifest["native_relaunch_acceptance"]
    proof = state["initialAudit"]
    require(len(proof["screens"]) == 2 and all(item["link"] and len(item["colors"]) >= 4 for item in proof["screens"]),
            "Native WebKit 3D proof is missing")
    if title == "LastCarUpright":
        require(state["narration"] is False and state["voices"] is True and state["favorite"] and
                proof["checks"]["storySkip"] and proof["checks"]["muteStopsSpeech"] and
                proof["checks"]["backgroundCancelsSpeech"] and proof["checks"]["profile"] and proof["checks"]["nativeHeadToHead"],
                "Last Car behavior or persistence proof is incomplete")
    else:
        require(state["order"]["orderDone"] and proof["checks"]["delivered"] == {"coins": 61, "copper": 3} and proof["audio"]["ask"]
                and proof["audio"]["thanks"] and proof["audio"]["ore"]["peak"] > .0005,
                "Miner first order or audio proof is incomplete")
    return {**manifest, "process_ids": [int(pid) for pid in pid_records]}


def main():
    root = Path(os.environ["RUNNER_TEMP"])
    inputs = root / "mac-job-products"
    output = root / "mac-qa-products"
    output.mkdir()
    status = {"passed": False, "phase": "verify package"}
    status_path = output / "qa-report.json"
    title = os.environ["APP_KEY"]
    kit = Path(__file__).parent
    capture_kit = root / "capture-kit"
    with ZipFile(kit / "capture-kit.zip") as packed:
        names_in(packed)
        packed.extractall(capture_kit)
    try:
        frozen = json.loads((inputs / "source-and-package.json").read_bytes())
        require(frozen["app"] == title, "Wrong source package")
        packages = list(inputs.glob("*.pkg"))
        require(len(packages) == 1, "QA received an unexpected installer inventory")
        app, details = verify_package(packages[0], root / "inspection-qa", title, frozen["pins"], frozen["game"])
        require(details == frozen["package"], "Signed installer changed between runners")
        status.update(app=title, source_sha256=frozen["pins"]["source_sha256"], signed_package=details)
        status["phase"] = "verify test companion"
        instrumented = inputs / "qa-companion.zip"
        compiled = json.loads((inputs / "qa-build.json").read_bytes())
        require(compiled["archive_sha256"] == digest(instrumented), "Sandbox companion transfer changed")
        companion_root = root / "companion"
        run(["ditto", "-x", "-k", str(instrumented), str(companion_root)], timeout=150)
        companion = companion_root / (title + ".app")
        qa_details = verify_app(companion, title, frozen["pins"], frozen["game"], signed=False)
        require(all(compiled[key] == value for key, value in qa_details.items()),
                "The SDK-matched QA product changed on transfer")
        status.update(companion=qa_details, phase="qualify native gameplay")
        receipt(status_path, status)
        run(["/usr/bin/swift", str(capture_kit / "set-display.swift")], timeout=75)
        native_log = output / "native-qualification.log"
        try:
            with native_log.open("w") as log:
                run([sys.executable, str(capture_kit / "capture-runner.py"), "invoke",
                     str(companion), title, frozen["pins"]["bundle"], "Mac"],
                    timeout=520, stdout=log, stderr=log)
            status["native"] = read_capture(root, title, native_log)
            status["audio_scope"] = "WebKit media clock plus WebAudio PCM probe where applicable"
            status["passed"] = True
        finally:
            try:
                status["signed_launch_diagnostic"] = signed_launch(app, title, output / "unmodified-launch.log")
            except Exception as error:
                status["signed_launch_diagnostic"] = {"opened": False, "error": type(error).__name__}
            for name in ("capture-stdout.log", "capture-stderr.log", "verify-stdout.log", "verify-stderr.log"):
                path = root / name
                if path.is_file():
                    (output / name).write_bytes(path.read_bytes())
            with ZipFile(output / "native-captures.zip", "w", compression=ZIP_DEFLATED) as archive:
                for name in ("captures", "own-process-comparison"):
                    for file in (root / name).glob("*"):
                        if file.is_file():
                            archive.write(file, f"{name}/{file.name}")
        status["phase"] = "native qualification complete"
        print(f"{title}: native evidence and exact package provenance preserved.")
    finally:
        receipt(status_path, status)


if __name__ == "__main__":
    main()
