"""Verify pinned Mac source, sandboxed build, and actual signed package."""
from hashlib import file_digest, sha256
import json
from pathlib import Path, PurePosixPath
import plistlib
import re
import subprocess
from zipfile import ZipFile

TOOLCHAIN = {"xcode": "27.2", "build": "27B52", "sdk": "27.2", "minimum": "14.0"}
APP_IDS = {"LastCarUpright": "com.connor.lastcarupright", "Miner3D": "com.charbej.miner3d"}
HOST_PINS = {
    "Sources/AppleGameApp.swift": "a1f468a45a4b5b063fb9875dad5c3ab8b640828869d23434ce73f2fd2c9d6387",
    "Sources/GameSession.swift": "8ec09e12439c9c1228fb9dbf8cfda639100e1ddb817e7e4765fcff8c4f71b482",
}
ENTITLEMENT_PINS = {
    "LastCarUpright": "c0e0afd6abe100386f5bc3ee241557a7b91c9ce59b8c1e99e962bceb49729cfb",
    "Miner3D": "b043dea477bbd5da1552ef2f436a0cb644b884bb2568a9f831bd4ee362f9e99b",
}
ARCHITECTURES = {"arm64", "x86_64"}


def require(condition, explanation):
    if not condition:
        raise RuntimeError(explanation)


def digest(path):
    with path.open("rb") as stream:
        return file_digest(stream, "sha256").hexdigest()


def names_in(archive):
    names = archive.namelist()
    require(len(set(names)) == len(names), "Duplicate archive member")
    for raw in names:
        name = PurePosixPath(raw)
        require(not name.is_absolute() and ".." not in name.parts and "\\" not in raw
                and ":" not in raw and name.parts, "Unsafe archive member")
    return names


def inventory(directory):
    require(directory.is_dir(), "Packaged resource folder is missing")
    files = sorted(path for path in directory.rglob("*") if path.is_file())
    require(all(not path.is_symlink() for path in files), "Unexpected symlink in game resources")
    return {path.relative_to(directory).as_posix(): digest(path) for path in files}


def canonical_manifest(hashes):
    return sha256(json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def source_extract(archive_path, work, app, pins):
    require(digest(archive_path) == pins["source_sha256"], "Frozen source ZIP SHA mismatch")
    with ZipFile(archive_path) as archive:
        names_in(archive)
        archive.extractall(work)
    return verify_source_tree(work, app, pins)


def verify_source_tree(work, app, pins):
    require(app in APP_IDS and pins["bundle"] == APP_IDS[app], "Unexpected Mac app")
    require(inventory(work) == pins["source_files"], "Merged source does not match every frozen ZIP member")
    scheme = app + "-Mac"
    project = json.loads((work / "project.json").read_bytes())
    target = project["targets"][scheme]
    settings = target["settings"]["base"]
    require(target["deploymentTarget"] == TOOLCHAIN["minimum"], "Unexpected macOS minimum deployment target")
    require(str(settings["MARKETING_VERSION"]) == pins["version"]
            and str(settings["CURRENT_PROJECT_VERSION"]) == pins["build"]
            and settings["PRODUCT_BUNDLE_IDENTIFIER"] == pins["bundle"], "Frozen source identity mismatch")
    for name, expected in HOST_PINS.items():
        require(digest(work / name) == expected, "Native host changed: " + name)
    entitlements = work / "Apps" / app / "Mac.entitlements"
    require(digest(entitlements) == ENTITLEMENT_PINS[app], "Sandbox entitlements changed")
    game = inventory(work / "Apps" / app / "game")
    require(len(game) == pins["game_files"] and canonical_manifest(game) == pins["game_sha256"],
            "Game resources differ from the approved hash manifest")
    require("index.html" in game, "Missing game entry point")
    return game


def run(command, timeout=90):
    return subprocess.run(command, check=True, capture_output=True, timeout=timeout).stdout


def build_version(executable, architecture):
    output = run(["xcrun", "vtool", "-arch", architecture, "-show-build", str(executable)]).decode()
    selected = re.findall(r"^\s+(platform|minos|sdk)\s+(\S+)\s*$", output, re.MULTILINE)
    require(len(selected) == 3 and len(dict(selected)) == 3, "Missing or ambiguous Mach-O build version")
    result = dict(selected)
    require(result["platform"] == "MACOS" and tuple(map(int, result["minos"].split(".")))[:2] == (14, 0)
            and tuple(map(int, result["sdk"].split(".")))[:2] == (27, 2),
            "Mac executable does not use stable SDK 27.2 with deployment target 14.0")
    return result


def verify_app(app_path, app, pins, game, signed):
    contents = app_path / "Contents"
    info = plistlib.loads((contents / "Info.plist").read_bytes())
    expected = {
        "CFBundleIdentifier": APP_IDS[app], "CFBundleExecutable": app,
        "CFBundleShortVersionString": pins["version"], "CFBundleVersion": pins["build"],
        "DTXcode": "2720", "DTXcodeBuild": TOOLCHAIN["build"],
        "DTSDKName": "macosx" + TOOLCHAIN["sdk"], "DTPlatformName": "macosx",
        "LSMinimumSystemVersion": TOOLCHAIN["minimum"],
    }
    require(all(str(info.get(key)) == value for key, value in expected.items()) and info.get("DTSDKBuild"),
            "App Info.plist does not match the selected toolchain, macOS minimum, and expected identity")
    executable = contents / "MacOS" / app
    require(set(run(["xcrun", "lipo", "-archs", str(executable)]).decode().split()) == ARCHITECTURES,
            "Mac binary no longer carries Apple Silicon and Intel slices")
    run(["codesign", "--verify", "--deep", "--strict", str(app_path)])
    attributes = plistlib.loads(run(["codesign", "-d", "--entitlements", ":-", str(app_path)]))
    require(attributes.get("com.apple.security.app-sandbox") is True and not attributes.get("get-task-allow"),
            "Sandbox entitlement missing or debugging entitlement present")
    if app == "LastCarUpright":
        require(attributes.get("com.apple.security.files.user-selected.read-write") is True,
                "Garage file open/save entitlement missing")
    if signed:
        require(attributes.get("com.apple.developer.team-identifier") == "S5763GXRG9"
                and attributes.get("com.apple.application-identifier",
                                   attributes.get("application-identifier")) == "S5763GXRG9." + APP_IDS[app],
                "Exported app signature is not the intended team and app")
    require(inventory(contents / "Resources/game") == game, "Built game does not match signed source bytes")
    require((contents / "Resources/PrivacyInfo.xcprivacy").is_file(), "Missing packaged privacy declaration")
    return {
        "identity_and_toolchain": {**expected, "DTSDKBuild": info["DTSDKBuild"]},
        "slices": {architecture: build_version(executable, architecture) for architecture in sorted(ARCHITECTURES)},
        "executable_sha256": digest(executable),
        "game_files": len(game), "game_sha256": canonical_manifest(game),
    }


def verify_package(package, extract_to, app, pins, game):
    run(["pkgutil", "--check-signature", str(package)], timeout=120)
    run(["pkgutil", "--expand-full", str(package), str(extract_to)], timeout=180)
    matches = [path for path in extract_to.rglob(app + ".app") if path.is_dir()]
    require(len(matches) == 1, "Package did not contain exactly one expected Mac app")
    details = verify_app(matches[0], app, pins, game, signed=True)
    return matches[0], {**details, "package_sha256": digest(package)}
