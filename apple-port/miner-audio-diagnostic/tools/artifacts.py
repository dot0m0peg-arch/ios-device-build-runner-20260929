"""Fetch exact encrypted inputs and exchange authenticated runner products."""
from hashlib import sha1
import json
import os
from pathlib import Path
from io import BytesIO
from shutil import copyfileobj
from urllib.request import Request, urlopen
from zipfile import ZipFile

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from verify_release import APP_IDS, digest, names_in, require, verify_source_tree

REPOSITORY = "dot0m0peg-arch/ios-device-build-runner-20260929"
BRANCH = "codex/miner-audio-diagnostic-20261119"
PREFIX = "apple-port/polished-mac-20261119/"
BASE_COMMIT = "daa72e74cdcbbe17a40bb7c46e9f3091312c4473"
ROOT = Path(os.environ["RUNNER_TEMP"])


def cipher():
    return AESGCM(bytes.fromhex(os.environ["IPA_KEY_HEX"]))


def context_file():
    app = os.environ["APP_KEY"]
    require(app in APP_IDS, "Unknown polished Mac app")
    require(os.environ["GITHUB_REPOSITORY"] == REPOSITORY, "Unexpected runner repository")
    require(os.environ["GITHUB_REF"] == "refs/heads/" + BRANCH, "Unexpected workflow branch")
    return app, ROOT / "polished-release.json"


def fetch_sources():
    app, state = context_file()
    def files(commit):
        api_url = f"https://api.github.com/repos/{REPOSITORY}/git/trees/{commit}?recursive=1"
        req = Request(api_url, headers={"Authorization": "Bearer " + os.environ["GH_TOKEN"],
                                        "Accept": "application/vnd.github+json"})
        with urlopen(req, timeout=45) as response:
            tree = json.load(response)
        require(not tree.get("truncated"), "Incomplete Git tree")
        return {entry["path"]: entry["sha"] for entry in tree["tree"] if entry["type"] == "blob"}

    def read(commit, identifiers, name):
        raw_url = f"https://raw.githubusercontent.com/{REPOSITORY}/{commit}/"
        with urlopen(raw_url + name, timeout=95) as response:
            content = response.read()
        git_payload = f"blob {len(content)}".encode() + b"\0" + content
        require(sha1(git_payload).hexdigest() == identifiers[name], "Git blob identity mismatch")
        return content

    commit = os.environ["GITHUB_SHA"]
    new_files, base_files = files(commit), files(BASE_COMMIT)
    aes = cipher()
    private_prefix = PREFIX + app + "/"
    encrypted = read(commit, new_files, private_prefix + "pins.aesgcm")
    pins = json.loads(aes.decrypt(encrypted[:12], encrypted[12:], (app + ":pins").encode()))
    base_prefix = "apple-port/" + app + "/"
    parts = sorted(name for name in base_files
                   if name.startswith(base_prefix) and name.endswith(".aesgcm"))
    require(parts and parts == [
        base_prefix + f"{number:03d}.aesgcm" for number in range(len(parts))
    ], "Unexpected encrypted baseline segment inventory")
    original = ROOT / "baseline-mac-source.zip"
    with original.open("xb") as destination:
        for number, name in enumerate(parts):
            encrypted = read(BASE_COMMIT, base_files, name)
            destination.write(aes.decrypt(encrypted[:12], encrypted[12:], f"{app}:{number}".encode()))
    require(digest(original) == pins["baseline_sha256"], "Immutable encrypted Apple baseline did not match the local source pin")
    overlay = ROOT / "polished-source-overlay.zip"
    chunks = sorted(name for name in new_files
                    if name.startswith(private_prefix + "overlay/") and name.endswith(".aesgcm"))
    require(chunks and chunks == [
        private_prefix + f"overlay/{number:03d}.aesgcm" for number in range(len(chunks))
    ], "Unexpected encrypted overlay segment inventory")
    with overlay.open("xb") as destination:
        for number, name in enumerate(chunks):
            encrypted = read(commit, new_files, name)
            destination.write(aes.decrypt(encrypted[:12], encrypted[12:], f"{app}:overlay:{number}".encode()))
    require(digest(overlay) == pins["overlay_sha256"], "Polished source overlay SHA mismatch")
    frozen = ROOT / "apple-source"
    materialize_source(original, overlay, frozen, pins)
    game = verify_source_tree(frozen, app, pins)
    state.write_text(json.dumps({"app": app, "pins": pins, "game": game}))
    print(f"{app}: source and {len(game)} resource digests verified")


def materialize_source(original, overlay, frozen, pins):
    with ZipFile(original) as base, ZipFile(overlay) as replacement:
        base_names, overlay_names = set(names_in(base)), set(names_in(replacement))
        for name in pins["source_files"]:
            archive = replacement if name in overlay_names else base
            require(name in overlay_names or name in base_names, "Frozen source member missing from both layers")
            target = frozen / name
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(name) as source, target.open("xb") as destination:
                copyfileobj(source, destination)


def transfer(mode, source_dir, destination_dir, phase):
    app, _ = context_file()
    source, destination = Path(source_dir), Path(destination_dir)
    destination.mkdir(exist_ok=True)
    aes = cipher()
    run = os.environ["GITHUB_RUN_ID"]
    if mode == "encrypt":
        for path in sorted(source.glob("*")):
            require(path.is_file() and not path.is_symlink(), "Unexpected transfer member")
            nonce = os.urandom(12)
            aad = f"{app}:{run}:{phase}:{path.name}".encode()
            (destination / (path.name + ".aesgcm")).write_bytes(nonce + aes.encrypt(nonce, path.read_bytes(), aad))
    else:
        parts = list(source.glob("*.aesgcm"))
        require(parts and len(parts) == len(list(source.iterdir())), "Unexpected encrypted artifact")
        for path in sorted(parts):
            encrypted = path.read_bytes()
            aad = f"{app}:{run}:{phase}:{path.stem}".encode()
            (destination / path.stem).write_bytes(aes.decrypt(encrypted[:12], encrypted[12:], aad))


if __name__ == "__main__":
    import sys

    operation, *arguments = sys.argv[1:]
    if operation == "source" and not arguments:
        fetch_sources()
    elif operation in {"encrypt", "decrypt"} and len(arguments) == 3:
        transfer(operation, *arguments)
    else:
        raise SystemExit("Expected source, encrypt, or decrypt")
