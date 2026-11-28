"""Mac-lane AES-GCM envelope and P8 chunk transport. Codex (worker for Command)."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
from urllib.request import Request, urlopen
from zipfile import ZipFile
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PREFIX = "apple-port/ios-p8-20261125/"
AAD = "apple-iphone-lastcar-miner-20261125"


def cipher():
    return AESGCM(bytes.fromhex(os.environ["IPA_KEY_HEX"].strip()))


def pack(source, dest):
    dest.mkdir(parents=True, exist_ok=False)
    aes = cipher()
    rows = []
    with source.open("rb") as stream:
        while data := stream.read(12 * 1024 * 1024):
            index = len(rows)
            name = f"{index:03d}.aesgcm"
            nonce = os.urandom(12)
            encrypted = nonce + aes.encrypt(nonce, data, f"{AAD}:{index}".encode())
            (dest / name).write_bytes(encrypted)
            rows.append({"name": name, "sha256": hashlib.sha256(encrypted).hexdigest()})
    with source.open("rb") as stream:
        sha = hashlib.file_digest(stream, "sha256").hexdigest()
    (dest / "index.json").write_text(json.dumps({"sha256": sha, "chunks": rows}), encoding="utf-8")
    print(f"Encrypted {len(rows)} overlay segments for {sha}")


def receive(tree):
    root = Path(os.environ["RUNNER_TEMP"])
    repo = os.environ["GITHUB_REPOSITORY"]
    revision = os.environ["GITHUB_SHA"]
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("Missing exact commit SHA")
    headers = {"Authorization": "Bearer " + os.environ["GH_TOKEN"],
               "Accept": "application/vnd.github.raw+json", "X-GitHub-Api-Version": "2022-11-28"}

    def fetch(name):
        req = Request(f"https://api.github.com/repos/{repo}/contents/{PREFIX}{name}?ref={revision}", headers=headers)
        with urlopen(req, timeout=120) as response:
            return response.read()

    index = json.loads(fetch("index.json"))
    archive = root / "p8-overlay.zip"
    aes = cipher()
    if not index["chunks"] or len(index["chunks"]) > 95:
        raise ValueError("Unexpected overlay chunk count")
    with archive.open("wb") as stream:
        for number, row in enumerate(index["chunks"]):
            name = f"{number:03d}.aesgcm"
            if name != row["name"]:
                raise ValueError("Unordered overlay chunks")
            encrypted = fetch(name)
            if hashlib.sha256(encrypted).hexdigest() != row["sha256"]:
                raise ValueError(f"Overlay chunk {name} hash mismatch")
            stream.write(aes.decrypt(encrypted[:12], encrypted[12:], f"{AAD}:{number}".encode()))
    with archive.open("rb") as stream:
        sha = hashlib.file_digest(stream, "sha256").hexdigest()
    if sha != index["sha256"]:
        raise ValueError("Overlay archive hash mismatch")
    with ZipFile(archive) as bundle:
        seen = set()
        for name in bundle.namelist():
            target = (tree / name).resolve()
            if not target.is_relative_to(tree.resolve()) or target in seen:
                raise ValueError("Unsafe or duplicate ZIP path")
            seen.add(target)
        bundle.extractall(tree)
    (tree / "release/overlay-sha256.txt").write_text(sha, encoding="ascii")
    print(f"Verified encrypted overlay {sha}")


def artifacts(source, dest):
    dest.mkdir(parents=True, exist_ok=True)
    aes = cipher()
    for path in sorted(source.glob("*")):
        if not path.is_file():
            continue
        nonce = os.urandom(12)
        (dest / (path.name + ".aesgcm")).write_bytes(nonce + aes.encrypt(nonce, path.read_bytes(), None))


def decrypt(source, dest):
    dest.mkdir(parents=True, exist_ok=True)
    aes = cipher()
    for path in sorted(source.glob("*.aesgcm")):
        target = dest / path.name.removesuffix(".aesgcm")
        data = path.read_bytes()
        clear = aes.decrypt(data[:12], data[12:], None)
        if target.exists() and target.read_bytes() != clear:
            raise ValueError(f"Different existing artifact {target}")
        target.write_bytes(clear)
        print("Decrypted", target)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="mode", required=True)
    for name in ("pack", "artifacts", "decrypt"):
        command = commands.add_parser(name)
        command.add_argument("source", type=Path)
        command.add_argument("destination", type=Path)
    command = commands.add_parser("receive")
    command.add_argument("tree", type=Path)
    args = parser.parse_args()
    if args.mode == "receive":
        receive(args.tree)
    else:
        {"pack": pack, "artifacts": artifacts, "decrypt": decrypt}[args.mode](args.source, args.destination)

