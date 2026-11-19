"""Carry reviewed device inputs and signed output only as authenticated encrypted archives."""
from argparse import ArgumentParser
from hashlib import sha256
from io import BytesIO
import os
from pathlib import Path, PurePosixPath
import stat
from zipfile import ZIP_DEFLATED, ZipFile

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

INPUT_AAD = b"InspectAndFile:device-release:v1:input"
OUTPUT_AAD = b"InspectAndFile:device-release:v1:products"
PRODUCTS = {"InspectAndFile.ipa", "receipt.json", "device-archive.log", "apple-delivery.log"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unpack(source, destination, cipher, expected):
    require(28 <= source.stat().st_size <= 24 * 1024 * 1024 + 28, "Unexpected encrypted input size.")
    payload = source.read_bytes()
    raw = cipher.decrypt(payload[:12], payload[12:], INPUT_AAD)
    require(expected and sha256(raw).hexdigest() == expected, "Reviewed device input hash mismatch.")
    with ZipFile(BytesIO(raw)) as archive:
        used = set()
        require(sum(item.file_size for item in archive.infolist()) <= 25 * 1024 * 1024, "Unexpected expanded input size.")
        for item in archive.infolist():
            path = PurePosixPath(item.filename)
            require(not item.is_dir() and path.as_posix() == item.filename and len(path.parts) > 0
                    and not path.is_absolute() and ".." not in path.parts and "\\" not in item.filename
                    and ":" not in item.filename and item.filename not in used
                    and not stat.S_ISLNK(item.external_attr >> 16), "Unsafe release archive member.")
            used.add(item.filename)
        destination.mkdir(parents=True, exist_ok=False)
        archive.extractall(destination)
    print("Verified and opened the encrypted device release input.")


def pack(source, destination, cipher):
    paths = sorted(source.iterdir())
    require(paths and all(p.name in PRODUCTS and p.is_file() and not p.is_symlink() for p in paths),
            "An unexpected release product would have been exported.")
    require(sum(p.stat().st_size for p in paths) <= 160 * 1024 * 1024, "Unexpected device artifact size.")
    buffer = BytesIO()
    with ZipFile(buffer, "w", ZIP_DEFLATED) as archive:
        for path in paths:
            archive.write(path, path.name)
    nonce = os.urandom(12)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as output:
        output.write(nonce + cipher.encrypt(nonce, buffer.getvalue(), OUTPUT_AAD))
    print("Encrypted exact device products and logs.")


def main():
    parser = ArgumentParser()
    parser.add_argument("operation", choices=["unpack", "pack"])
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--sha256")
    args = parser.parse_args()
    key = bytes.fromhex(os.environ["IPA_KEY_HEX"].strip())
    require(len(key) == 32, "Expected the existing 256-bit transport key.")
    cipher = AESGCM(key)
    if args.operation == "unpack":
        unpack(args.source, args.destination, cipher, args.sha256)
    else:
        pack(args.source, args.destination, cipher)


if __name__ == "__main__":
    main()
