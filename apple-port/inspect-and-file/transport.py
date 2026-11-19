"""Encrypted transport only. No company source or device data is accepted here."""
import argparse, hashlib, json, os, pathlib, subprocess, sys, zipfile
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
AAD = b'InspectAndFile:native-qualification:v1'
p = argparse.ArgumentParser()
p.add_argument('action', choices=['unpack', 'pack'])
p.add_argument('source', type=pathlib.Path)
p.add_argument('dest', type=pathlib.Path)
p.add_argument('--sha256')
a = p.parse_args()
key = bytes.fromhex(os.environ['IPA_KEY_HEX'].strip())
if len(key) != 32: raise ValueError('Existing transport key must be 256 bit')
box = AESGCM(key)
if a.action == 'unpack':
    sealed = a.source.read_bytes()
    raw = box.decrypt(sealed[:12], sealed[12:], AAD)
    if not a.sha256 or hashlib.sha256(raw).hexdigest() != a.sha256:
        raise ValueError('Source archive does not match reviewed SHA256')
    import io
    a.dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        if sum(i.file_size for i in z.infolist()) > 40_000_000:
            raise ValueError('Unexpected source archive size')
        for item in z.infolist():
            path = pathlib.PurePosixPath(item.filename)
            if path.is_absolute() or '..' in path.parts or '\\' in item.filename or ':' in item.filename:
                raise ValueError('Unsafe archive path')
            if ((item.external_attr >> 16) & 0o170000) == 0o120000:
                raise ValueError('Source symlink forbidden')
        z.extractall(a.dest)
    print('Verified and opened reviewed native source')
else:
    import io
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w', zipfile.ZIP_DEFLATED) as z:
        for path in sorted(a.source.rglob('*')):
            if path.is_file() and not path.is_symlink():
                z.write(path, path.relative_to(a.source).as_posix())
    raw = stream.getvalue()
    nonce = os.urandom(12)
    a.dest.parent.mkdir(parents=True, exist_ok=True)
    a.dest.write_bytes(nonce + box.encrypt(nonce, raw, AAD))
    print(json.dumps({'encrypted_artifact_bytes': a.dest.stat().st_size, 'clear_sha256': hashlib.sha256(raw).hexdigest()}))