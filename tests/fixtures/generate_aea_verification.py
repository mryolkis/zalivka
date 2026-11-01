"""Independent AEA vectors; Python cryptography + Apple's/Corellium's C codecs.

Usage: python generate_aea_verification.py /path/to/reference-codecs.so
The .so contains lzfse-cgo's lzfse/lzvn and libzbitmap C sources (see README).
Rust tests use the checked-in output and need neither Python nor C.
"""
import base64
import ctypes
import hashlib
import hmac
import json
from pathlib import Path
import struct
import sys
import zlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

CODECS = ctypes.CDLL(sys.argv[1])
KEY = bytes(range(32))
SALT = bytes(range(32, 64))
PAYLOAD = (b"independent Apple archive verification vector\0" * 128) + b"last segment"
SEGMENT = 1024
COUNT = 2
PADDING = b"authenticated padding"


def derive(key, info, length=80, salt=None):
    return HKDF(SHA256(), length, salt, info).derive(key)


def crypt(data, material):
    enc = Cipher(algorithms.AES(material[32:64]), modes.CTR(material[64:])).encryptor()
    return enc.update(data) + enc.finalize()


def mac(data, key, salt=b""):
    return hmac.digest(key, salt + data + struct.pack("<Q", len(salt)), "sha256")


def compressed(data, method):
    output = ctypes.create_string_buffer(len(data) * 2 + 4096)
    if method == "zlib" or method == "unsupported":
        return zlib.compress(data)
    if method in ("lzfse", "lzvn"):
        scratch_size = getattr(CODECS, method + "_encode_scratch_size")()
        scratch = ctypes.create_string_buffer(scratch_size)
        n = getattr(CODECS, method + "_encode_buffer")(output, len(output), data, len(data), scratch)
    elif method == "lzbitmap":
        n = ctypes.c_size_t()
        assert CODECS.zbm_compress(output, len(output), data, len(data), ctypes.byref(n)) == 0
        n = n.value
    elif method == "lz4":
        lib = ctypes.CDLL("liblz4.so.1")
        n = lib.LZ4_compress_default(data, output, len(data), len(output))
    else:
        return data
    assert n > 0
    return output.raw[:n]


def archive(method, bad_checksum=False):
    main = derive(KEY, b"AEA_AMK" + struct.pack("<I", 1), 32, SALT)
    padding_key = derive(main, b"AEA_PAK")
    next_mac = hmac.digest(padding_key[:32], PADDING, "sha256")
    clusters = []
    chunks = [PAYLOAD[i:i + SEGMENT] for i in range(0, len(PAYLOAD), SEGMENT)]
    for index in reversed(range((len(chunks) + COUNT - 1) // COUNT)):
        cluster = derive(main, b"AEA_CK" + struct.pack("<I", index), 32)
        headers = bytearray()
        segments = bytearray()
        segment_macs = bytearray()
        for j in range(COUNT):
            number = index * COUNT + j
            if number >= len(chunks):
                headers += bytes(40)
                segment_macs += bytes(32)
                continue
            raw = chunks[number]
            data = compressed(raw, method)
            if len(data) >= len(raw):
                data = raw
            checksum = hashlib.sha256(raw).digest()
            if bad_checksum and number == 0:
                checksum = bytes(32)
            headers += struct.pack("<II", len(raw), len(data)) + checksum
            material = derive(cluster, b"AEA_SK" + struct.pack("<I", j))
            encrypted = crypt(data, material)
            segments += encrypted
            segment_macs += mac(encrypted, material[:32])
        material = derive(cluster, b"AEA_CHEK")
        encrypted = crypt(headers, material)
        salt = next_mac + segment_macs
        clusters.insert(0, encrypted + salt + segments)
        next_mac = mac(encrypted, material[:32], salt)
    body = b"".join(clusters) + PADDING
    code = {"none": b"-", "zlib": b"z", "lzfse": b"e", "lzvn": b"f", "lzbitmap": b"b", "lz4": b"4", "unsupported": b"?"}[method]
    root = struct.pack("<QQII", len(PAYLOAD), 156 + len(body), SEGMENT, COUNT) + code + b"\x02" + bytes(22)
    material = derive(main, b"AEA_RHEK")
    encrypted = crypt(root, material)
    root_mac = mac(encrypted, material[:32], next_mac)
    return b"AEA1" + struct.pack("<II", 1, 0) + SALT + root_mac + encrypted + next_mac + body


value = {"key": KEY.hex(), "plaintext": base64.b64encode(PAYLOAD).decode(), "sha384": hashlib.sha384(PAYLOAD).hexdigest(), "vectors": []}
for method in ("none", "zlib", "lzfse", "lzvn", "lzbitmap", "lz4", "unsupported"):
    value["vectors"].append({"compression": method, "archive": base64.b64encode(archive(method)).decode()})
value["bad_checksum"] = base64.b64encode(archive("zlib", True)).decode()
Path(__file__).with_name("aea-verification.json").write_text(json.dumps(value, indent=2) + "\n")
