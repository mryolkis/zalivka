These are small reference samples from Apple's public
[UniversalMac 27.2 / 26B123 IPSW](https://updates.cdn-apple.com/2026FallFCS/c9671975-52db-4fb5-9af2-00217169ba8d/UniversalMac_27.2_26B123_Restore.ipsw),
retrieved with bounded HTTP Range requests on 2026-11-01. The complete IPSW is
25,595,669,503 bytes and is not included. `provenance.json` records source and
fixture SHA-256 values. These are firmware samples, not tickets from a user's
personalization session.

- `restore.im4m` and `cryptex.im4m` are unchanged `j313ap` global manifests.
- The two `.im4p` files are unchanged BaseSystem and Cryptex App trust caches.
  `members.json` preserves their original ZIP member paths.
- `BuildManifest-excerpt.plist` retains original identities 3 and 63 (erase and
  update for j313ap), their metadata, and only those two component declarations.
  Its digest values are unchanged. The original complete manifest's SHA-256 is
  recorded in `provenance.json`.
- `aea-first-segment.bin` is the original BaseSystem AEA prefix, authenticated
  cluster header, and first encrypted segment. It is deliberately incomplete.
  Tests authenticate and decode its first 1 MiB segment, compare its SHA-256,
  then require rejection of the truncated archive. They never mark it as a
  successfully verified complete image.
- `public-fcs.pem` is the public firmware key published by Apple's
  `wkms-public.apple.com/fcs-keys/` service, identified in that AEA's metadata.
  The expected archive key was independently unwrapped with `blacktop/ipsw`;
  the plaintext segment was independently decoded with Apple's C LZFSE decoder.
- `ipsw-reference.json` contains the measurement output of `blacktop/ipsw`
  3.1.741, build `126b1d5ec810a3a7a94a9d4942aaa76ca03fb350`.
  Both IM4M comparisons against the excerpt also succeed with that CLI.
- `murmur64-reference.json` contains `github.com/twmb/murmur3` v1.2.2
  `SeedSum64(0xE2236FDC26A5F6D2, bytes(0..length))` for lengths 0 through 33.
  This covers complete blocks and every tail length using AEA's 64-bit seed.

The ordinary Rust test suite uses these checked-in samples without a network,
Python, a C compiler, or an external IPSW. To repeat the independent comparison:

```sh
python tests/fixtures/ipsw-verification/check_reference.py /path/to/ipsw
```

`../aea-verification.json` is a separate set of complete, independently generated
AEA archives. They cover several clusters, partial final segments, padding,
every supported compression method, an unknown compression method, and a validly
authenticated image with an invalid plaintext checksum. The generator is
`../generate_aea_verification.py`; it uses Python `cryptography`, zlib, the system
LZ4 C library, and Apple's LZFSE/LZVN and Corellium's LZBITMAP C implementations
from [lzfse-cgo](https://github.com/blacktop/lzfse-cgo/tree/9aa17847f933b151210446ffd54325925d125f65).
The Rust verifier does not generate its own expected crypto/codec results.

To reproduce these synthetic vectors, compile the reference C sources into a
shared library and pass its path to the generator:

```sh
cc -shared -fPIC -O2 lzfse_decode.c lzfse_decode_base.c lzfse_encode.c \
  lzfse_encode_base.c lzfse_fse.c lzvn_decode_base.c lzvn_encode_base.c \
  libzbitmap.c -o /tmp/reference-codecs.so
python /path/to/zalivka/tests/fixtures/generate_aea_verification.py /tmp/reference-codecs.so
```
