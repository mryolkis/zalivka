"""Compare the checked-in Apple samples with an independent ipsw executable.

Usage: python check_reference.py /path/to/blacktop/ipsw
Uses only local fixture files, including Apple's public FCS PEM.
"""
import base64
import json
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parent
executable = sys.argv[1]
reference = json.loads((root / "ipsw-reference.json").read_text())
for name, expected in reference["manifests"].items():
    path = root / (name + ".im4m")
    actual = json.loads(subprocess.check_output([executable, "img4", "im4m", "info", "--json", str(path)]))
    assert actual["properties"] == expected["properties"], name
    assert actual["images"] == expected["images"], name
    subprocess.run([executable, "img4", "im4m", "verify", "--build-manifest", str(root / "BuildManifest-excerpt.plist"), str(path)], check=True)
    print(f"{name}: hardware and {len(actual['images'])} image measurements agree")

key = subprocess.check_output([executable, "fw", "aea", "--key", "--pem", str(root / "public-fcs.pem"), str(root / "aea-first-segment.bin")], text=True).strip()
expected = json.loads((root / "aea-first-segment.json").read_text())
assert bytes.fromhex(expected["archive_key"]) == base64.b64decode(key.removeprefix("base64:"))
print("AEA: public FCS archive key agrees")
