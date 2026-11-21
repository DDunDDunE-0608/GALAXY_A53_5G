#!/usr/bin/env python3
"""Read-only static inventory for Samsung SM-A536N BL firmware.

This script never flashes, patches, signs, or executes firmware contents.
It decompresses the supplied LZ4 files into a temporary directory and emits
hashes, file identification, AVB header presence, and selected printable strings.
"""
from __future__ import annotations

import hashlib
import re
import subprocess
import tempfile
from pathlib import Path

ROOT = Path("BL_A536NKSUIGZI2_A536NKSUIGZI2_MQB114816381_REV00_user_low_ship_MULTI_CERT")
NAMES = [
    "fld.bin.lz4", "harx.bin.lz4", "keystorage.bin.lz4", "ldfw.img.lz4",
    "sboot.bin.lz4", "tzar.img.lz4", "tzsw.img.lz4", "uh.bin.lz4",
    "up_param.bin.lz4", "vbmeta.img.lz4",
]
PATTERNS = re.compile(
    rb"(?i)(sboot|s5e8825|a536n|exynos|avb|vbmeta|key2|key.?management|"
    rb"up.?param|boot.?param|secure.?boot|verified.?boot|rollback|"
    rb"jpeg|jpg|version|build|release| samsung )"
)

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def printable_strings(data: bytes, min_len: int = 7):
    for match in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, data):
        value = match.group().decode("ascii", "replace")
        if PATTERNS.search(value.encode("ascii", "ignore")):
            yield (match.start(), value[:240])

def main() -> int:
    if not ROOT.is_dir():
        raise SystemExit(f"Firmware directory not found: {ROOT}")
    report = [
        "SM-A536N BL FIRMWARE — READ-ONLY STATIC INVENTORY",
        "Firmware label: A536NKSUIGZI2",
        "Source directory: " + str(ROOT),
        "Scope: metadata/strings only; no exploit execution or device modification.",
        "",
    ]
    with tempfile.TemporaryDirectory(prefix="a536n-bl-") as td:
        temp = Path(td)
        for name in NAMES:
            src = ROOT / name
            report.append("=" * 78)
            report.append(f"FILE: {name}")
            if not src.is_file():
                report.append("STATUS: MISSING")
                continue
            packed = src.read_bytes()
            report.append(f"Compressed size: {len(packed)} bytes")
            report.append(f"Compressed SHA-256: {sha256(packed)}")
            try:
                proc = subprocess.run(
                    ["lz4", "-d", "-c", str(src)],
                    check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                data = proc.stdout
            except subprocess.CalledProcessError as exc:
                report.append("DECOMPRESSION: FAILED")
                report.append(exc.stderr.decode("utf-8", "replace")[:1000])
                continue
            except FileNotFoundError:
                raise SystemExit("lz4 command not installed on runner")
            out = temp / (name[:-4] if name.endswith(".lz4") else name)
            out.write_bytes(data)
            report.append("Decompression: OK")
            report.append(f"Decompressed size: {len(data)} bytes")
            report.append(f"Decompressed SHA-256: {sha256(data)}")
            report.append(f"First 16 bytes: {data[:16].hex(' ')}")
            if data.startswith(b"AVB0"):
                report.append("AVB HEADER: AVB0 magic present (header presence only)")
            if data.startswith(b"\x7fELF"):
                report.append("FORMAT: ELF magic present")
            elif data.startswith(b"ANDROID!"):
                report.append("FORMAT: Android boot image magic present")
            matches = list(printable_strings(data))
            report.append(f"Selected printable-string matches: {len(matches)}")
            for offset, value in matches[:100]:
                report.append(f"  0x{offset:08x}: {value}")
            if len(matches) > 100:
                report.append(f"  ... {len(matches) - 100} additional matches omitted")
            report.append("")
    report.extend([
        "=" * 78,
        "INTERPRETATION LIMITS",
        "- A matching string or magic value does not prove a vulnerability is present.",
        "- Absence of a string does not prove the corresponding code is absent.",
        "- This report does not determine exploitability, unlock eligibility, or KEY2 state.",
        "- No firmware image was modified, signed, flashed, or executed.",
        "",
    ])
    Path("A536N_BL_STATIC_REPORT.txt").write_text("\n".join(report), encoding="utf-8")
    print("\n".join(report[:12]))
    print("\nReport written to A536N_BL_STATIC_REPORT.txt")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
