#!/usr/bin/env python3
"""Read-only extraction of S-Boot and UP_PARAM for offline static inspection."""
from __future__ import annotations
import hashlib, re, subprocess
from pathlib import Path

ROOT = Path("BL_A536NKSUIGZI2_A536NKSUIGZI2_MQB114816381_REV00_user_low_ship_MULTI_CERT")
OUT = Path("analysis_payload")
TARGETS = {"sboot.bin.lz4": "sboot.bin", "up_param.bin.lz4": "up_param.bin"}

def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def jpeg_records(data: bytes):
    pos = 0
    while True:
        start = data.find(b"\xff\xd8", pos)
        if start < 0: break
        end = data.find(b"\xff\xd9", start + 2)
        if end < 0: break
        end += 2
        yield start, end, data[start:end]
        pos = end

def main():
    OUT.mkdir(exist_ok=True)
    report = ["SM-A536N S-BOOT / UP_PARAM EXTRACTION", "Read-only; no device interaction."]
    for packed_name, out_name in TARGETS.items():
        packed_path = ROOT / packed_name
        if not packed_path.is_file(): raise SystemExit(f"Missing input: {packed_path}")
        data = subprocess.run(["lz4", "-d", "-c", str(packed_path)], check=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
        (OUT / out_name).write_bytes(data)
        report += ["", f"{out_name}: {len(data)} bytes; SHA256={sha(data)}"]
        if out_name == "sboot.bin":
            terms = re.compile(rb"(?i)(download|odin|sod|usb|jpeg|libavb|secure boot|compressed)")
            matches = [(m.start(), m.group().decode("ascii", "replace")[:200])
                       for m in re.finditer(rb"[\x20-\x7e]{6,}", data) if terms.search(m.group())]
            report.append(f"Relevant printable strings: {len(matches)}")
            report.extend(f"0x{o:08x}: {v}" for o, v in matches[:250])
        else:
            records = list(jpeg_records(data))
            report.append(f"JPEG SOI/EOI pairs: {len(records)}")
            for i, (start, end, blob) in enumerate(records, 1):
                names = re.findall(rb"[A-Za-z0-9_]+\.jpg", data[max(0,start-0x400):start], re.I)
                name = names[-1].decode("ascii", "replace") if names else f"image_{i:02d}.jpg"
                target = OUT / f"{i:02d}_{re.sub(r'[^A-Za-z0-9_.-]', '_', name)}"
                target.write_bytes(blob)
                report.append(f"{target.name}: offset=0x{start:x}, size={len(blob)}, sha256={sha(blob)}")
    Path("A536N_DEEP_STATIC_REPORT.txt").write_text("\n".join(report)+"\n", encoding="utf-8")
    print("\n".join(report[:30]))

if __name__ == "__main__": main()
