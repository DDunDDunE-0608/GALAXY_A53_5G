#!/usr/bin/env python3
"""Read-only AArch64 ADR/ADRP reference scan over raw S-Boot image."""
from __future__ import annotations
import struct
from pathlib import Path

BIN = Path("analysis_payload/sboot.bin")
OUT = Path("A536N_SBOOT_XREF_REPORT.txt")
PATTERNS = [
    b"Not a JPEG file", b"Invalid JPEG file structure", b"Premature end of JPEG file",
    b"Corrupt JPEG data", b"JPEG Load Failed", b"Buffer passed to JPEG library is too small",
    b"JPEG image is bigger than LCD", b"Error Exit at JPEG!!",
    b"Secure boot is enabled (secure chip)", b"Secure boot: enabled (secure chip)",
    b"Secure boot: enabled (test key)", b"Secure boot: disabled",
]
def sx(v: int, bits: int) -> int:
    return (v ^ (1 << (bits - 1))) - (1 << (bits - 1))
def regname(n: int) -> str:
    return "sp" if n == 31 else f"x{n}"
def decode(w: int, pc: int) -> str:
    # ADR / ADRP
    if (w & 0x9F000000) in (0x10000000, 0x90000000):
        imm = (((w >> 5) & 0x7ffff) << 2) | ((w >> 29) & 3)
        imm = sx(imm, 21)
        rd = regname(w & 31)
        if (w & 0x9F000000) == 0x90000000:
            target = (pc & ~0xfff) + (imm << 12)
            return f"adrp {rd}, 0x{target:x}"
        target = pc + imm
        return f"adr {rd}, 0x{target:x}"
    # ADD (immediate), 32- or 64-bit
    if (w & 0x7F000000) == 0x11000000:
        rd, rn = w & 31, (w >> 5) & 31
        imm = (w >> 10) & 0xfff
        if (w >> 22) & 1: imm <<= 12
        return f"add {regname(rd)}, {regname(rn)}, #0x{imm:x}"
    # B / BL
    if (w & 0x7C000000) == 0x14000000:
        imm = sx(w & 0x03ffffff, 26) << 2
        op = "bl" if (w >> 31) else "b"
        return f"{op} 0x{(pc + imm):x}"
    return f".word 0x{w:08x}"

def main():
    data = BIN.read_bytes()
    targets = {}
    for s in PATTERNS:
        p = 0
        while True:
            p = data.find(s, p)
            if p < 0: break
            targets[p] = s.decode("ascii", "replace")
            p += 1
    words = list(struct.unpack("<" + "I" * (len(data)//4), data[:len(data)//4*4]))
    hits = {}
    # Direct ADR references and ADRP followed by ADD using the same base register.
    for i, w in enumerate(words):
        pc = i * 4
        op = w & 0x9F000000
        if op == 0x10000000:
            imm = sx((((w >> 5) & 0x7ffff) << 2) | ((w >> 29) & 3), 21)
            dst = pc + imm
            if dst in targets: hits[(i, dst)] = "ADR"
        elif op == 0x90000000:
            page = (pc & ~0xfff) + (sx((((w >> 5) & 0x7ffff) << 2) | ((w >> 29) & 3), 21) << 12)
            rd = w & 31
            for j in range(i + 1, min(i + 7, len(words))):
                a = words[j]
                if (a & 0x7F000000) == 0x11000000:
                    ard, arn = a & 31, (a >> 5) & 31
                    if ard == rd and arn == rd:
                        imm = (a >> 10) & 0xfff
                        if (a >> 22) & 1: imm <<= 12
                        dst = page + imm
                        if dst in targets: hits[(i, dst)] = f"ADRP+ADD (+{j-i} insns)"
                        break
                # Stop when the ADRP register is overwritten by a non-ADD instruction.
                if (a & 31) == rd and ((a >> 5) & 31) != rd and (a & 0x1f000000) != 0x11000000:
                    break
    lines = [
        "SM-A536N S-BOOT STATIC XREF SCAN",
        "Read-only AArch64 instruction-pattern scan; no device interaction or firmware modification.",
        f"Binary size: {len(data)} bytes; aligned 32-bit words scanned: {len(words)}",
        "Address model: raw file offsets treated as virtual addresses for PC-relative matching.",
        "Assumption: image load base is page-aligned; matches are candidate references, not proof of runtime reachability.",
        f"Target strings found: {len(targets)}",
        f"Candidate references: {len(hits)}",
        "",
    ]
    for (i, dst), how in sorted(hits.items()):
        lines.append(f"TARGET 0x{dst:08x} [{how}]: {targets[dst]}")
        for k in range(max(0, i-5), min(len(words), i+10)):
            pc = k*4
            mark = ">>" if k == i else "  "
            lines.append(f"{mark} 0x{pc:08x}: {words[k]:08x}  {decode(words[k], pc)}")
        lines.append("")
    if not hits:
        lines += [
            "No direct ADR or ADRP+ADD references matched the selected strings.",
            "Possible explanations: indirect pointer tables, a nonzero/non-page-aligned image mapping, references in another BL component, or strings retained but unused.",
        ]
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines[:50]))

if __name__ == "__main__":
    main()
