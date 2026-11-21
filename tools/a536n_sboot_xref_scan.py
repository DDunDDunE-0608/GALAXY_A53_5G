#!/usr/bin/env python3
"""Read-only AArch64 PC-relative reference scan for selected S-Boot strings."""
from __future__ import annotations
import re
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

BIN = Path("analysis_payload/sboot.bin")
OUT = Path("A536N_SBOOT_XREF_REPORT.txt")
PATTERNS = [
    b"Not a JPEG file", b"Invalid JPEG file structure", b"Premature end of JPEG file",
    b"Corrupt JPEG data", b"JPEG Load Failed", b"Buffer passed to JPEG library is too small",
    b"JPEG image is bigger than LCD", b"Error Exit at JPEG!!",
    b"Secure boot is enabled (secure chip)", b"Secure boot: enabled (secure chip)",
    b"Secure boot: enabled (test key)", b"Secure boot: disabled",
]
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
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    insns = list(md.disasm(data, 0))
    by_addr = {i.address: n for n, i in enumerate(insns)}
    hits = []
    # Direct ADR references.
    for n, ins in enumerate(insns):
        if ins.mnemonic == "adr" and len(ins.operands) >= 2:
            dst = ins.operands[1].imm
            if dst in targets:
                hits.append((n, dst, "ADR"))
        # ADRP + ADD (same destination register) references.
        if ins.mnemonic != "adrp" or len(ins.operands) < 2:
            continue
        reg = ins.operands[0].reg
        page = ins.operands[1].imm
        for j in range(n + 1, min(n + 7, len(insns))):
            nxt = insns[j]
            if nxt.mnemonic == "add" and len(nxt.operands) >= 3:
                if nxt.operands[0].reg == reg and nxt.operands[1].reg == reg:
                    imm = nxt.operands[2].imm
                    dst = page + imm
                    if dst in targets:
                        hits.append((n, dst, f"ADRP+ADD at +{j-n} insns"))
                    break
            # Stop if the ADRP destination register is overwritten.
            if nxt.operands and nxt.operands[0].type == 1 and nxt.operands[0].reg == reg:
                if nxt.mnemonic not in ("add", "mov"):
                    break
    # De-duplicate and render compact context around each reference.
    unique = {}
    for n, dst, how in hits:
        unique[(n, dst)] = how
    lines = [
        "SM-A536N S-BOOT STATIC XREF SCAN",
        "Read-only disassembly; no device interaction or firmware modification.",
        f"Binary size: {len(data)} bytes",
        f"Disassembled AArch64 instructions: {len(insns)}",
        "Address model: raw file offsets used as virtual addresses for PC-relative reference matching.",
        "This assumes a page-aligned load base; matches are candidate references, not proof of runtime reachability.",
        f"Target strings found: {len(targets)}",
        f"Candidate references: {len(unique)}",
        "",
    ]
    for (n, dst), how in sorted(unique.items()):
        label = targets[dst]
        lines.append(f"TARGET 0x{dst:08x} [{how}]: {label}")
        lo, hi = max(0, n - 5), min(len(insns), n + 10)
        for k in range(lo, hi):
            ins = insns[k]
            mark = ">>" if k == n else "  "
            lines.append(f"{mark} 0x{ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}")
        lines.append("")
    if not unique:
        lines += ["No direct ADR or ADRP+ADD references matched the selected strings.",
                  "This can occur if references are indirect, data is relocated, or the raw image uses a different layout."]
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines[:40]))

if __name__ == "__main__":
    main()
