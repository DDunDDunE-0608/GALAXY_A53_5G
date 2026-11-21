#!/usr/bin/env python3
"""Read-only whole-image search for stores to selected S-Boot USB globals."""
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM, ARM64_OP_MEM

BIN = Path("analysis_payload/sboot.bin")
OUT = Path("A536N_USB_POINTER_STORE_REPORT.txt")
PAGE = 0x564000
TARGETS = {0x1b8: "end_or_limit_A", 0x1c0: "receive_current_pointer", 0x1c8: "receive_end_pointer"}
STORE_MNEMONICS = {"str", "stur", "stp", "stnp", "stlr", "stxr", "stlxr", "cas", "casa", "casal", "swp"}

def insn_at(md, data, off):
    return next(md.disasm(data[off:off+4], off), None)

def main():
    data = BIN.read_bytes()
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    lines = [
        "SM-A536N S-BOOT USB POINTER STORE XREF (READ-ONLY)",
        f"Image size: {len(data)} bytes",
        "Search: ADRP page 0x564000 followed by nearby memory accesses to selected offsets.",
        "This is a static candidate scan; mixed code/data and register reuse can create false positives.",
        ""
    ]
    hits = 0
    for off in range(0, len(data)-4, 4):
        x = insn_at(md, data, off)
        if not x or x.mnemonic != "adrp" or len(x.operands) < 2:
            continue
        if x.operands[0].type != ARM64_OP_REG or x.operands[1].type != ARM64_OP_IMM or x.operands[1].imm != PAGE:
            continue
        base = x.operands[0].reg
        found = []
        for j in range(1, 65):
            y = insn_at(md, data, off + 4*j)
            if not y:
                continue
            for op in y.operands:
                if op.type == ARM64_OP_MEM and op.mem.base == base and op.mem.disp in TARGETS:
                    if y.mnemonic in STORE_MNEMONICS:
                        found.append((y, op.mem.disp))
            # Stop once an instruction overwrites the ADRP destination register.
            if y.operands and y.operands[0].type == ARM64_OP_REG and y.operands[0].reg == base:
                if y.mnemonic not in STORE_MNEMONICS and y.mnemonic not in {"ldr", "ldur", "ldp", "ldnp", "ldar", "ldxr", "ldaxr"}:
                    break
        if found:
            hits += len(found)
            lines.append(f"ADRP @ 0x{x.address:08x}: {x.mnemonic} {x.op_str}")
            for y, disp in found:
                lines.append(f"  STORE @ 0x{y.address:08x}: {y.mnemonic:<8} {y.op_str} ; +0x{disp:x} {TARGETS[disp]}")
            lines.append("")
    lines += [
        f"Candidate store references: {hits}",
        "Zero hits would not prove absence: globals may be initialized through aliases, relocations, copied structures, or another base page.",
        "No runtime behavior, exploitability, or vulnerability conclusion is made."
    ]
    OUT.write_text("\\n".join(lines) + "\\n", encoding="utf-8")
    print("\\n".join(lines[:240]))

if __name__ == "__main__":
    main()
