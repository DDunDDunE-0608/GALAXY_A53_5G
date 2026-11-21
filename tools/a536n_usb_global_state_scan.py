#!/usr/bin/env python3
"""Capstone disassembly of USB receive routine and references to its global bounds state."""
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

BIN=Path("analysis_payload/sboot.bin")
OUT=Path("A536N_USB_GLOBAL_STATE_REPORT.txt")
START=0x0f8e80
END=0x0f9300

def main():
    data=BIN.read_bytes()
    md=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
    md.detail=True
    lines=[
      "SM-A536N S-BOOT USB RECEIVE GLOBAL-STATE TRACE",
      "Read-only AArch64 disassembly using Capstone.",
      "Offsets are shown as image-relative addresses; runtime load base is not assumed.",
      f"Disassembly window: 0x{START:08x}..0x{END:08x}",
      ""
    ]
    for ins in md.disasm(data[START:END],START):
      lines.append(f"0x{ins.address:08x}: {ins.bytes.hex():<16} {ins.mnemonic:<9} {ins.op_str}")
    lines += [
      "",
      "Review checklist:",
      "- Identify the base/end pointers and their initialization stores in this routine.",
      "- Track every load/store to the globals used around the 0xF9000 receive loop.",
      "- Determine whether the command-specific comparisons use the same end pointer.",
      "- This report is disassembly evidence only; it does not prove runtime reachability or full safety."
    ]
    OUT.write_text("\n".join(lines)+"\n",encoding="utf-8")
    print("\n".join(lines[:180]))
if __name__=="__main__": main()
