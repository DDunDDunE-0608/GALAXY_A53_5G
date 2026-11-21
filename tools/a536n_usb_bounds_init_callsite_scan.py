#!/usr/bin/env python3
"""Read-only cross-reference and context for the USB length/bounds initializer."""
from pathlib import Path
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

BIN=Path("analysis_payload/sboot.bin")
OUT=Path("A536N_USB_BOUNDS_INIT_CALLSITE_REPORT.txt")
TARGET=0x0f8e1c
HELPER_START=0x0f8e1c
HELPER_END=0x0f8e84
CONTEXT=0x80

def decode(md,data,start,end):
    return [f"0x{i.address:08x}: {i.bytes.hex():<16} {i.mnemonic:<9} {i.op_str}"
            for i in md.disasm(data[start:end],start)]

def main():
    data=BIN.read_bytes()
    md=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
    refs=[]
    for off in range(0,len(data)-3,4):
        word=struct.unpack_from("<I",data,off)[0]
        if word & 0xfc000000 == 0x94000000:
            imm=word & 0x03ffffff
            if imm & (1<<25): imm-=1<<26
            dest=off+(imm<<2)
            if dest==TARGET: refs.append(off)
    lines=[
      "SM-A536N USB BOUNDS INITIALIZER CALLSITE TRACE (READ-ONLY)",
      f"Image size: {len(data)} bytes",
      f"Direct BL target scanned: 0x{TARGET:08x}",
      f"Direct BL references found: {len(refs)}",
      "Method: aligned AArch64 BL immediate scan, followed by Capstone disassembly of callsite context.",
      "A missing direct BL reference would not exclude indirect calls or function-pointer dispatch.",
      ""
    ]
    for addr in refs:
        start=max(0,addr-CONTEXT); end=min(len(data),addr+CONTEXT)
        lines.append(f"CALLSITE CONTEXT 0x{start:08x}..0x{end:08x} (call at 0x{addr:08x})")
        lines.extend(decode(md,data,start,end))
        lines.append("")
    lines.append(f"INITIALIZER BODY 0x{HELPER_START:08x}..0x{HELPER_END:08x}")
    lines.extend(decode(md,data,HELPER_START,HELPER_END))
    lines += [
      "",
      "Review notes:",
      "- Establish the caller-supplied meaning and origin of x2 before treating it as a transfer length.",
      "- Establish the runtime value and meaning of the global loaded into x8 before interpreting alignment arithmetic.",
      "- Verify whether the initializer is reached on the USB receive path.",
      "- This is static evidence only; it does not prove runtime reachability, memory unsafety, or vulnerability."
    ]
    OUT.write_text("\n".join(lines)+"\n",encoding="utf-8")
    print("\n".join(lines[:500]))
if __name__=="__main__": main()
