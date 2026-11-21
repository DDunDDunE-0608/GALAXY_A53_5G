#!/usr/bin/env python3
"""Validate the observed S-Boot USB packet-size guard instruction sequence."""
from pathlib import Path
import struct

BIN=Path("analysis_payload/sboot.bin")
OUT=Path("A536N_USB_SIZE_GUARD_REPORT.txt")
# Raw offsets from the USB packet-size diagnostic's direct ADRP+ADD reference.
OFF=0x1c1b24
EXPECTED=[
 0xb9801be1, # LDRSW X1, [SP,#0x18]
 0xf0003173, # ADRP X19, global state
 0x9136f273, # ADD X19, X19, #0xdbc
 0xd360fc28, # LSR X8, X1, #32
 0xd3587c29, # UBFX W9, W1, #24, #8
 0x29002261, # STP W1, W8, [X19]
 0x34005f29, # CBZ W9, accepted path
 0xd0000600, # ADRP X0, USB size error string
 0x9101f400, # ADD X0, X0, #0x7d
 0x97fe8f1c, # BL logger
]
def main():
 data=BIN.read_bytes()
 got=list(struct.unpack_from("<10I",data,OFF))
 ok=got==EXPECTED
 lines=[
  "SM-A536N S-BOOT USB PACKET-SIZE GUARD",
  "Read-only instruction-pattern validation; no device access or firmware modification.",
  f"Binary size: {len(data)} bytes",
  f"Sequence offset: 0x{OFF:08x}",
  f"Exact instruction sequence match: {'yes' if ok else 'no'}",
  "",
 ]
 names=[
  "LDRSW X1, [SP,#0x18]",
  "ADRP X19, global state",
  "ADD X19, X19, #0xdbc",
  "LSR X8, X1, #32",
  "UBFX W9, W1, #24, #8",
  "STP W1, W8, [X19]",
  "CBZ W9, accepted path",
  "ADRP X0, USB packet-size diagnostic",
  "ADD X0, X0, #0x7d",
  "BL logger",
 ]
 for i,(w,n) in enumerate(zip(got,names)):
  lines.append(f"0x{OFF+i*4:08x}: 0x{w:08x}  {n}")
 lines += [
  "",
  "Static interpretation:",
  "- A 32-bit value is loaded from the stack slot at SP+0x18 with sign extension.",
  "- Bits 24..31 of its low 32-bit value are extracted into W9.",
  "- If W9 is zero, control branches to the accepted path; otherwise the USB packet-size diagnostic is logged.",
  "- This is consistent with a guard rejecting values whose upper byte is nonzero (including negative signed values).",
  "- This does NOT establish the maximum safe allocation, per-transfer bounds, destination buffer capacity, or the absence/presence of a separate copy overflow.",
  "- The field's full semantic role should be confirmed by tracing the caller and downstream consumers.",
 ]
 if not ok: lines += ["", "WARNING: instruction bytes differ from the expected sequence; do not rely on the interpretation above."]
 OUT.write_text("\n".join(lines)+"\n",encoding="utf-8")
 print("\n".join(lines))
if __name__=="__main__": main()
