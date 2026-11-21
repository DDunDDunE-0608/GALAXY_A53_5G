#!/usr/bin/env python3
"""Validate static USB receive-buffer and 1 KiB command-parser guard patterns."""
from pathlib import Path
import struct

BIN=Path("analysis_payload/sboot.bin")
OUT=Path("A536N_USB_BUFFER_BOUNDS_REPORT.txt")
CHECKS={
 "receive_buffer_alloc_512KiB":(0x0f8f24,[0x52a00100,0x940188f6,0xf9011e80,0xb4009120]),
 "receive_buffer_zero_512KiB":(0x0f8f34,[0x52a00102,0x2a1f03e1,0x9401c40f,0xf9411e88]),
 "current_pointer_plus_received_length":(0x0f8fec,[0x2a1403f3,0x8b130168,0x7101953f,0xf900e148]),
 "per_command_end_pointer_check":(0x0f9018,[0x121d794a,0x7100095f,0x54001041,0xeb09011f,0x540014e2]),
 "one_kib_threshold_and_parser_call":(0x0f918c,[0x0b140108,0x7110011f,0xb901f268,0x54000ccb,0x9403218a]),
 "parser_fixed_1KiB_copy":(0x1c17dc,[0xd11083ff,0xaa0003e1,0x910043e0,0x52808002,0x97fe9fae]),
}
def main():
 d=BIN.read_bytes(); lines=[
 "SM-A536N S-BOOT USB RECEIVE-BUFFER / PARSER BOUNDS REVIEW",
 "Read-only byte-pattern validation of selected AArch64 sequences.",
 "No device interaction, exploit payload generation, flashing, or fuse operation.",
 f"S-Boot image size: {len(d)} bytes",""
 ]
 all_ok=True
 for name,(off,expected) in CHECKS.items():
  actual=list(struct.unpack_from("<"+"I"*len(expected),d,off))
  ok=actual==expected; all_ok &= ok
  lines.append(f"{name}: {'MATCH' if ok else 'MISMATCH'} @ 0x{off:08x}")
  for i,w in enumerate(actual): lines.append(f"  0x{off+i*4:08x}: 0x{w:08x}")
 lines += [
 "",
 "Static observations from the matching instruction sequences:",
 "- A receive-buffer allocation request of 0x80000 bytes (512 KiB) is visible, followed by a zero-fill call using the same size.",
 "- A running pointer is formed by adding a received-length value to a base pointer.",
 "- In the command-ID 0x66 path, the resulting pointer is compared with a separately loaded end pointer; the unsigned-greater-or-equal branch goes to a different path.",
 "- A 0x400 (1 KiB) threshold gates invocation of a command parser.",
 "- That parser reserves a 0x420-byte local frame and copies a fixed 0x400 bytes into a local area beginning at SP+0x10, then inspects fields in that local copy.",
 "- The 1 KiB local destination is consistent with the 1 KiB copy size. This alone does not prove that the source pointer always references 1 KiB of valid data.",
 "",
 "Limitations:",
 "- The full caller/callee dataflow and all command-ID paths still need tracing; this report does not prove that every receive path checks both start and end bounds.",
 "- The meaning and initialization of the end-pointer global must be established before treating the comparison as a complete bounds guarantee.",
 "- No conclusion about a reachable overflow or the SVE-2026-3546 vulnerability can be made from these patterns alone.",
 "- The observed 0x400 callback argument is not assumed to be a copy length unless the relevant callsite confirms it.",
 "",
 f"All exact instruction windows matched: {'yes' if all_ok else 'no'}",
 ]
 OUT.write_text("\n".join(lines)+"\n",encoding="utf-8")
 print("\n".join(lines))
 if not all_ok: raise SystemExit("One or more instruction windows differ")
if __name__=="__main__": main()
