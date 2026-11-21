#!/usr/bin/env python3
"""Read-only aligned-word ADRP scan for USB global-state references."""
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM, ARM64_OP_MEM
BIN=Path("analysis_payload/sboot.bin"); OUT=Path("A536N_USB_GLOBAL_XREF_REPORT.txt")
PAGE=0x564000
TARGETS={0x1b8:"candidate_end_or_limit_A",0x1c0:"receive_current_pointer",0x1c8:"candidate_receive_end_pointer",0x200:"parser_write_pointer",0x208:"state_flag_A",0x20c:"state_flag_B",0x238:"allocated_buffer_pointer"}
def decode(md,data,off):
 return next(md.disasm(data[off:off+4],off),None)
def main():
 data=BIN.read_bytes(); md=Cs(CS_ARCH_ARM64,CS_MODE_ARM); md.detail=True
 lines=["SM-A536N S-BOOT USB GLOBAL-STATE CROSS-REFERENCE (READ-ONLY)",
 f"Image size: {len(data)} bytes","Method: decode each 4-byte-aligned word independently, then inspect following aligned instructions.",
 "Target ADRP page: 0x564000","Caution: raw data can decode as instructions; every hit requires contextual validation.",""]
 hits=0
 for off in range(0,len(data)-4,4):
  x=decode(md,data,off)
  if not x or x.mnemonic!="adrp" or len(x.operands)<2: continue
  if x.operands[0].type!=ARM64_OP_REG or x.operands[1].type!=ARM64_OP_IMM or x.operands[1].imm!=PAGE: continue
  reg=x.operands[0].reg; found=[]
  for j in range(1,13):
   y=decode(md,data,off+4*j)
   if not y: continue
   for op in y.operands:
    if op.type==ARM64_OP_MEM and op.mem.base==reg and op.mem.disp in TARGETS: found.append((y,op.mem.disp))
   if y.operands and y.operands[0].type==ARM64_OP_REG and y.operands[0].reg==reg and y.mnemonic not in ("str","stur"): break
  if found:
   hits+=1; lines.append(f"ADRP @ 0x{x.address:08x}: {x.mnemonic} {x.op_str}")
   for y,d in found: lines.append(f"  0x{y.address:08x}: {y.mnemonic:<8} {y.op_str} ; +0x{d:x} {TARGETS[d]}")
   lines.append("")
 lines += [f"Matched ADRP windows: {hits}","This is a candidate xref index only, not proof of pointer provenance, runtime reachability, or vulnerability."]
 OUT.write_text("\n".join(lines)+"\n",encoding="utf-8"); print("\n".join(lines[:260]))
if __name__=="__main__": main()
