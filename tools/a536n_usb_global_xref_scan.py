#!/usr/bin/env python3
"""Read-only whole-image xref scan for USB receive global-state page."""
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM, ARM64_OP_MEM
BIN=Path("analysis_payload/sboot.bin")
OUT=Path("A536N_USB_GLOBAL_XREF_REPORT.txt")
PAGE=0x564000
TARGETS={0x1b8:"candidate_end_or_limit_A",0x1c0:"receive_current_pointer",0x1c8:"candidate_receive_end_pointer",0x200:"parser_write_pointer",0x220:"candidate_length_or_status",0x238:"allocated_buffer_pointer"}
def main():
 data=BIN.read_bytes(); md=Cs(CS_ARCH_ARM64,CS_MODE_ARM); md.detail=True
 ins=list(md.disasm(data,0))
 lines=["SM-A536N S-BOOT USB GLOBAL-STATE CROSS-REFERENCE (READ-ONLY)",f"Image size: {len(data)} bytes","Search: ADRP references resolving to page 0x564000, followed by nearby memory accesses.","Caution: local instruction windows are not full interprocedural dataflow; register reuse can create false associations.",""]
 hits=0
 for i,x in enumerate(ins):
  if x.mnemonic!="adrp" or len(x.operands)<2 or x.operands[0].type!=ARM64_OP_REG or x.operands[1].type!=ARM64_OP_IMM or x.operands[1].imm!=PAGE: continue
  reg=x.operands[0].reg; found=[]
  for y in ins[i+1:i+13]:
   for op in y.operands:
    if op.type==ARM64_OP_MEM and op.mem.base==reg and op.mem.disp in TARGETS: found.append((y,op.mem.disp))
   if y.operands and y.operands[0].type==ARM64_OP_REG and y.operands[0].reg==reg and y.mnemonic not in ("str","stur"): break
  if found:
   hits+=1; lines.append(f"ADRP @ 0x{x.address:08x}: {x.mnemonic} {x.op_str}")
   for y,off in found: lines.append(f"  0x{y.address:08x}: {y.mnemonic:<8} {y.op_str}  ; +0x{off:x} {TARGETS[off]}")
   lines.append("")
 lines += [f"Matched ADRP windows: {hits}","Interpretation limit: cross-reference index only; not proof of pointer provenance, runtime reachability, or vulnerability."]
 OUT.write_text("\n".join(lines)+"\n",encoding="utf-8"); print("\n".join(lines[:240]))
if __name__=="__main__": main()
