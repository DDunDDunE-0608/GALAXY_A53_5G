#!/usr/bin/env python3
"""Read-only aligned AArch64 linear register-provenance scan for stores to USB globals."""
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM, ARM64_OP_MEM

BIN=Path("analysis_payload/sboot.bin")
OUT=Path("A536N_USB_POINTER_STORE_PROVENANCE_REPORT.txt")
PAGE=0x564000
TARGETS={0x1b8:"end_or_limit_A",0x1c0:"receive_current_pointer",0x1c8:"receive_end_pointer"}

def main():
    data=BIN.read_bytes()
    md=Cs(CS_ARCH_ARM64,CS_MODE_ARM); md.detail=True
    insns=[]
    for off in range(0,len(data)-3,4):
        ins=next(md.disasm(data[off:off+4],off),None)
        insns.append(ins)
    known={}
    hits=[]
    for idx,ins in enumerate(insns):
        if ins is None:
            known.clear()
            continue
        ops=ins.operands
        # Determine memory accesses before applying this instruction's register writes.
        if ins.mnemonic in {"str","stur","stp","stnp","stlr","stxr","stlxr"}:
            for op in ops:
                if op.type==ARM64_OP_MEM and op.mem.base in known:
                    absolute=known[op.mem.base]+op.mem.disp
                    rel=absolute-PAGE
                    if rel in TARGETS:
                        hits.append((ins.address,ins.mnemonic,ins.op_str,rel,idx))
        # Track ADRP and simple address-preserving aliases.
        propagated=None
        if ins.mnemonic=="adrp" and len(ops)>=2 and ops[0].type==ARM64_OP_REG and ops[1].type==ARM64_OP_IMM:
            propagated=(ops[0].reg,ops[1].imm)
        elif ins.mnemonic in {"mov","orr"} and len(ops)>=2 and ops[0].type==ARM64_OP_REG:
            src=ops[-1]
            if src.type==ARM64_OP_REG and src.reg in known:
                propagated=(ops[0].reg,known[src.reg])
        elif ins.mnemonic=="add" and len(ops)>=3 and ops[0].type==ARM64_OP_REG and ops[1].type==ARM64_OP_REG and ops[1].reg in known and ops[2].type==ARM64_OP_IMM:
            propagated=(ops[0].reg,known[ops[1].reg]+ops[2].imm)
        try:
            _,writes=ins.regs_access()
        except Exception:
            writes=[]
        for reg in writes:
            known.pop(reg,None)
        if propagated:
            known[propagated[0]]=propagated[1]
    lines=[
      "SM-A536N S-BOOT USB POINTER STORE PROVENANCE SCAN (READ-ONLY)",
      f"Image size: {len(data)} bytes",
      "Method: 4-byte aligned AArch64 decode; track ADRP and simple MOV/ADD aliases across linear instruction stream.",
      "Targets: 0x5641b8, 0x5641c0, 0x5641c8.",
      "Caution: S-Boot mixes code/data; linear decoding and register provenance can produce false positives or miss control-flow-dependent aliases.",
      ""
    ]
    for addr,mnem,opstr,rel,idx in hits:
        lines.append(f"STORE @ 0x{addr:08x}: {mnem:<6} {opstr} ; +0x{rel:x} {TARGETS[rel]}")
        for k in range(max(0,idx-4),min(len(insns),idx+3)):
            q=insns[k]
            if q: lines.append(f"  0x{q.address:08x}: {q.mnemonic:<8} {q.op_str}")
        lines.append("")
    lines += [f"Candidate stores: {len(hits)}",
      "This is an index for manual validation, not proof of pointer initialization, runtime reachability, memory safety, or vulnerability."]
    OUT.write_text("\n".join(lines)+"\n",encoding="utf-8")
    print("\n".join(lines[:400]))
if __name__=="__main__": main()
