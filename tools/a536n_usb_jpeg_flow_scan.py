#!/usr/bin/env python3
"""Read-only S-Boot cross-reference/context report for USB and JPEG diagnostics."""
from __future__ import annotations
import struct
from pathlib import Path

BIN=Path("analysis_payload/sboot.bin")
OUT=Path("A536N_USB_JPEG_FLOW_REPORT.txt")
TARGETS=[
 b"USB packet size is too big!", b"Buffer passed to JPEG library is too small",
 b"JPEG image is bigger than LCD", b"Not a JPEG file", b"JPEG Load Failed",
 b"Error Exit at JPEG!!", b"get_usb_buffer", b"do_download",
 b"parallel_download_init", b"compressed_download_init",
 b"usb buffer alloc failed", b"image is waiting to get BIG usb buffer",
]
def u32(d,o): return struct.unpack_from("<I",d,o)[0]
def sx(v,b): return (v^(1<<(b-1)))-(1<<(b-1))
def adrp(w,pc):
 imm=((w>>29)&3)|(((w>>5)&0x7ffff)<<2)
 return (pc&~0xfff)+(sx(imm,21)<<12),w&31
def add(w):
 imm=(w>>10)&0xfff
 if (w>>22)&1: imm <<= 12
 return imm,w&31,(w>>5)&31
def decode(w,pc):
 if w&0x9f000000==0x90000000:
  dst,r=adrp(w,pc); return f"ADRP x{r}, 0x{dst:x}"
 if w&0x9f000000==0x10000000:
  imm=((w>>29)&3)|(((w>>5)&0x7ffff)<<2); return f"ADR rd={w&31}, 0x{pc+sx(imm,21):x}"
 if w&0xff000000==0x91000000:
  imm,rd,rn=add(w); return f"ADD x{rd}, x{rn}, #0x{imm:x}"
 if w&0x7f000000==0x11000000:
  imm=(w>>10)&0xfff
  if w>>22&1: imm <<=12
  return f"ADD/SUB imm rd={w&31}, rn={(w>>5)&31}, imm=0x{imm:x}"
 if w&0xfc000000==0x94000000:
  return f"BL 0x{pc+(sx(w&0x3ffffff,26)<<2):x}"
 if w&0xfc000000==0x14000000:
  return f"B 0x{pc+(sx(w&0x3ffffff,26)<<2):x}"
 if w&0xff000010==0x54000000:
  return f"B.cond cond={w&15}"
 if w&0xffc00000==0xf9400000:
  return f"LDR x{w&31}, [x{(w>>5)&31}, #0x{((w>>10)&0xfff)*8:x}]"
 if w&0xffc00000==0xb9400000:
  return f"LDR w{w&31}, [x{(w>>5)&31}, #0x{((w>>10)&0xfff)*4:x}]"
 if w&0x7f80001f==0x52800000:
  return f"MOVZ w{w&31}, #0x{(w>>5)&0xffff:x}"
 return f".word 0x{w:08x}"
def main():
 d=BIN.read_bytes(); words=len(d)//4; refs=[]
 for s in TARGETS:
  p=0; found=[]
  while True:
   p=d.find(s,p)
   if p<0: break
   found.append(p); p+=1
  for target in found:
   matches=[]
   for off in range(0,len(d)-0x30,4):
    w=u32(d,off)
    if w&0x9f000000!=0x90000000: continue
    page,reg=adrp(w,off)
    for j in range(off+4,min(off+0x30,len(d)-3),4):
     a=u32(d,j)
     if a&0xff000000==0x91000000:
      imm,rd,rn=add(a)
      if rn==reg and page+imm==target:
       matches.append((off,j)); break
   refs.append((s,target,found,matches))
 lines=[
 "SM-A536N S-BOOT USB/JPEG STATIC FLOW REPORT",
 "Read-only string cross-reference scan; no device interaction, loader build, flashing, or fuse changes.",
 f"S-Boot size: {len(d)} bytes; aligned AArch64 words scanned: {words}",
 "Reference method: ADRP+ADD immediate pairs only. Indirect tables, literal loads, and computed pointers may be missed.",
 ""
 ]
 for s,target,allpos,matches in refs:
  lines.append(f"STRING {s.decode('ascii','replace')} @ 0x{target:08x}")
  lines.append(f"  occurrences: {', '.join(hex(x) for x in allpos)}")
  lines.append(f"  direct ADRP+ADD references: {len(matches)}")
  for a,b in matches:
   lines.append(f"  reference sequence at 0x{a:08x} (ADD at 0x{b:08x}):")
   lo=max(0,a-0x20); hi=min(len(d)-3,b+0x24)
   lo=(lo+3)&~3
   for off in range(lo,hi,4):
    w=u32(d,off); mark=">>" if off in (a,b) else "  "
    lines.append(f"    {mark} 0x{off:08x}: {w:08x}  {decode(w,off)}")
  lines.append("")
 lines += [
 "Cautions:",
 "- A diagnostic string and its reference do not establish that the path is reachable from an external USB request.",
 "- The USB packet-size diagnostic has a direct code reference; the JPEG diagnostics mostly lack direct ADRP+ADD references in this scan. They may be referenced indirectly or through library error tables.",
 "- No conclusion about buffer overflow, copy bounds, or exploitability can be drawn from string references alone.",
 "- The callback immediate reported by the companion signature scan is an observed argument constant, not proven to be a copy length."
 ]
 OUT.write_text("\n".join(lines)+"\n",encoding="utf-8")
 print("\n".join(lines[:100]))
if __name__=="__main__": main()
