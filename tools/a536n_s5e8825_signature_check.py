#!/usr/bin/env python3
"""Read-only comparison of the A536N LK image with public S5E8825 resolver signatures.

This checks for static layout/signature presence only. It does not build a loader,
generate flashable images, access a device, or modify firmware.
"""
from __future__ import annotations
import collections, struct
from pathlib import Path

SBOOT = Path("analysis_payload/sboot.bin")
REPORT = Path("A536N_S5E8825_SIGNATURE_REPORT.txt")
LK_START, LK_END = 0xED000, 0x4ED000
PAGE = 0x1000

def u32(b, o): return struct.unpack_from("<I", b, o)[0]
def sx(v, bits): return (v ^ (1 << (bits-1))) - (1 << (bits-1))
def adrp(w, pc):
    imm = ((w >> 29) & 3) | (((w >> 5) & 0x7ffff) << 2)
    return (pc & ~0xfff) + (sx(imm, 21) << 12), w & 31
def add_imm(w):
    v = (w >> 10) & 0xfff
    if (w >> 22) & 1: v <<= 12
    return v, w & 31, (w >> 5) & 31
def image_map(data):
    bss = []
    for off in range(0, min(len(data), 0x400)-0x18+1, 8):
        start, duplicate, end = struct.unpack_from("<QQQ", data, off)
        if (start == duplicate and 0x80000000 <= start < 0x1000000000
                and start % PAGE == 0 and start < end and end-start < 0x10000000):
            bss.append((start, end))
    if len(bss) != 1: return None, None
    bss_start, bss_end = bss[0]
    maps = []
    for off in range(0, len(data)-0x28, 8):
        name, start, end, physical, _ = struct.unpack_from("<5Q", data, off)
        if (start != physical or start % 0x100000 or not start <= bss_start < bss_end <= end
                or not 0 < bss_start-start < 0x1000000):
            continue
        name_off = name-start
        if not 0 <= name_off < len(data): continue
        name_end = data.find(b"\0", name_off, min(len(data), name_off+0x80))
        if name_end < 0: continue
        label = data[name_off:name_end]
        if label and all(0x20 <= x < 0x7f for x in label):
            maps.append((start, end, label))
    maps = sorted(set(maps))
    if len(maps) != 1: return None, None
    return maps[0][0], (bss_start, bss_end)

def send_info_signature(data, base, bss):
    if base is None or bss is None: return {"bss_map":"not resolved"}
    setters=[]
    for off in range(0, len(data)-0x18, 4):
        w=[u32(data,off+i*4) for i in range(6)]
        if (w[0]&0x9f00001f != 0x90000008 or w[1]&0x9f00001f != 0x90000009
            or w[2]&0xffc003ff != 0xf9000100 or w[3] != 0x2a1f03e0
            or w[4]&0xffc003ff != 0xf9000121 or w[5] != 0xd65f03c0):
            continue
        p0,r0=adrp(w[0],base+off); p1,r1=adrp(w[1],base+off+4)
        a0=p0+((w[2]>>10)&0xfff)*8
        a1=p1+((w[4]>>10)&0xfff)*8
        if a1==a0+8: setters.append((off,a0,a1))
    if len(setters)!=1:
        return {"bss_map":"resolved","setter_pattern_count":len(setters)}
    setter, reply_slot, callback_slot=setters[0]
    registrations=[]
    for off in range(16,len(data),4):
        w=u32(data,off)
        if w&0xfc000000 != 0x14000000: continue
        imm=sx(w&0x3ffffff,26)
        if base+off+(imm<<2) != base+setter: continue
        pre=[u32(data,off-16+i*4) for i in range(4)]
        if pre[0]&0x9f00001f != 0x90000000 or pre[1]&0x9f00001f != 0x90000001: continue
        p0,r0=adrp(pre[0],base+off-16); p1,r1=adrp(pre[1],base+off-12)
        v0,d0,s0=add_imm(pre[2]); v1,d1,s1=add_imm(pre[3])
        if (r0,d0,s0)==(0,0,0) and (r1,d1,s1)==(1,1,1):
            registrations.append((p0+v0,p1+v1))
    uses=[]
    callback_lengths=set()
    for off in range(0,len(data)-0x30,4):
        first=u32(data,off)
        if first&0x9f000000 != 0x90000000: continue
        page,reg=adrp(first,base+off)
        for load_off in range(off+4,min(off+0x20,len(data)-3),4):
            load=u32(data,load_off)
            if (load&0xffc00000)!=0xf9400000 or ((load>>5)&31)!=reg: continue
            addr=page+((load>>10)&0xfff)*8
            if addr!=callback_slot: continue
            target=load&31
            for call_off in range(load_off+4,min(load_off+0x14,len(data)-3),4):
                call=u32(data,call_off)
                if call != (0xd63f0000|(target<<5)): continue
                for arg_off in range(load_off+4,call_off,4):
                    arg=u32(data,arg_off)
                    # MOVZ W1, #imm16 (accept the firmware's actual immediate).
                    if (arg&0x7f80001f)==0x52800001:
                        callback_lengths.add((arg>>5)&0xffff)
                        uses.append(off)
                        break
                break
            break
    uses=sorted(set(uses))
    counts=collections.Counter()
    for use in uses:
        found=set()
        for off in range(max(0,use-0x100),use,4):
            ins=u32(data,off)
            if ins&0x9f000000 != 0x90000000: continue
            page,reg=adrp(ins,base+off)
            for pos in range(off+4,min(use,off+0x24),4):
                load=u32(data,pos)
                if (load&0xffc00000==0xf9400000 and ((load>>5)&31)==reg and (load&31)==0):
                    addr=page+((load>>10)&0xfff)*8
                    if bss[0]<=addr<bss[1]: found.add(addr)
        counts.update(found)
    reply_candidates=[addr for addr,count in counts.items() if count==len(uses)] if uses else []
    return {
        "bss_map":"resolved",
        "setter_pattern_count":1,
        "setter_pair_spacing_8_bytes":callback_slot==reply_slot+8,
        "registration_call_count":len(registrations),
        "callback_dispatch_count":len(uses),
        "callback_length_immediates":sorted(callback_lengths),
        "reply_pointer_candidate_count":len(reply_candidates),
        "reply_pointer_inside_bss":len(reply_candidates)==1,
        "reply_callback_distance_within_4k":len(reply_candidates)==1 and 0<callback_slot-reply_candidates[0]<=PAGE,
    }

def string_xrefs(data, base, value):
    offs=[]; p=0
    while True:
        p=data.find(value+b"\0",p)
        if p<0: break
        offs.append(p); p+=1
    refs=[]
    for target in offs:
        for off in range(0,len(data)-0x24,4):
            w=u32(data,off)
            if w&0x9f000000 != 0x90000000: continue
            page,reg=adrp(w,base+off)
            for pos in range(off+4,min(off+0x24,len(data)-3),4):
                a=u32(data,pos)
                if a&0xff000000==0x91000000:
                    val,dst,src=add_imm(a)
                    if src==reg and page+val==base+target:
                        refs.append((target,off)); break
    return len(set(refs))

def main():
    whole=SBOOT.read_bytes()
    if len(whole)<LK_END: raise SystemExit("S-Boot image is shorter than expected S5E8825 LK slice")
    lk=whole[LK_START:LK_END]
    base,bss=image_map(lk)
    sig=send_info_signature(lk,base,bss)
    lines=[
        "SM-A536N / S5E8825 STATIC SIGNATURE COMPARISON",
        "Read-only analysis of the LK slice; no loader build, device access, flash, or fuse operation.",
        f"S-Boot image bytes: {len(whole)}",
        f"LK slice: 0x{LK_START:x}..0x{LK_END:x} ({len(lk)} bytes)",
        f"LK image base resolved: {'yes' if base is not None else 'no'}",
        f"LK BSS range resolved: {'yes' if bss is not None else 'no'}",
    ]
    for k,v in sig.items(): lines.append(f"{k}: {v}")
    for s in (b"parallel_download_init",b"compressed_download_init",b"em_crypto_sha256",b"blk_bread",b"blk_bwrite"):
        lines.append(f"direct xrefs to {s.decode()}: {string_xrefs(lk,base or 0,s)}")
    lines += [
        "",
        "Interpretation:",
        "- A complete setter/callback/reply-buffer signature match would support structural compatibility with the public S5E8825 resolver.",
        "- This is not a proof of an exploitable out-of-bounds copy: copy length, destination capacity, runtime initialization, and November 2026 patch changes require separate verification.",
        "- No exploit payload is generated and no device state is changed.",
    ]
    REPORT.write_text("\n".join(lines)+"\n",encoding="utf-8")
    print("\n".join(lines))

if __name__=="__main__": main()
