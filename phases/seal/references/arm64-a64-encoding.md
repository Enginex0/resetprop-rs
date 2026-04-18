# ARM64 (A64) Instruction Encoding Reference

Hand-encoding reference for writing a function-prologue hook into a remote process. Every instruction is an aligned 32-bit little-endian word.

Source: ARM DDI 0487 (Arm Architecture Reference Manual for A-profile architecture), A64 base instructions (Part C, Chapter C6).

## Conventions

- `Rn`, `Rt`, `Rd`, `Rm`, `Rt2` are 5-bit register indices (0..31). `31` = XZR/WZR in data-processing, = SP in addressing.
- `sf` = 1 selects 64-bit (X) registers; `sf` = 0 selects 32-bit (W) registers.
- All immediate offsets are in bytes; scale as noted.
- Branch offsets are PC-relative from the branching instruction's address.

## Instruction Table

| Mnemonic | Hex | Bit layout (31..0) | Section |
|---|---|---|---|
| `svc #0` | `0xd4000001` | `11010100 000 imm16 000 01` (imm16=0, LL=01) | C6.2.392 |
| `brk #0` | `0xd4200000` | `11010100 001 imm16 000 00` (imm16=0) | C6.2.44 |
| `nop` | `0xd503201f` | `11010101 00000011 0010 0000 000 11111` (HINT CRm=0,op2=0) | C6.2.273 |
| `isb` (SY) | `0xd5033fdf` | `11010101 00000011 0011 1111 110 11111` (CRm=0b1111, op2=0b110) | C6.2.187 |
| `ret` (x30) | `0xd65f03c0` | `11010110 01011111 0000 00 Rn=11110 00000` | C6.2.312 |
| `br Xn` | `0xd61f0000 \| (Rn<<5)` | `11010110 00011111 0000 00 Rn 00000` | C6.2.41 |
| `blr Xn` | `0xd63f0000 \| (Rn<<5)` | `11010110 00111111 0000 00 Rn 00000` | C6.2.40 |
| `add Xd, Xn, #imm12` | `0x91000000 \| (imm12<<10) \| (Rn<<5) \| Rd` | `1 0010001 00 imm12 Rn Rd` (sf=1, sh=0) | C6.2.4 |
| `add Wd, Wn, #imm12` | `0x11000000 \| (imm12<<10) \| (Rn<<5) \| Rd` | `0 0010001 00 imm12 Rn Rd` | C6.2.4 |
| `sub Xd, Xn, #imm12` | `0xd1000000 \| (imm12<<10) \| (Rn<<5) \| Rd` | `1 1010001 00 imm12 Rn Rd` | C6.2.381 |
| `sub Wd, Wn, #imm12` | `0x51000000 \| ...` | `0 1010001 00 imm12 Rn Rd` | C6.2.381 |
| `movz Xd, #imm16, LSL #(hw*16)` | `0xd2800000 \| (hw<<21) \| (imm16<<5) \| Rd` | `1 10100101 hw imm16 Rd` (sf=1) | C6.2.271 |
| `movz Wd, #imm16, LSL #(hw*16)` | `0x52800000 \| ...` (hw in {0,1}) | `0 10100101 hw imm16 Rd` | C6.2.271 |
| `movk Xd, #imm16, LSL #(hw*16)` | `0xf2800000 \| (hw<<21) \| (imm16<<5) \| Rd` | `1 11100101 hw imm16 Rd` | C6.2.270 |
| `movk Wd, #imm16, LSL #(hw*16)` | `0x72800000 \| ...` | `0 11100101 hw imm16 Rd` | C6.2.270 |
| `mov Xd, Xn` (ORR alias, Rm=Xn, Rn=XZR) | `0xaa0003e0 \| (Rm<<16) \| Rd` | `1 01010100 shift=00 0 Rm imm6=000000 Rn=11111 Rd` | C6.2.269 |
| `ldr Xt, [pc, #imm]` | `0x58000000 \| (imm19<<5) \| Rt` | `01 011000 imm19 Rt` (opc=01, scale ×4) | C6.2.200 |
| `ldrb Wt, [Xn, #imm12]` (unsigned offset) | `0x39400000 \| (imm12<<10) \| (Rn<<5) \| Rt` | `00 111001 01 imm12 Rn Rt` (unsigned, size=00, opc=01) | C6.2.203 |
| `stp Xt1, Xt2, [Xn, #imm7]!` (pre-index) | `0xa9800000 \| (imm7s<<15) \| (Rt2<<10) \| (Rn<<5) \| Rt1` | `10 101 001 10 imm7 Rt2 Rn Rt` (opc=10, L=0, pre-index) | C6.2.388 |
| `ldp Xt1, Xt2, [Xn], #imm7` (post-index) | `0xa8c00000 \| (imm7s<<15) \| (Rt2<<10) \| (Rn<<5) \| Rt1` | `10 101 000 11 imm7 Rt2 Rn Rt` (opc=10, L=1, post-index) | C6.2.198 |
| `cbz Wt, #off` | `0x34000000 \| (imm19s<<5) \| Rt` | `0 011010 0 imm19 Rt` (sf=0) | C6.2.48 |
| `cbz Xt, #off` | `0xb4000000 \| ...` | `1 011010 0 imm19 Rt` | C6.2.48 |
| `cbnz Wt, #off` | `0x35000000 \| ...` | `0 011010 1 imm19 Rt` | C6.2.47 |
| `cbnz Xt, #off` | `0xb5000000 \| ...` | `1 011010 1 imm19 Rt` | C6.2.47 |
| `b #off` | `0x14000000 \| imm26s` | `0 00101 imm26` (scale ×4) | C6.2.34 |
| `bl #off` | `0x94000000 \| imm26s` | `1 00101 imm26` (scale ×4, writes X30) | C6.2.38 |
| `b.cond #off` | `0x54000000 \| (imm19s<<5) \| cond` | `01010100 imm19 0 cond` | C6.2.35 |
| `b.eq` / `b.ne` | cond=`0b0000` / `0b0001` | see condition table | C6.2.35 |
| `cmp Wn, Wm` (SUBS Wzr, Wn, Wm shifted=0) | `0x6b00001f \| (Rm<<16) \| (Rn<<5)` | `0 1101011 00 0 Rm imm6=0 Rn Rd=11111` | C6.2.370 |
| `cmp Xn, Xm` | `0xeb00001f \| ...` | sf=1 variant | C6.2.370 |
| `cmp Wn, #imm12` (SUBS Wzr, Wn, #imm) | `0x7100001f \| (imm12<<10) \| (Rn<<5)` | `0 1110001 00 imm12 Rn 11111` | C6.2.369 |
| `cmp Xn, #imm12` | `0xf100001f \| ...` | sf=1 variant | C6.2.369 |

Condition codes (low 4 bits of B.cond): `EQ=0x0, NE=0x1, CS=0x2, CC=0x3, MI=0x4, PL=0x5, VS=0x6, VC=0x7, HI=0x8, LS=0x9, GE=0xA, LT=0xB, GT=0xC, LE=0xD, AL=0xE`.

## Rust const-fn encoder module

```rust
//! A64 instruction encoders. All outputs are LE u32 words.
//! Cite: ARM DDI 0487 Part C, Chapter C6.

#[inline]
const fn fits_signed(v: i32, bits: u32) -> bool {
    let half = 1i32 << (bits - 1);
    v >= -half && v <= half - 1
}

#[inline]
const fn mask_signed(v: i32, bits: u32) -> u32 {
    (v as u32) & ((1u32 << bits) - 1)
}

// Fixed opcodes.
pub const SVC_0: u32 = 0xd400_0001;
pub const BRK_0: u32 = 0xd420_0000;
pub const NOP:   u32 = 0xd503_201f;
pub const ISB_SY: u32 = 0xd503_3fdf;
pub const RET_X30: u32 = 0xd65f_03c0;

/// BR Xn (C6.2.41).
pub const fn br(rn: u8) -> u32 {
    assert!(rn < 32);
    0xd61f_0000 | ((rn as u32) << 5)
}

/// BLR Xn (C6.2.40).
pub const fn blr(rn: u8) -> u32 {
    assert!(rn < 32);
    0xd63f_0000 | ((rn as u32) << 5)
}

/// RET Xn (C6.2.312). Default in the ISA is Rn=30.
pub const fn ret_xn(rn: u8) -> u32 {
    assert!(rn < 32);
    0xd65f_0000 | ((rn as u32) << 5)
}

/// ADD Xd, Xn, #imm12 (C6.2.4, sf=1, sh=0).
pub const fn add_imm64(rd: u8, rn: u8, imm12: u16) -> u32 {
    assert!(rd < 32 && rn < 32 && (imm12 as u32) < (1 << 12));
    0x9100_0000 | ((imm12 as u32) << 10) | ((rn as u32) << 5) | (rd as u32)
}

/// ADD Wd, Wn, #imm12 (C6.2.4, sf=0, sh=0).
pub const fn add_imm32(rd: u8, rn: u8, imm12: u16) -> u32 {
    assert!(rd < 32 && rn < 32 && (imm12 as u32) < (1 << 12));
    0x1100_0000 | ((imm12 as u32) << 10) | ((rn as u32) << 5) | (rd as u32)
}

/// SUB Xd, Xn, #imm12 (C6.2.381, sf=1, sh=0).
pub const fn sub_imm64(rd: u8, rn: u8, imm12: u16) -> u32 {
    assert!(rd < 32 && rn < 32 && (imm12 as u32) < (1 << 12));
    0xd100_0000 | ((imm12 as u32) << 10) | ((rn as u32) << 5) | (rd as u32)
}

/// MOVZ Xd, #imm16, LSL #(hw*16) (C6.2.271, sf=1). `hw` in 0..=3.
pub const fn movz64(rd: u8, imm16: u16, hw: u8) -> u32 {
    assert!(rd < 32 && hw < 4);
    0xd280_0000 | ((hw as u32) << 21) | ((imm16 as u32) << 5) | (rd as u32)
}

/// MOVZ Wd, #imm16, LSL #(hw*16) (C6.2.271, sf=0). `hw` in 0..=1.
pub const fn movz32(rd: u8, imm16: u16, hw: u8) -> u32 {
    assert!(rd < 32 && hw < 2);
    0x5280_0000 | ((hw as u32) << 21) | ((imm16 as u32) << 5) | (rd as u32)
}

/// MOVK Xd, #imm16, LSL #(hw*16) (C6.2.270, sf=1).
pub const fn movk64(rd: u8, imm16: u16, hw: u8) -> u32 {
    assert!(rd < 32 && hw < 4);
    0xf280_0000 | ((hw as u32) << 21) | ((imm16 as u32) << 5) | (rd as u32)
}

/// MOVK Wd, #imm16, LSL #(hw*16) (C6.2.270, sf=0).
pub const fn movk32(rd: u8, imm16: u16, hw: u8) -> u32 {
    assert!(rd < 32 && hw < 2);
    0x7280_0000 | ((hw as u32) << 21) | ((imm16 as u32) << 5) | (rd as u32)
}

/// `MOV Wd, #imm` when the value fits 16 bits (MOVZ alias, hw=0).
pub const fn mov_w_imm16(rd: u8, imm16: u16) -> u32 {
    movz32(rd, imm16, 0)
}

/// MOV Xd, Xm — ORR alias with Rn=XZR, shift=00, imm6=0 (C6.2.269).
pub const fn mov_reg64(rd: u8, rm: u8) -> u32 {
    assert!(rd < 32 && rm < 32);
    0xaa00_03e0 | ((rm as u32) << 16) | (rd as u32)
}

/// LDR Xt, [pc, #byte_offset] (C6.2.200). Signed 21-bit range, must be ×4.
pub const fn ldr_literal64(rt: u8, byte_offset: i32) -> u32 {
    assert!(byte_offset % 4 == 0);
    let imm19 = byte_offset / 4;
    assert!(fits_signed(imm19, 19));
    0x5800_0000 | (mask_signed(imm19, 19) << 5) | (rt as u32)
}

/// LDRB Wt, [Xn, #imm12] unsigned-offset form (C6.2.203). Byte-scaled.
pub const fn ldrb_uoff(rt: u8, rn: u8, imm12: u16) -> u32 {
    assert!(rt < 32 && rn < 32 && (imm12 as u32) < (1 << 12));
    0x3940_0000 | ((imm12 as u32) << 10) | ((rn as u32) << 5) | (rt as u32)
}

/// STP Xt1, Xt2, [Xn, #byte_off]! pre-indexed, 64-bit (C6.2.388). `byte_off` must be a ×8 signed 10-bit value.
pub const fn stp_x_preidx(rt1: u8, rt2: u8, rn: u8, byte_off: i32) -> u32 {
    assert!(byte_off % 8 == 0);
    let imm7 = byte_off / 8;
    assert!(fits_signed(imm7, 7));
    0xa980_0000
        | (mask_signed(imm7, 7) << 15)
        | ((rt2 as u32) << 10)
        | ((rn as u32) << 5)
        | (rt1 as u32)
}

/// LDP Xt1, Xt2, [Xn], #byte_off post-indexed, 64-bit (C6.2.198).
pub const fn ldp_x_postidx(rt1: u8, rt2: u8, rn: u8, byte_off: i32) -> u32 {
    assert!(byte_off % 8 == 0);
    let imm7 = byte_off / 8;
    assert!(fits_signed(imm7, 7));
    0xa8c0_0000
        | (mask_signed(imm7, 7) << 15)
        | ((rt2 as u32) << 10)
        | ((rn as u32) << 5)
        | (rt1 as u32)
}

/// CBZ Wt, #byte_off (C6.2.48, sf=0). Signed 21-bit range, must be ×4.
pub const fn cbz_w(rt: u8, byte_off: i32) -> u32 {
    assert!(byte_off % 4 == 0);
    let imm19 = byte_off / 4;
    assert!(fits_signed(imm19, 19));
    0x3400_0000 | (mask_signed(imm19, 19) << 5) | (rt as u32)
}

/// CBZ Xt, #byte_off (C6.2.48, sf=1).
pub const fn cbz_x(rt: u8, byte_off: i32) -> u32 {
    assert!(byte_off % 4 == 0);
    let imm19 = byte_off / 4;
    assert!(fits_signed(imm19, 19));
    0xb400_0000 | (mask_signed(imm19, 19) << 5) | (rt as u32)
}

/// CBNZ Wt, #byte_off (C6.2.47, sf=0).
pub const fn cbnz_w(rt: u8, byte_off: i32) -> u32 {
    assert!(byte_off % 4 == 0);
    let imm19 = byte_off / 4;
    assert!(fits_signed(imm19, 19));
    0x3500_0000 | (mask_signed(imm19, 19) << 5) | (rt as u32)
}

/// CBNZ Xt, #byte_off (C6.2.47, sf=1).
pub const fn cbnz_x(rt: u8, byte_off: i32) -> u32 {
    assert!(byte_off % 4 == 0);
    let imm19 = byte_off / 4;
    assert!(fits_signed(imm19, 19));
    0xb500_0000 | (mask_signed(imm19, 19) << 5) | (rt as u32)
}

/// B #byte_off (C6.2.34). Signed 28-bit range, must be ×4.
pub const fn b_rel(byte_off: i32) -> u32 {
    assert!(byte_off % 4 == 0);
    let imm26 = byte_off / 4;
    assert!(fits_signed(imm26, 26));
    0x1400_0000 | mask_signed(imm26, 26)
}

/// BL #byte_off (C6.2.38). Writes X30.
pub const fn bl_rel(byte_off: i32) -> u32 {
    assert!(byte_off % 4 == 0);
    let imm26 = byte_off / 4;
    assert!(fits_signed(imm26, 26));
    0x9400_0000 | mask_signed(imm26, 26)
}

// Condition codes for B.cond (C6.2.35).
pub const COND_EQ: u8 = 0x0;
pub const COND_NE: u8 = 0x1;
pub const COND_GE: u8 = 0xA;
pub const COND_LT: u8 = 0xB;

/// B.cond #byte_off (C6.2.35).
pub const fn b_cond(cond: u8, byte_off: i32) -> u32 {
    assert!(cond < 16 && byte_off % 4 == 0);
    let imm19 = byte_off / 4;
    assert!(fits_signed(imm19, 19));
    0x5400_0000 | (mask_signed(imm19, 19) << 5) | (cond as u32)
}

/// CMP Wn, Wm — SUBS Wzr, Wn, Wm alias (C6.2.370, shift=0, imm6=0).
pub const fn cmp_reg32(rn: u8, rm: u8) -> u32 {
    assert!(rn < 32 && rm < 32);
    0x6b00_001f | ((rm as u32) << 16) | ((rn as u32) << 5)
}

/// CMP Xn, Xm — SUBS Xzr, Xn, Xm alias (C6.2.370, sf=1).
pub const fn cmp_reg64(rn: u8, rm: u8) -> u32 {
    assert!(rn < 32 && rm < 32);
    0xeb00_001f | ((rm as u32) << 16) | ((rn as u32) << 5)
}

/// CMP Wn, #imm12 — SUBS Wzr, Wn, #imm alias (C6.2.369, sh=0).
pub const fn cmp_imm32(rn: u8, imm12: u16) -> u32 {
    assert!(rn < 32 && (imm12 as u32) < (1 << 12));
    0x7100_001f | ((imm12 as u32) << 10) | ((rn as u32) << 5)
}

/// CMP Xn, #imm12 — SUBS Xzr, Xn, #imm alias (C6.2.369, sf=1, sh=0).
pub const fn cmp_imm64(rn: u8, imm12: u16) -> u32 {
    assert!(rn < 32 && (imm12 as u32) < (1 << 12));
    0xf100_001f | ((imm12 as u32) << 10) | ((rn as u32) << 5)
}
```

## Absolute-target trampoline

4 words (16 bytes). `ldr x16, [pc, #8]` pulls the 64-bit target literal that follows, then `br x16` branches.

```text
offset 0x00 : 0x58000050   ldr x16, [pc, #8]
offset 0x04 : 0xd61f0200   br  x16
offset 0x08 : <target[31:0]>     (LE)
offset 0x0c : <target[63:32]>    (LE)
```

```rust
const TRAMPOLINE_LDR_X16: u32 = 0x5800_0050; // ldr x16, [pc, #8]
const TRAMPOLINE_BR_X16:  u32 = 0xd61f_0200; // br  x16

pub const fn trampoline_to(target: u64) -> [u8; 16] {
    let ldr = TRAMPOLINE_LDR_X16.to_le_bytes();
    let br  = TRAMPOLINE_BR_X16.to_le_bytes();
    let lo  = (target as u32).to_le_bytes();
    let hi  = ((target >> 32) as u32).to_le_bytes();
    [
        ldr[0], ldr[1], ldr[2], ldr[3],
        br[0],  br[1],  br[2],  br[3],
        lo[0],  lo[1],  lo[2],  lo[3],
        hi[0],  hi[1],  hi[2],  hi[3],
    ]
}
```

Example: `trampoline_to(0x0000_7fff_abcd_1234)` → bytes `50 00 00 58  00 02 1f d6  34 12 cd ab  ff 7f 00 00`.

## Strcmp loop skeleton

Compares null-terminated C strings pointed to by `x0` and `x1`. Returns `w0 = 0` on full match (both reached NUL together), `w0 = 1` on mismatch. Drop-in ready; no post-hoc patching required.

Layout (13 words, 52 bytes):

| Word | Addr | Label | Instruction |
|---:|---:|---|---|
| 0 | +0x00 | `.loop` | `ldrb w9,  [x0]` |
| 1 | +0x04 |  | `ldrb w10, [x1]` |
| 2 | +0x08 |  | `cmp  w9, w10` |
| 3 | +0x0c |  | `b.ne .mismatch`  (+24) |
| 4 | +0x10 |  | `cbz  w9, .match` (+28) |
| 5 | +0x14 |  | `add  x0, x0, #1` |
| 6 | +0x18 |  | `add  x1, x1, #1` |
| 7 | +0x1c |  | `b    .loop` (-28) |
| 8 | +0x20 |  | `nop` (padding) |
| 9 | +0x24 | `.mismatch` | `movz w0, #1` |
| 10 | +0x28 |  | `ret` |
| 11 | +0x2c | `.match` | `movz w0, #0` |
| 12 | +0x30 |  | `ret` |

```rust
pub const STRCMP_BODY: [u32; 13] = [
    0x3940_0009, // ldrb w9,  [x0]
    0x3940_002a, // ldrb w10, [x1]
    0x6b0a_013f, // cmp  w9, w10
    0x5400_00c1, // b.ne .mismatch  (imm19 = +6 words)
    0x3400_00e9, // cbz  w9, .match (imm19 = +7 words)
    0x9100_0400, // add  x0, x0, #1
    0x9100_0421, // add  x1, x1, #1
    0x17ff_fff9, // b    .loop      (imm26 = -7 words)
    0xd503_201f, // nop
    0x5280_0020, // movz w0, #1
    0xd65f_03c0, // ret
    0x5280_0000, // movz w0, #0
    0xd65f_03c0, // ret
];
```

## Hook body sketch: prop-lookup guard

ABI preserved: `x0 = prop_info*`, `x1 = value`, `w2 = len`. On a name match, the hook returns `w0 = 0`. Otherwise it executes the four stolen prologue instructions and branches back to `original_fn + 16`.

The body is a 23-word (92-byte) blob with three patch regions filled at install time. The inline `strcmp` is stubbed with a direct branch; the installer is expected to splice the 13-word `STRCMP_BODY` from the previous section into the stub slot, with its entry/exit branches adjusted.

Layout:

| Word | Label | Instruction | Notes |
|---:|---|---|---|
| 0 | | `cbz  x0, .fall_through` | guard against NULL `prop_info` |
| 1 | | `add  x9, x0, #96` | `x9 = &pi->name` |
| 2 | | `ldr  x10, =LOCK_LIST` | load base of name table (literal at word 21) |
| 3 | `.next_entry` | `ldrb w11, [x10]` | peek first byte of current name |
| 4 | | `cbz  w11, .fall_through` | NUL = end-of-list sentinel |
| 5 | | `b    .advance` (stub) | installer replaces with strcmp splice |
| 6 | `.on_match` | `movz w0, #0` | return 0 on match |
| 7 | | `ret` | |
| 8 | `.advance` | `add  x10, x10, #1` | installer replaces with "scan past NUL" |
| 9 | | `b    .next_entry` | |
| 10-12 | | `nop` | alignment padding |
| 13-16 | `.fall_through` | four stolen instructions | patched at install |
| 17 | | `ldr  x16, =RESTORE_TARGET` | literal at word 19 |
| 18 | | `br   x16` | tail-branch to `original_fn + 16` |
| 19-20 | | `RESTORE_TARGET` u64 | patch: absolute `original_fn + 16` |
| 21-22 | | `LOCK_LIST` u64 | patch: absolute base of name list |

Patch-point indices:

```rust
pub const STOLEN_START: usize = 13; // words 13..=16 hold the 4 stolen prologue instructions
pub const RESTORE_LIT: usize  = 19; // words 19..=20 hold the u64 restore target
pub const LOCK_LIST_LIT: usize = 21; // words 21..=22 hold the u64 lock-list base
pub const STRCMP_STUB: usize = 5;    // word 5 is the b-stub the strcmp splice overwrites
```

Encoded body:

```rust
pub const HOOK_BODY: [u32; 23] = [
    0xb400_01a0, // cbz  x0, .fall_through  (+52)
    0x9101_8009, // add  x9, x0, #96
    0x5800_026a, // ldr  x10, =LOCK_LIST    (+76)
    0x3940_014b, // ldrb w11, [x10]
    0x3400_012b, // cbz  w11, .fall_through (+36)
    0x1400_0003, // b .advance              (+12) -- installer splices strcmp here
    0x5280_0000, // movz w0, #0
    0xd65f_03c0, // ret
    0x9100_054a, // add  x10, x10, #1
    0x17ff_fffa, // b .next_entry           (-24)
    0xd503_201f, // nop
    0xd503_201f, // nop
    0xd503_201f, // nop
    0xd503_201f, // STOLEN_0 (patch)
    0xd503_201f, // STOLEN_1 (patch)
    0xd503_201f, // STOLEN_2 (patch)
    0xd503_201f, // STOLEN_3 (patch)
    0x5800_0050, // ldr  x16, =RESTORE_TARGET (+8)
    0xd61f_0200, // br   x16
    0x0000_0000, // RESTORE_TARGET lo (patch)
    0x0000_0000, // RESTORE_TARGET hi (patch)
    0x0000_0000, // LOCK_LIST lo (patch)
    0x0000_0000, // LOCK_LIST hi (patch)
];
```

Install-time patching rules:

- Copy the four original prologue words into `HOOK_BODY[STOLEN_START..STOLEN_START + 4]`. Any PC-relative word among them (`b`, `bl`, `b.cond`, `cbz`, `cbnz`, `ldr literal`, `adr`, `adrp`) must be re-materialised through `MOVZ`/`MOVK` + `BR` at a dedicated thunk — raw relocation is unsafe at a new address.
- Write the u64 `original_fn + 16` little-endian into `HOOK_BODY[RESTORE_LIT..RESTORE_LIT + 2]`.
- Write the u64 `LOCK_LIST` base little-endian into `HOOK_BODY[LOCK_LIST_LIT..LOCK_LIST_LIT + 2]`.
- Splice the 13-word `STRCMP_BODY` over `HOOK_BODY[STRCMP_STUB]`. Re-encode its exit branches so mismatch flows into word 8 (`.advance`) and match flows into word 6 (`.on_match`).

## i-cache invalidation options

| Option | Pros | Cons |
|---|---|---|
| `__builtin___clear_cache(start, end)` via remote `libc` | Fully correct across cores; uses the kernel's own cache-maintenance path (`DC CVAU` + `IC IVAU` + `DSB` + `ISB`) | Requires resolving the symbol in the tracee (`libc.so!__clear_cache`), setting up a remote call frame, and handling its return |
| `membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE, 0, 0)` via remote syscall | No symbol resolution; only syscall 283 + cmd=`0x80`; forces `isb` on every core in the address space | Requires `MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE` (`0x40`) registration first; kernel ≥ 4.16; still does **not** invalidate i-cache lines — it only synchronises cores |
| Remote `isb` (`0xd5033fdf`) executed on the tracee's own PC | Zero plumbing; single-instruction staged slot | Only synchronises the core that executed it; other cores may still hold stale i-cache lines; unsafe on SMP unless pinned. Additionally, **does not** flush `DC CVAU`/`IC IVAU`, so if the kernel zero-copy mapped the page with `D`-cache lines still dirty, CPU fetches may see stale bytes |

Recommendation: prefer `__clear_cache`. It is the only option that does the full data-cache-to-PoU clean + i-cache invalidation dance that the ARM ARM requires (see B2.2.5 "Ordering of cache and memory maintenance instructions"). `membarrier` + `isb` only covers the synchronisation half; it is correct **after** the kernel has already cleaned/invalidated for you (e.g. `ptrace(PTRACE_POKETEXT)` does this on Linux; `process_vm_writev` does **not**).

## Endianness

ARM64 Linux userspace is always little-endian (`E` bit in SCTLR_EL1 is 0). Each encoded `u32` is stored least-significant byte first at the lowest address.

Trampoline for `target = 0xDEAD_BEEF_CAFE_BABE`:

```text
word          hex          bytes at offset
ldr x16 lit   0x58000050   50 00 00 58
br  x16       0xd61f0200   00 02 1f d6
target.lo     0xcafebabe   be ba fe ca
target.hi     0xdeadbeef   ef be ad de
full block:   50 00 00 58 00 02 1f d6 be ba fe ca ef be ad de
```

Use `u32::to_le_bytes()` in Rust when emitting instruction words into the tracee's page.

## Sources

- [ARM DDI 0487 (Arm Architecture Reference Manual for A-profile), A64 base instructions](https://developer.arm.com/documentation/ddi0487/latest)
- [A64 Base Instructions (alphabetic index)](https://www.scs.stanford.edu/~zyedidia/arm64/)
- [A64 Instruction Set Index by Encoding (DDI 0602)](https://developer.arm.com/documentation/ddi0602/latest/Index-by-Encoding)
- [LDR (literal) — A64](https://www.scs.stanford.edu/~zyedidia/arm64/ldr_lit_gen.html)
- [LDP / STP — A64](https://www.scs.stanford.edu/~zyedidia/arm64/ldp_gen.html)
- [MOVZ / MOVK — A64](https://www.scs.stanford.edu/~zyedidia/arm64/movz.html)
- [B.cond, CBZ, CBNZ — A64](https://www.scs.stanford.edu/~zyedidia/arm64/cbz.html)
- [llvm aarch64 branch-encoding tests (ground truth)](https://github.com/llvm/llvm-project/blob/main/llvm/test/MC/AArch64/arm64-branch-encoding.s)
