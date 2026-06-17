// ─────────────────────────────────────────────────────────────────────────────
// Independent encoding oracle for HOOK_BODY_TEMPLATE (seal/hook.rs)  — T16 / H1
// ─────────────────────────────────────────────────────────────────────────────
//
// WHY THIS FILE EXISTS
//   The 35-word `HOOK_BODY_TEMPLATE` and the `encoder` helpers in hook.rs are
//   hand-encoded ARM64. Their unit tests assert the SAME hand-derived hex, so a
//   transcription error confirms itself — exactly how Defect-A shipped green
//   (word 22 was `ldrb w11,[x10],#16` / 0x3841_054b instead of `#1` /
//   0x3840_154b, and the test asserted the wrong constant too).
//
//   This file is the *independent* derivation: the trampoline written as
//   mnemonics with LABELS, so a real assembler computes every opcode AND every
//   branch displacement (imm19/imm26) on its own. The checked-in golden blob
//   `hook_body.golden.bin` is this file's assembled output; the oracle test in
//   hook.rs diffs `HOOK_BODY_TEMPLATE` against that blob and fails on any
//   divergence. Because the blob comes from the assembler — not from copying
//   the hand hex — it cannot ratify a hand-encoding mistake.
//
// REGENERATION (run when HOOK_BODY_TEMPLATE legitimately changes)
//   From this directory (crates/resetprop/src/seal/oracle/):
//
//       aarch64-linux-gnu-as hook_body.s -o /tmp/hook_body.o \
//         && aarch64-linux-gnu-objcopy -O binary /tmp/hook_body.o hook_body.golden.bin
//
//   Equivalent with the LLVM toolchain (verified to produce identical bytes):
//
//       llvm-mc -triple=aarch64-linux-gnu -filetype=obj hook_body.s -o /tmp/hook_body.o \
//         && llvm-objcopy -O binary /tmp/hook_body.o hook_body.golden.bin
//
//   The result must be exactly 140 bytes (35 little-endian u32 words). Keep the
//   mnemonics below in lock-step with the `//` annotations on each
//   HOOK_BODY_TEMPLATE row; the patch-slot seeds (words 25..=28 = nop, words
//   31..=34 = 0) match the template's pre-patch seed values so the diff is exact.
// ─────────────────────────────────────────────────────────────────────────────
	.text
	.balign 4
hook_body:
	cbz	x0, .Lfall_through        // 0:  cbz  x0, .fall_through
	add	x9, x0, #96               // 1:  add  x9, x0, #96
	ldr	x10, .Llock_list          // 2:  ldr  x10, =LOCK_LIST
.Lnext_entry:
	ldrb	w11, [x10]                // 3:  .next_entry: ldrb w11, [x10]
	cbz	w11, .Lfall_through       // 4:  cbz  w11, .fall_through
	mov	x12, x9                   // 5:  mov  x12, x9   (rebind name ptr)
	mov	x13, x10                  // 6:  mov  x13, x10  (rebind entry ptr)
.Lstrcmp_loop:
	ldrb	w14, [x12]                // 7:  .strcmp_loop: ldrb w14, [x12]
	ldrb	w15, [x13]                // 8:  ldrb w15, [x13]
	cmp	w14, w15                  // 9:  cmp  w14, w15
	b.ne	.Lmismatch                // 10: b.ne .mismatch
	cbz	w14, .Lmatch              // 11: cbz  w14, .match
	add	x12, x12, #1              // 12: add  x12, x12, #1
	add	x13, x13, #1              // 13: add  x13, x13, #1
	b	.Lstrcmp_loop             // 14: b    .strcmp_loop
	nop                               // 15: nop
.Lmismatch:
	b	.Ladvance                 // 16: .mismatch: b .advance
	nop                               // 17: nop (unused — was canonical ret)
.Lmatch:
	b	.Lon_match                // 18: .match: b .on_match
	nop                               // 19: nop (unused — was canonical ret)
.Lon_match:
	movz	w0, #0                    // 20: .on_match: movz w0, #0
	ret                               // 21: ret
.Ladvance:
	ldrb	w11, [x10], #1            // 22: .advance: ldrb w11, [x10], #1 (post-indexed)
	cbnz	w11, .Ladvance            // 23: cbnz w11, .-4
	b	.Lnext_entry              // 24: b    .next_entry
.Lfall_through:
	nop                               // 25: STOLEN_0 (patched at install — seed nop)
	nop                               // 26: STOLEN_1 (patched at install — seed nop)
	nop                               // 27: STOLEN_2 (patched at install — seed nop)
	nop                               // 28: STOLEN_3 (patched at install — seed nop)
	ldr	x16, .Lrestore_target     // 29: ldr  x16, =RESTORE_TARGET
	br	x16                       // 30: br   x16
.Lrestore_target:
	.word	0                         // 31: RESTORE_TARGET lo (patched — seed 0)
	.word	0                         // 32: RESTORE_TARGET hi (patched — seed 0)
.Llock_list:
	.word	0                         // 33: LOCK_LIST lo (patched — seed 0)
	.word	0                         // 34: LOCK_LIST hi (patched — seed 0)
