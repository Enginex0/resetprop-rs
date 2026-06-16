//! Pure-Rust XZ decode for the seal feature.
//!
//! A thin, honest wrapper over `lzma-rs`'s `xz_decompress`. Its sole consumer
//! is the future `.gnu_debugdata` mini-symtab path (T11): ELF `.gnu_debugdata`
//! sections hold an XZ-compressed mini `.symtab`/`.strtab`, so we must inflate
//! the section bytes before parsing the embedded symbol table.
//!
//! No speculative options and no public surface beyond [`decode`]: input slice
//! in, decompressed bytes out. Decode failures (truncated/corrupt/unsupported
//! XZ streams) map onto the crate's existing [`crate::error::Error::Unsupported`]
//! variant — `xz_decoder` deliberately adds no new error variant, keeping the
//! shared error enum untouched.

use std::io::Cursor;

use crate::error::{Error, Result};

/// Decompress an XZ stream into its original bytes.
///
/// `input` is a complete `.xz` container (the `\xfd7zXZ\x00` magic through the
/// stream footer). On success the fully-inflated payload is returned. Any
/// failure from the decompressor — bad magic, truncated stream, unsupported
/// filter — surfaces as [`Error::Unsupported`] carrying the underlying message.
pub fn decode(input: &[u8]) -> Result<Vec<u8>> {
    let mut reader = Cursor::new(input);
    let mut output = Vec::new();
    lzma_rs::xz_decompress(&mut reader, &mut output)
        .map_err(|e| Error::Unsupported(format!("xz decode failed: {e}")))?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip proof: an embedded, known-good `.xz` stream decodes back to
    /// the exact original bytes. The fixture is produced out-of-band with
    /// `printf 'resetprop xz round-trip\n' | xz -9 -c | xxd -i` and pasted in
    /// as a `const`, so the test asserts against a real XZ container rather
    /// than re-encoding in-test (lzma-rs ships no encoder for XZ).
    const FIXTURE_XZ: &[u8] = &[
        0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x04, 0xe6, 0xd6, 0xb4, 0x46, 0x04, 0xc0, 0x1c,
        0x18, 0x21, 0x01, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd3, 0x7d,
        0x3d, 0x61, 0x01, 0x00, 0x17, 0x72, 0x65, 0x73, 0x65, 0x74, 0x70, 0x72, 0x6f, 0x70, 0x20,
        0x78, 0x7a, 0x20, 0x72, 0x6f, 0x75, 0x6e, 0x64, 0x2d, 0x74, 0x72, 0x69, 0x70, 0x0a, 0x00,
        0x7b, 0x3a, 0xfb, 0x5a, 0xca, 0x42, 0xbe, 0xf2, 0x00, 0x01, 0x38, 0x18, 0x86, 0x91, 0x75,
        0x24, 0x1f, 0xb6, 0xf3, 0x7d, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x59, 0x5a,
    ];

    const FIXTURE_PLAIN: &[u8] = b"resetprop xz round-trip\n";

    #[test]
    fn decode_roundtrips_known_xz_stream() {
        let out = decode(FIXTURE_XZ).expect("known-good XZ stream must decode");
        assert_eq!(out, FIXTURE_PLAIN);
    }

    #[test]
    fn decode_rejects_garbage_as_unsupported() {
        let err = decode(b"not an xz stream").expect_err("garbage must not decode");
        assert!(
            matches!(err, Error::Unsupported(_)),
            "decode failure must map to Error::Unsupported, got {err:?}",
        );
    }
}
