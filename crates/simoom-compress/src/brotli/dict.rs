//! The RFC 7932 static dictionary (Appendix A, 122,784 bytes). It is stored DEFLATE-compressed
//! (58,898 bytes, see `dictionary.deflate`) and inflated on first use, which keeps 64 KB out of
//! every binary with the `brotli` feature; the first Brotli stream that needs it pays about
//! 0.3 ms once. Its SHA-256 is checked in the tests against the RFC's value.

use std::sync::OnceLock;

/// Offset of the words of each length (4..=24) in the dictionary.
pub(crate) const OFFSETS: [u32; 25] = [
    0, 0, 0, 0, 0, 4096, 9216, 21504, 35840, 44032, 53248, 63488, 74752, 87040, 93696, 100864, 104704, 106752, 108928, 113536, 115968, 118528,
    119872, 121280, 122016,
];

/// log2 of the number of words of each length.
pub(crate) const NDBITS: [u32; 25] = [0, 0, 0, 0, 10, 10, 11, 11, 10, 10, 10, 10, 10, 9, 9, 8, 7, 7, 8, 7, 7, 6, 6, 5, 5];

pub(crate) const SIZE: usize = 122_784;

static PACKED: &[u8] = include_bytes!("dictionary.deflate");

/// The dictionary.
pub(crate) fn dictionary() -> &'static [u8] {
    static D: OnceLock<Vec<u8>> = OnceLock::new();
    D.get_or_init(|| {
        let d = crate::decompress(PACKED, crate::Format::Raw, SIZE).expect("the embedded Brotli dictionary");
        assert_eq!(d.len(), SIZE, "the embedded Brotli dictionary");
        d
    })
}
