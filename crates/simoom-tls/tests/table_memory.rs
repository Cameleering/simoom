//! K11: the fixed-base tables (P-256, Ed25519) are built on first use with no scratch beyond
//! the table itself. One batch over every point needed 160 KB of scratch for P-256, which glibc
//! kept resident in the arena of the loop thread that did the first handshake: most of the TLS
//! build's idle memory gap against cameleer-http.
//!
//! One test function, so nothing else in this binary builds a table first.

use simoom_tls::crypto::p256;

#[global_allocator]
static A: simoom_sys::alloc::Counting = simoom_sys::alloc::Counting;

/// Heap the calling thread needs at its peak while running `f`.
fn peak_of(f: impl FnOnce()) -> i64 {
    let start = simoom_sys::alloc::thread_bytes();
    simoom_sys::alloc::reset_thread_peak();
    f();
    simoom_sys::alloc::thread_peak_bytes() - start
}

#[test]
fn fixed_base_tables_need_no_scratch() {
    let k = p256::generate_private();
    // The untabled path builds nothing; the tabled one builds the table on its first call.
    let expect = p256::public_key_untabled(&k).unwrap();
    let mut got = None;
    let t = std::time::Instant::now();
    let peak = peak_of(|| got = p256::public_key(&k));
    let first = t.elapsed();
    assert_eq!(got.unwrap(), expect);
    let table = 64 * 8 * 64; // 64 rows of 8 affine points, two 32-byte coordinates each
    eprintln!("P-256 first fixed-base multiplication: {peak} B at the peak (table {table} B), {first:?}");
    assert!(peak <= table + 4096, "P-256 table build needed {peak} B, table is {table} B");
    // Later calls allocate nothing.
    assert_eq!(peak_of(|| assert_eq!(p256::public_key(&k).unwrap(), expect)), 0);

    #[cfg(feature = "ed25519")]
    {
        use simoom_tls::crypto::ed25519;
        // RFC 8032 section 7.1, test 1.
        let seed: [u8; 32] = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").try_into().unwrap();
        let mut public = [0u8; 32];
        let peak = peak_of(|| public = ed25519::public_key(&seed));
        assert_eq!(public.to_vec(), hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"));
        let table = 32 * 8 * 120; // 32 rows of 8 Niels points, three 40-byte field elements each
        eprintln!("Ed25519 first fixed-base multiplication: {peak} B at the peak (table {table} B)");
        assert!(peak <= table + 4096, "Ed25519 table build needed {peak} B, table is {table} B");
    }
}

#[cfg(feature = "ed25519")]
fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
