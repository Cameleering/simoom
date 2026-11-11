//! The operating system's trusted root certificates, for TLS clients.
//!
//! - Windows: the `ROOT` system store of the current user (which includes the machine roots),
//!   read with `CertOpenSystemStoreW` and `CertEnumCertificatesInStore` from crypt32.
//! - Elsewhere: nothing here; Unix systems keep their roots in PEM bundles (`/etc/ssl/...`,
//!   `SSL_CERT_FILE`), which simoom-tls reads itself. macOS ships `/etc/ssl/cert.pem` with the
//!   system roots, so the bundle path covers it too.

/// DER-encoded root certificates from the OS store (empty where the OS has no such store or it
/// cannot be opened).
pub fn system_roots() -> Vec<Vec<u8>> {
    imp::roots()
}

#[cfg(windows)]
mod imp {
    use core::ffi::c_void;

    /// The fields of `CERT_CONTEXT` that are read.
    #[repr(C)]
    struct CertContext {
        encoding_type: u32,
        cert_encoded: *const u8,
        cert_encoded_len: u32,
        cert_info: *mut c_void,
        store: *mut c_void,
    }

    #[link(name = "crypt32")]
    extern "system" {
        fn CertOpenSystemStoreW(prov: usize, subsystem: *const u16) -> *mut c_void;
        fn CertEnumCertificatesInStore(store: *mut c_void, prev: *const CertContext) -> *const CertContext;
        fn CertCloseStore(store: *mut c_void, flags: u32) -> i32;
    }

    const X509_ASN_ENCODING: u32 = 1;

    pub(super) fn roots() -> Vec<Vec<u8>> {
        let name: Vec<u16> = "ROOT".encode_utf16().chain(Some(0)).collect();
        // SAFETY: `name` is a NUL-terminated UTF-16 string that outlives the call; a zero
        // provider handle asks for the default provider.
        let store = unsafe { CertOpenSystemStoreW(0, name.as_ptr()) };
        if store.is_null() {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut ctx: *const CertContext = std::ptr::null();
        loop {
            // SAFETY: `store` is an open store handle; `ctx` is null or the context returned by
            // the previous call, which this call frees (the documented enumeration pattern).
            ctx = unsafe { CertEnumCertificatesInStore(store, ctx) };
            if ctx.is_null() {
                break;
            }
            // SAFETY: a non-null context returned by the enumeration is valid until the next
            // call; its encoded certificate is `cert_encoded_len` readable bytes.
            let der = unsafe {
                let c = &*ctx;
                if c.encoding_type & X509_ASN_ENCODING == 0 || c.cert_encoded.is_null() {
                    None
                } else {
                    Some(std::slice::from_raw_parts(c.cert_encoded, c.cert_encoded_len as usize).to_vec())
                }
            };
            if let Some(d) = der {
                out.push(d);
            }
        }
        // SAFETY: `store` is open and no context from it is still held (the enumeration ended
        // with null, which freed the last one).
        unsafe { CertCloseStore(store, 0) };
        out
    }
}

#[cfg(not(windows))]
mod imp {
    pub(super) fn roots() -> Vec<Vec<u8>> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    #[test]
    fn windows_root_store_has_certificates() {
        let roots = super::system_roots();
        assert!(roots.len() > 5, "{} roots", roots.len());
        assert!(roots.iter().all(|d| d.first() == Some(&0x30)), "DER SEQUENCE");
    }

    #[cfg(not(windows))]
    #[test]
    fn other_systems_use_bundles() {
        assert!(super::system_roots().is_empty());
    }
}
