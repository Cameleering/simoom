//! Revocation in the handshake (feature `revocation`): OCSP stapling (`status_request`) in TLS
//! 1.3 (leaf certificate entry extension) and TLS 1.2 (CertificateStatus), client policies
//! (Request / Require), CRL checks of server and client certificates, and interop with
//! `openssl s_client -status` and `openssl s_server -status_file`.

mod common;

use common::*;
use simoom_tls::revocation::ocsp::CertStatus;
use simoom_tls::revocation::testing::{issue, TestCert, TestPki};
use simoom_tls::revocation::{CrlMode, OcspMode, RevocationPolicy, StapleSource};
use simoom_tls::tls::ProtocolVersion;
use simoom_tls::x509::{CertError, RootStore};
use simoom_tls::{alert, CertifiedKey, ClientAuth, ClientConfig, ClientConnection, Error, ServerConfig, ServerConnection};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

fn setup() -> (TestPki, ServerConfig, ClientConfig) {
    let pki = TestPki::new((now_ms() / 1000) as i64);
    let ck = CertifiedKey::new(vec![pki.leaf.cert_der.clone(), pki.intermediate.cert_der.clone()], pki.leaf.key.clone()).unwrap();
    let scfg = ServerConfig::new(ck);
    let mut roots = RootStore::empty();
    roots.add_der(&pki.ca.cert_der).unwrap();
    let ccfg = ClientConfig::new(roots);
    (pki, scfg, ccfg)
}

fn versions() -> [ProtocolVersion; 2] {
    [ProtocolVersion::Tls13, ProtocolVersion::Tls12]
}

fn handshake(scfg: &ServerConfig, ccfg: &ClientConfig, v: ProtocolVersion) -> (ClientConnection, ServerConnection, Result<(), (char, Error)>) {
    let mut scfg = scfg.clone();
    scfg.max_version = v;
    let mut c = ClientConnection::new(Arc::new(clone_client(ccfg)), "leaf.test").unwrap();
    let mut s = ServerConnection::new(Arc::new(scfg));
    let r = pump(&mut c, &mut s);
    (c, s, r)
}

fn clone_client(c: &ClientConfig) -> ClientConfig {
    let mut n = ClientConfig::new(c.roots.clone());
    n.revocation = c.revocation.clone();
    n.client_cert = c.client_cert.clone();
    n
}

#[test]
fn stapled_ocsp_good_revoked_missing() {
    for v in versions() {
        let (pki, mut scfg, mut ccfg) = setup();
        let staple = StapleSource::new();
        scfg.ocsp_staple = Some(staple.clone());
        // good staple, client requires one
        let good = pki.leaf_ocsp(CertStatus::Good);
        assert_eq!(staple.set_checked(good.clone(), &pki.leaf_cert, &pki.int_cert, pki.now).unwrap(), CertStatus::Good);
        ccfg.revocation = Some(RevocationPolicy::new().with_ocsp(OcspMode::Require));
        let (c, s, r) = handshake(&scfg, &ccfg, v);
        r.unwrap_or_else(|(side, e)| panic!("{v:?} {side}: {e}"));
        assert_eq!(c.protocol_version(), Some(v));
        assert_eq!(c.ocsp_response(), Some(&good[..]));
        drop(s);
        // revoked staple: refused with certificate_revoked, even in Request mode
        staple.set(Some(pki.leaf_ocsp(CertStatus::Revoked { time: pki.now - 10, reason: Some(1) })));
        ccfg.revocation = Some(RevocationPolicy::new().with_ocsp(OcspMode::Request));
        let (_, _, r) = handshake(&scfg, &ccfg, v);
        let (side, e) = r.unwrap_err();
        assert_eq!(side, 'c');
        assert!(matches!(e, Error::Certificate(CertError::Revoked { .. })), "{v:?}: {e}");
        assert_eq!(e.alert(), Some(alert::CERTIFICATE_REVOKED));
        // no staple: Request accepts, Require refuses
        staple.set(None);
        let (c, _, r) = handshake(&scfg, &ccfg, v);
        r.unwrap();
        assert_eq!(c.ocsp_response(), None);
        ccfg.revocation = Some(RevocationPolicy::new().with_ocsp(OcspMode::Require));
        let (_, _, r) = handshake(&scfg, &ccfg, v);
        assert!(matches!(r.unwrap_err().1, Error::Certificate(CertError::RevocationUnknown { .. })));
        // a client that does not ask gets no staple
        staple.set(Some(good.clone()));
        ccfg.revocation = None;
        let (c, _, r) = handshake(&scfg, &ccfg, v);
        r.unwrap();
        assert_eq!(c.ocsp_response(), None);
    }
}

#[test]
fn crls_for_server_and_client_certificates() {
    for v in versions() {
        let (pki, mut scfg, mut ccfg) = setup();
        let ca_crl = pki.ca_crl(&[]);
        // the leaf revoked in the intermediate's CRL
        let revoked = pki.int_crl(&[&pki.leaf_cert.serial]);
        let policy = |int_crl: &[u8]| {
            let mut p = RevocationPolicy::new().with_crl_mode(CrlMode::Require);
            p.add_crls(&ca_crl).unwrap();
            p.add_crls(int_crl).unwrap();
            p
        };
        ccfg.revocation = Some(policy(&revoked));
        let (_, _, r) = handshake(&scfg, &ccfg, v);
        assert!(matches!(r.unwrap_err().1, Error::Certificate(CertError::Revoked { .. })), "{v:?}");
        ccfg.revocation = Some(policy(&pki.int_crl(&[])));
        let (_, _, r) = handshake(&scfg, &ccfg, v);
        r.unwrap_or_else(|(side, e)| panic!("{v:?} {side}: {e}"));
        // Require without any CRL: refused
        ccfg.revocation = Some(RevocationPolicy::new().with_crl_mode(CrlMode::Require));
        let (_, _, r) = handshake(&scfg, &ccfg, v);
        assert!(matches!(r.unwrap_err().1, Error::Certificate(CertError::RevocationUnknown { .. })));

        // client certificates checked by the server
        let mut t = TestCert::server("client.test", pki.now);
        t.ext_key_usage = vec![simoom_tls::x509::OID_EKU_CLIENT_AUTH.to_string()];
        let client = issue(&t, simoom_tls::revocation::testing::ec_key(), Some(&pki.intermediate));
        let client_cert = simoom_tls::x509::Certificate::from_der(&client.cert_der).unwrap();
        let mut roots = RootStore::empty();
        roots.add_der(&pki.ca.cert_der).unwrap();
        scfg.client_auth = ClientAuth::Required(roots);
        ccfg.revocation = None;
        ccfg.client_cert = Some(CertifiedKey::new(vec![client.cert_der.clone(), pki.intermediate.cert_der.clone()], client.key.clone()).unwrap());
        scfg.client_revocation = Some(policy(&pki.int_crl(&[&client_cert.serial])));
        let (_, _, r) = handshake(&scfg, &ccfg, v);
        let (side, e) = r.unwrap_err();
        assert_eq!(side, 's');
        assert_eq!(e.alert(), Some(alert::CERTIFICATE_REVOKED), "{v:?}: {e}");
        scfg.client_revocation = Some(policy(&pki.int_crl(&[])));
        let (_, s, r) = handshake(&scfg, &ccfg, v);
        r.unwrap_or_else(|(side, e)| panic!("{v:?} {side}: {e}"));
        assert_eq!(s.peer_certificates().len(), 2);
    }
}

fn openssl() -> Option<std::path::PathBuf> {
    let p = std::env::var("SIMOOM_OPENSSL").unwrap_or_else(|_| "openssl".into());
    if Command::new(&p).arg("version").stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok() {
        Some(p.into())
    } else {
        println!("NOTE: openssl not found; stapling interop skipped");
        None
    }
}

fn tempdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("simoom-tls-staple-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn p(d: &std::path::Path, name: &str) -> String {
    d.join(name).to_string_lossy().replace('\\', "/")
}

#[test]
fn openssl_s_client_status_against_simoom_server() {
    let Some(ossl) = openssl() else { return };
    for (v, flag) in [(ProtocolVersion::Tls13, "-tls1_3"), (ProtocolVersion::Tls12, "-tls1_2")] {
        let (pki, mut scfg, _) = setup();
        let dir = tempdir(flag);
        std::fs::write(dir.join("ca.pem"), &pki.ca.cert_pem).unwrap();
        let staple = StapleSource::new();
        staple.set(Some(pki.leaf_ocsp(CertStatus::Good)));
        scfg.ocsp_staple = Some(staple);
        scfg.max_version = v;
        let cfg = Arc::new(scfg);
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            let (mut sock, _) = l.accept().unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            let mut conn = ServerConnection::new(cfg);
            let mut buf = [0u8; 16384];
            loop {
                while conn.wants_write() {
                    let n = sock.write(conn.tls_output()).unwrap();
                    conn.consume_tls_output(n);
                }
                if !conn.is_handshaking() {
                    conn.send_close_notify();
                    let out = conn.tls_output().to_vec();
                    let _ = sock.write_all(&out);
                    return Ok(());
                }
                let n = match sock.read(&mut buf) {
                    Ok(0) | Err(_) => return Err("eof".to_string()),
                    Ok(n) => n,
                };
                conn.read_tls(&buf[..n]);
                conn.process_new_packets().map_err(|e| e.to_string())?;
            }
        });
        let o = Command::new(&ossl)
            .args(["s_client", "-connect", &format!("127.0.0.1:{port}"), flag, "-servername", "leaf.test", "-status", "-CAfile", &p(&dir, "ca.pem"), "-verify_return_error"])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let out = String::from_utf8_lossy(&o.stdout);
        let r = h.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(r.is_ok(), "{flag}: {r:?}");
        assert!(out.contains("OCSP Response Status: successful") && out.contains("Cert Status: good"), "{flag}: {out}");
        println!("s_client {flag} -status: ok");
    }
}

#[test]
fn simoom_client_against_openssl_s_server_status_file() {
    let Some(ossl) = openssl() else { return };
    for (v, flag) in [(ProtocolVersion::Tls13, "-tls1_3"), (ProtocolVersion::Tls12, "-tls1_2")] {
        let (pki, _, mut ccfg) = setup();
        let dir = tempdir(&format!("srv{flag}"));
        std::fs::write(dir.join("leaf.pem"), &pki.leaf.cert_pem).unwrap();
        std::fs::write(dir.join("int.pem"), &pki.intermediate.cert_pem).unwrap();
        std::fs::write(dir.join("leaf.key"), &pki.leaf.key_pem).unwrap();
        let resp = pki.leaf_ocsp(CertStatus::Good);
        std::fs::write(dir.join("resp.der"), &resp).unwrap();
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let mut child = Command::new(&ossl)
            .args(["s_server", "-accept", &port.to_string(), flag, "-cert", &p(&dir, "leaf.pem"), "-key", &p(&dir, "leaf.key"), "-cert_chain", &p(&dir, "int.pem"), "-status_file", &p(&dir, "resp.der"), "-www", "-naccept", "1"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        ccfg.revocation = Some(RevocationPolicy::new().with_ocsp(OcspMode::Require));
        let mut sock = None;
        for _ in 0..200 {
            if let Ok(s) = TcpStream::connect(("127.0.0.1", port)) {
                sock = Some(s);
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let mut sock = sock.expect("s_server");
        sock.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut conn = ClientConnection::new(Arc::new(ccfg), "leaf.test").unwrap();
        conn.write_plaintext(b"GET / HTTP/1.0\r\n\r\n").unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 16384];
        let mut err = None;
        loop {
            while conn.wants_write() {
                let n = sock.write(conn.tls_output()).unwrap();
                conn.consume_tls_output(n);
            }
            let n = match sock.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            conn.read_tls(&buf[..n]);
            if let Err(e) = conn.process_new_packets() {
                err = Some(e);
                break;
            }
            let n = conn.read_plaintext(&mut buf);
            got.extend_from_slice(&buf[..n]);
            if conn.peer_has_closed() {
                break;
            }
        }
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(err.is_none(), "{flag}: {err:?}");
        assert_eq!(conn.protocol_version(), Some(v));
        assert_eq!(conn.ocsp_response(), Some(&resp[..]), "{flag}: staple received");
        assert!(String::from_utf8_lossy(&got).starts_with("HTTP/1.0 200 ok"));
        println!("s_server {flag} -status_file: ok");
    }
}
