#![allow(dead_code)]

use simoom_rt::{Backend, Builder, Runtime};
use std::time::{Duration, Instant};

/// Every back end this machine can run.
pub fn backends() -> Vec<Backend> {
    if cfg!(target_os = "linux") {
        let mut v = vec![Backend::Epoll];
        // Probe io_uring by starting a tiny runtime with it.
        let rt = Runtime::builder().threads(1).backend(Backend::IoUring).start().unwrap();
        if rt.backend() == Backend::IoUring {
            v.push(Backend::IoUring);
        } else {
            eprintln!("io_uring not available: {:?}", rt.fallback_reason());
        }
        v
    } else if cfg!(windows) {
        vec![Backend::Iocp]
    } else {
        vec![Backend::Kqueue]
    }
}

pub fn builder(b: Backend, threads: usize) -> Builder {
    Runtime::builder().threads(threads).backend(b)
}

/// Polls `f` until it returns true or `secs` pass.
pub fn wait_until(secs: u64, mut f: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < end {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    f()
}
