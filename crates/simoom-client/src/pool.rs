//! Connections per origin: idle HTTP/1.1 connections with a cap on live ones, and shared
//! multiplexed (HTTP/2, HTTP/3) connections.

use crate::error::{Error, Result, TimeoutKind};
use crate::h1::H1Conn;
use crate::proxy::ProxyAddr;
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Weak;
use std::hash::{BuildHasherDefault, Hasher};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

#[cfg(any(feature = "client-h2", feature = "client-h3"))]
use crate::mux::Mux;

/// What a pooled connection is for.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct OriginKey {
    pub secure: bool,
    pub host: String,
    pub port: u16,
    pub proxy: Option<ProxyAddr>,
    /// 0 auto, 1 HTTP/1.1, 2 HTTP/2, 3 HTTP/3.
    pub mode: u8,
}

/// A fast hasher for pool keys (FxHash's multiply-rotate): the keys are not attacker-chosen
/// in a way that matters (a client picks its own origins), and SipHash cost showed in profiles.
#[derive(Default)]
pub(crate) struct FxHasher(u64);

impl Hasher for FxHasher {
    fn write(&mut self, bytes: &[u8]) {
        for c in bytes.chunks(8) {
            let mut w = [0u8; 8];
            w[..c.len()].copy_from_slice(c);
            self.0 = (self.0.rotate_left(5) ^ u64::from_le_bytes(w)).wrapping_mul(0x51_7c_c1_b7_27_22_0a_95);
        }
    }
    fn write_u8(&mut self, i: u8) {
        self.write_u64(u64::from(i));
    }
    fn write_u16(&mut self, i: u16) {
        self.write_u64(u64::from(i));
    }
    fn write_usize(&mut self, i: usize) {
        self.write_u64(i as u64);
    }
    fn write_u64(&mut self, i: u64) {
        self.0 = (self.0.rotate_left(5) ^ i).wrapping_mul(0x51_7c_c1_b7_27_22_0a_95);
    }
    fn finish(&self) -> u64 {
        self.0
    }
}

type Map = HashMap<OriginKey, Origin, BuildHasherDefault<FxHasher>>;

#[derive(Default)]
struct Origin {
    /// The key, shared with the slots checked out for this origin.
    key: Option<Arc<OriginKey>>,
    idle: Vec<H1Conn>,
    live: usize,
    #[cfg(any(feature = "client-h2", feature = "client-h3"))]
    mux: Vec<Arc<Mux>>,
}

/// Pool limits.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
    pub max_per_origin: usize,
    pub max_idle_per_origin: usize,
    pub idle_timeout: Duration,
    pub max_requests: Option<u32>,
    #[cfg_attr(not(any(feature = "client-h2", feature = "client-h3")), allow(dead_code))]
    pub max_mux_per_origin: usize,
    /// Streams per multiplexed connection before another connection is opened (when
    /// `max_mux_per_origin` allows).
    #[cfg_attr(not(any(feature = "client-h2", feature = "client-h3")), allow(dead_code))]
    pub streams_per_mux: usize,
}

pub(crate) struct Pool {
    st: Mutex<Map>,
    cv: Condvar,
    pub(crate) lim: Limits,
    /// Unique per pool, so a thread's cached connection is never handed to another client.
    id: u64,
    /// Bumped by `clear`: cached connections of older generations are dropped.
    gen: AtomicU64,
    /// Connections parked in threads' caches (counted as idle in the stats).
    local_idle: AtomicUsize,
    /// Multiplexed connections in the pool (lets HTTP/1.1 requests skip the lookup).
    mux_count: AtomicUsize,
    /// Threads' cached connections, for the evictor.
    #[cfg(any(feature = "evict", feature = "client-h2", feature = "client-h3"))]
    locals: Mutex<Vec<(std::sync::Weak<Mutex<Option<H1Conn>>>, Arc<OriginKey>)>>,
    #[cfg(feature = "evict")]
    evictor: std::sync::Once,
}

/// One idle connection per thread: a thread that sends requests back to back gets its own
/// connection back without touching the pool lock. Used only when connections per origin are
/// unlimited (a parked connection must not block another thread waiting at a cap).
struct Local {
    pool: Weak<Pool>,
    id: u64,
    gen: u64,
    key: Arc<OriginKey>,
    /// Shared with the pool's evictor, which closes it when it stays idle too long.
    cell: Arc<Mutex<Option<H1Conn>>>,
}

type Cell = Arc<Mutex<Option<H1Conn>>>;

fn take(cell: &Cell) -> Option<H1Conn> {
    cell.lock().unwrap_or_else(|p| p.into_inner()).take()
}

fn has(cell: &Cell) -> bool {
    cell.lock().unwrap_or_else(|p| p.into_inner()).is_some()
}

impl Drop for Local {
    fn drop(&mut self) {
        if let Some(c) = take(&self.cell) {
            match self.pool.upgrade() {
                // the thread is ending (or the cache entry is replaced): the connection goes
                // to the shared pool, or is closed if it belongs to an older generation
                Some(p) => {
                    p.local_idle.fetch_sub(1, Ordering::Relaxed);
                    if p.gen.load(Ordering::Relaxed) == self.gen {
                        p.put_idle(self.key.clone(), c);
                    } else {
                        c.io.close();
                        p.release_slot(&self.key);
                    }
                }
                None => c.io.close(),
            }
        }
    }
}

thread_local! {
    static LOCAL: RefCell<Option<Local>> = const { RefCell::new(None) };
}

static POOL_IDS: AtomicU64 = AtomicU64::new(1);

/// A checked-out HTTP/1.1 slot: `live` was incremented; dropping it gives the slot back.
pub(crate) struct Slot {
    pool: Arc<Pool>,
    key: Option<Arc<OriginKey>>,
}

impl Drop for Slot {
    fn drop(&mut self) {
        if let Some(k) = self.key.take() {
            self.pool.release_slot(&k);
        }
    }
}

impl Slot {
    /// Returns a reusable connection to the pool (the slot stays counted as live).
    pub(crate) fn put_back(mut self, mut conn: H1Conn) {
        let Some(k) = self.key.take() else { return };
        let p = &self.pool;
        #[cfg(feature = "evict")]
        p.start_evictor();
        let reuse_ok = p.lim.max_requests.is_none_or(|m| conn.requests < m);
        if reuse_ok && conn.reusable && p.lim.max_per_origin == usize::MAX && p.lim.max_idle_per_origin > 0 {
            conn.idle_since = Instant::now();
            let gen = p.gen.load(Ordering::Relaxed);
            let parked = LOCAL.with(|l| {
                let mut l = l.borrow_mut();
                if l.as_ref().is_some_and(|x| has(&x.cell)) {
                    return Some(conn);
                }
                p.local_idle.fetch_add(1, Ordering::Relaxed);
                // reuse this thread's cell (already known to the evictor) when it is for this pool
                if let Some(x) = l.as_mut().filter(|x| x.id == p.id) {
                    x.gen = gen;
                    x.key = k.clone();
                    *x.cell.lock().unwrap_or_else(|e| e.into_inner()) = Some(conn);
                    return None;
                }
                let cell: Cell = Arc::new(Mutex::new(Some(conn)));
                #[cfg(any(feature = "evict", feature = "client-h2", feature = "client-h3"))]
                p.locals.lock().unwrap_or_else(|e| e.into_inner()).push((Arc::downgrade(&cell), k.clone()));
                *l = Some(Local { pool: Arc::downgrade(p), id: p.id, gen, key: k.clone(), cell });
                None
            });
            match parked {
                None => return,
                Some(c) => conn = c,
            }
        }
        self.pool.put_idle(k, conn);
    }
}

impl Pool {
    pub(crate) fn new(lim: Limits) -> Pool {
        Pool {
            st: Mutex::new(Map::default()),
            cv: Condvar::new(),
            lim,
            id: POOL_IDS.fetch_add(1, Ordering::Relaxed),
            gen: AtomicU64::new(0),
            local_idle: AtomicUsize::new(0),
            mux_count: AtomicUsize::new(0),
            #[cfg(any(feature = "evict", feature = "client-h2", feature = "client-h3"))]
            locals: Mutex::new(Vec::new()),
            #[cfg(feature = "evict")]
            evictor: std::sync::Once::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Map> {
        self.st.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn release_slot(&self, k: &OriginKey) {
        let mut st = self.lock();
        if let Some(o) = st.get_mut(k) {
            o.live = o.live.saturating_sub(1);
        }
        drop(st);
        self.cv.notify_one();
    }

    fn put_idle(&self, k: Arc<OriginKey>, mut conn: H1Conn) {
        conn.idle_since = Instant::now();
        let reuse_ok = self.lim.max_requests.is_none_or(|m| conn.requests < m);
        let mut st = self.lock();
        if !st.contains_key(&*k) {
            st.insert((*k).clone(), Origin { key: Some(k.clone()), ..Origin::default() });
        }
        let o = st.get_mut(&*k).unwrap_or_else(|| unreachable!());
        if reuse_ok && conn.reusable && o.idle.len() < self.lim.max_idle_per_origin {
            o.idle.push(conn);
        } else {
            o.live = o.live.saturating_sub(1);
            drop(st);
            conn.io.close();
        }
        self.cv.notify_one();
    }

    /// Whether any multiplexed connection is pooled.
    pub(crate) fn has_mux(&self) -> bool {
        self.mux_count.load(Ordering::Relaxed) > 0
    }

    /// This thread's cached idle connection, if it is for this origin (compared field by field,
    /// so no key is built on the hot path).
    pub(crate) fn take_local(self: &Arc<Self>, secure: bool, host: &str, port: u16, proxy: Option<&ProxyAddr>, mode: u8) -> Option<(H1Conn, Slot)> {
        let gen = self.gen.load(Ordering::Relaxed);
        let (c, k) = LOCAL.with(|l| {
            let mut l = l.borrow_mut();
            let x = l.as_mut()?;
            let k = &x.key;
            if x.id != self.id || x.gen != gen || k.secure != secure || k.port != port || k.mode != mode || k.host != host || k.proxy.as_ref() != proxy {
                return None;
            }
            let c = take(&x.cell)?;
            self.local_idle.fetch_sub(1, Ordering::Relaxed);
            Some((c, x.key.clone()))
        })?;
        let idle = c.idle_since.elapsed();
        if idle < self.lim.idle_timeout && !(idle >= Duration::from_secs(1) && c.io.idle_is_broken()) {
            return Some((c, Slot { pool: self.clone(), key: Some(k) }));
        }
        c.io.close();
        self.release_slot(&k);
        None
    }

    /// An idle connection to reuse, or a slot to open a new one. Waits while the origin is at
    /// its cap.
    pub(crate) fn checkout(self: &Arc<Self>, key: &OriginKey, deadline: Option<Instant>, what: &dyn std::fmt::Display) -> Result<(Option<H1Conn>, Slot)> {
        // this thread's own idle connection first: no lock
        let gen = self.gen.load(Ordering::Relaxed);
        let local = LOCAL.with(|l| {
            let mut l = l.borrow_mut();
            let x = l.as_mut()?;
            if x.id != self.id || !has(&x.cell) {
                return None;
            }
            if x.gen != gen || *x.key != *key {
                if x.gen != gen {
                    // closed by `clear`: drop it (Drop gives the slot back)
                    *l = None;
                }
                return None;
            }
            let c = take(&x.cell)?;
            self.local_idle.fetch_sub(1, Ordering::Relaxed);
            Some((c, x.key.clone()))
        });
        if let Some((c, k)) = local {
            let idle = c.idle_since.elapsed();
            if idle < self.lim.idle_timeout && !(idle >= Duration::from_secs(1) && c.io.idle_is_broken()) {
                return Ok((Some(c), Slot { pool: self.clone(), key: Some(k) }));
            }
            c.io.close();
            self.release_slot(&k);
        }
        let mut st = self.lock();
        let mut stale: Vec<H1Conn> = Vec::new();
        loop {
            if !st.contains_key(key) {
                st.insert(key.clone(), Origin { key: Some(Arc::new(key.clone())), ..Origin::default() });
            }
            let o = st.get_mut(key).unwrap_or_else(|| unreachable!());
            let k = o.key.get_or_insert_with(|| Arc::new(key.clone())).clone();
            while let Some(c) = o.idle.pop() {
                let idle = c.idle_since.elapsed();
                if idle >= self.lim.idle_timeout || (idle >= Duration::from_secs(1) && c.io.idle_is_broken()) {
                    o.live = o.live.saturating_sub(1);
                    stale.push(c);
                    continue;
                }
                drop(st);
                for s in stale {
                    s.io.close();
                }
                return Ok((Some(c), Slot { pool: self.clone(), key: Some(k) }));
            }
            if o.live < self.lim.max_per_origin {
                o.live += 1;
                drop(st);
                for s in stale {
                    s.io.close();
                }
                return Ok((None, Slot { pool: self.clone(), key: Some(k) }));
            }
            let now = Instant::now();
            let wait = match deadline {
                Some(d) if now >= d => return Err(Error::timeout(TimeoutKind::Pool, what)),
                Some(d) => d - now,
                None => Duration::from_secs(3600),
            };
            st = self.cv.wait_timeout(st, wait).unwrap_or_else(|p| p.into_inner()).0;
        }
    }

    /// A shared connection for `key` that can take a new stream (or any live one when all are
    /// busy and `any` is set; its `open` then waits for a free stream).
    #[cfg(any(feature = "client-h2", feature = "client-h3"))]
    pub(crate) fn mux(&self, key: &OriginKey, any: bool) -> Option<Arc<Mux>> {
        if self.mux_count.load(Ordering::Relaxed) == 0 {
            return None;
        }
        let mut st = self.lock();
        let o = st.get_mut(key)?;
        let mut dead = Vec::new();
        let idle_lim = self.lim.idle_timeout;
        let mut open = None;
        o.mux.retain(|m| {
            let (gone, mut can) = m.usable(idle_lim);
            can = can && m.active() < self.lim.streams_per_mux;
            if gone {
                dead.push(m.clone());
                false
            } else {
                if can && open.is_none() {
                    open = Some(m.clone());
                }
                true
            }
        });
        let found = open.or_else(|| if any && o.mux.len() >= self.lim.max_mux_per_origin { o.mux.first().cloned() } else { None });
        self.mux_count.fetch_sub(dead.len(), Ordering::Relaxed);
        drop(st);
        for d in dead {
            d.close();
        }
        found
    }

    #[cfg(any(feature = "client-h2", feature = "client-h3"))]
    pub(crate) fn add_mux(&self, key: OriginKey, m: Arc<Mux>) {
        self.lock().entry(key).or_default().mux.push(m);
        self.mux_count.fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(any(feature = "client-h2", feature = "client-h3"))]
    pub(crate) fn remove_mux(&self, key: &OriginKey, m: &Arc<Mux>) {
        if let Some(o) = self.lock().get_mut(key) {
            let before = o.mux.len();
            o.mux.retain(|x| !Arc::ptr_eq(x, m));
            self.mux_count.fetch_sub(before - o.mux.len(), Ordering::Relaxed);
        }
    }

    /// Every shared connection.
    #[cfg(any(feature = "client-h2", feature = "client-h3"))]
    pub(crate) fn all_mux(&self) -> Vec<(OriginKey, Arc<Mux>)> {
        let st = self.lock();
        st.iter().flat_map(|(k, o)| o.mux.iter().map(move |m| (k.clone(), m.clone()))).collect()
    }

    /// Starts the background evictor once: a thread that closes connections idle longer than
    /// the idle timeout (shared and cached ones), so idle sockets do not linger until the next
    /// request. It exits when the pool is dropped.
    #[cfg(feature = "evict")]
    fn start_evictor(self: &Arc<Self>) {
        self.evictor.call_once(|| {
            let weak = Arc::downgrade(self);
            let tick = (self.lim.idle_timeout / 2).clamp(Duration::from_millis(50), Duration::from_secs(5));
            let _ = std::thread::Builder::new().name("simoom-client-evict".into()).spawn(move || loop {
                std::thread::sleep(tick);
                let Some(p) = weak.upgrade() else { return };
                p.evict();
            });
        });
    }

    /// Closes idle HTTP/1.1 connections past the idle timeout.
    #[cfg(any(feature = "evict", feature = "client-h2", feature = "client-h3"))]
    pub(crate) fn evict(&self) {
        let lim = self.lim.idle_timeout;
        let mut gone = Vec::new();
        self.locals.lock().unwrap_or_else(|p| p.into_inner()).retain(|(w, k)| {
            let Some(cell) = w.upgrade() else { return false };
            let mut g = cell.lock().unwrap_or_else(|p| p.into_inner());
            if g.as_ref().is_some_and(|c| c.idle_since.elapsed() >= lim) {
                if let Some(c) = g.take() {
                    gone.push((c, k.clone()));
                }
            }
            true
        });
        for (c, k) in gone {
            c.io.close();
            self.local_idle.fetch_sub(1, Ordering::Relaxed);
            self.release_slot(&k);
        }
        let mut closed = Vec::new();
        {
            let mut st = self.lock();
            for o in st.values_mut() {
                let before = o.idle.len();
                let lim = self.lim.idle_timeout;
                let mut keep = Vec::with_capacity(before);
                for c in o.idle.drain(..) {
                    if c.idle_since.elapsed() >= lim {
                        closed.push(c);
                    } else {
                        keep.push(c);
                    }
                }
                o.live = o.live.saturating_sub(before - keep.len());
                o.idle = keep;
            }
        }
        for c in closed {
            c.io.close();
        }
    }

    /// Idle HTTP/1.1 connections (all origins).
    pub(crate) fn idle_count(&self) -> usize {
        self.lock().values().map(|o| o.idle.len()).sum::<usize>() + self.local_idle.load(Ordering::Relaxed)
    }

    /// Live HTTP/1.1 connections (idle and in use) and shared connections.
    pub(crate) fn counts(&self) -> (usize, usize) {
        let st = self.lock();
        let live = st.values().map(|o| o.live).sum();
        #[cfg(any(feature = "client-h2", feature = "client-h3"))]
        let mux = st.values().map(|o| o.mux.len()).sum();
        #[cfg(not(any(feature = "client-h2", feature = "client-h3")))]
        let mux = 0;
        (live, mux)
    }

    /// Closes every connection.
    pub(crate) fn clear(&self) {
        self.gen.fetch_add(1, Ordering::Relaxed);
        // this thread's cached connection goes now; other threads drop theirs on next use
        LOCAL.with(|l| {
            let mut l = l.borrow_mut();
            if l.as_ref().is_some_and(|x| x.id == self.id) {
                *l = None;
            }
        });
        let mut st = self.lock();
        let all: Vec<(OriginKey, Origin)> = st.drain().collect();
        self.mux_count.store(0, Ordering::Relaxed);
        drop(st);
        for (_, o) in all {
            for c in o.idle {
                c.io.close();
            }
            #[cfg(any(feature = "client-h2", feature = "client-h3"))]
            for m in o.mux {
                m.close();
            }
        }
    }
}
