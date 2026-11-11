//! A lock-free multi-producer, single-consumer queue: any thread pushes, one thread takes
//! everything at once.
//!
//! Producers push onto an atomic stack with one compare-and-swap; the consumer swaps the whole
//! stack out in one atomic exchange and reverses it, so items come out in the order they were
//! pushed (per producer, and in push order overall). There is no lock, so a producer never
//! waits on the consumer or on another producer's critical section, and nothing ever calls into
//! the kernel. Taking the whole stack at once has no ABA problem: a node is only ever freed by
//! the consumer after it left the shared stack.
//!
//! The event loops use it for messages from other threads (`Responder::send`, offloaded jobs),
//! together with [`crate::driver::Waker::post`], which wakes a loop only when it is parked.

use core::ptr;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicPtr, Ordering};

struct Node<T> {
    next: *mut Node<T>,
    value: T,
}

/// The queue (see the module documentation).
pub struct Mpsc<T> {
    head: AtomicPtr<Node<T>>,
    _owns: PhantomData<Box<Node<T>>>,
}

// SAFETY: the queue moves `T` values between threads (so `T: Send`), and every access to the
// shared head is atomic; nodes are owned by exactly one side at a time (a producer until its
// compare-and-swap succeeds, then the stack, then the consumer after its exchange).
unsafe impl<T: Send> Send for Mpsc<T> {}
// SAFETY: as above; `push` and `take` only touch the head through atomics.
unsafe impl<T: Send> Sync for Mpsc<T> {}

impl<T> Default for Mpsc<T> {
    fn default() -> Self {
        Mpsc::new()
    }
}

impl<T> std::fmt::Debug for Mpsc<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mpsc").field("empty", &self.is_empty()).finish()
    }
}

impl<T> Mpsc<T> {
    /// An empty queue.
    pub const fn new() -> Mpsc<T> {
        Mpsc { head: AtomicPtr::new(ptr::null_mut()), _owns: PhantomData }
    }

    /// Adds `value` (any thread). Sequentially consistent, so a consumer that announces it is
    /// about to sleep and then checks [`Mpsc::is_empty`] either sees the value or is seen by
    /// the producer's following check of that announcement.
    pub fn push(&self, value: T) {
        let node = Box::into_raw(Box::new(Node { next: ptr::null_mut(), value }));
        let mut head = self.head.load(Ordering::Relaxed);
        loop {
            // SAFETY: `node` came from `Box::into_raw` above and is not shared until the
            // compare-and-swap below succeeds, so this thread has exclusive access to it.
            unsafe { (*node).next = head };
            match self.head.compare_exchange_weak(head, node, Ordering::SeqCst, Ordering::Relaxed) {
                Ok(_) => return,
                Err(h) => head = h,
            }
        }
    }

    /// Whether the queue looks empty (a push may be landing concurrently).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.head.load(Ordering::SeqCst).is_null()
    }

    /// Moves every queued value into `into`, oldest first (the consumer thread).
    pub fn take(&self, into: &mut Vec<T>) {
        if self.head.load(Ordering::Relaxed).is_null() {
            return;
        }
        let mut p = self.head.swap(ptr::null_mut(), Ordering::Acquire);
        let start = into.len();
        while !p.is_null() {
            // SAFETY: the exchange above took the whole list out of the shared head, so no
            // other thread can reach these nodes any more; each was made by `Box::into_raw` in
            // `push` and is freed exactly once here.
            let node = unsafe { Box::from_raw(p) };
            p = node.next;
            into.push(node.value);
        }
        // The stack holds the newest first.
        into[start..].reverse();
    }
}

impl<T> Drop for Mpsc<T> {
    fn drop(&mut self) {
        let mut p = *self.head.get_mut();
        while !p.is_null() {
            // SAFETY: `&mut self` means no producer or consumer is running; every node in the
            // list came from `Box::into_raw` and is freed exactly once.
            let node = unsafe { Box::from_raw(p) };
            p = node.next;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn values_come_out_in_push_order() {
        let q = Mpsc::new();
        let mut v = Vec::new();
        q.take(&mut v);
        assert!(v.is_empty() && q.is_empty());
        for i in 0..5 {
            q.push(i);
        }
        assert!(!q.is_empty());
        v.push(-1);
        q.take(&mut v);
        assert_eq!(v, [-1, 0, 1, 2, 3, 4]);
        assert!(q.is_empty());
    }

    #[test]
    fn many_producers_lose_nothing_and_keep_their_own_order() {
        let q = Arc::new(Mpsc::new());
        let producers: Vec<_> = (0..8u64)
            .map(|p| {
                let q = q.clone();
                std::thread::spawn(move || {
                    for i in 0..20_000u64 {
                        q.push((p, i));
                    }
                })
            })
            .collect();
        let mut seen = vec![0u64; 8];
        let mut got = 0;
        let mut buf = Vec::new();
        while got < 8 * 20_000 {
            q.take(&mut buf);
            for (p, i) in buf.drain(..) {
                assert_eq!(seen[p as usize], i, "producer {p} out of order");
                seen[p as usize] += 1;
                got += 1;
            }
        }
        for t in producers {
            t.join().unwrap();
        }
        assert!(q.is_empty());
    }

    #[test]
    fn dropping_a_full_queue_drops_its_values() {
        let marker = Arc::new(());
        let q = Mpsc::new();
        for _ in 0..10 {
            q.push(marker.clone());
        }
        assert_eq!(Arc::strong_count(&marker), 11);
        drop(q);
        assert_eq!(Arc::strong_count(&marker), 1);
    }
}
