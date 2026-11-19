//! `LoopHandle::current`, handle equality, and same-turn delivery of what a loop queues for
//! itself.

use simoom_rt::{LoopHandle, Runtime};
use std::sync::mpsc::channel;
use std::time::Duration;

#[test]
fn a_loop_thread_knows_its_loop() {
    assert!(LoopHandle::current().is_none(), "not a loop thread");
    let rt = Runtime::builder().threads(2).start().unwrap();
    let other = Runtime::builder().threads(1).start().unwrap();
    let loops = rt.loops();
    assert_eq!(loops.len(), 2);
    assert_ne!(loops[0], loops[1]);
    assert_eq!(loops[0], loops[0].clone());
    assert_ne!(loops[0], other.loops()[0]);
    assert!(!loops[0].is_current());
    for lh in &loops {
        let (tx, rx) = channel();
        let me = lh.clone();
        assert!(lh.run(move |_| {
            let cur = LoopHandle::current();
            tx.send((cur.as_ref() == Some(&me), me.is_current(), cur.map(|c| c.index()))).unwrap();
        }));
        let (same, is_current, index) = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(same && is_current);
        assert_eq!(index, Some(lh.index()));
    }
    rt.stop(Duration::from_millis(100));
    rt.join();
    other.stop(Duration::from_millis(100));
    other.join();
}

/// 1000 tasks, each queued by the one before from the loop's own thread: they run in the turn
/// that started them (one wait in the OS for all of them, not one each).
#[test]
fn tasks_a_loop_queues_for_itself_run_in_the_same_turn() {
    let rt = Runtime::builder().threads(1).start().unwrap();
    let lh = rt.loops()[0].clone();
    // let the loop settle and publish its counters
    let (tx, rx) = channel();
    lh.run(move |_| tx.send(()).unwrap());
    rx.recv_timeout(Duration::from_secs(5)).unwrap();
    std::thread::sleep(Duration::from_millis(50));
    let before = rt.stats().loops[0].driver.waits;

    fn chain(lh: LoopHandle, left: usize, done: std::sync::mpsc::Sender<()>) {
        let next = lh.clone();
        lh.run(move |_| {
            if left == 0 {
                done.send(()).unwrap();
            } else {
                chain(next, left - 1, done);
            }
        });
    }
    let (tx, rx) = channel();
    let (l2, t2) = (lh.clone(), tx);
    lh.run(move |_| chain(l2, 1000, t2));
    rx.recv_timeout(Duration::from_secs(5)).unwrap();
    std::thread::sleep(Duration::from_millis(50));
    let waits = rt.stats().loops[0].driver.waits - before;
    assert!(waits < 20, "{waits} waits for 1000 self-queued tasks");
    rt.stop(Duration::from_millis(100));
    rt.join();
}
