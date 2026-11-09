//! The stall watchdog left out (the `watchdog` feature is off): the same interface, with every
//! route always inline and never measured, so the calls around it fold away.

#![allow(dead_code)]

use std::sync::atomic::{AtomicBool, AtomicU32};
use std::sync::Arc;

/// The watchdog settings, from [`crate::Limits`] (ignored).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Policy {
    pub(crate) budget_ns: u64,
    pub(crate) stalls: u32,
    pub(crate) window_ns: u64,
    pub(crate) recover: u32,
}

/// Never produced without the feature.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Sample {
    pub(crate) cpu_ns: u64,
}

pub(crate) type Mark = ();

pub(crate) fn mark() -> Mark {}

pub(crate) fn since(_: Mark) -> Option<Sample> {
    None
}

pub(crate) fn measured<T>(f: impl FnOnce() -> T) -> (T, Option<Sample>) {
    (f(), None)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Event {
    None,
    Stall,
    Offloaded,
}

#[derive(Debug)]
pub(crate) struct Watch {
    pub(crate) logged: AtomicBool,
}

impl Watch {
    pub(crate) fn new(_group: Option<Arc<AtomicU32>>) -> Watch {
        Watch { logged: AtomicBool::new(false) }
    }

    #[inline(always)]
    pub(crate) fn offloaded(&self) -> bool {
        false
    }

    #[inline(always)]
    pub(crate) fn suspect(&self) -> bool {
        false
    }

    pub(crate) fn wall_overrun(&self) -> bool {
        false
    }

    pub(crate) fn measured(&self, _wall_ns: u64, _s: Sample, _p: &Policy, _stalls: u32, _now: u64) -> Event {
        Event::None
    }

    pub(crate) fn offloaded_call(&self, _wall_ns: u64, _s: Option<Sample>) -> bool {
        false
    }
}
