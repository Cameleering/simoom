//! Benchmarks for simoom (not published): the open-loop load generator, its HdrHistogram-compatible
//! histogram, the SLO sweep, the multi-node coordinator, the cold-start timer and the raw responder. The binary is
//! `simoom-bench` (`src/main.rs`); the method is docs/design/plan.md §6.

#![forbid(unsafe_code)]

pub mod attack;
pub mod coldstart;
pub mod cpu;
pub mod dist;
pub mod h1;
pub mod h3load;
pub mod hdr;
pub mod load;
pub mod newconn;
pub mod raw;
pub mod sweep;
