//! The agent service.
//!
//! This module hosts the long-running agent orchestration. In this foundation
//! phase it provides the [`Agent`] type that owns the shared [`AppState`] and
//! exposes read-only lifecycle accessors. The synchronisation loop, networking,
//! and CA management are implemented in later phases.

pub mod agent;
pub mod scheduler;

pub use agent::Agent;
pub use scheduler::{
    run_polling, FixedRandom, JitteredInterval, OsRandom, PollAction, RandomSource, Scheduler,
    Sleeper, ThreadSleeper,
};
