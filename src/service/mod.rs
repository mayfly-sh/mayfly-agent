//! The agent service.
//!
//! This module hosts the long-running agent orchestration. In this foundation
//! phase it provides the [`Agent`] type that owns the shared [`AppState`] and
//! exposes read-only lifecycle accessors. The synchronisation loop, networking,
//! and CA management are implemented in later phases.

pub mod agent;
pub mod backoff;
pub mod daemon;
pub mod runtime_state;
pub mod scheduler;
pub mod shutdown;

pub use agent::Agent;
pub use backoff::{retry_with_backoff, BackoffPolicy};
pub use daemon::Daemon;
pub use runtime_state::RuntimeStatus;
pub use scheduler::{
    run_polling, FixedRandom, JitteredInterval, OsRandom, PollAction, RandomSource, Scheduler,
    Sleeper, ThreadSleeper,
};
pub use shutdown::{install_signal_handlers, InterruptibleSleeper, Shutdown};

/// Drive a future to completion on the current thread without pulling in an
/// async runtime.
///
/// The agent is intentionally synchronous (blocking `reqwest`, a thread-based
/// scheduler). The only async surface in the crate is the
/// [`MayflyApiClient`](crate::identity::MayflyApiClient) trait; its production
/// implementation performs blocking I/O and resolves on the first poll, so a
/// no-op waker suffices. This is the single, audited place that bridges the
/// vestigial async API into the synchronous runtime.
pub(crate) fn block_on<F: std::future::Future>(future: F) -> F::Output {
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};

    struct NoopWaker;
    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    let waker = Waker::from(Arc::new(NoopWaker));
    let mut cx = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
    }
}
