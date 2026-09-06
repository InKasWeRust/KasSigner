macro_rules! wasm_error {
    ($message:expr $(,)?) => {
        $crate::wasm_api::utilities::common::js_error($message)
    };
}

mod contracts;
mod privacy;
mod protocol;
mod transactions;
mod utilities;
mod wallet;

pub use contracts::*;
pub use privacy::*;
pub use protocol::*;
pub use transactions::*;
pub use utilities::*;
pub use wallet::*;

#[cfg(test)]
pub(crate) mod test_support {
    use core::{
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
    };
    use std::sync::Arc;
    use std::task::Wake;

    struct NoopWake;

    impl Wake for NoopWake {
        fn wake(self: Arc<Self>) {}
    }

    /// Poll a boundary future that is expected to complete without browser I/O.
    pub(crate) fn ready<F: Future>(future: F) -> F::Output {
        let waker = Waker::from(Arc::new(NoopWake));
        let mut context = Context::from_waker(&waker);
        let mut future = pin!(future);
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => output,
            Poll::Pending => panic!("host boundary unexpectedly attempted browser I/O"),
        }
    }
}
