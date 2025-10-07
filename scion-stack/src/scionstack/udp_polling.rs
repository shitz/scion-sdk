// Copyright 2025 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! UDP polling abstractions for async UDP sockets.
//! The code in this file is copied from [quinn](https://github.com/quinn-rs) licensed
//! under the [MIT](https://github.com/quinn-rs/quinn/blob/main/LICENSE-MIT) and
//! [Apache 2.0](https://github.com/quinn-rs/quinn/blob/main/LICENSE-APACHE)

use std::{
    fmt,
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};

/// An object polled to detect when an associated [`AsyncUdpUnderlaySocket`] is writable
///
/// Any number of `UdpPoller`s may exist for a single [`AsyncUdpUnderlaySocket`]. Each `UdpPoller`
/// is responsible for notifying at most one task when that socket becomes writable.
pub(crate) trait UdpPoller: Send + Sync + std::fmt::Debug + 'static {
    /// Check whether the associated socket is likely to be writable
    ///
    /// Must be called after [`AsyncUdpUnderlaySocket::try_send`] returns
    /// [`io::ErrorKind::WouldBlock`] to register the task associated with `cx` to be woken when
    /// a send should be attempted again. Unlike in [`Future::poll`], a [`UdpPoller`] may be
    /// reused indefinitely no matter how many times `poll_writable` returns [`Poll::Ready`].
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>>;
}

pin_project_lite::pin_project! {
    /// Helper adapting a function `MakeFut` that constructs a single-use future `Fut` into a
    /// [`UdpPoller`] that may be reused indefinitely
    pub(crate) struct UdpPollHelper<MakeFut, Fut>
    {
        make_fut: MakeFut,
        #[pin]
        fut: Option<Fut>,
    }
}

impl<MakeFut, Fut> UdpPollHelper<MakeFut, Fut> {
    /// Construct a [`UdpPoller`] that calls `make_fut` to get the future to poll, storing it until
    /// it yields [`Poll::Ready`], then creating a new one on the next
    /// [`poll_writable`](UdpPoller::poll_writable)
    pub(crate) fn new(make_fut: MakeFut) -> Self {
        Self {
            make_fut,
            fut: None,
        }
    }
}

impl<MakeFut, Fut> UdpPoller for UdpPollHelper<MakeFut, Fut>
where
    MakeFut: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = io::Result<()>> + Send + Sync + 'static,
{
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let mut this = self.project();
        if this.fut.is_none() {
            this.fut.set(Some((this.make_fut)()));
        }
        // We're forced to `unwrap` here because `Fut` may be `!Unpin`, which means we can't safely
        // obtain an `&mut Fut` after storing it in `self.fut` when `self` is already behind `Pin`,
        // and if we didn't store it then we wouldn't be able to keep it alive between
        // `poll_writable` calls.
        let result = this.fut.as_mut().as_pin_mut().unwrap().poll(cx);
        if result.is_ready() {
            // Polling an arbitrary `Future` after it becomes ready is a logic error, so arrange for
            // a new `Future` to be created on the next call.
            this.fut.set(None);
        }
        result
    }
}

impl<MakeFut, Fut> fmt::Debug for UdpPollHelper<MakeFut, Fut> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpPollHelper").finish_non_exhaustive()
    }
}
